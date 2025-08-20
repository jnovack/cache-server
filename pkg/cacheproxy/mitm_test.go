package cacheproxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jnovack/cache-server/pkg/admin"
	"github.com/jnovack/cache-server/pkg/ca"
)

func TestHandleMITMHTTPS_EndToEnd(t *testing.T) {
	td := t.TempDir()

	// Origin TLS server with ETag+max-age=1 and 304 on If-None-Match.
	etag := `"v1"`
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if inm := r.Header.Get("If-None-Match"); inm == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "max-age=1")
		_, _ = io.WriteString(w, "hello-v1")
	}))
	defer origin.Close()

	// Root CA for MITM server.
	name, err := ca.ParseDN("CN=mitm-root")
	if err != nil {
		t.Fatalf("ParseDN: %v", err)
	}
	root, err := ca.GenerateRootCASelfSigned(name)
	if err != nil {
		t.Fatalf("GenerateRootCA: %v", err)
	}
	root.CacheDir = td

	// HTTP client used by proxy to talk to origin (trusts origin's cert).
	originClient := origin.Client()

	metrics := admin.NewMetrics()
	cfg := Config{
		CacheDir:   td,
		Private:    false,
		Metrics:    metrics,
		RootCA:     root,
		HTTPClient: originClient,
	}

	hostPort := strings.TrimPrefix(origin.URL, "https://")

	runOnce := func() (body string, status string) {
		srv, cli := net.Pipe()
		go HandleMITMHTTPS(srv, strings.Split(hostPort, ":")[0], cfg)

		tlsCli := tls.Client(cli, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err := tlsCli.Handshake(); err != nil {
			t.Fatalf("client handshake: %v", err)
		}

		req := "GET /greeting HTTP/1.1\r\nHost: " + hostPort + "\r\nConnection: close\r\n\r\n"
		if _, err := io.WriteString(tlsCli, req); err != nil {
			t.Fatalf("write request: %v", err)
		}

		br := bufio.NewReader(tlsCli)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), resp.Header.Get("X-Cache")
	}

	// First run: MISS (or REVALIDATED depending on timing)
	b1, xc1 := runOnce()
	if b1 != "hello-v1" {
		t.Fatalf("unexpected body: %q", b1)
	}
	if xc1 != "MISS" && xc1 != "REVALIDATED" {
		t.Fatalf("expected MISS/REVALIDATED, got %s", xc1)
	}

	// Second run before expiry: HIT or REVALIDATED
	b2, xc2 := runOnce()
	if b2 != "hello-v1" {
		t.Fatalf("unexpected body (2): %q", b2)
	}
	if xc2 != "HIT" && xc2 != "REVALIDATED" {
		t.Fatalf("expected HIT/REVALIDATED, got %s", xc2)
	}

	time.Sleep(1100 * time.Millisecond)
	_, xc3 := runOnce()
	if xc3 != "REVALIDATED" && xc3 != "HIT" {
		t.Fatalf("expected REVALIDATED/HIT, got %s", xc3)
	}
}
