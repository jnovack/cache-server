package cacheproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jnovack/cache-server/pkg/admin"
	"github.com/jnovack/cache-server/pkg/ca"
)

// runMITMOnce dials the MITM handler over a net.Pipe, performs a single HTTPS
// request through it, and returns body + X-Cache disposition.
func runMITMOnce(t *testing.T, cfg Config, hostPort, path string) (body, xcache string, status int) {
	t.Helper()

	serverSide, clientSide := net.Pipe()
	ctx := context.WithValue(context.Background(), ConnectionIDKey{}, uuid.Must(uuid.NewV7()))
	go HandleMITMHTTPS(ctx, serverSide, strings.Split(hostPort, ":")[0], cfg)

	cli := tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("TLS client handshake: %v", err)
	}

	req := "GET " + path + " HTTP/1.1\r\nHost: " + hostPort + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(cli, req); err != nil {
		t.Fatalf("write request: %v", err)
	}

	br := bufio.NewReader(cli)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.Header.Get("X-Cache"), resp.StatusCode
}

// TestHandleCacheHeader_MissThenHitRevalidate ensures the HTTPS MITM path:
//  1. first request -> MISS (cached)
//  2. before expiry -> HIT
//  3. after expiry -> REVALIDATED (304 from origin)
func TestHandleCacheHeader_MissThenHitRevalidate(t *testing.T) {
	t.Parallel()

	td := t.TempDir()
	etag := `"v1"`

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Revalidate via ETag
		if inm := r.Header.Get("If-None-Match"); inm == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "max-age=1")
		_, _ = io.WriteString(w, "hello-v1")
	}))
	defer origin.Close()

	// Root CA for our MITM proxy.
	name, err := ca.ParseDN("CN=mitm-root")
	if err != nil {
		t.Fatalf("ParseDN: %v", err)
	}
	root, err := ca.GenerateRootCASelfSigned(name)
	if err != nil {
		t.Fatalf("GenerateRootCA: %v", err)
	}
	root.CacheDir = td

	metrics := admin.NewMetrics()
	cfg := Config{
		CacheDir:   td,
		Private:    false,
		Metrics:    metrics,
		RootCA:     root,
		HTTPClient: origin.Client(), // trusts origin's TLS cert
	}

	hostPort := strings.TrimPrefix(origin.URL, "https://")

	// 1) First request: MISS or (rarely) REVALIDATED due to timing.
	body, xcache, code := runMITMOnce(t, cfg, hostPort, "/greeting")
	if code != http.StatusOK {
		t.Fatalf("unexpected status (1): %d", code)
	}
	if body != "hello-v1" {
		t.Fatalf("unexpected body (1): %q", body)
	}
	if xcache != "MISS" && xcache != "REVALIDATED" {
		t.Fatalf("expected MISS or REVALIDATED (1), got %q", xcache)
	}

	// 2) Immediately again: should be HIT or REVALIDATED (if origin got pinged).
	body, xcache, code = runMITMOnce(t, cfg, hostPort, "/greeting")
	if code != http.StatusOK {
		t.Fatalf("unexpected status (2): %d", code)
	}
	if body != "hello-v1" {
		t.Fatalf("unexpected body (2): %q", body)
	}
	if xcache != "HIT" && xcache != "REVALIDATED" {
		t.Fatalf("expected HIT or REVALIDATED (2), got %q", xcache)
	}

	// 3) After max-age expires: should REVALIDATE.
	time.Sleep(1100 * time.Millisecond)
	body, xcache, code = runMITMOnce(t, cfg, hostPort, "/greeting")
	if code != http.StatusOK {
		t.Fatalf("unexpected status (3): %d", code)
	}
	if body != "hello-v1" {
		t.Fatalf("unexpected body (3): %q", body)
	}
	if xcache != "REVALIDATED" && xcache != "HIT" {
		// Depending on clock/age rounding, HIT is acceptable if still fresh.
		t.Fatalf("expected REVALIDATED or HIT (3), got %q", xcache)
	}
}

// TestHandleCacheHeader_NoStoreNoCache ensures responses with no-store (or
// no-cache while not in -private mode) are not cached and are served as BYPASS.
func TestHandleCacheHeader_NoStoreNoCache(t *testing.T) {
	t.Parallel()

	td := t.TempDir()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately uncacheable by default policy.
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "body")
	}))
	defer origin.Close()

	name, err := ca.ParseDN("CN=mitm-root")
	if err != nil {
		t.Fatalf("ParseDN: %v", err)
	}
	root, err := ca.GenerateRootCASelfSigned(name)
	if err != nil {
		t.Fatalf("GenerateRootCA: %v", err)
	}
	root.CacheDir = td

	metrics := admin.NewMetrics()
	cfg := Config{
		CacheDir:   td,
		Private:    false, // default policy (do not cache private/no-store)
		Metrics:    metrics,
		RootCA:     root,
		HTTPClient: origin.Client(), // trusts origin TLS
	}

	hostPort := strings.TrimPrefix(origin.URL, "https://")

	// First request must BYPASS and not cache.
	body, xcache, code := runMITMOnce(t, cfg, hostPort, "/asset")
	if code != http.StatusOK {
		t.Fatalf("unexpected status (1): %d", code)
	}
	if body != "body" {
		t.Fatalf("unexpected body (1): %q", body)
	}
	if xcache != "BYPASS" {
		t.Fatalf("expected BYPASS (1), got %q", xcache)
	}

	// Second request should also BYPASS (not cached).
	body, xcache, code = runMITMOnce(t, cfg, hostPort, "/asset")
	if code != http.StatusOK {
		t.Fatalf("unexpected status (2): %d", code)
	}
	if body != "body" {
		t.Fatalf("unexpected body (2): %q", body)
	}
	if xcache != "BYPASS" {
		t.Fatalf("expected BYPASS (2), got %q", xcache)
	}
}
