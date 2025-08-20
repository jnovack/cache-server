package socks

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jnovack/cache-server/pkg/ca"
	"github.com/jnovack/cache-server/pkg/cacheproxy"
)

func TestSocksCaptureRecordsHTTP(t *testing.T) {
	td := t.TempDir()

	// origin HTTP
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	defer origin.Close()
	hostPort := strings.TrimPrefix(origin.URL, "http://")

	// root CA for MITM path (not used here but required by config)
	name, err := ca.ParseDN("CN=mitm-root")
	if err != nil {
		t.Fatalf("ParseDN: %v", err)
	}
	root, err := ca.GenerateRootCASelfSigned(name)
	if err != nil {
		t.Fatalf("GenerateRootCA: %v", err)
	}
	root.CacheDir = td

	// cacheproxy config - use origin client for TLS cases if needed
	cfg := cacheproxy.Config{
		CacheDir:   td,
		Private:    false,
		HTTPClient: origin.Client(),
	}

	s := &Server{
		Addr:     "127.0.0.1:0",
		CacheCfg: cfg,
		RootCA:   root,
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start socks: %v", err)
	}
	defer s.Close()

	addr := s.ln.Addr().String()

	// connect and perform SOCKS handshake + CONNECT to hostPort
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	// greet
	_, _ = bw.Write([]byte{0x05, 0x01, 0x00})
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush greeting: %v", err)
	}
	// read method selection
	ver, _ := br.ReadByte()
	meth, _ := br.ReadByte()
	if ver != 0x05 || meth != 0x00 {
		t.Fatalf("unexpected greeting reply")
	}

	// send CONNECT to domain (atyp=3)
	parts := strings.Split(hostPort, ":")
	port, _ := strconv.Atoi(parts[1])
	_, _ = bw.Write([]byte{0x05, 0x01, 0x00, 0x03, byte(len(parts[0]))})
	_, _ = bw.Write([]byte(parts[0]))
	_, _ = bw.Write([]byte{byte(port >> 8), byte(port)})
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush connect: %v", err)
	}
	// read reply
	reply := make([]byte, 10)
	if _, err := io.ReadFull(br, reply); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("connect failed: %d", reply[1])
	}

	// now send an HTTP request over the established connection
	_, _ = bw.WriteString("GET /g HTTP/1.1\r\nHost: " + hostPort + "\r\nConnection: close\r\n\r\n")
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush http request: %v", err)
	}
	// read response
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// allow observer goroutine to run
	time.Sleep(100 * time.Millisecond)
	entries := s.Capture.List()
	if len(entries) == 0 {
		t.Fatalf("expected captures, got none")
	}
	found := false
	for _, e := range entries {
		if strings.Contains(e.Path, "/g") || strings.Contains(e.URL, "/g") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected capture entry for /g, entries: %+v", entries)
	}
}
