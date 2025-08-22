//go:build integration

// Package test contains end-to-end integration tests for the cache-server
// using the public package APIs (socks server + cacheproxy + ca).
//
// These tests simulate a browser using a SOCKS5 proxy to reach an HTTPS
// origin, with our proxy performing MITM using a project Root CA. We verify:
//   - Leaf cert generation for DNS (SNI hostname) and IP SAN (SNI IP)
//   - Cache write on first fetch
//   - Cache hit on second fetch (served from disk, no origin fetch)
//   - End-to-end content integrity
package test

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jnovack/cache-server/pkg/ca"
	"github.com/jnovack/cache-server/pkg/cacheproxy"
	"github.com/jnovack/cache-server/pkg/socks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Minimal metrics stub to satisfy cacheproxy.Metrics ---

type nopMetrics struct{}

func (nopMetrics) IncTotalRequests()                   {}
func (nopMetrics) IncHit()                             {}
func (nopMetrics) IncMiss()                            {}
func (nopMetrics) IncRevalidated()                     {}
func (nopMetrics) IncBypass()                          {}
func (nopMetrics) IncNoStore()                         {}
func (nopMetrics) IncNoCache()                         {}
func (nopMetrics) IncStale()                           {}
func (nopMetrics) IncOriginErrors()                    {}
func (nopMetrics) ObserveDuration(_ string, _ float64) {}

// reservePort returns an available local TCP port by briefly listening and closing.
func reservePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "reserve a local port")
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// newRootCA creates a self-signed root CA and prepares its on-disk leaf cache dir.
func newRootCA(t *testing.T, dir string) *ca.RootCA {
	t.Helper()
	// DN can be flexible; use a simple CN.
	name := pkix.Name{CommonName: "Test Root CA"}
	root, err := ca.GenerateRootCASelfSigned(name)
	require.NoError(t, err, "generate root CA")
	root.CacheDir = filepath.Join(dir, "certs")
	require.NoError(t, os.MkdirAll(root.CacheDir, 0o755))
	return root
}

// newHTTPSOrigin spins up a TLS test server that serves a single path with the provided body
// and sets caching headers to allow a cache HIT without revalidation.
func newHTTPSOrigin(t *testing.T, body string) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// Make it cacheable and fresh for a while.
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		_, _ = io.WriteString(w, body)
	})
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// httpClientTrusting returns an *http.Client that trusts the given tls.Certificate (origin server).
func httpClientTrusting(cert tls.Certificate) *http.Client {
	cp := x509.NewCertPool()
	if len(cert.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			cp.AddCert(leaf)
		}
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: cp},
		},
		Timeout: 10 * time.Second,
	}
}

// dialThroughSOCKS performs a bare SOCKS5 handshake to proxyAddr, requesting CONNECT destHost:destPort.
func dialThroughSOCKS(t *testing.T, proxyAddr, destHost string, destPort uint16) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err, "dial socks proxy")
	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)

	// greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
	_, _ = bw.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, bw.Flush())

	ver, _ := br.ReadByte()
	method, _ := br.ReadByte()
	require.Equal(t, byte(0x05), ver, "socks version")
	require.Equal(t, byte(0x00), method, "no-auth selected")

	// request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP, DST.ADDR, DST.PORT
	host := net.ParseIP(destHost)
	var atyp byte
	var addr []byte
	if host != nil && host.To4() != nil {
		atyp = 0x01
		addr = host.To4()
	} else if host != nil && host.To16() != nil {
		atyp = 0x04
		addr = host.To16()
	} else {
		atyp = 0x03
		addr = append([]byte{byte(len(destHost))}, []byte(destHost)...)
	}
	portHi := byte(destPort >> 8)
	portLo := byte(destPort & 0xff)

	req := []byte{0x05, 0x01, 0x00, atyp}
	req = append(req, addr...)
	req = append(req, portHi, portLo)
	_, _ = bw.Write(req)
	require.NoError(t, bw.Flush())

	// reply: VER=5, REP=0, RSV=0, ATYP, BND.ADDR, BND.PORT
	rep := make([]byte, 4)
	_, err = io.ReadFull(br, rep)
	require.NoError(t, err, "read socks reply header")
	require.Equal(t, byte(0x05), rep[0], "socks version in reply")
	require.Equal(t, byte(0x00), rep[1], "socks connect success")

	// read and discard BND.ADDR + BND.PORT
	var addrLen int
	switch rep[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		l, _ := br.ReadByte()
		addrLen = int(l)
	default:
		t.Fatalf("unknown ATYP in reply: 0x%02x", rep[3])
	}
	if addrLen > 0 {
		_, _ = io.CopyN(io.Discard, br, int64(addrLen))
	}
	_, _ = io.CopyN(io.Discard, br, 2) // port
	return c
}

// tlsClientOver wraps conn with a TLS client using sniHost and trusting rootPEM.
func tlsClientOver(t *testing.T, conn net.Conn, sniHost string, rootPEM []byte) *tls.Conn {
	t.Helper()
	cp := x509.NewCertPool()
	require.True(t, cp.AppendCertsFromPEM(rootPEM), "append root CA to pool")
	cfg := &tls.Config{
		ServerName: sniHost, // ensure SNI and verification
		RootCAs:    cp,
		MinVersion: tls.VersionTLS12,
	}
	tlsConn := tls.Client(conn, cfg)
	require.NoError(t, tlsConn.Handshake(), "TLS handshake with proxy")
	return tlsConn
}

// sendHTTPRequest writes a minimal HTTP/1.1 request over w, with explicit Host header.
func sendHTTPRequest(t *testing.T, w io.Writer, method, hostWithPort, path string) {
	t.Helper()
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", method, path, hostWithPort)
	_, err := io.WriteString(w, req)
	require.NoError(t, err, "write HTTP request")
}

// readHTTPResponse parses an HTTP/1.1 response from r.
func readHTTPResponse(t *testing.T, r *bufio.Reader) *http.Response {
	t.Helper()
	resp, err := http.ReadResponse(r, nil)
	require.NoError(t, err, "read HTTP response")
	return resp
}

// --- Tests ---

func TestMITM_LeafCertificate_DNS_SNI(t *testing.T) {
	cacheDir := t.TempDir()
	root := newRootCA(t, cacheDir)

	// Origin TLS server with a simple handler.
	content := "hello-dns-sni"
	origin := newHTTPSOrigin(t, content)

	// SOCKS proxy, configured to trust origin and sign leaves with our RootCA.
	port := reservePort(t)
	s := &socks.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", port),
		CacheCfg: cacheproxy.Config{
			CacheDir:   filepath.Join(cacheDir, "data"),
			Metrics:    nopMetrics{},
			RootCA:     root,
			HTTPClient: httpClientTrusting(origin.TLS.Certificates[0]),
		},
		RootCA: root,
	}
	require.NoError(t, os.MkdirAll(s.CacheCfg.CacheDir, 0o755))
	require.NoError(t, s.Start(), "start socks proxy")
	t.Cleanup(func() { _ = s.Close() })

	// SOCKS destination host (used for SNI and leaf CN/SAN), port must be 443 to trigger MITM path.
	sniHost := "example.test"
	socksDestPort := uint16(443)

	// Connect through SOCKS, then perform TLS to the proxy using SNI=sniHost.
	conn := dialThroughSOCKS(t, s.Addr, sniHost, socksDestPort)
	defer conn.Close()
	tlsConn := tlsClientOver(t, conn, sniHost, root.PEM())
	defer tlsConn.Close()

	// Send an HTTPS request with Host header pointing to our origin host:port.
	originHostPort := strings.TrimPrefix(origin.URL, "https://")
	sendHTTPRequest(t, tlsConn, http.MethodGet, originHostPort, "/dns-sni.txt")

	// Read and validate response.
	br := bufio.NewReader(tlsConn)
	resp := readHTTPResponse(t, br)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("X-Cache"), "MISS", "first fetch should reach origin")
	require.Equal(t, content, string(body))

	// Verify the presented leaf certificate was minted for sniHost and signed by our Root.
	state := tlsConn.ConnectionState()
	require.GreaterOrEqual(t, len(state.PeerCertificates), 1)
	leaf := state.PeerCertificates[0]
	assert.Contains(t, leaf.DNSNames, sniHost, "leaf DNSNames should include SNI host")
	require.Equal(t, root.Cert.Subject.CommonName, state.VerifiedChains[0][len(state.VerifiedChains[0])-1].Subject.CommonName, "chain should include our RootCA")
}

func TestMITM_LeafCertificate_IP_SNI(t *testing.T) {
	cacheDir := t.TempDir()
	root := newRootCA(t, cacheDir)
	origin := newHTTPSOrigin(t, "hello-ip-sni")

	// SOCKS proxy
	port := reservePort(t)
	s := &socks.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", port),
		CacheCfg: cacheproxy.Config{
			CacheDir:   filepath.Join(cacheDir, "data"),
			Metrics:    nopMetrics{},
			RootCA:     root,
			HTTPClient: httpClientTrusting(origin.TLS.Certificates[0]),
		},
		RootCA: root,
	}
	require.NoError(t, os.MkdirAll(s.CacheCfg.CacheDir, 0o755))
	require.NoError(t, s.Start(), "start socks proxy")
	t.Cleanup(func() { _ = s.Close() })

	// Use an IPv4 SNI host to force IP SAN in leaf.
	sniIP := "127.0.0.1"
	conn := dialThroughSOCKS(t, s.Addr, sniIP, 443)
	defer conn.Close()
	tlsConn := tlsClientOver(t, conn, sniIP, root.PEM())
	defer tlsConn.Close()

	originHostPort := strings.TrimPrefix(origin.URL, "https://")
	sendHTTPRequest(t, tlsConn, http.MethodGet, originHostPort, "/ip-sni.txt")

	br := bufio.NewReader(tlsConn)
	resp := readHTTPResponse(t, br)
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify the leaf contains the IP in SANs.
	state := tlsConn.ConnectionState()
	require.GreaterOrEqual(t, len(state.PeerCertificates), 1)
	leaf := state.PeerCertificates[0]
	var hasIP bool
	for _, ip := range leaf.IPAddresses {
		if ip.String() == sniIP {
			hasIP = true
			break
		}
	}
	require.True(t, hasIP, "leaf should include IP SAN for %s", sniIP)
}

func TestEndToEnd_Cache_Fresh_HIT(t *testing.T) {
	cacheDir := t.TempDir()
	root := newRootCA(t, cacheDir)

	// Create a random 32-char alphanumeric string as file body.
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[n.Int64()]
	}
	content := string(b)

	origin := newHTTPSOrigin(t, content)

	// SOCKS proxy
	port := reservePort(t)
	s := &socks.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", port),
		CacheCfg: cacheproxy.Config{
			CacheDir:   filepath.Join(cacheDir, "data"),
			Metrics:    nopMetrics{},
			RootCA:     root,
			HTTPClient: httpClientTrusting(origin.TLS.Certificates[0]),
		},
		RootCA: root,
	}
	require.NoError(t, os.MkdirAll(s.CacheCfg.CacheDir, 0o755))
	require.NoError(t, s.Start(), "start socks proxy")
	t.Cleanup(func() { _ = s.Close() })

	sniHost := "cache.test"
	conn := dialThroughSOCKS(t, s.Addr, sniHost, 443)
	defer conn.Close()
	tlsConn := tlsClientOver(t, conn, sniHost, root.PEM())
	defer tlsConn.Close()

	// Path to fetch
	const path = "/random.txt"
	originHostPort := strings.TrimPrefix(origin.URL, "https://")

	// First fetch: should hit origin and write to cache.
	sendHTTPRequest(t, tlsConn, http.MethodGet, originHostPort, path)
	br := bufio.NewReader(tlsConn)
	resp := readHTTPResponse(t, br)
	firstBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("X-Cache"), "MISS", "first response should be from origin")
	require.Equal(t, content, string(firstBody), "content mismatch on first fetch")

	// Check file exists on disk in expected path.
	cacheFile, _ := cacheproxy.CachePathForOrigin(s.CacheCfg.CacheDir, originHostPort, path)
	_, err := os.Stat(cacheFile)
	require.NoError(t, err, "cache file should exist after first fetch")

	// Second fetch: new connection over SOCKS+TLS, expect HIT (served from cache w/o contacting origin).
	conn2 := dialThroughSOCKS(t, s.Addr, sniHost, 443)
	defer conn2.Close()
	tlsConn2 := tlsClientOver(t, conn2, sniHost, root.PEM())
	defer tlsConn2.Close()

	sendHTTPRequest(t, tlsConn2, http.MethodGet, originHostPort, path)
	br2 := bufio.NewReader(tlsConn2)
	resp2 := readHTTPResponse(t, br2)
	secondBody, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	require.Equal(t, content, string(secondBody), "content mismatch on second fetch")
	require.Equal(t, "HIT", resp2.Header.Get("X-Cache"), "expected HIT on second fetch")

	// Also test HEAD returns headers from cache.
	conn3 := dialThroughSOCKS(t, s.Addr, sniHost, 443)
	defer conn3.Close()
	tlsConn3 := tlsClientOver(t, conn3, sniHost, root.PEM())
	defer tlsConn3.Close()

	sendHTTPRequest(t, tlsConn3, http.MethodHead, originHostPort, path)
	br3 := bufio.NewReader(tlsConn3)
	resp3 := readHTTPResponse(t, br3)
	defer resp3.Body.Close()
	require.Equal(t, http.StatusOK, resp3.StatusCode)
	require.Equal(t, "HIT", resp3.Header.Get("X-Cache"), "expected HIT on HEAD")
}
