package helpers

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jnovack/cache-server/pkg/ca"
	"github.com/stretchr/testify/require"
)

// --- Minimal metrics stub to satisfy cacheproxy.Metrics ---

type NopMetrics struct{}

func (NopMetrics) IncTotalRequests()                   {}
func (NopMetrics) IncHit()                             {}
func (NopMetrics) IncMiss()                            {}
func (NopMetrics) IncRevalidated()                     {}
func (NopMetrics) IncBypass()                          {}
func (NopMetrics) IncNoStore()                         {}
func (NopMetrics) IncNoCache()                         {}
func (NopMetrics) IncStale()                           {}
func (NopMetrics) IncOriginErrors()                    {}
func (NopMetrics) IncCacheErrors()                     {}
func (NopMetrics) ObserveDuration(_ string, _ float64) {}

// ReservePort returns an available local TCP port by briefly listening and closing.
func ReservePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "reserve a local port")
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// NewRootCA creates a self-signed root CA and prepares its on-disk leaf cache dir.
func NewRootCA(t *testing.T, dir string) *ca.RootCA {
	t.Helper()
	// DN can be flexible; use a simple CN.
	name := pkix.Name{CommonName: "Test Root CA"}
	root, err := ca.GenerateRootCASelfSigned(name)
	require.NoError(t, err, "generate root CA")
	root.CacheDir = filepath.Join(dir, "certs")
	require.NoError(t, os.MkdirAll(root.CacheDir, 0o755))
	return root
}

// NewHTTPSOrigin spins up a TLS test server that serves a single path with the provided body
// and sets caching headers to allow a cache HIT without revalidation.
func NewHTTPSOrigin(t *testing.T, body string) *httptest.Server {
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

// HttpClientTrusting returns an *http.Client that trusts the given tls.Certificate (origin server).
func HttpClientTrusting(cert tls.Certificate) *http.Client {
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

// DialThroughSOCKS performs a bare SOCKS5 handshake to proxyAddr, requesting CONNECT destHost:destPort.
func DialThroughSOCKS(t *testing.T, proxyAddr, destHost string, destPort uint16) net.Conn {
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

// TlsClientOver wraps conn with a TLS client using sniHost and trusting rootPEM.
func TlsClientOver(t *testing.T, conn net.Conn, sniHost string, rootPEM []byte) *tls.Conn {
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

// SendHTTPRequest writes a minimal HTTP/1.1 request over w, with explicit Host header.
func SendHTTPRequest(t *testing.T, w io.Writer, method, hostWithPort, path string) {
	t.Helper()
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", method, path, hostWithPort)
	_, err := io.WriteString(w, req)
	require.NoError(t, err, "write HTTP request")
}

// ReadHTTPResponse parses an HTTP/1.1 response from r.
func ReadHTTPResponse(t *testing.T, r *bufio.Reader) *http.Response {
	t.Helper()
	resp, err := http.ReadResponse(r, nil)
	require.NoError(t, err, "read HTTP response")
	return resp
}
