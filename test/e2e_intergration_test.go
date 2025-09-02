//go:build integration
// +build integration

// 1. Setup origin with OPTIONS + GET handlers
// 2. Setup socks.Server with RootCA + CacheDir
// 3. Dial through proxy with SNI host
// 4. Send OPTIONS, assert 204 and Access-Control headers
// 5. Send GET with Origin, custom headers, and Cookie
// 6. Assert CORS headers, cookie echoed, body content matches
// 7. Check X-Cache == MISS on first fetch
// 8. Send GET again, check X-Cache == HIT

package integrations

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cachepkg "github.com/jnovack/cache-server/pkg/cache"
	"github.com/jnovack/cache-server/pkg/cacheproxy"
	. "github.com/jnovack/cache-server/pkg/cacheproxy"
	"github.com/jnovack/cache-server/pkg/socks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jnovack/cache-server/internal/helpers"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// TestMITM_CORS_Cookies_Flow validates that a browser-style CORS + cookie
// flow works end-to-end through the MITM SOCKS proxy.
func TestE2E_CORS_Cookies_Flow(t *testing.T) {
	cacheDir := t.TempDir()
	root := helpers.NewRootCA(t, cacheDir)

	// Generate a random 32-character alphanumeric body
	content, err := randomAlphaNumeric(32)
	require.NoError(t, err)

	// Origin server with CORS preflight + GET handler
	origin := newHTTPSOriginWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "authorization,content-type,x-custom-header")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Cache-Control", "no-store")
		// Set a cookie
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123", Path: "/", HttpOnly: true})

		switch r.Method {
		case http.MethodOptions:
			w.WriteHeader(http.StatusNoContent)
			return
		case http.MethodGet:
			fmt.Fprint(w, content)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// SOCKS proxy, configured to trust origin and sign leaves with our RootCA.
	port := helpers.ReservePort(t)
	s := &socks.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", port),
		CacheCfg: cacheproxy.Config{
			CacheDir:   filepath.Join(cacheDir, "data"),
			Metrics:    helpers.NopMetrics{},
			RootCA:     root,
			Private:    true,
			HTTPClient: helpers.HttpClientTrusting(origin.TLS.Certificates[0]),
		},
		RootCA: root,
	}
	require.NoError(t, os.MkdirAll(s.CacheCfg.CacheDir, 0o755))
	require.NoError(t, s.Start(), "start socks proxy")
	t.Cleanup(func() { _ = s.Close() })

	// SOCKS destination host (used for SNI and leaf CN/SAN)
	sniHost := "cors.test"
	socksDestPort := uint16(443)

	// Connect through SOCKS, then perform TLS to the proxy using SNI=sniHost.
	conn := helpers.DialThroughSOCKS(t, s.Addr, sniHost, socksDestPort)
	defer conn.Close()
	tlsConn := helpers.TlsClientOver(t, conn, sniHost, root.PEM())
	defer tlsConn.Close()

	// --- Step 1: Preflight OPTIONS ---
	preflightReq := "OPTIONS /cors-test.txt HTTP/1.1\r\n" +
		"Host: " + strings.TrimPrefix(origin.URL, "https://") + "\r\n" +
		"Origin: https://example.org\r\n" +
		"Access-Control-Request-Method: GET\r\n" +
		"Access-Control-Request-Headers: authorization,content-type,x-custom-header\r\n" +
		"Connection: close\r\n\r\n"
	_, _ = tlsConn.Write([]byte(preflightReq))

	br := bufio.NewReader(tlsConn)
	resp := helpers.ReadHTTPResponse(t, br)
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "preflight should return 204")
	assert.Equal(t, "https://example.org", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), "GET")
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Headers"), "x-custom-header")

	// --- Step 2: Actual GET with cookie ---
	conn2 := helpers.DialThroughSOCKS(t, s.Addr, sniHost, socksDestPort)
	defer conn2.Close()
	tlsConn2 := helpers.TlsClientOver(t, conn2, sniHost, root.PEM())
	defer tlsConn2.Close()

	getReq := "GET /cors-test.txt HTTP/1.1\r\n" +
		"Host: " + strings.TrimPrefix(origin.URL, "https://") + "\r\n" +
		"Origin: https://example.org\r\n" +
		"Cookie: session=abc123\r\n" +
		"Authorization: Bearer testtoken\r\n" +
		"Content-Type: application/json\r\n" +
		"X-Custom-Header: 1\r\n" +
		"Connection: close\r\n\r\n"
	_, _ = tlsConn2.Write([]byte(getReq))

	br2 := bufio.NewReader(tlsConn2)
	resp2 := helpers.ReadHTTPResponse(t, br2)
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	require.Equal(t, http.StatusOK, resp2.StatusCode, "GET should return 200")
	assert.Equal(t, "https://example.org", resp2.Header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, string(body2), content)
	assert.Contains(t, resp2.Header.Get("Set-Cookie"), "session=abc123")
	assert.Contains(t, resp2.Header.Get("X-Cache"), "BYPASS", "first fetch should reach origin")

	// Check for file and metadata
	cacheFile, metaFile := CachePathForOrigin(filepath.Join(cacheDir, "data"), url.URL{Scheme: "https", Host: strings.TrimPrefix(origin.URL, "https://"), Path: "/cors-test.txt"})
	_, err = os.Stat(cacheFile)
	assert.True(t, err == nil, "cache file for `/cors-test.txt` should exist, but got err=%v", err)
	meta := cachepkg.ReadMeta(metaFile)
	assert.True(t, meta.NoStore, "no-store should be true")

	// --- Step 3: Cached GET ---
	conn3 := helpers.DialThroughSOCKS(t, s.Addr, sniHost, socksDestPort)
	defer conn3.Close()
	tlsConn3 := helpers.TlsClientOver(t, conn3, sniHost, root.PEM())
	defer tlsConn3.Close()

	_, _ = tlsConn3.Write([]byte(getReq))
	br3 := bufio.NewReader(tlsConn3)
	resp3 := helpers.ReadHTTPResponse(t, br3)
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()

	require.Equal(t, http.StatusOK, resp3.StatusCode)
	assert.Contains(t, string(body3), content)
	assert.Contains(t, resp3.Header.Get("X-Cache"), "BYPASS", "second fetch should ALSO miss because we sent no-store")

	// Re-check for file and metadata
	cacheFile, metaFile = CachePathForOrigin(filepath.Join(cacheDir, "data"), url.URL{Scheme: "https", Host: strings.TrimPrefix(origin.URL, "https://"), Path: "/cors-test.txt"})
	_, err = os.Stat(cacheFile)
	assert.True(t, err == nil, "cache file for `/cors-test.txt` should exist, but got err=%v", err)
	meta = cachepkg.ReadMeta(metaFile)
	assert.True(t, meta.NoStore, "no-store should be true")
}

// newHTTPSOriginWithHandler is like newHTTPSOrigin but accepts a handler.
func newHTTPSOriginWithHandler(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{newSelfSignedCert(t)}}
	srv.StartTLS()
	t.Cleanup(func() { srv.Close() })
	return srv
}

// newSelfSignedCert generates a throwaway TLS certificate for test servers.
func newSelfSignedCert(t *testing.T) tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return cert
}

// RandomAlphaNumeric returns a securely generated random alphanumeric string of the given length.
func randomAlphaNumeric(n int) (string, error) {
	var sb strings.Builder
	sb.Grow(n)

	// Each byte maps to an index in `letters`
	for i := 0; i < n; i++ {
		b := make([]byte, 1)
		_, err := rand.Read(b)
		if err != nil {
			return "", err
		}
		sb.WriteByte(letters[int(b[0])%len(letters)])
	}
	return sb.String(), nil
}
