//go:build integration
// +build integration

// Package test contains end-to-end integration tests for the cache-server
// using the public package APIs (socks server + cacheproxy + ca).
//
// These tests simulate a browser using a SOCKS5 proxy to reach an HTTPS
// origin, with our proxy performing MITM using a project Root CA. We verify:
//   - Leaf cert generation for DNS (SNI hostname) and IP SAN (SNI IP)
//   - Cache write on first fetch
//   - Cache hit on second fetch (served from disk, no origin fetch)
//   - End-to-end content integrity
package integrations

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jnovack/cache-server/pkg/cacheproxy"
	"github.com/jnovack/cache-server/pkg/socks"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jnovack/cache-server/internal/helpers"
)

// --- Tests ---

func TestMITM_LeafCertificate_DNS_SNI(t *testing.T) {
	cacheDir := t.TempDir()
	root := helpers.NewRootCA(t, cacheDir)

	// Origin TLS server with a simple handler.
	content := "hello-dns-sni"
	origin := helpers.NewHTTPSOrigin(t, content)

	// SOCKS proxy, configured to trust origin and sign leaves with our RootCA.
	port := helpers.ReservePort(t)
	s := &socks.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", port),
		CacheCfg: cacheproxy.Config{
			CacheDir:   filepath.Join(cacheDir, "data"),
			Metrics:    helpers.NopMetrics{},
			RootCA:     root,
			HTTPClient: helpers.HttpClientTrusting(origin.TLS.Certificates[0]),
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
	conn := helpers.DialThroughSOCKS(t, s.Addr, sniHost, socksDestPort)
	defer conn.Close()
	tlsConn := helpers.TlsClientOver(t, conn, sniHost, root.PEM())
	defer tlsConn.Close()

	// Send an HTTPS request with Host header pointing to our origin host:port.
	originHostPort := strings.TrimPrefix(origin.URL, "https://")
	helpers.SendHTTPRequest(t, tlsConn, http.MethodGet, originHostPort, "/dns-sni.txt")

	// Read and validate response.
	br := bufio.NewReader(tlsConn)
	resp := helpers.ReadHTTPResponse(t, br)

	// Verify the presented leaf certificate was minted for sniHost and signed by our Root.
	state := tlsConn.ConnectionState()
	require.GreaterOrEqual(t, len(state.PeerCertificates), 1, "peerCertificates should exist")
	leaf := state.PeerCertificates[0]
	assert.Contains(t, leaf.DNSNames, sniHost, "leaf DNSNames should include SNI host")
	assert.Equal(t, root.Cert.Subject.CommonName, state.VerifiedChains[0][len(state.VerifiedChains[0])-1].Subject.CommonName, "chain should include our RootCA")

	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("X-Cache"), "MISS", "first fetch should reach origin")
	assert.Equal(t, content, string(body))

}

func TestMITM_LeafCertificate_IP_SNI(t *testing.T) {
	cacheDir := t.TempDir()
	root := helpers.NewRootCA(t, cacheDir)
	origin := helpers.NewHTTPSOrigin(t, "hello-ip-sni")

	// SOCKS proxy
	port := helpers.ReservePort(t)
	s := &socks.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", port),
		CacheCfg: cacheproxy.Config{
			CacheDir:   filepath.Join(cacheDir, "data"),
			Metrics:    helpers.NopMetrics{},
			RootCA:     root,
			HTTPClient: helpers.HttpClientTrusting(origin.TLS.Certificates[0]),
		},
		RootCA: root,
	}
	require.NoError(t, os.MkdirAll(s.CacheCfg.CacheDir, 0o755))
	require.NoError(t, s.Start(), "start socks proxy")
	t.Cleanup(func() { _ = s.Close() })

	// Use an IPv4 SNI host to force IP SAN in leaf.
	sniIP := "127.0.0.1"
	conn := helpers.DialThroughSOCKS(t, s.Addr, sniIP, 443)
	defer conn.Close()
	tlsConn := helpers.TlsClientOver(t, conn, sniIP, root.PEM())
	defer tlsConn.Close()

	originHostPort := strings.TrimPrefix(origin.URL, "https://")
	helpers.SendHTTPRequest(t, tlsConn, http.MethodGet, originHostPort, "/ip-sni.txt")

	br := bufio.NewReader(tlsConn)
	resp := helpers.ReadHTTPResponse(t, br)
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
	root := helpers.NewRootCA(t, cacheDir)

	// Create a random 32-char alphanumeric string as file body.
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[n.Int64()]
	}
	content := string(b)

	origin := helpers.NewHTTPSOrigin(t, content)

	// SOCKS proxy
	port := helpers.ReservePort(t)
	s := &socks.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", port),
		CacheCfg: cacheproxy.Config{
			CacheDir:   filepath.Join(cacheDir, "data"),
			Metrics:    helpers.NopMetrics{},
			RootCA:     root,
			HTTPClient: helpers.HttpClientTrusting(origin.TLS.Certificates[0]),
		},
		RootCA: root,
	}
	require.NoError(t, os.MkdirAll(s.CacheCfg.CacheDir, 0o755))
	log.Debug().Str("CacheDir", s.CacheCfg.CacheDir).Msg("using cache dir")
	require.NoError(t, s.Start(), "start socks proxy")
	t.Cleanup(func() { _ = s.Close() })

	sniHost := "cache.test"
	conn := helpers.DialThroughSOCKS(t, s.Addr, sniHost, 443)
	defer conn.Close()
	tlsConn := helpers.TlsClientOver(t, conn, sniHost, root.PEM())
	defer tlsConn.Close()

	// Path to fetch
	const path = "/random.txt"
	originHostPort := strings.TrimPrefix(origin.URL, "https://")

	log.Debug().Str("uri", originHostPort+path).Msg("fetching URL")

	// First fetch: should hit origin and write to cache.
	helpers.SendHTTPRequest(t, tlsConn, http.MethodGet, originHostPort, path)
	br := bufio.NewReader(tlsConn)
	resp := helpers.ReadHTTPResponse(t, br)
	firstBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("X-Cache"), "MISS", "first response should be from origin")
	require.Equal(t, content, string(firstBody), "content mismatch on first fetch")

	// Origin file should be cached on disk now.
	originURL := &url.URL{
		Scheme:   "https",
		Host:     originHostPort,
		Path:     path,
		RawQuery: "",
	}
	// Check file exists on disk in expected path.
	cacheFile, _ := cacheproxy.CachePathForOrigin(s.CacheCfg.CacheDir, *originURL)
	_, err := os.Stat(cacheFile)
	require.NoError(t, err, "cache file should exist after first fetch")

	// Second fetch: new connection over SOCKS+TLS, expect HIT (served from cache w/o contacting origin).
	conn2 := helpers.DialThroughSOCKS(t, s.Addr, sniHost, 443)
	defer conn2.Close()
	tlsConn2 := helpers.TlsClientOver(t, conn2, sniHost, root.PEM())
	defer tlsConn2.Close()

	helpers.SendHTTPRequest(t, tlsConn2, http.MethodGet, originHostPort, path)
	br2 := bufio.NewReader(tlsConn2)
	resp2 := helpers.ReadHTTPResponse(t, br2)
	secondBody, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	require.Equal(t, content, string(secondBody), "content mismatch on second fetch")
	require.Equal(t, "HIT", resp2.Header.Get("X-Cache"), "expected HIT on second fetch")

	// Also test HEAD returns headers from cache.
	conn3 := helpers.DialThroughSOCKS(t, s.Addr, sniHost, 443)
	defer conn3.Close()
	tlsConn3 := helpers.TlsClientOver(t, conn3, sniHost, root.PEM())
	defer tlsConn3.Close()

	helpers.SendHTTPRequest(t, tlsConn3, http.MethodHead, originHostPort, path)
	br3 := bufio.NewReader(tlsConn3)
	resp3 := helpers.ReadHTTPResponse(t, br3)
	defer resp3.Body.Close()
	require.Equal(t, http.StatusOK, resp3.StatusCode)
	require.Equal(t, "HIT", resp3.Header.Get("X-Cache"), "expected HIT on HEAD")
}
