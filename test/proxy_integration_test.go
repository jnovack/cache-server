//go:build integration
// +build integration

package test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jnovack/cache-server/pkg/cache"
	. "github.com/jnovack/cache-server/pkg/cacheproxy"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type dummyMetrics struct {
	mu     sync.Mutex
	counts map[string]int
	obs    map[string][]float64
}

func (d *dummyMetrics) IncHit()           { d.inc("hit") }
func (d *dummyMetrics) IncMiss()          { d.inc("miss") }
func (d *dummyMetrics) IncStale()         { d.inc("stale") }
func (d *dummyMetrics) IncRevalidated()   { d.inc("revalidated") }
func (d *dummyMetrics) IncBypass()        { d.inc("bypass") }
func (d *dummyMetrics) IncNoStore()       { d.inc("nostore") }
func (d *dummyMetrics) IncNoCache()       { d.inc("nocache") }
func (d *dummyMetrics) IncCacheErrors()   { d.inc("cacheerr") }
func (d *dummyMetrics) IncOriginErrors()  { d.inc("originerr") }
func (d *dummyMetrics) IncTotalRequests() { d.inc("total") }

func (d *dummyMetrics) ObserveDuration(k string, v float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.obs == nil {
		d.obs = map[string][]float64{}
	}
	d.obs[k] = append(d.obs[k], v)
}
func (d *dummyMetrics) inc(k string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.counts == nil {
		d.counts = map[string]int{}
	}
	d.counts[k]++
}

func TestHandleCacheRequest_AllPaths(t *testing.T) {
	tmp := t.TempDir()
	ctx := context.WithValue(context.Background(), RequestIDKey{}, uuid.New())
	ctx = context.WithValue(ctx, ConnectionIDKey{}, uuid.New())
	ctx = log.Logger.WithContext(ctx)

	metrics := &dummyMetrics{}
	var observed []RequestRecord
	observer := func(r RequestRecord) { observed = append(observed, r) }

	// Dummy origin server with /fresh returning a 32-char random string
	var freshString string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fresh":
			w.Header().Set("Cache-Control", "max-age=60")
			b := make([]byte, 32)
			for i := range b {
				b[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[time.Now().UnixNano()%36]
			}
			freshString = string(b)
			fmt.Fprint(w, freshString)
		case "/nostore":
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprint(w, "nostore-data")
		case "/nocache":
			w.Header().Set("Cache-Control", "no-cache")
			fmt.Fprint(w, "nocache-data")
		case "/privateauth":
			w.Header().Set("Cache-Control", "private")
			fmt.Fprint(w, "privateauth-data")
		case "/error":
			w.WriteHeader(502)
			fmt.Fprint(w, "bad gateway")
		case "/notmod":
			w.WriteHeader(304)
			w.Header().Set("ETag", "abc")
			w.Header().Set("Cache-Control", "max-age=60")
		case "/bad":
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		default:
			w.Header().Set("Cache-Control", "max-age=0")
			fmt.Fprint(w, "default")
		}
	}))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)

	// Start a single TCP listener for all subtests
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cfg := Config{
		CacheDir:        tmp,
		HTTPClient:      &http.Client{Timeout: 2 * time.Second},
		Metrics:         metrics,
		RequestObserver: observer,
		Private:         false,
	}

	// Accept loop for all requests
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					c.Close()
					return

				}
				HandleCacheRequest(ctx, c, req, cfg, false)
				c.Close()
			}(conn)
		}
	}()

	t.Run("cache miss then hit", func(t *testing.T) {
		// First request: MISS, populates cache
		req, _ := http.NewRequest("GET", "/fresh", nil)
		req.Host = originURL.Host
		clientConn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err, "dial")
		require.NoError(t, req.Write(clientConn), "write req")
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
		require.NoError(t, err, "read resp")
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "read body")
		assert.Equal(t, 32, len(b), "/fresh should return 32 bytes")
		assert.Equal(t, freshString, string(b), "/fresh body mismatch")
		resp.Body.Close()
		clientConn.Close()

		// Second request: HIT (should serve from cache)
		clientConn2, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err, "dial2")
		require.NoError(t, req.Write(clientConn2), "write req2")
		resp2, err := http.ReadResponse(bufio.NewReader(clientConn2), req)
		require.NoError(t, err, "read resp2")
		b2, err := io.ReadAll(resp2.Body)
		require.NoError(t, err, "read body2")
		assert.Equal(t, freshString, string(b2), "cache HIT body mismatch")
		resp2.Body.Close()
		clientConn2.Close()

		// Check cache file matches
		cacheFile, _ := CachePathForOrigin(tmp, url.URL{Scheme: "http", Host: originURL.Host, Path: "/fresh"})
		disk, err := os.ReadFile(cacheFile)
		require.NoError(t, err, "read cache file")
		assert.Equal(t, freshString, string(disk), "cache file mismatch")
	})

	t.Run("no-store bypass", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/nostore", nil)
		require.NoError(t, err, "new request")
		req.Host = originURL.Host
		clientConn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err, "dial")
		require.NoError(t, req.Write(clientConn), "write req")
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
		require.NoError(t, err, "read resp")
		assert.Equal(t, "BYPASS", resp.Header.Get("X-Cache"), "want BYPASS")
		require.NoError(t, resp.Body.Close(), "close body")
		require.NoError(t, clientConn.Close(), "close clientConn")
		// Confirm file is not on disk
		cacheFile, _ := CachePathForOrigin(tmp, url.URL{Scheme: "http", Host: originURL.Host, Path: "/nostore"})
		_, err = os.Stat(cacheFile)
		assert.True(t, os.IsNotExist(err), "cache file for /nostore should not exist, but got err=%v", err)
	})

	t.Run("no-cache bypass", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/nocache", nil)
		require.NoError(t, err, "new request")
		req.Host = originURL.Host
		clientConn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err, "dial")
		require.NoError(t, req.Write(clientConn), "write req")
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
		require.NoError(t, err, "read resp")
		assert.Equal(t, "BYPASS", resp.Header.Get("X-Cache"), "want BYPASS")
		require.NoError(t, resp.Body.Close(), "close body")
		require.NoError(t, clientConn.Close(), "close clientConn")
		// Confirm file is not on disk
		cacheFile, _ := CachePathForOrigin(tmp, url.URL{Scheme: "http", Host: originURL.Host, Path: "/nocache"})
		_, err = os.Stat(cacheFile)
		assert.True(t, os.IsNotExist(err), "cache file for /nocache should not exist, but got err=%v", err)
	})

	t.Run("origin error no cache", func(t *testing.T) {
		// Ensure no cache file exists
		cacheFile, metaFile := CachePathForOrigin(tmp, url.URL{Scheme: "http", Host: originURL.Host, Path: "/error"})
		_ = os.Remove(cacheFile)
		_ = os.Remove(metaFile)
		req, err := http.NewRequest("GET", "/error", nil)
		require.NoError(t, err, "new request")
		req.Host = originURL.Host
		clientConn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err, "dial")
		require.NoError(t, req.Write(clientConn), "write req")
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
		require.NoError(t, err, "read resp")
		assert.Equal(t, 502, resp.StatusCode, "want 502 for origin error")
		require.NoError(t, resp.Body.Close(), "close body")
		require.NoError(t, clientConn.Close(), "close clientConn")
	})
	t.Run("origin error fallback to stale", func(t *testing.T) {
		// Write a stale cache file
		cacheFile, metaFile := CachePathForOrigin(tmp, url.URL{Scheme: "http", Host: originURL.Host, Path: "/error"})
		err := os.WriteFile(cacheFile, []byte("stale-data"), 0644)
		require.NoError(t, err, "write stale cache file")
		err = cache.WriteMeta(metaFile, cache.Meta{ExpiresAt: time.Now().Add(-time.Hour)})
		require.NoError(t, err, "write stale meta file")
		req, err := http.NewRequest("GET", "/error", nil)
		require.NoError(t, err, "new request")
		req.Host = originURL.Host
		clientConn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err, "dial")
		require.NoError(t, req.Write(clientConn), "write req")
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
		require.NoError(t, err, "read resp")
		assert.Equal(t, 200, resp.StatusCode, "want 200 for stale fallback")
		require.NoError(t, resp.Body.Close(), "close body")
		require.NoError(t, clientConn.Close(), "close clientConn")
	})

	t.Run("not modified no cache", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/notmod", nil)
		require.NoError(t, err, "new request")
		req.Host = originURL.Host
		clientConn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err, "dial")
		require.NoError(t, req.Write(clientConn), "write req")
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
		require.NoError(t, err, "read resp")
		assert.Equal(t, 500, resp.StatusCode, "want 500 for notmod no cache")
		require.NoError(t, resp.Body.Close(), "close body")
		require.NoError(t, clientConn.Close(), "close clientConn")
	})

	t.Run("non-200 no cache", func(t *testing.T) {
		// Ensure no cache file exists before test
		cacheFile, metafile := CachePathForOrigin(tmp, url.URL{Scheme: "http", Host: originURL.Host, Path: "/bad"})
		_ = os.Remove(cacheFile)
		_ = os.Remove(metafile)

		req, err := http.NewRequest("GET", "/bad", nil)
		require.NoError(t, err, "new request")
		req.Host = originURL.Host
		clientConn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err, "dial")
		require.NoError(t, req.Write(clientConn), "write req")
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
		require.NoError(t, err, "read resp")
		assert.False(t, resp.StatusCode == 200 || resp.StatusCode < 400, "want error for non-200 no cache, got %d", resp.StatusCode)
		require.NoError(t, resp.Body.Close(), "close body")
		require.NoError(t, clientConn.Close(), "close clientConn")
		// Confirm file is not on disk
		cacheFile, _ = CachePathForOrigin(tmp, url.URL{Scheme: "http", Host: originURL.Host, Path: "/bad"})
		_, err = os.Stat(cacheFile)
		assert.True(t, os.IsNotExist(err), "cache file for /bad should not exist, but got err=%v", err)
	})

	t.Run("non-200 fallback to stale", func(t *testing.T) {
		cacheFile, metaFile := CachePathForOrigin(tmp, url.URL{Scheme: "http", Host: originURL.Host, Path: "/bad"})
		err := os.WriteFile(cacheFile, []byte("stale-bad"), 0644)
		require.NoError(t, err, "write stale cache file")
		err = cache.WriteMeta(metaFile, cache.Meta{ExpiresAt: time.Now().Add(-time.Hour)})
		require.NoError(t, err, "write stale meta file")
		req, err := http.NewRequest("GET", "/bad", nil)
		require.NoError(t, err, "new request")
		req.Host = originURL.Host
		clientConn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err, "dial")
		require.NoError(t, req.Write(clientConn), "write req")
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
		require.NoError(t, err, "read resp")
		assert.Equal(t, 200, resp.StatusCode, "want 200 for stale fallback")
		require.NoError(t, resp.Body.Close(), "close body")
		require.NoError(t, clientConn.Close(), "close clientConn")
	})

	t.Run("HEAD request", func(t *testing.T) {
		req, err := http.NewRequest("HEAD", "/fresh", nil)
		require.NoError(t, err, "new request")
		req.Host = originURL.Host
		clientConn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err, "dial")
		require.NoError(t, req.Write(clientConn), "write req")
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
		require.NoError(t, err, "read resp")
		assert.Equal(t, 200, resp.StatusCode, "want 200 for HEAD")
		require.NoError(t, resp.Body.Close(), "close body")
		require.NoError(t, clientConn.Close(), "close clientConn")
	})
}
