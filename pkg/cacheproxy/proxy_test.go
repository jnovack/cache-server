package cacheproxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	cachepkg "github.com/jnovack/cache-server/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type dummyConn struct {
	bytes.Buffer
	closed bool
}

func (d *dummyConn) Read(b []byte) (int, error)         { return d.Buffer.Read(b) }
func (d *dummyConn) Write(b []byte) (int, error)        { return d.Buffer.Write(b) }
func (d *dummyConn) Close() error                       { d.closed = true; return nil }
func (d *dummyConn) LocalAddr() net.Addr                { return nil }
func (d *dummyConn) RemoteAddr() net.Addr               { return nil }
func (d *dummyConn) SetDeadline(t time.Time) error      { return nil }
func (d *dummyConn) SetReadDeadline(t time.Time) error  { return nil }
func (d *dummyConn) SetWriteDeadline(t time.Time) error { return nil }

func TestFileMutex(t *testing.T) {
	key := "testkey"
	m1 := fileMutex(key)
	m2 := fileMutex(key)
	if m1 != m2 {
		t.Error("fileMutex should return the same mutex for the same key")
	}
	var wg sync.WaitGroup
	locked := false
	wg.Add(1)
	go func() {
		m1.Lock()
		locked = true
		wg.Done()
		m1.Unlock()
	}()
	wg.Wait()
	if !locked {
		t.Error("mutex should have locked in goroutine")
	}
}

func TestCachePathForOrigin(t *testing.T) {
	u, _ := url.Parse("https://example.com/foo/bar")
	cacheDir := "/tmp/cache"
	file, meta := CachePathForOrigin(cacheDir, *u)
	if !strings.HasPrefix(file, cacheDir) || !strings.HasSuffix(meta, ".meta.json") {
		t.Errorf("unexpected cache paths: %s, %s", file, meta)
	}
	if file != "/tmp/cache/example.com/foo/bar" {
		t.Errorf("unexpected cache paths: %s, %s", file, meta)
	}
	if meta != "/tmp/cache/example.com/foo/.bar.meta.json" {
		t.Errorf("unexpected cache paths: %s, %s", file, meta)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dst := "test_atomic.txt"
	defer os.Remove(dst)
	defer os.Remove(dst + ".tmp")
	data := "hello world"
	err := WriteFileAtomic(dst, strings.NewReader(data))
	if err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}
	b, _ := os.ReadFile(dst)
	if string(b) != data {
		t.Errorf("file contents mismatch: got %q", string(b))
	}
}

func newCtx() context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, ConnectionIDKey{}, uuid.New())
	ctx = context.WithValue(ctx, RequestIDKey{}, uuid.New())
	return ctx
}

func TestFetchOrigin(t *testing.T) {
	tests := []struct {
		name         string
		clientReq    *http.Request
		prevMeta     cachepkg.Meta
		isTLS        bool
		wantScheme   string
		wantCond     bool
		wantHeaders  map[string]string
		wantContains []string
	}{
		{
			name: "basic GET without conditionals",
			clientReq: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "https://example.org/foo?bar=baz", nil)
				req.Header.Set("Origin", "https://example.org")
				req.Header.Set("Authorization", "Bearer 123")
				req.Header.Set("Accept-Encoding", "deflate") // should be stripped
				return req
			}(),
			prevMeta:   cachepkg.Meta{},
			isTLS:      true,
			wantScheme: "https",
			wantCond:   false,
			wantHeaders: map[string]string{
				"Origin":        "https://example.org",
				"Authorization": "Bearer 123",
			},
		},
		{
			name: "with conditional headers",
			clientReq: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "https://example.org/cond", nil)
				return req
			}(),
			prevMeta: cachepkg.Meta{
				ETag:         `"abc123"`,
				LastModified: time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat),
			},
			isTLS:      true,
			wantScheme: "https",
			wantCond:   true,
			wantHeaders: map[string]string{
				"If-None-Match":     `"abc123"`,
				"If-Modified-Since": "", // we’ll check Contains instead, since timestamp varies
			},
		},
		{
			name: "with cookies",
			clientReq: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "https://example.org/cookie", nil)
				req.Header.Set("Cookie", "session=xyz; logged_in=true")
				return req
			}(),
			prevMeta:   cachepkg.Meta{},
			isTLS:      true,
			wantScheme: "https",
			wantCond:   false,
			wantHeaders: map[string]string{
				"Cookie": "session=xyz; logged_in=true",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedReq *http.Request

			// Fake origin server that captures the request
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedReq = r
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))
			defer origin.Close()

			// Adjust host/URL so proxy will hit httptest.Server
			u, _ := url.Parse(origin.URL)
			tt.clientReq.Host = u.Host
			tt.clientReq.URL.Host = u.Host
			tt.clientReq.URL.Scheme = u.Scheme
			tt.clientReq.URL.Path = path.Clean(tt.clientReq.URL.Path)

			ctx := newCtx()
			resp, didCond, err := FetchOrigin(ctx, tt.clientReq, tt.prevMeta, origin.Client(), tt.isTLS, &tt.prevMeta)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Response is from fake server
			body, _ := io.ReadAll(resp.Body)
			assert.Contains(t, string(body), `"ok":true`)

			// DidCond matches expected
			assert.Equal(t, tt.wantCond, didCond)

			// Scheme correctness
			if tt.wantScheme == "https" {
				assert.True(t, strings.HasPrefix(resp.Request.URL.String(), "https://"))
			} else {
				assert.True(t, strings.HasPrefix(resp.Request.URL.String(), "http://"))
			}

			// Check headers that should be present
			for k, v := range tt.wantHeaders {
				if v == "" {
					assert.NotEmpty(t, capturedReq.Header.Get(k), "expected header %s to be set", k)
				} else {
					assert.Equal(t, v, capturedReq.Header.Get(k), "header mismatch for %s", k)
				}
			}

			// Ensure Accept-Encoding was stripped
			assert.Empty(t, capturedReq.Header.Get("Accept-Encoding"))
		})
	}
}

func TestProxyCopy(t *testing.T) {
	a, b := net.Pipe()
	go func() { a.Write([]byte("foo")); a.Close() }()
	buf := make([]byte, 3)
	go proxyCopy(a, b)
	b.Read(buf)
	if string(buf) != "foo" {
		t.Errorf("proxyCopy did not copy data: got %q", string(buf))
	}
}

func TestSendCachedOnConn(t *testing.T) {
	// Test all combinations of meta fields, headOnly, and file presence
	cases := []struct {
		status   int
		meta     cachepkg.Meta
		outcome  string
		headOnly bool
		fileData string
		expect   []string
	}{
		{
			status: 200,
			meta: cachepkg.Meta{
				ContentType:  "text/plain",
				ETag:         "abc",
				LastModified: "yesterday",
				NoStore:      false,
				NoCache:      false,
				ExpiresAt:    time.Now().Add(1 * time.Hour),
			},
			outcome:  "HIT",
			headOnly: false,
			fileData: "cached data",
			expect:   []string{"HTTP/1.1 200 OK", "Content-Type: text/plain", "ETag: abc", "Last-Modified: yesterday", "Cache-Control: max-age=", "Expires: ", "Content-Length: 11", "X-Cache: HIT", "Connection: close", "cached data"},
		},
		{
			status: 304,
			meta: cachepkg.Meta{
				ContentType:  "",
				ETag:         "etag2",
				LastModified: "",
				NoStore:      true,
			},
			outcome:  "STALE",
			headOnly: true,
			fileData: "should not appear",
			expect:   []string{"HTTP/1.1 304 Not Modified", "ETag: etag2", "Cache-Control: no-store", "X-Cache: STALE", "Connection: close"},
		},
		{
			status: 200,
			meta: cachepkg.Meta{
				ContentType:  "application/json",
				ETag:         "",
				LastModified: "",
				NoCache:      true,
			},
			outcome:  "MISS",
			headOnly: false,
			fileData: "jsondata",
			expect:   []string{"HTTP/1.1 200 OK", "Content-Type: application/json", "Cache-Control: no-cache", "X-Cache: MISS", "Connection: close", "jsondata"},
		},
		{
			status:   200,
			meta:     cachepkg.Meta{},
			outcome:  "MISS",
			headOnly: false,
			fileData: "empty",
			expect:   []string{"HTTP/1.1 200 OK", "X-Cache: MISS", "Connection: close", "empty"},
		},
	}
	for i, c := range cases {
		ctx := context.WithValue(
			context.WithValue(context.Background(),
				ConnectionIDKey{}, uuid.New()),
			RequestIDKey{}, uuid.New(),
		)
		conn := &dummyConn{}
		var fi os.FileInfo
		var fname string
		if c.fileData != "" {
			f, _ := os.CreateTemp("", "testcache*")
			fname = f.Name()
			f.WriteString(c.fileData)
			f.Close()
			fi, _ = os.Stat(fname)
			defer os.Remove(fname)
		}
		sendCachedOnConn(ctx, conn, c.status, c.meta, c.outcome, c.headOnly, fname, fi)
		out := conn.String()
		for _, exp := range c.expect {
			if !strings.Contains(out, exp) {
				t.Errorf("case %d: expected %q in output, got: %s", i, exp, out)
			}
		}
		if c.headOnly && c.fileData != "" && strings.Contains(out, c.fileData) {
			t.Errorf("case %d: headOnly should not include file data", i)
		}
	}
}

func TestSendError(t *testing.T) {
	conn := &dummyConn{}
	sendError(conn, 404)
	out := conn.String()
	if !strings.Contains(out, "404 Not Found") {
		t.Errorf("sendError output incorrect: %s", out)
	}
	if !strings.Contains(out, "Content-Length: 9") { // len("Not Found") == 9
		t.Errorf("sendError missing or incorrect Content-Length: %s", out)
	}
}

func TestSendCustomError(t *testing.T) {
	conn := &dummyConn{}
	sendCustomError(conn, 418, "I'm a teapot")
	out := conn.String()
	if !strings.Contains(out, "418 I'm a teapot") || !strings.Contains(out, "I'm a teapot") {
		t.Errorf("sendCustomError output incorrect: %s", out)
	}
	if !strings.Contains(out, "Content-Length: 12") { // len("I'm a teapot") == 12
		t.Errorf("sendCustomError missing or incorrect Content-Length: %s", out)
	}
}
