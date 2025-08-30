package cacheproxy

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	cachepkg "github.com/jnovack/cache-server/pkg/cache"
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

func TestFetchOrigin(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "etag")
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()
	ctx := context.WithValue(
		context.WithValue(context.Background(),
			ConnectionIDKey{}, uuid.New()),
		RequestIDKey{}, uuid.New(),
	)
	meta := cachepkg.Meta{ETag: "etag", LastModified: "Mon, 02 Jan 2006 15:04:05 GMT"}
	resp, didCond, err := FetchOrigin(ctx, ts.URL, meta, nil)
	if err != nil || resp == nil {
		t.Fatalf("FetchOrigin failed: %v", err)
	}
	if !didCond {
		t.Error("FetchOrigin should set conditional headers if meta present")
	}
	resp.Body.Close()
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
