// pkg/cacheproxy/proxy.go
package cacheproxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	cachepkg "github.com/jnovack/cache-server/pkg/cache"
)

// file-level locks to avoid concurrent writes to same cache path.
var fileLocks sync.Map // map[string]*sync.Mutex

func fileMutex(key string) *sync.Mutex {
	actual, _ := fileLocks.LoadOrStore(key, &sync.Mutex{})
	return actual.(*sync.Mutex)
}

// CachePathForOrigin maps an origin host + path to a file path on disk.
func CachePathForOrigin(cacheDir, host, p string) (string, string) {
	clean := path.Clean("/" + strings.TrimPrefix(p, "/"))
	rel := filepath.Join(filepath.FromSlash(host), filepath.FromSlash(clean))
	fp := filepath.Join(cacheDir, rel)
	return fp, fp + ".meta.json"
}

// WriteFileAtomic writes contents from r into dst atomically.
func WriteFileAtomic(dst string, r io.Reader) error {
	tmp := dst + ".tmp"
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdirall %s: %w", dir, err)
	}
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create tmp %s: %w", tmp, err)
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("copy tmp %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close tmp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename tmp %s -> %s: %w", tmp, dst, err)
	}
	return nil
}

// FetchOrigin GETs rawURL, using prev to set If-None-Match / If-Modified-Since when available.
// Returns (resp, didConditional, err). Caller must close resp.
func FetchOrigin(rawURL string, prev cachepkg.Meta, client *http.Client) (*http.Response, bool, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "cache-server/1.0")
	didCond := false
	if prev.ETag != "" {
		req.Header.Set("If-None-Match", prev.ETag)
		didCond = true
	}
	if prev.LastModified != "" {
		req.Header.Set("If-Modified-Since", prev.LastModified)
		didCond = true
	}
	log.Debug().Str("url", rawURL).Bool("conditional", didCond).Msg("fetching origin")
	resp, err := client.Do(req)
	return resp, didCond, err
}

// helper to copy bidirectionally.
func proxyCopy(a, b net.Conn) error {
	errc := make(chan error, 2)
	go func() { _, e := io.Copy(a, b); errc <- e }()
	go func() { _, e := io.Copy(b, a); errc <- e }()
	e1 := <-errc
	_ = a.Close()
	_ = b.Close()
	e2 := <-errc
	if e1 != nil && e1 != io.EOF {
		return e1
	}
	if e2 != nil && e2 != io.EOF {
		return e2
	}
	return nil
}

// sendCachedOnConn writes an HTTP response over conn based on a cached file + meta.
func sendCachedOnConn(conn net.Conn, status int, meta cachepkg.Meta, outcome string, headOnly bool, filePath string, fi os.FileInfo) {
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	if meta.ContentType != "" {
		fmt.Fprintf(conn, "Content-Type: %s\r\n", meta.ContentType)
	}
	if meta.ETag != "" {
		fmt.Fprintf(conn, "ETag: %s\r\n", meta.ETag)
	}
	if meta.LastModified != "" {
		fmt.Fprintf(conn, "Last-Modified: %s\r\n", meta.LastModified)
	}
	if meta.NoStore {
		fmt.Fprintf(conn, "Cache-Control: no-store\r\n")
	} else if meta.NoCache {
		fmt.Fprintf(conn, "Cache-Control: no-cache\r\n")
	} else if !meta.ExpiresAt.IsZero() {
		secs := int(time.Until(meta.ExpiresAt).Seconds())
		if secs < 0 {
			secs = 0
		}
		fmt.Fprintf(conn, "Cache-Control: max-age=%d\r\n", secs)
		fmt.Fprintf(conn, "Expires: %s\r\n", meta.ExpiresAt.UTC().Format(http.TimeFormat))
	}
	if fi != nil {
		fmt.Fprintf(conn, "Content-Length: %d\r\n", fi.Size())
	}
	fmt.Fprintf(conn, "X-Cache: %s\r\n", outcome)
	fmt.Fprintf(conn, "Connection: close\r\n\r\n")
	if headOnly {
		return
	}
	f, err := os.Open(filePath)
	if err != nil {
		log.Error().Err(err).Str("file", filePath).Msg("open cached file for serve failed (conn)")
		return
	}
	defer f.Close()
	_, _ = io.Copy(conn, f)
}

// sendCachedResponse writes cached response to http.ResponseWriter.
func sendCachedResponse(w http.ResponseWriter, status int, filePath string, meta cachepkg.Meta, outcome string, headOnly bool, fi os.FileInfo) {
	if meta.ContentType != "" {
		w.Header().Set("Content-Type", meta.ContentType)
	}
	if meta.ETag != "" {
		w.Header().Set("ETag", meta.ETag)
	}
	if meta.LastModified != "" {
		w.Header().Set("Last-Modified", meta.LastModified)
	}
	if meta.NoStore {
		w.Header().Set("Cache-Control", "no-store")
	} else if meta.NoCache {
		w.Header().Set("Cache-Control", "no-cache")
	} else if !meta.ExpiresAt.IsZero() {
		secs := int(time.Until(meta.ExpiresAt).Seconds())
		if secs < 0 {
			secs = 0
		}
		w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(secs))
		w.Header().Set("Expires", meta.ExpiresAt.UTC().Format(http.TimeFormat))
	}
	w.Header().Set("X-Cache", outcome)
	if fi != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	}
	w.WriteHeader(status)
	if headOnly {
		return
	}
	f, err := os.Open(filePath)
	if err != nil {
		log.Error().Err(err).Str("file", filePath).Msg("open cached file for serve failed")
		return
	}
	defer f.Close()
	_, _ = io.Copy(w, f)
}
