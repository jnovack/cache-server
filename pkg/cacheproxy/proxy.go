// pkg/cacheproxy/proxy.go
package cacheproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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
func CachePathForOrigin(cacheDir string, originURL url.URL) (string, string) {
	clean := path.Clean("/" + strings.TrimPrefix(originURL.Path, "/"))
	rel := filepath.Join(filepath.FromSlash(originURL.Host), filepath.FromSlash(clean))
	fp := filepath.Join(cacheDir, rel)
	log.Trace().Str("origin", originURL.String()).Str("file_path", fp).Str("function", "CachePathForOrigin").Msg("CachePathForOrigin()")
	// return fp, fp + ".meta.json"

	dir := filepath.Dir(fp)
	base := filepath.Base(fp)
	meta := filepath.Join(dir, "."+base+".meta.json")
	// return meta filename with a period in front of it.
	return fp, meta
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

// FetchOrigin forwards the client request to the origin server.
// It clones all headers from the original client request, while adding
// conditional caching headers (If-None-Match / If-Modified-Since).
// It also extracts any Set-Cookie headers from the origin response into metaOut.SetCookies.
// Returns (resp, didConditional, err). Caller must close resp.
func FetchOrigin(
	ctx context.Context,
	clientReq *http.Request,
	prev cachepkg.Meta,
	client *http.Client,
	isTLS bool,
	metaOut *cachepkg.Meta,
) (*http.Response, bool, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	uri := clientReq.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}

	scheme := "http"
	if isTLS {
		scheme = "https"
	}

	parsed, _ := url.ParseRequestURI(uri)
	pathPart := "/"
	rawQuery := ""
	if parsed != nil {
		pathPart = path.Clean(parsed.Path)
		rawQuery = parsed.RawQuery
	}

	originURL := &url.URL{
		Scheme:   scheme,
		Host:     clientReq.Host,
		Path:     pathPart,
		RawQuery: rawQuery,
	}
	rawURL := originURL.String()

	// Create origin request with same method/body as client.
	originReq, err := http.NewRequest(clientReq.Method, rawURL, clientReq.Body)
	if err != nil {
		return nil, false, err
	}

	// Deep copy headers from client request.
	originReq.Header = make(http.Header, len(clientReq.Header))
	for k, vv := range clientReq.Header {
		for _, v := range vv {
			if !strings.EqualFold(k, "Accept-Encoding") {
				originReq.Header.Add(k, v)
			}
		}
	}

	// Preserve Host explicitly (important for picky origins).
	originReq.Host = clientReq.Host

	// Set/override UA for the proxy (optional).
	// originReq.Header.Set("User-Agent", "cache-server/1.0")

	// Apply conditional headers if present.
	didCond := false
	if prev.ETag != "" {
		originReq.Header.Set("If-None-Match", prev.ETag)
		didCond = true
	}
	if prev.LastModified != "" {
		originReq.Header.Set("If-Modified-Since", prev.LastModified)
		didCond = true
	}

	// Send to origin.
	resp, err := client.Do(originReq)
	if err != nil {
		return nil, didCond, err
	}

	// Capture Set-Cookie from the origin (ephemeral; not cached on disk).
	if metaOut != nil {
		metaOut.SetCookies = metaOut.SetCookies[:0] // reset if reused
		for _, sc := range resp.Header.Values("Set-Cookie") {
			metaOut.SetCookies = append(metaOut.SetCookies, sc)
		}
	}

	log.Ctx(ctx).Debug().
		Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
		Str("request_id", ctx.Value(RequestIDKey{}).(uuid.UUID).String()).
		Str("url", rawURL).
		Bool("conditional", didCond).
		Int64("length", resp.ContentLength).
		Str("function", "FetchOrigin").
		Msg("FetchOrigin()")

	return resp, didCond, nil
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
func sendCachedOnConn(
	ctx context.Context,
	conn net.Conn,
	status int,
	meta cachepkg.Meta,
	outcome string,
	req http.Request,
	filePath string,
) {
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

	// Inject CORS into every proxied response
	origin := req.Header.Get("Origin")
	if origin != "" {
		fmt.Fprintf(conn, "Access-Control-Allow-Origin: %s\r\n", origin)
		fmt.Fprint(conn, "Vary: Origin\r\n")
	} else {
		fmt.Fprint(conn, "Access-Control-Allow-Origin: *\r\n")
	}
	fmt.Fprint(conn, "Access-Control-Allow-Methods: GET, POST, HEAD, OPTIONS\r\n")
	fmt.Fprint(conn, "Access-Control-Allow-Credentials: true\r\n")

	if rh := req.Header.Get("Access-Control-Request-Headers"); rh != "" {
		fmt.Fprintf(conn, "Access-Control-Allow-Headers: %s\r\n", rh)
	} else {
		fmt.Fprint(conn, "Access-Control-Allow-Headers: Content-Type, Authorization\r\n")
	}

	// Forward any Set-Cookie headers captured from a live origin response.
	// (These are ephemeral: stored in meta only for this response; never written to cache.)
	for _, setCookie := range meta.SetCookies {
		fmt.Fprintf(conn, "Set-Cookie: %s\r\n", setCookie)
	}

	// File size for Content-Length
	fi, _ := os.Stat(filePath)
	if fi != nil {
		fmt.Fprintf(conn, "Content-Length: %d\r\n", fi.Size())
	}

	fmt.Fprintf(conn, "X-Cache: %s\r\n", outcome)
	fmt.Fprint(conn, "Connection: close\r\n\r\n")

	// End response if head only
	if req.Method == http.MethodHead {
		return
	}

	f, err := os.Open(filePath)
	if err != nil {
		log.Ctx(ctx).
			Error().
			Str("function", "sendCachedOnConn").
			Str("file", filePath).
			Err(err).
			Msg("open cached file for serve failed")
		return
	}
	defer f.Close()

	log.Ctx(ctx).Trace().
		Str("function", "sendCachedOnConn").
		Str("file", filePath).
		Int("status", status).
		Str("outcome", outcome).
		Int64("size", fi.Size()).
		Msg("sending cached response")

	_, _ = io.Copy(conn, f)
}

// sendError writes an HTTP error response over conn.
func sendError(conn net.Conn, status int) {
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(http.StatusText(status)), http.StatusText(status))
	return
}

// sendError writes an HTTP error response over conn.
func sendCustomError(conn net.Conn, status int, message string) {
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(message), message)
	return
}
