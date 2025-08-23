package cacheproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	cachepkg "github.com/jnovack/cache-server/pkg/cache"
)

// file locks to avoid concurrent writes to same cache path.
var locks sync.Map // map[string]*sync.Mutex

// HandleHTTPOverConn reads a single HTTP request from br (wrapping conn), processes
// caching logic and writes back the HTTP response over conn. This is used by the socks code.
func HandleHTTPOverConn(conn net.Conn, br *bufio.Reader, cfg Config) {
	start := time.Now()

	if cfg.Metrics != nil {
		cfg.Metrics.IncTotalRequests()
	}

	// HTTP specific checks
	req, err := http.ReadRequest(br)
	if err != nil {
		if cfg.Metrics != nil {
			cfg.Metrics.IncOriginErrors()
		}
		log.Debug().Err(err).Msg("failed to read HTTP request from connection")
		fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Request")
		return
	}
	defer req.Body.Close()

	// Only GET and HEAD are cacheable; others are proxied (simple tunnel)
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		target := req.Host
		if !strings.Contains(target, ":") {
			target = net.JoinHostPort(target, "80")
		}
		server, err := net.DialTimeout("tcp", target, 15*time.Second)
		if err != nil {
			if cfg.Metrics != nil {
				cfg.Metrics.IncOriginErrors()
			}
			log.Error().Err(err).Str("target", target).Msg("failed to dial origin for non-GET/HEAD")
			fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Gateway")
			return
		}
		defer server.Close()
		_ = req.Write(server)
		_ = proxyCopy(conn, server)
		return
	}

	// Build origin URL
	originURL := &url.URL{
		Scheme: "http",
		Host:   req.Host,
	}
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	parsed, _ := url.Parse(uri)
	originURL.Path = path.Clean(parsed.Path)
	originURL.RawQuery = parsed.RawQuery
	rawURL := originURL.String()

	cacheFile, metaFile := CachePathForOrigin(cfg.CacheDir, originURL.Host, originURL.Path)
	mtx := fileMutex(cacheFile)
	mtx.Lock()
	defer mtx.Unlock()

	meta := cachepkg.ReadMeta(metaFile)
	fi, _ := os.Stat(cacheFile)

	// Serve fresh cache
	if fi != nil && !meta.NoCache && cachepkg.IsFresh(meta) {
		sendCachedOnConn(conn, http.StatusOK, meta, "HIT", req.Method == http.MethodHead, cacheFile, fi)
		if cfg.Metrics != nil {
			cfg.Metrics.IncHit()
			cfg.Metrics.ObserveDuration("HIT", time.Since(start).Seconds())
		}
		NotifyObserver(cfg.RequestObserver, RequestRecord{
			Time:        time.Now(),
			URL:         rawURL,
			Method:      req.Method,
			Host:        originURL.Host,
			Path:        originURL.Path,
			Outcome:     "HIT",
			IsTLS:       false,
			LatencySecs: time.Since(start).Seconds(),
			Size:        fi.Size(),
			Status:      http.StatusOK,
		})
		log.Info().Str("url", rawURL).Str("scheme", originURL.Scheme).Str("outcome", "HIT").Dur("latency", time.Since(start)).Str("scheme", originURL.Scheme).Msg("served")
		return
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, didCond, err := FetchOrigin(rawURL, meta, client)
	if err != nil {
		if fi != nil {
			sendCachedOnConn(conn, http.StatusOK, meta, "STALE", req.Method == http.MethodHead, cacheFile, fi)
			if cfg.Metrics != nil {
				cfg.Metrics.IncStale()
				cfg.Metrics.IncOriginErrors()
				cfg.Metrics.ObserveDuration("STALE", time.Since(start).Seconds())
			}
			NotifyObserver(cfg.RequestObserver, RequestRecord{
				Time:        time.Now(),
				URL:         rawURL,
				Method:      req.Method,
				Host:        originURL.Host,
				Path:        originURL.Path,
				Outcome:     "STALE",
				IsTLS:       false,
				LatencySecs: time.Since(start).Seconds(),
				Size: func() int64 {
					if fi != nil {
						return fi.Size()
					}
					return 0
				}(),
				Status: http.StatusOK,
			})
			log.Info().Str("url", rawURL).Str("scheme", originURL.Scheme).Str("outcome", "STALE").Dur("latency", time.Since(start)).Msg("served stale")
			return
		}
		if cfg.Metrics != nil {
			cfg.Metrics.IncOriginErrors()
		}
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Gateway")
		NotifyObserver(cfg.RequestObserver, RequestRecord{
			Time:        time.Now(),
			URL:         rawURL,
			Method:      req.Method,
			Host:        originURL.Host,
			Path:        originURL.Path,
			Outcome:     "ORIGIN-ERROR",
			IsTLS:       false,
			LatencySecs: time.Since(start).Seconds(),
			Size:        0,
			Status:      http.StatusBadGateway,
		})
		log.Error().Err(err).Str("url", rawURL).Str("scheme", originURL.Scheme).Msg("origin fetch failed")
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		newMeta := cachepkg.MetaFromHeaders(resp.Header, meta)
		_ = cachepkg.WriteMeta(metaFile, newMeta)
		if fi != nil {
			sendCachedOnConn(conn, http.StatusOK, newMeta, "REVALIDATED", req.Method == http.MethodHead, cacheFile, fi)
			if cfg.Metrics != nil {
				cfg.Metrics.IncRevalidated()
				cfg.Metrics.ObserveDuration("REVALIDATED", time.Since(start).Seconds())
			}
			NotifyObserver(cfg.RequestObserver, RequestRecord{
				Time:        time.Now(),
				URL:         rawURL,
				Method:      req.Method,
				Host:        originURL.Host,
				Path:        originURL.Path,
				Outcome:     "REVALIDATED",
				IsTLS:       false,
				LatencySecs: time.Since(start).Seconds(),
				Size: func() int64 {
					if fi != nil {
						return fi.Size()
					}
					return 0
				}(),
				Status:      http.StatusOK,
				Conditional: true,
			})
			log.Info().Str("url", rawURL).Str("scheme", originURL.Scheme).Str("outcome", "REVALIDATED").Dur("latency", time.Since(start)).Msg("served")
			return
		}
		if cfg.Metrics != nil {
			cfg.Metrics.IncOriginErrors()
		}
		fmt.Fprintf(conn, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 21\r\nConnection: close\r\n\r\nNot Modified without cache")
		NotifyObserver(cfg.RequestObserver, RequestRecord{
			Time:        time.Now(),
			URL:         rawURL,
			Method:      req.Method,
			Host:        originURL.Host,
			Path:        originURL.Path,
			Outcome:     "REVALIDATED_NO_CACHE",
			IsTLS:       false,
			LatencySecs: time.Since(start).Seconds(),
			Size:        0,
			Status:      http.StatusInternalServerError,
		})
		// log.Warn().Str("url", rawURL).Str("scheme", originURL.Scheme).Dur("latency", time.Since(start)).Msg("not modified but no cached file")
		return
	case http.StatusOK:
		newMeta := cachepkg.MetaFromHeaders(resp.Header, meta)
		if newMeta.NoStore || (!cfg.Private && req.Header.Get("Authorization") != "") || (!cfg.Private && newMeta.NoCache) {
			if newMeta.NoStore && cfg.Metrics != nil {
				cfg.Metrics.IncNoStore()
			}
			if newMeta.NoCache && cfg.Metrics != nil {
				cfg.Metrics.IncNoCache()
			}
			fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
			for k, vv := range resp.Header {
				for _, v := range vv {
					fmt.Fprintf(conn, "%s: %s\r\n", k, v)
				}
			}
			fmt.Fprintf(conn, "X-Cache: BYPASS\r\nConnection: close\r\n\r\n")
			var copied int64
			if req.Method != http.MethodHead {
				n, _ := io.Copy(conn, resp.Body)
				copied = n
			}
			if cfg.Metrics != nil {
				cfg.Metrics.IncBypass()
				cfg.Metrics.ObserveDuration("BYPASS", time.Since(start).Seconds())
			}
			NotifyObserver(cfg.RequestObserver, RequestRecord{
				Time:        time.Now(),
				URL:         rawURL,
				Method:      req.Method,
				Host:        originURL.Host,
				Path:        originURL.Path,
				Outcome:     "BYPASS",
				IsTLS:       false,
				LatencySecs: time.Since(start).Seconds(),
				Size:        copied,
				Status:      resp.StatusCode,
			})
			log.Info().Str("url", rawURL).Str("scheme", originURL.Scheme).Str("outcome", "BYPASS").Dur("latency", time.Since(start)).Msg("streamed (conn bypass)")
			return
		}

		if err := WriteFileAtomic(cacheFile, resp.Body); err != nil {
			fmt.Fprintf(conn, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 13\r\nConnection: close\r\n\r\nServer Error")
			NotifyObserver(cfg.RequestObserver, RequestRecord{
				Time:        time.Now(),
				URL:         rawURL,
				Method:      req.Method,
				Host:        originURL.Host,
				Path:        originURL.Path,
				Outcome:     "WRITE_ERROR",
				IsTLS:       false,
				LatencySecs: time.Since(start).Seconds(),
				Size:        0,
				Status:      http.StatusInternalServerError,
			})
			log.Error().Err(err).Str("file", cacheFile).Msg("failed to write cache file")
			return
		}
		_ = cachepkg.WriteMeta(metaFile, newMeta)
		fi2, _ := os.Stat(cacheFile)
		outcome := "MISS"
		sendCachedOnConn(conn, http.StatusOK, newMeta, outcome, req.Method == http.MethodHead, cacheFile, fi2)
		if cfg.Metrics != nil {
			if outcome == "MISS" {
				cfg.Metrics.IncMiss()
			} else {
				cfg.Metrics.IncRevalidated()
			}
			cfg.Metrics.ObserveDuration(outcome, time.Since(start).Seconds())
		}
		NotifyObserver(cfg.RequestObserver, RequestRecord{
			Time:        time.Now(),
			URL:         rawURL,
			Method:      req.Method,
			Host:        originURL.Host,
			Path:        originURL.Path,
			Outcome:     outcome,
			IsTLS:       false,
			LatencySecs: time.Since(start).Seconds(),
			Size: func() int64 {
				if fi2 != nil {
					return fi2.Size()
				}
				return 0
			}(),
			Status:      http.StatusOK,
			Conditional: didCond,
		})
		log.Info().Str("url", rawURL).Str("scheme", originURL.Scheme).Str("outcome", outcome).Dur("latency", time.Since(start)).Msg("served")
		return
	default:
		if fi != nil {
			sendCachedOnConn(conn, http.StatusOK, meta, "STALE", req.Method == http.MethodHead, cacheFile, fi)
			if cfg.Metrics != nil {
				cfg.Metrics.IncStale()
				cfg.Metrics.ObserveDuration("STALE", time.Since(start).Seconds())
			}
			NotifyObserver(cfg.RequestObserver, RequestRecord{
				Time:        time.Now(),
				URL:         rawURL,
				Method:      req.Method,
				Host:        originURL.Host,
				Path:        originURL.Path,
				Outcome:     "STALE",
				IsTLS:       false,
				LatencySecs: time.Since(start).Seconds(),
				Size: func() int64 {
					if fi != nil {
						return fi.Size()
					}
					return 0
				}(),
				Status: http.StatusOK,
			})
			log.Info().Str("url", rawURL).Str("scheme", originURL.Scheme).Str("outcome", "STALE").Dur("latency", time.Since(start)).Msg("served stale (conn non-200)")
			return
		}
		fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
		for k, vv := range resp.Header {
			for _, v := range vv {
				fmt.Fprintf(conn, "%s: %s\r\n", k, v)
			}
		}
		fmt.Fprintf(conn, "\r\n")
		var copied int64
		if req.Method != http.MethodHead {
			n, _ := io.Copy(conn, resp.Body)
			copied = n
		}
		if cfg.Metrics != nil {
			cfg.Metrics.ObserveDuration("ORIGIN-"+strconv.Itoa(resp.StatusCode), time.Since(start).Seconds())
		}
		NotifyObserver(cfg.RequestObserver, RequestRecord{
			Time:        time.Now(),
			URL:         rawURL,
			Method:      req.Method,
			Host:        originURL.Host,
			Path:        originURL.Path,
			Outcome:     "ORIGIN-" + strconv.Itoa(resp.StatusCode),
			IsTLS:       false,
			LatencySecs: time.Since(start).Seconds(),
			Size:        copied,
			Status:      resp.StatusCode,
		})
		log.Info().Str("url", rawURL).Str("scheme", originURL.Scheme).Str("outcome", "ORIGIN-"+strconv.Itoa(resp.StatusCode)).Dur("latency", time.Since(start)).Msg("proxied origin response")
		return
	}
}
