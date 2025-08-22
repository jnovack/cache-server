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

// internal: emit a record to the observer (non-blocking)
func maybeObserve(cfg Config, rec RequestRecord) {
	if cfg.RequestObserver == nil {
		return
	}
	// copy to local var and call asynchronously to avoid blocking the request path.
	go func(r RequestRecord) {
		defer func() {
			// defensive recover in case observer panics
			_ = recover()
		}()
		cfg.RequestObserver(r)
	}(rec)
}

// file locks to avoid concurrent writes to same cache path.
var locks sync.Map // map[string]*sync.Mutex

// CacheHandler returns an http.HandlerFunc that implements GET/HEAD caching behavior.
// Requests are expected to be of the form: /<origin-host>/<rest...>
func CacheHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if cfg.Metrics != nil {
			cfg.Metrics.IncTotalRequests()
		}

		// Only GET and HEAD are cacheable
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not supported by cache", http.StatusMethodNotAllowed)
			return
		}

		trimmed := strings.TrimPrefix(r.URL.Path, "/")
		parts := strings.SplitN(trimmed, "/", 2)
		if len(parts) == 0 || parts[0] == "" {
			http.Error(w, "missing origin host in path", http.StatusBadRequest)
			return
		}
		originHost := parts[0]
		restPath := "/"
		if len(parts) == 2 {
			restPath = "/" + parts[1]
		}
		originURL := &url.URL{
			Scheme:   "https",
			Host:     originHost,
			Path:     path.Clean(restPath),
			RawQuery: r.URL.RawQuery,
		}
		rawURL := originURL.String()

		cacheFile, metaFile := CachePathForOrigin(cfg.CacheDir, originHost, restPath)
		mtx := fileMutex(cacheFile)
		mtx.Lock()
		defer mtx.Unlock()

		meta := cachepkg.ReadMeta(metaFile)
		fi, _ := os.Stat(cacheFile)

		// Serve fresh cache
		if fi != nil && !meta.NoCache && cachepkg.IsFresh(meta) {
			sendCachedResponse(w, http.StatusOK, cacheFile, meta, "HIT", r.Method == http.MethodHead, fi)
			if cfg.Metrics != nil {
				cfg.Metrics.IncHit()
				cfg.Metrics.ObserveDuration("HIT", time.Since(start).Seconds())
			}
			log.Info().Str("url", rawURL).Str("outcome", "HIT").Dur("latency", time.Since(start)).Msg("served")
			// observe
			maybeObserve(cfg, RequestRecord{
				Time:        time.Now(),
				URL:         rawURL,
				Method:      r.Method,
				Host:        originHost,
				Path:        restPath,
				Outcome:     "HIT",
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
			return
		}

		client := cfg.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: 30 * time.Second}
		}
		resp, didCond, err := FetchOrigin(rawURL, meta, client)
		if err != nil {
			if fi != nil {
				// serve stale
				sendCachedResponse(w, http.StatusOK, cacheFile, meta, "STALE", r.Method == http.MethodHead, fi)
				if cfg.Metrics != nil {
					cfg.Metrics.IncStale()
					cfg.Metrics.IncOriginErrors()
					cfg.Metrics.ObserveDuration("STALE", time.Since(start).Seconds())
				}
				log.Info().Str("url", rawURL).Str("outcome", "STALE").Dur("latency", time.Since(start)).Msg("served stale due to origin error")
				maybeObserve(cfg, RequestRecord{
					Time:        time.Now(),
					URL:         rawURL,
					Method:      r.Method,
					Host:        originHost,
					Path:        restPath,
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
				return
			}
			if cfg.Metrics != nil {
				cfg.Metrics.IncOriginErrors()
			}
			log.Error().Err(err).Str("url", rawURL).Msg("origin fetch failed")
			http.Error(w, "bad gateway", http.StatusBadGateway)
			maybeObserve(cfg, RequestRecord{
				Time:        time.Now(),
				URL:         rawURL,
				Method:      r.Method,
				Host:        originHost,
				Path:        restPath,
				Outcome:     "ORIGIN-ERROR",
				IsTLS:       false,
				LatencySecs: time.Since(start).Seconds(),
				Size:        0,
				Status:      http.StatusBadGateway,
			})
			return
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusNotModified:
			newMeta := cachepkg.MetaFromHeaders(resp.Header, meta)
			_ = cachepkg.WriteMeta(metaFile, newMeta)
			if fi != nil {
				sendCachedResponse(w, http.StatusOK, cacheFile, newMeta, "REVALIDATED", r.Method == http.MethodHead, fi)
				if cfg.Metrics != nil {
					cfg.Metrics.IncRevalidated()
					cfg.Metrics.ObserveDuration("REVALIDATED", time.Since(start).Seconds())
				}
				log.Info().Str("url", rawURL).Str("outcome", "REVALIDATED").Dur("latency", time.Since(start)).Msg("served")
				maybeObserve(cfg, RequestRecord{
					Time:        time.Now(),
					URL:         rawURL,
					Method:      r.Method,
					Host:        originHost,
					Path:        restPath,
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
				return
			}
			if cfg.Metrics != nil {
				cfg.Metrics.IncOriginErrors()
			}
			http.Error(w, "not modified but no cached file", http.StatusInternalServerError)
			maybeObserve(cfg, RequestRecord{
				Time:        time.Now(),
				URL:         rawURL,
				Method:      r.Method,
				Host:        originHost,
				Path:        restPath,
				Outcome:     "REVALIDATED_NO_CACHE",
				IsTLS:       false,
				LatencySecs: time.Since(start).Seconds(),
				Size:        0,
				Status:      http.StatusInternalServerError,
			})
			return
		case http.StatusOK:
			newMeta := cachepkg.MetaFromHeaders(resp.Header, meta)

			// bypass conditions
			if newMeta.NoStore || (!cfg.Private && r.Header.Get("Authorization") != "") || (!cfg.Private && newMeta.NoCache) {
				if newMeta.NoStore && cfg.Metrics != nil {
					cfg.Metrics.IncNoStore()
				}
				if newMeta.NoCache && cfg.Metrics != nil {
					cfg.Metrics.IncNoCache()
				}
				for k, vv := range resp.Header {
					for _, v := range vv {
						w.Header().Add(k, v)
					}
				}
				w.Header().Set("X-Cache", "BYPASS")
				w.WriteHeader(resp.StatusCode)
				var copied int64
				if r.Method != http.MethodHead {
					n, _ := io.Copy(w, resp.Body)
					copied = n
				}
				if cfg.Metrics != nil {
					cfg.Metrics.IncBypass()
					cfg.Metrics.ObserveDuration("BYPASS", time.Since(start).Seconds())
				}
				log.Info().Str("url", rawURL).Str("outcome", "BYPASS").Dur("latency", time.Since(start)).Msg("streamed (bypassed cache)")
				maybeObserve(cfg, RequestRecord{
					Time:        time.Now(),
					URL:         rawURL,
					Method:      r.Method,
					Host:        originHost,
					Path:        restPath,
					Outcome:     "BYPASS",
					IsTLS:       false,
					LatencySecs: time.Since(start).Seconds(),
					Size:        copied,
					Status:      resp.StatusCode,
					Conditional: false,
				})
				return
			}

			// write body to disk then serve
			// We need to write body to disk and then read file to serve; so copy into tmp file first.
			// To preserve the resp.Body for WriteFileAtomic, we must give it directly.
			// Use a temp buffer in filesystem via WriteFileAtomic which will read from resp.Body.
			if err := WriteFileAtomic(cacheFile, resp.Body); err != nil {
				log.Error().Err(err).Str("file", cacheFile).Msg("failed to write cache file")
				http.Error(w, "server error", http.StatusInternalServerError)
				maybeObserve(cfg, RequestRecord{
					Time:        time.Now(),
					URL:         rawURL,
					Method:      r.Method,
					Host:        originHost,
					Path:        restPath,
					Outcome:     "WRITE_ERROR",
					IsTLS:       false,
					LatencySecs: time.Since(start).Seconds(),
					Size:        0,
					Status:      http.StatusInternalServerError,
				})
				return
			}
			if err := cachepkg.WriteMeta(metaFile, newMeta); err != nil {
				log.Warn().Err(err).Str("file", metaFile).Msg("failed to write meta")
			}
			fi2, _ := os.Stat(cacheFile)
			outcome := "MISS"
			sendCachedResponse(w, http.StatusOK, cacheFile, newMeta, outcome, r.Method == http.MethodHead, fi2)
			if cfg.Metrics != nil {
				if outcome == "MISS" {
					cfg.Metrics.IncMiss()
				} else {
					cfg.Metrics.IncRevalidated()
				}
				cfg.Metrics.ObserveDuration(outcome, time.Since(start).Seconds())
			}
			log.Info().Str("url", rawURL).Str("outcome", outcome).Dur("latency", time.Since(start)).Msg("served")
			maybeObserve(cfg, RequestRecord{
				Time:        time.Now(),
				URL:         rawURL,
				Method:      r.Method,
				Host:        originHost,
				Path:        restPath,
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
			return
		default:
			// non-200 from origin
			if fi != nil {
				sendCachedResponse(w, http.StatusOK, cacheFile, meta, "STALE", r.Method == http.MethodHead, fi)
				if cfg.Metrics != nil {
					cfg.Metrics.IncStale()
					cfg.Metrics.ObserveDuration("STALE", time.Since(start).Seconds())
				}
				log.Info().Str("url", rawURL).Str("outcome", "STALE").Dur("latency", time.Since(start)).Msg("served stale due to non-200 origin")
				maybeObserve(cfg, RequestRecord{
					Time:        time.Now(),
					URL:         rawURL,
					Method:      r.Method,
					Host:        originHost,
					Path:        restPath,
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
				return
			}
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			var copied int64
			if r.Method != http.MethodHead {
				n, _ := io.Copy(w, resp.Body)
				copied = n
			}
			if cfg.Metrics != nil {
				cfg.Metrics.ObserveDuration("ORIGIN-"+strconv.Itoa(resp.StatusCode), time.Since(start).Seconds())
			}
			log.Info().Str("url", rawURL).Str("outcome", "ORIGIN-"+strconv.Itoa(resp.StatusCode)).Dur("latency", time.Since(start)).Msg("proxied origin response")
			maybeObserve(cfg, RequestRecord{
				Time:        time.Now(),
				URL:         rawURL,
				Method:      r.Method,
				Host:        originHost,
				Path:        restPath,
				Outcome:     "ORIGIN-" + strconv.Itoa(resp.StatusCode),
				IsTLS:       false,
				LatencySecs: time.Since(start).Seconds(),
				Size:        copied,
				Status:      resp.StatusCode,
			})
			return
		}
	}
}

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
		log.Info().Str("url", rawURL).Str("outcome", "HIT").Dur("latency", time.Since(start)).Msg("served (conn)")
		maybeObserve(cfg, RequestRecord{
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
			log.Info().Str("url", rawURL).Str("outcome", "STALE").Dur("latency", time.Since(start)).Msg("served stale (conn)")
			maybeObserve(cfg, RequestRecord{
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
			return
		}
		if cfg.Metrics != nil {
			cfg.Metrics.IncOriginErrors()
		}
		log.Error().Err(err).Str("url", rawURL).Msg("origin fetch failed (conn)")
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Gateway")
		maybeObserve(cfg, RequestRecord{
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
			log.Info().Str("url", rawURL).Str("outcome", "REVALIDATED").Dur("latency", time.Since(start)).Msg("served (conn)")
			maybeObserve(cfg, RequestRecord{
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
			return
		}
		if cfg.Metrics != nil {
			cfg.Metrics.IncOriginErrors()
		}
		fmt.Fprintf(conn, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 21\r\nConnection: close\r\n\r\nNot Modified without cache")
		maybeObserve(cfg, RequestRecord{
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
			log.Info().Str("url", rawURL).Str("outcome", "BYPASS").Dur("latency", time.Since(start)).Msg("streamed (conn bypass)")
			maybeObserve(cfg, RequestRecord{
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
			return
		}

		if err := WriteFileAtomic(cacheFile, resp.Body); err != nil {
			log.Error().Err(err).Str("file", cacheFile).Msg("failed to write cache file (conn)")
			fmt.Fprintf(conn, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 13\r\nConnection: close\r\n\r\nServer Error")
			maybeObserve(cfg, RequestRecord{
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
		log.Info().Str("url", rawURL).Str("outcome", outcome).Dur("latency", time.Since(start)).Msg("served (conn)")
		maybeObserve(cfg, RequestRecord{
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
		return
	default:
		if fi != nil {
			sendCachedOnConn(conn, http.StatusOK, meta, "STALE", req.Method == http.MethodHead, cacheFile, fi)
			if cfg.Metrics != nil {
				cfg.Metrics.IncStale()
				cfg.Metrics.ObserveDuration("STALE", time.Since(start).Seconds())
			}
			log.Info().Str("url", rawURL).Str("outcome", "STALE").Dur("latency", time.Since(start)).Msg("served stale (conn non-200)")
			maybeObserve(cfg, RequestRecord{
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
		log.Info().Str("url", rawURL).Str("outcome", "ORIGIN-"+strconv.Itoa(resp.StatusCode)).Dur("latency", time.Since(start)).Msg("proxied origin response (conn)")
		maybeObserve(cfg, RequestRecord{
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
		return
	}
}
