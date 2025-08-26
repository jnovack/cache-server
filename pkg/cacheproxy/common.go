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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	cachepkg "github.com/jnovack/cache-server/pkg/cache"
)

// HandleCacheRequest is the main entry for both HTTP and HTTPS cache logic.
// It handles cache lookup, origin fetch, cache write, and response sending.
// All protocol-specific response writing is abstracted via function arguments.
func HandleCacheRequest(
	ctx context.Context,
	conn net.Conn,
	req *http.Request,
	cfg Config,
	isTLS bool,
) {
	// Extract needed fields from cfg
	start := time.Now()
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	reqID := ctx.Value(RequestIDKey{}).(uuid.UUID)

	// Build origin URL using scheme
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	parsed, _ := url.ParseRequestURI(uri)
	originURL := &url.URL{
		Scheme:   scheme,
		Host:     req.Host,
		Path:     path.Clean(parsed.Path),
		RawQuery: parsed.RawQuery,
	}
	rawURL := originURL.String()
	cacheFile, metaFile := CachePathForOrigin(cfg.CacheDir, *originURL)

	mtx := fileMutex(cacheFile)
	mtx.Lock()
	defer mtx.Unlock()

	meta := cachepkg.ReadMeta(metaFile)
	fi, _ := os.Stat(cacheFile)

	// Serve fresh cache if present and fresh
	if fi != nil && !meta.NoCache && cachepkg.IsFresh(meta) {
		sendCachedOnConn(ctx, conn, http.StatusOK, meta, "HIT", req.Method == http.MethodHead, cacheFile, fi)
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
			IsTLS:       isTLS,
			LatencySecs: time.Since(start).Seconds(),
			Size:        fi.Size(),
			Status:      http.StatusOK,
		})
		log.Ctx(ctx).Info().
			Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
			Str("request_id", reqID.String()).
			Str("url", rawURL).
			Str("scheme", originURL.Scheme).
			Str("outcome", "HIT").
			Dur("latency", time.Since(start)).
			Msg("served")
		return
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, didCond, err := FetchOrigin(ctx, rawURL, meta, client)
	if err != nil {
		// attempt stale if exists
		if fi != nil {
			sendCachedOnConn(ctx, conn, http.StatusOK, meta, "STALE", req.Method == http.MethodHead, cacheFile, fi)
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
				IsTLS:       isTLS,
				LatencySecs: time.Since(start).Seconds(),
				Size: func() int64 {
					if fi != nil {
						return fi.Size()
					}
					return 0
				}(),
				Status: http.StatusOK,
			})
			log.Ctx(ctx).Info().
				Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
				Str("request_id", reqID.String()).
				Str("url", rawURL).
				Str("scheme", originURL.Scheme).
				Str("outcome", "STALE").
				Dur("latency", time.Since(start)).
				Msg("served stale")
			return
		}
		if cfg.Metrics != nil {
			cfg.Metrics.IncOriginErrors()
		}
		sendError(conn, http.StatusBadGateway)
		NotifyObserver(cfg.RequestObserver, RequestRecord{
			Time:        time.Now(),
			URL:         rawURL,
			Method:      req.Method,
			Host:        originURL.Host,
			Path:        originURL.Path,
			Outcome:     "ORIGIN-ERROR",
			IsTLS:       isTLS,
			LatencySecs: time.Since(start).Seconds(),
			Size:        0,
			Status:      http.StatusBadGateway,
		})
		log.Ctx(ctx).Error().
			Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
			Str("request_id", reqID.String()).
			Err(err).
			Str("url", rawURL).
			Str("scheme", originURL.Scheme).
			Msg("origin fetch failed")
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		newMeta := cachepkg.MetaFromHeaders(resp.Header, meta)
		_ = cachepkg.WriteMeta(metaFile, newMeta)
		if fi != nil {
			sendCachedOnConn(ctx, conn, http.StatusOK, newMeta, "REVALIDATED", req.Method == http.MethodHead, cacheFile, fi)
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
				IsTLS:       isTLS,
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
			log.Ctx(ctx).Info().
				Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
				Str("request_id", reqID.String()).
				Str("url", rawURL).
				Str("scheme", originURL.Scheme).
				Str("outcome", "REVALIDATED").
				Dur("latency", time.Since(start)).
				Msg("served")
			return
		}
		// no cached file to revalidate against
		// this should be rare; treat as error
		if cfg.Metrics != nil {
			cfg.Metrics.IncOriginErrors()
		}
		sendCustomError(conn, http.StatusInternalServerError, "Not Modified without cache")
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
		log.Ctx(ctx).Warn().
			Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
			Str("request_id", reqID.String()).
			Str("url", rawURL).
			Str("scheme", originURL.Scheme).
			Str("outcome", "REVALIDATED_NO_CACHE").
			Dur("latency", time.Since(start)).
			Msg("not modified but no cached file")
		return
	case http.StatusOK:
		newMeta := cachepkg.MetaFromHeaders(resp.Header, meta)

		// BYPASS: origin response must be forwarded without caching. Write a well-formed
		// HTTP response: status line -> headers -> CRLF -> body. Do not write any headers
		// before the status line (that was causing the malformed-status issues).
		if newMeta.NoStore || (!cfg.Private && req.Header.Get("Authorization") != "") || (!cfg.Private && newMeta.NoCache) {
			if newMeta.NoStore && cfg.Metrics != nil {
				cfg.Metrics.IncNoStore()
			}
			if newMeta.NoCache && cfg.Metrics != nil {
				cfg.Metrics.IncNoCache()
			}
			// Build a safe header set to emit.
			outHdr := make(http.Header)
			for k, vv := range resp.Header {
				lk := strings.ToLower(k)
				if hopByHopHeaders[lk] {
					continue
				}
				for _, v := range vv {
					outHdr.Add(k, v)
				}
			}
			// Ensure we declare the response is a BYPASS and close the connection.
			outHdr.Set("X-Cache", "BYPASS")
			outHdr.Set("Connection", "close")

			// Write status line first (HTTP/1.1), then headers, then blank line, then body.
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
			for k, vv := range outHdr {
				for _, v := range vv {
					_, _ = fmt.Fprintf(conn, "%s: %s\r\n", k, v)
				}
			}
			_, _ = fmt.Fprintf(conn, "\r\n")

			// Stream body (unless HEAD). Measure bytes copied for metrics/observer.
			var copied int64
			if req.Method != http.MethodHead && resp.Body != nil {
				n, _ := io.Copy(conn, resp.Body)
				copied = n
			}

			// Close upstream response body now that we've forwarded it.
			if resp.Body != nil {
				_ = resp.Body.Close()
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
				IsTLS:       isTLS,
				LatencySecs: time.Since(start).Seconds(),
				Size:        copied,
				Status:      resp.StatusCode,
			})
			log.Ctx(ctx).Info().
				Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
				Str("request_id", reqID.String()).
				Str("url", rawURL).
				Str("scheme", originURL.Scheme).
				Str("outcome", "BYPASS").
				Dur("latency", time.Since(start)).
				Msg("streamed origin without caching")
			return
		}

		// persist to cache then serve
		if err := WriteFileAtomic(cacheFile, resp.Body); err != nil {
			if cfg.Metrics != nil {
				cfg.Metrics.IncCacheErrors()
			}
			sendCustomError(conn, http.StatusInternalServerError, "Server Error")
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
			log.Ctx(ctx).Error().Err(err).
				Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
				Str("request_id", reqID.String()).
				Str("url", rawURL).
				Str("scheme", originURL.Scheme).
				Str("outcome", "WRITE_ERROR").
				Dur("latency", time.Since(start)).
				Str("file", cacheFile).
				Msg("failed to write cache file")
			return
		}
		_ = cachepkg.WriteMeta(metaFile, newMeta)

		outcome := "MISS"
		sendCachedOnConn(ctx, conn, http.StatusOK, newMeta, outcome, req.Method == http.MethodHead, cacheFile, fi)
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
			IsTLS:       isTLS,
			LatencySecs: time.Since(start).Seconds(),
			Size: func() int64 {
				if fi != nil {
					return fi.Size()
				}
				return 0
			}(),
			Status:      http.StatusOK,
			Conditional: didCond,
		})
		log.Ctx(ctx).Info().
			Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
			Str("request_id", reqID.String()).
			Str("url", rawURL).
			Str("scheme", originURL.Scheme).
			Str("outcome", outcome).
			Dur("latency", time.Since(start)).
			Msg("served")
		return
	default:
		// non-200: try stale, else stream origin
		if fi != nil {
			sendCachedOnConn(ctx, conn, http.StatusOK, meta, "STALE", req.Method == http.MethodHead, cacheFile, fi)
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
				IsTLS:       isTLS,
				LatencySecs: time.Since(start).Seconds(),
				Size: func() int64 {
					if fi != nil {
						return fi.Size()
					}
					return 0
				}(),
				Status: http.StatusOK,
			})
			log.Ctx(ctx).Info().
				Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
				Str("request_id", reqID.String()).
				Str("url", rawURL).
				Str("scheme", originURL.Scheme).
				Str("outcome", "STALE").
				Dur("latency", time.Since(start)).
				Msg("served stale (non-200)")
			return
		}
		// forward origin body
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
			IsTLS:       isTLS,
			LatencySecs: time.Since(start).Seconds(),
			Size:        copied,
			Status:      resp.StatusCode,
		})
		log.Ctx(ctx).Info().
			Str("connection_id", ctx.Value(ConnectionIDKey{}).(uuid.UUID).String()).
			Str("request_id", reqID.String()).
			Str("url", rawURL).
			Str("scheme", originURL.Scheme).
			Str("outcome", "ORIGIN-"+strconv.Itoa(resp.StatusCode)).
			Dur("latency", time.Since(start)).
			Msg("proxied origin")
	}
}
