// pkg/cacheproxy/mitm.go
package cacheproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	cachepkg "github.com/jnovack/cache-server/pkg/cache"
)

// HandleMITMHTTPS terminates TLS using a leaf cert from cfg.RootCA, reads one HTTP
// request from the client, applies caching rules and proxies to origin over HTTPS.
func HandleMITMHTTPS(conn net.Conn, host string, cfg Config) {
	start := time.Now()
	defer func() { _ = conn.Close() }()

	if cfg.Metrics != nil {
		cfg.Metrics.IncTotalRequests()
	}

	if cfg.RootCA == nil {
		log.Error().Str("host", host).Msg("MITM requested but RootCA is nil")
		fmt.Fprintf(conn, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 21\r\nConnection: close\r\n\r\nRoot CA not configured")
		return
	}

	leaf, err := cfg.RootCA.GetOrCreateLeaf(host)
	if err != nil {
		log.Error().Err(err).Str("host", host).Msg("failed to obtain leaf certificate")
		fmt.Fprintf(conn, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 26\r\nConnection: close\r\n\r\nCannot provision leaf cert")
		return
	}

	tlsSrv := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tlsSrv.Handshake(); err != nil {
		log.Debug().Err(err).Str("host", host).Msg("TLS handshake with client failed")
		return
	}

	br := bufio.NewReader(tlsSrv)
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Debug().Err(err).Msg("failed to read HTTPS request from client")
		fmt.Fprintf(tlsSrv, "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Request")
		return
	}
	defer req.Body.Close()

	// Only GET and HEAD are cacheable; other methods are rejected in this MITM path.
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		log.Debug().Str("method", req.Method).Msg("non-cacheable HTTPS method, denied in MITM mode")
		fmt.Fprintf(tlsSrv, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 18\r\nConnection: close\r\n\r\nMethod Not Allowed")
		return
	}

	originURL := &url.URL{Scheme: "https", Host: req.Host}
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

	// Serve fresh cache if present and still fresh
	if fi != nil && !meta.NoCache && cachepkg.IsFresh(meta) {
		sendCachedOnConn(tlsSrv, http.StatusOK, meta, "HIT", req.Method == http.MethodHead, cacheFile, fi)
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
			IsTLS:       true,
			LatencySecs: time.Since(start).Seconds(),
			Size:        fi.Size(),
			Status:      http.StatusOK,
		})
		log.Info().Str("url", rawURL).Str("outcome", "HIT").Dur("latency", time.Since(start)).Msg("served (https mitm)")
		return
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, didCond, err := FetchOrigin(rawURL, meta, client)
	if err != nil {
		// attempt stale if exists
		if fi != nil {
			sendCachedOnConn(tlsSrv, http.StatusOK, meta, "STALE", req.Method == http.MethodHead, cacheFile, fi)
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
				IsTLS:       true,
				LatencySecs: time.Since(start).Seconds(),
				Size:        fi.Size(),
				Status:      http.StatusOK,
			})
			log.Info().Str("url", rawURL).Str("outcome", "STALE").Dur("latency", time.Since(start)).Msg("served stale (https mitm)")
			return
		}
		if cfg.Metrics != nil {
			cfg.Metrics.IncOriginErrors()
		}
		log.Error().Err(err).Str("url", rawURL).Msg("origin fetch failed (https mitm)")
		fmt.Fprintf(tlsSrv, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Gateway")
		NotifyObserver(cfg.RequestObserver, RequestRecord{
			Time:        time.Now(),
			URL:         rawURL,
			Method:      req.Method,
			Host:        originURL.Host,
			Path:        originURL.Path,
			Outcome:     "ORIGIN-ERROR",
			IsTLS:       true,
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
			sendCachedOnConn(tlsSrv, http.StatusOK, newMeta, "REVALIDATED", req.Method == http.MethodHead, cacheFile, fi)
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
				IsTLS:       true,
				LatencySecs: time.Since(start).Seconds(),
				Size:        fi.Size(),
				Status:      http.StatusOK,
				Conditional: true,
			})
			log.Info().Str("url", rawURL).Str("outcome", "REVALIDATED").Dur("latency", time.Since(start)).Msg("served (https mitm)")
			return
		}
		fmt.Fprintf(tlsSrv, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 21\r\nConnection: close\r\n\r\nNot Modified without cache")
		return
	case http.StatusOK:
		newMeta := cachepkg.MetaFromHeaders(resp.Header, meta)
		// bypass conditions
		if newMeta.NoStore || (!cfg.Private && req.Header.Get("Authorization") != "") || (!cfg.Private && newMeta.NoCache) {
			if newMeta.NoStore && cfg.Metrics != nil {
				cfg.Metrics.IncNoStore()
			}
			if newMeta.NoCache && cfg.Metrics != nil {
				cfg.Metrics.IncNoCache()
			}
			fmt.Fprintf(tlsSrv, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
			for k, vv := range resp.Header {
				for _, v := range vv {
					fmt.Fprintf(tlsSrv, "%s: %s\r\n", k, v)
				}
			}
			fmt.Fprintf(tlsSrv, "X-Cache: BYPASS\r\nConnection: close\r\n\r\n")
			var copied int64
			if req.Method != http.MethodHead {
				n, _ := io.Copy(tlsSrv, resp.Body)
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
				IsTLS:       true,
				LatencySecs: time.Since(start).Seconds(),
				Size:        copied,
				Status:      resp.StatusCode,
			})
			log.Info().Str("url", rawURL).Str("outcome", "BYPASS").Dur("latency", time.Since(start)).Msg("streamed (https mitm)")
			return
		}

		// persist to cache then serve
		if err := WriteFileAtomic(cacheFile, resp.Body); err != nil {
			log.Error().Err(err).Str("file", cacheFile).Msg("failed to write cache file (https mitm)")
			fmt.Fprintf(tlsSrv, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 13\r\nConnection: close\r\n\r\nServer Error")
			return
		}
		_ = cachepkg.WriteMeta(metaFile, newMeta)
		fi2, _ := os.Stat(cacheFile)
		outcome := "MISS"
		if didCond || (fi2 != nil && !fi2.ModTime().IsZero()) {
			outcome = "REVALIDATED"
		}
		sendCachedOnConn(tlsSrv, http.StatusOK, newMeta, outcome, req.Method == http.MethodHead, cacheFile, fi2)
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
			IsTLS:       true,
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
		log.Info().Str("url", rawURL).Str("outcome", outcome).Dur("latency", time.Since(start)).Msg("served (https mitm)")
		return
	default:
		// non-200: try stale, else stream origin
		if fi != nil {
			sendCachedOnConn(tlsSrv, http.StatusOK, meta, "STALE", req.Method == http.MethodHead, cacheFile, fi)
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
				IsTLS:       true,
				LatencySecs: time.Since(start).Seconds(),
				Size:        fi.Size(),
				Status:      http.StatusOK,
			})
			log.Info().Str("url", rawURL).Str("outcome", "STALE").Dur("latency", time.Since(start)).Msg("served stale (https mitm non-200)")
			return
		}
		// forward origin body
		fmt.Fprintf(tlsSrv, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
		for k, vv := range resp.Header {
			for _, v := range vv {
				fmt.Fprintf(tlsSrv, "%s: %s\r\n", k, v)
			}
		}
		fmt.Fprintf(tlsSrv, "\r\n")
		if req.Method != http.MethodHead {
			_, _ = io.Copy(tlsSrv, resp.Body)
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
			IsTLS:       true,
			LatencySecs: time.Since(start).Seconds(),
			Size:        0,
			Status:      resp.StatusCode,
		})
		log.Info().Str("url", rawURL).Str("outcome", "ORIGIN-"+strconv.Itoa(resp.StatusCode)).Dur("latency", time.Since(start)).Msg("proxied origin (https mitm)")
	}
}
