// main.go
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	flag "github.com/jnovack/flag"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const faviconBase64 = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAACXBIWXMAAA7EAAAOxAGVKw4bAAACIklEQVRYw8XXQUsVYRQG4OeCGmWLpE0IBUHcMFAQCsqgRUEQ/oCCoFV/IAjatOkHtLNFpEVBIEELhQiylmnhqlpEqLQIKohSSawuZG2OMExzx7nXmXzhW9yZc99z5jvfec/5ajZGF47iGAZwAL3owfaw+Ylv+IgFvMY0XqChTQzhHpbxp821HBzHW3Fcx9QmnDZbUziYdlZL/R7GOHamni/gGWbxFh/wFavxfgd2Yy/6cBinIl1JrOAcHmV9+UAQrkfcwC0Mah+DwdFI8K6Gr38wkTCab2bUJvoxl+CfyDJaSRj0KR99Cf7v6w87EgbdthjJEztXcgoGIq25KUiXTQOjVR/CWiqAZmi1DI/gZKtlmBaNKoSoXvQMrEvx3aqluFkKks87oxHlNaMfWIxmNB/NaKbVZpTegSpwBmNbFUAdS7FLGwZwqGTn3XgT3A+LClF/iQGMJ7gvFwmgrG4Il1K8Q0WqoIgQfYnTn4cTeBqVBL+wK0a4TQvRGkZynPfiU+o/M+0I0VJOEM12oBPPM+yvt6MDXbGVV3AfLyMFi7jWhGukoFLeqUIHzkd6iqTwQhUB3C749aP/cyR7l3L+KtFHMofSMieiHvxOdch60bF8tAQhOp3K+9k84+GYWNP5msdNXIzevi/0vRarG3syLjpwNcFzo+qr2ZMMvsl4N4ttVV9O1zKudZ/j5rw/y0lHTgDTsVqZiMaimpJ4jAd4n+XkL2LKZt4RcuKGAAAAAElFTkSuQmCC"

var faviconBytes []byte

type Config struct {
	Port      string `json:"port"`
	Domain    string `json:"domain"`   // your server's domain (used to avoid self-fetch)
	CacheDir  string `json:"cacheDir"` // where to store cached files
	LogLevel  string `json:"logLevel"`
	UserAgent string `json:"userAgent"`
}

var config = Config{
	Port:      ":8080",
	Domain:    "cache.domain.local",
	CacheDir:  "./cache",
	LogLevel:  "info",
	UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1 OPX/2.2.0",
}

// ---------------- Metrics ----------------

var (
	// counters
	metrics = struct {
		sync.Mutex
		Total       uint64
		Hits        uint64
		Misses      uint64
		Revalidated uint64
		Stale       uint64
		Bypass      uint64
		NoStore     uint64
		NoCache     uint64
		OriginError uint64
	}{}

	// in-flight requests table + gauge
	inflight = struct {
		sync.Mutex
		Count int
		Reqs  map[string]time.Time // key: method+space+url
	}{Reqs: make(map[string]time.Time)}

	// histograms
	histogramBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	histograms       = struct {
		sync.Mutex
		ByOutcome map[string]*histogram
	}{ByOutcome: make(map[string]*histogram)}
)

type histogram struct {
	Counts []uint64
	Sum    float64
	Total  uint64
}

func inc(name string) {
	metrics.Lock()
	defer metrics.Unlock()
	metrics.Total++
	switch name {
	case "HIT":
		metrics.Hits++
	case "MISS":
		metrics.Misses++
	case "REVALIDATED":
		metrics.Revalidated++
	case "STALE":
		metrics.Stale++
	case "BYPASS":
		metrics.Bypass++
	case "NOSTORE":
		metrics.NoStore++
	case "NOCACHE":
		metrics.NoCache++
	case "ORIGIN_ERROR":
		metrics.OriginError++
	}
}

func observe(outcome string, d time.Duration) {
	seconds := d.Seconds()
	histograms.Lock()
	defer histograms.Unlock()
	h, ok := histograms.ByOutcome[outcome]
	if !ok {
		h = &histogram{Counts: make([]uint64, len(histogramBuckets))}
		histograms.ByOutcome[outcome] = h
	}
	h.Total++
	h.Sum += seconds
	for i, b := range histogramBuckets {
		if seconds <= b {
			h.Counts[i]++
			return
		}
	}
	// falls into +Inf implicitly via count
}

func trackInflight(id string, add bool) {
	inflight.Lock()
	defer inflight.Unlock()
	if add {
		inflight.Count++
		inflight.Reqs[id] = time.Now()
	} else {
		if inflight.Count > 0 {
			inflight.Count--
		}
		delete(inflight.Reqs, id)
	}
}

// ---------------- Per-file locks ----------------

var inflightLocks sync.Map // map[string]*sync.Mutex

func fileMutex(key string) *sync.Mutex {
	actual, _ := inflightLocks.LoadOrStore(key, &sync.Mutex{})
	return actual.(*sync.Mutex)
}

// ---------------- Cache metadata ----------------

type cacheMeta struct {
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
	NoStore      bool      `json:"no_store,omitempty"`
	NoCache      bool      `json:"no_cache,omitempty"`
	ContentType  string    `json:"content_type,omitempty"`
}

func readMeta(path string) cacheMeta {
	var m cacheMeta
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func writeMeta(path string, m cacheMeta) error {
	m.FetchedAt = time.Now()
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func isFresh(m cacheMeta) bool {
	if m.NoCache {
		return false
	}
	if m.ExpiresAt.IsZero() {
		return false
	}
	return true
	// ALWAYS return true for now
	// return time.Now().Before(m.ExpiresAt)
}

// ---------------- HTTP helpers ----------------

func forwardCacheHeaders(dst http.Header, meta cacheMeta) {
	if meta.ContentType != "" {
		dst.Set("Content-Type", meta.ContentType)
	}
	if !meta.ExpiresAt.IsZero() {
		dst.Set("Expires", meta.ExpiresAt.UTC().Format(http.TimeFormat))
	}
	if meta.ETag != "" {
		dst.Set("ETag", meta.ETag)
	}
	if meta.LastModified != "" {
		dst.Set("Last-Modified", meta.LastModified)
	}
	// Reconstruct Cache-Control
	var directives []string
	switch {
	case meta.NoStore:
		directives = append(directives, "no-store")
	case meta.NoCache:
		directives = append(directives, "no-cache")
	default:
		if !meta.ExpiresAt.IsZero() {
			secs := int(time.Until(meta.ExpiresAt).Seconds())
			if secs < 0 {
				secs = 0
			}
			directives = append(directives, "max-age="+strconv.Itoa(secs))
		}
	}
	if len(directives) > 0 {
		dst.Set("Cache-Control", strings.Join(directives, ", "))
	}
}

func forwardOriginHeaders(dst, src http.Header) {
	copyIf(dst, src, "Content-Type")
	copyIf(dst, src, "Cache-Control")
	copyIf(dst, src, "ETag")
	copyIf(dst, src, "Last-Modified")
	copyIf(dst, src, "Expires")
}

func copyIf(dst, src http.Header, k string) {
	if v := src.Get(k); v != "" {
		dst.Set(k, v)
	}
}

func metaFromHeaders(h http.Header, prev cacheMeta) cacheMeta {
	m := cacheMeta{
		ETag:         first(h, "ETag", prev.ETag),
		LastModified: first(h, "Last-Modified", prev.LastModified),
		ContentType:  first(h, "Content-Type", prev.ContentType),
		FetchedAt:    time.Now(),
	}
	cc := h.Get("Cache-Control")
	if cc != "" {
		parts := strings.Split(cc, ",")
		for _, p := range parts {
			p = strings.TrimSpace(strings.ToLower(p))
			switch {
			case p == "no-store":
				m.NoStore = true
				inc("NOSTORE")
			case p == "no-cache":
				m.NoCache = true
				inc("NOCACHE")
			case strings.HasPrefix(p, "max-age="):
				if secs, err := strconv.Atoi(strings.TrimPrefix(p, "max-age=")); err == nil {
					m.ExpiresAt = m.FetchedAt.Add(time.Duration(secs) * time.Second)
				}
			}
		}
	}
	if exp := h.Get("Expires"); exp != "" {
		if t, err := http.ParseTime(exp); err == nil {
			if m.ExpiresAt.IsZero() || t.After(m.ExpiresAt) {
				m.ExpiresAt = t
			}
		}
	}
	return m
}

func first(h http.Header, key, fb string) string {
	if v := h.Get(key); v != "" {
		return v
	}
	return fb
}

// ---------------- Core proxy logic ----------------

func handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqID := r.Method + " " + r.URL.String()
	trackInflight(reqID, true)
	defer trackInflight(reqID, false)

	// Map /<origin-host>/<rest...>  ->  https://<origin-host>/<rest...>
	cleanPath := path.Clean(r.URL.Path)
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}
	rel := strings.TrimPrefix(cleanPath, "/")
	parts := strings.SplitN(rel, "/", 2)
	if len(parts) < 2 {
		http.Error(w, "invalid path: must start with <origin-host>/...", http.StatusBadRequest)
		log.Error().Str("path", r.URL.Path).Msg("invalid path (no origin host segment)")
		return
	}
	originHost := parts[0]
	rest := parts[1]
	if originHost == "" || strings.Contains(originHost, "..") || strings.ContainsAny(originHost, "/\\") {
		http.Error(w, "invalid origin host", http.StatusBadRequest)
		log.Error().Str("originHost", originHost).Msg("invalid origin host")
		return
	}
	// Avoid accidental self-fetch loops
	if config.Domain != "" && strings.EqualFold(originHost, config.Domain) {
		http.Error(w, "refusing to proxy to self", http.StatusBadRequest)
		log.Error().Str("originHost", originHost).Msg("attempted self-proxy")
		return
	}

	originURL := url.URL{
		Scheme:   "https",
		Host:     originHost,
		Path:     "/" + rest,
		RawQuery: r.URL.RawQuery,
	}

	// Filesystem target: <cacheDir>/<origin-host>/<rest>
	relativeFS := rel // already excludes leading slash
	cachePath := filepath.Join(config.CacheDir, filepath.FromSlash(relativeFS))
	metaPath := cachePath + ".meta.json"

	// Per-file lock to avoid duplicate fetches
	mtx := fileMutex(cachePath)
	mtx.Lock()
	defer mtx.Unlock()

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		log.Error().Err(err).Str("dir", filepath.Dir(cachePath)).Msg("failed to create cache directory")
		return
	}

	// Load meta if present
	meta := readMeta(metaPath)
	exists := fileExists(cachePath)

	// Fast path: fresh cache and not 'no-cache'
	if exists && !meta.NoCache && isFresh(meta) {
		w.Header().Set("X-Cache", "HIT")
		forwardCacheHeaders(w.Header(), meta)
		http.ServeFile(w, r, cachePath)
		inc("HIT")
		observe("HIT", time.Since(start))
		log.Info().Str("url", originURL.String()).Str("outcome", "HIT").Dur("latency", time.Since(start)).Msg("served")
		return
	}

	// Need origin contact (either initial or stale)
	resp, didCond, err := fetchFromOrigin(originURL.String(), meta)
	if err != nil {
		if exists {
			// Serve stale
			log.Warn().Err(err).Str("url", originURL.String()).Msg("origin fetch failed, serving stale cache")
			w.Header().Set("X-Cache", "STALE")
			forwardCacheHeaders(w.Header(), meta)
			http.ServeFile(w, r, cachePath)
			inc("STALE")
			inc("ORIGIN_ERROR")
			observe("STALE", time.Since(start))
			log.Info().Str("url", originURL.String()).Str("outcome", "STALE").Dur("latency", time.Since(start)).Msg("served")
			return
		}
		inc("ORIGIN_ERROR")
		http.Error(w, "bad gateway", http.StatusBadGateway)
		log.Error().Err(err).Str("url", originURL.String()).Msg("origin fetch failed (no cache)")
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// Revalidated OK
		newMeta := metaFromHeaders(resp.Header, meta)
		_ = writeMeta(metaPath, newMeta)
		w.Header().Set("X-Cache", "REVALIDATED")
		forwardCacheHeaders(w.Header(), newMeta)
		http.ServeFile(w, r, cachePath)
		inc("REVALIDATED")
		observe("REVALIDATED", time.Since(start))
		log.Info().Str("url", originURL.String()).Str("outcome", "REVALIDATED").Dur("latency", time.Since(start)).Msg("served")
		return

	case http.StatusOK:
		newMeta := metaFromHeaders(resp.Header, meta)
		if newMeta.NoStore {
			// Do not write to disk, just stream through
			log.Debug().Str("url", originURL.String()).Msg("origin returned no-store; streaming only")
			w.Header().Set("X-Cache", "BYPASS")
			forwardOriginHeaders(w.Header(), resp.Header)
			w.WriteHeader(http.StatusOK)
			_, _ = io.Copy(w, resp.Body)
			inc("BYPASS")
			observe("BYPASS", time.Since(start))
			log.Info().Str("url", originURL.String()).Str("outcome", "BYPASS").Dur("latency", time.Since(start)).Msg("served")
			return
		}

		// Write atomically to disk then persist metadata
		if err := writeFileAtomically(cachePath, resp.Body); err != nil {
			http.Error(w, "cache write failed", http.StatusInternalServerError)
			log.Error().Err(err).Str("file", cachePath).Msg("failed to write cache file")
			return
		}
		if err := writeMeta(metaPath, newMeta); err != nil {
			log.Warn().Err(err).Str("file", metaPath).Msg("failed to write meta (non-fatal)")
		}

		// Serve from disk (ensures consistent file handle semantics)
		if ct := newMeta.ContentType; ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		forwardCacheHeaders(w.Header(), newMeta)
		var outcome string
		if exists || didCond {
			outcome = "REVALIDATED"
			inc("REVALIDATED")
		} else {
			outcome = "MISS"
			inc("MISS")
		}
		w.Header().Set("X-Cache", outcome)
		http.ServeFile(w, r, cachePath)
		observe(outcome, time.Since(start))
		log.Info().Str("url", originURL.String()).Str("outcome", outcome).Dur("latency", time.Since(start)).Msg("served")
		return

	default:
		// Non-200, non-304 from origin
		log.Debug().Int("status", resp.StatusCode).Str("url", originURL.String()).Msg("unexpected origin status")
		if exists {
			w.Header().Set("X-Cache", "STALE")
			forwardCacheHeaders(w.Header(), meta)
			http.ServeFile(w, r, cachePath)
			inc("STALE")
			observe("STALE", time.Since(start))
			log.Info().Str("url", originURL.String()).Str("outcome", "STALE").Dur("latency", time.Since(start)).Msg("served")
			return
		}
		http.Error(w, "origin error", resp.StatusCode)
		return
	}
}

// fetchFromOrigin performs an GET to the given URL, adding conditional headers
// from the provided cacheMeta if available. It returns the HTTP response, whether
// a conditional request was made, and any error encountered.
func fetchFromOrigin(url string, meta cacheMeta) (*http.Response, bool, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", config.UserAgent)

	didCond := false
	// Conditional if we have validators OR we’re stale
	if meta.ETag != "" {
		req.Header.Set("If-None-Match", meta.ETag)
		didCond = true
	}
	if meta.LastModified != "" {
		req.Header.Set("If-Modified-Since", meta.LastModified)
		didCond = true
	}
	log.Debug().Str("url", url).Bool("conditional", didCond).Msg("fetching")
	resp, err := client.Do(req)
	if err != nil {
		return nil, didCond, err
	}
	return resp, didCond, nil
}

func writeFileAtomically(dst string, r io.Reader) error {
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, r)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, dst)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ---------------- Admin endpoints ----------------

func handleFavIcon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=7776000")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(faviconBytes)
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// counters
	metrics.Lock()
	writeMetric := func(name, help string, v uint64) {
		_, _ = w.Write([]byte("# HELP " + name + " " + help + "\n"))
		_, _ = w.Write([]byte("# TYPE " + name + " counter\n"))
		_, _ = w.Write([]byte(name + " " + strconv.FormatUint(v, 10) + "\n\n"))
	}
	writeMetric("cache_requests_total", "Total requests processed", metrics.Total)
	writeMetric("cache_hits_total", "Served from fresh cache", metrics.Hits)
	writeMetric("cache_misses_total", "Fetched from origin and cached", metrics.Misses)
	writeMetric("cache_revalidated_total", "Served after revalidation (200 refresh or 304)", metrics.Revalidated)
	writeMetric("cache_stale_total", "Served stale due to origin error or non-200", metrics.Stale)
	writeMetric("cache_bypass_total", "Streamed directly due to no-store", metrics.Bypass)
	writeMetric("cache_no_store_total", "Origin responses with Cache-Control: no-store", metrics.NoStore)
	writeMetric("cache_no_cache_total", "Origin responses with Cache-Control: no-cache", metrics.NoCache)
	writeMetric("cache_origin_error_total", "Errors contacting origin (network/DNS/timeout)", metrics.OriginError)
	metrics.Unlock()

	// inflight gauge
	inflight.Lock()
	_, _ = w.Write([]byte("# HELP cache_inflight_requests In-flight requests\n"))
	_, _ = w.Write([]byte("# TYPE cache_inflight_requests gauge\n"))
	_, _ = w.Write([]byte("cache_inflight_requests " + strconv.Itoa(inflight.Count) + "\n\n"))
	inflight.Unlock()

	// histograms
	histograms.Lock()
	_, _ = w.Write([]byte("# HELP cache_request_duration_seconds Request duration by cache outcome\n"))
	_, _ = w.Write([]byte("# TYPE cache_request_duration_seconds histogram\n"))
	for outcome, h := range histograms.ByOutcome {
		cumulative := uint64(0)
		for i, b := range histogramBuckets {
			cumulative += h.Counts[i]
			_, _ = w.Write([]byte(
				"cache_request_duration_seconds_bucket{outcome=\"" + outcome + "\",le=\"" +
					strconv.FormatFloat(b, 'f', -1, 64) + "\"} " + strconv.FormatUint(cumulative, 10) + "\n"))
		}
		_, _ = w.Write([]byte(
			"cache_request_duration_seconds_bucket{outcome=\"" + outcome + "\",le=\"+Inf\"} " +
				strconv.FormatUint(h.Total, 10) + "\n"))
		_, _ = w.Write([]byte(
			"cache_request_duration_seconds_sum{outcome=\"" + outcome + "\"} " +
				strconv.FormatFloat(h.Sum, 'f', -1, 64) + "\n"))
		_, _ = w.Write([]byte(
			"cache_request_duration_seconds_count{outcome=\"" + outcome + "\"} " +
				strconv.FormatUint(h.Total, 10) + "\n\n"))
	}
	histograms.Unlock()
}

func handleStatusz(w http.ResponseWriter, _ *http.Request) {
	inflight.Lock()
	defer inflight.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte("<html><head><title>Status</title></head><body>"))
	_, _ = w.Write([]byte("<h1>Status</h1>"))
	_, _ = w.Write([]byte("<p>Inflight: " + strconv.Itoa(inflight.Count) + "</p>"))
	_, _ = w.Write([]byte("<table border='1' cellpadding='4' cellspacing='0'>"))
	_, _ = w.Write([]byte("<tr><th>Request</th><th>Start (RFC3339)</th><th>Age (s)</th></tr>"))
	now := time.Now()
	for k, t := range inflight.Reqs {
		age := now.Sub(t).Seconds()
		_, _ = w.Write([]byte("<tr><td>" + html.EscapeString(k) + "</td><td>" + t.Format(time.RFC3339) + "</td><td>" + strconv.FormatFloat(age, 'f', 3, 64) + "</td></tr>"))
	}
	_, _ = w.Write([]byte("</table></body></html>"))
}

func handleVarz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(config)
}

// ---------------- Signal handling / server bootstrap ----------------

func setupSignalHandler(srv *http.Server) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Error().Str("signal", sig.String()).Msg("received signal, shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx) // graceful stop; ListenAndServe will return
	}()
}

func main() {
	var err error

	// Logging
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// Flags (jnovack/flag)
	flag.StringVar(&config.Port, "Port", config.Port, "Listen on port")
	flag.StringVar(&config.Domain, "domain", config.Domain, "This server's domain (avoid self-fetch)")
	flag.StringVar(&config.CacheDir, "cache", config.CacheDir, "Cache directory")
	flag.StringVar(&config.LogLevel, "log-level", config.LogLevel, "Log level: debug|info|warn|error")
	flag.StringVar(&config.UserAgent, "user-agent", config.UserAgent, "User-Agent to send to origin")
	flag.Parse()

	// Set log level
	switch strings.ToLower(config.LogLevel) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Prepare cache dir
	if err := os.MkdirAll(config.CacheDir, 0o755); err != nil {
		log.Fatal().Err(err).Str("dir", config.CacheDir).Msg("failed to create cache directory")
	}

	faviconBytes, err = base64.StdEncoding.DecodeString(faviconBase64)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to decode favicon base64")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/statusz", handleStatusz)
	mux.HandleFunc("/varz", handleVarz)
	mux.HandleFunc("/favicon.ico", handleFavIcon)
	mux.HandleFunc("/", handleRequest)

	srv := &http.Server{
		Addr:              config.Port,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
	}

	setupSignalHandler(srv)

	log.Info().
		Str("port", config.Port).
		Str("domain", config.Domain).
		Str("cacheDir", config.CacheDir).
		Str("logLevel", strings.ToLower(config.LogLevel)).
		Msg("starting cache server")

	err = srv.ListenAndServe()
	// If graceful shutdown was triggered, err will be http.ErrServerClosed
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal().Err(err).Msg("server failed")
	}
	// Application stop should log as error
	log.Error().Msg("server stopped")
}
