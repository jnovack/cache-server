package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Config struct {
	ListenAddr string
	Domain     string
	CacheDir   string
}

var (
	config = Config{}

	// in-flight request tracking
	inflight = struct {
		sync.Mutex
		Count int
		Reqs  map[string]time.Time
	}{Reqs: make(map[string]time.Time)}

	// counters
	counters = struct {
		sync.Mutex
		Values map[string]uint64
	}{Values: make(map[string]uint64)}

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

func main() {
	// flags
	flag.StringVar(&config.ListenAddr, "listen", ":8080", "listen address")
	flag.StringVar(&config.Domain, "domain", "cache.local", "domain of the cache server")
	flag.StringVar(&config.CacheDir, "cache", "./cache", "cache directory")
	flag.Parse()

	// structured logging setup
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	log.Info().
		Str("listen", config.ListenAddr).
		Str("domain", config.Domain).
		Str("cacheDir", config.CacheDir).
		Msg("starting cache server")

	setupSignalHandler()

	// endpoints
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/metrics", handleMetrics)
	http.HandleFunc("/statusz", handleStatusz)
	http.HandleFunc("/varz", handleVarz)
	http.HandleFunc("/", handleRequest)

	if err := http.ListenAndServe(config.ListenAddr, nil); err != nil {
		log.Error().Err(err).Msg("server stopped unexpectedly")
		os.Exit(1)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	raw := "https://" + strings.TrimPrefix(r.Host+r.URL.Path, config.Domain)
	u, err := url.Parse(raw)
	if err != nil {
		log.Error().Err(err).Str("raw", raw).Msg("failed to parse url")
		http.Error(w, "bad url", http.StatusBadRequest)
		return
	}

	trackInflight(u.String(), true)
	defer trackInflight(u.String(), false)

	cachePath := filepath.Join(config.CacheDir, u.Host, u.Path)
	cacheDir := filepath.Dir(cachePath)

	// outcome label for metrics/logging
	outcome := "MISS"

	// check cache
	// var fi os.FileInfo
	// if fi, err = os.Stat(cachePath); err == nil {
	if _, err = os.Stat(cachePath); err == nil {
		// revalidate
		req, _ := http.NewRequest("GET", u.String(), nil)
		if etag, lm := getCacheHeaders(cachePath); etag != "" || lm != "" {
			if etag != "" {
				req.Header.Set("If-None-Match", etag)
			}
			if lm != "" {
				req.Header.Set("If-Modified-Since", lm)
			}
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Error().Err(err).Str("url", u.String()).Msg("revalidation failed, serving stale")
			http.ServeFile(w, r, cachePath)
			incrementCounter("STALE")
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotModified {
			outcome = "HIT"
			http.ServeFile(w, r, cachePath)
			incrementCounter(outcome)
			log.Info().Str("url", u.String()).Str("outcome", outcome).Msg("served request")
			observeDuration(outcome, time.Since(start))
			return
		}

		// update cache
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			log.Error().Err(err).Str("dir", cacheDir).Msg("failed to create directory")
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		f, err := os.Create(cachePath)
		if err != nil {
			log.Error().Err(err).Str("path", cachePath).Msg("failed to create cache file")
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		defer f.Close()

		io.Copy(f, resp.Body)
		f.Sync()

		outcome = "REVALIDATED"
		http.ServeFile(w, r, cachePath)
		incrementCounter(outcome)
		log.Info().Str("url", u.String()).Str("outcome", outcome).Msg("served request")
		observeDuration(outcome, time.Since(start))
		return
	}

	// MISS
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Error().Err(err).Str("dir", cacheDir).Msg("failed to create directory")
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	resp, err := http.Get(u.String())
	if err != nil {
		log.Error().Err(err).Str("url", u.String()).Msg("failed to fetch origin")
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	f, err := os.Create(cachePath)
	if err != nil {
		log.Error().Err(err).Str("path", cachePath).Msg("failed to create cache file")
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	io.Copy(f, resp.Body)
	f.Sync()

	http.ServeFile(w, r, cachePath)
	incrementCounter(outcome)
	log.Info().Str("url", u.String()).Str("outcome", outcome).Msg("served request")
	observeDuration(outcome, time.Since(start))
}

func getCacheHeaders(path string) (etag, lastModified string) {
	etagPath := path + ".etag"
	lmPath := path + ".lastmod"
	if b, err := os.ReadFile(etagPath); err == nil {
		etag = string(b)
	}
	if b, err := os.ReadFile(lmPath); err == nil {
		lastModified = string(b)
	}
	return
}

func trackInflight(id string, add bool) {
	inflight.Lock()
	defer inflight.Unlock()
	if add {
		inflight.Count++
		inflight.Reqs[id] = time.Now()
	} else {
		inflight.Count--
		delete(inflight.Reqs, id)
	}
}

func incrementCounter(name string) {
	counters.Lock()
	defer counters.Unlock()
	counters.Values[name]++
}

func observeDuration(outcome string, d time.Duration) {
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
			break
		}
	}
}

// prometheus
func handleMetrics(w http.ResponseWriter, _ *http.Request) {
	counters.Lock()
	for k, v := range counters.Values {
		fmt.Fprintf(w, "cache_%s_total %d\n", strings.ToLower(k), v)
	}
	counters.Unlock()

	inflight.Lock()
	fmt.Fprintf(w, "cache_inflight_requests %d\n", inflight.Count)
	inflight.Unlock()

	// histograms
	histograms.Lock()
	for outcome, h := range histograms.ByOutcome {
		cumulative := uint64(0)
		for i, b := range histogramBuckets {
			cumulative += h.Counts[i]
			fmt.Fprintf(w,
				"cache_request_duration_seconds_bucket{outcome=\"%s\",le=\"%f\"} %d\n",
				outcome, b, cumulative)
		}
		fmt.Fprintf(w,
			"cache_request_duration_seconds_bucket{outcome=\"%s\",le=\"+Inf\"} %d\n",
			outcome, h.Total)
		fmt.Fprintf(w,
			"cache_request_duration_seconds_sum{outcome=\"%s\"} %f\n",
			outcome, h.Sum)
		fmt.Fprintf(w,
			"cache_request_duration_seconds_count{outcome=\"%s\"} %d\n",
			outcome, h.Total)
	}
	histograms.Unlock()
}

// /statusz
func handleStatusz(w http.ResponseWriter, _ *http.Request) {
	inflight.Lock()
	defer inflight.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><h1>Status</h1>")
	fmt.Fprintf(w, "<p>Inflight: %d</p>", inflight.Count)
	fmt.Fprintf(w, "<table border=1><tr><th>URL</th><th>Start</th></tr>")
	for url, t := range inflight.Reqs {
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td></tr>", url, t.Format(time.RFC3339))
	}
	fmt.Fprintf(w, "</table></body></html>")
}

// /varz
func handleVarz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// graceful shutdown on SIGINT/SIGTERM
func setupSignalHandler() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Error().Str("signal", sig.String()).Msg("received signal, shutting down")
		os.Exit(0)
	}()
}
