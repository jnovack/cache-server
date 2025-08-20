// Package admin implements small HTTP admin endpoints used by binaries.
// It includes counters, inflight gauges and a simple histogram facility for request durations.
package admin

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// HistogramBuckets defines the latency buckets (seconds) used when observing request durations.
var HistogramBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Metrics is a minimal metrics container consumed by /metrics handler.
type Metrics struct {
	sync.Mutex

	TotalRequests uint64 `json:"total_requests"`
	Hits          uint64 `json:"hits"`
	Misses        uint64 `json:"misses"`
	Revalidated   uint64 `json:"revalidated"`
	Stale         uint64 `json:"stale"`
	Bypass        uint64 `json:"bypass"`
	NoStore       uint64 `json:"no_store"`
	NoCache       uint64 `json:"no_cache"`
	OriginErrors  uint64 `json:"origin_errors"`

	// In-flight gauge + map of id->start time for /statusz
	Inflight     int                  `json:"inflight"`
	InflightList map[string]time.Time `json:"inflight_list"`

	// Histograms: map outcome -> counts per bucket
	HistCounts map[string][]uint64 `json:"hist_counts"`
	HistSum    map[string]float64  `json:"hist_sum"`
	HistTotal  map[string]uint64   `json:"hist_total"`
}

// NewMetrics constructs a Metrics instance with initialized histogram maps.
func NewMetrics() *Metrics {
	return &Metrics{
		InflightList: make(map[string]time.Time),
		HistCounts:   make(map[string][]uint64),
		HistSum:      make(map[string]float64),
		HistTotal:    make(map[string]uint64),
	}
}

// InflightAdd records an inflight request with id.
func (m *Metrics) InflightAdd(id string) {
	m.Lock()
	defer m.Unlock()
	m.Inflight++
	m.InflightList[id] = time.Now()
}

// InflightRemove removes an inflight request id.
func (m *Metrics) InflightRemove(id string) {
	m.Lock()
	defer m.Unlock()
	if m.Inflight > 0 {
		m.Inflight--
	}
	delete(m.InflightList, id)
}

// Increment helpers
func (m *Metrics) IncTotalRequests() { m.Lock(); m.TotalRequests++; m.Unlock() }
func (m *Metrics) IncHit()           { m.Lock(); m.Hits++; m.Unlock() }
func (m *Metrics) IncMiss()          { m.Lock(); m.Misses++; m.Unlock() }
func (m *Metrics) IncRevalidated()   { m.Lock(); m.Revalidated++; m.Unlock() }
func (m *Metrics) IncStale()         { m.Lock(); m.Stale++; m.Unlock() }
func (m *Metrics) IncBypass()        { m.Lock(); m.Bypass++; m.Unlock() }
func (m *Metrics) IncNoStore()       { m.Lock(); m.NoStore++; m.Unlock() }
func (m *Metrics) IncNoCache()       { m.Lock(); m.NoCache++; m.Unlock() }
func (m *Metrics) IncOriginErrors()  { m.Lock(); m.OriginErrors++; m.Unlock() }

// ObserveDuration records a request duration (in seconds) under a named outcome.
func (m *Metrics) ObserveDuration(outcome string, seconds float64) {
	m.Lock()
	defer m.Unlock()
	// ensure buckets exist for this outcome
	if _, ok := m.HistCounts[outcome]; !ok {
		m.HistCounts[outcome] = make([]uint64, len(HistogramBuckets))
		m.HistSum[outcome] = 0
		m.HistTotal[outcome] = 0
	}
	m.HistSum[outcome] += seconds
	m.HistTotal[outcome]++
	for i, b := range HistogramBuckets {
		if seconds <= b {
			m.HistCounts[outcome][i]++
			return
		}
	}
	// larger than last bucket: increment last index
	if len(m.HistCounts[outcome]) > 0 {
		m.HistCounts[outcome][len(m.HistCounts[outcome])-1]++
	}
}

// Admin handlers

// HandleHealth is a simple healthz handler.
func HandleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// HandleVarz writes config (provided) as JSON.
func HandleVarz(w http.ResponseWriter, cfg interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

// HandleStatusz renders a small HTML page showing inflight requests.
func HandleStatusz(w http.ResponseWriter, m *Metrics) {
	m.Lock()
	defer m.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte("<html><body><h1>Status</h1>"))
	_, _ = w.Write([]byte("<p>Inflight: " + strconv.Itoa(m.Inflight) + "</p>"))
	_, _ = w.Write([]byte("<table border='1'><tr><th>Request</th><th>Start</th><th>Age(s)</th></tr>"))
	now := time.Now()
	for k, t := range m.InflightList {
		age := now.Sub(t).Seconds()
		_, _ = w.Write([]byte("<tr><td>" + html.EscapeString(k) + "</td><td>" + t.Format(time.RFC3339) + "</td><td>" + strconv.FormatFloat(age, 'f', 3, 64) + "</td></tr>"))
	}
	_, _ = w.Write([]byte("</table></body></html>"))
}

// HandleMetrics writes Prometheus-compatible output including histograms and counters.
func HandleMetrics(w http.ResponseWriter, m *Metrics) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	m.Lock()
	// counters
	write := func(name, help string, v uint64) {
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n", name, help)
		_, _ = fmt.Fprintf(w, "# TYPE %s counter\n", name)
		_, _ = fmt.Fprintf(w, "%s %d\n\n", name, v)
	}
	write("cache_requests_total", "Total requests processed", m.TotalRequests)
	write("cache_hits_total", "Served from fresh cache", m.Hits)
	write("cache_misses_total", "Fetched from origin and cached", m.Misses)
	write("cache_revalidated_total", "Served after revalidation", m.Revalidated)
	write("cache_stale_total", "Served stale due to origin error or non-200", m.Stale)
	write("cache_bypass_total", "Streamed due to no-store or private", m.Bypass)
	write("cache_no_store_total", "Responses with Cache-Control: no-store", m.NoStore)
	write("cache_no_cache_total", "Responses with Cache-Control: no-cache", m.NoCache)
	write("cache_origin_error_total", "Errors contacting origin", m.OriginErrors)

	// inflight gauge
	_, _ = fmt.Fprintf(w, "# HELP cache_inflight_requests In-flight requests\n")
	_, _ = fmt.Fprintf(w, "# TYPE cache_inflight_requests gauge\n")
	_, _ = fmt.Fprintf(w, "cache_inflight_requests %d\n\n", m.Inflight)

	// histograms
	_, _ = fmt.Fprintf(w, "# HELP cache_request_duration_seconds Request duration by cache outcome\n")
	_, _ = fmt.Fprintf(w, "# TYPE cache_request_duration_seconds histogram\n")
	for outcome, counts := range m.HistCounts {
		cum := uint64(0)
		for i, b := range HistogramBuckets {
			if i < len(counts) {
				cum += counts[i]
			}
			_, _ = fmt.Fprintf(w, "cache_request_duration_seconds_bucket{outcome=\"%s\",le=\"%g\"} %d\n", outcome, b, cum)
		}
		// +Inf bucket
		total := m.HistTotal[outcome]
		_, _ = fmt.Fprintf(w, "cache_request_duration_seconds_bucket{outcome=\"%s\",le=\"+Inf\"} %d\n", outcome, total)
		_, _ = fmt.Fprintf(w, "cache_request_duration_seconds_sum{outcome=\"%s\"} %g\n", outcome, m.HistSum[outcome])
		_, _ = fmt.Fprintf(w, "cache_request_duration_seconds_count{outcome=\"%s\"} %d\n\n", outcome, total)
	}
	m.Unlock()
}
