// pkg/cacheproxy/types.go
package cacheproxy

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// RequestRecord represents a captured request/result for in-memory inspection
// or later persistence.
type RequestRecord struct {
	Time        time.Time `json:"time"`
	URL         string    `json:"url"`
	Method      string    `json:"method"`
	Host        string    `json:"host"`
	Path        string    `json:"path"`
	Outcome     string    `json:"outcome"`      // HIT, MISS, REVALIDATED, BYPASS, STALE, ORIGIN-xxx
	IsTLS       bool      `json:"is_tls"`       // true for MITM HTTPS flows
	LatencySecs float64   `json:"latency_secs"` // seconds
	Size        int64     `json:"size_bytes"`
	Status      int       `json:"status"`
	Conditional bool      `json:"conditional"`
}

type ConnectionIDKey struct{}
type RequestIDKey struct{}

// RequestObserver receives RequestRecords. Observers should be fast — NotifyObserver
// will invoke them asynchronously.
type RequestObserver func(RequestRecord)

// RootCAProvider is the contract the cacheproxy expects for certificate issuance
// during MITM. Your concrete CA implementation (e.g. pkg/ca.RootCA) should
// implement this interface.
type RootCAProvider interface {
	// GetOrCreateLeaf returns a tls.Certificate for the given host (leaf cert).
	// The implementation is expected to cache / persist leaf certs for reuse.
	GetOrCreateLeaf(host string) (tls.Certificate, error)
	// PEM returns the PEM-encoded root certificate if available (optional).
	PEM() []byte
}

// Metrics is a minimal interface of counters/histograms used by cacheproxy.
// Your concrete admin/metrics implementation should provide these methods.
type Metrics interface {
	IncTotalRequests()
	IncHit()
	IncMiss()
	IncRevalidated()
	IncBypass()
	IncNoStore()
	IncNoCache()
	IncStale()
	IncOriginErrors()
	IncCacheErrors()
	ObserveDuration(string, float64)
}

// Config holds the behavior/configuration for cacheproxy handlers.
type Config struct {
	CacheDir        string
	Private         bool // allow caching of Authorization / Cache-Control: private
	Metrics         Metrics
	RootCA          RootCAProvider
	MinTTL          time.Duration
	HTTPClient      *http.Client
	RequestObserver RequestObserver
}

// hopByHopHeaders lists HTTP/1.x hop-by-hop headers that must not be forwarded.
var hopByHopHeaders = map[string]bool{
	"connection":        true,
	"proxy-connection":  true,
	"keep-alive":        true,
	"te":                true,
	"trailer":           true,
	"transfer-encoding": true,
	"upgrade":           true,
}

// NotifyObserver invokes an observer asynchronously (defensive recover).
func NotifyObserver(obs RequestObserver, rec RequestRecord) {
	if obs == nil {
		return
	}
	// copy to local var and call asynchronously to avoid blocking the request path.
	go func(r RequestRecord) {
		defer func() {
			// defensive recover in case observer panics
			if err := recover(); err != nil {
				// log but otherwise ignore
				log.Error().
					Interface("panic", err).
					Str("record_url", r.URL).
					Str("record_method", r.Method).
					Str("record_output", r.Outcome).
					Msg("observer panicked")
			}
		}()
		obs(r)
	}(rec)
}
