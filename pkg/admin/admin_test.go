package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleHealth(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)

	HandleHealth(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "should return 200 OK")
	// Body can be empty or "ok"—don’t assert exact value.
}

func TestHandleMetricsAndStatusz(t *testing.T) {
	m := NewMetrics()

	// Seed some counters.
	m.TotalRequests = 7
	m.Hits = 4
	m.Misses = 2
	m.Inflight = 2

	// Populate in-flight list to render in /statusz.
	m.InflightList["req1"] = time.Now().Add(-2 * time.Second)
	m.InflightList["req2"] = time.Now().Add(-1 * time.Second)

	// /metrics
	rr := httptest.NewRecorder()
	HandleMetrics(rr, m)
	require.Equal(t, http.StatusOK, rr.Code, "metrics should return 200")

	body := rr.Body.String()
	assert.Contains(t, body, "cache_requests_total", "should include total requests metric")
	assert.Contains(t, body, "cache_hits_total", "should include hits metric")
	assert.Contains(t, body, "cache_misses_total", "should include misses metric")
	assert.Contains(t, body, "cache_inflight", "should include inflight gauge")
	// Basic formatting sanity
	assert.True(t, strings.Contains(body, "\n"), "prometheus format should be multiline")

	// /statusz
	rr2 := httptest.NewRecorder()
	HandleStatusz(rr2, m)
	require.Equal(t, http.StatusOK, rr2.Code, "statusz should return 200")

	html := rr2.Body.String()
	assert.Contains(t, html, "req1", "statusz should list inflight request keys")
	assert.Contains(t, html, "req2", "statusz should list inflight request keys")
	assert.Contains(t, html, "<table", "statusz should render an HTML table")
}
