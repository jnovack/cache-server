package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleHealth(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	HandleHealth(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}
}

func TestHandleMetricsAndStatusz(t *testing.T) {
	m := NewMetrics()
	m.TotalRequests = 7
	m.Hits = 4
	m.Misses = 2
	m.Inflight = 2
	// populate inflight list
	m.InflightList["req1"] = time.Now().Add(-2 * time.Second)
	m.InflightList["req2"] = time.Now().Add(-1 * time.Second)

	// Metrics endpoint
	rr := httptest.NewRecorder()
	HandleMetrics(rr, m)
	if rr.Code != http.StatusOK {
		t.Fatalf("metrics: expected 200 got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "cache_hits_total") {
		t.Fatalf("metrics output missing expected metric: %s", body)
	}

	// Statusz endpoint
	rr2 := httptest.NewRecorder()
	HandleStatusz(rr2, m)
	if rr2.Code != http.StatusOK {
		t.Fatalf("statusz: expected 200 got %d", rr2.Code)
	}
	b2 := rr2.Body.String()
	if !strings.Contains(b2, "req1") || !strings.Contains(b2, "req2") {
		t.Fatalf("statusz missing inflight entries: %s", b2)
	}
}
