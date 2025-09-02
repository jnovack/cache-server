package cache

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestMetaFromHeadersMaxAgeAndExpires(t *testing.T) {
	h := http.Header{}
	h.Set("Cache-Control", "max-age=60")
	m := MetaFromHeaders(h, Meta{}, time.Duration(0))
	if m.ExpiresAt.IsZero() {
		t.Fatalf("expected ExpiresAt to be set for max-age")
	}
	// Now test Expires header overrides / coexists
	h2 := http.Header{}
	h2.Set("Expires", time.Now().Add(120*time.Second).UTC().Format(http.TimeFormat))
	m2 := MetaFromHeaders(h2, Meta{}, time.Duration(0))
	if m2.ExpiresAt.IsZero() {
		t.Fatalf("expected ExpiresAt from Expires header")
	}

	lower := time.Now().Add(119 * time.Second) // subtract 1s slack
	upper := time.Now().Add(601 * time.Second) // add 1s slack

	// Test max-age header overrides
	h3 := http.Header{}
	h3.Set("Cache-Control", "max-age=60")
	m3 := MetaFromHeaders(h3, Meta{}, time.Duration(600*time.Second))
	if !(m3.ExpiresAt.After(lower) && (m3.ExpiresAt.Equal(upper) || m3.ExpiresAt.Before(upper))) {
		t.Fatalf("expected ExpiresAt between %v and %v, got %v", lower, upper, m3.ExpiresAt)
	}

	// Now test Expires header overrides / coexists
	h4 := http.Header{}
	h4.Set("Expires", time.Now().Add(60*time.Second).UTC().Format(http.TimeFormat))
	m4 := MetaFromHeaders(h4, Meta{}, time.Duration(600*time.Second))
	if !(m4.ExpiresAt.After(lower) && (m4.ExpiresAt.Equal(upper) || m4.ExpiresAt.Before(upper))) {
		t.Fatalf("expected ExpiresAt between %v and %v, got %v", lower, upper, m4.ExpiresAt)
	}
}

func TestMetaNoStoreNoCache(t *testing.T) {
	h := http.Header{}
	h.Set("Cache-Control", "no-store, no-cache")
	m := MetaFromHeaders(h, Meta{}, time.Duration(0))
	if !m.NoStore || !m.NoCache {
		t.Fatalf("expected NoStore and NoCache to be true")
	}
}

func TestReadWriteMetaRoundTrip(t *testing.T) {
	td := t.TempDir()
	metaPath := filepath.Join(td, "m.meta.json")
	m := Meta{ETag: "tag1", ContentType: "image/png"}
	if err := WriteMeta(metaPath, m); err != nil {
		t.Fatalf("WriteMeta error: %v", err)
	}
	got := ReadMeta(metaPath)
	if got.ETag != "tag1" || got.ContentType != "image/png" {
		t.Fatalf("roundtrip mismatch: got %+v", got)
	}
	// IsFresh false because ExpiresAt zero
	if IsFresh(got) {
		t.Fatalf("expected IsFresh false for zero ExpiresAt")
	}
}
