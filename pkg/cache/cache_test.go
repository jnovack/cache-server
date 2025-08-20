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
	m := MetaFromHeaders(h, Meta{})
	if m.ExpiresAt.IsZero() {
		t.Fatalf("expected ExpiresAt to be set for max-age")
	}
	// Now test Expires header overrides / coexists
	h2 := http.Header{}
	h2.Set("Expires", time.Now().Add(120*time.Second).UTC().Format(http.TimeFormat))
	m2 := MetaFromHeaders(h2, Meta{})
	if m2.ExpiresAt.IsZero() {
		t.Fatalf("expected ExpiresAt from Expires header")
	}
}

func TestMetaNoStoreNoCache(t *testing.T) {
	h := http.Header{}
	h.Set("Cache-Control", "no-store, no-cache")
	m := MetaFromHeaders(h, Meta{})
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
