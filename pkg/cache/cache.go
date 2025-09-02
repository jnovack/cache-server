// Package cache contains small helpers for cache metadata and header->meta conversions.
package cache

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Meta struct {
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
	NoStore      bool      `json:"no_store,omitempty"`
	NoCache      bool      `json:"no_cache,omitempty"`
	SetCookies   []string  `json:"-"` // ephemeral: Set-Cookie lines from live origin response (not cached)
	ContentType  string    `json:"content_type,omitempty"`
}

// ReadMeta reads metadata JSON from path; returns zero Meta on error.
func ReadMeta(path string) Meta {
	var m Meta
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// WriteMeta writes metadata to path atomically.
func WriteMeta(path string, m Meta) error {
	m.FetchedAt = time.Now()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// IsFresh returns true if the meta indicates still-fresh content.
func IsFresh(m Meta) bool {
	if m.NoCache {
		return false
	}
	if m.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().Before(m.ExpiresAt)
}

// MetaFromHeaders builds Meta from HTTP headers, using previous meta as fallback for missing fields.
func MetaFromHeaders(h http.Header, prev Meta, minTTL time.Duration) Meta {
	m := Meta{
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
			case p == "no-cache":
				m.NoCache = true
			case strings.HasPrefix(p, "max-age="):
				if secs, err := strconv.Atoi(strings.TrimPrefix(p, "max-age=")); err == nil {
					maxAge := max(time.Duration(secs)*time.Second, minTTL)
					m.ExpiresAt = m.FetchedAt.Add(maxAge)
				}
			}
		}
	}
	if exp := h.Get("Expires"); exp != "" {
		if t, err := http.ParseTime(exp); err == nil {
			if m.ExpiresAt.IsZero() || t.After(m.ExpiresAt) {
				// setting from expires header
				later := t // t = expires header
				if time.Now().Add(minTTL).After(t) {
					later = time.Now().Add(minTTL)
				}
				m.ExpiresAt = later
			}
		}
	}
	return m
}

func first(h http.Header, k, fb string) string {
	if v := h.Get(k); v != "" {
		return v
	}
	return fb
}
