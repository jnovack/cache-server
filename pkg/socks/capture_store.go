// pkg/socks/capture_store.go
package socks

import (
	"sync"

	"github.com/jnovack/cache-server/pkg/cacheproxy"
)

// CaptureStore is a concurrency-safe in-memory store for recent RequestRecord entries.
type CaptureStore struct {
	mu      sync.Mutex
	entries []cacheproxy.RequestRecord
	max     int
}

// NewCaptureStore creates a CaptureStore with capacity maxEntries.
func NewCaptureStore(maxEntries int) *CaptureStore {
	if maxEntries <= 0 {
		maxEntries = 1000
	}
	return &CaptureStore{max: maxEntries}
}

// Add adds a record to the store.
func (c *CaptureStore) Add(r cacheproxy.RequestRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		// evict the oldest entry
		c.entries = c.entries[1:]
	}
	c.entries = append(c.entries, r)
}

// List returns a snapshot copy of entries.
func (c *CaptureStore) List() []cacheproxy.RequestRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]cacheproxy.RequestRecord, len(c.entries))
	copy(out, c.entries)
	return out
}

// Clear empties the store.
func (c *CaptureStore) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = nil
}
