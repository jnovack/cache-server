// pkg/socks/capture_store_test.go
package socks

import (
	"testing"
	"time"

	"github.com/jnovack/cache-server/pkg/cacheproxy"
)

func TestCaptureStore_AddListClear(t *testing.T) {
	cs := NewCaptureStore(2)

	cs.Add(cacheproxy.RequestRecord{URL: "a"})
	cs.Add(cacheproxy.RequestRecord{URL: "b"})
	cs.Add(cacheproxy.RequestRecord{URL: "c"}) // should evict "a"

	got := cs.List()
	if len(got) != 2 {
		t.Fatalf("expected 2 entries after overflow, got %d", len(got))
	}
	if got[0].URL != "b" || got[1].URL != "c" {
		t.Fatalf("unexpected entries order: %+v", got)
	}

	cs.Clear()
	if l := len(cs.List()); l != 0 {
		t.Fatalf("expected 0 entries after Clear(), got %d", l)
	}
}

func TestAttachCaptureStore_Chaining(t *testing.T) {
	s := &Server{}
	cs := NewCaptureStore(10)
	// Simulate a pre-existing observer which records something externally.
	called := false
	s.CacheCfg.RequestObserver = func(r cacheproxy.RequestRecord) {
		// mark called and leave
		called = true
	}
	// Attach the store - should chain
	s.AttachCaptureStore(cs)

	// Call the configured observer
	if s.CacheCfg.RequestObserver == nil {
		t.Fatalf("expected RequestObserver to be set")
	}
	rec := cacheproxy.RequestRecord{URL: "x", Time: time.Now()}
	s.CacheCfg.RequestObserver(rec)

	// allow potential goroutines to finish (observer is synchronous here)
	time.Sleep(10 * time.Millisecond)

	if !called {
		t.Fatalf("expected previous observer to be called")
	}

	ent := cs.List()
	if len(ent) != 1 {
		t.Fatalf("expected store to capture 1 entry, got %d", len(ent))
	}
	if ent[0].URL != "x" {
		t.Fatalf("unexpected stored URL: %s", ent[0].URL)
	}
}
