package portal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingHandler reports how many requests are inside it at once and holds
// each one until release is closed, which is what lets a test observe the
// limit rather than infer it from timing.
type blockingHandler struct {
	entered chan struct{}
	release chan struct{}

	mu      sync.Mutex
	inside  int
	highest int
}

func newBlockingHandler() *blockingHandler {
	return &blockingHandler{
		entered: make(chan struct{}, 64),
		release: make(chan struct{}),
	}
}

func (h *blockingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.inside++
	if h.inside > h.highest {
		h.highest = h.inside
	}
	h.mu.Unlock()

	h.entered <- struct{}{}
	<-h.release

	h.mu.Lock()
	h.inside--
	h.mu.Unlock()
}

func (h *blockingHandler) peak() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.highest
}

func TestLimitSubmissionsCapsConcurrency(t *testing.T) {
	inner := newBlockingHandler()
	// A wait long enough that nothing in this test reaches the timeout: the
	// assertion is about the cap, not about rejection.
	limited := LimitSubmissions(2, time.Minute, inner)

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			limited.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/submit", nil))
		}()
	}

	// Two requests get in; the other three must still be waiting.
	for range 2 {
		select {
		case <-inner.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for the first two requests to enter the handler")
		}
	}

	select {
	case <-inner.entered:
		t.Fatal("a third request entered the handler while both slots were held")
	case <-time.After(100 * time.Millisecond):
	}

	close(inner.release)
	wg.Wait()

	if peak := inner.peak(); peak > 2 {
		t.Errorf("peak concurrency inside the handler = %d, want at most 2", peak)
	}
}

func TestLimitSubmissionsReleasesSlots(t *testing.T) {
	var served atomic.Int64
	limited := LimitSubmissions(1, time.Minute, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
	}))

	// Sequential requests through a limit of one: every slot must come back,
	// or the second call would block until the wait elapsed.
	for range 3 {
		rec := httptest.NewRecorder()
		limited.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/submit", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 — the slot was not released", rec.Code)
		}
	}

	if got := served.Load(); got != 3 {
		t.Errorf("handler ran %d times, want 3", got)
	}
}

func TestLimitSubmissionsRejectsAfterWait(t *testing.T) {
	inner := newBlockingHandler()
	defer close(inner.release)

	limited := LimitSubmissions(1, 50*time.Millisecond, inner)

	go limited.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/submit", nil))
	select {
	case <-inner.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first request to occupy the only slot")
	}

	rec := httptest.NewRecorder()
	limited.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/submit", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if retry := rec.Header().Get("Retry-After"); retry == "" {
		t.Error("Retry-After header is missing, so a client has nothing to back off against")
	}

	// The upload page reads the body before it looks at the status, so a
	// rejection that is not the usual JSON shape shows as a blank error.
	var resp submitResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("rejection body is not the submitResponse JSON shape: %v (body %q)", err, rec.Body.String())
	}
	if resp.OK {
		t.Error("rejection reported ok:true")
	}
	if resp.Error == "" {
		t.Error("rejection carries no error message for the page to display")
	}
}

func TestLimitSubmissionsAbandonsOnClientDisconnect(t *testing.T) {
	inner := newBlockingHandler()
	defer close(inner.release)

	limited := LimitSubmissions(1, time.Minute, inner)

	go limited.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/submit", nil))
	select {
	case <-inner.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first request to occupy the only slot")
	}

	ctx, cancel := context.WithCancel(context.Background())
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		limited.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/submit", nil).WithContext(ctx))
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a waiting request outlived its own cancelled context")
	}

	// Nothing is written to a connection the client has already dropped.
	if rec.Body.Len() != 0 {
		t.Errorf("wrote %q to a disconnected client", rec.Body.String())
	}
}

func TestLimitSubmissionsDisabled(t *testing.T) {
	inner := newBlockingHandler()
	limited := LimitSubmissions(0, time.Minute, inner)

	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			limited.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/submit", nil))
		}()
	}

	for range 3 {
		select {
		case <-inner.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("a limit of 0 did not pass every request straight through")
		}
	}

	close(inner.release)
	wg.Wait()
}
