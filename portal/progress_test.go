package portal

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/auth"
)

// TestCountingSeeker_SeekReportsDeltaNotRawCount is the unit-level check on
// the byte accounting the storage-seam regression test in submit_test.go
// doesn't itself exercise: the AWS SDK's retry middleware rewinds to 0 and
// re-reads the whole body after a transient failure. A wrapper that only
// ever added on Read would double the published count for every retried
// byte; reporting Seek's delta instead keeps the published total equal to
// the wrapped reader's actual current offset.
func TestCountingSeeker_SeekReportsDeltaNotRawCount(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 10)
	var total int64
	cs := &countingSeeker{r: bytes.NewReader(data), add: func(n int64) { total += n }}

	buf := make([]byte, 10)
	if n, err := cs.Read(buf); err != nil || n != 10 {
		t.Fatalf("first read: n=%d err=%v, want 10 bytes, no error", n, err)
	}
	if total != 10 {
		t.Fatalf("after first read: total=%d, want 10", total)
	}

	if _, err := cs.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	if total != 0 {
		t.Fatalf("after rewind to 0: total=%d, want 0 (published count tracks the current offset)", total)
	}

	if n, err := cs.Read(buf); err != nil || n != 10 {
		t.Fatalf("re-read: n=%d err=%v, want 10 bytes, no error", n, err)
	}
	if total != 10 {
		t.Fatalf("after re-read: total=%d, want 10, not 20 — a naive add-only wrapper would double-count the retry", total)
	}
}

func TestProgressTracker_BeginGetDone(t *testing.T) {
	tracker := NewProgressTracker()

	if _, ok := tracker.Get("g1alice"); ok {
		t.Fatal("Get reported progress before anything began")
	}

	h := tracker.Begin("g1alice")
	got, ok := tracker.Get("g1alice")
	if !ok {
		t.Fatal("Get reported nothing after Begin")
	}
	if got.PhaseStartedAt.IsZero() {
		t.Error("PhaseStartedAt is zero, want the time Begin ran")
	}

	h.Done()
	if _, ok := tracker.Get("g1alice"); ok {
		t.Error("Get still reported progress after Done")
	}
}

func TestProgressTracker_PhaseResetsBytesAndSetsTotal(t *testing.T) {
	tracker := NewProgressTracker()
	h := tracker.Begin("g1alice")

	h.Phase(PhaseScanning, 0)
	h.Add(100)
	h.Add(50)

	got, _ := tracker.Get("g1alice")
	if got.Phase != PhaseScanning || got.Bytes != 150 || got.Total != 0 {
		t.Fatalf("after scanning: %+v, want {Phase:scanning Bytes:150 Total:0}", got)
	}

	// A new phase starts its own count: carrying the scan's bytes into the
	// storing phase would show a store as instantly over its own total.
	h.Phase(PhaseStoring, 2048)
	got, _ = tracker.Get("g1alice")
	if got.Phase != PhaseStoring || got.Bytes != 0 || got.Total != 2048 {
		t.Fatalf("after storing: %+v, want {Phase:storing Bytes:0 Total:2048}", got)
	}
}

func TestProgressTracker_OperatorsAreIsolated(t *testing.T) {
	// This is the authorization property the endpoint relies on, so it is
	// asserted here directly rather than inferred from handler behaviour.
	tracker := NewProgressTracker()

	alice := tracker.Begin("g1alice")
	bob := tracker.Begin("g1bob")
	alice.Phase(PhaseScanning, 0)
	alice.Add(999)
	bob.Phase(PhaseStoring, 10)

	gotAlice, _ := tracker.Get("g1alice")
	gotBob, _ := tracker.Get("g1bob")
	if gotAlice.Phase != PhaseScanning || gotAlice.Bytes != 999 {
		t.Errorf("alice = %+v, want her own scanning progress", gotAlice)
	}
	if gotBob.Phase != PhaseStoring || gotBob.Bytes != 0 {
		t.Errorf("bob = %+v, want his own storing progress, not alice's", gotBob)
	}

	alice.Done()
	if _, ok := tracker.Get("g1bob"); !ok {
		t.Error("alice's Done removed bob's entry")
	}
}

func TestProgressTracker_SecondBeginReplacesTheFirst(t *testing.T) {
	tracker := NewProgressTracker()

	first := tracker.Begin("g1alice")
	first.Phase(PhaseScanning, 0)
	first.Add(500)

	tracker.Begin("g1alice")
	got, ok := tracker.Get("g1alice")
	if !ok {
		t.Fatal("Get reported nothing after the second Begin")
	}
	if got.Bytes != 0 || got.Phase != "" {
		t.Errorf("got %+v, want a fresh entry: the second submission must not inherit the first's counters", got)
	}
}

func TestProgressTracker_SupersededHandleWritesAreInert(t *testing.T) {
	// A superseded handle's Phase and Add must not reach into the entry a
	// later Begin created — that entry belongs to a different submission.
	tracker := NewProgressTracker()

	first := tracker.Begin("g1alice")
	second := tracker.Begin("g1alice")
	second.Phase(PhaseScanning, 0)
	second.Add(10)

	first.Phase(PhaseStoring, 999)
	first.Add(500)

	got, ok := tracker.Get("g1alice")
	if !ok {
		t.Fatal("Get reported nothing after the second Begin")
	}
	if got.Phase != PhaseScanning || got.Bytes != 10 || got.Total != 0 {
		t.Errorf("got %+v, want the second submission's progress untouched by the first's stale writes", got)
	}
}

func TestProgressTracker_SupersededHandleDoneDoesNotRemoveTheNewEntry(t *testing.T) {
	tracker := NewProgressTracker()

	first := tracker.Begin("g1alice")
	second := tracker.Begin("g1alice")

	first.Done()
	if _, ok := tracker.Get("g1alice"); !ok {
		t.Error("the superseded handle's Done removed the newer submission's entry")
	}

	second.Done()
	if _, ok := tracker.Get("g1alice"); ok {
		t.Error("the current handle's Done did not remove its own entry")
	}
}

func TestProgressTracker_AddIsRaceSafeUnderConcurrentGet(t *testing.T) {
	// The mutex correctness otherwise rests on code reading alone; this is
	// the test that makes `-race` meaningful for this type.
	tracker := NewProgressTracker()
	h := tracker.Begin("g1alice")

	const goroutines = 20
	const perGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				h.Add(1)
			}
		}()
	}

	// Concurrent readers exercise the mutex from the other side while the
	// writers above are still running.
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				tracker.Get("g1alice")
			}
		}
	}()

	wg.Wait()
	close(done)

	got, ok := tracker.Get("g1alice")
	if !ok {
		t.Fatal("Get reported nothing after concurrent Add calls")
	}
	if want := int64(goroutines * perGoroutine); got.Bytes != want {
		t.Errorf("got Bytes = %d, want %d", got.Bytes, want)
	}
}

func TestProgressTracker_StaleEntryIsReportedAbsent(t *testing.T) {
	// Done runs from a defer and covers every normal exit; this bounds what
	// a killed goroutine can leave behind.
	tracker := NewProgressTracker()
	now := time.Now()
	tracker.now = func() time.Time { return now }

	tracker.Begin("g1alice")
	if _, ok := tracker.Get("g1alice"); !ok {
		t.Fatal("fresh entry reported absent")
	}

	now = now.Add(progressTTL + time.Second)
	if _, ok := tracker.Get("g1alice"); ok {
		t.Error("an entry untouched for longer than progressTTL was still reported")
	}
}

func TestProgressTracker_StalenessIsRefreshedByUpdates(t *testing.T) {
	// A scan updates every window, roughly every seven seconds, so a long
	// scan must never be mistaken for an abandoned one.
	tracker := NewProgressTracker()
	now := time.Now()
	tracker.now = func() time.Time { return now }

	h := tracker.Begin("g1alice")
	for i := 0; i < 5; i++ {
		now = now.Add(progressTTL - time.Second)
		h.Add(1)
	}
	now = now.Add(time.Second)

	if _, ok := tracker.Get("g1alice"); !ok {
		t.Error("an entry updated throughout was dropped as stale")
	}
}

func TestProgressTracker_NilIsUsable(t *testing.T) {
	// cmd/portal-dev and most handler tests run with no tracker at all, so
	// every one of these must be a no-op rather than a panic.
	var tracker *ProgressTracker

	h := tracker.Begin("g1alice")
	h.Phase(PhaseScanning, 0)
	h.Add(10)
	h.Done()

	if _, ok := tracker.Get("g1alice"); ok {
		t.Error("a nil tracker reported progress")
	}
}

func TestProgressHandler_RequiresASession(t *testing.T) {
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	handler := ProgressHandler(sessions, NewProgressTracker())

	req := httptest.NewRequest(http.MethodGet, "/submit/progress", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 without a session", rec.Code)
	}
}

func TestProgressHandler_RejectsNonGET(t *testing.T) {
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	handler := ProgressHandler(sessions, NewProgressTracker())

	req := httptest.NewRequest(http.MethodPost, "/submit/progress", nil)
	req.Header.Set("Authorization", "Bearer "+sessions.Issue(testOperatorAddr()))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestProgressHandler_NotFoundWhenNothingInFlight(t *testing.T) {
	// The page polls from the moment its last byte leaves the browser, which
	// is before the server has finished reading the body — so this is a
	// normal, frequent answer, not an error condition.
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	handler := ProgressHandler(sessions, NewProgressTracker())

	req := httptest.NewRequest(http.MethodGet, "/submit/progress", nil)
	req.Header.Set("Authorization", "Bearer "+sessions.Issue(testOperatorAddr()))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestProgressHandler_ServesTheOperatorsProgress(t *testing.T) {
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	tracker := NewProgressTracker()
	addr := testOperatorAddr()

	h := tracker.Begin(addr.String())
	h.Phase(PhaseStoring, 2048)
	h.Add(512)

	handler := ProgressHandler(sessions, tracker)
	req := httptest.NewRequest(http.MethodGet, "/submit/progress", nil)
	req.Header.Set("Authorization", "Bearer "+sessions.Issue(addr))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got Progress
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding body %q: %v", rec.Body.String(), err)
	}
	if got.Phase != PhaseStoring || got.Bytes != 512 || got.Total != 2048 {
		t.Errorf("got %+v, want {Phase:storing Bytes:512 Total:2048}", got)
	}
	if got.PhaseStartedAt.IsZero() {
		t.Error("PhaseStartedAt is zero; the page needs it to compute elapsed time")
	}
}

func TestProgressHandler_NeverServesAnotherOperatorsProgress(t *testing.T) {
	// The session is what selects the row, so this is the whole of the
	// endpoint's authorization. Assert it directly.
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	tracker := NewProgressTracker()

	other := tracker.Begin("g1someoneelse")
	other.Phase(PhaseScanning, 0)
	other.Add(4096)

	handler := ProgressHandler(sessions, tracker)
	req := httptest.NewRequest(http.MethodGet, "/submit/progress", nil)
	req.Header.Set("Authorization", "Bearer "+sessions.Issue(testOperatorAddr()))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: a session must only ever reach its own row", rec.Code)
	}
}
