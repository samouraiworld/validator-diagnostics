package portal

import (
	"sync"
	"testing"
	"time"
)

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
