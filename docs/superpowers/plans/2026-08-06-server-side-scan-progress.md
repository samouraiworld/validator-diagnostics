# Server-Side Scan Progress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the upload page show what the server is actually doing during the eight minutes a 2.4 GB submission spends being validated, scanned, stored and scored, so a working scan stops looking like a hang.

**Architecture:** An in-memory tracker in `portal`, keyed by authenticated operator address, holds one in-flight submission's phase and byte count. `SubmitHandler` publishes transitions and wraps its scanner and its store reader in counting decorators. A new `GET /submit/progress` endpoint serves the entry to the page, which polls it every two seconds on a second connection while the upload request is still in flight.

**Tech Stack:** Go 1.26.1, standard library only. Dependency-free vanilla JS with no build step or test harness.

**Design spec:** `docs/superpowers/specs/2026-08-06-server-side-scan-progress-design.md`

## Global Constraints

- Go 1.26.1, no new module dependencies. Standard library plus this repo's own packages.
- **The order validate → scan → store → score does not change.** Everything here is observation placed alongside work that already happened in this sequence. A change to that ordering is a defect, not a refactor.
- **Nil is usable throughout.** `Begin` on a nil `*ProgressTracker` returns a nil `*ProgressHandle`; every `ProgressHandle` method tolerates a nil receiver by doing nothing. A `SubmitHandler` built without a tracker needs no guard at any call site. `cmd/portal-dev` and most existing tests run exactly that way.
- **A polling failure must be invisible.** On 404, on any error status, or on a network failure, the page keeps what it is showing and retries on the next tick. If polling never succeeds, the page degrades exactly to today's behaviour.
- **No invented percentage for the scan.** The log's decompressed size is unknown until it is decompressed. The scanning phase reports absolute numbers under an indeterminate bar. Only `storing`, whose total is `header.Size`, gets a percentage.
- The tracker is written by the submit handler's goroutine and read by the poll handler's: every test run includes `-race`.
- UI strings stay in English, matching the rest of the page.
- `.env` is gitignored — never `git add` it. An unrelated pre-existing `.gitignore` modification is in the working tree; leave it alone and never stage it. Note it currently ignores `/docs/**`, so committing files under `docs/` needs `git add -f`.
- This codebase comments heavily and deliberately; comments explaining *why* are part of the deliverable.

---

## File Structure

**Created:**
- `portal/progress.go` — the `Phase` constants, `Progress`, `ProgressTracker`, `ProgressHandle`, `ProgressHandler`, and the two counting decorators. One responsibility: knowing and publishing how far an in-flight submission has got. Roughly 180 lines.
- `portal/progress_test.go` — tracker semantics, nil semantics, staleness, operator isolation, and the endpoint.

**Modified:**
- `portal/submit.go` — the `Progress` field, `Begin`/`defer Done`, four `Phase` calls, and the two decorator wrappings.
- `portal/submit_test.go` — the mid-scan visibility test.
- `cmd/portal/main.go` — construct the tracker, add it to `muxDeps` and `submitHandlerFor`, register the route.
- `cmd/portal/main_test.go` — wiring and routing assertions.
- `cmd/portal/static/index.html` — one `<p id="upload-detail">`.
- `cmd/portal/static/portal.js` — polling, rendering, and the phase announcement.

---

### Task 1: The progress tracker

**Files:**
- Create: `portal/progress.go`
- Test: `portal/progress_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `portal.Phase` (a `string` type) with `PhaseValidating`, `PhaseScanning`, `PhaseStoring`, `PhaseScoring`
  - `portal.Progress` — `struct { Phase Phase; Bytes, Total int64; PhaseStartedAt time.Time }` with JSON tags `phase`, `bytes`, `total,omitempty`, `phase_started_at`
  - `portal.ProgressTracker` and `func NewProgressTracker() *ProgressTracker`
  - `func (t *ProgressTracker) Begin(operator string) *ProgressHandle`
  - `func (t *ProgressTracker) Get(operator string) (Progress, bool)`
  - `func (h *ProgressHandle) Phase(p Phase, total int64)`
  - `func (h *ProgressHandle) Add(n int64)`
  - `func (h *ProgressHandle) Done()`

- [ ] **Step 1: Write the failing tests**

Create `portal/progress_test.go`:

```go
package portal

import (
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./portal/ -run TestProgressTracker -v`
Expected: FAIL to compile — `undefined: NewProgressTracker`, `undefined: PhaseScanning`, `undefined: progressTTL`.

- [ ] **Step 3: Write `portal/progress.go`**

```go
package portal

import (
	"sync"
	"time"
)

// Phase names the server-side stage a submission has reached. The transfer
// itself is deliberately absent: the browser observes that directly through
// XMLHttpRequest's upload progress events, and only the work that happens
// after the last byte arrives is invisible to it.
type Phase string

const (
	PhaseValidating Phase = "validating"
	PhaseScanning   Phase = "scanning"
	PhaseStoring    Phase = "storing"
	PhaseScoring    Phase = "scoring"
)

// progressTTL bounds how long an entry survives without an update. Done runs
// from a defer and covers every normal exit including a panic, so this only
// catches a handler goroutine killed outright.
//
// Five minutes rather than something tighter because the validating phase
// reports nothing while it runs and can legitimately be silent for a minute
// on a large archive. The scanning phase, by contrast, updates every window —
// roughly every seven seconds.
const progressTTL = 5 * time.Minute

// Progress is one in-flight submission's server-side state, as served by
// ProgressHandler.
type Progress struct {
	Phase Phase `json:"phase"`

	// Bytes is work completed in the current phase, reset at each
	// transition. Total is the phase's expected size, or 0 when it cannot be
	// known ahead of time — the scanning phase has no denominator, because
	// the log's decompressed size is not known until it is decompressed.
	Bytes int64 `json:"bytes"`
	Total int64 `json:"total,omitempty"`

	// PhaseStartedAt lets the page compute elapsed time and throughput
	// without having to assume it started polling when the phase did.
	PhaseStartedAt time.Time `json:"phase_started_at"`
}

// ProgressTracker holds progress for in-flight submissions, keyed by
// authenticated operator address rather than by a generated submission ID.
// The session that reaches ProgressHandler is what selects the row, so an
// operator can only ever read their own progress and there is no identifier
// to plumb through the browser and the handler.
//
// The cost of that choice is one degraded case: an operator running two
// submissions at once gets a display driven by whichever wrote last, and the
// first handle's Done removes the second's entry. Both submissions still
// complete and record correctly — only the display is affected.
//
// The zero value is not usable; call NewProgressTracker. A nil
// *ProgressTracker, however, is: it behaves as "reporting disabled".
type ProgressTracker struct {
	mu       sync.Mutex
	inflight map[string]*progressEntry

	// now is swappable so the staleness tests don't have to sleep.
	now func() time.Time
}

type progressEntry struct {
	progress   Progress
	lastUpdate time.Time
}

func NewProgressTracker() *ProgressTracker {
	return &ProgressTracker{
		inflight: make(map[string]*progressEntry),
		now:      time.Now,
	}
}

// ProgressHandle publishes into the entry Begin created. Every method
// tolerates a nil receiver, so a handler built without a tracker needs no
// guard at any call site.
type ProgressHandle struct {
	tracker  *ProgressTracker
	operator string
}

// Begin starts tracking a submission for operator, replacing any entry that
// operator already had. Callers must defer the returned handle's Done.
func (t *ProgressTracker) Begin(operator string) *ProgressHandle {
	if t == nil {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	t.inflight[operator] = &progressEntry{
		progress:   Progress{PhaseStartedAt: now},
		lastUpdate: now,
	}
	return &ProgressHandle{tracker: t, operator: operator}
}

// Get returns operator's current progress. ok is false when nothing is in
// flight — which includes the window between the browser handing over its
// last byte and the server finishing reading the request body, so callers
// must treat "not found" as "not yet", not as an error.
func (t *ProgressTracker) Get(operator string) (Progress, bool) {
	if t == nil {
		return Progress{}, false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.inflight[operator]
	if !ok {
		return Progress{}, false
	}
	if t.now().Sub(e.lastUpdate) > progressTTL {
		delete(t.inflight, operator)
		return Progress{}, false
	}
	return e.progress, true
}

// Phase moves to p and resets the byte counter, because each phase counts its
// own work: carrying the scan's bytes into the storing phase would show a
// store as instantly past its own total. total is the phase's expected size,
// or 0 when it cannot be known.
func (h *ProgressHandle) Phase(p Phase, total int64) {
	h.update(func(e *progressEntry, now time.Time) {
		e.progress = Progress{Phase: p, Total: total, PhaseStartedAt: now}
	})
}

// Add accumulates bytes within the current phase.
func (h *ProgressHandle) Add(n int64) {
	h.update(func(e *progressEntry, now time.Time) {
		e.progress.Bytes += n
	})
}

// Done removes the entry. Safe to call twice, and safe on a nil handle.
func (h *ProgressHandle) Done() {
	if h == nil {
		return
	}

	h.tracker.mu.Lock()
	defer h.tracker.mu.Unlock()
	delete(h.tracker.inflight, h.operator)
}

// update applies f to this handle's entry under the tracker's lock, and
// refreshes the staleness clock. It is a no-op on a nil handle, and on an
// entry that no longer exists — which is what a handle outliving its own
// Done looks like.
func (h *ProgressHandle) update(f func(e *progressEntry, now time.Time)) {
	if h == nil {
		return
	}

	h.tracker.mu.Lock()
	defer h.tracker.mu.Unlock()

	e, ok := h.tracker.inflight[h.operator]
	if !ok {
		return
	}
	now := h.tracker.now()
	f(e, now)
	e.lastUpdate = now
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./portal/ -run TestProgressTracker -race -v`
Expected: PASS, all seven.

- [ ] **Step 5: Run the whole package**

Run: `go test ./portal/ -race`
Expected: PASS — nothing else in the package references any of this yet.

- [ ] **Step 6: Commit**

```bash
git add portal/progress.go portal/progress_test.go
git commit -m "Track how far an in-flight submission has got, per operator"
```

---

### Task 2: The progress endpoint

**Files:**
- Modify: `portal/progress.go` (append the handler)
- Test: `portal/progress_test.go` (append)

**Interfaces:**
- Consumes: `ProgressTracker`, `Progress`, `Phase` constants from Task 1.
- Produces: `func ProgressHandler(sessions *auth.SessionSigner, tracker *ProgressTracker) http.HandlerFunc`, serving `GET /submit/progress`.

- [ ] **Step 1: Write the failing tests**

Append to `portal/progress_test.go`:

```go
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
```

Add `"encoding/json"`, `"net/http"`, `"net/http/httptest"` and `"github.com/samourai/validator-diagnostics/auth"` to `portal/progress_test.go`'s imports. `testOperatorAddr()` already exists in the package's test files — do not redefine it.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./portal/ -run TestProgressHandler -v`
Expected: FAIL to compile — `undefined: ProgressHandler`.

- [ ] **Step 3: Append the handler to `portal/progress.go`**

```go
// ProgressHandler serves GET /submit/progress: the server-side progress of
// the calling operator's in-flight submission, for the upload page to poll
// while its POST /submit is still running.
//
// It exists as a separate request because the submission's own response
// cannot carry progress: its status is not decided until the very end — 422
// for an infected archive, 503 for a scanner failure, 400 for a log that
// cannot be decompressed — and a streaming body would force the status to be
// written first, collapsing all of those into a 200.
//
// 404 is a normal answer, not an error: the page starts polling when its last
// byte leaves the browser, which is before the server has finished reading
// the request body, and it keeps polling until the response lands.
func ProgressHandler(sessions *auth.SessionSigner, tracker *ProgressTracker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		addr, err := auth.RequireSession(sessions, r)
		if err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		progress, ok := tracker.Get(addr.String())
		if !ok {
			http.Error(w, "no submission in flight", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(progress)
	}
}
```

Add `"encoding/json"`, `"net/http"` and `"github.com/samourai/validator-diagnostics/auth"` to `portal/progress.go`'s imports.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./portal/ -run TestProgress -race -v`
Expected: PASS, twelve tests across both groups.

- [ ] **Step 5: Commit**

```bash
git add portal/progress.go portal/progress_test.go
git commit -m "Serve an operator's in-flight submission progress"
```

---

### Task 3: Publish progress from the submit handler

**Files:**
- Modify: `portal/progress.go` (append the two decorators), `portal/submit.go`
- Test: `portal/submit_test.go`

**Interfaces:**
- Consumes: `ProgressTracker`, `ProgressHandle`, the `Phase` constants (Tasks 1–2); the existing `scanArchive(ctx, file, opts, metadata, scanner, budget)` and `clamav.Scanner`.
- Produces:
  - `portal.SubmitHandler.Progress *ProgressTracker`
  - `countingScanner` and `countingReader`, unexported, used only here.

- [ ] **Step 1: Write the failing test**

Append to `portal/submit_test.go`:

```go
// blockingScanner lets a test observe the handler *during* the scan. Without
// it every assertion about progress would run after the handler returned, by
// which point the deferred Done has already removed the entry — and a test
// that passes against a handler publishing nothing at all proves nothing.
type blockingScanner struct {
	mu       sync.Mutex
	calls    int
	scanning chan struct{} // closed once the log's window is being scanned
	release  chan struct{} // closed by the test to let the handler finish
}

func (s *blockingScanner) Scan(ctx context.Context, r io.Reader) (clamav.Verdict, error) {
	if _, err := io.ReadAll(r); err != nil {
		return clamav.Verdict{}, err
	}

	s.mu.Lock()
	s.calls++
	n := s.calls
	s.mu.Unlock()

	// Call 1 is metadata.json; call 2 is the log's only window, which is the
	// phase this test is about.
	if n == 2 {
		close(s.scanning)
		<-s.release
	}
	return clamav.Verdict{}, nil
}

func TestSubmitHandler_PublishesProgressWhileScanning(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	tracker := NewProgressTracker()
	scanner := &blockingScanner{scanning: make(chan struct{}), release: make(chan struct{})}

	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     newFakeStore(),
		AVScanner: scanner,
		Progress:  tracker,
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Built here, not in the goroutine below: these helpers call t.Fatalf,
	// which is only valid on the test's own goroutine.
	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", buildValidArchive(t, operatorAddr.String()))
	token := sessions.Issue(operatorAddr)

	status := make(chan int, 1)
	go func() {
		req, err := http.NewRequest(http.MethodPost, srv.URL, body)
		if err != nil {
			status <- 0
			return
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			status <- 0
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		status <- resp.StatusCode
	}()

	select {
	case <-scanner.scanning:
	case <-time.After(10 * time.Second):
		t.Fatal("the log scan never started")
	}

	got, ok := tracker.Get(operatorAddr.String())
	if !ok {
		t.Fatal("no progress published while the scan was running")
	}
	if got.Phase != PhaseScanning {
		t.Errorf("Phase = %q, want %q", got.Phase, PhaseScanning)
	}
	if got.Bytes == 0 {
		t.Error("Bytes = 0 mid-scan, want the bytes already streamed to the scanner")
	}

	close(scanner.release)
	if code := <-status; code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if _, ok := tracker.Get(operatorAddr.String()); ok {
		t.Error("progress outlived the handler; the deferred Done must remove it")
	}
}

func TestSubmitHandler_WithoutATrackerBehavesAsBefore(t *testing.T) {
	// cmd/portal-dev builds the handler this way, and so does every other
	// test in this file. A nil tracker must be a no-op, not a panic.
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)

	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     newFakeStore(),
		AVScanner: &capturingScanner{},
		// Progress deliberately nil.
	}

	if status := submitArchive(t, handler, sessions, operatorAddr, buildValidArchive(t, operatorAddr.String())); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
}
```

Add `"sync"` to `portal/submit_test.go`'s imports if it is not already there.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./portal/ -run TestSubmitHandler_PublishesProgress -v`
Expected: FAIL to compile — `unknown field Progress in struct literal of type SubmitHandler`.

- [ ] **Step 3: Append the counting decorators to `portal/progress.go`**

```go
// countingScanner reports how much of each window reaches the wrapped
// Scanner, so a scan in progress can be shown advancing rather than as a
// frozen bar. It exists here rather than in the clamav package because
// counting is this package's concern: clamav.WindowedScanner's contract is
// unchanged by it.
//
// It counts bytes streamed to the antivirus, which includes the 1 MiB
// re-sent at each window boundary — roughly 0.1% more than the Coverage the
// submission finally records. That skew is deliberate: this is a liveness
// indicator, and Coverage.Bytes remains the authoritative number, both on the
// log entry and on the dashboard badge.
type countingScanner struct {
	inner clamav.Scanner
	add   func(int64)
}

func (s countingScanner) Scan(ctx context.Context, r io.Reader) (clamav.Verdict, error) {
	return s.inner.Scan(ctx, &countingReader{r: r, add: s.add})
}

// countingReader reports bytes as they are read, for phases whose progress is
// otherwise invisible from outside.
type countingReader struct {
	r   io.Reader
	add func(int64)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.add(int64(n))
	}
	return n, err
}
```

Add `"context"`, `"io"` and `"github.com/samourai/validator-diagnostics/clamav"` to `portal/progress.go`'s imports.

- [ ] **Step 4: Add the field to `SubmitHandler`**

In `portal/submit.go`, beside the other optional collaborators:

```go
	// Progress publishes server-side progress for the upload page to poll
	// (see ProgressHandler). Optional — a nil Progress disables reporting
	// and changes nothing else about how a submission is handled.
	Progress *ProgressTracker
```

- [ ] **Step 5: Begin tracking once the server-side work starts**

In `ServeHTTP`, immediately after `defer r.MultipartForm.RemoveAll()`:

```go
	// Tracking starts here, not earlier: everything before this was reading
	// the request body, which the browser already observes through its own
	// upload progress events. The page polls from the moment its last byte
	// leaves, so it will see 404s until this line runs — which is correct,
	// and which it treats as "not yet".
	progress := h.Progress.Begin(operatorAddr.String())
	defer progress.Done()
```

- [ ] **Step 6: Publish the four transitions**

Each of these goes immediately before the work it names. None of them moves any existing statement.

Before `submission.ValidateArchive`:

```go
	progress.Phase(PhaseValidating, 0)
```

Inside `if h.AVScanner != nil {`, before the `scanArchive` call, and wrap the scanner:

```go
		progress.Phase(PhaseScanning, 0)
		// Always wrapped: Add on a nil handle is a no-op, so this needs no
		// guard for a handler built without a tracker.
		scanner := countingScanner{inner: h.AVScanner, add: progress.Add}
		verdict, coverage, err := scanArchive(r.Context(), file, h.ArchiveOptions, archiveResult.Metadata, scanner, h.AVScanBudget)
```

Before `h.Store.Save`, with the archive's own size as the total — this is the one phase whose denominator is known, so it is the one that gets a real percentage:

```go
	progress.Phase(PhaseStoring, header.Size)
	if err := h.Store.Save(r.Context(), header.Filename, &countingReader{r: file, add: progress.Add}, header.Size); err != nil {
```

Inside `if h.Exercise != nil {`, as its first statement:

```go
		progress.Phase(PhaseScoring, 0)
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./portal/ -race -v`
Expected: PASS, including every pre-existing handler test — none of them wires a tracker, so all of them exercise the nil path.

- [ ] **Step 8: Run the whole suite**

Run: `go test ./... -race`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add portal/progress.go portal/submit.go portal/submit_test.go
git commit -m "Publish which phase a submission is in, and how far"
```

---

### Task 4: Wire the tracker and the route

**Files:**
- Modify: `cmd/portal/main.go`
- Test: `cmd/portal/main_test.go`

**Interfaces:**
- Consumes: `portal.NewProgressTracker`, `portal.ProgressHandler`, `portal.SubmitHandler.Progress` (Tasks 1–3).
- Produces: `muxDeps.ProgressTracker *portal.ProgressTracker`, and the `/submit/progress` route.

- [ ] **Step 1: Write the failing tests**

Append to `cmd/portal/main_test.go`:

```go
func TestSubmitHandlerFor_PassesTheProgressTracker(t *testing.T) {
	tracker := portal.NewProgressTracker()
	if h := submitHandlerFor(muxDeps{ProgressTracker: tracker}); h.Progress != tracker {
		t.Error("Progress did not reach the handler")
	}
}

func TestNewMux_RoutesSubmitProgress(t *testing.T) {
	// /submit is registered as an exact pattern, so /submit/progress does not
	// collide with it — but adding a trailing slash to either registration
	// would silently change which handler wins, so assert the routing.
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	tracker := portal.NewProgressTracker()

	mux := newMux(muxDeps{
		Sessions:        sessions,
		AdminSessions:   auth.NewSessionSigner([]byte("admin-secret"), 5*time.Minute),
		Store:           storage.LocalStore{Dir: t.TempDir()},
		SubmissionLog:   portal.NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl")),
		ExerciseStore:   exercise.NewFileStore(filepath.Join(t.TempDir(), "exercise.json")),
		ScoresStore:     scoring.NewStore(filepath.Join(t.TempDir(), "scores.json")),
		ProgressTracker: tracker,
		StaticFS:        os.DirFS(t.TempDir()),
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	var addr crypto.Address
	copy(addr[:], []byte("01234567890123456789")) // 20 bytes

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/submit/progress", nil)
	req.Header.Set("Authorization", "Bearer "+sessions.Issue(addr))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /submit/progress: %v", err)
	}
	defer resp.Body.Close()

	// 404 from the progress handler, not 405 from /submit's POST-only guard:
	// the session is valid and nothing is in flight.
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 from the progress handler", resp.StatusCode)
	}
}
```

`cmd/portal/main_test.go` has no address helper — it uses literal bech32 strings and real keys — so the address is built inline above, the same way `portal/submit_test.go:182` does it. Read the file's existing `muxDeps` literals before writing, match the field list, and add only the imports it does not already have (`crypto` is already imported for `FetchPubKey`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/portal/ -run 'TestSubmitHandlerFor_PassesTheProgress|TestNewMux_RoutesSubmitProgress' -v`
Expected: FAIL to compile — `unknown field ProgressTracker in struct literal of type muxDeps`.

- [ ] **Step 3: Add the dependency and the route**

In `cmd/portal/main.go`:

- Add `ProgressTracker *portal.ProgressTracker` to `muxDeps`.
- Add `Progress: d.ProgressTracker,` to `submitHandlerFor`'s literal, beside `AVScanner`.
- Register the route in `newMux`, next to `/submit`:

```go
	mux.Handle("/submit/progress", portal.ProgressHandler(d.Sessions, d.ProgressTracker))
```

- In `main`, construct it beside the other stores and pass it:

```go
	// One tracker for the process: it holds at most one entry per operator
	// with a submission in flight.
	progressTracker := portal.NewProgressTracker()
```

and `ProgressTracker: progressTracker,` in the `newMux(muxDeps{...})` call.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./cmd/portal/ -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/portal/main.go cmd/portal/main_test.go
git commit -m "Route /submit/progress and wire the tracker"
```

---

### Task 5: Show the progress on the upload page

**Files:**
- Modify: `cmd/portal/static/index.html`, `cmd/portal/static/portal.js`

**Interfaces:**
- Consumes: `GET /submit/progress`, returning `{"phase": "...", "bytes": N, "total": N, "phase_started_at": "RFC3339"}` with `total` absent when unknown; 404 when nothing is in flight.
- Produces: nothing other code depends on.

There is no JS test harness. Verify by inspection, `node --check`, and the manual run in Step 7.

- [ ] **Step 1: Add the detail line to the markup**

In `cmd/portal/static/index.html`, inside `#upload-progress`, immediately after the `#upload-status` paragraph and before the `#upload-phase` one:

```html
    <!-- Byte counts for the server-side phases, refreshed every couple of
         seconds while the server works — so aria-live stays off here for the
         same reason it is off above. #upload-phase below is the announced
         surface, and it only changes when the phase itself does. -->
    <p id="upload-detail" aria-live="off"></p>
```

- [ ] **Step 2: Add the rendering helpers to `portal.js`**

Immediately after the existing `setUploadProcessing` function:

```js
function formatDuration(seconds) {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) {
    return s + "s";
  }
  return Math.floor(s / 60) + "m " + (s % 60) + "s";
}

// PHASE_SENTENCES is what the validator reads for each server-side phase
// (portal.Phase). A phase this page does not know about falls back to the
// generic message rather than rendering a raw identifier.
const PHASE_SENTENCES = {
  validating: "Checking the archive's structure.",
  scanning: "Antivirus scan in progress.",
  storing: "Storing the archive.",
  scoring: "Scoring your submission.",
};

let announcedPhase = null;

// renderServerProgress paints one poll result. The scanning phase gets an
// indeterminate bar and absolute numbers on purpose: the log's decompressed
// size is not known until it has been decompressed, so there is no honest
// denominator, and a bar driven by the budget instead would glide along and
// then jump to done. Storing is the opposite case — its total is the
// archive's own size — so it gets a real percentage.
function renderServerProgress(p) {
  const bar = document.getElementById("upload-bar");
  const status = document.getElementById("upload-status");
  const detail = document.getElementById("upload-detail");

  const sentence = PHASE_SENTENCES[p.phase] || "The server is processing your archive.";
  let detailText = "";

  if (p.phase === "storing" && p.total > 0) {
    const pct = Math.round((p.bytes / p.total) * 100);
    bar.value = pct;
    detailText = `${formatBytes(p.bytes)} / ${formatBytes(p.total)} (${pct}%)`;
  } else {
    bar.removeAttribute("value");
    if (p.phase === "scanning") {
      const elapsed = (Date.now() - Date.parse(p.phase_started_at)) / 1000;
      const rate = elapsed > 0 ? p.bytes / elapsed : 0;
      detailText =
        `${formatBytes(p.bytes)} streamed · ${formatDuration(elapsed)} · ${formatBytes(rate)}/s`;
    }
  }

  status.textContent = sentence + " Keep this tab open.";
  detail.textContent = detailText;

  // Announced only when the phase itself changes — the byte count beside it
  // refreshes every two seconds and must never reach the live region.
  if (p.phase !== announcedPhase) {
    announcedPhase = p.phase;
    announcePhase(sentence);
  }
}
```

- [ ] **Step 3: Add the polling lifecycle to `portal.js`**

Immediately after `renderServerProgress`:

```js
let progressTimer = null;

// startProgressPolling opens the second connection this page needs: the
// submission's own response cannot report progress without freezing its
// status code, so progress arrives on its own request.
//
// Every failure path here returns silently. A 404 is normal — it is the
// answer until the server finishes reading the request body, and again once
// it has responded — and a network error on a poll says nothing about the
// upload, which is being decided on the other connection entirely. If polling
// never succeeds, the page simply keeps the message setUploadProcessing left.
function startProgressPolling(token) {
  stopProgressPolling();
  announcedPhase = null;

  progressTimer = setInterval(async () => {
    let resp;
    try {
      resp = await fetch("/submit/progress", {
        headers: { Authorization: "Bearer " + token },
      });
    } catch (err) {
      return;
    }
    if (!resp.ok) {
      return;
    }

    let p;
    try {
      p = await resp.json();
    } catch (err) {
      return;
    }

    // The submission may have completed while this poll was in flight;
    // painting now would resurrect a panel the load handler just hid.
    if (progressTimer === null) {
      return;
    }
    renderServerProgress(p);
  }, 2000);
}

function stopProgressPolling() {
  if (progressTimer !== null) {
    clearInterval(progressTimer);
    progressTimer = null;
  }
}
```

- [ ] **Step 4: Hook it into the submission**

In the submit click handler in `portal.js`:

Replace

```js
  xhr.upload.addEventListener("load", setUploadProcessing);
```

with

```js
  xhr.upload.addEventListener("load", () => {
    setUploadProcessing();
    startProgressPolling(sessionToken);
  });
```

Add `stopProgressPolling();` as the first statement of both the `xhr` `"load"` and `"error"` listeners, before `progress.hidden = true;`.

Add an abort listener beside them, which the page currently lacks:

```js
  xhr.addEventListener("abort", () => {
    stopProgressPolling();
    progress.hidden = true;
    button.disabled = false;
  });
```

- [ ] **Step 5: Check the JavaScript parses**

Run: `node --check cmd/portal/static/portal.js`
Expected: no output. If `node` is unavailable, say so in the report rather than claiming the check passed.

- [ ] **Step 6: Check the build**

Run: `go build ./... && go test ./... -race`
Expected: PASS. The static files are embedded with `go:embed`, so a malformed file would surface here.

- [ ] **Step 7: Manual verification**

```bash
docker compose up -d --build
docker compose ps   # wait for clamav to report healthy
```

Submit `test/samourai-crew-huge-20260805-2232UTC.tar.gz` through the page. The targets are known from a measured run of this exact archive:

1. The upload bar behaves as before while bytes are transferring.
2. `Checking the archive's structure.` appears once the transfer ends.
3. `Antivirus scan in progress.` with a byte count climbing towards roughly 25.4 GB over about 5m23s, an elapsed timer, and a rate near 140 MiB/s.
4. `Storing the archive.` with a real percentage over 2.4 GB.
5. `Scoring your submission.`
6. The success panel, as before.

The single thing this exists to prove: **at no point does the display sit still for minutes.** If any phase shows no movement, that phase needs its own counter, and this plan is not done.

- [ ] **Step 8: Commit**

```bash
git add cmd/portal/static/index.html cmd/portal/static/portal.js
git commit -m "Show what the server is doing while a submission is processed"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
| --- | --- |
| 1. Why polling, on a second connection | 2 (the handler's doc comment), 5 (the client) |
| 1. Keyed by operator, not by a generated ID | 1 |
| 1. `portal/progress.go` — types, nil semantics, staleness | 1 |
| 1. The endpoint | 2 |
| 2. Instrumenting the handler — `Begin`, four phases | 3 |
| 2. Counting scanned bytes without touching `clamav` | 3 |
| 3. No invented percentage; phase table | 5 |
| 3. Markup and accessibility | 5 |
| 3. Polling lifecycle; invisible failure | 5 |
| 4. Wiring | 4 |
| Testing — tracker, nil, staleness, isolation | 1 |
| Testing — endpoint | 2 |
| Testing — visible *during* the scan | 3 |
| Testing — wiring, routing | 4 |
| Testing — `-race`, manual run | 3, 4, 5 |

**Type consistency:** `Progress{Phase, Bytes, Total, PhaseStartedAt}` is defined in Task 1 and consumed unchanged in Tasks 2, 3 and 5, where the JS reads `p.phase`, `p.bytes`, `p.total` and `p.phase_started_at` — matching the JSON tags exactly. `ProgressHandle.Phase/Add/Done` keep their signatures across Tasks 1 and 3. `muxDeps.ProgressTracker` (Task 4) and `SubmitHandler.Progress` (Task 3) are deliberately named differently: the dependency is a tracker, the handler field is what it does.

**Things an implementer must not treat as incidental:**

1. The nil-receiver behaviour in Task 1 is what lets Task 3 skip guards at five call sites, and what keeps every existing handler test passing. Removing it turns those tests into panics.
2. `Phase` resets `Bytes`. Storing counts its own bytes against `header.Size`; inheriting the scan's count would render a store as instantly complete.
3. The mid-scan test in Task 3 is the only one that proves the feature works. A version of it that reads the tracker after the request completes passes against a handler that publishes nothing.
4. The counting scanner counts ~0.1% more than `Coverage.Bytes` because it sees the re-sent overlap. That is intended; `Coverage.Bytes` stays the number that is recorded and badged.
