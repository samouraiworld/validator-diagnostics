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
