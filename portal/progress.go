package portal

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/samourai/validator-diagnostics/auth"
	"github.com/samourai/validator-diagnostics/clamav"
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
// submissions at once gets a display driven by the newer one. Begin stamps
// each entry with a generation token, so a second Begin supersedes the
// first — the first handle's Phase and Add calls become inert rather than
// corrupting the second submission's counters, and its Done cannot remove
// the second's entry. Both submissions still complete and record correctly;
// only the superseded handle's writes are discarded.
//
// The zero value is not usable; call NewProgressTracker. A nil
// *ProgressTracker, however, is: it behaves as "reporting disabled".
type ProgressTracker struct {
	mu       sync.Mutex
	inflight map[string]*progressEntry

	// nextGen hands out each new entry's generation token. Monotonically
	// increasing under mu, so the most recent Begin for an operator always
	// holds the highest token and every older handle for that operator can
	// tell it has been superseded.
	nextGen uint64

	// now is swappable so the staleness tests don't have to sleep.
	now func() time.Time
}

type progressEntry struct {
	progress   Progress
	lastUpdate time.Time

	// gen is this entry's generation token, assigned by Begin. A handle
	// only matches the entry that has the same token: once a second Begin
	// replaces the entry, the first handle's token is stale and every
	// method on it becomes a no-op instead of reaching into the new entry.
	gen uint64
}

func NewProgressTracker() *ProgressTracker {
	return &ProgressTracker{
		inflight: make(map[string]*progressEntry),
		now:      time.Now,
	}
}

// ProgressHandle publishes into the entry Begin created. Every method
// tolerates a nil receiver, so a handler built without a tracker needs no
// guard at any call site. A handle also goes inert once a later Begin for
// the same operator supersedes its entry — see ProgressTracker's doc
// comment.
type ProgressHandle struct {
	tracker  *ProgressTracker
	operator string
	gen      uint64
}

// Begin starts tracking a submission for operator, replacing any entry that
// operator already had and superseding whatever handle owned it — that
// handle's Phase, Add, and Done become no-ops. Callers must defer the
// returned handle's Done.
func (t *ProgressTracker) Begin(operator string) *ProgressHandle {
	if t == nil {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	t.nextGen++
	gen := t.nextGen
	t.inflight[operator] = &progressEntry{
		progress:   Progress{PhaseStartedAt: now},
		lastUpdate: now,
		gen:        gen,
	}
	return &ProgressHandle{tracker: t, operator: operator, gen: gen}
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

// Done removes the entry, unless a later Begin for the same operator has
// already superseded it — in which case that entry belongs to a different
// submission and Done leaves it alone. Safe to call twice, and safe on a
// nil handle.
func (h *ProgressHandle) Done() {
	if h == nil {
		return
	}

	h.tracker.mu.Lock()
	defer h.tracker.mu.Unlock()

	if e, ok := h.tracker.inflight[h.operator]; ok && e.gen == h.gen {
		delete(h.tracker.inflight, h.operator)
	}
}

// update applies f to this handle's entry under the tracker's lock, and
// refreshes the staleness clock. It is a no-op on a nil handle, on an entry
// that no longer exists — which is what a handle outliving its own Done
// looks like — and on an entry whose generation has moved past this
// handle's, which is what a handle outlived by a later Begin looks like.
func (h *ProgressHandle) update(f func(e *progressEntry, now time.Time)) {
	if h == nil {
		return
	}

	h.tracker.mu.Lock()
	defer h.tracker.mu.Unlock()

	e, ok := h.tracker.inflight[h.operator]
	if !ok || e.gen != h.gen {
		return
	}
	now := h.tracker.now()
	f(e, now)
	e.lastUpdate = now
}

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
// otherwise invisible from outside. It wraps a plain io.Reader on purpose:
// the antivirus path wraps a gzip stream, which is genuinely not seekable,
// and giving it a Seek method that fails at runtime would advertise a
// capability it does not have — see countingSeeker for the storage path,
// which does need one.
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

// countingSeeker is countingReader's counterpart for the storage path, which
// wraps a multipart.File — genuinely seekable, and storage.S3Store.Save
// depends on that: the AWS SDK's checksum middleware refuses a non-seekable
// body over plain HTTP, and its retry middleware rewinds and re-reads a
// seekable one after a transient failure. A single type that tried to cover
// both call sites would either hide a gzip stream's real non-seekability
// (the antivirus path) or hide a multipart.File's real seekability (this
// one) — so this is deliberately a second type, not a flag on the first.
//
// offset tracks the wrapper's own position so Seek reports the delta to the
// new position, not the raw byte count: the SDK seeks back to 0 and re-reads
// on retry, and a wrapper that only ever adds on Read would double-count
// every retried byte. Reporting the delta keeps the published count equal to
// the current offset, matching what the wrapped reader has actually done.
type countingSeeker struct {
	r      io.ReadSeeker
	add    func(int64)
	offset int64
}

func (c *countingSeeker) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.offset += int64(n)
		c.add(int64(n))
	}
	return n, err
}

// Seek forwards to the wrapped seeker and reports the change in position —
// which may be negative, on a rewind — rather than the magnitude of the
// jump, so repeated seeks never drift the published count away from the
// wrapped reader's actual offset.
func (c *countingSeeker) Seek(offset int64, whence int) (int64, error) {
	newOffset, err := c.r.Seek(offset, whence)
	if err != nil {
		return newOffset, err
	}
	c.add(newOffset - c.offset)
	c.offset = newOffset
	return newOffset, nil
}
