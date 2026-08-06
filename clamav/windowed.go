package clamav

import (
	"bytes"
	"context"
	"io"
)

const (
	// defaultWindowSize is how much fresh content each INSTREAM session
	// carries. libclamav cannot scan any single file of 2147483648 bytes
	// or more — no clamd.conf setting lifts that — so a window has to stay
	// under it with room to spare for the overlap prepended to the next
	// one. See README.md's "The 2 GiB wall".
	defaultWindowSize = 1 << 30 // 1 GiB

	// defaultOverlap is how much of window N is re-sent at the head of
	// window N+1. Each window is its own INSTREAM session, so a signature
	// straddling a boundary would be split across two independent scans
	// and matched by neither; the overlap is what closes that gap. ClamAV
	// signatures run to a few KB at most, so 1 MiB is deliberately
	// generous: on a 25 GB log it re-scans about 25 MiB, roughly 0.1%.
	defaultOverlap = 1 << 20 // 1 MiB
)

// DefaultScanBudget bounds how much decompressed content one submission may
// cost the antivirus. It is exported because cmd/portal uses it as its own
// flag default: unlike -max-log-size, this deployment has no reason to
// standardise on a different value, and two copies of the number could drift
// apart.
//
// 32 GiB is roughly four minutes of scanning at the ~142 MB/s clamd manages
// on the target machine. Its job is prd.md's zip/tar bomb defence, not cost
// control — a submission that exceeds it is accepted and recorded as
// partially scanned, never rejected and never silently passed as clean.
const DefaultScanBudget = 32 << 30 // 32 GiB

// Coverage reports what a windowed scan actually examined. It travels with
// the submission (see portal.Entry), so a partially scanned archive can
// never be mistaken for a fully scanned one.
type Coverage struct {
	// Complete is true when the stream reached EOF within the budget.
	Complete bool `json:"complete"`

	// Bytes is how much of the stream was handed to the scanner and came
	// back with a verdict, counting the overlap between consecutive
	// windows once. A window whose scan never completed is not counted.
	Bytes int64 `json:"bytes"`
}

// WindowedScanner scans an arbitrarily long stream by feeding it to Scanner
// in fixed-size overlapping windows, each its own scan. It deliberately does
// not implement Scanner itself: it has to report something Verdict cannot
// carry, namely how much of the stream was examined.
//
// Memory is O(Overlap) regardless of the stream's length — no window is ever
// buffered, only the tail carried between two of them.
type WindowedScanner struct {
	Scanner Scanner

	// WindowSize, Overlap and Budget all fall back to package defaults
	// when zero. Only Budget is meant to be set by callers: the other two
	// encode protocol and signature facts rather than policy.
	WindowSize int64
	Overlap    int64
	Budget     int64
}

// ScanStream reads r to EOF or to the budget, whichever comes first.
//
// A clean run returns a zero Verdict and Coverage{Complete: true}. The
// budget running out, or r failing partway through, both return a nil error
// with Coverage{Complete: false} — those are recorded, not rejected. Only a
// failure of the underlying Scanner itself returns a non-nil error, which
// callers must treat as fail-closed exactly as they treat Scan's.
func (w WindowedScanner) ScanStream(ctx context.Context, r io.Reader) (Verdict, Coverage, error) {
	windowSize, overlap, budget := w.windowSize(), w.overlap(), w.budget()

	// Windows are read by the Scanner, not by this loop, so a broken source
	// would otherwise surface only as whatever error Scan happens to return
	// — indistinguishable from the antivirus daemon being down. src records
	// that the failure was the source's, so every error return below can
	// tell the two apart and give each its own outcome.
	src := &errRecorder{r: r}
	bounded := &io.LimitedReader{R: src, N: budget}

	var tail []byte
	var scanned int64

	for {
		if err := ctx.Err(); err != nil {
			return Verdict{}, Coverage{}, err
		}

		// One byte before building the window, so a stream whose length is
		// an exact multiple of the window capacity doesn't end with a
		// window holding nothing but the previous one's overlap. Zero bytes
		// ends the loop either way — whether that was the stream genuinely
		// ending or the source breaking is decided below, from src.err, not
		// from this read directly.
		var head [1]byte
		n, _ := io.ReadFull(bounded, head[:])
		if n == 0 {
			break
		}

		capacity := windowSize - int64(len(tail))
		fresh := &io.LimitedReader{R: bounded, N: capacity - 1}
		ring := newTailBuffer(overlap)
		window := io.MultiReader(
			bytes.NewReader(tail),
			io.TeeReader(io.MultiReader(bytes.NewReader(head[:]), fresh), ring),
		)

		verdict, err := w.Scanner.Scan(ctx, window)
		if err != nil {
			if src.err != nil {
				// The source broke, not the scanner. The window being fed
				// when it broke was never verdicted, so its bytes are not
				// counted and the loop ends with incomplete coverage
				// instead of an error.
				return Verdict{}, Coverage{Bytes: scanned}, nil
			}
			return Verdict{}, Coverage{}, err
		}

		// The Scanner is not trusted to have read its whole window: without
		// this drain the byte count and the next window's alignment would
		// depend on how much the implementation chose to consume.
		if _, err := io.Copy(io.Discard, window); err != nil {
			if src.err != nil {
				return Verdict{}, Coverage{Bytes: scanned}, nil
			}
			return Verdict{}, Coverage{}, err
		}

		scanned += capacity - fresh.N
		if verdict.Infected {
			return verdict, Coverage{Bytes: scanned}, nil
		}
		if fresh.N > 0 {
			// Short window: r (or the budget) ran out inside it.
			break
		}
		tail = ring.bytes()
	}

	// A recorded source error can never be reported as complete, regardless
	// of what complete's own probe would say — the loop above only reaches
	// here after src has already had every chance to set it.
	return Verdict{}, Coverage{Complete: src.err == nil && w.complete(bounded, src), Bytes: scanned}, nil
}

// complete reports whether the loop stopped because the stream genuinely
// ended. With budget left over it plainly did. With the budget exactly spent
// the two cases are indistinguishable from bounded alone, so one byte is
// probed from the underlying reader — the same trick scoring.scanHitCap uses
// for the log-window scan.
func (w WindowedScanner) complete(bounded *io.LimitedReader, r io.Reader) bool {
	if bounded.N > 0 {
		return true
	}
	var probe [1]byte
	n, err := io.ReadFull(r, probe[:])
	// A probe that fails for a reason other than EOF found out nothing
	// about whether the stream ended — it must not be read as "complete".
	// That's the same failure mode as the head peek above, just off by one
	// window: the source broke instead of running out.
	return n == 0 && (err == nil || err == io.EOF)
}

func (w WindowedScanner) windowSize() int64 {
	if w.WindowSize <= 0 {
		return defaultWindowSize
	}
	return w.WindowSize
}

// overlap clamps to half the window: an overlap at or above the window size
// would leave no room for fresh bytes, and the loop would never advance.
// Only reachable from an explicitly wrong caller configuration.
func (w WindowedScanner) overlap() int64 {
	overlap := w.Overlap
	if overlap <= 0 {
		overlap = defaultOverlap
	}
	if windowSize := w.windowSize(); overlap >= windowSize {
		overlap = windowSize / 2
	}
	return overlap
}

func (w WindowedScanner) budget() int64 {
	if w.Budget <= 0 {
		return DefaultScanBudget
	}
	return w.Budget
}

// errRecorder remembers the first non-EOF read error the wrapped reader
// produced. ScanStream needs it because the windows are read by the Scanner,
// so a failure of the source arrives as an error returned by Scan — the same
// shape as a daemon that is down, and the opposite outcome: a truncated log
// is an accepted submission with partial coverage, a dead daemon is a 503.
type errRecorder struct {
	r   io.Reader
	err error
}

func (e *errRecorder) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err != nil && err != io.EOF {
		e.err = err
	}
	return n, err
}

// tailBuffer keeps the last size bytes written to it and discards the rest,
// so the overlap can be carried into the next window without retaining the
// window that produced it.
type tailBuffer struct {
	size int
	buf  []byte
}

func newTailBuffer(size int64) *tailBuffer {
	return &tailBuffer{size: int(size)}
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) >= t.size {
		t.buf = append(t.buf[:0], p[len(p)-t.size:]...)
		return n, nil
	}
	if len(t.buf)+len(p) > t.size {
		drop := len(t.buf) + len(p) - t.size
		t.buf = append(t.buf[:0], t.buf[drop:]...)
	}
	t.buf = append(t.buf, p...)
	return n, nil
}

func (t *tailBuffer) bytes() []byte { return t.buf }
