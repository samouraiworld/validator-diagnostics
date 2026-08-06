# Windowed Antivirus Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop handing clamd the raw `.tar.gz` — which libclamav refuses to scan past 2 GiB - 1 — and instead scan the extracted content: `metadata.json` whole, then the decompressed `gnoland.log.gz` in overlapping 1 GiB windows under a configurable byte budget, recording how much was actually examined.

**Architecture:** A new `clamav.WindowedScanner` wraps the existing `clamav.Scanner` interface and drives it repeatedly over fixed-size windows with a 1 MiB overlap, returning a `Coverage` alongside the `Verdict`. `portal.SubmitHandler` calls it after `ValidateArchive` and before `Store.Save`, so the fail-closed ordering is preserved, and stores the resulting `Coverage` on the submission log entry, where the admin dashboard renders it as a badge.

**Tech Stack:** Go 1.26.1, standard library only (`archive/tar`, `compress/gzip`, `io`, `bytes`). Frontend is dependency-free vanilla JS. Tests are `go test` with no test framework.

**Design spec:** `docs/superpowers/specs/2026-08-05-windowed-av-scanning-design.md`

## Global Constraints

- Go 1.26.1, no new module dependencies. Everything here is standard library.
- Memory must stay O(overlap) — never buffer a window, a log, or an archive.
- The antivirus layer is **fail-closed**: a scan that cannot be completed rejects the submission. The only accepted incompleteness is the two documented cases (budget exhausted, source stream broke mid-read), and both are recorded, never silent.
- `Coverage` non-nil on a submission log entry is an affirmative claim that a real scanner ran. Never write one for a submission nothing scanned.
- Window size `1 << 30` (1 GiB) and overlap `1 << 20` (1 MiB) are package constants, not operator knobs. Only the budget is configurable.
- Budget default: `32 << 30` = `34359738368` bytes (32 GiB). This exact number appears in `clamav`, `docker-compose.yml`, `.env.example` and the README.
- Upload ceiling stays `2147483647`. Raising it is explicitly out of scope.
- `.env` is gitignored — edit it when needed, **never `git add` it**. `.env.example` is tracked and must be kept in step.
- The working tree carries an unrelated uncommitted `.gitignore` change (`/test/**`) that predates this work. Leave it alone; never stage it.
- Comments explain *why*, matching the density and tone of the surrounding code. This codebase comments heavily and deliberately.

---

## File Structure

**Created:**
- `clamav/windowed.go` — `Coverage`, `WindowedScanner`, `tailBuffer`, `errRecorder`. One responsibility: turn an arbitrarily long stream into a sequence of bounded, overlapping scans and report what was covered.
- `clamav/windowed_test.go` — a recording fake `Scanner` plus the window-geometry, budget and error-attribution assertions.

**Modified:**
- `portal/log.go:24-30` — `Entry` gains `Scan *clamav.Coverage`.
- `portal/submit.go:44-75, 162-181, 262-277` — `AVScanBudget` field, the new `scanArchive` helper, the rewritten AV block, the `Entry` construction.
- `portal/submit_test.go:103, 207-256, 445-512` — `buildValidArchive` must emit a real gzip log; new handler tests.
- `portal/log_test.go` — round-trip and legacy-line tests for the new field.
- `cmd/portal/main.go:62-92, 106-110, 144-149, 156-170, 180-200` — flag, `muxDeps`, the `NoopScanner` fallback removal, comment corrections.
- `scoring/checks.go:15, 31, 69, 79`, `scoring/score.go:70`, `scoring/checks_test.go:180, 199` — the `maxLogScanBytes` → `maxLogWindowBytes` rename.
- `cmd/portal/static/admin.js` — the scan badge and a local `formatBytes`.
- `docker-compose.yml:69-85`, `.env.example`, `.env`, `clamd.conf:1-13`, `README.md:60-130` — configuration and documentation.

---

### Task 1: The windowed scanner's geometry

**Files:**
- Create: `clamav/windowed.go`
- Test: `clamav/windowed_test.go`

**Interfaces:**
- Consumes: `clamav.Scanner` (`Scan(ctx context.Context, r io.Reader) (Verdict, error)`) and `clamav.Verdict` from `clamav/scanner.go`.
- Produces:
  - `clamav.Coverage` — `struct { Complete bool "json:\"complete\""; Bytes int64 "json:\"bytes\"" }`
  - `clamav.WindowedScanner` — `struct { Scanner Scanner; WindowSize, Overlap, Budget int64 }`
  - `func (w WindowedScanner) ScanStream(ctx context.Context, r io.Reader) (Verdict, Coverage, error)`
  - `const DefaultScanBudget = 32 << 30`

In this task every error from the underlying `Scan` propagates unchanged. Task 2 adds the source-vs-scanner distinction.

- [ ] **Step 1: Write the failing tests for window geometry**

Create `clamav/windowed_test.go`:

```go
package clamav

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// recordingScanner keeps a copy of every window it is handed, which is what
// makes the window geometry assertable at all: without it the overlap and the
// budget are invisible from outside ScanStream.
//
// verdicts, when non-empty, is consulted per call (index 0 for the first
// window, and so on) so a test can make exactly one window come back
// infected; a shorter slice than the number of calls means "clean".
type recordingScanner struct {
	windows  [][]byte
	verdicts []Verdict
	errs     []error

	// readLimit, when > 0, makes the scanner read only that many bytes of
	// each window instead of draining it, standing in for a real Scanner
	// that gives up early.
	readLimit int
}

func (s *recordingScanner) Scan(ctx context.Context, r io.Reader) (Verdict, error) {
	var data []byte
	var err error
	if s.readLimit > 0 {
		data = make([]byte, s.readLimit)
		n, readErr := io.ReadFull(r, data)
		data = data[:n]
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			err = readErr
		}
	} else {
		data, err = io.ReadAll(r)
	}
	i := len(s.windows)
	s.windows = append(s.windows, data)

	if err != nil {
		return Verdict{}, err
	}
	if i < len(s.errs) && s.errs[i] != nil {
		return Verdict{}, s.errs[i]
	}
	if i < len(s.verdicts) {
		return s.verdicts[i], nil
	}
	return Verdict{}, nil
}

// seq builds n bytes of non-repeating content, so an assertion about which
// window a byte landed in cannot pass by accident.
func seq(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i%251) + 1
	}
	return out
}

func TestWindowedScanner_ShorterThanOneWindow(t *testing.T) {
	fake := &recordingScanner{}
	w := WindowedScanner{Scanner: fake, WindowSize: 100, Overlap: 10, Budget: 1000}

	input := seq(40)
	verdict, cov, err := w.ScanStream(context.Background(), bytes.NewReader(input))
	if err != nil {
		t.Fatalf("ScanStream: %v", err)
	}
	if verdict.Infected {
		t.Error("Infected = true, want false")
	}
	if len(fake.windows) != 1 {
		t.Fatalf("got %d windows, want 1", len(fake.windows))
	}
	if !bytes.Equal(fake.windows[0], input) {
		t.Error("the single window is not the input")
	}
	if !cov.Complete || cov.Bytes != 40 {
		t.Errorf("Coverage = %+v, want {Complete:true Bytes:40}", cov)
	}
}

func TestWindowedScanner_OverlapsConsecutiveWindows(t *testing.T) {
	fake := &recordingScanner{}
	w := WindowedScanner{Scanner: fake, WindowSize: 100, Overlap: 10, Budget: 10000}

	// 100 fresh + 90 fresh + 90 fresh = 280: three windows, the last short.
	input := seq(280)
	_, cov, err := w.ScanStream(context.Background(), bytes.NewReader(input))
	if err != nil {
		t.Fatalf("ScanStream: %v", err)
	}
	if len(fake.windows) != 3 {
		t.Fatalf("got %d windows, want 3", len(fake.windows))
	}

	// Every window after the first opens with the previous one's tail.
	for i := 1; i < len(fake.windows); i++ {
		prev := fake.windows[i-1]
		want := prev[len(prev)-10:]
		if !bytes.Equal(fake.windows[i][:10], want) {
			t.Errorf("window %d does not start with window %d's last 10 bytes", i, i-1)
		}
	}

	// Dropping each overlap reconstructs the input exactly, which is the
	// property that proves nothing was skipped or double-counted.
	var rebuilt []byte
	rebuilt = append(rebuilt, fake.windows[0]...)
	for _, win := range fake.windows[1:] {
		rebuilt = append(rebuilt, win[10:]...)
	}
	if !bytes.Equal(rebuilt, input) {
		t.Errorf("rebuilt stream is %d bytes, want %d", len(rebuilt), len(input))
	}
	if !cov.Complete || cov.Bytes != 280 {
		t.Errorf("Coverage = %+v, want {Complete:true Bytes:280}", cov)
	}
}

func TestWindowedScanner_NoTrailingOverlapOnlyWindow(t *testing.T) {
	fake := &recordingScanner{}
	w := WindowedScanner{Scanner: fake, WindowSize: 100, Overlap: 10, Budget: 10000}

	// Exactly 100 + 90: the stream ends flush with a window boundary, and
	// the peek is what stops a third window holding nothing but overlap.
	if _, _, err := w.ScanStream(context.Background(), bytes.NewReader(seq(190))); err != nil {
		t.Fatalf("ScanStream: %v", err)
	}
	if len(fake.windows) != 2 {
		t.Fatalf("got %d windows, want 2 (a third would carry only overlap)", len(fake.windows))
	}
}

func TestWindowedScanner_MarkerStraddlingABoundaryIsSeenWhole(t *testing.T) {
	fake := &recordingScanner{}
	w := WindowedScanner{Scanner: fake, WindowSize: 100, Overlap: 10, Budget: 10000}

	// "SIGNATURE" spans bytes 96..104, i.e. the first window's last four
	// bytes and the second window's first five. Only the overlap can make
	// some single window contain it whole — which is the entire reason the
	// overlap exists.
	input := make([]byte, 200)
	for i := range input {
		input[i] = 'x'
	}
	copy(input[96:], "SIGNATURE")

	if _, _, err := w.ScanStream(context.Background(), bytes.NewReader(input)); err != nil {
		t.Fatalf("ScanStream: %v", err)
	}
	var found bool
	for _, win := range fake.windows {
		if bytes.Contains(win, []byte("SIGNATURE")) {
			found = true
		}
	}
	if !found {
		t.Error("no window contained the whole marker: the overlap is not working")
	}
}

func TestWindowedScanner_BudgetExhausted(t *testing.T) {
	fake := &recordingScanner{}
	w := WindowedScanner{Scanner: fake, WindowSize: 100, Overlap: 10, Budget: 150}

	_, cov, err := w.ScanStream(context.Background(), bytes.NewReader(seq(500)))
	if err != nil {
		t.Fatalf("ScanStream: %v", err)
	}
	if cov.Complete {
		t.Error("Complete = true, want false: the budget cut the stream short")
	}
	if cov.Bytes != 150 {
		t.Errorf("Bytes = %d, want 150 (the budget)", cov.Bytes)
	}
	if len(fake.windows) != 2 {
		t.Errorf("got %d windows, want 2 (100 fresh, then 50 before the budget ran out)", len(fake.windows))
	}
}

func TestWindowedScanner_BudgetExactlyEqualToStream(t *testing.T) {
	fake := &recordingScanner{}
	w := WindowedScanner{Scanner: fake, WindowSize: 100, Overlap: 10, Budget: 190}

	_, cov, err := w.ScanStream(context.Background(), bytes.NewReader(seq(190)))
	if err != nil {
		t.Fatalf("ScanStream: %v", err)
	}
	if !cov.Complete {
		t.Error("Complete = false, want true: the stream ended exactly at the budget, it was not truncated")
	}
	if cov.Bytes != 190 {
		t.Errorf("Bytes = %d, want 190", cov.Bytes)
	}
}

func TestWindowedScanner_InfectedStopsImmediately(t *testing.T) {
	fake := &recordingScanner{
		verdicts: []Verdict{{}, {Infected: true, Signature: "Test.Sig"}},
	}
	w := WindowedScanner{Scanner: fake, WindowSize: 100, Overlap: 10, Budget: 10000}

	verdict, _, err := w.ScanStream(context.Background(), bytes.NewReader(seq(500)))
	if err != nil {
		t.Fatalf("ScanStream: %v", err)
	}
	if !verdict.Infected || verdict.Signature != "Test.Sig" {
		t.Fatalf("Verdict = %+v, want the infected one", verdict)
	}
	if len(fake.windows) != 2 {
		t.Errorf("got %d windows, want 2: nothing after the detection should be scanned", len(fake.windows))
	}
}

func TestWindowedScanner_ScannerErrorPropagates(t *testing.T) {
	sentinel := errors.New("clamd is down")
	fake := &recordingScanner{errs: []error{sentinel}}
	w := WindowedScanner{Scanner: fake, WindowSize: 100, Overlap: 10, Budget: 10000}

	_, cov, err := w.ScanStream(context.Background(), bytes.NewReader(seq(500)))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
	if cov != (Coverage{}) {
		t.Errorf("Coverage = %+v, want zero: a failed scan covered nothing it can vouch for", cov)
	}
}

func TestWindowedScanner_DrainsWindowsTheScannerAbandons(t *testing.T) {
	// A Scanner that reads only 5 bytes of each window must not shift the
	// window boundaries: ScanStream drains the rest itself.
	fake := &recordingScanner{readLimit: 5}
	w := WindowedScanner{Scanner: fake, WindowSize: 100, Overlap: 10, Budget: 10000}

	_, cov, err := w.ScanStream(context.Background(), bytes.NewReader(seq(280)))
	if err != nil {
		t.Fatalf("ScanStream: %v", err)
	}
	if len(fake.windows) != 3 {
		t.Fatalf("got %d windows, want 3", len(fake.windows))
	}
	if !cov.Complete || cov.Bytes != 280 {
		t.Errorf("Coverage = %+v, want {Complete:true Bytes:280}", cov)
	}
}

func TestWindowedScanner_ContextCancelled(t *testing.T) {
	fake := &recordingScanner{}
	w := WindowedScanner{Scanner: fake, WindowSize: 100, Overlap: 10, Budget: 10000}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := w.ScanStream(ctx, strings.NewReader(strings.Repeat("a", 500)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestWindowedScanner_Defaults(t *testing.T) {
	fake := &recordingScanner{}
	w := WindowedScanner{Scanner: fake} // every knob zero

	_, cov, err := w.ScanStream(context.Background(), bytes.NewReader(seq(40)))
	if err != nil {
		t.Fatalf("ScanStream: %v", err)
	}
	if len(fake.windows) != 1 || !cov.Complete {
		t.Errorf("zero-valued knobs must fall back to the package defaults, got %d windows and %+v", len(fake.windows), cov)
	}
}

func TestWindowedScanner_OverlapNotSmallerThanWindow(t *testing.T) {
	// A caller configuration with no room for fresh bytes must still
	// terminate rather than spin forever re-sending the same overlap.
	fake := &recordingScanner{}
	w := WindowedScanner{Scanner: fake, WindowSize: 20, Overlap: 20, Budget: 1000}

	_, cov, err := w.ScanStream(context.Background(), bytes.NewReader(seq(100)))
	if err != nil {
		t.Fatalf("ScanStream: %v", err)
	}
	if !cov.Complete || cov.Bytes != 100 {
		t.Errorf("Coverage = %+v, want {Complete:true Bytes:100}", cov)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./clamav/ -run TestWindowedScanner -v`
Expected: FAIL — the package does not compile, `undefined: WindowedScanner`, `undefined: Coverage`.

- [ ] **Step 3: Write `clamav/windowed.go`**

```go
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

	bounded := &io.LimitedReader{R: r, N: budget}

	var tail []byte
	var scanned int64

	for {
		if err := ctx.Err(); err != nil {
			return Verdict{}, Coverage{}, err
		}

		// One byte before building the window, so a stream whose length is
		// an exact multiple of the window capacity doesn't end with a
		// window holding nothing but the previous one's overlap.
		var head [1]byte
		if n, _ := io.ReadFull(bounded, head[:]); n == 0 {
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
			return Verdict{}, Coverage{}, err
		}

		// The Scanner is not trusted to have read its whole window: without
		// this drain the byte count and the next window's alignment would
		// depend on how much the implementation chose to consume.
		if _, err := io.Copy(io.Discard, window); err != nil {
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

	return Verdict{}, Coverage{Complete: w.complete(bounded, r), Bytes: scanned}, nil
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
	n, _ := io.ReadFull(r, probe[:])
	return n == 0
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./clamav/ -v`
Expected: PASS, including the pre-existing `clamd` and `noop` tests.

- [ ] **Step 5: Commit**

```bash
git add clamav/windowed.go clamav/windowed_test.go
git commit -m "Scan long streams in overlapping windows below libclamav's ceiling"
```

---

### Task 2: Telling a broken source from a broken scanner

**Files:**
- Modify: `clamav/windowed.go`
- Test: `clamav/windowed_test.go`

**Interfaces:**
- Consumes: `WindowedScanner.ScanStream` from Task 1.
- Produces: no signature change. `ScanStream` gains the behaviour that a read failure on `r` returns `(Verdict{}, Coverage{Complete: false, Bytes: through the last verdicted window}, nil)` instead of an error.

The windows are read *by* the Scanner, so a read failure on `r` reaches `ScanStream` as an error returned by `Scan` — indistinguishable, at that point, from clamd being down. `ClamdScanner` even wraps it (`clamav: reading input: %w`). The two need opposite outcomes: a broken daemon is a 503, a truncated log is an accepted submission with partial coverage.

- [ ] **Step 1: Write the failing tests**

Append to `clamav/windowed_test.go`:

```go
// failingReader yields n good bytes and then fails, standing in for a gzip
// stream that turns out to be truncated: a full disk or a killed collection
// process on the validator's side.
type failingReader struct {
	data []byte
	off  int
	err  error
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.off >= len(f.data) {
		return 0, f.err
	}
	n := copy(p, f.data[f.off:])
	f.off += n
	return n, nil
}

func TestWindowedScanner_SourceFailureIsPartialCoverageNotAnError(t *testing.T) {
	fake := &recordingScanner{}
	w := WindowedScanner{Scanner: fake, WindowSize: 100, Overlap: 10, Budget: 10000}

	// 150 readable bytes: window 1 (100 fresh) completes and is verdicted,
	// window 2 breaks partway through.
	src := &failingReader{data: seq(150), err: errors.New("unexpected EOF")}

	verdict, cov, err := w.ScanStream(context.Background(), src)
	if err != nil {
		t.Fatalf("err = %v, want nil: a broken source is recorded, not rejected", err)
	}
	if verdict.Infected {
		t.Error("Infected = true, want false")
	}
	if cov.Complete {
		t.Error("Complete = true, want false")
	}
	if cov.Bytes != 100 {
		t.Errorf("Bytes = %d, want 100: the interrupted window was never verdicted, so it is not credited", cov.Bytes)
	}
}

func TestWindowedScanner_SourceFailureOnTheFirstWindow(t *testing.T) {
	fake := &recordingScanner{}
	w := WindowedScanner{Scanner: fake, WindowSize: 100, Overlap: 10, Budget: 10000}

	src := &failingReader{data: seq(20), err: errors.New("unexpected EOF")}

	_, cov, err := w.ScanStream(context.Background(), src)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if cov.Complete || cov.Bytes != 0 {
		t.Errorf("Coverage = %+v, want {Complete:false Bytes:0}", cov)
	}
}

func TestWindowedScanner_ScannerErrorStillWinsOverACleanSource(t *testing.T) {
	// The guard against over-generalising the previous two tests: with the
	// source healthy, a scanner error must still be an error.
	sentinel := errors.New("clamd is down")
	fake := &recordingScanner{errs: []error{nil, sentinel}}
	w := WindowedScanner{Scanner: fake, WindowSize: 100, Overlap: 10, Budget: 10000}

	_, cov, err := w.ScanStream(context.Background(), bytes.NewReader(seq(500)))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
	if cov != (Coverage{}) {
		t.Errorf("Coverage = %+v, want zero", cov)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./clamav/ -run 'TestWindowedScanner_Source|TestWindowedScanner_ScannerErrorStill' -v`
Expected: FAIL — the two source tests report `err = unexpected EOF, want nil`, because `ScanStream` currently propagates every error from `Scan`.

- [ ] **Step 3: Add the error recorder**

Add to `clamav/windowed.go`:

```go
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
```

- [ ] **Step 4: Route the stream through it and consult it on failure**

In `ScanStream`, replace

```go
	bounded := &io.LimitedReader{R: r, N: budget}
```

with

```go
	src := &errRecorder{r: r}
	bounded := &io.LimitedReader{R: src, N: budget}
```

Replace both error returns inside the loop — the one after `Scan` and the one after the drain — with the same attribution:

```go
		verdict, err := w.Scanner.Scan(ctx, window)
		if err != nil {
			if src.err != nil {
				// The source broke, not the scanner. The window being fed
				// when it broke was never verdicted, so its bytes are not
				// counted and the loop ends with incomplete coverage.
				return Verdict{}, Coverage{Bytes: scanned}, nil
			}
			return Verdict{}, Coverage{}, err
		}

		if _, err := io.Copy(io.Discard, window); err != nil {
			if src.err != nil {
				return Verdict{}, Coverage{Bytes: scanned}, nil
			}
			return Verdict{}, Coverage{}, err
		}
```

Change the final return so a recorded source error can never be reported as complete, and probe through the recorder rather than around it:

```go
	return Verdict{}, Coverage{Complete: src.err == nil && w.complete(bounded, src), Bytes: scanned}, nil
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./clamav/ -v`
Expected: PASS, all of Task 1's tests included — the drain, budget and geometry behaviour is unchanged for a healthy source.

- [ ] **Step 6: Commit**

```bash
git add clamav/windowed.go clamav/windowed_test.go
git commit -m "Record a broken source as partial coverage, not a failed scan"
```

---

### Task 3: Carry the coverage on the submission log entry

**Files:**
- Modify: `portal/log.go:19-30`
- Test: `portal/log_test.go`

**Interfaces:**
- Consumes: `clamav.Coverage` from Task 1.
- Produces: `portal.Entry.Scan *clamav.Coverage` with JSON tag `scan,omitempty`.

- [ ] **Step 1: Write the failing tests**

Append to `portal/log_test.go`:

```go
func TestFileLog_RoundTripsScanCoverage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "submissions.jsonl")
	l := NewFileLog(path)

	want := &clamav.Coverage{Complete: false, Bytes: 34359738368}
	if err := l.Record(context.Background(), Entry{ID: "a", Moniker: "samourai", Scan: want}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	entries, err := l.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Scan == nil {
		t.Fatal("Scan = nil, want the recorded coverage")
	}
	if *entries[0].Scan != *want {
		t.Errorf("Scan = %+v, want %+v", *entries[0].Scan, *want)
	}
}

func TestFileLog_LegacyLineHasNoScanClaim(t *testing.T) {
	// Lines written before windowed scanning must decode as "unknown", not
	// as "partially scanned": the old whole-archive path did scan them in
	// full, and a false partial badge would be as misleading as a false
	// clean one.
	path := filepath.Join(t.TempDir(), "submissions.jsonl")
	line := `{"id":"a","moniker":"samourai","operator_address":"g1x","filename":"f.tar.gz","submitted_at":"2026-08-01T10:00:00Z"}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entries, err := NewFileLog(path).Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if entries[0].Scan != nil {
		t.Errorf("Scan = %+v, want nil for a line that predates the field", entries[0].Scan)
	}
}

func TestFileLog_DeletePreservesScanCoverage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "submissions.jsonl")
	l := NewFileLog(path)

	if err := l.Record(context.Background(), Entry{ID: "a", Scan: &clamav.Coverage{Complete: true, Bytes: 10}}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := l.Record(context.Background(), Entry{ID: "b", Scan: &clamav.Coverage{Complete: true, Bytes: 20}}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := l.Delete("a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	entries, err := l.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Scan == nil || entries[0].Scan.Bytes != 20 {
		t.Errorf("Scan = %+v, want the surviving entry's coverage intact after the rewrite", entries[0].Scan)
	}
}
```

Add `"os"` and `"github.com/samourai/validator-diagnostics/clamav"` to `portal/log_test.go`'s imports if they are not already there.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./portal/ -run TestFileLog -v`
Expected: FAIL to compile — `unknown field Scan in struct literal of type Entry`.

- [ ] **Step 3: Add the field**

In `portal/log.go`, add the import `"github.com/samourai/validator-diagnostics/clamav"` and extend `Entry`:

```go
type Entry struct {
	ID              string    `json:"id"`
	Moniker         string    `json:"moniker"`
	OperatorAddress string    `json:"operator_address"`
	Filename        string    `json:"filename"`
	SubmittedAt     time.Time `json:"submitted_at"`

	// Scan is what the antivirus actually examined. Non-nil is an
	// affirmative claim: a real Scanner was wired and returned a verdict
	// over Bytes bytes of extracted content. Nil claims nothing — either
	// the entry predates windowed scanning, or no scanner was wired at
	// all. There is nothing in between: a scan that errors, or finds
	// something, fails the submission outright, so no Entry is written
	// for it.
	//
	// clamav.Coverage's JSON tags are a persisted format from here on —
	// they are what submissions.jsonl holds.
	Scan *clamav.Coverage `json:"scan,omitempty"`
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./portal/ -v`
Expected: PASS. The rest of the package is unaffected — the field is additive and every other `Entry` literal leaves it nil.

- [ ] **Step 5: Commit**

```bash
git add portal/log.go portal/log_test.go
git commit -m "Record what the antivirus examined on the submission entry"
```

---

### Task 4: Scan extracted content in `/submit`

**Files:**
- Modify: `portal/submit.go:44-75` (the `AVScanBudget` field), `portal/submit.go:162-181` (the AV block), `portal/submit.go:262-277` (the `Entry`), and the end of the file (the `scanArchive` helper)
- Test: `portal/submit_test.go`

**Interfaces:**
- Consumes: `clamav.WindowedScanner`, `clamav.Coverage`, `clamav.DefaultScanBudget` (Tasks 1–2); `portal.Entry.Scan` (Task 3); the existing `submission.OpenLog(ctx, r, opts) (io.ReadCloser, error)` and `submission.Options`.
- Produces:
  - `portal.SubmitHandler.AVScanBudget int64` — zero uses `clamav.DefaultScanBudget`.
  - `func scanArchive(ctx context.Context, file io.ReadSeeker, opts submission.Options, metadata []byte, scanner clamav.Scanner, budget int64) (clamav.Verdict, clamav.Coverage, error)` — unexported, used only by `ServeHTTP`.
  - `var errUnreadableLog = errors.New(...)` — the sentinel that separates "the log's gzip header is unreadable" (a 400) from a scanner failure (a 503).

**Note on the existing test helper:** `buildValidArchive` currently writes a `gnoland.log.gz` entry of `{0x1f, 0x8b}` followed by plain text. That satisfies `ValidateArchive`'s magic-byte check but is not a gzip stream, so under this task every test that wires an `AVScanner` would get a 400. The helper must emit a real gzip. This does not change any scoring assertion: the payload has no parseable timestamps either way, so `scanLogWindow` returns the same zero-valued `LogWindowCheck`.

- [ ] **Step 1: Make the test helper build a real gzip log**

Restructure `buildValidArchive` (lines 86-133) so the log entry's raw bytes are a parameter, and keep the old name as the one-line wrapper every existing caller already uses. Nothing is duplicated: `buildValidArchive` becomes a call into `buildArchiveWithLog`.

```go
// buildValidArchive is buildArchiveWithLog carrying a genuinely
// decompressible gnoland.log.gz. The AV pass reads that stream now, so the
// hand-rolled two-magic-bytes stand-in this used to write would be rejected
// as an unreadable log rather than exercising the happy path.
func buildValidArchive(t *testing.T, validatorAddress string) []byte {
	t.Helper()
	return buildArchiveWithLog(t, validatorAddress, gzipBytes(t, []byte("fake gzip log payload")))
}

// buildArchiveWithLog builds the same archive with the gnoland.log.gz
// entry's raw bytes under the caller's control, so a test can supply a
// broken or truncated gzip.
func buildArchiveWithLog(t *testing.T, validatorAddress string, logContent []byte) []byte {
	t.Helper()

	metadata := []byte(`{
		"validator_address": "` + validatorAddress + `",
		"moniker": "samourai",
		"chain_id": "topaz-1",
		"gnoland_version": "v1.0.0",
		"genesis_sha256": "deadbeef",
		"operating_system": "Debian 12",
		"architecture": "amd64",
		"sentry_enabled": true,
		"backup_node": true,
		"hosting_provider": "Scaleway",
		"deployment_method": "docker",
		"recent_operations": "None"
	}`)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for _, e := range []struct {
		name    string
		content []byte
	}{
		{"gnoland.log.gz", logContent},
		{"metadata.json", metadata},
	} {
		hdr := &tar.Header{Name: e.name, Typeflag: tar.TypeReg, Size: int64(len(e.content)), Mode: 0o644}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write(e.content); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}

	return buf.Bytes()
}

func gzipBytes(t *testing.T, content []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(content); err != nil {
		t.Fatalf("gzip Write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}
```

- [ ] **Step 2: Write the failing tests**

Append to `portal/submit_test.go`. `submitArchive` is a small helper that removes the boilerplate repeated by every one of these:

```go
// submitArchive posts archive to a server wrapping handler and returns the
// response status. handler's Sessions must be sessions.
func submitArchive(t *testing.T, handler *SubmitHandler, sessions *auth.SessionSigner, addr crypto.Address, archive []byte) int {
	t.Helper()

	srv := httptest.NewServer(handler)
	defer srv.Close()

	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", archive)
	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+sessions.Issue(addr))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// capturingScanner records every stream it is handed, so the tests can
// assert what clamd would actually have received.
type capturingScanner struct {
	mu       sync.Mutex
	streams  [][]byte
	verdicts []clamav.Verdict
	errs     []error
}

func (s *capturingScanner) Scan(ctx context.Context, r io.Reader) (clamav.Verdict, error) {
	data, err := io.ReadAll(r)
	s.mu.Lock()
	i := len(s.streams)
	s.streams = append(s.streams, data)
	s.mu.Unlock()
	if err != nil {
		return clamav.Verdict{}, err
	}
	if i < len(s.errs) && s.errs[i] != nil {
		return clamav.Verdict{}, s.errs[i]
	}
	if i < len(s.verdicts) {
		return s.verdicts[i], nil
	}
	return clamav.Verdict{}, nil
}

func (s *capturingScanner) captured() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams
}

func TestSubmitHandler_ScansExtractedContentNotTheArchive(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	scanner := &capturingScanner{}
	submissionLog := &fakeLog{}

	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     newFakeStore(),
		Log:       submissionLog,
		AVScanner: scanner,
	}

	if status := submitArchive(t, handler, sessions, operatorAddr, buildValidArchive(t, operatorAddr.String())); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	streams := scanner.captured()
	if len(streams) != 2 {
		t.Fatalf("got %d scans, want 2 (metadata.json, then the log)", len(streams))
	}
	if !bytes.Contains(streams[0], []byte(`"moniker": "samourai"`)) {
		t.Error("the first scan is not metadata.json")
	}
	if string(streams[1]) != "fake gzip log payload" {
		t.Errorf("the second scan is %q, want the decompressed log — clamd must never see compressed or archived bytes", streams[1])
	}

	submissionLog.mu.Lock()
	defer submissionLog.mu.Unlock()
	got := submissionLog.entries[0].Scan
	if got == nil {
		t.Fatal("Entry.Scan = nil, want a coverage claim")
	}
	if !got.Complete || got.Bytes != int64(len("fake gzip log payload")) {
		t.Errorf("Scan = %+v, want complete coverage of the decompressed log", *got)
	}
}

func TestSubmitHandler_RejectsUnreadableLogGzip(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	store := newFakeStore()

	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     store,
		AVScanner: &capturingScanner{},
	}

	// The right magic bytes over a header that is not a gzip header:
	// ValidateArchive accepts it, and nothing beyond it can ever be read.
	broken := append([]byte{0x1f, 0x8b}, []byte("not really a gzip header at all")...)
	archive := buildArchiveWithLog(t, operatorAddr.String(), broken)

	if status := submitArchive(t, handler, sessions, operatorAddr, archive); status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: a log nothing can read is a log nothing can scan", status)
	}
	if _, ok := store.get("samourai-20260709-1830UTC.tar.gz"); ok {
		t.Error("the archive was stored despite being entirely unscanned")
	}
}

func TestSubmitHandler_AcceptsTruncatedLogWithPartialCoverage(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	store := newFakeStore()
	submissionLog := &fakeLog{}

	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     store,
		Log:       submissionLog,
		AVScanner: &capturingScanner{},
	}

	// A real gzip stream with its tail cut off — a full disk or a killed
	// collection process, not an exotic case. The exercise wants the
	// diagnostic it can still read.
	full := gzipBytes(t, []byte("a log that was being written when the disk filled up"))
	archive := buildArchiveWithLog(t, operatorAddr.String(), full[:len(full)-8])

	if status := submitArchive(t, handler, sessions, operatorAddr, archive); status != http.StatusOK {
		t.Fatalf("status = %d, want 200: what could be read was read", status)
	}
	if _, ok := store.get("samourai-20260709-1830UTC.tar.gz"); !ok {
		t.Error("the archive was not stored")
	}

	submissionLog.mu.Lock()
	defer submissionLog.mu.Unlock()
	got := submissionLog.entries[0].Scan
	if got == nil {
		t.Fatal("Entry.Scan = nil, want a partial coverage claim")
	}
	if got.Complete {
		t.Error("Complete = true, want false: the stream broke before the end")
	}
}

func TestSubmitHandler_NoScannerMakesNoClaim(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	submissionLog := &fakeLog{}

	handler := &SubmitHandler{
		Sessions: sessions,
		Store:    newFakeStore(),
		Log:      submissionLog,
		// AVScanner deliberately nil — cmd/portal-dev runs this way.
	}

	if status := submitArchive(t, handler, sessions, operatorAddr, buildValidArchive(t, operatorAddr.String())); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	submissionLog.mu.Lock()
	defer submissionLog.mu.Unlock()
	if submissionLog.entries[0].Scan != nil {
		t.Errorf("Scan = %+v, want nil: nothing examined this submission, so nothing may vouch for it",
			*submissionLog.entries[0].Scan)
	}
}

func TestSubmitHandler_BudgetExhaustedIsRecordedNotRejected(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	submissionLog := &fakeLog{}

	handler := &SubmitHandler{
		Sessions:     sessions,
		Store:        newFakeStore(),
		Log:          submissionLog,
		AVScanner:    &capturingScanner{},
		AVScanBudget: 5, // far below the log's decompressed length
	}

	if status := submitArchive(t, handler, sessions, operatorAddr, buildValidArchive(t, operatorAddr.String())); status != http.StatusOK {
		t.Fatalf("status = %d, want 200: exceeding the budget is recorded, not rejected", status)
	}

	submissionLog.mu.Lock()
	defer submissionLog.mu.Unlock()
	got := submissionLog.entries[0].Scan
	if got == nil || got.Complete || got.Bytes != 5 {
		t.Errorf("Scan = %+v, want {Complete:false Bytes:5}", got)
	}
}

func TestSubmitHandler_RejectsInfectedLog(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	store := newFakeStore()

	// Clean on metadata.json, infected on the log: proves the log windows
	// are verdicted too, not just the first scan.
	scanner := &capturingScanner{
		verdicts: []clamav.Verdict{{}, {Infected: true, Signature: "Test.Sig"}},
	}
	handler := &SubmitHandler{Sessions: sessions, Store: store, AVScanner: scanner}

	if status := submitArchive(t, handler, sessions, operatorAddr, buildValidArchive(t, operatorAddr.String())); status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", status)
	}
	if _, ok := store.get("samourai-20260709-1830UTC.tar.gz"); ok {
		t.Error("an infected archive was stored")
	}
}

func TestSubmitHandler_ScannerFailureOnTheLogIs503(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	store := newFakeStore()

	scanner := &capturingScanner{errs: []error{nil, errors.New("connection refused")}}
	handler := &SubmitHandler{Sessions: sessions, Store: store, AVScanner: scanner}

	if status := submitArchive(t, handler, sessions, operatorAddr, buildValidArchive(t, operatorAddr.String())); status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: a scan that could not be completed fails closed", status)
	}
	if _, ok := store.get("samourai-20260709-1830UTC.tar.gz"); ok {
		t.Error("an unscanned archive was stored")
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./portal/ -run TestSubmitHandler -v`
Expected: FAIL to compile — `unknown field AVScanBudget`. After adding the field alone, the new behavioural tests still fail: only one scan is recorded, `Entry.Scan` is nil, and the broken-gzip archive returns 200.

- [ ] **Step 4: Add the `AVScanBudget` field and correct the `AVScanner` comment**

In `portal/submit.go`, replace the `AVScanner` field's doc comment and add the budget beneath `MaxUploadSize`:

```go
	// AVScanner scans the archive's extracted content for malware before
	// it is stored (prd.md, "Security Considerations" — "Run an antivirus
	// scan (e.g. ClamAV) on extracted content").
	//
	// A nil AVScanner disables scanning entirely, and that is a real
	// configuration, not just a test shortcut: cmd/portal-dev runs this
	// way, and cmd/portal does too when -clamav-addr is unset. Nil also
	// means no Entry.Scan is recorded — the dashboard must not vouch for a
	// submission nothing examined.
	AVScanner clamav.Scanner
```

```go
	// AVScanBudget caps how many decompressed bytes of gnoland.log.gz are
	// submitted to the scanner. Zero uses clamav.DefaultScanBudget.
	// Exceeding it is recorded as partial coverage, never a rejection.
	AVScanBudget int64
```

- [ ] **Step 5: Replace the AV block**

In `portal/submit.go`, replace lines 162-181 (the whole `if h.AVScanner != nil { ... }` block) with:

```go
	// scanCoverage is nil unless a scanner actually ran: see Entry.Scan.
	var scanCoverage *clamav.Coverage

	if h.AVScanner != nil {
		verdict, coverage, err := scanArchive(r.Context(), file, h.ArchiveOptions, archiveResult.Metadata, h.AVScanner, h.AVScanBudget)
		switch {
		case errors.Is(err, errUnreadableLog):
			// ValidateArchive only checked this entry's two magic bytes,
			// so a log that cannot be decompressed at all gets this far.
			// Nothing in it was ever readable, so nothing in it can be
			// scanned, and storing it would be exactly the fail-open the
			// AV step exists to prevent.
			writeSubmitResult(w, http.StatusBadRequest, submitResponse{
				Error: fmt.Sprintf("%s could not be decompressed, so it could not be scanned: %v", submission.LogFileName, err),
			})
			return
		case err != nil:
			log.Printf("antivirus scan for %s failed: %v", header.Filename, err)
			writeSubmitResult(w, http.StatusServiceUnavailable, submitResponse{
				Error: "antivirus scan unavailable, please try again shortly",
			})
			return
		}
		if verdict.Infected {
			writeSubmitResult(w, http.StatusUnprocessableEntity, submitResponse{
				Error: fmt.Sprintf("archive rejected: malware detected (%s)", verdict.Signature),
			})
			return
		}
		if !coverage.Complete {
			// Accepted, but never silently: the budget running out and the
			// log's stream breaking are the only two incomplete outcomes,
			// and Bytes against the budget says which one happened.
			log.Printf("antivirus coverage incomplete for %s: %d bytes scanned (budget %d)",
				header.Filename, coverage.Bytes, h.avScanBudget())
		}
		scanCoverage = &coverage
	}
```

- [ ] **Step 6: Add the helper, the sentinel, and the budget accessor**

At the end of `portal/submit.go`, beside `autoChecks`:

```go
// errUnreadableLog marks a gnoland.log.gz whose gzip stream could not be
// opened at all. It is distinct from a scanner failure because the two are
// answered differently: this is the submitter's problem (400), a scanner
// failure is ours (503).
var errUnreadableLog = errors.New("not a readable gzip stream")

// scanArchive submits the archive's extracted content to scanner: first
// metadata.json, already in memory and small enough to scan whole, then the
// decompressed log in windows under budget.
//
// clamd never sees the raw .tar.gz. libclamav refuses to scan any single
// file of 2 GiB or more, and that ceiling applies to every file it extracts
// — including the decompressed log — so the archive is taken apart here
// instead, which is also what prd.md asks for ("Run an antivirus scan on
// extracted content").
//
// file must be the already-validated upload; it is rewound first, so callers
// must not rely on its offset afterwards. This is a function rather than an
// inline block so the log stream is closed as soon as the scan ends rather
// than at the end of the whole request.
func scanArchive(ctx context.Context, file io.ReadSeeker, opts submission.Options, metadata []byte, scanner clamav.Scanner, budget int64) (clamav.Verdict, clamav.Coverage, error) {
	verdict, err := scanner.Scan(ctx, bytes.NewReader(metadata))
	if err != nil {
		return clamav.Verdict{}, clamav.Coverage{}, fmt.Errorf("scanning %s: %w", submission.MetadataFileName, err)
	}
	if verdict.Infected {
		return verdict, clamav.Coverage{}, nil
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return clamav.Verdict{}, clamav.Coverage{}, fmt.Errorf("rewinding upload: %w", err)
	}
	logGz, err := submission.OpenLog(ctx, file, opts)
	if err != nil {
		return clamav.Verdict{}, clamav.Coverage{}, err
	}
	defer logGz.Close()

	gz, err := gzip.NewReader(logGz)
	if err != nil {
		return clamav.Verdict{}, clamav.Coverage{}, fmt.Errorf("%w: %v", errUnreadableLog, err)
	}
	defer gz.Close()

	return clamav.WindowedScanner{Scanner: scanner, Budget: budget}.ScanStream(ctx, gz)
}

// avScanBudget is the effective budget, for logging: WindowedScanner applies
// the same fallback internally.
func (h *SubmitHandler) avScanBudget() int64 {
	if h.AVScanBudget <= 0 {
		return clamav.DefaultScanBudget
	}
	return h.AVScanBudget
}
```

Add `"bytes"`, `"compress/gzip"` and `"errors"` to `portal/submit.go`'s imports.

- [ ] **Step 7: Attach the coverage to the entry**

In `portal/submit.go`, extend the `Entry` literal:

```go
		entry := Entry{
			ID:              submissionID,
			Moniker:         moniker,
			OperatorAddress: operatorAddr.String(),
			Filename:        header.Filename,
			SubmittedAt:     recordedAt,
			Scan:            scanCoverage,
		}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `go test ./portal/ -v`
Expected: PASS, including the pre-existing `TestSubmitHandler_StoresOriginalBytesAfterCleanScan`, `TestSubmitHandler_RejectsInfectedArchive` and `TestSubmitHandler_RejectsWhenAVScannerUnavailable` — the first now goes through the windowed path, and the latter two still reject on the `metadata.json` scan.

- [ ] **Step 9: Run the whole suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add portal/submit.go portal/submit_test.go
git commit -m "Scan metadata and the decompressed log instead of the raw archive"
```

---

### Task 5: Wire the budget knob and stop faking a scanner

**Files:**
- Modify: `cmd/portal/main.go:106-110` (flags), `:144-149` (the scanner fallback), `:156-170` and `:180-200` (`muxDeps`), and the handler construction inside `newMux`
- Modify: `docker-compose.yml:69-85`, `.env.example`, `.env`
- Test: `cmd/portal/main_test.go`

**Interfaces:**
- Consumes: `clamav.DefaultScanBudget` (Task 1), `portal.SubmitHandler.AVScanBudget` (Task 4).
- Produces: `muxDeps.AVScanBudget int64`, flag `-av-scan-budget`, env var `AV_SCAN_BUDGET`.

- [ ] **Step 1: Write the failing test**

Append to `cmd/portal/main_test.go`:

```go
func TestSubmitHandlerFor_PassesTheAVScanBudget(t *testing.T) {
	h := submitHandlerFor(muxDeps{
		AVScanner:    clamav.NoopScanner{},
		AVScanBudget: 4096,
	})
	if h.AVScanBudget != 4096 {
		t.Errorf("AVScanBudget = %d, want 4096", h.AVScanBudget)
	}
	if h.AVScanner == nil {
		t.Error("AVScanner = nil, want the wired scanner")
	}
}

func TestSubmitHandlerFor_NilScannerStaysNil(t *testing.T) {
	// The guard for the whole point of dropping the NoopScanner fallback:
	// nothing between the flag and the handler may substitute a scanner.
	if h := submitHandlerFor(muxDeps{}); h.AVScanner != nil {
		t.Errorf("AVScanner = %#v, want nil when none was wired", h.AVScanner)
	}
}
```

`newMux` currently builds the handler inline at `cmd/portal/main.go:214-224` and returns `*http.ServeMux` with no error. Extract that literal into a function in `cmd/portal/main.go` — not the test file — so there is exactly one construction site and the test asserts the real one:

```go
// submitHandlerFor builds the upload handler newMux serves at /submit.
// Extracted so the wiring can be asserted directly, without unpicking the
// routing table to reach the handler.
func submitHandlerFor(d muxDeps) *portal.SubmitHandler {
	return &portal.SubmitHandler{
		Sessions:      d.Sessions,
		Store:         d.Store,
		Log:           d.SubmissionLog,
		AVScanner:     d.AVScanner,
		AVScanBudget:  d.AVScanBudget,
		Exercise:      d.ExerciseStore,
		Scores:        d.ScoresStore,
		MaxUploadSize: d.MaxUploadSize,

		ArchiveOptions: d.ArchiveOptions,
	}
}
```

and replace the inline literal with `mux.Handle("/submit", submitHandlerFor(d))`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/portal/ -run TestSubmitHandlerFor -v`
Expected: FAIL to compile — `undefined: submitHandlerFor` and `unknown field AVScanBudget in struct literal of type muxDeps`.

- [ ] **Step 3: Add the flag, the dep, and the wiring**

In `cmd/portal/main.go`, after the `maxLogSize` flag:

```go
	avScanBudget := flag.Int64("av-scan-budget", clamav.DefaultScanBudget, "maximum decompressed bytes of gnoland.log.gz submitted to the antivirus; a submission that exceeds it is accepted and recorded as partially scanned, not rejected")
```

Add `AVScanBudget int64` to `muxDeps`, pass `AVScanBudget: *avScanBudget` in `main`'s `newMux` call, and forward it in `submitHandlerFor`.

- [ ] **Step 4: Stop falling back to `NoopScanner`**

Replace `cmd/portal/main.go:144-149` with:

```go
	// Deliberately left nil when -clamav-addr is unset, rather than filled
	// with clamav.NoopScanner: a no-op scanner returns a clean verdict over
	// every window, which would have the portal record complete coverage
	// and the dashboard show a reassuring "scan ✓" on a submission no
	// antivirus ever looked at. Nil records no coverage claim at all, which
	// is the only honest answer. NoopScanner remains in the clamav package
	// for tests, where claiming coverage is exactly what is wanted.
	var avScanner clamav.Scanner
	if *clamavAddr != "" {
		avScanner = clamav.ClamdScanner{Addr: *clamavAddr, Timeout: *clamavTimeout}
	} else {
		log.Println("-clamav-addr not set: uploads will NOT be scanned for malware (fine for local dev, not for production)")
	}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./cmd/portal/ -v`
Expected: PASS.

- [ ] **Step 6: Wire it through Compose**

In `docker-compose.yml`, after the `-max-log-size` line in the `portal` service's `command:` list:

```yaml
      # Decompressed bytes of gnoland.log.gz the antivirus may examine.
      # Past this the submission is accepted and recorded as partially
      # scanned — the cap is bomb defence, not cost control.
      - -av-scan-budget=${AV_SCAN_BUDGET:-34359738368}
```

- [ ] **Step 7: Add the variable to `.env.example` and `.env`**

Append to `.env.example` (and mirror it in the gitignored `.env`, which must **not** be staged):

```bash
# How many DECOMPRESSED bytes of gnoland.log.gz the antivirus examines, in
# bytes (default 32 GiB). The log is scanned in 1 GiB windows, so this is
# not a memory cost — it is a time cost, about four minutes at the ~142 MB/s
# clamd manages here.
#
# Exceeding it does not reject the submission: the archive is stored and the
# admin dashboard shows a "scan partiel" badge saying how much was examined.
# Its real job is zip/tar bomb defence.
AV_SCAN_BUDGET=34359738368
```

- [ ] **Step 8: Verify Compose still parses**

Run: `docker compose config --quiet && echo OK`
Expected: `OK`, with no warnings about `AV_SCAN_BUDGET`.

- [ ] **Step 9: Commit**

```bash
git add cmd/portal/main.go cmd/portal/main_test.go docker-compose.yml .env.example
git commit -m "Make the antivirus scan budget configurable"
```

---

### Task 6: Rename the scoring budget

**Files:**
- Modify: `scoring/checks.go:15, 31, 69, 79`, `scoring/score.go:70`, `scoring/checks_test.go:180, 199`
- Test: existing `scoring` tests, unchanged in behaviour

**Interfaces:**
- Consumes: nothing new.
- Produces: `scoring.maxLogWindowBytes` replaces `scoring.maxLogScanBytes`. Unexported, so no other package is affected.

After this change the same `gnoland.log.gz` is bounded twice in decompressed bytes, 32x apart and for unrelated reasons. "Scan" becomes the antivirus's word; the scoring constant is named for what it bounds.

- [ ] **Step 1: Rename every occurrence**

Run: `grep -rn maxLogScanBytes --include='*.go' .`
Expected sites: `scoring/checks.go` lines 15, 31, 69, 79; `scoring/score.go` line 70; `scoring/checks_test.go` lines 180, 199; `cmd/portal/main.go` line 84.

Rename the constant and every reference to `maxLogWindowBytes`.

- [ ] **Step 2: Update the constant's doc comment**

In `scoring/checks.go`, the comment above the constant currently opens "maxLogScanBytes bounds how much *decompressed* plaintext scanLogWindow will read". Rewrite the opening so the name and the neighbouring AV budget are both accounted for:

```go
// maxLogWindowBytes bounds how much *decompressed* plaintext scanLogWindow
// will read out of gnoland.log.gz, independent of the compressed-size cap
// submission.ValidateArchive enforces and submission.OpenLog re-applies, and
// independent of the antivirus's own decompressed budget
// (clamav.DefaultScanBudget, 32 GiB). Two budgets over the same bytes, for
// unrelated reasons: exceeding this one costs partial credit via
// LogWindowCheck.Truncated, exceeding the antivirus's costs coverage.
```

Keep the rest of the existing comment — the tar-bomb reasoning and the "not the smallest workable value" paragraph are still exactly right.

- [ ] **Step 3: Update `cmd/portal/main.go:84`**

`defaultMaxLogSize`'s comment names the old constant. Replace that sentence with one that names both decompressed bounds:

```go
// The entry is streamed and never buffered (see submission.ValidateArchive
// and submission.OpenLog), so this bounds *compressed* bytes read out of
// the archive rather than resident memory. Two separate bounds apply to the
// *decompressed* bytes: scoring.maxLogWindowBytes (1 GiB) for the log-window
// scan, and -av-scan-budget (32 GiB) for the antivirus.
```

- [ ] **Step 4: Run the tests**

Run: `go test ./... && go vet ./...`
Expected: PASS. This is a rename; no behaviour changes.

- [ ] **Step 5: Commit**

```bash
git add scoring/ cmd/portal/main.go
git commit -m "Rename the scoring log budget so \"scan\" means antivirus"
```

---

### Task 7: Show the coverage on the admin dashboard

**Files:**
- Modify: `cmd/portal/static/admin.js:170-175` (near `badge`), `:351-376` (`checksCell`)

**Interfaces:**
- Consumes: the `scan` object on each row of `GET /admin/submissions`, which arrives automatically because `AdminSubmission` embeds `Entry` (Task 3).
- Produces: nothing other code depends on.

There is no test harness for the frontend; this task is verified by reading the rendered dashboard, and by the manual end-to-end run in Task 8.

- [ ] **Step 1: Add a byte formatter**

`admin.js` has none. Copy the one from `cmd/portal/static/portal.js:39` verbatim, above `badge`:

```js
function formatBytes(n) {
  // Divides by 1024, so the labels are the binary units (MiB/GiB), not the
  // decimal ones (MB/GB) — matches the README, .env.example, and the
  // upload page's own help text, which all quote limits in MiB/GiB.
  //
  // Duplicated from portal.js rather than shared: the two files serve
  // different pages and this project has no module bundler.
  const mib = n / (1024 * 1024);
  if (mib >= 1024) {
    return (mib / 1024).toFixed(1) + " GiB";
  }
  return mib.toFixed(1) + " MiB";
}
```

- [ ] **Step 2: Render the badge outside the scoring guard**

In `admin.js`, `checksCell` is currently filled only when `s.score && s.score.scored`. Add the scan badge before that block, so it shows on unscored submissions too:

```js
    const checksCell = document.createElement("td");
    checksCell.className = "checks-cell";

    // Coverage is a property of the submission, not of the score, so this
    // sits outside the scored guard below. An absent s.scan is not a claim
    // either way: the entry predates windowed scanning, or no scanner was
    // wired. Never render anything reassuring for it.
    if (s.scan) {
      if (s.scan.complete) {
        checksCell.appendChild(badge("ok", "scan ✓"));
      } else {
        const partial = badge("caution", `scan partiel — ${formatBytes(s.scan.bytes)}`);
        partial.title =
          "The antivirus stopped before the end of the log — the budget ran out, " +
          "or the log's stream broke. The rest of it was never examined.";
        checksCell.appendChild(partial);
      }
    }

    if (s.score && s.score.scored) {
```

Leave the existing scored-only badges (`genesis`, `version`, `logs`) exactly as they are.

- [ ] **Step 3: Verify by eye**

Run the dev binary against a submissions log holding one entry with `"scan":{"complete":true,"bytes":1234567}`, one with `"scan":{"complete":false,"bytes":34359738368}`, and one legacy line with no `scan` key:

```bash
go run ./cmd/portal -help  # confirm the binary builds
```

Then open the admin dashboard and confirm three rows showing, respectively, `scan ✓`, `scan partiel — 32.0 GiB`, and no scan badge at all.

- [ ] **Step 4: Commit**

```bash
git add cmd/portal/static/admin.js
git commit -m "Show antivirus coverage on the admin dashboard"
```

---

### Task 8: Correct every text this change makes wrong

**Files:**
- Modify: `cmd/portal/main.go:62-75` (`defaultMaxUploadSize`'s comment), `:9-12` (the package comment), `:107` (`-clamav-timeout`'s usage)
- Modify: `clamd.conf:1-13`, `.env.example` (`MAX_UPLOAD_SIZE`, `MAX_LOG_SIZE`), `README.md:60-130`

**Interfaces:**
- Consumes: everything above. No code changes.

Each of these currently asserts something that stops being true the moment clamd receives extracted content instead of the archive. Leaving them is worse than never having written them: they name libclamav's ceiling as the reason for limits it no longer constrains.

- [ ] **Step 1: `cmd/portal/main.go`**

- The package comment (lines 9-12) says uploads "are streamed to clamd for a malware scan before being stored" and to keep `-max-upload-size` at or below `StreamMaxLength`. Rewrite: the archive's *extracted content* is streamed to clamd, `StreamMaxLength` now only has to cover one 1 GiB window, and the scan still fails closed.
- `defaultMaxUploadSize`'s comment (lines 62-75) attributes `2147483647` to libclamav's ceiling. Rewrite: that is where the ceiling was left when the wall stopped binding it. Raising it is now a disk, S3 and time question — `storage.S3Store.Save` issues a single `PutObject`, which S3 caps at 5 GiB, and that is the first thing that would have to move.
- `-clamav-timeout`'s usage string (line 107) says it "must comfortably cover streaming a whole `-max-upload-size` archive to clamd". It now bounds a single window: at most 1 GiB, roughly 7 seconds at the measured rate. Say that; leave the 15-minute default alone.

- [ ] **Step 2: `clamd.conf`**

The header comment (lines 1-13) justifies the 2 GiB values by the size of archive the portal accepts. Rewrite the justification: the portal now sends extracted content in 1 GiB windows, so `StreamMaxLength` only has to cover one window plus its 1 MiB overlap. The values stay at `2147483647` as headroom rather than as a binding constraint, and `AlertExceedsMax yes` stays exactly as important as before. Do not change any directive value.

- [ ] **Step 3: `.env.example`**

- `MAX_UPLOAD_SIZE`'s comment says raising it "does not work" because libclamav cannot scan a larger file. That is no longer why. Rewrite: the ceiling is now a disk/S3/time question, and `storage.S3Store.Save`'s single `PutObject` (5 GiB) is the next limit.
- `MAX_LOG_SIZE`'s comment says a compressed entry past ~140 MB decompresses beyond what clamd can scan and is rejected with a 503. That is precisely what stops being true. Rewrite: the decompressed log is scanned in windows, so the antivirus no longer caps it; what caps it is `AV_SCAN_BUDGET` (coverage, not rejection) and `scoring.maxLogWindowBytes` (partial credit, not rejection).

- [ ] **Step 4: `README.md`**

- Add a `-av-scan-budget` row to the flags table and an `AV_SCAN_BUDGET` row to the environment table, both stating that exceeding the budget records partial coverage rather than rejecting.
- Correct the `-clamav-timeout` and `-max-upload-size` / `MAX_UPLOAD_SIZE` / `MAX_LOG_SIZE` rows in the same way as `.env.example`.
- Rewrite "Upload size and ClamAV": clamd receives `metadata.json` and the decompressed log in 1 GiB windows with a 1 MiB overlap, never the raw archive.
- Rewrite "The 2 GiB wall": keep the warning text and the ClamAV 1.5.3 verification — the wall is real and is *why* a window is 1 GiB — but replace the closing paragraph ("Accepting genuinely large archives therefore needs the portal to ... That work is not done yet") with what now happens.
- Add a short subsection on what a partially scanned submission means: accepted, stored, badged in the dashboard, never silently treated as clean. State that with `-clamav-addr` unset the dashboard shows no scan badge at all rather than a reassuring one.

- [ ] **Step 5: Check no stale claim survives**

Run:

```bash
grep -rn "StreamMaxLength\|2 GiB\|2147483647\|not done yet" README.md .env.example clamd.conf cmd/portal/main.go docker-compose.yml
```

Read every hit and confirm each one still states something true.

- [ ] **Step 6: Full verification**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS.

- [ ] **Step 7: Manual end-to-end run**

This is the whole point of the work and cannot be asserted in Go:

```bash
docker compose up -d --build
# wait for the clamav service to report healthy (it downloads ~1 GB of signatures on first run)
docker compose ps
```

Submit `test/samourai-crew-huge-20260805-2232UTC.tar.gz` — the 2.41 GB archive that motivated this change — through the portal UI. Confirm:

1. It is **accepted** (it currently fails with a 503).
2. The admin dashboard shows `scan ✓` on the row.
3. `submissions.jsonl` carries a `"scan":{"complete":true,...}` object on that entry.
4. `docker compose logs clamav` shows no `Max file-size was set to` warning.

- [ ] **Step 8: Commit**

```bash
git add README.md .env.example clamd.conf cmd/portal/main.go
git commit -m "Retire the documentation that blames libclamav for the upload ceiling"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
| --- | --- |
| 1. The windowed scanner — geometry, overlap, budget, completeness | 1 |
| 1. Telling a broken source from a broken scanner | 2 |
| 2. The scan path in `/submit`, response codes, corrupt/truncated logs | 4 |
| 2. `AVScanner` nil means no scan and no claim | 4 (handler), 5 (`cmd/portal` wiring) |
| 3. Recording the coverage on `portal.Entry` | 3 |
| 4. The budget knob | 5 |
| 4. Naming: two decompressed-byte budgets | 6 |
| 4. Text that this change makes wrong | 8 |
| 5. Admin dashboard | 7 |
| Testing — `clamav/windowed_test.go` | 1, 2 |
| Testing — `portal/submit_test.go` | 4 |
| Testing — `portal/log_test.go`, `cmd/portal/main_test.go`, manual run | 3, 5, 8 |

**Type consistency:** `Coverage{Complete bool, Bytes int64}` is defined in Task 1 and used unchanged in Tasks 2, 3, 4 and 7 (`s.scan.complete` / `s.scan.bytes` match the JSON tags). `ScanStream(ctx, r) (Verdict, Coverage, error)` keeps its signature through Task 2. `scanArchive`'s parameter list in Task 4 matches its call site in the same task. `AVScanBudget` is named identically on `SubmitHandler` (Task 4), `muxDeps` (Task 5) and the flag `-av-scan-budget` (Task 5).

**Behaviour changes an implementer must not treat as incidental:**

1. `buildValidArchive`'s log entry stops being a fake gzip (Task 4, Step 1). Without it, every existing test that wires an `AVScanner` gets the new 400. It changes no scoring assertion — the payload has no parseable timestamps either way, so `scanLogWindow` returns the same zero-valued `LogWindowCheck`.
2. `cmd/portal` no longer substitutes `NoopScanner` for a missing `-clamav-addr` (Task 5, Step 4). This is the whole reason the dashboard can be trusted; it is not a cleanup.
3. A `gnoland.log.gz` that cannot be decompressed at all is now rejected where it used to be stored and quietly scored low (Task 4). A *truncated* one is still accepted.
