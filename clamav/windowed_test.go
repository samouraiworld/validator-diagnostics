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
