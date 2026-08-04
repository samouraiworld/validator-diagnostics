package scoring

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/submission"
)

func gzipLines(t *testing.T, lines ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	for _, l := range lines {
		if _, err := gw.Write([]byte(l + "\n")); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func windowTestConfig() exercise.Config {
	return exercise.Config{
		InvestigationWindowStart: time.Date(2026, 7, 8, 18, 0, 0, 0, time.UTC),
		InvestigationWindowEnd:   time.Date(2026, 7, 9, 18, 30, 0, 0, time.UTC),
		ExpectedGenesisSHA256:    "abc123",
		SupportedGnolandVersions: []string{"v1.0.0", "v1.0.1"},
	}
}

func TestAutoChecks_GenesisAndVersionMatch(t *testing.T) {
	cfg := windowTestConfig()
	meta := submission.Metadata{GenesisSHA256: "abc123", GnolandVersion: "v1.0.1"}
	logGz := gzipLines(t, "2026-07-08T19:00:00Z hello")

	genesisMatch, versionSupported, _ := AutoChecks(meta, logGz, cfg)
	if !genesisMatch {
		t.Error("genesisMatch = false, want true")
	}
	if !versionSupported {
		t.Error("versionSupported = false, want true")
	}
}

func TestAutoChecks_GenesisAndVersionMismatch(t *testing.T) {
	cfg := windowTestConfig()
	meta := submission.Metadata{GenesisSHA256: "wrong-hash", GnolandVersion: "v9.9.9"}
	logGz := gzipLines(t, "2026-07-08T19:00:00Z hello")

	genesisMatch, versionSupported, _ := AutoChecks(meta, logGz, cfg)
	if genesisMatch {
		t.Error("genesisMatch = true, want false")
	}
	if versionSupported {
		t.Error("versionSupported = true, want false")
	}
}

func TestAutoChecks_LogWindowFullyCovered(t *testing.T) {
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-08T17:00:00Z starting up",
		"2026-07-08T20:00:00Z consensus running",
		"2026-07-09T19:00:00Z shutting down",
	)

	_, _, window := AutoChecks(submission.Metadata{}, logGz, cfg)
	if !window.Detected || !window.Covered {
		t.Errorf("window = %+v, want Detected and Covered", window)
	}
}

func TestAutoChecks_LogWindowStartsAfterWindowOpened(t *testing.T) {
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-08T19:00:00Z starting up",
		"2026-07-08T20:00:00Z consensus running",
	)

	_, _, window := AutoChecks(submission.Metadata{}, logGz, cfg)
	if !window.Detected {
		t.Error("window.Detected = false, want true")
	}
	if window.Covered {
		t.Error("window.Covered = true, want false (the log begins after the investigation window opened)")
	}
}

func TestAutoChecks_LogWindowEndsBeforeWindowClosed(t *testing.T) {
	// The start side is fine and only the end side fails. Without this
	// case the end-side half of the coverage check is dead weight: a
	// start-side-only implementation passes every other test in the repo.
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-08T17:00:00Z starting up before the window opened",
		"2026-07-09T10:00:00Z stopped well before the window closed",
	)

	_, _, window := AutoChecks(submission.Metadata{}, logGz, cfg)
	if !window.Detected {
		t.Error("window.Detected = false, want true")
	}
	if window.Covered {
		t.Error("window.Covered = true, want false (the log ends before the investigation window closed)")
	}
}

func TestScanLogWindow_TruncatedIsNotTreatedAsCovered(t *testing.T) {
	// A log whose real timestamps span one second, padded past the scan
	// budget. It says nothing about covering a 24-hour window, so it must
	// not score as if it did: an unverified tail is not a verified one.
	cfg := windowTestConfig()

	const budget = 64 << 10
	lines := []string{"2026-07-08T17:00:00Z starting up"}
	filler := "2026-07-08T17:00:01Z " + strings.Repeat("x", 200)
	for len(lines)*len(filler) < budget*2 {
		lines = append(lines, filler)
	}
	lines = append(lines, "2026-07-09T19:00:00Z shutting down") // past the budget, never read
	logGz := gzipLines(t, lines...)

	window := scanLogWindow(logGz, cfg, budget)
	if !window.Truncated {
		t.Fatalf("window = %+v, want Truncated (the budget, not the log, ended the scan)", window)
	}
	if !window.Detected {
		t.Error("window.Detected = false, want true")
	}
	if window.Covered {
		t.Error("window.Covered = true, want false: the tail was never read, so coverage was never verified")
	}
	if got := LogQualityScore(window); got != 15 {
		t.Errorf("LogQualityScore = %d, want 15 (partial credit — detected but unverified, neither full marks nor a penalty)", got)
	}
}

func TestScanLogWindow_OverlongLineMarksTruncated(t *testing.T) {
	// bufio.Scanner gives up on a line past its buffer cap. That ends the
	// scan for our reasons, not the submitter's, so it has to raise the
	// same "unverified" signal the byte budget does — otherwise the
	// generated summary states as fact that a validator's logs miss the
	// window, when all that happened is our buffer overflowed.
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-08T17:00:00Z starting up before the window opened",
		strings.Repeat("x", maxLogLineBytes+1), // e.g. a panic dump
		"2026-07-09T19:00:00Z ran past the end of the window",
	)

	window := scanLogWindow(logGz, cfg, maxLogScanBytes)
	if !window.Truncated {
		t.Fatalf("window = %+v, want Truncated (an over-long line ended the scan early)", window)
	}
	if window.Covered {
		t.Error("window.Covered = true, want false: the scan never reached the closing timestamp")
	}
}

func TestScanLogWindow_UsesEarliestAndLatestTimestamps(t *testing.T) {
	// Rotated log files concatenated out of order, or interleaved
	// goroutine output, break the assumption that the first line carries
	// the earliest timestamp and the last line the latest.
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-09T19:00:00Z this line is last chronologically but comes first",
		"2026-07-08T17:00:00Z and this one is earliest but comes last",
	)

	window := scanLogWindow(logGz, cfg, maxLogScanBytes)
	if want := time.Date(2026, 7, 8, 17, 0, 0, 0, time.UTC); !window.FirstSeen.Equal(want) {
		t.Errorf("FirstSeen = %v, want %v (the earliest timestamp, not the first line)", window.FirstSeen, want)
	}
	if want := time.Date(2026, 7, 9, 19, 0, 0, 0, time.UTC); !window.LastSeen.Equal(want) {
		t.Errorf("LastSeen = %v, want %v (the latest timestamp, not the last line)", window.LastSeen, want)
	}
	if !window.Covered {
		t.Error("window.Covered = false, want true: the timestamps present do span the window")
	}
}

func TestScanLogWindow_BudgetBoundsDecompression(t *testing.T) {
	// The bomb defence: gnoland.log.gz's content is itself compressed
	// plaintext that ValidateArchive never decompresses, so this is the
	// first place decompression happens and the budget is what keeps a
	// small upload from expanding without limit.
	cfg := windowTestConfig()

	const budget = 64 << 10
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	line := []byte("2026-07-08T17:00:00Z " + strings.Repeat("x", 200) + "\n")
	for i := 0; i < 100*budget/len(line); i++ {
		if _, err := gw.Write(line); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	window := scanLogWindow(buf.Bytes(), cfg, budget)
	if !window.Truncated {
		t.Errorf("window = %+v, want Truncated: the scan must stop at its budget rather than decompress the whole stream", window)
	}
}

func TestAutoChecks_LogWindowNotTruncatedWhenUnderCap(t *testing.T) {
	cfg := windowTestConfig()
	logGz := gzipLines(t, "2026-07-08T17:00:00Z starting up", "2026-07-09T19:00:00Z shutting down")

	_, _, window := AutoChecks(submission.Metadata{}, logGz, cfg)
	if window.Truncated {
		t.Errorf("window = %+v, want Truncated = false for a log well under the cap", window)
	}
}

func TestAutoChecks_LogWindowNoTimestamps(t *testing.T) {
	cfg := windowTestConfig()
	logGz := gzipLines(t, "no timestamp here", "nor here either")

	_, _, window := AutoChecks(submission.Metadata{}, logGz, cfg)
	if window.Detected {
		t.Errorf("window = %+v, want !Detected", window)
	}
}

func TestAutoChecks_LogNotGzip(t *testing.T) {
	cfg := windowTestConfig()

	_, _, window := AutoChecks(submission.Metadata{}, []byte("not gzip at all"), cfg)
	if window.Detected || window.Covered {
		t.Errorf("window = %+v, want the zero value for unparseable input", window)
	}
}
