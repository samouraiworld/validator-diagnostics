package scoring

import (
	"bytes"
	"compress/gzip"
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

func TestAutoChecks_LogWindowPartiallyCovered(t *testing.T) {
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
		t.Error("window.Covered = true, want false (log ends well before the investigation window does)")
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
