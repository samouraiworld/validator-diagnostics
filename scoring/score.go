// Package scoring implements prd.md's Phase 3 "Evaluation Criteria":
// the 5x20-point rubric (acknowledgement time, upload completion time,
// metadata completeness, log quality, incident response quality) and
// the automatic checks (genesis hash, gnoland version, log time
// window) that feed part of it. See
// docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md for
// the full design and the rationale behind each formula below.
package scoring

import (
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
)

// TieredTimeScore implements the tiered formula shared by upload
// completion time and acknowledgement time: full marks for acting in
// the first quarter of the announce-to-deadline window, degrading by
// quarter, zero once past the deadline. A non-positive
// (DeadlineAt - AnnouncedAt) — i.e. an unconfigured or invalid exercise
// — always scores 0; callers are expected to check
// exercise.Config.Configured() before relying on this for anything
// other than that fallback.
func TieredTimeScore(t time.Time, cfg exercise.Config) int {
	total := cfg.DeadlineAt.Sub(cfg.AnnouncedAt)
	if total <= 0 {
		return 0
	}
	elapsed := t.Sub(cfg.AnnouncedAt)

	switch {
	case elapsed <= total/4:
		return 20
	case elapsed <= total/2:
		return 15
	case elapsed <= total*3/4:
		return 10
	case elapsed <= total:
		return 5
	default:
		return 0
	}
}

// LogWindowCheck is the result of scanning a submitted log for
// timestamps that fall within the exercise's investigation window
// (see scanLogWindow in checks.go, Task 6).
type LogWindowCheck struct {
	// Detected is false if no recognizable timestamp was found at all
	// — parsing is best-effort, so this is a warning condition, not an
	// error.
	Detected bool `json:"detected"`
	// Covered is true if Detected and the recognized timestamps span the
	// full investigation window. When Truncated is true the tail of the
	// log was never read, so LastSeen carries no information about the
	// end of the window and only the start side is checked — see
	// Truncated.
	Covered bool `json:"covered"`

	// Truncated is true when scanLogWindow stopped because it hit its own
	// decompression cap (maxLogScanBytes), not because the log ended. The
	// cap is ours, so a truncated scan is never held against the
	// submitter: coverage is decided on the start side alone and the
	// generated summary reports "could not be fully verified" rather than
	// the "does not cover the window" warning.
	Truncated bool `json:"truncated,omitempty"`

	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

// LogQualityScore combines the fixed base credit for passing archive
// structure validation — already enforced before a submission is ever
// scored, see submission.ValidateArchive — with credit for how well
// the detected log timestamps cover the investigation window.
func LogQualityScore(window LogWindowCheck) int {
	const structuralBase = 10
	switch {
	case window.Covered:
		return structuralBase + 10
	case window.Detected:
		return structuralBase + 5
	default:
		return structuralBase
	}
}
