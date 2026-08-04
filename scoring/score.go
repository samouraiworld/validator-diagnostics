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
	// Covered is true only if the recognized timestamps were *verified* to
	// span the full investigation window, which takes a scan that reached
	// the end of the log. A truncated scan is therefore never Covered —
	// see Truncated.
	Covered bool `json:"covered"`

	// Truncated is true when scanLogWindow stopped early for its own
	// reasons — the decompression budget (maxLogScanBytes) ran out, or a
	// single line exceeded maxLogLineBytes — rather than because the log
	// ended. Everything past that point is unread, so the end of the
	// window is unverifiable and Covered is false.
	//
	// That limit is ours, not the submitter's fault, so the three states
	// are kept distinct rather than collapsed into pass/fail: a truncated
	// scan earns the same partial credit as any other detected-but-not-
	// covering log (LogQualityScore) and the generated summary reports it
	// as "could not be fully verified", never as the validator's logs
	// failing to cover the window.
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
