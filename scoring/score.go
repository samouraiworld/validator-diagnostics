// Package scoring implements prd.md's Phase 3 "Evaluation Criteria":
// the 4x25-point rubric (upload completion time, metadata completeness,
// log quality, incident response quality) and the automatic checks
// (genesis hash, gnoland version, log time window) that feed part of
// it. See docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md
// and docs/superpowers/specs/2026-08-04-merge-ack-upload-scoring-design.md
// for the full design and the rationale behind each formula below, and
// docs/superpowers/specs/2026-08-06-sentry-log-scoring-design.md for the
// sentry-log split, which supersedes the log-quality parts (the
// LogQualityScore breakdown and the 13/+12/+6 figures) of those two
// earlier documents.
package scoring

import (
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
)

// TieredTimeScore scores upload completion time: full marks for acting
// in the first quarter of the announce-to-deadline window, degrading by
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
	// An event before the exercise was announced hasn't happened yet as
	// far as the rubric is concerned. Without this, elapsed is negative
	// and satisfies the first tier — full marks. Unreachable in
	// practice since t is always the server clock at upload time, but
	// the guard costs nothing.
	if elapsed < 0 {
		return 0
	}

	switch {
	case elapsed <= total/4:
		return 25
	case elapsed <= total/2:
		return 19
	// total/4*3, not total*3/4: the latter overflows time.Duration's
	// int64 nanoseconds for a window past ~97 years and wraps negative,
	// so the tier would never fire.
	case elapsed <= total/4*3:
		return 13
	case elapsed <= total:
		return 6
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
	// reasons — the decompression budget (maxLogWindowBytes) ran out, or a
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

	// ScannedBytes is how much decompressed content the scan actually
	// read. It exists to separate the two ways a log can end up
	// undetected: an empty file, and a file full of lines nothing could
	// parse. Both score the same, but only the second is worth
	// investigating, and telling a validator "no recognizable timestamps"
	// about an empty upload sends them looking for a formatting problem
	// they do not have.
	//
	// Records written before this field existed decode it as 0, which
	// reads as "empty". That is only correct after a rescore has rewritten
	// them (see cmd/rescore); until then, treat a 0 here as unknown.
	ScannedBytes int64 `json:"scanned_bytes,omitempty"`
}

// LogQualityScore combines the fixed base credit for passing archive
// structure validation — already enforced before a submission is ever
// scored, see submission.ValidateArchive — with credit for how well
// each submitted log's timestamps cover the investigation window.
//
// The sentry log is worth 4 of the 25, taken out of the validator log's
// share rather than added on top: the rubric totals 100 and this
// criterion caps at 25. A submission with no sentry log therefore caps
// at 21. That is the intended incentive — running a sentry is the
// behaviour this is meant to reward, and a criterion every submission
// maxes out measures nothing.
func LogQualityScore(validator, sentry LogWindowCheck) int {
	const structuralBase = 13
	return structuralBase + windowCredit(validator, 8, 4) + windowCredit(sentry, 4, 2)
}

// windowCredit grades one log's window check: full credit for verified
// coverage, partial for timestamps that were found but do not (or could
// not be shown to) span the window, none for a log that yielded no
// recognizable timestamp — which is also what an absent optional log
// yields, since its zero LogWindowCheck is not Detected.
func windowCredit(w LogWindowCheck, covered, detected int) int {
	switch {
	case w.Covered:
		return covered
	case w.Detected:
		return detected
	default:
		return 0
	}
}
