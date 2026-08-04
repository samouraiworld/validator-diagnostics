// Package exercise holds the admin-configured parameters of a single
// fire-drill exercise (prd.md, "Fire Drill Procedure" / "Evaluation
// Criteria") — the values the scoring package needs to know to judge a
// submission: when the exercise was announced and is due, what
// investigation window the logs should cover, and what genesis
// hash/gnoland version are expected.
package exercise

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Config is the exercise-wide configuration an admin sets once (and
// may update) via POST /admin/exercise.
type Config struct {
	AnnouncedAt              time.Time `json:"announced_at"`
	DeadlineAt               time.Time `json:"deadline_at"`
	InvestigationWindowStart time.Time `json:"investigation_window_start"`
	InvestigationWindowEnd   time.Time `json:"investigation_window_end"`

	ExpectedGenesisSHA256    string   `json:"expected_genesis_sha256"`
	SupportedGnolandVersions []string `json:"supported_gnoland_versions"`

	// Observations is free text, included verbatim at the end of the
	// generated summary (see portal.AdminSummaryHandler).
	Observations string `json:"observations"`
}

// Configured reports whether an admin has ever set this exercise up,
// as opposed to the zero Config returned before that's happened.
func (c Config) Configured() bool {
	return !c.AnnouncedAt.IsZero() || !c.DeadlineAt.IsZero()
}

// ErrInvalidConfig wraps every error Validate returns, so callers can
// tell "the admin sent something wrong" (a 400 they can act on) from
// "the disk is full" (a 500 they can't). Without it both arrive through
// FileStore.Set's single error return and an unwritable path reads as
// bad input, leaving the admin retyping a form that was always correct.
var ErrInvalidConfig = errors.New("invalid exercise config")

// Validate enforces the two timing invariants scoring depends on: a
// non-empty announce-to-deadline window (scoring.TieredTimeScore
// divides by its length) and a non-empty investigation window.
func (c Config) Validate() error {
	if !c.DeadlineAt.After(c.AnnouncedAt) {
		return fmt.Errorf("%w: deadline_at (%s) must be after announced_at (%s)", ErrInvalidConfig, c.DeadlineAt, c.AnnouncedAt)
	}
	if !c.InvestigationWindowEnd.After(c.InvestigationWindowStart) {
		return fmt.Errorf("%w: investigation_window_end (%s) must be after investigation_window_start (%s)", ErrInvalidConfig, c.InvestigationWindowEnd, c.InvestigationWindowStart)
	}
	// The genesis and version checks don't have a "not configured"
	// outcome — they compare, and an empty expectation compares unequal
	// to everything. Left unset, they'd report every submission as a
	// mismatch, which reads as the validators being wrong rather than the
	// exercise being half-configured. Refuse at the point the admin can
	// still fix it.
	if strings.TrimSpace(c.ExpectedGenesisSHA256) == "" {
		return fmt.Errorf("%w: expected_genesis_sha256 is required — without it every submission is reported as a genesis mismatch", ErrInvalidConfig)
	}
	if len(c.SupportedGnolandVersions) == 0 {
		return fmt.Errorf("%w: supported_gnoland_versions must list at least one version — without it every submission is reported as unsupported", ErrInvalidConfig)
	}
	return nil
}
