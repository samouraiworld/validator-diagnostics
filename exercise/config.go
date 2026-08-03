// Package exercise holds the admin-configured parameters of a single
// fire-drill exercise (prd.md, "Fire Drill Procedure" / "Evaluation
// Criteria") — the values the scoring package needs to know to judge a
// submission: when the exercise was announced and is due, what
// investigation window the logs should cover, and what genesis
// hash/gnoland version are expected.
package exercise

import (
	"fmt"
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

// Validate enforces the two timing invariants scoring depends on: a
// non-empty announce-to-deadline window (scoring.TieredTimeScore
// divides by its length) and a non-empty investigation window.
func (c Config) Validate() error {
	if !c.DeadlineAt.After(c.AnnouncedAt) {
		return fmt.Errorf("deadline_at (%s) must be after announced_at (%s)", c.DeadlineAt, c.AnnouncedAt)
	}
	if !c.InvestigationWindowEnd.After(c.InvestigationWindowStart) {
		return fmt.Errorf("investigation_window_end (%s) must be after investigation_window_start (%s)", c.InvestigationWindowEnd, c.InvestigationWindowStart)
	}
	return nil
}
