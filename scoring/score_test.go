package scoring

import (
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
)

func testExerciseConfig() exercise.Config {
	return exercise.Config{
		AnnouncedAt: time.Date(2026, 7, 8, 18, 0, 0, 0, time.UTC),
		DeadlineAt:  time.Date(2026, 7, 8, 22, 0, 0, 0, time.UTC), // 4h window, 1h quarters
	}
}

func TestTieredTimeScore(t *testing.T) {
	cfg := testExerciseConfig()

	cases := []struct {
		name string
		at   time.Time
		want int
	}{
		{"at announcement", cfg.AnnouncedAt, 25},
		// Not 25: an event predating the exercise hasn't happened yet as
		// far as the rubric goes. Unreachable in practice since t is the
		// server clock, but guarded anyway — see TieredTimeScore.
		{"before announcement", cfg.AnnouncedAt.Add(-time.Minute), 0},
		{"exactly 25%", cfg.AnnouncedAt.Add(1 * time.Hour), 25},
		{"just past 25%", cfg.AnnouncedAt.Add(1*time.Hour + time.Second), 19},
		{"exactly 50%", cfg.AnnouncedAt.Add(2 * time.Hour), 19},
		{"just past 50%", cfg.AnnouncedAt.Add(2*time.Hour + time.Second), 13},
		{"exactly 75%", cfg.AnnouncedAt.Add(3 * time.Hour), 13},
		{"just past 75%", cfg.AnnouncedAt.Add(3*time.Hour + time.Second), 6},
		{"exactly at deadline (100%)", cfg.DeadlineAt, 6},
		{"just past deadline", cfg.DeadlineAt.Add(time.Second), 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := TieredTimeScore(c.at, cfg)
			if got != c.want {
				t.Errorf("TieredTimeScore(%s) = %d, want %d", c.name, got, c.want)
			}
		})
	}
}

func TestLogQualityScore(t *testing.T) {
	// No sentry log submitted (the zero LogWindowCheck): the validator
	// log alone caps at 21, not the old 25 — 4 of the 25 points now
	// belong to a covering sentry log. See
	// TestLogQualityScore_SplitsCreditBetweenBothLogs for the full
	// cross-product of validator/sentry outcomes.
	cases := []struct {
		name   string
		window LogWindowCheck
		want   int
	}{
		{"fully covered", LogWindowCheck{Detected: true, Covered: true}, 21},
		{"detected but not covered", LogWindowCheck{Detected: true, Covered: false}, 17},
		{"nothing detected", LogWindowCheck{}, 13},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := LogQualityScore(c.window, LogWindowCheck{})
			if got != c.want {
				t.Errorf("LogQualityScore(%+v, none) = %d, want %d", c.window, got, c.want)
			}
		})
	}
}

func TestLogQualityScore_SplitsCreditBetweenBothLogs(t *testing.T) {
	covered := LogWindowCheck{Detected: true, Covered: true}
	detected := LogWindowCheck{Detected: true}
	none := LogWindowCheck{}

	cases := []struct {
		name              string
		validator, sentry LogWindowCheck
		want              int
	}{
		{"both covered is full marks", covered, covered, 25},
		{"covered validator, no sentry", covered, none, 21},
		{"covered validator, sentry detected only", covered, detected, 23},
		{"validator detected only, no sentry", detected, none, 17},
		{"validator detected only, sentry covered", detected, covered, 21},
		{"neither detected", none, none, 13},
		{"no validator log, sentry covered", none, covered, 17},
		{"truncated validator scan is not covered", LogWindowCheck{Detected: true, Truncated: true}, none, 17},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LogQualityScore(tc.validator, tc.sentry); got != tc.want {
				t.Errorf("LogQualityScore = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestTieredTimeScore_LongWindowDoesNotOverflow(t *testing.T) {
	// total*3/4 overflows time.Duration's int64 nanoseconds once the
	// window passes ~97 years, wrapping negative so the 75% tier never
	// fires. An absurd config, but silently scoring the wrong tier is
	// worse than the arithmetic being obviously careful.
	announced := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := exercise.Config{AnnouncedAt: announced, DeadlineAt: announced.Add(100 * 365 * 24 * time.Hour)}

	sixtyPercent := announced.Add(60 * 365 * 24 * time.Hour)
	if got := TieredTimeScore(sixtyPercent, cfg); got != 13 {
		t.Errorf("TieredTimeScore at 60%% of a 100-year window = %d, want 13", got)
	}
}
