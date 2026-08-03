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
		{"at announcement", cfg.AnnouncedAt, 20},
		{"before announcement", cfg.AnnouncedAt.Add(-time.Minute), 20},
		{"exactly 25%", cfg.AnnouncedAt.Add(1 * time.Hour), 20},
		{"just past 25%", cfg.AnnouncedAt.Add(1*time.Hour + time.Second), 15},
		{"exactly 50%", cfg.AnnouncedAt.Add(2 * time.Hour), 15},
		{"just past 50%", cfg.AnnouncedAt.Add(2*time.Hour + time.Second), 10},
		{"exactly 75%", cfg.AnnouncedAt.Add(3 * time.Hour), 10},
		{"just past 75%", cfg.AnnouncedAt.Add(3*time.Hour + time.Second), 5},
		{"exactly at deadline (100%)", cfg.DeadlineAt, 5},
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
	cases := []struct {
		name   string
		window LogWindowCheck
		want   int
	}{
		{"fully covered", LogWindowCheck{Detected: true, Covered: true}, 20},
		{"detected but not covered", LogWindowCheck{Detected: true, Covered: false}, 15},
		{"nothing detected", LogWindowCheck{}, 10},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := LogQualityScore(c.window)
			if got != c.want {
				t.Errorf("LogQualityScore(%+v) = %d, want %d", c.window, got, c.want)
			}
		})
	}
}
