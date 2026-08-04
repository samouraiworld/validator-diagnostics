package exercise

import (
	"errors"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{
		AnnouncedAt:              time.Date(2026, 7, 8, 18, 0, 0, 0, time.UTC),
		DeadlineAt:               time.Date(2026, 7, 9, 19, 30, 0, 0, time.UTC),
		InvestigationWindowStart: time.Date(2026, 7, 8, 18, 0, 0, 0, time.UTC),
		InvestigationWindowEnd:   time.Date(2026, 7, 9, 18, 30, 0, 0, time.UTC),
		ExpectedGenesisSHA256:    "deadbeef",
		SupportedGnolandVersions: []string{"v1.0.0"},
	}
}

func TestConfig_Validate_OK(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestConfig_Validate_DeadlineNotAfterAnnounced(t *testing.T) {
	cfg := validConfig()
	cfg.DeadlineAt = cfg.AnnouncedAt
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() = nil, want an error when deadline_at == announced_at")
	}

	cfg.DeadlineAt = cfg.AnnouncedAt.Add(-time.Hour)
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() = nil, want an error when deadline_at is before announced_at")
	}
}

func TestConfig_Validate_WindowEndNotAfterStart(t *testing.T) {
	cfg := validConfig()
	cfg.InvestigationWindowEnd = cfg.InvestigationWindowStart
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() = nil, want an error when investigation_window_end == investigation_window_start")
	}
}

func TestConfig_Configured(t *testing.T) {
	if (Config{}).Configured() {
		t.Error("zero-value Config should report Configured() == false")
	}
	if !validConfig().Configured() {
		t.Error("a fully set Config should report Configured() == true")
	}
}

func TestConfig_Validate_RequiresSomethingToCheckAgainst(t *testing.T) {
	// An exercise with no expected genesis hash, or no supported version
	// list, has nothing to compare a submission against — and the checks
	// don't report "not configured", they report a mismatch. Every
	// validator would then be flagged as submitting the wrong genesis or
	// an unsupported version, with nothing pointing at the config as the
	// cause. Reject it at the point the admin can still fix it.
	t.Run("no expected genesis hash", func(t *testing.T) {
		cfg := validConfig()
		cfg.ExpectedGenesisSHA256 = "   "
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() = nil, want an error")
		} else if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("Validate() = %v, want it to wrap ErrInvalidConfig", err)
		}
	})

	t.Run("no supported versions", func(t *testing.T) {
		cfg := validConfig()
		cfg.SupportedGnolandVersions = nil
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() = nil, want an error")
		} else if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("Validate() = %v, want it to wrap ErrInvalidConfig", err)
		}
	})
}
