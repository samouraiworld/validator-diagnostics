package portal

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/scoring"
)

func TestAdminSummaryHandler(t *testing.T) {
	submissionLog := NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	if err := submissionLog.Record(context.Background(), Entry{
		ID:              "scored-1",
		Moniker:         "samourai",
		OperatorAddress: "g1abc",
		Filename:        "samourai-20260709-1830UTC.tar.gz",
		SubmittedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := submissionLog.Record(context.Background(), Entry{
		ID:              "unscored-1",
		Moniker:         "other",
		OperatorAddress: "g1def",
		Filename:        "other-20260709-1830UTC.tar.gz",
		SubmittedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	exerciseStore := exercise.NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	if err := exerciseStore.Set(exercise.Config{
		AnnouncedAt:              time.Now().UTC().Add(-2 * time.Hour),
		DeadlineAt:               time.Now().UTC().Add(2 * time.Hour),
		InvestigationWindowStart: time.Now().UTC().Add(-24 * time.Hour),
		InvestigationWindowEnd:   time.Now().UTC(),
		Observations:             "Everyone please double-check log rotation settings.",
	}); err != nil {
		t.Fatalf("exerciseStore.Set: %v", err)
	}

	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if err := scoresStore.Set(scoring.Result{
		SubmissionID:     "scored-1",
		Scored:           true,
		GenesisMatch:     false,
		VersionSupported: true,
		LogWindow:        scoring.LogWindowCheck{Detected: true, Covered: true},
		UploadTimeScore:  20,
		MetadataScore:    20,
		LogQualityScore:  20,
	}); err != nil {
		t.Fatalf("scoresStore.Set: %v", err)
	}

	srv := httptest.NewServer(AdminSummaryHandler(submissionLog, exerciseStore, scoresStore))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	text := string(body)

	for _, want := range []string{
		"2 submission",                  // participation count
		"samourai",                      // scored entry's moniker
		"other",                         // unscored entry's moniker
		"not yet scored",                // unscored entry's status
		"genesis_sha256 does not match", // warning for the mismatched genesis
		"Everyone please double-check log rotation", // free-text observations
	} {
		if !strings.Contains(text, want) {
			t.Errorf("summary text missing %q; got:\n%s", want, text)
		}
	}
}

func TestAdminSummaryHandler_NoObservations(t *testing.T) {
	submissionLog := NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	if err := submissionLog.Record(context.Background(), Entry{
		ID:              "submission-1",
		Moniker:         "validator",
		OperatorAddress: "g1xyz",
		Filename:        "validator-20260709-1830UTC.tar.gz",
		SubmittedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	exerciseStore := exercise.NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	if err := exerciseStore.Set(exercise.Config{
		AnnouncedAt:              time.Now().UTC().Add(-2 * time.Hour),
		DeadlineAt:               time.Now().UTC().Add(2 * time.Hour),
		InvestigationWindowStart: time.Now().UTC().Add(-24 * time.Hour),
		InvestigationWindowEnd:   time.Now().UTC(),
		Observations:             "", // Empty observations
	}); err != nil {
		t.Fatalf("exerciseStore.Set: %v", err)
	}

	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if err := scoresStore.Set(scoring.Result{
		SubmissionID:     "submission-1",
		Scored:           true,
		GenesisMatch:     true,
		VersionSupported: true,
		LogWindow:        scoring.LogWindowCheck{Detected: true, Covered: true},
		UploadTimeScore:  25,
		MetadataScore:    25,
		LogQualityScore:  25,
	}); err != nil {
		t.Fatalf("scoresStore.Set: %v", err)
	}

	srv := httptest.NewServer(AdminSummaryHandler(submissionLog, exerciseStore, scoresStore))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	text := string(body)

	// Verify that **Observations:** section is NOT present
	if strings.Contains(text, "**Observations:**") {
		t.Errorf("summary text should not contain **Observations:** section when observations are empty; got:\n%s", text)
	}

	// Verify basic content is still present
	if !strings.Contains(text, "1 submission") {
		t.Errorf("summary text missing participation count; got:\n%s", text)
	}
	if !strings.Contains(text, "validator") {
		t.Errorf("summary text missing validator moniker; got:\n%s", text)
	}
}
