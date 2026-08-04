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

// summaryText runs AdminSummaryHandler over a single submission carrying
// result, and returns the generated Markdown.
func summaryText(t *testing.T, result scoring.Result) string {
	t.Helper()

	submissionLog := NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	if err := submissionLog.Record(context.Background(), Entry{
		ID:              result.SubmissionID,
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
	}); err != nil {
		t.Fatalf("exerciseStore.Set: %v", err)
	}

	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if err := scoresStore.Set(result); err != nil {
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
	return string(body)
}

func TestAdminSummaryHandler_TruncatedLogScan(t *testing.T) {
	// The scan stopped at its own size cap, so coverage was never
	// verified. That is this tool's limit, not the validator's fault: the
	// summary must say so informationally and must not accuse the
	// validator of submitting logs that don't cover the window.
	text := summaryText(t, scoring.Result{
		SubmissionID:     "truncated-1",
		Scored:           true,
		GenesisMatch:     true,
		VersionSupported: true,
		LogWindow:        scoring.LogWindowCheck{Detected: true, Covered: true, Truncated: true},
		UploadTimeScore:  20,
		MetadataScore:    20,
		LogQualityScore:  20,
	})

	if !strings.Contains(text, "could not be fully verified") {
		t.Errorf("summary missing the truncated-scan note; got:\n%s", text)
	}
	if strings.Contains(text, "do not fully cover") {
		t.Errorf("summary blames the validator for a scan-cap truncation; got:\n%s", text)
	}
}

func TestAdminSummaryHandler_UncoveredLogStillWarns(t *testing.T) {
	// The counterpart: a genuinely short log (scan never hit its cap)
	// keeps the original warning.
	text := summaryText(t, scoring.Result{
		SubmissionID:     "uncovered-1",
		Scored:           true,
		GenesisMatch:     true,
		VersionSupported: true,
		LogWindow:        scoring.LogWindowCheck{Detected: true, Covered: false},
		UploadTimeScore:  20,
		MetadataScore:    20,
		LogQualityScore:  15,
	})

	if !strings.Contains(text, "do not fully cover") {
		t.Errorf("summary missing the coverage warning; got:\n%s", text)
	}
	if strings.Contains(text, "could not be fully verified") {
		t.Errorf("summary shows the truncation note for an untruncated scan; got:\n%s", text)
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
