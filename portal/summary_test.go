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
		ExpectedGenesisSHA256:    "deadbeef",
		SupportedGnolandVersions: []string{"v1.0.0"},
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
		ExpectedGenesisSHA256:    "deadbeef",
		SupportedGnolandVersions: []string{"v1.0.0"},
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

func TestAdminSummaryHandler_PendingManualScores(t *testing.T) {
	// This text gets pasted into Discord, so a total that is still
	// missing manually entered criteria must not read as a final mark.
	ack := 20

	both := summaryText(t, scoring.Result{
		SubmissionID: "pending-both", Scored: true,
		GenesisMatch: true, VersionSupported: true,
		LogWindow:       scoring.LogWindowCheck{Detected: true, Covered: true},
		UploadTimeScore: 20, MetadataScore: 20, LogQualityScore: 20,
	})
	if !strings.Contains(both, "60/100 (ack + incident response pending)") {
		t.Errorf("summary missing the pending annotation; got:\n%s", both)
	}

	one := summaryText(t, scoring.Result{
		SubmissionID: "pending-one", Scored: true,
		GenesisMatch: true, VersionSupported: true,
		LogWindow:       scoring.LogWindowCheck{Detected: true, Covered: true},
		UploadTimeScore: 20, MetadataScore: 20, LogQualityScore: 20,
		AckTimeScore: &ack,
	})
	if !strings.Contains(one, "80/100 (incident response pending)") {
		t.Errorf("summary missing the partial pending annotation; got:\n%s", one)
	}
}

func TestAdminSummaryHandler_CompleteScoreHasNoPendingNote(t *testing.T) {
	ack, irq := 20, 20
	text := summaryText(t, scoring.Result{
		SubmissionID: "complete", Scored: true,
		GenesisMatch: true, VersionSupported: true,
		LogWindow:       scoring.LogWindowCheck{Detected: true, Covered: true},
		UploadTimeScore: 20, MetadataScore: 20, LogQualityScore: 20,
		AckTimeScore: &ack, IncidentResponseQualityScore: &irq,
	})

	if !strings.Contains(text, "100/100\n") {
		t.Errorf("summary missing the bare final total; got:\n%s", text)
	}
	if strings.Contains(text, "pending") {
		t.Errorf("summary annotates a fully scored submission as pending; got:\n%s", text)
	}
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
		// The reachable shape: a truncated scan cannot verify the end of
		// the window, so Covered is false. What distinguishes it from a
		// genuinely short log is Truncated, and only that.
		LogWindow:       scoring.LogWindowCheck{Detected: true, Covered: false, Truncated: true},
		UploadTimeScore: 20,
		MetadataScore:   20,
		LogQualityScore: 15,
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
		ExpectedGenesisSHA256:    "deadbeef",
		SupportedGnolandVersions: []string{"v1.0.0"},
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

func TestAdminSummaryHandler_NoSubmissions(t *testing.T) {
	// The state the summary is in for most of an exercise: announced,
	// nobody has uploaded yet. It has to render, not divide by zero or
	// emit a headerless blank.
	submissionLog := NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	exerciseStore := exercise.NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	if err := exerciseStore.Set(exercise.Config{
		AnnouncedAt:              time.Now().UTC().Add(-2 * time.Hour),
		DeadlineAt:               time.Now().UTC().Add(2 * time.Hour),
		InvestigationWindowStart: time.Now().UTC().Add(-24 * time.Hour),
		InvestigationWindowEnd:   time.Now().UTC(),
		ExpectedGenesisSHA256:    "deadbeef",
		SupportedGnolandVersions: []string{"v1.0.0"},
	}); err != nil {
		t.Fatalf("exerciseStore.Set: %v", err)
	}
	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))

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

	if !strings.Contains(text, "Validator Fire Drill") {
		t.Errorf("summary missing its heading; got:\n%s", text)
	}
	if !strings.Contains(text, "0 submission") {
		t.Errorf("summary missing a zero participation count; got:\n%s", text)
	}
}

func TestAdminHandlers_RejectWrongMethod(t *testing.T) {
	// All three implement their own method routing, and none of it was
	// covered.
	submissionLog := NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	exerciseStore := exercise.NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))

	handlers := map[string]http.Handler{
		"submissions": AdminSubmissionsHandler(submissionLog, scoresStore),
		"summary":     AdminSummaryHandler(submissionLog, exerciseStore, scoresStore),
		"exercise":    exercise.ConfigHandler(exerciseStore),
	}
	// exercise.ConfigHandler serves GET and POST; the other two are
	// GET-only.
	methods := map[string][]string{
		"submissions": {http.MethodPost, http.MethodPut, http.MethodDelete},
		"summary":     {http.MethodPost, http.MethodPut, http.MethodDelete},
		"exercise":    {http.MethodPut, http.MethodDelete},
	}

	for name, h := range handlers {
		srv := httptest.NewServer(h)
		defer srv.Close()

		for _, method := range methods[name] {
			t.Run(name+" "+method, func(t *testing.T) {
				req, err := http.NewRequest(method, srv.URL, nil)
				if err != nil {
					t.Fatalf("NewRequest: %v", err)
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("%s: %v", method, err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusMethodNotAllowed {
					t.Errorf("status = %d, want 405", resp.StatusCode)
				}
			})
		}
	}
}
