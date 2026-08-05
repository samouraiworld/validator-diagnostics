package portal

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/scoring"
)

func TestAdminAuth(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := AdminAuth("correct-password", inner)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	t.Run("correct password", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		req.SetBasicAuth("admin", "correct-password")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		req.SetBasicAuth("admin", "wrong-password")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("no credentials", func(t *testing.T) {
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})
}

func TestAdminSubmissionsHandler(t *testing.T) {
	path := filepath.Join(t.TempDir(), "submissions.jsonl")
	fileLog := NewFileLog(path)
	if err := fileLog.Record(context.Background(), Entry{
		ID:              "entry-1",
		Moniker:         "samourai",
		OperatorAddress: "g1abc",
		Filename:        "samourai-20260709-1830UTC.tar.gz",
		SubmittedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if err := scoresStore.Set(scoring.Result{SubmissionID: "entry-1", Scored: true, UploadTimeScore: 20}); err != nil {
		t.Fatalf("scoresStore.Set: %v", err)
	}

	srv := httptest.NewServer(AdminSubmissionsHandler(fileLog, scoresStore))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var submissions []AdminSubmission
	if err := json.NewDecoder(resp.Body).Decode(&submissions); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(submissions) != 1 || submissions[0].Moniker != "samourai" {
		t.Fatalf("submissions = %+v, want one entry for samourai", submissions)
	}
	if submissions[0].Score == nil || submissions[0].Score.UploadTimeScore != 20 {
		t.Errorf("Score = %+v, want a joined scoring.Result with UploadTimeScore 20", submissions[0].Score)
	}
}

func TestAdminSubmissionsHandler_TotalAndPending(t *testing.T) {
	// total_score/pending are computed server-side from scoring.Result so
	// the dashboard never reimplements the rubric, and so a submission
	// still missing its manual scores can't be mistaken for a final one.
	fileLog := NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	for _, id := range []string{"partial", "complete"} {
		if err := fileLog.Record(context.Background(), Entry{
			ID:          id,
			Moniker:     id,
			SubmittedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	irq := 15
	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if err := scoresStore.Set(scoring.Result{
		SubmissionID: "partial", Scored: true,
		UploadTimeScore: 25, MetadataScore: 25, LogQualityScore: 25,
	}); err != nil {
		t.Fatalf("scoresStore.Set: %v", err)
	}
	if err := scoresStore.Set(scoring.Result{
		SubmissionID: "complete", Scored: true,
		UploadTimeScore: 25, MetadataScore: 25, LogQualityScore: 25,
		IncidentResponseQualityScore: &irq,
	}); err != nil {
		t.Fatalf("scoresStore.Set: %v", err)
	}

	srv := httptest.NewServer(AdminSubmissionsHandler(fileLog, scoresStore))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	var submissions []AdminSubmission
	if err := json.NewDecoder(resp.Body).Decode(&submissions); err != nil {
		t.Fatalf("decode: %v", err)
	}

	byID := map[string]AdminSubmission{}
	for _, s := range submissions {
		byID[s.ID] = s
	}
	if got := byID["partial"]; got.TotalScore != 75 || !got.Pending {
		t.Errorf("partial: total_score = %d, pending = %v; want 75, true", got.TotalScore, got.Pending)
	}
	if got := byID["complete"]; got.TotalScore != 90 || got.Pending {
		t.Errorf("complete: total_score = %d, pending = %v; want 90, false", got.TotalScore, got.Pending)
	}
}

func TestAdminSubmissionsHandler_UnscoredIsPendingEvenWithManualScores(t *testing.T) {
	// A record with manual scores but no automatic half is contradictory:
	// its total carries none of the automatic points, so presenting it as
	// final would publish a meaningless "25/100". The scoring endpoint now
	// refuses to create that state, but records written before it did — or
	// edited by hand — still exist, so the join has to hold the line too.
	fileLog := NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	if err := fileLog.Record(context.Background(), Entry{
		ID: "never-auto-scored", Moniker: "validator", SubmittedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	irq := 5
	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if err := scoresStore.Set(scoring.Result{
		SubmissionID: "never-auto-scored", Scored: false,
		IncidentResponseQualityScore: &irq,
	}); err != nil {
		t.Fatalf("scoresStore.Set: %v", err)
	}

	srv := httptest.NewServer(AdminSubmissionsHandler(fileLog, scoresStore))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	var submissions []AdminSubmission
	if err := json.NewDecoder(resp.Body).Decode(&submissions); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(submissions) != 1 {
		t.Fatalf("got %d submissions, want 1", len(submissions))
	}
	if got := submissions[0]; got.TotalScore != 0 || !got.Pending {
		t.Errorf("total_score = %d, pending = %v; want 0, true — an unscored submission has no total to show",
			got.TotalScore, got.Pending)
	}
}

func TestAdminSubmissionsHandler_UnreadableScoresIsNotPending(t *testing.T) {
	// A corrupt or unreadable scores file must not render as a dashboard
	// full of "pending" rows — that would hide total loss of the scoring
	// data behind a perfectly normal-looking page.
	fileLog := NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	if err := fileLog.Record(context.Background(), Entry{
		ID: "entry-3", Moniker: "samourai", SubmittedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	scoresPath := filepath.Join(t.TempDir(), "scores.json")
	if err := os.WriteFile(scoresPath, []byte("{ this is not json"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	srv := httptest.NewServer(AdminSubmissionsHandler(fileLog, scoring.NewStore(scoresPath)))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "scoring records") {
		t.Errorf("body = %q, want it to name the scoring records as the problem", body)
	}
}

func TestAdminSubmissionsHandler_NilScoreWhenUnscored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "submissions.jsonl")
	fileLog := NewFileLog(path)
	if err := fileLog.Record(context.Background(), Entry{
		ID:              "entry-2",
		Moniker:         "other",
		OperatorAddress: "g1def",
		Filename:        "other-20260709-1830UTC.tar.gz",
		SubmittedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json")) // nothing recorded

	srv := httptest.NewServer(AdminSubmissionsHandler(fileLog, scoresStore))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	var submissions []AdminSubmission
	if err := json.NewDecoder(resp.Body).Decode(&submissions); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(submissions) != 1 || submissions[0].Score != nil {
		t.Errorf("submissions = %+v, want Score == nil for an unscored entry", submissions)
	}
}
