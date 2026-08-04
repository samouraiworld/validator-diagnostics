package portal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
