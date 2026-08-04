package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/scoring"
)

// newTestScoreServer sets up a submission log with one recorded entry
// and, if autoScored is true, a matching scoring.Result with its
// automatic half already filled in — the shape SubmitHandler leaves
// behind when the exercise was configured at submit time.
func newTestScoreServer(t *testing.T, entryID string, autoScored bool) (*httptest.Server, *scoring.Store) {
	t.Helper()

	submissionLog := NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	if err := submissionLog.Record(context.Background(), Entry{
		ID:              entryID,
		Moniker:         "samourai",
		OperatorAddress: "g1abc",
		Filename:        "samourai-20260709-1830UTC.tar.gz",
		SubmittedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if autoScored {
		if err := scoresStore.Set(scoring.Result{
			SubmissionID:    entryID,
			Scored:          true,
			UploadTimeScore: 25,
			MetadataScore:   25,
			LogQualityScore: 19,
		}); err != nil {
			t.Fatalf("scoresStore.Set: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.Handle("POST /admin/submissions/{id}/score", AdminScoreHandler(submissionLog, scoresStore))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv, scoresStore
}

// assertUnscored checks a rejected request left the manual field alone.
// The record itself exists — SubmitHandler wrote the automatic half —
// so "nothing was stored" means specifically that no manual score was.
func assertUnscored(t *testing.T, scores *scoring.Store, id string) {
	t.Helper()
	result, ok, err := scores.Get(id)
	if err != nil {
		t.Fatalf("scoresStore.Get: %v", err)
	}
	if !ok {
		return
	}
	if result.IncidentResponseQualityScore != nil {
		t.Errorf("result = %+v, want the manual field untouched by a rejected request", result)
	}
}

func TestAdminScoreHandler_Success(t *testing.T) {
	srv, scoresStore := newTestScoreServer(t, "entry-1", true)

	body, _ := json.Marshal(map[string]any{
		"incident_response_quality_score": 18,
	})
	resp, err := http.Post(srv.URL+"/admin/submissions/entry-1/score", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	result, ok, err := scoresStore.Get("entry-1")
	if err != nil || !ok {
		t.Fatalf("scoresStore.Get: ok=%v err=%v", ok, err)
	}
	if result.IncidentResponseQualityScore == nil || *result.IncidentResponseQualityScore != 18 {
		t.Errorf("IncidentResponseQualityScore = %v, want 18", result.IncidentResponseQualityScore)
	}
}

func TestAdminScoreHandler_RejectsNonJSONContentType(t *testing.T) {
	// The shape a cross-site CSRF attempt takes: a form POST carrying a
	// JSON-shaped body under a "simple request" content type, riding on
	// the admin's cached Basic credentials. It must be refused before the
	// body is decoded, and nothing may be written to the scores store.
	body, _ := json.Marshal(map[string]any{
		"incident_response_quality_score": 20,
	})

	for _, contentType := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""} {
		t.Run("content-type "+contentType, func(t *testing.T) {
			srv, scoresStore := newTestScoreServer(t, "entry-1", true)

			resp, err := http.Post(srv.URL+"/admin/submissions/entry-1/score", contentType, bytes.NewReader(body))
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415", resp.StatusCode)
			}

			assertUnscored(t, scoresStore, "entry-1")
		})
	}
}

func TestAdminScoreHandler_AcceptsJSONWithCharset(t *testing.T) {
	srv, _ := newTestScoreServer(t, "entry-1", true)

	body, _ := json.Marshal(map[string]any{
		"incident_response_quality_score": 12,
	})
	resp, err := http.Post(srv.URL+"/admin/submissions/entry-1/score", "application/json; charset=utf-8", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestAdminScoreHandler_RejectsOutOfRangeScore(t *testing.T) {
	srv, _ := newTestScoreServer(t, "entry-1", true)

	body, _ := json.Marshal(map[string]any{
		"incident_response_quality_score": 30,
	})
	resp, err := http.Post(srv.URL+"/admin/submissions/entry-1/score", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAdminScoreHandler_RejectsMissingScore(t *testing.T) {
	// A score the admin never entered must not decode to a valid-looking
	// 0. Recording one would flip Result.Pending() to false and let the
	// dashboard and the generated summary present a fabricated total as
	// final — exactly what the pending state exists to prevent.
	bodies := map[string]string{
		"omitted":       `{}`,
		"null":          `{"incident_response_quality_score":null}`,
		"misspelt key":  `{"incident_response_score":19}`,
		"empty string":  `{"incident_response_quality_score":""}`,
		"unknown field": `{"incident_response_quality_score":19,"bogus":true}`,
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			srv, scoresStore := newTestScoreServer(t, "entry-1", true)

			resp, err := http.Post(srv.URL+"/admin/submissions/entry-1/score", "application/json", strings.NewReader(body))
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}

			assertUnscored(t, scoresStore, "entry-1")
		})
	}
}

func TestAdminScoreHandler_RejectsUnknownID(t *testing.T) {
	srv, _ := newTestScoreServer(t, "entry-1", true)

	body, _ := json.Marshal(map[string]any{
		"incident_response_quality_score": 10,
	})
	resp, err := http.Post(srv.URL+"/admin/submissions/does-not-exist/score", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminScoreHandler_RejectsSubmissionThatWasNeverAutoScored(t *testing.T) {
	// A submission that arrived before the exercise was configured has no
	// automatic half and can never get one — AutoChecks needs the log
	// bytes, which aren't retained. Accepting a manual score for it
	// produces a record that reads as complete (Pending false) while
	// carrying none of the automatic points, i.e. a "final" 5/100 that
	// means nothing. Refuse instead of recording the contradiction. This
	// is also, now that AdminScoreHandler no longer reads exercise
	// config at all, the only way an "exercise not configured" style
	// rejection can happen — there's no separate 400 for that anymore.
	srv, scoresStore := newTestScoreServer(t, "entry-1", false)

	// The shape SubmitHandler records when no exercise existed yet.
	if err := scoresStore.Set(scoring.Result{SubmissionID: "entry-1", Scored: false}); err != nil {
		t.Fatalf("scoresStore.Set: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"incident_response_quality_score": 5,
	})
	resp, err := http.Post(srv.URL+"/admin/submissions/entry-1/score", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}

	result, ok, err := scoresStore.Get("entry-1")
	if err != nil || !ok {
		t.Fatalf("scoresStore.Get: ok=%v err=%v", ok, err)
	}
	if result.IncidentResponseQualityScore != nil {
		t.Errorf("result = %+v, want the manual field left unset", result)
	}
}
