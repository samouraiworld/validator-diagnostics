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

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/scoring"
)

func newTestScoreServer(t *testing.T, entryID string, cfg exercise.Config) (*httptest.Server, *scoring.Store) {
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

	exerciseStore := exercise.NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	if cfg.Configured() {
		if err := exerciseStore.Set(cfg); err != nil {
			t.Fatalf("exerciseStore.Set: %v", err)
		}
	}

	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))

	mux := http.NewServeMux()
	mux.Handle("POST /admin/submissions/{id}/score", AdminScoreHandler(submissionLog, exerciseStore, scoresStore))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv, scoresStore
}

func TestAdminScoreHandler_Success(t *testing.T) {
	cfg := exercise.Config{
		AnnouncedAt:              time.Now().UTC().Add(-2 * time.Hour),
		DeadlineAt:               time.Now().UTC().Add(2 * time.Hour),
		InvestigationWindowStart: time.Now().UTC().Add(-24 * time.Hour),
		InvestigationWindowEnd:   time.Now().UTC(),
	}
	srv, scoresStore := newTestScoreServer(t, "entry-1", cfg)

	body, _ := json.Marshal(map[string]any{
		"acknowledged_at":                 time.Now().UTC().Format(time.RFC3339),
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
	if result.AckTimeScore == nil {
		t.Fatal("AckTimeScore was not computed")
	}
}

func TestAdminScoreHandler_RejectsNonJSONContentType(t *testing.T) {
	// The shape a cross-site CSRF attempt takes: a form POST carrying a
	// JSON-shaped body under a "simple request" content type, riding on
	// the admin's cached Basic credentials. It must be refused before the
	// body is decoded, and nothing may be written to the scores store.
	cfg := exercise.Config{
		AnnouncedAt:              time.Now().UTC().Add(-2 * time.Hour),
		DeadlineAt:               time.Now().UTC().Add(2 * time.Hour),
		InvestigationWindowStart: time.Now().UTC().Add(-24 * time.Hour),
		InvestigationWindowEnd:   time.Now().UTC(),
	}

	body, _ := json.Marshal(map[string]any{
		"acknowledged_at":                 time.Now().UTC().Format(time.RFC3339),
		"incident_response_quality_score": 20,
	})

	for _, contentType := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""} {
		t.Run("content-type "+contentType, func(t *testing.T) {
			srv, scoresStore := newTestScoreServer(t, "entry-1", cfg)

			resp, err := http.Post(srv.URL+"/admin/submissions/entry-1/score", contentType, bytes.NewReader(body))
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415", resp.StatusCode)
			}

			if _, ok, err := scoresStore.Get("entry-1"); err != nil || ok {
				t.Errorf("scoresStore.Get: ok=%v err=%v, want the request to have been rejected before anything was stored", ok, err)
			}
		})
	}
}

func TestAdminScoreHandler_AcceptsJSONWithCharset(t *testing.T) {
	cfg := exercise.Config{
		AnnouncedAt:              time.Now().UTC().Add(-2 * time.Hour),
		DeadlineAt:               time.Now().UTC().Add(2 * time.Hour),
		InvestigationWindowStart: time.Now().UTC().Add(-24 * time.Hour),
		InvestigationWindowEnd:   time.Now().UTC(),
	}
	srv, _ := newTestScoreServer(t, "entry-1", cfg)

	body, _ := json.Marshal(map[string]any{
		"acknowledged_at":                 time.Now().UTC().Format(time.RFC3339),
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
	cfg := exercise.Config{
		AnnouncedAt:              time.Now().UTC().Add(-time.Hour),
		DeadlineAt:               time.Now().UTC().Add(time.Hour),
		InvestigationWindowStart: time.Now().UTC().Add(-24 * time.Hour),
		InvestigationWindowEnd:   time.Now().UTC(),
	}
	srv, _ := newTestScoreServer(t, "entry-1", cfg)

	body, _ := json.Marshal(map[string]any{
		"acknowledged_at":                 time.Now().UTC().Format(time.RFC3339),
		"incident_response_quality_score": 25,
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
	// 0/20. Recording one would flip Result.Pending() to false and let the
	// dashboard and the generated summary present a fabricated total as
	// final — exactly what the pending state exists to prevent.
	cfg := exercise.Config{
		AnnouncedAt:              time.Now().UTC().Add(-time.Hour),
		DeadlineAt:               time.Now().UTC().Add(time.Hour),
		InvestigationWindowStart: time.Now().UTC().Add(-24 * time.Hour),
		InvestigationWindowEnd:   time.Now().UTC(),
	}

	bodies := map[string]string{
		"omitted":       `{"acknowledged_at":"` + time.Now().UTC().Format(time.RFC3339) + `"}`,
		"null":          `{"acknowledged_at":"` + time.Now().UTC().Format(time.RFC3339) + `","incident_response_quality_score":null}`,
		"misspelt key":  `{"acknowledged_at":"` + time.Now().UTC().Format(time.RFC3339) + `","incident_response_score":19}`,
		"empty string":  `{"acknowledged_at":"` + time.Now().UTC().Format(time.RFC3339) + `","incident_response_quality_score":""}`,
		"missing ack":   `{"incident_response_quality_score":19}`,
		"unknown field": `{"acknowledged_at":"` + time.Now().UTC().Format(time.RFC3339) + `","incident_response_quality_score":19,"bogus":true}`,
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			srv, scoresStore := newTestScoreServer(t, "entry-1", cfg)

			resp, err := http.Post(srv.URL+"/admin/submissions/entry-1/score", "application/json", strings.NewReader(body))
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}

			if _, ok, err := scoresStore.Get("entry-1"); err != nil || ok {
				t.Errorf("scoresStore.Get: ok=%v err=%v, want nothing stored for a rejected request", ok, err)
			}
		})
	}
}

func TestAdminScoreHandler_RejectsUnknownID(t *testing.T) {
	cfg := exercise.Config{
		AnnouncedAt:              time.Now().UTC().Add(-time.Hour),
		DeadlineAt:               time.Now().UTC().Add(time.Hour),
		InvestigationWindowStart: time.Now().UTC().Add(-24 * time.Hour),
		InvestigationWindowEnd:   time.Now().UTC(),
	}
	srv, _ := newTestScoreServer(t, "entry-1", cfg)

	body, _ := json.Marshal(map[string]any{
		"acknowledged_at":                 time.Now().UTC().Format(time.RFC3339),
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

func TestAdminScoreHandler_RejectsWhenExerciseNotConfigured(t *testing.T) {
	srv, _ := newTestScoreServer(t, "entry-1", exercise.Config{}) // never configured

	body, _ := json.Marshal(map[string]any{
		"acknowledged_at":                 time.Now().UTC().Format(time.RFC3339),
		"incident_response_quality_score": 10,
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
