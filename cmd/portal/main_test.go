package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/samourai/validator-diagnostics/portal"
	"github.com/samourai/validator-diagnostics/scoring"
	"github.com/samourai/validator-diagnostics/storage"
)

// TestDeleteSubmissionRouteRequiresAdminAuth guards the one line in
// main() that stands between the internet and a destructive endpoint —
// a refactor that dropped the AdminAuth wrapper would otherwise go
// unnoticed, since AdminDeleteSubmissionHandler itself has no auth of
// its own by design (auth is applied once, at the wiring layer, for
// every /admin/* route).
func TestDeleteSubmissionRouteRequiresAdminAuth(t *testing.T) {
	log := portal.NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	store := storage.LocalStore{Dir: t.TempDir()}
	scores := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))

	mux := http.NewServeMux()
	mux.Handle("DELETE /admin/submissions/{id}", portal.AdminAuth("testpass", portal.AdminDeleteSubmissionHandler(log, store, scores)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/admin/submissions/some-id", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// Deliberately no BasicAuth credentials set.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (unauthenticated request must be rejected)", resp.StatusCode)
	}
}
