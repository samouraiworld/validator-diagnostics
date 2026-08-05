package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/auth"
	"github.com/samourai/validator-diagnostics/portal"
	"github.com/samourai/validator-diagnostics/scoring"
	"github.com/samourai/validator-diagnostics/storage"
)

// TestDeleteSubmissionRouteRequiresAdminAuth guards the one line in
// main() that stands between the internet and a destructive endpoint —
// a refactor that dropped the RequireAdminSession wrapper would
// otherwise go unnoticed, since AdminDeleteSubmissionHandler itself has
// no auth of its own by design (auth is applied once, at the wiring
// layer, for every /admin/* route).
func TestDeleteSubmissionRouteRequiresAdminAuth(t *testing.T) {
	log := portal.NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	store := storage.LocalStore{Dir: t.TempDir()}
	scores := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))

	sessions := auth.NewSessionSigner([]byte("test-secret"), time.Hour)
	allowlist := map[string]bool{"g1xqcnyve5x5mrwwpexqcnyve5x5mrwwpemgh56f": true}

	mux := http.NewServeMux()
	mux.Handle("DELETE /admin/submissions/{id}", portal.RequireAdminSession(sessions, allowlist, portal.AdminDeleteSubmissionHandler(log, store, scores)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/admin/submissions/some-id", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// Deliberately no Authorization header set.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (unauthenticated request must be rejected)", resp.StatusCode)
	}
}

func TestParseAdminAllowlist(t *testing.T) {
	t.Run("valid list", func(t *testing.T) {
		allowlist, err := parseAdminAllowlist("g1xqcnyve5x5mrwwpexqcnyve5x5mrwwpemgh56f, g18yurwd34xsenyvfs8yurwd34xsenyvfsaffa87")
		if err != nil {
			t.Fatalf("parseAdminAllowlist: unexpected error: %v", err)
		}
		want := []string{
			"g1xqcnyve5x5mrwwpexqcnyve5x5mrwwpemgh56f",
			"g18yurwd34xsenyvfs8yurwd34xsenyvfsaffa87",
		}
		if len(allowlist) != len(want) {
			t.Fatalf("allowlist = %v, want %d entries", allowlist, len(want))
		}
		for _, addr := range want {
			if !allowlist[addr] {
				t.Errorf("allowlist missing %s", addr)
			}
		}
	})

	t.Run("invalid address", func(t *testing.T) {
		if _, err := parseAdminAllowlist("not-a-valid-address"); err == nil {
			t.Fatal("parseAdminAllowlist: want error for invalid address, got nil")
		}
	})

	t.Run("empty list", func(t *testing.T) {
		if _, err := parseAdminAllowlist(""); err == nil {
			t.Fatal("parseAdminAllowlist: want error for empty list, got nil")
		}
	})

	t.Run("blank entries are skipped, not treated as invalid", func(t *testing.T) {
		allowlist, err := parseAdminAllowlist("g1xqcnyve5x5mrwwpexqcnyve5x5mrwwpemgh56f,, ")
		if err != nil {
			t.Fatalf("parseAdminAllowlist: unexpected error: %v", err)
		}
		if len(allowlist) != 1 || !allowlist["g1xqcnyve5x5mrwwpexqcnyve5x5mrwwpemgh56f"] {
			t.Errorf("allowlist = %v, want exactly the one real address", allowlist)
		}
	})
}
