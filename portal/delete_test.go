package portal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/scoring"
	"github.com/samourai/validator-diagnostics/storage"
)

// failingDeleteStore wraps a real LocalStore but always fails Delete,
// to exercise AdminDeleteSubmissionHandler's "storage failed, don't
// touch the log/score" path without a real broken backend.
type failingDeleteStore struct {
	storage.LocalStore
}

func (failingDeleteStore) Delete(ctx context.Context, key string) error {
	return errors.New("simulated storage failure")
}

func newTestDeleteServer(t *testing.T, store storage.Store) (srv *httptest.Server, log *FileLog, scores *scoring.Store) {
	t.Helper()

	log = NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	if err := log.Record(context.Background(), Entry{
		ID:              "entry-1",
		Moniker:         "samourai",
		OperatorAddress: "g1abc",
		Filename:        "samourai-20260709-1830UTC.tar.gz",
		SubmittedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	scores = scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if err := scores.Set(scoring.Result{SubmissionID: "entry-1", Scored: true, UploadTimeScore: 20}); err != nil {
		t.Fatalf("scores.Set: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("DELETE /admin/submissions/{id}", AdminDeleteSubmissionHandler(log, store, scores))
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv, log, scores
}

func doDelete(t *testing.T, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

func TestAdminDeleteSubmissionHandler_Success(t *testing.T) {
	uploadDir := t.TempDir()
	store := storage.LocalStore{Dir: uploadDir}
	if err := store.Save(context.Background(), "samourai-20260709-1830UTC.tar.gz", strings.NewReader("archive bytes"), 13); err != nil {
		t.Fatalf("seed Save: %v", err)
	}

	srv, log, scores := newTestDeleteServer(t, store)

	resp := doDelete(t, srv.URL+"/admin/submissions/entry-1")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}

	entries, err := log.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries after delete = %+v, want empty", entries)
	}

	if _, ok, err := scores.Get("entry-1"); err != nil || ok {
		t.Errorf("scores.Get after delete: ok=%v err=%v, want ok=false", ok, err)
	}

	if _, err := os.Stat(filepath.Join(uploadDir, "samourai-20260709-1830UTC.tar.gz")); !os.IsNotExist(err) {
		t.Errorf("archive still exists after delete (err = %v)", err)
	}
}

func TestAdminDeleteSubmissionHandler_UnknownID(t *testing.T) {
	store := storage.LocalStore{Dir: t.TempDir()}
	srv, _, _ := newTestDeleteServer(t, store)

	resp := doDelete(t, srv.URL+"/admin/submissions/does-not-exist")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAdminDeleteSubmissionHandler_StorageFailureLeavesLogAndScoreIntact(t *testing.T) {
	store := failingDeleteStore{}
	srv, log, scores := newTestDeleteServer(t, store)

	resp := doDelete(t, srv.URL+"/admin/submissions/entry-1")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}

	entries, err := log.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("entries after failed delete = %+v, want the original entry still present", entries)
	}

	if _, ok, err := scores.Get("entry-1"); err != nil || !ok {
		t.Errorf("scores.Get after failed delete: ok=%v err=%v, want ok=true (untouched)", ok, err)
	}
}
