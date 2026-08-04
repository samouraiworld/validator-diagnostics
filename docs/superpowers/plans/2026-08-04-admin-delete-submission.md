# Admin Delete Submission Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an admin permanently delete a single submission (its log entry, score record, and uploaded archive) from the dashboard, behind a confirmation modal.

**Architecture:** A new `storage.Store.Delete` method and two new `portal.FileLog.Delete`/`scoring.Store.Delete` methods back a new `DELETE /admin/submissions/{id}` handler, wired through `AdminAuth` like every other admin route. The frontend adds a per-row delete button that opens a native `<dialog>` confirmation before calling the endpoint.

**Tech Stack:** Go 1.x standard library (`net/http`, `encoding/json`), AWS SDK v2 (`github.com/aws/aws-sdk-go-v2/service/s3`) for the S3 backend, vanilla JS/CSS frontend (no framework), existing `internal/atomicfile` package for crash-safe file writes.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-04-admin-delete-submission-design.md`. Every task below implements a section of it — follow it for anything not spelled out here.
- No new dependencies. Everything needed (AWS SDK, standard library) is already imported elsewhere in this repo.
- `storage.Store.Delete` must be idempotent: deleting an already-missing key is success, not an error.
- Follow this repo's existing patterns exactly: mutex-guarded stores, `atomicfile.Write` for whole-file rewrites, `http.Error` for handler failures, table-driven-free but comment-heavy tests matching the style already in `*_test.go` files (see e.g. `portal/score_test.go`, `storage/local_test.go`).
- This repo has no automated frontend tests — frontend changes are verified with a manual smoke test (Task 6), per this project's existing convention (see the spec's Testing section).

---

### Task 1: `storage.Store.Delete`

**Files:**
- Modify: `storage/store.go` (interface)
- Modify: `storage/local.go` (`LocalStore.Delete`)
- Modify: `storage/s3.go` (`S3Store.Delete`)
- Test: `storage/local_test.go`
- Test: `storage/s3_test.go`

**Interfaces:**
- Produces: `Store` interface gains `Delete(ctx context.Context, key string) error`. `LocalStore` and `S3Store` both implement it. Task 4 depends on calling `store.Delete(ctx, filename)` where `store` is the same `storage.Store` value already wired into `cmd/portal/main.go`.

- [ ] **Step 1: Write the failing tests**

Append to `storage/local_test.go`:

```go
func TestLocalStore_Delete(t *testing.T) {
	dir := t.TempDir()
	store := LocalStore{Dir: dir}

	const key = "samourai-20260709-1830UTC.tar.gz"
	if err := store.Save(context.Background(), key, strings.NewReader("content"), 7); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, key)); !os.IsNotExist(err) {
		t.Errorf("file still exists after Delete (err = %v)", err)
	}
}

func TestLocalStore_DeleteMissingKeyIsNotError(t *testing.T) {
	dir := t.TempDir()
	store := LocalStore{Dir: dir}

	if err := store.Delete(context.Background(), "never-uploaded.tar.gz"); err != nil {
		t.Errorf("Delete of a missing key: %v, want nil (idempotent)", err)
	}
}
```

Append to `storage/s3_test.go`:

```go
// TestS3StoreDelete asserts the request DeleteObject actually sends —
// method and path — against a fake S3-compatible server, same approach
// as TestS3StoreSave.
func TestS3StoreDelete(t *testing.T) {
	const (
		bucket = "validator-fire-drill"
		key    = "samourai-20260709-1830UTC.tar.gz"
	)

	var gotMethod, gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	store, err := NewS3Store(context.Background(), S3Config{
		Bucket:    bucket,
		Region:    "fr-par",
		AccessKey: "test-access-key",
		SecretKey: "test-secret-key",
		Endpoint:  srv.URL,
	})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}

	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	wantPath := "/" + bucket + "/" + key
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./storage/... -run 'TestLocalStore_Delete|TestS3StoreDelete' -v`
Expected: FAIL — `store.Delete undefined (type LocalStore has no field or method Delete)` (and same for `*S3Store`).

- [ ] **Step 3: Implement `Delete` on the interface and both backends**

In `storage/store.go`, change the interface to:

```go
type Store interface {
	Save(ctx context.Context, key string, body io.Reader, size int64) error
	// Delete removes the object at key. Deleting a key that doesn't
	// exist is not an error — callers may retry a delete that partially
	// succeeded.
	Delete(ctx context.Context, key string) error
}
```

In `storage/local.go`, add below `Save`:

```go
func (s LocalStore) Delete(ctx context.Context, key string) error {
	dest := filepath.Join(s.Dir, filepath.Clean(string(filepath.Separator)+key))

	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unable to delete %s: %w", dest, err)
	}
	return nil
}
```

In `storage/s3.go`, add below `Save` (needs `aws` and `s3` already imported):

```go
func (s *S3Store) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("unable to delete object %q: %w", key, err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./storage/... -v`
Expected: PASS, all tests including the two new ones and the pre-existing `TestLocalStore_Save`, `TestLocalStore_RefusesToOverwrite`, `TestS3StoreSave`.

- [ ] **Step 5: Commit**

```bash
git add storage/store.go storage/local.go storage/s3.go storage/local_test.go storage/s3_test.go
git commit -m "Add Delete to storage.Store, idempotent on a missing key"
```

---

### Task 2: `portal.FileLog.Delete`

**Files:**
- Modify: `portal/log.go`
- Test: `portal/log_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `func (l *FileLog) Delete(id string) (found bool, err error)`. Task 4 depends on this exact signature.

- [ ] **Step 1: Write the failing tests**

Append to `portal/log_test.go`:

```go
func TestFileLog_Delete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "submissions.jsonl")
	log := NewFileLog(path)

	e1 := Entry{ID: "id-1", Moniker: "samourai", OperatorAddress: "g1abc", Filename: "a.tar.gz", SubmittedAt: time.Now().UTC()}
	e2 := Entry{ID: "id-2", Moniker: "other", OperatorAddress: "g1def", Filename: "b.tar.gz", SubmittedAt: time.Now().UTC()}
	e3 := Entry{ID: "id-3", Moniker: "third", OperatorAddress: "g1ghi", Filename: "c.tar.gz", SubmittedAt: time.Now().UTC()}
	for _, e := range []Entry{e1, e2, e3} {
		if err := log.Record(context.Background(), e); err != nil {
			t.Fatalf("Record(%s): %v", e.ID, err)
		}
	}

	found, err := log.Delete("id-2")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !found {
		t.Error("Delete: found = false, want true")
	}

	entries, err := log.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].ID != "id-1" || entries[1].ID != "id-3" {
		t.Errorf("entries = %+v, want id-1 then id-3, id-2 removed and order preserved", entries)
	}
}

func TestFileLog_Delete_UnknownID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "submissions.jsonl")
	log := NewFileLog(path)

	if err := log.Record(context.Background(), Entry{ID: "id-1", Moniker: "samourai", SubmittedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	found, err := log.Delete("does-not-exist")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if found {
		t.Error("Delete: found = true, want false")
	}

	entries, err := log.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("len(entries) = %d, want 1 (unchanged)", len(entries))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./portal/... -run 'TestFileLog_Delete' -v`
Expected: FAIL — `log.Delete undefined (type *FileLog has no field or method Delete)`.

- [ ] **Step 3: Implement `Delete`**

In `portal/log.go`, add the import (alongside the existing ones):

```go
"github.com/samourai/validator-diagnostics/internal/atomicfile"
```

Replace the body of `Entries` so the read/parse logic is reusable without re-acquiring the lock:

```go
// Entries returns every recorded entry, oldest first. A missing log file
// means no submissions yet — not an error.
func (l *FileLog) Entries() ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.readEntries()
}

// readEntries reads and parses every entry currently in the log.
// Callers must hold l.mu.
func (l *FileLog) readEntries() ([]Entry, error) {
	data, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unable to read submission log %s: %w", l.path, err)
	}

	entries := []Entry{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("unable to parse submission log line: %w", err)
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to scan submission log: %w", err)
	}

	return entries, nil
}

// Delete removes the entry with the given ID, rewriting the log file
// with atomicfile.Write so a torn write can't corrupt the remaining
// entries. found reports whether an entry with that ID existed.
func (l *FileLog) Delete(id string) (found bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries, err := l.readEntries()
	if err != nil {
		return false, err
	}

	remaining := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if e.ID == id {
			found = true
			continue
		}
		remaining = append(remaining, e)
	}
	if !found {
		return false, nil
	}

	var buf bytes.Buffer
	for _, e := range remaining {
		data, err := json.Marshal(e)
		if err != nil {
			return false, fmt.Errorf("unable to marshal log entry: %w", err)
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}
	if err := atomicfile.Write(l.path, buf.Bytes(), 0o644); err != nil {
		return false, fmt.Errorf("unable to write submission log %s: %w", l.path, err)
	}

	return true, nil
}
```

Leave `Record` exactly as-is.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./portal/... -run 'TestFileLog|TestNewSubmissionID' -v`
Expected: PASS, all `FileLog`/`NewSubmissionID` tests including the two new ones and the pre-existing `TestFileLog_RecordAndEntries`, `TestFileLog_EntriesOnMissingFile`.

- [ ] **Step 5: Commit**

```bash
git add portal/log.go portal/log_test.go
git commit -m "Add FileLog.Delete, rewriting the submission log with atomicfile.Write"
```

---

### Task 3: `scoring.Store.Delete`

**Files:**
- Modify: `scoring/store.go`
- Test: `scoring/store_test.go`

**Interfaces:**
- Produces: `func (s *Store) Delete(id string) error`. Task 4 depends on this exact signature.

- [ ] **Step 1: Write the failing tests**

Append to `scoring/store_test.go`:

```go
func TestStore_Delete(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "scores.json"))

	if err := store.Set(Result{SubmissionID: "abc", Scored: true, UploadTimeScore: 20}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := store.Delete("abc"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, ok, err := store.Get("abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Error("Get after Delete: ok = true, want false")
	}
}

func TestStore_Delete_UnknownIDIsNotError(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "scores.json"))

	if err := store.Delete("never-scored"); err != nil {
		t.Errorf("Delete of an unknown id: %v, want nil (no-op)", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./scoring/... -run 'TestStore_Delete' -v`
Expected: FAIL — `store.Delete undefined (type *Store has no field or method Delete)`.

- [ ] **Step 3: Implement `Delete`**

In `scoring/store.go`, add below `Set`:

```go
// Delete removes the record for id, if any. Deleting an id with no
// record is a no-op, not an error — a submission may not have been
// scored yet.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	results, err := s.all()
	if err != nil {
		return err
	}
	if _, ok := results[id]; !ok {
		return nil
	}
	delete(results, id)
	return s.save(results)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./scoring/... -v`
Expected: PASS, all tests in the package including the two new ones.

- [ ] **Step 5: Commit**

```bash
git add scoring/store.go scoring/store_test.go
git commit -m "Add scoring.Store.Delete, a no-op on an unscored id"
```

---

### Task 4: `AdminDeleteSubmissionHandler` and route wiring

**Files:**
- Create: `portal/delete.go`
- Test: `portal/delete_test.go`
- Modify: `cmd/portal/main.go`

**Interfaces:**
- Consumes: `FileLog.Entries() ([]Entry, error)`, `FileLog.Delete(id string) (bool, error)` (Task 2), `scoring.Store.Delete(id string) error` (Task 3), `storage.Store.Delete(ctx, key string) error` (Task 1).
- Produces: `func AdminDeleteSubmissionHandler(log *FileLog, store storage.Store, scores *scoring.Store) http.HandlerFunc`, registered at `DELETE /admin/submissions/{id}`.

- [ ] **Step 1: Write the failing tests**

Create `portal/delete_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./portal/... -run 'TestAdminDeleteSubmissionHandler' -v`
Expected: FAIL to compile — `undefined: AdminDeleteSubmissionHandler`.

- [ ] **Step 3: Implement the handler**

Create `portal/delete.go`:

```go
package portal

import (
	"net/http"

	"github.com/samourai/validator-diagnostics/scoring"
	"github.com/samourai/validator-diagnostics/storage"
)

// AdminDeleteSubmissionHandler serves DELETE /admin/submissions/{id}:
// removes one submission's log entry, scoring record, and uploaded
// archive together. Register with the "DELETE /admin/submissions/{id}"
// mux pattern so {id} is available via r.PathValue("id"); wrap with
// AdminAuth.
func AdminDeleteSubmissionHandler(log *FileLog, store storage.Store, scores *scoring.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing submission id", http.StatusBadRequest)
			return
		}

		entries, err := log.Entries()
		if err != nil {
			http.Error(w, "unable to read submissions", http.StatusInternalServerError)
			return
		}
		var entry Entry
		found := false
		for _, e := range entries {
			if e.ID == id {
				entry = e
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "unknown submission id", http.StatusNotFound)
			return
		}

		// Delete the archive before any bookkeeping: if this fails, the
		// row stays in the table and the admin can retry, rather than
		// the dashboard showing the submission gone while its archive
		// still exists somewhere with nothing left pointing at it.
		if err := store.Delete(r.Context(), entry.Filename); err != nil {
			http.Error(w, "unable to delete archive: "+err.Error(), http.StatusBadGateway)
			return
		}

		if err := scores.Delete(id); err != nil {
			http.Error(w, "unable to delete scoring record", http.StatusInternalServerError)
			return
		}

		if _, err := log.Delete(id); err != nil {
			http.Error(w, "unable to delete submission log entry", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./portal/... -v`
Expected: PASS, the whole `portal` package including the three new tests and every pre-existing test in the package.

- [ ] **Step 5: Wire the route in `cmd/portal/main.go`**

In `cmd/portal/main.go`, immediately after the existing line:

```go
	mux.Handle("POST /admin/submissions/{id}/score", portal.AdminAuth(adminPassword, portal.AdminScoreHandler(submissionLog, exerciseStore, scoresStore)))
```

add:

```go
	mux.Handle("DELETE /admin/submissions/{id}", portal.AdminAuth(adminPassword, portal.AdminDeleteSubmissionHandler(submissionLog, store, scoresStore)))
```

(`store` is the `storage.Store` already constructed a few lines earlier by `configureStore(...)` and already passed into `SubmitHandler` — reuse the same value, don't construct a new one.)

- [ ] **Step 6: Verify the whole module still builds**

Run: `go build ./...`
Expected: no output, exit code 0.

- [ ] **Step 7: Commit**

```bash
git add portal/delete.go portal/delete_test.go cmd/portal/main.go
git commit -m "Add DELETE /admin/submissions/{id}, removing the archive before the log/score bookkeeping"
```

---

### Task 5: Frontend — per-row delete button and confirmation dialog

**Files:**
- Modify: `cmd/portal/static/admin.html`
- Modify: `cmd/portal/static/admin.js`
- Modify: `cmd/portal/static/portal.css`

**Interfaces:**
- Consumes: `DELETE /admin/submissions/{id}` (Task 4), the existing `refresh({force})` function and `#admin-error` element already in `admin.js`.
- Produces: nothing consumed by a later task — this is the last code task.

- [ ] **Step 1: Add the table's action column and the dialog markup**

In `cmd/portal/static/admin.html`, change the submissions table header (currently a single line inside `#panel-validators`):

```html
<tr><th>Moniker</th><th>Operator address</th><th>Filename</th><th>Submitted at (UTC)</th><th>Score</th><th>Checks</th><th>Ack / Incident response</th></tr>
```

to:

```html
<tr><th>Moniker</th><th>Operator address</th><th>Filename</th><th>Submitted at (UTC)</th><th>Score</th><th>Checks</th><th>Ack / Incident response</th><th><span class="sr-only">Delete</span></th></tr>
```

Then, immediately after the `#summary-section` section and before the closing `</div>` of `#panel-validators`, add the shared confirmation dialog:

```html
  <dialog id="delete-confirm">
    <h2>Delete submission</h2>
    <p id="delete-confirm-body"></p>
    <div class="dialog-actions">
      <button type="button" id="delete-cancel">Cancel</button>
      <button type="button" id="delete-confirm-button" class="danger">Delete</button>
    </div>
  </dialog>
```

So the end of `#panel-validators` reads:

```html
  <section id="summary-section" class="step">
    <h2>Summary</h2>
    <button id="generate-summary">Generate summary</button>
    <pre id="summary-output" hidden></pre>
  </section>
  <dialog id="delete-confirm">
    <h2>Delete submission</h2>
    <p id="delete-confirm-body"></p>
    <div class="dialog-actions">
      <button type="button" id="delete-cancel">Cancel</button>
      <button type="button" id="delete-confirm-button" class="danger">Delete</button>
    </div>
  </dialog>
</div>
```

- [ ] **Step 2: Style the dialog and the new buttons**

In `cmd/portal/static/portal.css`, append:

```css
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

dialog {
  max-width: 28rem;
  width: calc(100% - 2rem);
  padding: 1.25rem;
  color: var(--fg);
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
}

dialog::backdrop {
  background: rgba(0, 0, 0, 0.5);
}

dialog h2 {
  margin-top: 0;
  font-size: 1.05rem;
}

.dialog-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
  margin-top: 1.25rem;
}

button.danger {
  background: var(--error);
}

button.danger:hover {
  filter: brightness(0.9);
}

.icon-button {
  padding: 0.35rem 0.6rem;
  color: var(--muted);
  background: none;
  border: 1px solid var(--border);
}

.icon-button:hover {
  color: var(--error);
  background: none;
  border-color: var(--error);
}
```

- [ ] **Step 3: Render a delete button per row and wire the dialog**

In `cmd/portal/static/admin.js`, add a new function near `buildScoreForm` (same file, above `refresh`):

```js
function buildDeleteButton(id, moniker, operatorAddress) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "icon-button";
  button.textContent = "Delete";
  button.setAttribute("aria-label", `Delete submission from ${moniker}`);
  button.addEventListener("click", () => openDeleteConfirm(id, moniker, operatorAddress));
  return button;
}
```

Inside `refresh()`, right after the existing block that builds `manualCell` and appends it to `row` (i.e. after `row.appendChild(manualCell);` and before `tbody.appendChild(row);`), add:

```js
    const deleteCell = document.createElement("td");
    deleteCell.appendChild(buildDeleteButton(s.id, s.moniker, s.operator_address));
    row.appendChild(deleteCell);
```

At the end of the file (after the existing `generate-summary` click handler), add:

```js
// Delete confirmation dialog: shared across all rows, filled in with
// the target submission each time a row's delete button is clicked.
const deleteDialog = document.getElementById("delete-confirm");
const deleteDialogBody = document.getElementById("delete-confirm-body");
const deleteCancelButton = document.getElementById("delete-cancel");
const deleteConfirmButton = document.getElementById("delete-confirm-button");
let pendingDeleteID = null;

function openDeleteConfirm(id, moniker, operatorAddress) {
  pendingDeleteID = id;
  deleteDialogBody.textContent =
    `Delete the submission from ${moniker} (${operatorAddress})? Its score and uploaded archive will also be deleted. This cannot be undone.`;
  deleteDialog.showModal();
}

deleteCancelButton.addEventListener("click", () => {
  pendingDeleteID = null;
  deleteDialog.close();
});

deleteConfirmButton.addEventListener("click", async () => {
  const id = pendingDeleteID;
  if (!id) return;

  let resp;
  try {
    resp = await fetch(`/admin/submissions/${encodeURIComponent(id)}`, { method: "DELETE" });
  } catch (err) {
    deleteDialog.close();
    document.getElementById("admin-error").textContent = "Network error: " + err.message;
    return;
  }

  deleteDialog.close();
  pendingDeleteID = null;

  if (!resp.ok) {
    const detail = (await resp.text()).trim();
    document.getElementById("admin-error").textContent =
      "Unable to delete submission (status " + resp.status + ")" + (detail ? ": " + detail : ".");
    return;
  }
  document.getElementById("admin-error").textContent = "";
  refresh({ force: true });
});
```

`openDeleteConfirm` is a function declaration, hoisted, so `buildDeleteButton` (defined earlier in the file) can reference it even though its own definition comes later — same pattern the file already relies on (`refresh` referencing functions and being referenced before its own declaration further down).

- [ ] **Step 4: Verify the module still builds (the static files are embedded via `//go:embed`)**

Run: `go build ./...`
Expected: no output, exit code 0. This doesn't check the frontend logic — Task 6 does that — but it does catch e.g. a typo'd file path breaking the `embed.FS`.

- [ ] **Step 5: Commit**

```bash
git add cmd/portal/static/admin.html cmd/portal/static/admin.js cmd/portal/static/portal.css
git commit -m "Add a per-row delete button with a confirmation dialog to the admin table"
```

---

### Task 6: Manual end-to-end verification

**Files:** none (verification only).

**Interfaces:** none.

- [ ] **Step 1: Build the real portal binary**

Run: `go build -o /tmp/portal ./cmd/portal`
Expected: exit code 0.

- [ ] **Step 2: Seed fixture data**

```bash
WORKDIR=$(mktemp -d)
mkdir -p "$WORKDIR/uploads"
echo "fake archive bytes" > "$WORKDIR/uploads/samourai-20260709-1830UTC.tar.gz"
cat > "$WORKDIR/submissions.jsonl" <<'EOF'
{"id":"entry-1","moniker":"samourai-crew","operator_address":"g1abc","filename":"samourai-20260709-1830UTC.tar.gz","submitted_at":"2026-07-09T18:30:00Z"}
EOF
cat > "$WORKDIR/scores.json" <<'EOF'
{"entry-1":{"submission_id":"entry-1","scored":true,"genesis_match":true,"version_supported":true,"log_window":{"detected":true,"covered":true},"upload_time_score":20,"metadata_score":20,"log_quality_score":20}}
EOF
```

- [ ] **Step 3: Start the portal against the fixtures**

Run in the background: `ADMIN_PASSWORD=testpass /tmp/portal -remote https://rpc.test13.testnets.gno.land:443 -upload-dir "$WORKDIR/uploads" -log-path "$WORKDIR/submissions.jsonl" -scores-path "$WORKDIR/scores.json" -exercise-path "$WORKDIR/exercise.json" -addr localhost:8899`

Poll until it's serving: `timeout 10 bash -c 'until curl -sf -u admin:testpass http://localhost:8899/admin/submissions >/dev/null; do sleep 0.5; done'`

- [ ] **Step 4: Verify the endpoint directly with curl before touching the browser**

```bash
curl -s -u admin:testpass http://localhost:8899/admin/submissions | grep -q entry-1 && echo "seeded row present"
curl -s -o /dev/null -w '%{http_code}\n' -u admin:testpass -X DELETE http://localhost:8899/admin/submissions/does-not-exist
# expect: 404
curl -s -o /dev/null -w '%{http_code}\n' -u admin:testpass -X DELETE http://localhost:8899/admin/submissions/entry-1
# expect: 204
curl -s -u admin:testpass http://localhost:8899/admin/submissions
# expect: []
test ! -f "$WORKDIR/uploads/samourai-20260709-1830UTC.tar.gz" && echo "archive deleted"
```

- [ ] **Step 5: Re-seed and verify the dialog in a real browser**

Re-run Step 2's fixture seeding (the previous step deleted the row and its archive) — the still-running portal process reads these files fresh on every request, so it does not need restarting. Then drive it headlessly. If Playwright isn't already available in the environment, install it first:

```bash
npm install playwright@1 --no-audit --no-fund
npx playwright install chromium
```

Then, using a small script (Node + `playwright`, `chromium.launch()` → `newPage()` with HTTP Basic Auth via `page.context().setHTTPCredentials` or `httpCredentials` in the browser context options, since this page sits behind `AdminAuth`):

1. Navigate to `http://localhost:8899/admin#validators`.
2. Wait for the row containing "samourai-crew" to appear in `#submissions tbody`.
3. Screenshot (`delete-flow-1-row-visible.png`).
4. Click that row's "Delete" button.
5. Wait for `dialog#delete-confirm[open]`.
6. Assert the dialog's `#delete-confirm-body` text contains "samourai-crew" and "g1abc".
7. Screenshot (`delete-flow-2-dialog-open.png`).
8. Click `#delete-cancel`; assert the dialog closes and the row is still present. Screenshot (`delete-flow-3-cancelled.png`).
9. Click the row's "Delete" button again, then click `#delete-confirm-button`.
10. Wait for the row to disappear from `#submissions tbody`.
11. Screenshot (`delete-flow-4-deleted.png`).
12. `console --errors` / check `page.on("console")` for any `error`-level messages — expect none.

Look at all four screenshots. A blank dialog, a dialog with unstyled/default browser chrome instead of the themed appearance, or a row that doesn't disappear after confirming are all failures — go back and fix before considering this task done.

- [ ] **Step 6: Clean up**

```bash
kill %1  # or: lsof -ti:8899 -sTCP:LISTEN | xargs -r kill
rm -rf "$WORKDIR"
```

No commit for this task — it's verification only, nothing to check in beyond what Tasks 1-5 already committed.
