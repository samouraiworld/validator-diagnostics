# Validator Fire Drill Portal — Frontend & Admin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a single deployable `cmd/portal` binary with a validator-facing submission web page and a password-protected admin dashboard, replacing `cmd/portal-dev`.

**Architecture:** A submission log (`portal.Log`/`portal.FileLog`) records each successful `/submit` call to a JSON-lines file. An admin HTTP Basic Auth middleware (`portal.AdminAuth`) protects a new `GET /admin/submissions` endpoint that reads that log. `cmd/portal/main.go` wires the existing `auth`/`submission`/`storage`/`portal` packages plus the new admin pieces together, and serves a small vanilla-JS frontend embedded via `embed.FS` — one binary, no separate build step.

**Tech Stack:** Go 1.26 (stdlib `net/http`, `embed`, `crypto/subtle`), vanilla HTML/CSS/JS (no framework, no npm).

## Global Constraints

- Go module: `github.com/samourai/validator-diagnostics`, `go 1.26.1` (see `go.mod`) — `http.ServeFileFS` and `embed.FS` are both available.
- No new Go dependencies beyond what's already in `go.mod` (`github.com/gnolang/gno`, `github.com/aws/aws-sdk-go-v2/*`).
- No JS framework, no npm, no build step for the frontend — plain files served as-is.
- Frontend talks only to the already-implemented, already-tested JSON APIs (`/auth/challenge`, `/auth/verify`, `/submit`) — no new backend request/response shapes for those three.
- Session tokens live only in a JS variable in the validator page — never `localStorage`, never cookies (per the design's stated reasoning: short-lived, single-purpose, no reason to persist across reloads).
- Admin dashboard data must be rendered via `textContent`, never `innerHTML`, since entries contain validator-controlled strings (moniker, operator address) that were schema-validated but not HTML-escaped.
- Every new Go file needs a passing `go build ./...`, `go vet ./...`, and `go test ./...` before its task is considered done.

---

## File Structure

```text
portal/
  log.go          — NEW: Entry, Log interface, FileLog
  log_test.go     — NEW
  submit.go       — MODIFY: add optional Log field, record on success
  submit_test.go  — MODIFY: add Log-recording tests
  admin.go        — NEW: AdminAuth middleware, AdminSubmissionsHandler
  admin_test.go   — NEW

cmd/portal/               — NEW (replaces cmd/portal-dev)
  main.go
  static/
    index.html    — validator flow
    portal.css    — shared styles
    portal.js     — validator flow logic
    admin.html    — admin dashboard
    admin.js      — admin dashboard logic

cmd/portal-dev/     — REMOVED (Task 9)
prd.md              — MODIFY (Task 9): update cmd/portal-dev references, add frontend status
```

---

### Task 1: Submission log (`portal.Entry`, `portal.Log`, `portal.FileLog`)

**Files:**
- Create: `portal/log.go`
- Test: `portal/log_test.go`

**Interfaces:**
- Produces: `type Entry struct { Moniker, OperatorAddress, Filename string; SubmittedAt time.Time }` (all fields JSON-tagged snake_case); `type Log interface { Record(ctx context.Context, e Entry) error }`; `func NewFileLog(path string) *FileLog`; `func (l *FileLog) Record(ctx context.Context, e Entry) error`; `func (l *FileLog) Entries() ([]Entry, error)`.
- Consumes: nothing from other tasks.

- [ ] **Step 1: Write the failing test**

Create `portal/log_test.go`:

```go
package portal

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestFileLog_RecordAndEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "submissions.jsonl")
	log := NewFileLog(path)

	e1 := Entry{
		Moniker:         "samourai",
		OperatorAddress: "g1abc",
		Filename:        "samourai-20260709-1830UTC.tar.gz",
		SubmittedAt:     time.Date(2026, 7, 9, 18, 30, 0, 0, time.UTC),
	}
	e2 := Entry{
		Moniker:         "other",
		OperatorAddress: "g1def",
		Filename:        "other-20260709-1831UTC.tar.gz",
		SubmittedAt:     time.Date(2026, 7, 9, 18, 31, 0, 0, time.UTC),
	}

	if err := log.Record(context.Background(), e1); err != nil {
		t.Fatalf("Record(e1): %v", err)
	}
	if err := log.Record(context.Background(), e2); err != nil {
		t.Fatalf("Record(e2): %v", err)
	}

	entries, err := log.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].Moniker != "samourai" || entries[1].Moniker != "other" {
		t.Errorf("entries out of order or wrong content: %+v", entries)
	}
	if !entries[0].SubmittedAt.Equal(e1.SubmittedAt) {
		t.Errorf("SubmittedAt = %v, want %v", entries[0].SubmittedAt, e1.SubmittedAt)
	}
}

func TestFileLog_EntriesOnMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.jsonl")
	log := NewFileLog(path)

	entries, err := log.Entries()
	if err != nil {
		t.Fatalf("Entries: unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("len(entries) = %d, want 0", len(entries))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/louis/Documents/Samourai/repos/validator-diagnostics && export PATH="/usr/local/go/bin:$PATH" && go test ./portal/... -run TestFileLog -v`
Expected: FAIL — `NewFileLog`/`Entry`/`FileLog` undefined (log.go doesn't exist yet).

- [ ] **Step 3: Write the implementation**

Create `portal/log.go`:

```go
package portal

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry is one recorded successful submission, written by SubmitHandler
// and read back by the admin dashboard.
type Entry struct {
	Moniker         string    `json:"moniker"`
	OperatorAddress string    `json:"operator_address"`
	Filename        string    `json:"filename"`
	SubmittedAt     time.Time `json:"submitted_at"`
}

// Log records successful submissions. SubmitHandler treats a nil Log as
// "logging disabled" — the field is optional.
type Log interface {
	Record(ctx context.Context, e Entry) error
}

// FileLog is a Log backed by an append-only JSON-lines file. Simple
// enough for a single exercise's admin dashboard — no database.
type FileLog struct {
	mu   sync.Mutex
	path string
}

func NewFileLog(path string) *FileLog {
	return &FileLog{path: path}
}

func (l *FileLog) Record(ctx context.Context, e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("unable to open submission log %s: %w", l.path, err)
	}
	defer f.Close()

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("unable to marshal log entry: %w", err)
	}
	data = append(data, '\n')

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("unable to write log entry: %w", err)
	}

	return nil
}

// Entries returns every recorded entry, oldest first. A missing log file
// means no submissions yet — not an error.
func (l *FileLog) Entries() ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./portal/... -run TestFileLog -v`
Expected: PASS (both `TestFileLog_RecordAndEntries` and `TestFileLog_EntriesOnMissingFile`).

- [ ] **Step 5: Full verification and commit**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: everything still green (existing `auth`/`storage`/`submission`/`portal` tests unaffected).

```bash
git add portal/log.go portal/log_test.go
git commit -m "Add append-only submission log for the admin dashboard"
```

---

### Task 2: Wire the submission log into `SubmitHandler`

**Files:**
- Modify: `portal/submit.go:8-17` (imports), `portal/submit.go:33-44` (struct), `portal/submit.go:136-139` (after successful `Store.Save`)
- Test: `portal/submit_test.go`

**Interfaces:**
- Consumes: `Entry`, `Log` from Task 1 (`portal/log.go`, same package — no import needed).
- Produces: `SubmitHandler.Log Log` field (nil-safe).

- [ ] **Step 1: Write the failing tests**

Add to `portal/submit_test.go` (after the existing `fakeStore` type, before `buildValidArchive`):

```go
type fakeLog struct {
	mu      sync.Mutex
	entries []Entry
}

func (l *fakeLog) Record(ctx context.Context, e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
	return nil
}
```

Add two new test functions at the end of `portal/submit_test.go`:

```go
func TestSubmitHandler_RecordsLogOnSuccess(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	submissionLog := &fakeLog{}
	handler := &SubmitHandler{Sessions: sessions, Store: store, Log: submissionLog}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, operatorAddr.String())
	filename := "samourai-20260709-1830UTC.tar.gz"
	body, contentType := multipartUpload(t, filename, archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	submissionLog.mu.Lock()
	defer submissionLog.mu.Unlock()
	if len(submissionLog.entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(submissionLog.entries))
	}
	got := submissionLog.entries[0]
	if got.Moniker != "samourai" || got.OperatorAddress != operatorAddr.String() || got.Filename != filename {
		t.Errorf("logged entry = %+v, unexpected content", got)
	}
}

func TestSubmitHandler_DoesNotRecordLogOnFailure(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	submissionLog := &fakeLog{}
	handler := &SubmitHandler{Sessions: sessions, Store: store, Log: submissionLog}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, operatorAddr.String())
	// Bad filename -> ValidateFilename fails before Store.Save/Log.Record.
	body, contentType := multipartUpload(t, "not-the-right-convention.tar.gz", archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()

	submissionLog.mu.Lock()
	defer submissionLog.mu.Unlock()
	if len(submissionLog.entries) != 0 {
		t.Errorf("expected no logged entries on failure, got %+v", submissionLog.entries)
	}
}
```

Add `"sync"` to `portal/submit_test.go`'s existing import block.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./portal/... -run TestSubmitHandler_RecordsLogOnSuccess -v`
Expected: FAIL to compile — `SubmitHandler` has no field `Log`.

- [ ] **Step 3: Write the implementation**

In `portal/submit.go`, add `"log"` and `"time"` to the import block (`portal/submit.go:8-17`):

```go
import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/samourai/validator-diagnostics/auth"
	"github.com/samourai/validator-diagnostics/storage"
	"github.com/samourai/validator-diagnostics/submission"
)
```

Add a `Log` field to the struct (`portal/submit.go:33-44`):

```go
type SubmitHandler struct {
	Sessions *auth.SessionSigner
	Store    storage.Store

	// Log records successful submissions for the admin dashboard.
	// Optional — a nil Log disables recording.
	Log Log

	// ArchiveOptions bounds ValidateArchive's per-entry reads. Zero
	// value uses submission's own defaults.
	ArchiveOptions submission.Options

	// MaxUploadSize caps the whole request body. Zero uses
	// defaultMaxUploadSize.
	MaxUploadSize int64
}
```

Record after a successful `Store.Save`, before the success response (`portal/submit.go:136-139`, replace):

```go
	if err := h.Store.Save(r.Context(), header.Filename, file, header.Size); err != nil {
		writeSubmitResult(w, http.StatusInternalServerError, submitResponse{Error: "unable to store archive"})
		return
	}

	if h.Log != nil {
		entry := Entry{
			Moniker:         moniker,
			OperatorAddress: operatorAddr.String(),
			Filename:        header.Filename,
			SubmittedAt:     time.Now().UTC(),
		}
		if err := h.Log.Record(r.Context(), entry); err != nil {
			// The archive is already safely stored — a logging failure
			// shouldn't fail the submission from the validator's point
			// of view, but organizers should still be able to see it
			// happened.
			log.Printf("submission log: unable to record entry for %s: %v", header.Filename, err)
		}
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./portal/... -v`
Expected: PASS for all `portal` tests, including the two new ones and the five pre-existing `TestSubmitHandler_*` tests.

- [ ] **Step 5: Full verification and commit**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all green.

```bash
git add portal/submit.go portal/submit_test.go
git commit -m "Record successful submissions to the submission log"
```

---

### Task 3: Admin Basic Auth middleware

**Files:**
- Create: `portal/admin.go`
- Test: `portal/admin_test.go`

**Interfaces:**
- Produces: `func AdminAuth(password string, next http.Handler) http.Handler`.
- Consumes: nothing from other tasks.

- [ ] **Step 1: Write the failing test**

Create `portal/admin_test.go`:

```go
package portal

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./portal/... -run TestAdminAuth -v`
Expected: FAIL to compile — `AdminAuth` undefined.

- [ ] **Step 3: Write the implementation**

Create `portal/admin.go`:

```go
package portal

import (
	"crypto/subtle"
	"net/http"
)

// AdminAuth wraps next with HTTP Basic Auth, checking only the password
// (any username is accepted) against a single admin password. The
// comparison is constant-time to avoid a timing side-channel on the
// password check.
func AdminAuth(password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="validator-fire-drill-admin"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./portal/... -run TestAdminAuth -v`
Expected: PASS (all three subtests).

- [ ] **Step 5: Full verification and commit**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all green.

```bash
git add portal/admin.go portal/admin_test.go
git commit -m "Add HTTP Basic Auth middleware for the admin dashboard"
```

---

### Task 4: `GET /admin/submissions` handler

**Files:**
- Modify: `portal/admin.go` (append)
- Modify: `portal/admin_test.go` (append)

**Interfaces:**
- Consumes: `*FileLog`, `Entry` (Task 1).
- Produces: `func AdminSubmissionsHandler(log *FileLog) http.HandlerFunc`.

- [ ] **Step 1: Write the failing test**

Append to `portal/admin_test.go` (extend the import block first — add `"context"`, `"encoding/json"`, `"path/filepath"`, `"time"`):

```go
import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)
```

Append a new test function:

```go
func TestAdminSubmissionsHandler(t *testing.T) {
	path := filepath.Join(t.TempDir(), "submissions.jsonl")
	fileLog := NewFileLog(path)
	if err := fileLog.Record(context.Background(), Entry{
		Moniker:         "samourai",
		OperatorAddress: "g1abc",
		Filename:        "samourai-20260709-1830UTC.tar.gz",
		SubmittedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	srv := httptest.NewServer(AdminSubmissionsHandler(fileLog))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var entries []Entry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 1 || entries[0].Moniker != "samourai" {
		t.Errorf("entries = %+v, want one entry for samourai", entries)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./portal/... -run TestAdminSubmissionsHandler -v`
Expected: FAIL to compile — `AdminSubmissionsHandler` undefined.

- [ ] **Step 3: Write the implementation**

In `portal/admin.go`, replace the existing import block:

```go
import (
	"crypto/subtle"
	"net/http"
)
```

with:

```go
import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
)
```

Then append the handler at the end of the file:

```go
// AdminSubmissionsHandler serves the recorded submissions as a JSON
// array, oldest first. Wrap it with AdminAuth.
func AdminSubmissionsHandler(log *FileLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		entries, err := log.Entries()
		if err != nil {
			http.Error(w, "unable to read submissions", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./portal/... -v`
Expected: PASS for every `portal` test, including `TestAdminSubmissionsHandler`.

- [ ] **Step 5: Full verification and commit**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all green.

```bash
git add portal/admin.go portal/admin_test.go
git commit -m "Add GET /admin/submissions endpoint"
```

---

### Task 5: Validator-facing frontend (`index.html`, `portal.css`, `portal.js`)

**Files:**
- Create: `cmd/portal/static/index.html`
- Create: `cmd/portal/static/portal.css`
- Create: `cmd/portal/static/portal.js`

**Interfaces:**
- Consumes (HTTP, already implemented and tested elsewhere): `POST /auth/challenge` → `{nonce, challenge_tx, chainid, account_number, account_sequence}`; `POST /auth/verify` → `{ok, session_token, error}`; `POST /submit` (multipart, field `archive`, header `Authorization: Bearer <token>`) → `{ok, moniker, submitted_at, error}`.
- Produces: nothing consumed by other Go code (static assets only, embedded by Task 7).

There's no Go compiler to catch mistakes here — verify by serving the directory statically and exercising the DOM logic directly in a browser console.

- [ ] **Step 1: Create the directory and the HTML shell**

Create `cmd/portal/static/index.html`:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Validator Fire Drill — Submit</title>
<link rel="stylesheet" href="/portal.css">
</head>
<body>
<main>
<h1>Validator Fire Drill — Submission</h1>

<section id="step-address" class="step">
  <h2>1. Operator address</h2>
  <label for="operator-address">Your valopers operator address</label>
  <input type="text" id="operator-address" placeholder="g1...">
  <button id="get-challenge">Get challenge</button>
  <p class="error" id="address-error"></p>
</section>

<section id="step-sign" class="step" hidden>
  <h2>2. Sign the challenge</h2>
  <p>Run this command locally, with your operator key:</p>
  <pre id="sign-command"></pre>
  <p><a id="download-challenge" download="challenge.json">Download challenge.json</a></p>
  <label for="sig-file">Upload the resulting sig.json</label>
  <input type="file" id="sig-file" accept=".json">
  <button id="verify-signature">Verify</button>
  <p class="error" id="sign-error"></p>
</section>

<section id="step-upload" class="step" hidden>
  <h2>3. Upload archive</h2>
  <p class="success">Authenticated as <span id="authenticated-address"></span></p>
  <label for="archive-file">Diagnostic archive (&lt;moniker&gt;-&lt;YYYYMMDD-HHMMUTC&gt;.tar.gz)</label>
  <input type="file" id="archive-file" accept=".gz,.tar.gz">
  <button id="submit-archive">Submit</button>
  <p class="error" id="upload-error"></p>
</section>

<section id="step-done" class="step" hidden>
  <h2>Submission received</h2>
  <p id="done-message"></p>
</section>

</main>
<script src="/portal.js"></script>
</body>
</html>
```

- [ ] **Step 2: Create the shared stylesheet**

Create `cmd/portal/static/portal.css`:

```css
:root {
  color-scheme: light dark;
  --fg: #1a1a1a;
  --bg: #ffffff;
  --border: #ccc;
  --error: #b00020;
  --success: #0a7d2c;
}

@media (prefers-color-scheme: dark) {
  :root {
    --fg: #e8e8e8;
    --bg: #1a1a1a;
    --border: #444;
  }
}

body {
  font-family: system-ui, sans-serif;
  color: var(--fg);
  background: var(--bg);
  max-width: 640px;
  margin: 2rem auto;
  padding: 0 1rem;
}

.step {
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1rem;
  margin-bottom: 1rem;
}

input[type="text"], input[type="file"] {
  display: block;
  width: 100%;
  margin: 0.5rem 0;
  box-sizing: border-box;
}

button {
  padding: 0.5rem 1rem;
  cursor: pointer;
}

pre {
  background: rgba(128, 128, 128, 0.15);
  padding: 0.75rem;
  overflow-x: auto;
  white-space: pre-wrap;
}

.error {
  color: var(--error);
}

.success {
  color: var(--success);
}

table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  border: 1px solid var(--border);
  padding: 0.5rem;
  text-align: left;
}
```

- [ ] **Step 3: Create the validator flow logic**

Create `cmd/portal/static/portal.js`:

```js
"use strict";

let currentNonce = null;
let currentOperatorAddress = null;
let sessionToken = null;

function show(id) {
  document.getElementById(id).hidden = false;
}

function setError(id, message) {
  document.getElementById(id).textContent = message || "";
}

// The server always returns JSON, but a response from something else
// entirely (a proxy's plain-text error page, a static file server
// during local testing) might not be — .json() throws on that, so every
// non-network-error response goes through this instead of a bare
// `await resp.json()`.
async function parseJSONResponse(resp) {
  try {
    return await resp.json();
  } catch (err) {
    return { error: `Unexpected response from server (status ${resp.status}).` };
  }
}

document.getElementById("get-challenge").addEventListener("click", async () => {
  setError("address-error", "");
  const address = document.getElementById("operator-address").value.trim();
  if (!address) {
    setError("address-error", "Enter your operator address.");
    return;
  }

  let resp;
  try {
    resp = await fetch("/auth/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operator_address: address }),
    });
  } catch (err) {
    setError("address-error", "Network error: " + err.message);
    return;
  }

  const data = await parseJSONResponse(resp);
  if (!resp.ok) {
    setError("address-error", data.error || "Unable to get a challenge.");
    return;
  }

  currentNonce = data.nonce;
  currentOperatorAddress = address;

  const challengeJSON = JSON.stringify(data.challenge_tx, null, 2);
  const blob = new Blob([challengeJSON], { type: "application/json" });
  const link = document.getElementById("download-challenge");
  link.href = URL.createObjectURL(blob);

  document.getElementById("sign-command").textContent =
    `gnokey sign --tx-path challenge.json \\\n` +
    `  --chainid ${data.chainid} \\\n` +
    `  --account-number ${data.account_number} --account-sequence ${data.account_sequence} \\\n` +
    `  --output-document sig.json <your-operator-key-name>`;

  show("step-sign");
});

document.getElementById("verify-signature").addEventListener("click", async () => {
  setError("sign-error", "");
  const fileInput = document.getElementById("sig-file");
  const file = fileInput.files[0];
  if (!file) {
    setError("sign-error", "Choose the sig.json file produced by gnokey sign.");
    return;
  }

  let sigDoc;
  try {
    sigDoc = JSON.parse(await file.text());
  } catch (err) {
    setError("sign-error", "sig.json is not valid JSON: " + err.message);
    return;
  }
  if (!sigDoc.signature) {
    setError("sign-error", 'sig.json has no "signature" field.');
    return;
  }

  let resp;
  try {
    resp = await fetch("/auth/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        operator_address: currentOperatorAddress,
        nonce: currentNonce,
        signature: sigDoc.signature,
      }),
    });
  } catch (err) {
    setError("sign-error", "Network error: " + err.message);
    return;
  }

  const data = await parseJSONResponse(resp);
  if (!resp.ok || !data.ok) {
    setError("sign-error", data.error || "Verification failed.");
    return;
  }

  sessionToken = data.session_token;
  document.getElementById("authenticated-address").textContent = currentOperatorAddress;
  show("step-upload");
});

document.getElementById("submit-archive").addEventListener("click", async () => {
  setError("upload-error", "");
  const fileInput = document.getElementById("archive-file");
  const file = fileInput.files[0];
  if (!file) {
    setError("upload-error", "Choose the diagnostic archive to upload.");
    return;
  }

  const form = new FormData();
  form.append("archive", file, file.name);

  let resp;
  try {
    resp = await fetch("/submit", {
      method: "POST",
      headers: { Authorization: "Bearer " + sessionToken },
      body: form,
    });
  } catch (err) {
    setError("upload-error", "Network error: " + err.message);
    return;
  }

  const data = await parseJSONResponse(resp);
  if (!resp.ok || !data.ok) {
    setError("upload-error", data.error || "Submission failed.");
    return;
  }

  document.getElementById("done-message").textContent =
    `Archive for "${data.moniker}" received (submitted_at: ${data.submitted_at}).`;
  show("step-done");
});
```

- [ ] **Step 4: Verify by serving the directory statically**

Run: `cd /home/louis/Documents/Samourai/repos/validator-diagnostics/cmd/portal/static && python3 -m http.server 8099`

Then open `http://localhost:8099/` in a browser and check:
- The page loads with only "1. Operator address" visible; sections 2–4 are hidden.
- Browser dev tools console shows no JS errors on load.
- Enter any address and click "Get challenge". Python's static server has no `/auth/challenge` route and returns a plain-text (non-JSON) error for POST — this exercises `parseJSONResponse`'s fallback path. Confirm `#address-error` shows a readable "Unexpected response from server (status ...)" message, and confirm there is no uncaught exception in the console — this is what would have broken before `parseJSONResponse` was added (a bare `resp.json()` throws on a non-JSON body).

Stop the python server (Ctrl-C) once confirmed.

- [ ] **Step 5: Commit**

```bash
git add cmd/portal/static/index.html cmd/portal/static/portal.css cmd/portal/static/portal.js
git commit -m "Add validator-facing submission web page"
```

---

### Task 6: Admin dashboard frontend (`admin.html`, `admin.js`)

**Files:**
- Create: `cmd/portal/static/admin.html`
- Create: `cmd/portal/static/admin.js`

**Interfaces:**
- Consumes (HTTP, implemented in Task 4): `GET /admin/submissions` → JSON array of `{moniker, operator_address, filename, submitted_at}`.
- Consumes: `cmd/portal/static/portal.css` (Task 5, shared stylesheet).

- [ ] **Step 1: Create the HTML shell**

Create `cmd/portal/static/admin.html`:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Validator Fire Drill — Admin</title>
<link rel="stylesheet" href="/portal.css">
</head>
<body>
<main>
<h1>Validator Fire Drill — Submissions</h1>
<table id="submissions">
  <thead>
    <tr><th>Moniker</th><th>Operator address</th><th>Filename</th><th>Submitted at (UTC)</th></tr>
  </thead>
  <tbody></tbody>
</table>
<p id="admin-error" class="error"></p>
</main>
<script src="/admin.js"></script>
</body>
</html>
```

- [ ] **Step 2: Create the polling/render logic**

Create `cmd/portal/static/admin.js`:

```js
"use strict";

async function refresh() {
  let resp;
  try {
    resp = await fetch("/admin/submissions");
  } catch (err) {
    document.getElementById("admin-error").textContent = "Network error: " + err.message;
    return;
  }

  if (!resp.ok) {
    document.getElementById("admin-error").textContent =
      "Unable to load submissions (status " + resp.status + ").";
    return;
  }
  document.getElementById("admin-error").textContent = "";

  const entries = await resp.json();
  const tbody = document.querySelector("#submissions tbody");
  tbody.innerHTML = "";
  for (const e of entries) {
    const row = document.createElement("tr");
    for (const value of [e.moniker, e.operator_address, e.filename, e.submitted_at]) {
      const cell = document.createElement("td");
      cell.textContent = value; // never innerHTML — these are validator-controlled strings
      row.appendChild(cell);
    }
    tbody.appendChild(row);
  }
}

refresh();
setInterval(refresh, 5000);
```

- [ ] **Step 3: Verify by serving the directory statically**

Run: `cd /home/louis/Documents/Samourai/repos/validator-diagnostics/cmd/portal/static && python3 -m http.server 8099`

Then open `http://localhost:8099/admin.html` in a browser and check:
- The page loads with an empty table and, since `/admin/submissions` doesn't exist on this bare static server, `#admin-error` shows a "status 404" message within 5 seconds — confirming the polling loop and error path both run without throwing.
- No uncaught JS errors in the console.

Stop the python server (Ctrl-C) once confirmed.

- [ ] **Step 4: Commit**

```bash
git add cmd/portal/static/admin.html cmd/portal/static/admin.js
git commit -m "Add admin submissions dashboard page"
```

---

### Task 7: `cmd/portal` binary — wire everything together

**Files:**
- Create: `cmd/portal/main.go`

**Interfaces:**
- Consumes: `auth.NewNonceStore`, `auth.Verifier`, `auth.NewSessionSigner`, `auth.ChallengeHandler`, `auth.VerifyHandler` (existing, `auth` package); `storage.LocalStore`, `storage.NewS3Store`, `storage.S3Config` (existing, `storage` package); `portal.SubmitHandler`, `portal.NewFileLog`, `portal.AdminAuth`, `portal.AdminSubmissionsHandler` (Tasks 1–4); the `cmd/portal/static` directory (Tasks 5–6).
- Produces: the `cmd/portal` executable — nothing else depends on it.

- [ ] **Step 1: Write `main.go`**

Create `cmd/portal/main.go`:

```go
// Command portal is the validator fire drill submission portal: the
// challenge-tx auth endpoints, the archive upload endpoint, the admin
// submissions dashboard, and the static frontend, all in one binary.
//
// Storage backend: pass either -upload-dir (local disk, for testing) or
// -s3-bucket (+ -s3-region/-s3-endpoint, with credentials from the
// S3_ACCESS_KEY/S3_SECRET_KEY environment variables) for production.
//
// Required environment variables:
//   - ADMIN_PASSWORD — protects /admin and /admin/submissions.
//   - SESSION_SECRET (optional) — hex-encoded HMAC secret for session
//     tokens. If unset, a random one is generated for this run (sessions
//     won't survive a restart — fine for a single exercise, not for a
//     long-lived deployment).
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/samourai/validator-diagnostics/auth"
	"github.com/samourai/validator-diagnostics/portal"
	"github.com/samourai/validator-diagnostics/storage"
)

//go:embed static
var staticFiles embed.FS

func main() {
	remote := flag.String("remote", "", "gno.land RPC endpoint to verify operator pubkeys against, e.g. https://rpc.test13.testnets.gno.land:443")
	addr := flag.String("addr", "localhost:8080", "address to listen on")
	sessionTTL := flag.Duration("session-ttl", 5*time.Minute, "how long an issued session token stays valid")
	uploadDir := flag.String("upload-dir", "", "local directory to save submitted archives into (use this OR the -s3-* flags)")
	s3Bucket := flag.String("s3-bucket", "", "S3-compatible bucket to save submitted archives into")
	s3Region := flag.String("s3-region", "", "S3-compatible region")
	s3Endpoint := flag.String("s3-endpoint", "", "S3-compatible endpoint (leave empty for real AWS S3)")
	logPath := flag.String("log-path", "./submissions.jsonl", "path to the submission log file, read by the admin dashboard")
	flag.Parse()

	if *remote == "" {
		log.Fatal("-remote is required (see docs/resources/gnoland-networks.md in gnolang/gno for known endpoints)")
	}

	adminPassword := os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		log.Fatal("ADMIN_PASSWORD environment variable is required")
	}

	store, err := configureStore(*uploadDir, *s3Bucket, *s3Region, *s3Endpoint)
	if err != nil {
		log.Fatalf("unable to configure storage: %v", err)
	}

	sessionSecret, err := loadOrGenerateSessionSecret()
	if err != nil {
		log.Fatalf("unable to prepare session secret: %v", err)
	}
	sessions := auth.NewSessionSigner(sessionSecret, *sessionTTL)

	nonces := auth.NewNonceStore()
	verifier := &auth.Verifier{Remote: *remote, Nonces: nonces}
	submissionLog := portal.NewFileLog(*logPath)

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("unable to load embedded static assets: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/challenge", auth.ChallengeHandler(nonces))
	mux.Handle("/auth/verify", auth.VerifyHandler(verifier, sessions))
	mux.Handle("/submit", &portal.SubmitHandler{Sessions: sessions, Store: store, Log: submissionLog})
	mux.Handle("/admin", portal.AdminAuth(adminPassword, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, staticFS, "admin.html")
	})))
	mux.Handle("/admin/submissions", portal.AdminAuth(adminPassword, portal.AdminSubmissionsHandler(submissionLog)))
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	log.Printf("listening on %s, verifying operator pubkeys against %s", *addr, *remote)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func configureStore(uploadDir, s3Bucket, s3Region, s3Endpoint string) (storage.Store, error) {
	switch {
	case s3Bucket != "":
		return storage.NewS3Store(context.Background(), storage.S3Config{
			Bucket:    s3Bucket,
			Region:    s3Region,
			Endpoint:  s3Endpoint,
			AccessKey: os.Getenv("S3_ACCESS_KEY"),
			SecretKey: os.Getenv("S3_SECRET_KEY"),
		})
	case uploadDir != "":
		if err := os.MkdirAll(uploadDir, 0o755); err != nil {
			return nil, err
		}
		return storage.LocalStore{Dir: uploadDir}, nil
	default:
		return nil, errNoStorageBackend
	}
}

var errNoStorageBackend = errUsage("either -upload-dir or -s3-bucket is required")

type errUsage string

func (e errUsage) Error() string { return string(e) }

func loadOrGenerateSessionSecret() ([]byte, error) {
	if hexSecret := os.Getenv("SESSION_SECRET"); hexSecret != "" {
		return hex.DecodeString(hexSecret)
	}

	log.Println("SESSION_SECRET not set: generating a random one for this run (sessions won't survive a restart)")
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}
```

- [ ] **Step 2: Build**

Run: `cd /home/louis/Documents/Samourai/repos/validator-diagnostics && export PATH="/usr/local/go/bin:$PATH" && go build ./...`
Expected: exits 0. If it fails on the `//go:embed static` directive because `cmd/portal/static` is missing or empty, re-check Tasks 5–6 completed first — `embed` requires the directory to exist and contain at least one file at build time.

- [ ] **Step 3: `go vet` and full test suite**

Run: `go vet ./... && go test ./...`
Expected: all green, including all pre-existing `auth`/`storage`/`submission`/`portal` tests (this task adds no new Go tests — `main.go` wiring is verified by the manual smoke test below, consistent with how `cmd/portal-dev` was verified).

- [ ] **Step 4: Manual smoke test against a real network**

Run (background):

```bash
export PATH="/usr/local/go/bin:$PATH"
cd /home/louis/Documents/Samourai/repos/validator-diagnostics
ADMIN_PASSWORD=test-admin-password go run ./cmd/portal \
  -remote https://rpc.topaz.testnets.gno.land \
  -addr localhost:8096 \
  -upload-dir /tmp/portal-smoketest
```

In another terminal, verify:

```bash
# Static frontend loads
curl -s -o /dev/null -w "index: HTTP %{http_code}\n" http://localhost:8096/
curl -s -o /dev/null -w "portal.js: HTTP %{http_code}\n" http://localhost:8096/portal.js

# Auth endpoints still work (same as the already-proven backend)
curl -s -X POST localhost:8096/auth/challenge -d '{"operator_address":"g1jg8mtutu9khhfwc4nxmuhcpftf0pajdhfvsqf5"}'

# Admin without credentials is rejected
curl -s -o /dev/null -w "admin (no auth): HTTP %{http_code}\n" http://localhost:8096/admin/submissions

# Admin with correct credentials works and returns an empty list (no submissions yet)
curl -s -u admin:test-admin-password http://localhost:8096/admin/submissions
```

Expected: `index` and `portal.js` both 200; `/auth/challenge` returns a nonce/challenge_tx as before; `/admin/submissions` without credentials is 401; with `-u admin:test-admin-password` it returns `[]`.

Stop the server and remove the temp dir: `rm -rf /tmp/portal-smoketest`.

- [ ] **Step 5: Commit**

```bash
git add cmd/portal/main.go
git commit -m "Add cmd/portal: the deployable portal binary with frontend and admin dashboard"
```

---

### Task 8: Full live end-to-end test with a real operator key (via the browser)

**Files:** none (verification only).

**Interfaces:** none — this exercises the whole system built in Tasks 1–7 through the browser UI, the way an actual validator would use it.

- [ ] **Step 1: Start the real portal binary against topaz**

```bash
export PATH="/usr/local/go/bin:$PATH"
cd /home/louis/Documents/Samourai/repos/validator-diagnostics
ADMIN_PASSWORD=<choose-a-password> go run ./cmd/portal \
  -remote https://rpc.topaz.testnets.gno.land \
  -addr localhost:8080 \
  -upload-dir ./portal-uploads
```

- [ ] **Step 2: Walk through the validator flow in a browser**

Open `http://localhost:8080/`:
1. Enter your real `valopers`-registered operator address, click "Get challenge". Confirm the `gnokey sign` command and the "Download challenge.json" link both appear.
2. Download `challenge.json`, run the displayed `gnokey sign` command locally with your real operator key to produce `sig.json`, upload it, click "Verify". Confirm it advances to step 3 and shows "Authenticated as `<your address>`".
3. Prepare a real (or synthetic-but-valid, per `prd.md`'s archive structure) `<moniker>-<YYYYMMDD-HHMMUTC>.tar.gz`, upload it, click "Submit". Confirm a success message with the moniker and submission time appears.

- [ ] **Step 3: Confirm the admin dashboard reflects the submission**

Open `http://localhost:8080/admin` (browser will prompt for Basic Auth — any username, the `ADMIN_PASSWORD` value). Confirm the submitted row appears (moniker, operator address, filename, submitted-at) within 5 seconds.

- [ ] **Step 4: Confirm the archive landed in storage**

```bash
ls -la ./portal-uploads/
```

Expected: the uploaded `.tar.gz`, byte-identical to what was submitted, named exactly as submitted.

- [ ] **Step 5: Record the result**

If every step above passed, this is the final proof the whole pipeline (auth → validation → storage → admin visibility) works end-to-end through the real UI with a real key, matching what was previously only proven via `curl`/Go tests. No commit for this task — proceed to Task 9 to update the docs with this confirmation.

---

### Task 9: Replace `cmd/portal-dev`, update `prd.md`

**Files:**
- Delete: `cmd/portal-dev/` (entire directory)
- Modify: `prd.md:428`, `prd.md:434`, `prd.md:441`, `prd.md:450`, `prd.md:452`

**Interfaces:** none — documentation and cleanup only.

- [ ] **Step 1: Remove the superseded dev tool**

```bash
cd /home/louis/Documents/Samourai/repos/validator-diagnostics
rm -rf cmd/portal-dev
go build ./... && go vet ./... && go test ./...
```

Expected: still all green — nothing else imports `cmd/portal-dev` (it's a `package main`, never imported elsewhere).

- [ ] **Step 2: Update `prd.md` references**

In `prd.md:428`, replace:

```
**Status: implemented and validated end-to-end.** `auth/challenge.go`, `auth/http.go` (`POST /auth/challenge`, `POST /auth/verify`) and the `cmd/portal-dev` local test server implement steps 2, 3, and 7. Confirmed against a live network (`topaz-1`): a real `valopers`-registered operator address signed a server-issued challenge with unmodified `gnokey sign`, and the portal's `/auth/verify` correctly accepted it (and rejects invalid signatures / replayed nonces — covered by `auth/challenge_test.go` and `auth/http_test.go`).
```

with:

```
**Status: implemented and validated end-to-end.** `auth/challenge.go`, `auth/http.go` (`POST /auth/challenge`, `POST /auth/verify`) and the `cmd/portal` server implement steps 2, 3, and 7. Confirmed against a live network (`topaz-1`): a real `valopers`-registered operator address signed a server-issued challenge with unmodified `gnokey sign`, and the portal's `/auth/verify` correctly accepted it (and rejects invalid signatures / replayed nonces — covered by `auth/challenge_test.go` and `auth/http_test.go`).
```

In `prd.md:434`, replace:

```
A successful `/auth/verify` needs to authorize the *subsequent* archive upload without re-running the challenge flow per request. Implemented as a short-lived, stateless, HMAC-signed token (`auth/session.go`, `SessionSigner`) rather than a JWT library or a server-side session store — a fixed-layout token has less attack surface for this one narrow use case (no algorithm negotiation, no claims-parsing ambiguity), and statelessness avoids needing session infra for a v1. Trade-off: a token can't be revoked before it expires, so the TTL is kept short (default 5 min in `cmd/portal-dev`).
```

with:

```
A successful `/auth/verify` needs to authorize the *subsequent* archive upload without re-running the challenge flow per request. Implemented as a short-lived, stateless, HMAC-signed token (`auth/session.go`, `SessionSigner`) rather than a JWT library or a server-side session store — a fixed-layout token has less attack surface for this one narrow use case (no algorithm negotiation, no claims-parsing ambiguity), and statelessness avoids needing session infra for a v1. Trade-off: a token can't be revoked before it expires, so the TTL is kept short (default 5 min in `cmd/portal`).
```

In `prd.md:441`, replace:

```
**Status: implemented and wired end-to-end.** `portal/submit.go` (`SubmitHandler`, served as `POST /submit` by `cmd/portal-dev`) composes the three pieces above into the actual upload flow from "Phase 2 — Artifact Collection & Submission":
```

with:

```
**Status: implemented and wired end-to-end.** `portal/submit.go` (`SubmitHandler`, served as `POST /submit` by `cmd/portal`) composes the three pieces above into the actual upload flow from "Phase 2 — Artifact Collection & Submission":
```

In `prd.md:450`, replace:

```
A `storage.LocalStore` (writes to a local directory, refuses to overwrite an existing key) was added alongside `S3Store` purely so `cmd/portal-dev` can exercise the full flow locally without needing real Scaleway/AWS credentials yet — swapping in `S3Store` for production is a one-line change at the `portal-dev`/deployment wiring level, not a code change to `SubmitHandler`.
```

with:

```
A `storage.LocalStore` (writes to a local directory, refuses to overwrite an existing key) was added alongside `S3Store` so `cmd/portal` can exercise the full flow locally without needing real Scaleway/AWS credentials — swapping in `S3Store` for production is a flag change (`-s3-bucket` instead of `-upload-dir`) at the `cmd/portal` deployment wiring level, not a code change to `SubmitHandler`.
```

In `prd.md:452`, replace:

```
Verified: `portal/submit_test.go` drives the handler end-to-end (valid submission, missing session, identity mismatch, bad filename, malformed archive) against an in-memory fake `Store`; `cmd/portal-dev` was smoke-tested live against `topaz-1` (auth rejection and challenge issuance both confirmed working through the fully-wired binary).
```

with:

```
Verified: `portal/submit_test.go` drives the handler end-to-end (valid submission, missing session, identity mismatch, bad filename, malformed archive) against an in-memory fake `Store`; `cmd/portal` was smoke-tested live against `topaz-1` (auth rejection and challenge issuance both confirmed working through the fully-wired binary), and the full flow — including the frontend and admin dashboard — was verified end-to-end through a browser with a real operator key (see Task 8 of `docs/superpowers/plans/2026-07-29-portal-frontend.md`).
```

- [ ] **Step 3: Add a status section for the frontend/admin work**

At the end of `prd.md`'s Security Considerations section (after the line ending `...frontend and admin dashboard — was verified end-to-end through a browser with a real operator key...` from Step 2), add a new subsection:

```markdown

## Frontend and admin dashboard

**Status: implemented.** `cmd/portal` serves a vanilla HTML/CSS/JS frontend (no build step, embedded in the binary via `embed.FS`):

- `/` — the validator submission flow (address → challenge → signature upload → archive upload), calling the same `/auth/challenge`, `/auth/verify`, and `/submit` endpoints already covered above.
- `/admin` and `/admin/submissions` — an HTTP-Basic-Auth-protected dashboard (`ADMIN_PASSWORD` environment variable, constant-time comparison) listing submissions as they arrive, backed by an append-only JSON-lines log (`portal.FileLog`) rather than a database.

Not yet implemented: enforcing "one successful submission per validator" (would need persistence beyond the current per-process `NonceStore`/`SessionSigner`), and Adena browser-wallet signing (the validator flow stays file-based: download `challenge.json`, run `gnokey sign` locally, upload `sig.json` — deliberately kept wallet-agnostic so this could be added later without touching `auth` or `portal.SubmitHandler`).
```

- [ ] **Step 4: Final verification and commit**

```bash
cd /home/louis/Documents/Samourai/repos/validator-diagnostics
go build ./... && go vet ./... && go test ./...
git add -A
git commit -m "Replace cmd/portal-dev with cmd/portal; update prd.md status"
git log --oneline
```

Expected: all green, and `git log` shows the full sequence of commits from Task 1 through this one.

---

## Plan Self-Review

**Spec coverage:**
- Single deployable binary, embedded frontend → Task 7.
- Validator flow (3 steps, file-based signing) → Task 5.
- Admin dashboard, Basic Auth, submission log → Tasks 1, 3, 4, 6.
- "What doesn't change" (auth/submission/storage/SubmitHandler core logic untouched) → Task 2 only adds an optional field, doesn't modify existing validation logic; confirmed by all pre-existing tests staying green through every task.
- Testing approach (backend TDD, frontend manual browser verification, live smoke test) → Tasks 1–4 (TDD), 5–6 (static-serve verification), 7 (build/vet/test + live smoke test), 8 (full real-key browser E2E).
- Non-goals (Adena, Phase 3 scoring, one-submission-per-validator) → explicitly called out as still-open in Task 9's `prd.md` update, not silently dropped.

**Type/interface consistency:** `Entry`/`Log`/`FileLog` (Task 1) are used identically in Task 2 (`SubmitHandler.Log Log`, `Entry{...}`), Task 4 (`AdminSubmissionsHandler(log *FileLog)`), and Task 7 (`portal.NewFileLog`, passed to both `SubmitHandler` and `AdminSubmissionsHandler`) — same names, same types throughout.

**No placeholders:** every step above contains complete file contents or exact diffs, not descriptions of what to write.
