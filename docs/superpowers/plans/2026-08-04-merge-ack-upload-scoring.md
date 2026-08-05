# Merge Acknowledgement Time into Upload Completion Time — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the manually-entered "Acknowledged at" admin field and its `AckTimeScore`, leaving "Upload completion time" (computed automatically from `submitted_at`) as the rubric's sole timing criterion, and rescale the four remaining 20-point criteria to 25 points each so the total stays 100.

**Architecture:** No new packages or types. This is a targeted removal of one field (`scoring.Result.AcknowledgedAt` / `AckTimeScore`) and a constant rescale (20→25) threaded through `scoring/`, `portal/`, `cmd/portal/`, the admin frontend, and the docs that describe them. Implemented directly on the current branch (`feature/json-log-timestamps-and-admin-ui`), not a new worktree.

**Tech Stack:** Go (stdlib `net/http`, `encoding/json`), vanilla JS/HTML frontend, Markdown docs.

## Global Constraints

- Rubric after this change (from the approved spec,
  `docs/superpowers/specs/2026-08-04-merge-ack-upload-scoring-design.md`):
  Upload completion time = 25, Metadata completeness = 25, Log quality = 25,
  Incident response quality = 25. Total = 100.
- `TieredTimeScore` tiers (100/75/50/25/0% of the announce→deadline window):
  25 / 19 / 13 / 6 / 0.
- `LogQualityScore`: structural base 13, +12 if `Covered` (→25), +6 if
  `Detected && !Covered` (→19), +0 otherwise (→13).
- `incident_response_quality_score` bounds move from 0-20 to 0-25.
- `AcknowledgedAt` and `AckTimeScore` are deleted, not deprecated — no
  backwards-compatibility shim, no renamed-but-kept field.

---

### Task 1: Rescale the automatic scoring formulas to 25 points

**Files:**
- Modify: `scoring/score.go:39-53` (`TieredTimeScore`'s switch), `scoring/score.go:92-102` (`LogQualityScore`)
- Modify: `scoring/score_test.go` (all expected values)
- Modify: `portal/submit.go:221` (`MetadataScore` literal)
- Modify: `portal/submit_test.go:578-583` (expected values)

**Interfaces:**
- Consumes: nothing new.
- Produces: `TieredTimeScore(t time.Time, cfg exercise.Config) int` now returns 25/19/13/6/0 instead of 20/15/10/5/0. `LogQualityScore(window LogWindowCheck) int` now returns 25/19/13. Both signatures unchanged — later tasks call them the same way.

This task only changes numeric literals (return values and test expectations). It does **not** touch `AcknowledgedAt`/`AckTimeScore` or any prose that mentions them — that's Task 2, so this task's diff stays reviewable on its own (it changes what a score is worth, not what a score means).

- [ ] **Step 1: Update `scoring/score_test.go`'s expected values**

Replace the body of `TestTieredTimeScore`'s `cases` table with:

```go
	cases := []struct {
		name string
		at   time.Time
		want int
	}{
		{"at announcement", cfg.AnnouncedAt, 25},
		// Not 25: an event predating the exercise hasn't happened yet as
		// far as the rubric goes. AckTimeScore is admin-typed, so a
		// mistyped year would otherwise silently earn full marks.
		{"before announcement", cfg.AnnouncedAt.Add(-time.Minute), 0},
		{"exactly 25%", cfg.AnnouncedAt.Add(1 * time.Hour), 25},
		{"just past 25%", cfg.AnnouncedAt.Add(1*time.Hour + time.Second), 19},
		{"exactly 50%", cfg.AnnouncedAt.Add(2 * time.Hour), 19},
		{"just past 50%", cfg.AnnouncedAt.Add(2*time.Hour + time.Second), 13},
		{"exactly 75%", cfg.AnnouncedAt.Add(3 * time.Hour), 13},
		{"just past 75%", cfg.AnnouncedAt.Add(3*time.Hour + time.Second), 6},
		{"exactly at deadline (100%)", cfg.DeadlineAt, 6},
		{"just past deadline", cfg.DeadlineAt.Add(time.Second), 0},
	}
```

Replace `TestLogQualityScore`'s `cases` table with:

```go
	cases := []struct {
		name   string
		window LogWindowCheck
		want   int
	}{
		{"fully covered", LogWindowCheck{Detected: true, Covered: true}, 25},
		{"detected but not covered", LogWindowCheck{Detected: true, Covered: false}, 19},
		{"nothing detected", LogWindowCheck{}, 13},
	}
```

In `TestTieredTimeScore_LongWindowDoesNotOverflow`, change the assertion:

```go
	sixtyPercent := announced.Add(60 * 365 * 24 * time.Hour)
	if got := TieredTimeScore(sixtyPercent, cfg); got != 13 {
		t.Errorf("TieredTimeScore at 60%% of a 100-year window = %d, want 13", got)
	}
```

- [ ] **Step 2: Run the scoring tests to verify they fail**

Run: `go test ./scoring/... -run 'TestTieredTimeScore|TestLogQualityScore' -v`
Expected: FAIL — the implementation still returns the old 20/15/10/5 and 20/15/10 values.

- [ ] **Step 3: Update `scoring/score.go`'s implementation**

In `TieredTimeScore`, replace the switch body:

```go
	switch {
	case elapsed <= total/4:
		return 25
	case elapsed <= total/2:
		return 19
	// total/4*3, not total*3/4: the latter overflows time.Duration's
	// int64 nanoseconds for a window past ~97 years and wraps negative,
	// so the tier would never fire.
	case elapsed <= total/4*3:
		return 13
	case elapsed <= total:
		return 6
	default:
		return 0
	}
```

Replace `LogQualityScore`:

```go
func LogQualityScore(window LogWindowCheck) int {
	const structuralBase = 13
	switch {
	case window.Covered:
		return structuralBase + 12
	case window.Detected:
		return structuralBase + 6
	default:
		return structuralBase
	}
}
```

- [ ] **Step 4: Run the scoring tests to verify they pass**

Run: `go test ./scoring/... -v`
Expected: PASS (all tests in the package, not just the two above — `store_test.go` and `checks_test.go` are untouched by this task and must stay green).

- [ ] **Step 5: Update `portal/submit.go`'s `MetadataScore` literal**

At `portal/submit.go:221`, change:

```go
				result.MetadataScore = 20
```

to:

```go
				result.MetadataScore = 25
```

- [ ] **Step 6: Update `portal/submit_test.go`'s expectations**

At `portal/submit_test.go:578-583`, change:

```go
	if result.MetadataScore != 20 {
		t.Errorf("MetadataScore = %d, want 20", result.MetadataScore)
	}
	if result.UploadTimeScore != 20 {
		t.Errorf("UploadTimeScore = %d, want 20 (submitted well within the first quarter)", result.UploadTimeScore)
	}
```

to:

```go
	if result.MetadataScore != 25 {
		t.Errorf("MetadataScore = %d, want 25", result.MetadataScore)
	}
	if result.UploadTimeScore != 25 {
		t.Errorf("UploadTimeScore = %d, want 25 (submitted well within the first quarter)", result.UploadTimeScore)
	}
```

- [ ] **Step 7: Run the full test suite to verify nothing else broke**

Run: `go test ./...`
Expected: PASS everywhere. (`portal/score_test.go`, `summary_test.go`, and `admin_test.go` seed `scoring.Result` literals like `UploadTimeScore: 20` directly rather than via `TieredTimeScore`/`LogQualityScore`, so they're unaffected by this task's formula change — Task 2 rewrites those files for the field removal.)

- [ ] **Step 8: Commit**

```bash
git add scoring/score.go scoring/score_test.go portal/submit.go portal/submit_test.go
git commit -m "Rescale automatic scoring formulas from 20 to 25 points"
```

---

### Task 2: Remove the acknowledgement-time criterion

This is the core removal: `scoring.Result` loses `AcknowledgedAt`/`AckTimeScore`, and every consumer across `scoring/` and `portal/` follows. Because Go requires whole-package compilation, this task touches every file that references either field in one pass — it can't be split further without leaving the tree non-compiling mid-task.

**Files:**
- Modify: `scoring/result.go` (struct, `Pending()`, `TotalScore()`, doc comments)
- Modify: `scoring/result_test.go`
- Modify: `scoring/score.go:1-8` (package doc), `scoring/score.go:16-23` (`TieredTimeScore` doc), `scoring/score.go:30-37` (`elapsed < 0` comment)
- Modify: `scoring/score_test.go:26-28` (the "before announcement" comment, now that `AckTimeScore` no longer exists)
- Modify: `scoring/store_test.go:77-96` (`TestStore_SetUpdatesInPlace` references `AckTimeScore`)
- Modify: `portal/score.go` (drop `AcknowledgedAt` from the request, drop the `exerciseStore` parameter, bound the score at 25)
- Modify: `portal/score_test.go`
- Modify: `portal/summary.go` (`pendingNote`)
- Modify: `portal/summary_test.go`
- Modify: `portal/admin_test.go`
- Modify: `cmd/portal/main.go:143`

**Interfaces:**
- Consumes: `TieredTimeScore`/`LogQualityScore` from Task 1 (unchanged signatures).
- Produces: `scoring.Result` with fields `SubmissionID string, Scored bool, GenesisMatch bool, VersionSupported bool, LogWindow LogWindowCheck, UploadTimeScore int, MetadataScore int, LogQualityScore int, IncidentResponseQualityScore *int` (no `AcknowledgedAt`, no `AckTimeScore`). `AdminScoreHandler(log *FileLog, scores *scoring.Store) http.HandlerFunc` (two params, was three). Later tasks (frontend, docs) reference this trimmed request/response shape.

- [ ] **Step 1: Update `scoring/result_test.go` to the post-removal expectations**

Replace the whole file:

```go
package scoring

import "testing"

func TestResult_TotalScore_AutoOnly(t *testing.T) {
	r := Result{UploadTimeScore: 25, MetadataScore: 25, LogQualityScore: 25}
	if got := r.TotalScore(); got != 75 {
		t.Errorf("TotalScore() = %d, want 75 (manual field not yet entered counts as 0)", got)
	}
}

func TestResult_TotalScore_Full(t *testing.T) {
	irq := 18
	r := Result{
		UploadTimeScore:              25,
		MetadataScore:                25,
		LogQualityScore:              25,
		IncidentResponseQualityScore: &irq,
	}
	if got := r.TotalScore(); got != 93 {
		t.Errorf("TotalScore() = %d, want 93", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails to compile**

Run: `go test ./scoring/...`
Expected: FAIL to build — `scoring/result.go` still declares `AckTimeScore` and other test/source files still reference it, so the package won't compile yet. This is expected; the point of writing the test first is that it encodes the target shape before `result.go` catches up.

- [ ] **Step 3: Rewrite `scoring/result.go`**

Replace the whole file:

```go
package scoring

// Result is one submission's Phase 3 scoring record, keyed by the
// owning portal.Entry's ID. The automatic fields are computed once, at
// submit time (see AutoChecks and portal.SubmitHandler); the manual
// field is filled in later by an admin, via
// POST /admin/submissions/{id}/score, since prd.md's rubric includes
// one criterion — incident response quality — that this codebase has
// no way to observe automatically.
type Result struct {
	SubmissionID string `json:"submission_id"`

	// Scored is false until an exercise.Config existed to score
	// against at submit time — distinguishes "not yet scored" from
	// "scored zero" for the automatic fields below.
	Scored           bool           `json:"scored"`
	GenesisMatch     bool           `json:"genesis_match"`
	VersionSupported bool           `json:"version_supported"`
	LogWindow        LogWindowCheck `json:"log_window"`
	UploadTimeScore  int            `json:"upload_time_score"`
	MetadataScore    int            `json:"metadata_score"`
	LogQualityScore  int            `json:"log_quality_score"`

	IncidentResponseQualityScore *int `json:"incident_response_quality_score,omitempty"`
}

// Pending reports whether the manual criterion is still unentered,
// which makes TotalScore a lower bound rather than a final mark.
// Anything that shows a total to a human — the admin dashboard, the
// Discord summary — has to say so, or a half-scored submission is
// indistinguishable from a finished one.
func (r Result) Pending() bool {
	return r.IncidentResponseQualityScore == nil
}

// TotalScore sums every sub-score against prd.md's 100-point rubric.
// The manual field, if not yet entered, counts as 0 — callers that
// need to distinguish "not yet scored" from "scored zero" should check
// Scored and Pending rather than relying on TotalScore alone.
func (r Result) TotalScore() int {
	total := r.UploadTimeScore + r.MetadataScore + r.LogQualityScore
	if r.IncidentResponseQualityScore != nil {
		total += *r.IncidentResponseQualityScore
	}
	return total
}
```

(Note: the `time` import is dropped — `AcknowledgedAt` was the only `time.Time` field in this file.)

- [ ] **Step 4: Update `scoring/score.go`'s comments that reference `AckTimeScore`**

Replace the package doc comment at the top of the file:

```go
// Package scoring implements prd.md's Phase 3 "Evaluation Criteria":
// the 4x25-point rubric (upload completion time, metadata completeness,
// log quality, incident response quality) and the automatic checks
// (genesis hash, gnoland version, log time window) that feed part of
// it. See docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md
// and docs/superpowers/specs/2026-08-04-merge-ack-upload-scoring-design.md
// for the full design and the rationale behind each formula below.
package scoring
```

Replace `TieredTimeScore`'s doc comment:

```go
// TieredTimeScore scores upload completion time: full marks for acting
// in the first quarter of the announce-to-deadline window, degrading by
// quarter, zero once past the deadline. A non-positive
// (DeadlineAt - AnnouncedAt) — i.e. an unconfigured or invalid exercise
// — always scores 0; callers are expected to check
// exercise.Config.Configured() before relying on this for anything
// other than that fallback.
```

Replace the comment above the `elapsed < 0` guard:

```go
	// An event before the exercise was announced hasn't happened yet as
	// far as the rubric is concerned. Without this, elapsed is negative
	// and satisfies the first tier — full marks. Unreachable in
	// practice since t is always the server clock at upload time, but
	// the guard costs nothing.
	if elapsed < 0 {
		return 0
	}
```

- [ ] **Step 5: Update `scoring/score_test.go`'s comment that references `AckTimeScore`**

Replace the comment above the `"before announcement"` case in `TestTieredTimeScore`:

```go
		{"at announcement", cfg.AnnouncedAt, 25},
		// Not 25: an event predating the exercise hasn't happened yet as
		// far as the rubric goes. Unreachable in practice since t is the
		// server clock, but guarded anyway — see TieredTimeScore.
		{"before announcement", cfg.AnnouncedAt.Add(-time.Minute), 0},
```

- [ ] **Step 6: Update `scoring/store_test.go`'s `AckTimeScore` reference**

`TestStore_SetUpdatesInPlace` (around line 77) uses `AckTimeScore` as a
throwaway pointer field to prove `Store.Set` overwrites an existing
record rather than merging it. Since it's the only pointer field left,
switch to `IncidentResponseQualityScore`. Replace:

```go
func TestStore_SetUpdatesInPlace(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "scores.json"))

	if err := store.Set(Result{SubmissionID: "abc", UploadTimeScore: 20}); err != nil {
		t.Fatalf("Set(first): %v", err)
	}

	ack := 10
	if err := store.Set(Result{SubmissionID: "abc", UploadTimeScore: 20, AckTimeScore: &ack}); err != nil {
		t.Fatalf("Set(second): %v", err)
	}

	got, ok, err := store.Get("abc")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.AckTimeScore == nil || *got.AckTimeScore != 10 {
		t.Errorf("AckTimeScore = %v, want a pointer to 10", got.AckTimeScore)
	}
}
```

with:

```go
func TestStore_SetUpdatesInPlace(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "scores.json"))

	if err := store.Set(Result{SubmissionID: "abc", UploadTimeScore: 20}); err != nil {
		t.Fatalf("Set(first): %v", err)
	}

	irq := 10
	if err := store.Set(Result{SubmissionID: "abc", UploadTimeScore: 20, IncidentResponseQualityScore: &irq}); err != nil {
		t.Fatalf("Set(second): %v", err)
	}

	got, ok, err := store.Get("abc")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.IncidentResponseQualityScore == nil || *got.IncidentResponseQualityScore != 10 {
		t.Errorf("IncidentResponseQualityScore = %v, want a pointer to 10", got.IncidentResponseQualityScore)
	}
}
```

- [ ] **Step 7: Run the scoring package tests**

Run: `go test ./scoring/... -v`
Expected: PASS.

- [ ] **Step 8: Rewrite `portal/score.go`**

Replace the whole file:

```go
package portal

import (
	"encoding/json"
	"mime"
	"net/http"

	"github.com/samourai/validator-diagnostics/scoring"
)

// scoreRequest is decoded from POST /admin/submissions/{id}/score's
// body. IncidentResponseQualityScore is a pointer so that an omitted or
// null field is distinguishable from a deliberate 0 — which is itself a
// valid score. Decoding a missing score to 0 would flip
// Result.Pending() to false and present a fabricated total as final.
type scoreRequest struct {
	IncidentResponseQualityScore *int `json:"incident_response_quality_score"`
}

// AdminScoreHandler serves POST /admin/submissions/{id}/score: the
// admin's manual entry for the one rubric criterion that can't be
// computed automatically (prd.md "Evaluation Criteria" — incident
// response quality). Register with the
// "POST /admin/submissions/{id}/score" mux pattern so {id} is
// available via r.PathValue("id"); wrap with AdminAuth.
func AdminScoreHandler(log *FileLog, scores *scoring.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing submission id", http.StatusBadRequest)
			return
		}

		// CSRF defence: without this, a cross-site
		// <form enctype="text/plain"> POST is a CORS "simple request"
		// that needs no preflight, so the browser would attach the
		// admin's cached Basic credentials and this handler would decode
		// the JSON-shaped body it can produce. Requiring
		// application/json makes the request non-simple, forcing a
		// preflight that this server (sending no
		// Access-Control-Allow-Origin) never approves.
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}

		var req scoreRequest
		dec := json.NewDecoder(r.Body)
		// Reject unknown fields, matching submission.ValidateMetadata: a
		// misspelt score key would otherwise be silently dropped and stored
		// as the zero value.
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.IncidentResponseQualityScore == nil {
			http.Error(w, "incident_response_quality_score is required", http.StatusBadRequest)
			return
		}
		if *req.IncidentResponseQualityScore < 0 || *req.IncidentResponseQualityScore > 25 {
			http.Error(w, "incident_response_quality_score must be between 0 and 25", http.StatusBadRequest)
			return
		}

		entries, err := log.Entries()
		if err != nil {
			http.Error(w, "unable to read submissions", http.StatusInternalServerError)
			return
		}
		found := false
		for _, e := range entries {
			if e.ID == id {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "unknown submission id", http.StatusNotFound)
			return
		}

		result, ok, err := scores.Get(id)
		if err != nil {
			http.Error(w, "unable to read scoring record", http.StatusInternalServerError)
			return
		}
		// A manual score completes an automatic half; it doesn't stand in
		// for one. A submission recorded before the exercise was
		// configured has no automatic half and can never acquire one —
		// AutoChecks needs the log bytes, which aren't retained past the
		// request. Writing the manual field onto it would clear
		// Pending() while the automatic scores stayed at zero, publishing
		// a total that reads as final and means nothing.
		if !ok || !result.Scored {
			http.Error(w, "submission was never auto-scored (it arrived before the exercise was configured), so it cannot be scored manually", http.StatusConflict)
			return
		}
		result.SubmissionID = id
		irq := *req.IncidentResponseQualityScore
		result.IncidentResponseQualityScore = &irq

		if err := scores.Set(result); err != nil {
			http.Error(w, "unable to save score", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}
}
```

(The `exercise` package import and its `Get()`/`Configured()` calls are gone: this handler no longer computes `AckTimeScore`, so it has no remaining use for `exercise.Config`. The `!ok || !result.Scored` guard already covers "nothing to score against" — a submission is only ever `Scored: true` if the exercise was configured at submit time, per `portal/submit.go`.)

- [ ] **Step 9: Rewrite `portal/score_test.go`**

Replace the whole file:

```go
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
```

Note what's deliberately gone: `TestAdminScoreHandler_RejectsWhenExerciseNotConfigured`. That test asserted a 400 specific to "no exercise config," which existed only because the old handler fetched `exercise.Config` to compute `AckTimeScore`. With `exerciseStore` removed from the handler, there is no code path left that distinguishes "exercise never configured" from "submission never auto-scored" — both now produce the same `!ok` (or `!result.Scored`) 409, which `TestAdminScoreHandler_RejectsSubmissionThatWasNeverAutoScored` already covers. Keeping the old test would mean asserting a 400 that the handler can no longer produce.

- [ ] **Step 10: Run the portal score tests**

Run: `go test ./portal/... -run TestAdminScoreHandler -v`
Expected: FAIL to build — `cmd/portal/main.go` and other `portal/` files still call the three-argument `AdminScoreHandler` and reference `AckTimeScore`. Continue to the next steps before expecting a pass.

- [ ] **Step 11: Update `portal/summary.go`'s `pendingNote`**

Replace:

```go
// pendingNote qualifies a total that isn't final yet. This text gets
// pasted into Discord, so a submission still missing its manually
// entered criterion must not read as a finished "60/100" — it is 60
// out of the points awarded so far.
func pendingNote(r scoring.Result) string {
	if r.IncidentResponseQualityScore == nil {
		return " (incident response pending)"
	}
	return ""
}
```

- [ ] **Step 12: Update `portal/summary_test.go`**

Replace `TestAdminSummaryHandler_PendingManualScores` and `TestAdminSummaryHandler_CompleteScoreHasNoPendingNote` (the two tests referencing `AckTimeScore`) with:

```go
func TestAdminSummaryHandler_PendingManualScores(t *testing.T) {
	// This text gets pasted into Discord, so a total that is still
	// missing its manually entered criterion must not read as a final
	// mark.
	text := summaryText(t, scoring.Result{
		SubmissionID: "pending", Scored: true,
		GenesisMatch: true, VersionSupported: true,
		LogWindow:       scoring.LogWindowCheck{Detected: true, Covered: true},
		UploadTimeScore: 25, MetadataScore: 25, LogQualityScore: 25,
	})
	if !strings.Contains(text, "75/100 (incident response pending)") {
		t.Errorf("summary missing the pending annotation; got:\n%s", text)
	}
}

func TestAdminSummaryHandler_CompleteScoreHasNoPendingNote(t *testing.T) {
	irq := 25
	text := summaryText(t, scoring.Result{
		SubmissionID: "complete", Scored: true,
		GenesisMatch: true, VersionSupported: true,
		LogWindow:       scoring.LogWindowCheck{Detected: true, Covered: true},
		UploadTimeScore: 25, MetadataScore: 25, LogQualityScore: 25,
		IncidentResponseQualityScore: &irq,
	})

	if !strings.Contains(text, "100/100\n") {
		t.Errorf("summary missing the bare final total; got:\n%s", text)
	}
	if strings.Contains(text, "pending") {
		t.Errorf("summary annotates a fully scored submission as pending; got:\n%s", text)
	}
}
```

(The old pair covered three states — both fields pending, only ack pending, only incident-response pending. With one manual field left, there are only two states — pending or not — so the "only ack pending" case is dropped rather than kept as dead weight.)

- [ ] **Step 13: Update `portal/admin_test.go`**

In `TestAdminSubmissionsHandler_TotalAndPending` (around line 121), replace:

```go
	ack, irq := 20, 15
	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if err := scoresStore.Set(scoring.Result{
		SubmissionID: "partial", Scored: true,
		UploadTimeScore: 20, MetadataScore: 20, LogQualityScore: 20,
	}); err != nil {
		t.Fatalf("scoresStore.Set: %v", err)
	}
	if err := scoresStore.Set(scoring.Result{
		SubmissionID: "complete", Scored: true,
		UploadTimeScore: 20, MetadataScore: 20, LogQualityScore: 20,
		AckTimeScore: &ack, IncidentResponseQualityScore: &irq,
	}); err != nil {
		t.Fatalf("scoresStore.Set: %v", err)
	}
```

with:

```go
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
```

and later in the same test:

```go
	if got := byID["partial"]; got.TotalScore != 75 || !got.Pending {
		t.Errorf("partial: total_score = %d, pending = %v; want 75, true", got.TotalScore, got.Pending)
	}
	if got := byID["complete"]; got.TotalScore != 90 || got.Pending {
		t.Errorf("complete: total_score = %d, pending = %v; want 90, false", got.TotalScore, got.Pending)
	}
```

In `TestAdminSubmissionsHandler_UnscoredIsPendingEvenWithManualScores` (around line 176), replace:

```go
	ack, irq := 20, 5
	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if err := scoresStore.Set(scoring.Result{
		SubmissionID: "never-auto-scored", Scored: false,
		AckTimeScore: &ack, IncidentResponseQualityScore: &irq,
	}); err != nil {
		t.Fatalf("scoresStore.Set: %v", err)
	}
```

with:

```go
	irq := 5
	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if err := scoresStore.Set(scoring.Result{
		SubmissionID: "never-auto-scored", Scored: false,
		IncidentResponseQualityScore: &irq,
	}); err != nil {
		t.Fatalf("scoresStore.Set: %v", err)
	}
```

- [ ] **Step 14: Update `cmd/portal/main.go`'s wiring**

At `cmd/portal/main.go:143`, change:

```go
	mux.Handle("POST /admin/submissions/{id}/score", portal.AdminAuth(adminPassword, portal.AdminScoreHandler(submissionLog, exerciseStore, scoresStore)))
```

to:

```go
	mux.Handle("POST /admin/submissions/{id}/score", portal.AdminAuth(adminPassword, portal.AdminScoreHandler(submissionLog, scoresStore)))
```

(`exerciseStore` stays declared and used by the other two routes — `/admin/exercise` and `/admin/summary` — on lines 142 and 145, so no import or variable becomes unused here.)

- [ ] **Step 15: Run the full test suite**

Run: `go build ./... && go test ./...`
Expected: PASS everywhere.

- [ ] **Step 16: Commit**

```bash
git add scoring/result.go scoring/result_test.go scoring/score.go scoring/score_test.go \
        portal/score.go portal/score_test.go portal/summary.go portal/summary_test.go \
        portal/admin_test.go cmd/portal/main.go
git commit -m "Remove the manual acknowledgement-time criterion and AckTimeScore"
```

---

### Task 3: Remove the "Acknowledged at" field from the admin frontend

**Files:**
- Modify: `cmd/portal/static/admin.js:35-115` (`buildScoreForm`)

**Interfaces:**
- Consumes: `POST /admin/submissions/{id}/score` now takes `{incident_response_quality_score: int}` only (Task 2), bounded 0-25.
- Produces: nothing consumed by later tasks — this is the last code change.

- [ ] **Step 1: Rewrite `buildScoreForm` in `cmd/portal/static/admin.js`**

Replace the function (currently lines 35-115):

```js
function buildScoreForm(id, score) {
  const form = document.createElement("div");
  form.className = "score-form";

  const irqInput = document.createElement("input");
  irqInput.type = "number";
  irqInput.min = "0";
  irqInput.max = "25";
  irqInput.placeholder = "0-25";

  // Prefill from what was already recorded, so the form shows the
  // current value instead of looking permanently unfilled.
  if (score && typeof score.incident_response_quality_score === "number") {
    irqInput.value = String(score.incident_response_quality_score);
  }

  const actions = document.createElement("div");
  actions.className = "score-form-actions";

  const button = document.createElement("button");
  button.type = "button";
  button.className = "btn-sm";
  button.textContent = "Save";

  // Errors from a Save land next to the form that produced them —
  // the shared #admin-error banner lives below the whole table, easy
  // to miss on a page with many rows, and previously the only place
  // this exact error ever appeared.
  const error = document.createElement("span");
  error.className = "error form-error";

  button.addEventListener("click", async () => {
    // An empty box gives Number("") === 0 and junk gives NaN, which
    // JSON.stringify writes as null. Both used to reach the server as a
    // score the admin never entered, so catch them here too rather than
    // relying on the 400 alone.
    const irq = Number(irqInput.value.trim());
    if (irqInput.value.trim() === "" || !Number.isInteger(irq)) {
      error.textContent = "Incident response quality score is required (whole number, 0-25).";
      return;
    }

    let resp;
    try {
      resp = await fetch(`/admin/submissions/${encodeURIComponent(id)}/score`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          incident_response_quality_score: irq,
        }),
      });
    } catch (err) {
      error.textContent = "Network error: " + err.message;
      return;
    }
    if (!resp.ok) {
      error.textContent = await resp.text();
      return;
    }
    error.textContent = "";
    // force: this refresh is the point of the click, and focus is still
    // inside the table (on this button) when it runs.
    refresh({ force: true });
  });

  actions.append(button, error);
  form.append(
    buildLabeledInput("Incident response (0–25)", irqInput),
    actions,
  );
  return form;
}
```

- [ ] **Step 2: Manually verify in the browser**

Run: `go run ./cmd/portal-dev` (or the project's existing dev-run convention), open `/admin`, configure an exercise, and confirm:
- A submission's score row shows only the "Incident response (0–25)" field — no "Acknowledged at" box.
- Saving a value outside 0-25 shows the client-side error message.
- Saving a valid value persists and reloads correctly (prefills on next render).

Report this as a manual check in the task's completion notes — there is no automated frontend test in this repo (per its existing convention, see `docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md`'s Testing section).

- [ ] **Step 3: Commit**

```bash
git add cmd/portal/static/admin.js
git commit -m "Remove the Acknowledged-at field from the admin score form"
```

---

### Task 4: Update `prd.md`'s rubric and objectives

**Files:**
- Modify: `prd.md:17-24` (Objectives bullets)
- Modify: `prd.md:314-324` (Evaluation Criteria table)

**Interfaces:**
- Consumes: nothing (docs-only).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Update the Objectives list**

At `prd.md:17-24`, remove the "Time required to acknowledge the incident." bullet (the event it referred to is no longer tracked or scored separately from submission):

```markdown
The fire drill evaluates several aspects of validator operations:

- Time required to submit the requested artifacts.
- Ability to follow a standardized incident-response procedure.
- Completeness and accuracy of the submitted information.
- Quality and usability of the collected logs.
- Overall operational readiness.
```

- [ ] **Step 2: Update the Evaluation Criteria table**

At `prd.md:314-324`, replace:

```markdown
| Metric | Score |
|---------|------:|
| Acknowledgement time | 20 |
| Upload completion time | 20 |
| Metadata completeness | 20 |
| Log quality | 20 |
| Incident response quality | 20 |

Maximum score:

**100 points**
```

with:

```markdown
| Metric | Score |
|---------|------:|
| Upload completion time | 25 |
| Metadata completeness | 25 |
| Log quality | 25 |
| Incident response quality | 25 |

Maximum score:

**100 points**
```

- [ ] **Step 3: Commit**

```bash
git add prd.md
git commit -m "Update prd.md's rubric for the merged upload/acknowledgement criterion"
```

---

### Task 5: Update the Phase 3 design spec and README to match

**Files:**
- Modify: `docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md` (lines 60-67, 112-113, 160-164, 190-231, 279-280, 284-296, 300)
- Modify: `README.md` (lines 100, 111-115, 161-163)

**Interfaces:**
- Consumes: nothing (docs-only).
- Produces: nothing.

- [ ] **Step 1: Update the `scoring.Result` code block in the Phase 3 spec**

At `docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md:52-68`, replace:

```go
type Result struct {
    SubmissionID string

    // Automatic — computed once, at submit time.
    GenesisMatch     bool
    VersionSupported bool
    LogWindow        LogWindowCheck
    UploadTimeScore  int // 0-20
    MetadataScore    int // 0-20, effectively always 20 for a logged submission — see Scoring formulas
    LogQualityScore  int // 0-20

    // Manual — entered later via POST /admin/submissions/{id}/score.
    AcknowledgedAt               *time.Time
    AckTimeScore                 *int
    IncidentResponseQualityScore *int
}
```

with:

```go
type Result struct {
    SubmissionID string

    // Automatic — computed once, at submit time.
    GenesisMatch     bool
    VersionSupported bool
    LogWindow        LogWindowCheck
    UploadTimeScore  int // 0-25
    MetadataScore    int // 0-25, effectively always 25 for a logged submission — see Scoring formulas
    LogQualityScore  int // 0-25

    // Manual — entered later via POST /admin/submissions/{id}/score.
    IncidentResponseQualityScore *int // 0-25
}
```

(This struct block was superseded by
`docs/superpowers/specs/2026-08-04-merge-ack-upload-scoring-design.md` — updating it here too, rather than leaving it stale, keeps a reader of this spec from being misled by dead code.)

- [ ] **Step 2: Update the `TotalScore()` description**

At `docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md:77-79`, replace:

```markdown
`Result.TotalScore()` sums all five sub-scores, treating unset manual fields
as "pending" (surfaced distinctly in the dashboard/summary, not silently
counted as 0).
```

with:

```markdown
`Result.TotalScore()` sums all four sub-scores, treating an unset manual
field as "pending" (surfaced distinctly in the dashboard/summary, not
silently counted as 0).
```

- [ ] **Step 3: Update the `score.go` bullet's formula description**

At `docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md:112-113`, replace:

```markdown
- `score.go` — the tiered time-based formula (shared by upload time and ack
  time), `LogQualityScore`, `Result.TotalScore()`.
```

with:

```markdown
- `score.go` — the tiered time-based formula (upload completion time),
  `LogQualityScore`, `Result.TotalScore()`.
```

- [ ] **Step 4: Update the `AdminScoreHandler` bullet**

At `docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md:160-164`, replace:

```markdown
- `score.go` (new) — `AdminScoreHandler`: `POST /admin/submissions/{id}/score`, body `{acknowledged_at: RFC3339, incident_response_quality_score: int}`. Validates the score is 0-20 (400 otherwise), looks up the
  submission's `Entry` to compute `AckTimeScore` against the exercise's
  announce/deadline window, and updates the `scoring.Result`. 404 on an
  unknown ID; 400 if the exercise isn't configured yet (nothing to score
  against).
```

with:

```markdown
- `score.go` (new) — `AdminScoreHandler`: `POST /admin/submissions/{id}/score`, body `{incident_response_quality_score: int}`. Validates the score is
  0-25 (400 otherwise) and updates the `scoring.Result`. 404 on an unknown
  ID; 409 if the submission was never auto-scored (nothing to complete).
```

- [ ] **Step 5: Update the Scoring formulas section**

At `docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md:190-217`, replace:

```markdown
## Scoring formulas

**Tiered time score** (shared by upload completion time and acknowledgement
time), given `announced_at`, `deadline_at`, and the event timestamp `t`:

```
pct = (t - announced_at) / (deadline_at - announced_at)
pct <= 25%  → 20
pct <= 50%  → 15
pct <= 75%  → 10
pct <= 100% → 5
pct > 100%  → 0
```

**Metadata completeness** — always 20 for a logged submission. `SubmitHandler` already rejects a submission with invalid `metadata.json` before
it's ever recorded (`submission.ValidateMetadata`), so by construction every
`scoring.Result` that exists corresponds to metadata that passed the schema.
The field is kept (rather than removed) for symmetry with the PRD's rubric
and in case per-field partial credit is wanted later — but as designed here,
it doesn't vary.

**Log quality** (0-20) — for the same reason, "archive present with valid
gzip magic bytes" is also already guaranteed by `submission.ValidateArchive`
before a submission is recorded. So: 10 points are a fixed base (that
structural guarantee), and up to 10 more come from `LogWindowCheck`:
`Covered` → 10, `Detected && !Covered` (partial overlap with the
investigation window) → 5, `!Detected` → 0 (surfaced as a warning in the
summary, not a rejection — timestamp parsing is best-effort).
```

with:

```markdown
## Scoring formulas

**Tiered time score** (upload completion time only — see
`2026-08-04-merge-ack-upload-scoring-design.md` for why acknowledgement
time was dropped), given `announced_at`, `deadline_at`, and the event
timestamp `t`:

```
pct = (t - announced_at) / (deadline_at - announced_at)
pct <= 25%  → 25
pct <= 50%  → 19
pct <= 75%  → 13
pct <= 100% → 6
pct > 100%  → 0
```

**Metadata completeness** — always 25 for a logged submission. `SubmitHandler` already rejects a submission with invalid `metadata.json` before
it's ever recorded (`submission.ValidateMetadata`), so by construction every
`scoring.Result` that exists corresponds to metadata that passed the schema.
The field is kept (rather than removed) for symmetry with the PRD's rubric
and in case per-field partial credit is wanted later — but as designed here,
it doesn't vary.

**Log quality** (0-25) — for the same reason, "archive present with valid
gzip magic bytes" is also already guaranteed by `submission.ValidateArchive`
before a submission is recorded. So: 13 points are a fixed base (that
structural guarantee), and up to 12 more come from `LogWindowCheck`:
`Covered` → +12, `Detected && !Covered` (partial overlap with the
investigation window) → +6, `!Detected` → +0 (surfaced as a warning in the
summary, not a rejection — timestamp parsing is best-effort).
```

(Leave the `Covered`/coverage-verification paragraph immediately below this block, and the "Genesis hash / gnoland version" paragraph after it, unchanged — neither references the removed criterion or the old point values.)

- [ ] **Step 6: Update the Frontend section**

At `docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md:279-280`, replace:

```markdown
- A per-row form for the two manual fields (acknowledged-at timestamp,
  incident response quality score).
```

with:

```markdown
- A per-row form for the one manual field (incident response quality
  score).
```

- [ ] **Step 7: Update the Error handling section**

At `docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md:284-296`, replace:

```markdown
- `POST /admin/submissions/{id}/score`: 400 on a score outside 0-20 or if no
  exercise is configured yet; 404 on an unknown submission ID.
```

with:

```markdown
- `POST /admin/submissions/{id}/score`: 400 on a score outside 0-25; 404 on
  an unknown submission ID; 409 if the submission was never auto-scored.
```

(Leave the surrounding bullets — AV scan, genesis/version mismatches, submissions arriving before exercise configuration — unchanged; none of them describe the removed criterion.)

- [ ] **Step 8: Update the Testing section's formula-boundary bullet**

At `docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md:300`, replace:

```markdown
- `scoring`: tiered-formula boundary tests (exactly at 25/50/75/100%, before
  announcement, after deadline); timestamp parsing (mixed recognized/
  unrecognized lines, no timestamps at all, decompression cap reached);
  genesis/version match and mismatch; `LogQualityScore` composite; `Result.TotalScore()` with pending manual fields.
```

with:

```markdown
- `scoring`: tiered-formula boundary tests (exactly at 25/50/75/100%, before
  announcement, after deadline); timestamp parsing (mixed recognized/
  unrecognized lines, no timestamps at all, decompression cap reached);
  genesis/version match and mismatch; `LogQualityScore` composite; `Result.TotalScore()` with a pending manual field.
```

- [ ] **Step 9: Update `README.md`'s admin routes table**

At `README.md:100`, replace:

```markdown
| `POST /admin/submissions/{id}/score` | Enter the two manually judged criteria: acknowledgement time and incident response quality |
```

with:

```markdown
| `POST /admin/submissions/{id}/score` | Enter the one manually judged criterion: incident response quality |
```

- [ ] **Step 10: Update `README.md`'s "Running an exercise" walkthrough**

At `README.md:112-115`, replace:

```markdown
3. Enter the two manual scores per submission from the dashboard. A total
   is shown as pending until both are in — an incident response quality
   score is required, and leaving the box empty is rejected rather than
   recorded as a 0 (which is itself a valid score).
```

with:

```markdown
3. Enter the manual incident response quality score per submission from
   the dashboard. A total is shown as pending until it's in — the score
   is required, and leaving the box empty is rejected rather than
   recorded as a 0 (which is itself a valid score).
```

- [ ] **Step 11: Update `README.md`'s "How it works" section**

At `README.md:161-163`, replace:

```markdown
   investigation-window coverage of the submitted log, and upload
   timeliness. The two criteria no code can observe — acknowledgement time
   and incident response quality — are entered by an admin afterwards.
```

with:

```markdown
   investigation-window coverage of the submitted log, and upload
   timeliness. The one criterion no code can observe — incident response
   quality — is entered by an admin afterwards.
```

- [ ] **Step 12: Commit**

```bash
git add docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md README.md
git commit -m "Update Phase 3 spec and README for the merged scoring rubric"
```

---

### Task 6: Final verification

**Files:** none modified — verification only.

**Interfaces:** none.

- [ ] **Step 1: Full build and test sweep**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS with no errors or vet warnings.

- [ ] **Step 2: Confirm no stray references remain**

Run: `grep -rn "AckTimeScore\|AcknowledgedAt\|acknowledged_at" --include='*.go' --include='*.js' --include='*.md' .`
Expected: no output (an empty grep means nothing was missed). If anything matches outside `.git/` or this plan/spec's own historical narration, fix it before proceeding.

- [ ] **Step 3: Manual smoke test**

Run: `go run ./cmd/portal-dev` (or this project's existing dev-run convention), and walk through: configure an exercise, submit a sample archive, open `/admin`, confirm the submissions table shows the auto-computed scores out of 25 each, enter an incident response score, confirm the total reads out of 100 with no pending note, and generate the summary to confirm the Markdown total line reads `100/100` with no ack-related text.

- [ ] **Step 4: Report completion**

No further commit needed for this task — it's verification-only. If Step 2 or Step 3 turns up an issue, fix it in the relevant task's files and amend that task's commit (not this one) via a new commit, then re-run Steps 1-3.
