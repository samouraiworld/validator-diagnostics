# Fire Drill Phase 3 (Scoring & ClamAV) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `prd.md`'s Phase 3 ("Analysis & Scoring") — automatic genesis/version/log-window checks, the 5×20-point evaluation rubric, and a generated Discord-ready summary — plus the previously-deferred ClamAV scan, per `docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md`.

**Architecture:** Two new pure-logic packages (`exercise` for admin-configured exercise parameters, `scoring` for the rubric and automatic checks) plus a new `clamav` package for AV scanning, all wired into the existing `portal.SubmitHandler` and three new admin endpoints. `exercise` and `scoring` persist to JSON files with the same read-modify-write-under-mutex shape; `clamav` talks to a `clamd` daemon over its `INSTREAM` protocol, defaulting to a no-op scanner when unconfigured.

**Tech Stack:** Go 1.26 (stdlib only for the new packages — `net`, `compress/gzip`, `bufio`, `encoding/json`), the existing `github.com/samourai/validator-diagnostics/{auth,storage,submission,portal}` packages, Docker Compose for the local `clamav/clamav` service.

## Global Constraints

- Never re-parse the raw uploaded archive a second time to get at `gnoland.log.gz`'s content — reuse the bytes `submission.ValidateArchive` already read and bounded (`submission.Result.LogGz`). See spec "Security" section.
- Any decompression of `gnoland.log.gz`'s own gzip content must go through its own `io.LimitReader`, independent of the archive-level size cap, per `prd.md`'s "decompressed-size limit, independent from the compressed upload size limit."
- Never store or render raw log line content anywhere (dashboard, generated summary) — only structured, parsed results (`bool`, `time.Time`).
- ClamAV scan failures (unreachable/timeout) are fail-closed: reject the upload (503), never fail-open.
- All new admin endpoints are wrapped in the existing `portal.AdminAuth`, matching `/admin` and `/admin/submissions` today.
- New optional `SubmitHandler` fields (`AVScanner`, `Exercise`, `Scores`) must default to "feature disabled" when nil/unset, so existing tests and callers that don't set them keep working unmodified — same convention already used for `Log`.
- No new third-party Go dependencies (no JWT libs, no ClamAV client wrapper) — matches this repo's existing preference for small hand-written clients over broad dependencies (see `auth.SessionSigner`'s doc comment).

---

### Task 1: `exercise.Config` and validation

**Files:**
- Create: `exercise/config.go`
- Test: `exercise/config_test.go`

**Interfaces:**
- Produces: `exercise.Config` struct (fields: `AnnouncedAt`, `DeadlineAt`, `InvestigationWindowStart`, `InvestigationWindowEnd time.Time`; `ExpectedGenesisSHA256 string`; `SupportedGnolandVersions []string`; `Observations string`), `Config.Validate() error`, `Config.Configured() bool`.

- [ ] **Step 1: Write the failing tests**

```go
// exercise/config_test.go
package exercise

import (
	"testing"
	"time"
)

func validConfig() Config {
	return Config{
		AnnouncedAt:              time.Date(2026, 7, 8, 18, 0, 0, 0, time.UTC),
		DeadlineAt:               time.Date(2026, 7, 9, 19, 30, 0, 0, time.UTC),
		InvestigationWindowStart: time.Date(2026, 7, 8, 18, 0, 0, 0, time.UTC),
		InvestigationWindowEnd:   time.Date(2026, 7, 9, 18, 30, 0, 0, time.UTC),
		ExpectedGenesisSHA256:    "deadbeef",
		SupportedGnolandVersions: []string{"v1.0.0"},
	}
}

func TestConfig_Validate_OK(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestConfig_Validate_DeadlineNotAfterAnnounced(t *testing.T) {
	cfg := validConfig()
	cfg.DeadlineAt = cfg.AnnouncedAt
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() = nil, want an error when deadline_at == announced_at")
	}

	cfg.DeadlineAt = cfg.AnnouncedAt.Add(-time.Hour)
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() = nil, want an error when deadline_at is before announced_at")
	}
}

func TestConfig_Validate_WindowEndNotAfterStart(t *testing.T) {
	cfg := validConfig()
	cfg.InvestigationWindowEnd = cfg.InvestigationWindowStart
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() = nil, want an error when investigation_window_end == investigation_window_start")
	}
}

func TestConfig_Configured(t *testing.T) {
	if (Config{}).Configured() {
		t.Error("zero-value Config should report Configured() == false")
	}
	if !validConfig().Configured() {
		t.Error("a fully set Config should report Configured() == true")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./exercise/...`
Expected: FAIL — `exercise` package doesn't exist yet (`no Go files`, or `undefined: Config`).

- [ ] **Step 3: Write the implementation**

```go
// exercise/config.go

// Package exercise holds the admin-configured parameters of a single
// fire-drill exercise (prd.md, "Fire Drill Procedure" / "Evaluation
// Criteria") — the values the scoring package needs to know to judge a
// submission: when the exercise was announced and is due, what
// investigation window the logs should cover, and what genesis
// hash/gnoland version are expected.
package exercise

import (
	"fmt"
	"time"
)

// Config is the exercise-wide configuration an admin sets once (and
// may update) via POST /admin/exercise.
type Config struct {
	AnnouncedAt              time.Time `json:"announced_at"`
	DeadlineAt               time.Time `json:"deadline_at"`
	InvestigationWindowStart time.Time `json:"investigation_window_start"`
	InvestigationWindowEnd   time.Time `json:"investigation_window_end"`

	ExpectedGenesisSHA256    string   `json:"expected_genesis_sha256"`
	SupportedGnolandVersions []string `json:"supported_gnoland_versions"`

	// Observations is free text, included verbatim at the end of the
	// generated summary (see portal.AdminSummaryHandler).
	Observations string `json:"observations"`
}

// Configured reports whether an admin has ever set this exercise up,
// as opposed to the zero Config returned before that's happened.
func (c Config) Configured() bool {
	return !c.AnnouncedAt.IsZero() || !c.DeadlineAt.IsZero()
}

// Validate enforces the two timing invariants scoring depends on: a
// non-empty announce-to-deadline window (scoring.TieredTimeScore
// divides by its length) and a non-empty investigation window.
func (c Config) Validate() error {
	if !c.DeadlineAt.After(c.AnnouncedAt) {
		return fmt.Errorf("deadline_at (%s) must be after announced_at (%s)", c.DeadlineAt, c.AnnouncedAt)
	}
	if !c.InvestigationWindowEnd.After(c.InvestigationWindowStart) {
		return fmt.Errorf("investigation_window_end (%s) must be after investigation_window_start (%s)", c.InvestigationWindowEnd, c.InvestigationWindowStart)
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./exercise/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add exercise/config.go exercise/config_test.go
git commit -m "Add exercise.Config for Phase 3 exercise parameters"
```

---

### Task 2: `exercise.FileStore`

**Files:**
- Create: `exercise/store.go`
- Test: `exercise/store_test.go`

**Interfaces:**
- Consumes: `Config`, `Config.Validate()` from Task 1.
- Produces: `exercise.FileStore` (`NewFileStore(path string) *FileStore`, `(*FileStore) Get() (Config, error)`, `(*FileStore) Set(Config) error`).

- [ ] **Step 1: Write the failing tests**

```go
// exercise/store_test.go
package exercise

import (
	"path/filepath"
	"testing"
)

func TestFileStore_GetOnMissingFile(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "does-not-exist.json"))

	cfg, err := store.Get()
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if cfg.Configured() {
		t.Errorf("Get() on a missing file = %+v, want the zero Config", cfg)
	}
}

func TestFileStore_SetAndGet(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	want := validConfig()

	if err := store.Set(want); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := store.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.AnnouncedAt.Equal(want.AnnouncedAt) || got.ExpectedGenesisSHA256 != want.ExpectedGenesisSHA256 {
		t.Errorf("Get() = %+v, want %+v", got, want)
	}
}

func TestFileStore_SetRejectsInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exercise.json")
	store := NewFileStore(path)

	cfg := validConfig()
	cfg.DeadlineAt = cfg.AnnouncedAt
	if err := store.Set(cfg); err == nil {
		t.Fatal("Set with an invalid config: expected an error, got nil")
	}

	got, err := store.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Configured() {
		t.Error("a rejected Set should not have persisted anything")
	}
}

func TestFileStore_SetReplacesPreviousConfig(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))

	first := validConfig()
	if err := store.Set(first); err != nil {
		t.Fatalf("Set(first): %v", err)
	}

	second := validConfig()
	second.ExpectedGenesisSHA256 = "different-hash"
	if err := store.Set(second); err != nil {
		t.Fatalf("Set(second): %v", err)
	}

	got, err := store.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ExpectedGenesisSHA256 != "different-hash" {
		t.Errorf("ExpectedGenesisSHA256 = %q, want the second Set's value", got.ExpectedGenesisSHA256)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./exercise/... -run FileStore`
Expected: FAIL — `undefined: NewFileStore`

- [ ] **Step 3: Write the implementation**

```go
// exercise/store.go
package exercise

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// FileStore persists a single Config to a JSON file, guarded by a
// mutex. Unlike portal.FileLog (append-only submissions), the exercise
// config is replaced wholesale each time an admin updates it, so this
// is a read-modify-write store, not an append log.
type FileStore struct {
	mu   sync.Mutex
	path string
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// Get returns the current config, or the zero Config (Configured() ==
// false) if none has been saved yet.
func (s *FileStore) Get() (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("unable to read exercise config %s: %w", s.path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("unable to parse exercise config %s: %w", s.path, err)
	}
	return cfg, nil
}

// Set validates cfg and persists it, replacing whatever was stored
// before. An invalid cfg is rejected without touching the file.
func (s *FileStore) Set(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to marshal exercise config: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.WriteFile(s.path, data, 0o644); err != nil {
		return fmt.Errorf("unable to write exercise config %s: %w", s.path, err)
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./exercise/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add exercise/store.go exercise/store_test.go
git commit -m "Add exercise.FileStore for persisting exercise config"
```

---

### Task 3: `exercise.ConfigHandler` (admin HTTP endpoint)

**Files:**
- Create: `exercise/http.go`
- Test: `exercise/http_test.go`

**Interfaces:**
- Consumes: `*FileStore` from Task 2.
- Produces: `exercise.ConfigHandler(store *FileStore) http.HandlerFunc` — GET returns the current `Config` as JSON, POST replaces it (400 on invalid JSON or a `Validate()` failure).

- [ ] **Step 1: Write the failing tests**

```go
// exercise/http_test.go
package exercise

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestConfigHandler_GetBeforeAnySet(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	srv := httptest.NewServer(ConfigHandler(store))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var cfg Config
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.Configured() {
		t.Errorf("GET before any POST = %+v, want the zero Config", cfg)
	}
}

func TestConfigHandler_PostThenGet(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	srv := httptest.NewServer(ConfigHandler(store))
	defer srv.Close()

	cfg := validConfig()
	body, _ := json.Marshal(cfg)

	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST status = %d, want 200", resp.StatusCode)
	}

	getResp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer getResp.Body.Close()

	var got Config
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ExpectedGenesisSHA256 != cfg.ExpectedGenesisSHA256 {
		t.Errorf("ExpectedGenesisSHA256 = %q, want %q", got.ExpectedGenesisSHA256, cfg.ExpectedGenesisSHA256)
	}
}

func TestConfigHandler_PostRejectsInvalidConfig(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	srv := httptest.NewServer(ConfigHandler(store))
	defer srv.Close()

	cfg := validConfig()
	cfg.DeadlineAt = cfg.AnnouncedAt
	body, _ := json.Marshal(cfg)

	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestConfigHandler_PostRejectsMalformedJSON(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	srv := httptest.NewServer(ConfigHandler(store))
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader([]byte("not json")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./exercise/... -run ConfigHandler`
Expected: FAIL — `undefined: ConfigHandler`

- [ ] **Step 3: Write the implementation**

```go
// exercise/http.go
package exercise

import (
	"encoding/json"
	"net/http"
)

// ConfigHandler serves GET (current config) and POST (replace it) on
// the same route. Wrap with portal.AdminAuth at the caller — this
// handler does no authentication of its own.
func ConfigHandler(store *FileStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg, err := store.Get()
			if err != nil {
				http.Error(w, "unable to read exercise config", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfg)

		case http.MethodPost:
			var cfg Config
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
				return
			}
			if err := store.Set(cfg); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfg)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./exercise/...`
Expected: PASS (all of Tasks 1-3's tests)

- [ ] **Step 5: Commit**

```bash
git add exercise/http.go exercise/http_test.go
git commit -m "Add exercise.ConfigHandler for GET/POST /admin/exercise"
```

---

### Task 4: `submission.Result.LogGz`

**Files:**
- Modify: `submission/archive.go:42-48` (the `Result` struct), `submission/archive.go:125-132` (the `switch hdr.Name` block), `submission/archive.go:141` (the final `return`)
- Modify: `submission/archive_test.go` (add one assertion)

**Interfaces:**
- Produces: `submission.Result` gains a `LogGz []byte` field — the same bounded bytes already read to check `gnoland.log.gz`'s magic bytes, now also returned instead of discarded. This is what `scoring.AutoChecks` (Task 6) will consume, instead of re-reading the raw upload.

- [ ] **Step 1: Write the failing test**

Add this assertion to the existing `TestValidateArchive_Success` (or equivalent success-case test) in `submission/archive_test.go` — find the test that builds a valid archive and checks `result.Metadata`, and add, right after that check:

```go
	if len(result.LogGz) == 0 {
		t.Error("result.LogGz is empty, want the gnoland.log.gz bytes")
	}
	if result.LogGz[0] != 0x1f || result.LogGz[1] != 0x8b {
		t.Errorf("result.LogGz does not start with gzip magic bytes: %x", result.LogGz[:2])
	}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./submission/... -run TestValidateArchive_Success`
Expected: FAIL — `result.LogGz undefined (type Result has no field or method LogGz)`

- [ ] **Step 3: Update the implementation**

In `submission/archive.go`, change the `Result` struct:

```go
// Result holds what ValidateArchive learned. Metadata is the raw,
// still-unvalidated content of metadata.json — pass it to
// ValidateMetadata separately; filename/structure checks and metadata
// *content* checks are different concerns with different failure modes.
// LogGz is the raw, still-gzip-compressed bytes of gnoland.log.gz,
// already bounded by Options.MaxLogSize — callers that need to look
// inside the log (see the scoring package) should use this instead of
// re-reading the raw upload, to avoid two independent parsers
// interpreting the same untrusted archive differently.
type Result struct {
	Metadata []byte
	LogGz    []byte
}
```

Change the `switch hdr.Name` block to keep the log bytes instead of discarding them:

```go
		switch hdr.Name {
		case LogFileName:
			if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
				return Result{}, fmt.Errorf("%s does not look like a gzip file (bad magic bytes)", LogFileName)
			}
			logGz = data
		case MetadataFileName:
			metadata = data
		}
```

Add `var logGz []byte` next to the existing `var metadata []byte` declaration, and change the final return:

```go
	return Result{Metadata: metadata, LogGz: logGz}, nil
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./submission/...`
Expected: PASS (the whole package, to confirm nothing else broke)

- [ ] **Step 5: Commit**

```bash
git add submission/archive.go submission/archive_test.go
git commit -m "Return gnoland.log.gz's bounded bytes from ValidateArchive"
```

---

### Task 5: `scoring.TieredTimeScore` and `scoring.LogQualityScore`

**Files:**
- Create: `scoring/score.go`
- Test: `scoring/score_test.go`

**Interfaces:**
- Consumes: `exercise.Config` from Task 1.
- Produces: `scoring.TieredTimeScore(t time.Time, cfg exercise.Config) int`, `scoring.LogWindowCheck` struct (`Detected, Covered bool`; `FirstSeen, LastSeen time.Time`), `scoring.LogQualityScore(window LogWindowCheck) int`.

- [ ] **Step 1: Write the failing tests**

```go
// scoring/score_test.go
package scoring

import (
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
)

func testExerciseConfig() exercise.Config {
	return exercise.Config{
		AnnouncedAt: time.Date(2026, 7, 8, 18, 0, 0, 0, time.UTC),
		DeadlineAt:  time.Date(2026, 7, 8, 22, 0, 0, 0, time.UTC), // 4h window, 1h quarters
	}
}

func TestTieredTimeScore(t *testing.T) {
	cfg := testExerciseConfig()

	cases := []struct {
		name string
		at   time.Time
		want int
	}{
		{"at announcement", cfg.AnnouncedAt, 20},
		{"before announcement", cfg.AnnouncedAt.Add(-time.Minute), 20},
		{"exactly 25%", cfg.AnnouncedAt.Add(1 * time.Hour), 20},
		{"just past 25%", cfg.AnnouncedAt.Add(1*time.Hour + time.Second), 15},
		{"exactly 50%", cfg.AnnouncedAt.Add(2 * time.Hour), 15},
		{"just past 50%", cfg.AnnouncedAt.Add(2*time.Hour + time.Second), 10},
		{"exactly 75%", cfg.AnnouncedAt.Add(3 * time.Hour), 10},
		{"just past 75%", cfg.AnnouncedAt.Add(3*time.Hour + time.Second), 5},
		{"exactly at deadline (100%)", cfg.DeadlineAt, 5},
		{"just past deadline", cfg.DeadlineAt.Add(time.Second), 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := TieredTimeScore(c.at, cfg)
			if got != c.want {
				t.Errorf("TieredTimeScore(%s) = %d, want %d", c.name, got, c.want)
			}
		})
	}
}

func TestLogQualityScore(t *testing.T) {
	cases := []struct {
		name   string
		window LogWindowCheck
		want   int
	}{
		{"fully covered", LogWindowCheck{Detected: true, Covered: true}, 20},
		{"detected but not covered", LogWindowCheck{Detected: true, Covered: false}, 15},
		{"nothing detected", LogWindowCheck{}, 10},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := LogQualityScore(c.window)
			if got != c.want {
				t.Errorf("LogQualityScore(%+v) = %d, want %d", c.window, got, c.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./scoring/...`
Expected: FAIL — `scoring` package doesn't exist yet.

- [ ] **Step 3: Write the implementation**

```go
// scoring/score.go

// Package scoring implements prd.md's Phase 3 "Evaluation Criteria":
// the 5x20-point rubric (acknowledgement time, upload completion time,
// metadata completeness, log quality, incident response quality) and
// the automatic checks (genesis hash, gnoland version, log time
// window) that feed part of it. See
// docs/superpowers/specs/2026-08-03-fire-drill-phase3-design.md for
// the full design and the rationale behind each formula below.
package scoring

import (
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
)

// TieredTimeScore implements the tiered formula shared by upload
// completion time and acknowledgement time: full marks for acting in
// the first quarter of the announce-to-deadline window, degrading by
// quarter, zero once past the deadline. A non-positive
// (DeadlineAt - AnnouncedAt) — i.e. an unconfigured or invalid exercise
// — always scores 0; callers are expected to check
// exercise.Config.Configured() before relying on this for anything
// other than that fallback.
func TieredTimeScore(t time.Time, cfg exercise.Config) int {
	total := cfg.DeadlineAt.Sub(cfg.AnnouncedAt)
	if total <= 0 {
		return 0
	}
	elapsed := t.Sub(cfg.AnnouncedAt)

	switch {
	case elapsed <= total/4:
		return 20
	case elapsed <= total/2:
		return 15
	case elapsed <= total*3/4:
		return 10
	case elapsed <= total:
		return 5
	default:
		return 0
	}
}

// LogWindowCheck is the result of scanning a submitted log for
// timestamps that fall within the exercise's investigation window
// (see scanLogWindow in checks.go, Task 6).
type LogWindowCheck struct {
	// Detected is false if no recognizable timestamp was found at all
	// — parsing is best-effort, so this is a warning condition, not an
	// error.
	Detected bool `json:"detected"`
	// Covered is true only if Detected and the earliest/latest
	// recognized timestamps span the full investigation window.
	Covered bool `json:"covered"`

	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

// LogQualityScore combines the fixed base credit for passing archive
// structure validation — already enforced before a submission is ever
// scored, see submission.ValidateArchive — with credit for how well
// the detected log timestamps cover the investigation window.
func LogQualityScore(window LogWindowCheck) int {
	const structuralBase = 10
	switch {
	case window.Covered:
		return structuralBase + 10
	case window.Detected:
		return structuralBase + 5
	default:
		return structuralBase
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./scoring/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scoring/score.go scoring/score_test.go
git commit -m "Add scoring.TieredTimeScore and scoring.LogQualityScore"
```

---

### Task 6: `scoring.AutoChecks` (genesis, version, log window)

**Files:**
- Create: `scoring/checks.go`
- Test: `scoring/checks_test.go`

**Interfaces:**
- Consumes: `exercise.Config` (Task 1), `submission.Metadata` (existing, `submission/metadata.go`), `LogWindowCheck` (Task 5).
- Produces: `scoring.AutoChecks(meta submission.Metadata, logGz []byte, cfg exercise.Config) (genesisMatch, versionSupported bool, window LogWindowCheck)`.

- [ ] **Step 1: Write the failing tests**

```go
// scoring/checks_test.go
package scoring

import (
	"bytes"
	"compress/gzip"
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/submission"
)

func gzipLines(t *testing.T, lines ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	for _, l := range lines {
		if _, err := gw.Write([]byte(l + "\n")); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func windowTestConfig() exercise.Config {
	return exercise.Config{
		InvestigationWindowStart: time.Date(2026, 7, 8, 18, 0, 0, 0, time.UTC),
		InvestigationWindowEnd:   time.Date(2026, 7, 9, 18, 30, 0, 0, time.UTC),
		ExpectedGenesisSHA256:    "abc123",
		SupportedGnolandVersions: []string{"v1.0.0", "v1.0.1"},
	}
}

func TestAutoChecks_GenesisAndVersionMatch(t *testing.T) {
	cfg := windowTestConfig()
	meta := submission.Metadata{GenesisSHA256: "abc123", GnolandVersion: "v1.0.1"}
	logGz := gzipLines(t, "2026-07-08T19:00:00Z hello")

	genesisMatch, versionSupported, _ := AutoChecks(meta, logGz, cfg)
	if !genesisMatch {
		t.Error("genesisMatch = false, want true")
	}
	if !versionSupported {
		t.Error("versionSupported = false, want true")
	}
}

func TestAutoChecks_GenesisAndVersionMismatch(t *testing.T) {
	cfg := windowTestConfig()
	meta := submission.Metadata{GenesisSHA256: "wrong-hash", GnolandVersion: "v9.9.9"}
	logGz := gzipLines(t, "2026-07-08T19:00:00Z hello")

	genesisMatch, versionSupported, _ := AutoChecks(meta, logGz, cfg)
	if genesisMatch {
		t.Error("genesisMatch = true, want false")
	}
	if versionSupported {
		t.Error("versionSupported = true, want false")
	}
}

func TestAutoChecks_LogWindowFullyCovered(t *testing.T) {
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-08T17:00:00Z starting up",
		"2026-07-08T20:00:00Z consensus running",
		"2026-07-09T19:00:00Z shutting down",
	)

	_, _, window := AutoChecks(submission.Metadata{}, logGz, cfg)
	if !window.Detected || !window.Covered {
		t.Errorf("window = %+v, want Detected and Covered", window)
	}
}

func TestAutoChecks_LogWindowPartiallyCovered(t *testing.T) {
	cfg := windowTestConfig()
	logGz := gzipLines(t,
		"2026-07-08T19:00:00Z starting up",
		"2026-07-08T20:00:00Z consensus running",
	)

	_, _, window := AutoChecks(submission.Metadata{}, logGz, cfg)
	if !window.Detected {
		t.Error("window.Detected = false, want true")
	}
	if window.Covered {
		t.Error("window.Covered = true, want false (log ends well before the investigation window does)")
	}
}

func TestAutoChecks_LogWindowNoTimestamps(t *testing.T) {
	cfg := windowTestConfig()
	logGz := gzipLines(t, "no timestamp here", "nor here either")

	_, _, window := AutoChecks(submission.Metadata{}, logGz, cfg)
	if window.Detected {
		t.Errorf("window = %+v, want !Detected", window)
	}
}

func TestAutoChecks_LogNotGzip(t *testing.T) {
	cfg := windowTestConfig()

	_, _, window := AutoChecks(submission.Metadata{}, []byte("not gzip at all"), cfg)
	if window.Detected || window.Covered {
		t.Errorf("window = %+v, want the zero value for unparseable input", window)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./scoring/... -run AutoChecks`
Expected: FAIL — `undefined: AutoChecks`

- [ ] **Step 3: Write the implementation**

```go
// scoring/checks.go
package scoring

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/submission"
)

// maxLogScanBytes bounds how much *decompressed* plaintext scanLogWindow
// will read out of gnoland.log.gz, independent of the compressed-size
// cap submission.ValidateArchive already applied to logGz. This is the
// inner-layer equivalent of prd.md's "decompressed-size limit,
// independent from the compressed upload size limit": gnoland.log.gz's
// own content is itself gzip-compressed plaintext that ValidateArchive
// never decompresses, so this is the first place that decompression
// happens, and it needs its own bomb protection.
const maxLogScanBytes = 8 << 20 // 8 MiB of plaintext is far more than needed to find a first/last timestamp

// timestampLayouts are tried, in order, against the first
// whitespace-delimited token of each log line.
var timestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
}

// AutoChecks runs prd.md's Phase 3 "Automatic validation" checks for
// one submission: genesis hash, supported gnoland version, and
// investigation-window coverage of the submitted log. logGz must be
// submission.Result.LogGz — the same bounded bytes ValidateArchive
// already read — never a second, independent read of the raw upload
// (see this repo's Phase 3 design spec, "Security").
func AutoChecks(meta submission.Metadata, logGz []byte, cfg exercise.Config) (genesisMatch, versionSupported bool, window LogWindowCheck) {
	genesisMatch = meta.GenesisSHA256 == cfg.ExpectedGenesisSHA256

	for _, v := range cfg.SupportedGnolandVersions {
		if v == meta.GnolandVersion {
			versionSupported = true
			break
		}
	}

	window = scanLogWindow(logGz, cfg)
	return genesisMatch, versionSupported, window
}

// scanLogWindow decompresses logGz under its own bounded reader and
// looks for a recognizable timestamp at the start of each line,
// best-effort: an unparseable or non-gzip input simply yields the zero
// LogWindowCheck rather than an error, since gnoland's exact log format
// isn't part of prd.md's contract.
func scanLogWindow(logGz []byte, cfg exercise.Config) LogWindowCheck {
	gz, err := gzip.NewReader(bytes.NewReader(logGz))
	if err != nil {
		return LogWindowCheck{}
	}
	defer gz.Close()

	bounded := io.LimitReader(gz, maxLogScanBytes)
	scanner := bufio.NewScanner(bounded)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20) // cap a single buffered line at 1 MiB

	var first, last time.Time
	var detected bool

	for scanner.Scan() {
		ts, ok := parseLeadingTimestamp(scanner.Text())
		if !ok {
			continue
		}
		if !detected {
			first = ts
			detected = true
		}
		last = ts
	}
	// scanner.Err() (e.g. ErrTooLong on a pathological line) just means
	// scanning stopped early — whatever was found before that point is
	// still returned, consistent with this being a best-effort check.

	if !detected {
		return LogWindowCheck{}
	}

	covered := !first.After(cfg.InvestigationWindowStart) && !last.Before(cfg.InvestigationWindowEnd)
	return LogWindowCheck{Detected: true, Covered: covered, FirstSeen: first, LastSeen: last}
}

// parseLeadingTimestamp tries each of timestampLayouts against the
// first whitespace-delimited token of line — splitting on whitespace
// first (rather than taking a fixed-length prefix) is what lets this
// correctly handle layouts like RFC3339 whose rendered width varies
// (e.g. "Z" vs "+02:00").
func parseLeadingTimestamp(line string) (time.Time, bool) {
	field := line
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		field = line[:i]
	}
	if len(field) == 0 || len(field) > 64 {
		return time.Time{}, false
	}
	for _, layout := range timestampLayouts {
		if ts, err := time.Parse(layout, field); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./scoring/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scoring/checks.go scoring/checks_test.go
git commit -m "Add scoring.AutoChecks for genesis/version/log-window validation"
```

---

### Task 7: `scoring.Result` and `scoring.Store`

**Files:**
- Create: `scoring/result.go`
- Create: `scoring/store.go`
- Test: `scoring/result_test.go`
- Test: `scoring/store_test.go`

**Interfaces:**
- Consumes: `LogWindowCheck` from Task 5.
- Produces: `scoring.Result` struct (`SubmissionID string`; `Scored, GenesisMatch, VersionSupported bool`; `LogWindow LogWindowCheck`; `UploadTimeScore, MetadataScore, LogQualityScore int`; `AcknowledgedAt *time.Time`; `AckTimeScore, IncidentResponseQualityScore *int`), `Result.TotalScore() int`; `scoring.Store` (`NewStore(path string) *Store`, `(*Store) Get(id string) (Result, bool, error)`, `(*Store) Set(Result) error`, `(*Store) List() ([]Result, error)`).

- [ ] **Step 1: Write the failing tests**

```go
// scoring/result_test.go
package scoring

import "testing"

func TestResult_TotalScore_AutoOnly(t *testing.T) {
	r := Result{UploadTimeScore: 20, MetadataScore: 20, LogQualityScore: 20}
	if got := r.TotalScore(); got != 60 {
		t.Errorf("TotalScore() = %d, want 60 (manual fields not yet entered count as 0)", got)
	}
}

func TestResult_TotalScore_Full(t *testing.T) {
	ack, irq := 15, 18
	r := Result{
		UploadTimeScore:               20,
		MetadataScore:                 20,
		LogQualityScore:               20,
		AckTimeScore:                  &ack,
		IncidentResponseQualityScore:  &irq,
	}
	if got := r.TotalScore(); got != 93 {
		t.Errorf("TotalScore() = %d, want 93", got)
	}
}
```

```go
// scoring/store_test.go
package scoring

import (
	"path/filepath"
	"testing"
)

func TestStore_GetOnMissingFile(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "does-not-exist.json"))

	_, ok, err := store.Get("some-id")
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if ok {
		t.Error("Get on an empty store: ok = true, want false")
	}
}

func TestStore_SetAndGet(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "scores.json"))
	want := Result{SubmissionID: "abc", UploadTimeScore: 20, MetadataScore: 20, LogQualityScore: 15, Scored: true}

	if err := store.Set(want); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, ok, err := store.Get("abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get: ok = false, want true")
	}
	if got.UploadTimeScore != 20 || got.LogQualityScore != 15 {
		t.Errorf("Get() = %+v, want %+v", got, want)
	}
}

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

func TestStore_List(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if err := store.Set(Result{SubmissionID: "a"}); err != nil {
		t.Fatalf("Set(a): %v", err)
	}
	if err := store.Set(Result{SubmissionID: "b"}); err != nil {
		t.Fatalf("Set(b): %v", err)
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("len(list) = %d, want 2", len(list))
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./scoring/... -run 'TestResult|TestStore'`
Expected: FAIL — `undefined: Result` / `undefined: NewStore`

- [ ] **Step 3: Write the implementation**

```go
// scoring/result.go
package scoring

import "time"

// Result is one submission's Phase 3 scoring record, keyed by the
// owning portal.Entry's ID. The automatic fields are computed once, at
// submit time (see AutoChecks and portal.SubmitHandler); the manual
// fields are filled in later by an admin, via
// POST /admin/submissions/{id}/score, since prd.md's rubric includes
// two criteria — acknowledgement time and incident response quality —
// that this codebase has no way to observe automatically.
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

	AcknowledgedAt                *time.Time `json:"acknowledged_at,omitempty"`
	AckTimeScore                  *int       `json:"ack_time_score,omitempty"`
	IncidentResponseQualityScore  *int       `json:"incident_response_quality_score,omitempty"`
}

// TotalScore sums every sub-score against prd.md's 100-point rubric.
// Manual fields not yet entered count as 0 — callers that need to
// distinguish "not yet scored" from "scored zero" should check Scored
// and the two manual pointer fields directly rather than relying on
// TotalScore alone.
func (r Result) TotalScore() int {
	total := r.UploadTimeScore + r.MetadataScore + r.LogQualityScore
	if r.AckTimeScore != nil {
		total += *r.AckTimeScore
	}
	if r.IncidentResponseQualityScore != nil {
		total += *r.IncidentResponseQualityScore
	}
	return total
}
```

```go
// scoring/store.go
package scoring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Store persists Result records to a single JSON file, keyed by
// SubmissionID. Same read-modify-write-under-mutex shape as
// exercise.FileStore — records get updated in place (manual fields
// arrive later), unlike portal.FileLog's append-only submissions log.
type Store struct {
	mu   sync.Mutex
	path string
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

func (s *Store) all() (map[string]Result, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Result{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unable to read scores %s: %w", s.path, err)
	}
	var results map[string]Result
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("unable to parse scores %s: %w", s.path, err)
	}
	return results, nil
}

func (s *Store) save(results map[string]Result) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to marshal scores: %w", err)
	}
	return os.WriteFile(s.path, data, 0o644)
}

// Get returns the record for id, or (Result{}, false, nil) if none
// exists yet.
func (s *Store) Get(id string) (Result, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	results, err := s.all()
	if err != nil {
		return Result{}, false, err
	}
	r, ok := results[id]
	return r, ok, nil
}

// Set writes or replaces the record for r.SubmissionID.
func (s *Store) Set(r Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	results, err := s.all()
	if err != nil {
		return err
	}
	results[r.SubmissionID] = r
	return s.save(results)
}

// List returns every record, in no particular order.
func (s *Store) List() ([]Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	results, err := s.all()
	if err != nil {
		return nil, err
	}
	list := make([]Result, 0, len(results))
	for _, r := range results {
		list = append(list, r)
	}
	return list, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./scoring/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scoring/result.go scoring/result_test.go scoring/store.go scoring/store_test.go
git commit -m "Add scoring.Result and scoring.Store"
```

---

### Task 8: `clamav.Scanner`, `Verdict`, `NoopScanner`

**Files:**
- Create: `clamav/scanner.go`
- Create: `clamav/noop.go`
- Test: `clamav/noop_test.go`

**Interfaces:**
- Produces: `clamav.Verdict` struct (`Infected bool`; `Signature string`), `clamav.Scanner` interface (`Scan(ctx context.Context, r io.Reader) (Verdict, error)`), `clamav.NoopScanner` (implements `Scanner`).

- [ ] **Step 1: Write the failing test**

```go
// clamav/noop_test.go
package clamav

import (
	"context"
	"strings"
	"testing"
)

func TestNoopScanner_AlwaysClean(t *testing.T) {
	verdict, err := NoopScanner{}.Scan(context.Background(), strings.NewReader("anything at all"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if verdict.Infected {
		t.Error("NoopScanner reported Infected = true, want false")
	}
}

func TestNoopScanner_DrainsReader(t *testing.T) {
	r := strings.NewReader("some content")
	if _, err := NoopScanner{}.Scan(context.Background(), r); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if r.Len() != 0 {
		t.Error("NoopScanner did not fully read its input")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./clamav/...`
Expected: FAIL — `clamav` package doesn't exist yet.

- [ ] **Step 3: Write the implementation**

```go
// clamav/scanner.go

// Package clamav scans submitted archives for malware via a clamd
// daemon, as defense in depth alongside submission.ValidateArchive's
// structural checks (prd.md, "Security Considerations" — "Run an
// antivirus scan (e.g. ClamAV) on extracted content"). Implementations
// must never execute, parse, or interpret the scanned content beyond
// what the wire protocol itself requires.
package clamav

import (
	"context"
	"io"
)

// Verdict is the outcome of a completed scan. It's only meaningful
// when Scan returns a nil error — a non-nil error means the scan
// itself could not be completed (unreachable daemon, timeout,
// malformed response), which callers must treat as "unknown", never as
// "clean". portal.SubmitHandler is fail-closed on that distinction: an
// error rejects the upload just as surely as Verdict.Infected does.
type Verdict struct {
	Infected  bool
	Signature string // populated when Infected
}

// Scanner scans r for malware.
type Scanner interface {
	Scan(ctx context.Context, r io.Reader) (Verdict, error)
}
```

```go
// clamav/noop.go
package clamav

import (
	"context"
	"io"
)

// NoopScanner always returns a clean verdict without contacting any
// daemon. Used where a real clamd isn't available (cmd/portal-dev,
// tests) — never wire this into a production deployment; cmd/portal
// only falls back to it when -clamav-addr is left empty, which its own
// flag help text calls out.
type NoopScanner struct{}

var _ Scanner = NoopScanner{}

func (NoopScanner) Scan(ctx context.Context, r io.Reader) (Verdict, error) {
	if _, err := io.Copy(io.Discard, r); err != nil {
		return Verdict{}, err
	}
	return Verdict{}, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./clamav/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clamav/scanner.go clamav/noop.go clamav/noop_test.go
git commit -m "Add clamav.Scanner interface and NoopScanner"
```

---

### Task 9: `clamav.ClamdScanner` (INSTREAM client)

**Files:**
- Create: `clamav/clamd.go`
- Test: `clamav/clamd_test.go`

**Interfaces:**
- Consumes: `Scanner`, `Verdict` from Task 8.
- Produces: `clamav.ClamdScanner` struct (`Addr string`; `Timeout time.Duration`), implementing `Scanner` via clamd's `INSTREAM` wire protocol.

- [ ] **Step 1: Write the failing tests**

```go
// clamav/clamd_test.go
package clamav

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeClamd starts a TCP listener that speaks just enough of the
// INSTREAM protocol to test ClamdScanner against, without needing a
// real clamd: it reads chunks until the terminating zero-length chunk,
// then writes back response.
func fakeClamd(t *testing.T, response string) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		cmd, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(cmd) != "nINSTREAM" {
			return
		}

		for {
			lenBuf := make([]byte, 4)
			if _, err := io.ReadFull(br, lenBuf); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(lenBuf)
			if n == 0 {
				break
			}
			if _, err := io.CopyN(io.Discard, br, int64(n)); err != nil {
				return
			}
		}

		_, _ = conn.Write([]byte(response))
	}()

	return ln.Addr().String()
}

func TestClamdScanner_Clean(t *testing.T) {
	addr := fakeClamd(t, "stream: OK\n")
	scanner := ClamdScanner{Addr: addr, Timeout: 5 * time.Second}

	verdict, err := scanner.Scan(context.Background(), strings.NewReader("harmless content"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if verdict.Infected {
		t.Error("Infected = true, want false")
	}
}

func TestClamdScanner_Infected(t *testing.T) {
	addr := fakeClamd(t, "stream: Eicar-Test-Signature FOUND\n")
	scanner := ClamdScanner{Addr: addr, Timeout: 5 * time.Second}

	verdict, err := scanner.Scan(context.Background(), strings.NewReader("fake eicar payload"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !verdict.Infected {
		t.Fatal("Infected = false, want true")
	}
	if verdict.Signature != "Eicar-Test-Signature" {
		t.Errorf("Signature = %q, want %q", verdict.Signature, "Eicar-Test-Signature")
	}
}

func TestClamdScanner_LargeInput(t *testing.T) {
	// Exercises the multi-chunk path (chunkSize is 1 MiB): 3 MiB of
	// input should be split across multiple INSTREAM chunks.
	addr := fakeClamd(t, "stream: OK\n")
	scanner := ClamdScanner{Addr: addr, Timeout: 5 * time.Second}

	large := strings.NewReader(strings.Repeat("a", 3<<20))
	verdict, err := scanner.Scan(context.Background(), large)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if verdict.Infected {
		t.Error("Infected = true, want false")
	}
}

func TestClamdScanner_Unreachable(t *testing.T) {
	// Port 1 is a privileged port nothing is listening on; dialing it
	// fails fast with "connection refused" rather than timing out.
	scanner := ClamdScanner{Addr: "127.0.0.1:1", Timeout: 2 * time.Second}

	_, err := scanner.Scan(context.Background(), strings.NewReader("content"))
	if err == nil {
		t.Fatal("expected an error for an unreachable daemon, got nil")
	}
}

func TestClamdScanner_MalformedResponse(t *testing.T) {
	addr := fakeClamd(t, "garbage\n")
	scanner := ClamdScanner{Addr: addr, Timeout: 5 * time.Second}

	_, err := scanner.Scan(context.Background(), strings.NewReader("content"))
	if err == nil {
		t.Fatal("expected an error for an unrecognized response, got nil")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./clamav/... -run ClamdScanner`
Expected: FAIL — `undefined: ClamdScanner`

- [ ] **Step 3: Write the implementation**

```go
// clamav/clamd.go
package clamav

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// chunkSize is how much of the scanned input ClamdScanner buffers per
// INSTREAM chunk. clamd's own default StreamMaxLength is 25 MiB per
// chunk; staying well below that keeps memory use predictable
// regardless of what a given deployment configures.
const chunkSize = 1 << 20 // 1 MiB

const defaultTimeout = 30 * time.Second

// ClamdScanner scans over clamd's INSTREAM protocol: a stream of
// 4-byte-big-endian-length-prefixed chunks terminated by a
// zero-length chunk, answered with a single response line
// ("stream: OK" or "stream: <signature> FOUND").
type ClamdScanner struct {
	// Addr is a "host:port" TCP address, or, prefixed with "unix:", a
	// Unix socket path (e.g. "unix:/var/run/clamav/clamd.ctl").
	Addr string

	// Timeout bounds the whole scan, dial included. Zero uses a 30s
	// default.
	Timeout time.Duration
}

var _ Scanner = ClamdScanner{}

func (c ClamdScanner) dial(ctx context.Context) (net.Conn, error) {
	network, addr := "tcp", c.Addr
	if rest, ok := strings.CutPrefix(c.Addr, "unix:"); ok {
		network, addr = "unix", rest
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// Scan streams r to clamd over a single INSTREAM session. Any failure
// to complete the exchange (dial, write, or an unreadable/unrecognized
// response) is returned as an error — portal.SubmitHandler treats that
// as fail-closed, the same as a real Verdict{Infected: true}.
func (c ClamdScanner) Scan(ctx context.Context, r io.Reader) (Verdict, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := c.dial(ctx)
	if err != nil {
		return Verdict{}, fmt.Errorf("clamav: unable to connect to %s: %w", c.Addr, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write([]byte("nINSTREAM\n")); err != nil {
		return Verdict{}, fmt.Errorf("clamav: unable to start INSTREAM: %w", err)
	}

	buf := make([]byte, chunkSize)
	lenPrefix := make([]byte, 4)
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(lenPrefix, uint32(n))
			if _, err := conn.Write(lenPrefix); err != nil {
				return Verdict{}, fmt.Errorf("clamav: writing chunk length: %w", err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return Verdict{}, fmt.Errorf("clamav: writing chunk: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return Verdict{}, fmt.Errorf("clamav: reading input: %w", readErr)
		}
	}

	binary.BigEndian.PutUint32(lenPrefix, 0)
	if _, err := conn.Write(lenPrefix); err != nil {
		return Verdict{}, fmt.Errorf("clamav: writing terminating chunk: %w", err)
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		return Verdict{}, fmt.Errorf("clamav: no response from daemon: %w", err)
	}
	line = strings.TrimSpace(line)

	switch {
	case strings.HasSuffix(line, "OK"):
		return Verdict{}, nil
	case strings.HasSuffix(line, "FOUND"):
		rest := strings.TrimSuffix(strings.TrimPrefix(line, "stream:"), "FOUND")
		return Verdict{Infected: true, Signature: strings.TrimSpace(rest)}, nil
	default:
		return Verdict{}, fmt.Errorf("clamav: unrecognized response %q", line)
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./clamav/...`
Expected: PASS

- [ ] **Step 5: Manual smoke test against a real clamd (documented, not automated)**

Add this as a doc comment above `ClamdScanner` in `clamav/clamd.go` (append to the existing comment), so it's discoverable without being part of CI:

```go
// Manual smoke test against a real daemon (not run in CI, not covered
// by clamd_test.go's fake server): start a real clamd
// (`docker run -d -p 3310:3310 clamav/clamav`, then wait ~60s for the
// virus database to load) and run a throwaway program that calls
// ClamdScanner{Addr: "localhost:3310"}.Scan against the standard
// EICAR test string (https://www.eicar.org/download-anti-malware-testfile/)
// — a clean clamd install must report that string FOUND, and a benign
// string must report OK.
```

Run this manually once by creating a scratch file (not committed) to confirm the real protocol matches the fake server's behavior in `clamd_test.go`:

```bash
mkdir -p /tmp/clamav-smoke && cat > /tmp/clamav-smoke/main.go <<'EOF'
package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/samourai/validator-diagnostics/clamav"
)

const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

func main() {
	scanner := clamav.ClamdScanner{Addr: "localhost:3310", Timeout: 10 * time.Second}

	clean, err := scanner.Scan(context.Background(), strings.NewReader("just some harmless text"))
	fmt.Printf("clean input: verdict=%+v err=%v\n", clean, err)

	infected, err := scanner.Scan(context.Background(), strings.NewReader(eicar))
	fmt.Printf("EICAR input: verdict=%+v err=%v\n", infected, err)
}
EOF
go run /tmp/clamav-smoke/main.go
```

Expected: the clean input prints `Infected:false`; the EICAR input prints `Infected:true Signature:"Eicar-Test-Signature"` (or a similar signature name — exact naming may vary by ClamAV version). Record the result in the task's PR/commit description, then delete `/tmp/clamav-smoke`; do not add this as an automated test (it depends on a running external daemon).

- [ ] **Step 6: Commit**

```bash
git add clamav/clamd.go clamav/clamd_test.go
git commit -m "Add clamav.ClamdScanner (INSTREAM protocol client)"
```

---

### Task 10: `portal.Entry.ID`

**Files:**
- Modify: `portal/log.go`
- Modify: `portal/log_test.go`

**Interfaces:**
- Produces: `Entry` gains an `ID string` field; `portal.NewSubmissionID() (string, error)` — a random, URL-safe identifier.

- [ ] **Step 1: Write the failing test**

Add to `portal/log_test.go`:

```go
func TestNewSubmissionID_Unique(t *testing.T) {
	a, err := NewSubmissionID()
	if err != nil {
		t.Fatalf("NewSubmissionID: %v", err)
	}
	b, err := NewSubmissionID()
	if err != nil {
		t.Fatalf("NewSubmissionID: %v", err)
	}
	if a == "" || b == "" {
		t.Fatal("NewSubmissionID returned an empty string")
	}
	if a == b {
		t.Error("two calls to NewSubmissionID returned the same ID")
	}
}
```

Also update the existing `TestFileLog_RecordAndEntries` to set and assert `ID` on both entries:

```go
	e1 := Entry{
		ID:              "id-1",
		Moniker:         "samourai",
		OperatorAddress: "g1abc",
		Filename:        "samourai-20260709-1830UTC.tar.gz",
		SubmittedAt:     time.Date(2026, 7, 9, 18, 30, 0, 0, time.UTC),
	}
	e2 := Entry{
		ID:              "id-2",
		Moniker:         "other",
		OperatorAddress: "g1def",
		Filename:        "other-20260709-1831UTC.tar.gz",
		SubmittedAt:     time.Date(2026, 7, 9, 18, 31, 0, 0, time.UTC),
	}
```

and add, next to the existing `Moniker`/`SubmittedAt` assertions:

```go
	if entries[0].ID != "id-1" || entries[1].ID != "id-2" {
		t.Errorf("IDs not round-tripped: entries = %+v", entries)
	}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./portal/... -run 'TestNewSubmissionID|TestFileLog_RecordAndEntries'`
Expected: FAIL — `undefined: NewSubmissionID` (and the `ID` field doesn't exist on `Entry`)

- [ ] **Step 3: Write the implementation**

In `portal/log.go`, add `ID` to `Entry` and add the generator function. Update the imports and the `Entry` struct:

```go
import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)
```

```go
// Entry is one recorded successful submission, written by SubmitHandler
// and read back by the admin dashboard. ID is the join key between
// this append-only log and the scoring package's per-submission
// records (see scoring.Store), which need to support updates that
// FileLog's append-only model doesn't.
type Entry struct {
	ID              string    `json:"id"`
	Moniker         string    `json:"moniker"`
	OperatorAddress string    `json:"operator_address"`
	Filename        string    `json:"filename"`
	SubmittedAt     time.Time `json:"submitted_at"`
}

// NewSubmissionID returns a random, URL-safe identifier for a new
// Entry.
func NewSubmissionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("unable to generate submission ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./portal/...`
Expected: PASS (note: `TestAdminSubmissionsHandler` in `admin_test.go` still compiles fine since it doesn't check `ID` yet — Task 13 updates it)

- [ ] **Step 5: Commit**

```bash
git add portal/log.go portal/log_test.go
git commit -m "Add Entry.ID and NewSubmissionID"
```

---

### Task 11: Wire AV scanning and scoring into `SubmitHandler`

**Files:**
- Modify: `portal/submit.go`
- Modify: `portal/submit_test.go`

**Interfaces:**
- Consumes: `clamav.Scanner`/`Verdict` (Task 8-9), `exercise.FileStore`/`Config` (Tasks 1-2), `scoring.Store`/`Result`/`AutoChecks`/`TieredTimeScore`/`LogQualityScore` (Tasks 5-7), `submission.Result.LogGz` (Task 4), `portal.NewSubmissionID` (Task 10).
- Produces: `SubmitHandler` gains `AVScanner clamav.Scanner`, `Exercise *exercise.FileStore`, `Scores *scoring.Store` fields (all nil-safe: nil disables that step, matching the existing `Log` convention). Rejects infected uploads with 422, rejects on AV-scan errors with 503 (fail-closed).

- [ ] **Step 1: Write the failing tests**

Add to `portal/submit_test.go`. First, a fake scanner (near the existing `fakeStore`/`fakeLog` helpers):

```go
type fakeScanner struct {
	verdict clamav.Verdict
	err     error
}

func (f fakeScanner) Scan(ctx context.Context, r io.Reader) (clamav.Verdict, error) {
	_, _ = io.Copy(io.Discard, r) // a real Scanner always drains r; assert callers behave the same
	return f.verdict, f.err
}
```

Then the new test functions:

```go
func TestSubmitHandler_RejectsInfectedArchive(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     store,
		AVScanner: fakeScanner{verdict: clamav.Verdict{Infected: true, Signature: "Test-Signature"}},
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, operatorAddr.String())
	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	if len(store.saved) != 0 {
		t.Error("infected archive should not have been stored")
	}
}

func TestSubmitHandler_RejectsWhenAVScannerUnavailable(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	handler := &SubmitHandler{
		Sessions:  sessions,
		Store:     store,
		AVScanner: fakeScanner{err: errors.New("connection refused")},
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, operatorAddr.String())
	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (fail-closed on scanner unavailability)", resp.StatusCode)
	}
	if len(store.saved) != 0 {
		t.Error("archive should not have been stored when the AV scan could not run")
	}
}

func TestSubmitHandler_RecordsScoreWhenExerciseConfigured(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	submissionLog := &fakeLog{}

	exerciseStore := exercise.NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	cfg := exercise.Config{
		AnnouncedAt:              time.Now().UTC().Add(-time.Hour),
		DeadlineAt:               time.Now().UTC().Add(time.Hour),
		InvestigationWindowStart: time.Now().UTC().Add(-24 * time.Hour),
		InvestigationWindowEnd:   time.Now().UTC(),
		ExpectedGenesisSHA256:    "deadbeef",
		SupportedGnolandVersions: []string{"v1.0.0"},
	}
	if err := exerciseStore.Set(cfg); err != nil {
		t.Fatalf("exerciseStore.Set: %v", err)
	}
	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))

	handler := &SubmitHandler{
		Sessions: sessions,
		Store:    store,
		Log:      submissionLog,
		Exercise: exerciseStore,
		Scores:   scoresStore,
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, operatorAddr.String())
	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", archive)

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
	id := submissionLog.entries[0].ID
	submissionLog.mu.Unlock()
	if id == "" {
		t.Fatal("recorded entry has no ID")
	}

	result, ok, err := scoresStore.Get(id)
	if err != nil {
		t.Fatalf("scoresStore.Get: %v", err)
	}
	if !ok || !result.Scored {
		t.Fatalf("result = %+v, ok=%v, want a Scored result", result, ok)
	}
	if result.MetadataScore != 20 {
		t.Errorf("MetadataScore = %d, want 20", result.MetadataScore)
	}
	if result.UploadTimeScore != 20 {
		t.Errorf("UploadTimeScore = %d, want 20 (submitted well within the first quarter)", result.UploadTimeScore)
	}
}

func TestSubmitHandler_ScoresPendingWhenExerciseNotConfigured(t *testing.T) {
	operatorAddr := testOperatorAddr()
	sessions := auth.NewSessionSigner([]byte("test-secret"), 5*time.Minute)
	token := sessions.Issue(operatorAddr)
	store := newFakeStore()
	submissionLog := &fakeLog{}

	exerciseStore := exercise.NewFileStore(filepath.Join(t.TempDir(), "exercise.json")) // never Set
	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))

	handler := &SubmitHandler{
		Sessions: sessions,
		Store:    store,
		Log:      submissionLog,
		Exercise: exerciseStore,
		Scores:   scoresStore,
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	archive := buildValidArchive(t, operatorAddr.String())
	body, contentType := multipartUpload(t, "samourai-20260709-1830UTC.tar.gz", archive)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (an unconfigured exercise must not block submission)", resp.StatusCode)
	}

	submissionLog.mu.Lock()
	id := submissionLog.entries[0].ID
	submissionLog.mu.Unlock()

	result, ok, err := scoresStore.Get(id)
	if err != nil {
		t.Fatalf("scoresStore.Get: %v", err)
	}
	if !ok {
		t.Fatal("expected a placeholder scoring record even with no exercise configured")
	}
	if result.Scored {
		t.Error("Scored = true, want false when the exercise wasn't configured at submit time")
	}
}
```

Add the new imports these tests need at the top of `portal/submit_test.go`: `"errors"`, `"path/filepath"`, and `"github.com/samourai/validator-diagnostics/clamav"`, `"github.com/samourai/validator-diagnostics/exercise"`, `"github.com/samourai/validator-diagnostics/scoring"`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./portal/... -run TestSubmitHandler`
Expected: FAIL — `unknown field AVScanner in struct literal` (and similarly for `Exercise`/`Scores`)

- [ ] **Step 3: Update the implementation**

In `portal/submit.go`, update the imports:

```go
import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/samourai/validator-diagnostics/auth"
	"github.com/samourai/validator-diagnostics/clamav"
	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/scoring"
	"github.com/samourai/validator-diagnostics/storage"
	"github.com/samourai/validator-diagnostics/submission"
)
```

Update the `SubmitHandler` struct:

```go
// SubmitHandler serves POST /submit: a multipart upload of the fire
// drill archive, authenticated via the session token minted by
// /auth/verify.
type SubmitHandler struct {
	Sessions *auth.SessionSigner
	Store    storage.Store

	// Log records successful submissions for the admin dashboard.
	// Optional — a nil Log disables recording.
	Log Log

	// AVScanner scans uploaded archives for malware before they're
	// stored (prd.md, "Security Considerations" — ClamAV defense in
	// depth). A nil AVScanner disables scanning; cmd/portal always
	// wires clamav.NoopScanner explicitly instead of leaving this nil,
	// so nil only shows up in tests that don't care about the AV step.
	AVScanner clamav.Scanner

	// Exercise and Scores wire in the Phase 3 automatic checks and
	// scoring (see the scoring package). A nil Exercise disables
	// scoring entirely, same convention as Log.
	Exercise *exercise.FileStore
	Scores   *scoring.Store

	// ArchiveOptions bounds ValidateArchive's per-entry reads. Zero
	// value uses submission's own defaults.
	ArchiveOptions submission.Options

	// MaxUploadSize caps the whole request body. Zero uses
	// defaultMaxUploadSize.
	MaxUploadSize int64
}
```

Replace the body of `ServeHTTP` from the `submission.ValidateArchive` call onward (renaming the local `result` variable to `archiveResult` throughout, to free up `result` for the new `scoring.Result`, and inserting the AV scan + scoring steps before `Store.Save`):

```go
	// file (a multipart.File) is always Seek-able, whether Go held it
	// in memory or spilled it to a temp file above — so ValidateArchive,
	// the AV scan, and Store.Save can each take their own full pass
	// over it without us buffering a second copy ourselves.
	archiveResult, err := submission.ValidateArchive(r.Context(), file, h.ArchiveOptions)
	if err != nil {
		writeSubmitResult(w, http.StatusBadRequest, submitResponse{Error: err.Error()})
		return
	}

	metadata, err := submission.ValidateMetadata(archiveResult.Metadata)
	if err != nil {
		writeSubmitResult(w, http.StatusBadRequest, submitResponse{Error: err.Error()})
		return
	}

	// The whole point of the challenge-tx auth is proving ownership of
	// the operator address (prd.md, "Authentication" — "proving
	// ownership of the validator identity"); a mismatch here means
	// metadata.json's claimed identity isn't backed by that proof.
	if metadata.ValidatorAddress != operatorAddr.String() {
		writeSubmitResult(w, http.StatusForbidden, submitResponse{
			Error: "metadata.json validator_address does not match the authenticated operator address",
		})
		return
	}
	if metadata.Moniker != moniker {
		writeSubmitResult(w, http.StatusBadRequest, submitResponse{
			Error: "metadata.json moniker does not match the archive filename",
		})
		return
	}

	if h.AVScanner != nil {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			writeSubmitResult(w, http.StatusInternalServerError, submitResponse{Error: "unable to rewind upload"})
			return
		}
		verdict, err := h.AVScanner.Scan(r.Context(), file)
		if err != nil {
			log.Printf("antivirus scan for %s failed: %v", header.Filename, err)
			writeSubmitResult(w, http.StatusServiceUnavailable, submitResponse{
				Error: "antivirus scan unavailable, please try again shortly",
			})
			return
		}
		if verdict.Infected {
			writeSubmitResult(w, http.StatusUnprocessableEntity, submitResponse{
				Error: fmt.Sprintf("archive rejected: malware detected (%s)", verdict.Signature),
			})
			return
		}
	}

	submissionID, err := NewSubmissionID()
	if err != nil {
		writeSubmitResult(w, http.StatusInternalServerError, submitResponse{Error: "unable to prepare submission record"})
		return
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		writeSubmitResult(w, http.StatusInternalServerError, submitResponse{Error: "unable to rewind upload"})
		return
	}

	if err := h.Store.Save(r.Context(), header.Filename, file, header.Size); err != nil {
		writeSubmitResult(w, http.StatusInternalServerError, submitResponse{Error: "unable to store archive"})
		return
	}

	if h.Exercise != nil {
		cfg, err := h.Exercise.Get()
		if err != nil {
			log.Printf("scoring: unable to read exercise config for %s: %v", header.Filename, err)
		} else {
			result := scoring.Result{SubmissionID: submissionID}
			if cfg.Configured() {
				genesisMatch, versionSupported, window := scoring.AutoChecks(metadata, archiveResult.LogGz, cfg)
				result.Scored = true
				result.GenesisMatch = genesisMatch
				result.VersionSupported = versionSupported
				result.LogWindow = window
				result.UploadTimeScore = scoring.TieredTimeScore(time.Now().UTC(), cfg)
				// Always 20: ValidateMetadata above already gated this
				// submission on a schema-valid metadata.json, so by the
				// time a Result exists at all, this criterion is
				// structurally satisfied — see scoring.LogQualityScore's
				// doc comment for the analogous reasoning on log quality.
				result.MetadataScore = 20
				result.LogQualityScore = scoring.LogQualityScore(window)
			}
			if h.Scores != nil {
				if err := h.Scores.Set(result); err != nil {
					log.Printf("scoring: unable to record result for %s: %v", header.Filename, err)
				}
			}
		}
	}

	if h.Log != nil {
		entry := Entry{
			ID:              submissionID,
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

	writeSubmitResult(w, http.StatusOK, submitResponse{
		OK:          true,
		Moniker:     moniker,
		SubmittedAt: submittedAt.UTC().Format("2006-01-02T15:04Z"),
	})
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./portal/...`
Expected: PASS — the full `portal` package, including every pre-existing `TestSubmitHandler_*` test (they don't set `AVScanner`/`Exercise`, so those steps are skipped, matching the "nil disables" contract).

- [ ] **Step 5: Commit**

```bash
git add portal/submit.go portal/submit_test.go
git commit -m "Wire ClamAV scanning and Phase 3 auto-scoring into SubmitHandler"
```

---

### Task 12: `portal.AdminScoreHandler`

**Files:**
- Create: `portal/score.go`
- Test: `portal/score_test.go`

**Interfaces:**
- Consumes: `*FileLog`, `Entry` (existing), `*exercise.FileStore` (Task 2), `*scoring.Store`/`Result`/`TieredTimeScore` (Tasks 5, 7).
- Produces: `portal.AdminScoreHandler(log *FileLog, exerciseStore *exercise.FileStore, scores *scoring.Store) http.HandlerFunc`, registered by the caller as `POST /admin/submissions/{id}/score` (Go 1.22+ `net/http.ServeMux` pattern routing, reading the ID via `r.PathValue("id")`).

- [ ] **Step 1: Write the failing tests**

```go
// portal/score_test.go
package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
		"acknowledged_at":                  time.Now().UTC().Format(time.RFC3339),
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

func TestAdminScoreHandler_RejectsOutOfRangeScore(t *testing.T) {
	cfg := exercise.Config{
		AnnouncedAt: time.Now().UTC().Add(-time.Hour),
		DeadlineAt:  time.Now().UTC().Add(time.Hour),
	}
	srv, _ := newTestScoreServer(t, "entry-1", cfg)

	body, _ := json.Marshal(map[string]any{
		"acknowledged_at":                  time.Now().UTC().Format(time.RFC3339),
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

func TestAdminScoreHandler_RejectsUnknownID(t *testing.T) {
	cfg := exercise.Config{
		AnnouncedAt: time.Now().UTC().Add(-time.Hour),
		DeadlineAt:  time.Now().UTC().Add(time.Hour),
	}
	srv, _ := newTestScoreServer(t, "entry-1", cfg)

	body, _ := json.Marshal(map[string]any{
		"acknowledged_at":                  time.Now().UTC().Format(time.RFC3339),
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
		"acknowledged_at":                  time.Now().UTC().Format(time.RFC3339),
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./portal/... -run AdminScoreHandler`
Expected: FAIL — `undefined: AdminScoreHandler`

- [ ] **Step 3: Write the implementation**

```go
// portal/score.go
package portal

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/scoring"
)

type scoreRequest struct {
	AcknowledgedAt               string `json:"acknowledged_at"`
	IncidentResponseQualityScore int    `json:"incident_response_quality_score"`
}

// AdminScoreHandler serves POST /admin/submissions/{id}/score: the
// admin's manual entry for the two rubric criteria that can't be
// computed automatically (prd.md "Evaluation Criteria" —
// acknowledgement time and incident response quality). Register with
// the "POST /admin/submissions/{id}/score" mux pattern so {id} is
// available via r.PathValue("id"); wrap with AdminAuth.
func AdminScoreHandler(log *FileLog, exerciseStore *exercise.FileStore, scores *scoring.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing submission id", http.StatusBadRequest)
			return
		}

		var req scoreRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.IncidentResponseQualityScore < 0 || req.IncidentResponseQualityScore > 20 {
			http.Error(w, "incident_response_quality_score must be between 0 and 20", http.StatusBadRequest)
			return
		}
		ackAt, err := time.Parse(time.RFC3339, req.AcknowledgedAt)
		if err != nil {
			http.Error(w, "acknowledged_at must be an RFC3339 timestamp", http.StatusBadRequest)
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

		cfg, err := exerciseStore.Get()
		if err != nil {
			http.Error(w, "unable to read exercise config", http.StatusInternalServerError)
			return
		}
		if !cfg.Configured() {
			http.Error(w, "exercise is not configured yet", http.StatusBadRequest)
			return
		}

		result, _, err := scores.Get(id)
		if err != nil {
			http.Error(w, "unable to read scoring record", http.StatusInternalServerError)
			return
		}
		result.SubmissionID = id
		result.AcknowledgedAt = &ackAt
		ackScore := scoring.TieredTimeScore(ackAt, cfg)
		result.AckTimeScore = &ackScore
		irq := req.IncidentResponseQualityScore
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

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./portal/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add portal/score.go portal/score_test.go
git commit -m "Add AdminScoreHandler for POST /admin/submissions/{id}/score"
```

---

### Task 13: Join `Entry` + `scoring.Result` in `AdminSubmissionsHandler`

**Files:**
- Modify: `portal/admin.go`
- Modify: `portal/admin_test.go`
- Modify: `cmd/portal/main.go:84` (call site — update in this task since the signature changes; full flag/routing wiring happens in Task 15)

**Interfaces:**
- Consumes: `*scoring.Store`/`Result` (Task 7).
- Produces: `AdminSubmissionsHandler(log *FileLog, scores *scoring.Store) http.HandlerFunc` (signature change from the current `AdminSubmissionsHandler(log *FileLog)`); new `AdminSubmission` struct (`Entry`; `Score *scoring.Result`).

- [ ] **Step 1: Write the failing test**

Update `TestAdminSubmissionsHandler` in `portal/admin_test.go` to pass a `scoring.Store` and assert the joined shape:

```go
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
```

Add `"github.com/samourai/validator-diagnostics/scoring"` to the imports at the top of `portal/admin_test.go`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./portal/... -run AdminSubmissionsHandler`
Expected: FAIL — signature mismatch, `undefined: AdminSubmission`

- [ ] **Step 3: Update the implementation**

In `portal/admin.go`, update imports and add the new type, then change `AdminSubmissionsHandler`:

```go
package portal

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"github.com/samourai/validator-diagnostics/scoring"
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

// AdminSubmission is one row of the admin dashboard: a recorded
// submission joined with its Phase 3 scoring record, if one exists yet
// (Score is nil before a submission has been auto-scored — see
// SubmitHandler's Exercise/Scores wiring).
type AdminSubmission struct {
	Entry
	Score *scoring.Result `json:"score,omitempty"`
}

// AdminSubmissionsHandler serves the recorded submissions, joined with
// their scoring records, as a JSON array. Wrap it with AdminAuth.
func AdminSubmissionsHandler(log *FileLog, scores *scoring.Store) http.HandlerFunc {
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

		out := make([]AdminSubmission, 0, len(entries))
		for _, e := range entries {
			sub := AdminSubmission{Entry: e}
			if result, ok, err := scores.Get(e.ID); err == nil && ok {
				sub.Score = &result
			}
			out = append(out, sub)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}
```

In `cmd/portal/main.go`, update the call site (line 84) to pass a `scoring.Store` — a full `scoresStore` variable is introduced properly in Task 15, so for now just pass `scoring.NewStore(*logPath + ".scores.json")` inline to keep the build green:

```go
	mux.Handle("/admin/submissions", portal.AdminAuth(adminPassword, portal.AdminSubmissionsHandler(submissionLog, scoring.NewStore(*logPath+".scores.json"))))
```

Add `"github.com/samourai/validator-diagnostics/scoring"` to `cmd/portal/main.go`'s imports.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go build ./... && go test ./...`
Expected: PASS across the whole module

- [ ] **Step 5: Commit**

```bash
git add portal/admin.go portal/admin_test.go cmd/portal/main.go
git commit -m "Join scoring.Result into AdminSubmissionsHandler's response"
```

---

### Task 14: `portal.AdminSummaryHandler`

**Files:**
- Create: `portal/summary.go`
- Test: `portal/summary_test.go`

**Interfaces:**
- Consumes: `*FileLog`, `*exercise.FileStore`, `*scoring.Store` (existing/Tasks 2, 7).
- Produces: `portal.AdminSummaryHandler(log *FileLog, exerciseStore *exercise.FileStore, scores *scoring.Store) http.HandlerFunc`, serving `GET /admin/summary` as `text/markdown`.

- [ ] **Step 1: Write the failing tests**

```go
// portal/summary_test.go
package portal

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/scoring"
)

func TestAdminSummaryHandler(t *testing.T) {
	submissionLog := NewFileLog(filepath.Join(t.TempDir(), "submissions.jsonl"))
	if err := submissionLog.Record(context.Background(), Entry{
		ID:              "scored-1",
		Moniker:         "samourai",
		OperatorAddress: "g1abc",
		Filename:        "samourai-20260709-1830UTC.tar.gz",
		SubmittedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := submissionLog.Record(context.Background(), Entry{
		ID:              "unscored-1",
		Moniker:         "other",
		OperatorAddress: "g1def",
		Filename:        "other-20260709-1830UTC.tar.gz",
		SubmittedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	exerciseStore := exercise.NewFileStore(filepath.Join(t.TempDir(), "exercise.json"))
	if err := exerciseStore.Set(exercise.Config{
		AnnouncedAt:              time.Now().UTC().Add(-2 * time.Hour),
		DeadlineAt:               time.Now().UTC().Add(2 * time.Hour),
		InvestigationWindowStart: time.Now().UTC().Add(-24 * time.Hour),
		InvestigationWindowEnd:   time.Now().UTC(),
		Observations:             "Everyone please double-check log rotation settings.",
	}); err != nil {
		t.Fatalf("exerciseStore.Set: %v", err)
	}

	scoresStore := scoring.NewStore(filepath.Join(t.TempDir(), "scores.json"))
	if err := scoresStore.Set(scoring.Result{
		SubmissionID:     "scored-1",
		Scored:           true,
		GenesisMatch:     false,
		VersionSupported: true,
		LogWindow:        scoring.LogWindowCheck{Detected: true, Covered: true},
		UploadTimeScore:  20,
		MetadataScore:    20,
		LogQualityScore:  20,
	}); err != nil {
		t.Fatalf("scoresStore.Set: %v", err)
	}

	srv := httptest.NewServer(AdminSummaryHandler(submissionLog, exerciseStore, scoresStore))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	text := string(body)

	for _, want := range []string{
		"2 submission",                              // participation count
		"samourai",                                  // scored entry's moniker
		"other",                                     // unscored entry's moniker
		"not yet scored",                            // unscored entry's status
		"genesis_sha256 does not match",             // warning for the mismatched genesis
		"Everyone please double-check log rotation", // free-text observations
	} {
		if !strings.Contains(text, want) {
			t.Errorf("summary text missing %q; got:\n%s", want, text)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./portal/... -run AdminSummaryHandler`
Expected: FAIL — `undefined: AdminSummaryHandler`

- [ ] **Step 3: Write the implementation**

```go
// portal/summary.go
package portal

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/scoring"
)

// AdminSummaryHandler serves GET /admin/summary: a Markdown-formatted
// report — participation, per-submission status and score, validation
// warnings, and free-text observations — matching what prd.md's Phase
// 3 asks to be "published on Discord (or another communication
// channel)". Publishing itself stays a manual admin action; this only
// generates the text. Wrap with AdminAuth.
func AdminSummaryHandler(log *FileLog, exerciseStore *exercise.FileStore, scores *scoring.Store) http.HandlerFunc {
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
		cfg, err := exerciseStore.Get()
		if err != nil {
			http.Error(w, "unable to read exercise config", http.StatusInternalServerError)
			return
		}

		sort.Slice(entries, func(i, j int) bool { return entries[i].Moniker < entries[j].Moniker })

		var b strings.Builder
		b.WriteString("## Validator Fire Drill — Summary\n\n")
		fmt.Fprintf(&b, "**Participation:** %d submission(s)\n\n", len(entries))

		for _, e := range entries {
			result, ok, err := scores.Get(e.ID)
			if err != nil {
				http.Error(w, "unable to read scoring record", http.StatusInternalServerError)
				return
			}

			fmt.Fprintf(&b, "- **%s** (%s) — ", e.Moniker, e.OperatorAddress)
			if !ok || !result.Scored {
				b.WriteString("not yet scored\n")
				continue
			}

			fmt.Fprintf(&b, "%d/100\n", result.TotalScore())
			if !result.GenesisMatch {
				b.WriteString("  - ⚠️ genesis_sha256 does not match the expected value\n")
			}
			if !result.VersionSupported {
				b.WriteString("  - ⚠️ gnoland_version is not in the supported list\n")
			}
			switch {
			case !result.LogWindow.Detected:
				b.WriteString("  - ⚠️ no recognizable timestamps found in gnoland.log.gz\n")
			case !result.LogWindow.Covered:
				b.WriteString("  - ⚠️ logs do not fully cover the investigation window\n")
			}
		}

		if cfg.Observations != "" {
			fmt.Fprintf(&b, "\n**Observations:**\n\n%s\n", cfg.Observations)
		}

		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write([]byte(b.String()))
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./portal/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add portal/summary.go portal/summary_test.go
git commit -m "Add AdminSummaryHandler for GET /admin/summary"
```

---

### Task 15: Wire everything into `cmd/portal/main.go`

**Files:**
- Modify: `cmd/portal/main.go`

**Interfaces:**
- Consumes: everything from Tasks 1-14.
- Produces: new flags `-exercise-path` (default `./exercise.json`), `-scores-path` (default `./scores.json`), `-clamav-addr` (optional); routes `/admin/exercise`, `POST /admin/submissions/{id}/score`, `/admin/summary`, all wrapped in the existing `portal.AdminAuth`.

- [ ] **Step 1: Update the flags and imports**

Replace the import block:

```go
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
	"github.com/samourai/validator-diagnostics/clamav"
	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/portal"
	"github.com/samourai/validator-diagnostics/scoring"
	"github.com/samourai/validator-diagnostics/storage"
)
```

Add new flags after `logPath` in `main()`:

```go
	logPath := flag.String("log-path", "./submissions.jsonl", "path to the submission log file, read by the admin dashboard")
	exercisePath := flag.String("exercise-path", "./exercise.json", "path to the Phase 3 exercise config file, managed via POST /admin/exercise")
	scoresPath := flag.String("scores-path", "./scores.json", "path to the Phase 3 scoring records file")
	clamavAddr := flag.String("clamav-addr", "", "clamd address to scan uploads against (host:port, or unix:/path/to/socket); leave empty to disable AV scanning (NOT recommended for production)")
	flag.Parse()
```

- [ ] **Step 2: Wire the new stores, scanner, and routes**

Replace the block from `nonces := auth.NewNonceStore()` through the `mux.Handle("/admin/submissions", ...)` line with:

```go
	nonces := auth.NewNonceStore()
	verifier := &auth.Verifier{Remote: *remote, Nonces: nonces}
	submissionLog := portal.NewFileLog(*logPath)
	exerciseStore := exercise.NewFileStore(*exercisePath)
	scoresStore := scoring.NewStore(*scoresPath)

	var avScanner clamav.Scanner = clamav.NoopScanner{}
	if *clamavAddr != "" {
		avScanner = clamav.ClamdScanner{Addr: *clamavAddr}
	} else {
		log.Println("-clamav-addr not set: uploads will NOT be scanned for malware (fine for local dev, not for production)")
	}

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("unable to load embedded static assets: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/challenge", auth.ChallengeHandler(nonces))
	mux.Handle("/auth/verify", auth.VerifyHandler(verifier, sessions))
	mux.Handle("/submit", &portal.SubmitHandler{
		Sessions:  sessions,
		Store:     store,
		Log:       submissionLog,
		AVScanner: avScanner,
		Exercise:  exerciseStore,
		Scores:    scoresStore,
	})
	mux.Handle("/admin", portal.AdminAuth(adminPassword, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, staticFS, "admin.html")
	})))
	mux.Handle("/admin/submissions", portal.AdminAuth(adminPassword, portal.AdminSubmissionsHandler(submissionLog, scoresStore)))
	mux.Handle("/admin/exercise", portal.AdminAuth(adminPassword, exercise.ConfigHandler(exerciseStore)))
	mux.Handle("POST /admin/submissions/{id}/score", portal.AdminAuth(adminPassword, portal.AdminScoreHandler(submissionLog, exerciseStore, scoresStore)))
	mux.Handle("/admin/summary", portal.AdminAuth(adminPassword, portal.AdminSummaryHandler(submissionLog, exerciseStore, scoresStore)))
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
```

(This replaces Task 13's temporary inline `scoring.NewStore(*logPath+".scores.json")` call site with the properly wired `scoresStore` variable.)

- [ ] **Step 3: Build and smoke-test manually**

```bash
export PATH="/usr/local/go/bin:$PATH"
go build ./...
```
Expected: builds cleanly.

```bash
ADMIN_PASSWORD=test go run ./cmd/portal -remote https://rpc.topaz.testnets.gno.land -addr localhost:8080 -upload-dir /tmp/fire-drill-uploads &
sleep 1
curl -s -u any:test http://localhost:8080/admin/exercise
curl -s -u any:test -X POST http://localhost:8080/admin/exercise -d '{"announced_at":"2026-07-08T18:00:00Z","deadline_at":"2026-07-09T19:30:00Z","investigation_window_start":"2026-07-08T18:00:00Z","investigation_window_end":"2026-07-09T18:30:00Z","expected_genesis_sha256":"deadbeef","supported_gnoland_versions":["v1.0.0"]}'
curl -s -u any:test http://localhost:8080/admin/summary
kill %1
```
Expected: first `curl` returns the zero config (`"announced_at":"0001-01-01T00:00:00Z"`, etc.); the `POST` returns the same config back; `/admin/summary` returns `## Validator Fire Drill — Summary` with `**Participation:** 0 submission(s)`.

- [ ] **Step 4: Run the full test suite**

Run: `go vet ./... && go test ./...`
Expected: PASS across the whole module.

- [ ] **Step 5: Commit**

```bash
git add cmd/portal/main.go
git commit -m "Wire exercise config, scoring, and ClamAV scanning into cmd/portal"
```

---

### Task 16: ClamAV service in `docker-compose.yml`

**Files:**
- Modify: `docker-compose.yml`
- Modify: `.env.example`
- Modify: `docs/superpowers/plans/2026-07-29-docker-compose-quickstart.md` is NOT modified (historical plan; leave as-is) — instead update `README.md`'s Docker section if it documents the service list (check first; add a one-line mention of the `clamav` service if it does).

**Interfaces:**
- Produces: a `clamav` service reachable at `clamd:3310` on the compose network; `portal`'s `command:` gains `-clamav-addr=clamd:3310`.

- [ ] **Step 1: Add the `clamav` service to `docker-compose.yml`**

Add a new service (alongside `minio`/`minio-init`), and update `portal`'s `depends_on` and `command`:

```yaml
services:
  clamav:
    image: clamav/clamav:stable
    volumes:
      - clamav-data:/var/lib/clamav
    healthcheck:
      test: ["CMD", "clamdcheck.sh"]
      interval: 30s
      timeout: 10s
      retries: 10
      start_period: 120s # first boot downloads the virus database

  minio:
    image: minio/minio:latest
    command: server /data --address ":9001" --console-address ":9002"
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
    volumes:
      - minio-data:/data

  minio-init:
    image: minio/mc:latest
    depends_on:
      - minio
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
      S3_BUCKET: ${S3_BUCKET:-submissions}
    entrypoint: >
      sh -c "
      until mc alias set local http://minio:9001 \"$$MINIO_ROOT_USER\" \"$$MINIO_ROOT_PASSWORD\"; do sleep 1; done &&
      mc mb --ignore-existing local/$$S3_BUCKET
      "

  portal:
    build:
      context: .
      dockerfile: Dockerfile
    depends_on:
      minio-init:
        condition: service_completed_successfully
      clamav:
        condition: service_healthy
    environment:
      ADMIN_PASSWORD: ${ADMIN_PASSWORD}
      SESSION_SECRET: ${SESSION_SECRET:-}
      S3_ACCESS_KEY: ${MINIO_ROOT_USER}
      S3_SECRET_KEY: ${MINIO_ROOT_PASSWORD}
    command:
      - -remote=${REMOTE}
      - -addr=0.0.0.0:8888
      - -s3-bucket=${S3_BUCKET:-submissions}
      - -s3-region=us-east-1
      - -s3-endpoint=http://minio:9001
      - -log-path=/data/submissions.jsonl
      - -exercise-path=/data/exercise.json
      - -scores-path=/data/scores.json
      - -clamav-addr=clamav:3310
    volumes:
      - portal-logs:/data
    ports:
      - "${PORTAL_PORT:-8080}:8888"

volumes:
  minio-data:
  portal-logs:
  clamav-data:
```

- [ ] **Step 2: Note the startup delay in `.env.example`**

Add a comment near the top of `.env.example` (no new variable needed — `clamav` requires no configuration):

```
# Note: `docker compose up` on a fresh volume takes ~1-2 extra minutes
# the first time, while the clamav service downloads its virus
# database (clamav-data volume caches it for subsequent starts).
```

- [ ] **Step 3: Bring the stack up and verify the AV path end to end**

```bash
docker compose up --build
```

Expected: `clamav` takes noticeably longer than the other services to report healthy on a first run (database download); once healthy, `portal` starts and logs do NOT include the "-clamav-addr not set" warning from Task 15.

Then, in another terminal, confirm scanning actually runs by uploading the standard EICAR test archive (a `.tar.gz` built the same way `buildValidArchive` does in `portal/submit_test.go`, but with EICAR's test string as `gnoland.log.gz`'s content) through the full auth+upload flow via the web UI at `http://localhost:8080/` — expect the submission to be rejected with a "malware detected" error. (This doubles as the Task 9 manual smoke test, now exercised through the full stack rather than `ClamdScanner` directly.)

- [ ] **Step 4: Tear down**

```bash
docker compose down
```

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml .env.example
git commit -m "Add ClamAV service to the docker-compose stack"
```

---

### Task 17: Admin frontend — exercise config form

**Files:**
- Modify: `cmd/portal/static/admin.html`
- Modify: `cmd/portal/static/admin.js`

**Interfaces:**
- Consumes: `GET`/`POST /admin/exercise` (Task 3).
- Produces: a form on the admin page to view and update the exercise config.

- [ ] **Step 1: Add the form markup**

In `cmd/portal/static/admin.html`, insert a new `<section>` right after the `</header>` closing tag and before `<table id="submissions">`:

```html
<section id="exercise-config" class="step">
  <h2>Exercise configuration</h2>
  <label for="ex-announced-at">Announced at (UTC, e.g. 2026-07-08T18:00:00Z)</label>
  <input type="text" id="ex-announced-at" placeholder="2026-07-08T18:00:00Z">
  <label for="ex-deadline-at">Deadline at (UTC)</label>
  <input type="text" id="ex-deadline-at" placeholder="2026-07-09T19:30:00Z">
  <label for="ex-window-start">Investigation window start (UTC)</label>
  <input type="text" id="ex-window-start" placeholder="2026-07-08T18:00:00Z">
  <label for="ex-window-end">Investigation window end (UTC)</label>
  <input type="text" id="ex-window-end" placeholder="2026-07-09T18:30:00Z">
  <label for="ex-genesis">Expected genesis SHA256</label>
  <input type="text" id="ex-genesis" placeholder="deadbeef...">
  <label for="ex-versions">Supported gnoland versions (comma-separated)</label>
  <input type="text" id="ex-versions" placeholder="v1.0.0, v1.0.1">
  <label for="ex-observations">Observations (included in the generated summary)</label>
  <input type="text" id="ex-observations" placeholder="">
  <button id="save-exercise">Save exercise config</button>
  <p class="error" id="exercise-error"></p>
  <p class="success" id="exercise-saved" hidden>Saved.</p>
</section>
```

- [ ] **Step 2: Add the JS wiring**

Append to `cmd/portal/static/admin.js`:

```javascript
async function loadExerciseConfig() {
  let resp;
  try {
    resp = await fetch("/admin/exercise");
  } catch (err) {
    document.getElementById("exercise-error").textContent = "Network error: " + err.message;
    return;
  }
  if (!resp.ok) return;

  const cfg = await resp.json();
  const setIfPresent = (id, value) => {
    if (value) document.getElementById(id).value = value;
  };
  setIfPresent("ex-announced-at", cfg.announced_at?.startsWith("0001") ? "" : cfg.announced_at);
  setIfPresent("ex-deadline-at", cfg.deadline_at?.startsWith("0001") ? "" : cfg.deadline_at);
  setIfPresent("ex-window-start", cfg.investigation_window_start?.startsWith("0001") ? "" : cfg.investigation_window_start);
  setIfPresent("ex-window-end", cfg.investigation_window_end?.startsWith("0001") ? "" : cfg.investigation_window_end);
  setIfPresent("ex-genesis", cfg.expected_genesis_sha256);
  setIfPresent("ex-versions", (cfg.supported_gnoland_versions || []).join(", "));
  setIfPresent("ex-observations", cfg.observations);
}

document.getElementById("save-exercise").addEventListener("click", async () => {
  document.getElementById("exercise-error").textContent = "";
  document.getElementById("exercise-saved").hidden = true;

  const body = {
    announced_at: document.getElementById("ex-announced-at").value.trim(),
    deadline_at: document.getElementById("ex-deadline-at").value.trim(),
    investigation_window_start: document.getElementById("ex-window-start").value.trim(),
    investigation_window_end: document.getElementById("ex-window-end").value.trim(),
    expected_genesis_sha256: document.getElementById("ex-genesis").value.trim(),
    supported_gnoland_versions: document
      .getElementById("ex-versions")
      .value.split(",")
      .map((v) => v.trim())
      .filter(Boolean),
    observations: document.getElementById("ex-observations").value,
  };

  let resp;
  try {
    resp = await fetch("/admin/exercise", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (err) {
    document.getElementById("exercise-error").textContent = "Network error: " + err.message;
    return;
  }

  if (!resp.ok) {
    const text = await resp.text();
    document.getElementById("exercise-error").textContent = text || "Unable to save exercise config.";
    return;
  }

  document.getElementById("exercise-saved").hidden = false;
});

loadExerciseConfig();
```

- [ ] **Step 3: Manual verification in a browser**

```bash
export PATH="/usr/local/go/bin:$PATH"
ADMIN_PASSWORD=test go run ./cmd/portal -remote https://rpc.topaz.testnets.gno.land -addr localhost:8080 -upload-dir /tmp/fire-drill-uploads
```

Open `http://localhost:8080/admin` (Basic Auth: any username, password `test`) in a browser. Verify:
- The exercise config section renders with empty fields (no exercise configured yet).
- Filling in all fields and clicking "Save exercise config" shows the "Saved." message.
- Reloading the page repopulates the fields with the saved values.
- Submitting an obviously invalid config (e.g. deadline before announced) shows the server's error text in `#exercise-error`.

- [ ] **Step 4: Commit**

```bash
git add cmd/portal/static/admin.html cmd/portal/static/admin.js
git commit -m "Add exercise config form to the admin dashboard"
```

---

### Task 18: Admin frontend — score columns, badges, and manual score entry

**Files:**
- Modify: `cmd/portal/static/admin.html`
- Modify: `cmd/portal/static/admin.js`
- Modify: `cmd/portal/static/portal.css`

**Interfaces:**
- Consumes: the joined `AdminSubmission` shape from `GET /admin/submissions` (Task 13), `POST /admin/submissions/{id}/score` (Task 12).
- Produces: extra table columns (total score, genesis/version/log-window badges) and a per-row "Score" action opening a small inline form for the two manual fields.

- [ ] **Step 1: Extend the table markup**

In `cmd/portal/static/admin.html`, update the `<thead>` row:

```html
<thead>
  <tr><th>Moniker</th><th>Operator address</th><th>Filename</th><th>Submitted at (UTC)</th><th>Score</th><th>Checks</th><th>Ack / Incident response</th></tr>
</thead>
```

- [ ] **Step 2: Add CSS for the badges**

Append to `cmd/portal/static/portal.css`:

```css
.badge {
  display: inline-block;
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  margin-right: 0.25rem;
}

.badge-ok {
  background: var(--green-600);
  color: #ffffff;
}

.badge-warn {
  background: var(--red-600);
  color: #ffffff;
}

.score-form input {
  width: 3.5rem;
  display: inline-block;
  margin: 0 0.25rem;
}
```

- [ ] **Step 3: Rewrite `refresh()` and add the score-submission handler**

Replace the body of `refresh()` in `cmd/portal/static/admin.js` (the function from Task-0 code, i.e. the file as it exists before this task):

```javascript
function badge(ok, okText, warnText) {
  const span = document.createElement("span");
  span.className = "badge " + (ok ? "badge-ok" : "badge-warn");
  span.textContent = ok ? okText : warnText;
  return span;
}

function buildScoreForm(id) {
  const form = document.createElement("span");
  form.className = "score-form";

  const ackInput = document.createElement("input");
  ackInput.type = "text";
  ackInput.placeholder = "ack RFC3339";

  const irqInput = document.createElement("input");
  irqInput.type = "number";
  irqInput.min = "0";
  irqInput.max = "20";
  irqInput.placeholder = "0-20";

  const button = document.createElement("button");
  button.textContent = "Save";
  button.addEventListener("click", async () => {
    let resp;
    try {
      resp = await fetch(`/admin/submissions/${id}/score`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          acknowledged_at: ackInput.value.trim(),
          incident_response_quality_score: Number(irqInput.value),
        }),
      });
    } catch (err) {
      document.getElementById("admin-error").textContent = "Network error: " + err.message;
      return;
    }
    if (!resp.ok) {
      document.getElementById("admin-error").textContent = await resp.text();
      return;
    }
    document.getElementById("admin-error").textContent = "";
    refresh();
  });

  form.append(ackInput, irqInput, button);
  return form;
}

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

  const submissions = await resp.json();
  const tbody = document.querySelector("#submissions tbody");
  tbody.innerHTML = "";
  for (const s of submissions) {
    const row = document.createElement("tr");

    for (const value of [s.moniker, s.operator_address, s.filename, s.submitted_at]) {
      const cell = document.createElement("td");
      cell.textContent = value; // never innerHTML — these are validator-controlled strings
      row.appendChild(cell);
    }

    const scoreCell = document.createElement("td");
    scoreCell.textContent = s.score && s.score.scored ? `${s.score.upload_time_score + s.score.metadata_score + s.score.log_quality_score + (s.score.ack_time_score || 0) + (s.score.incident_response_quality_score || 0)}/100` : "pending";
    row.appendChild(scoreCell);

    const checksCell = document.createElement("td");
    if (s.score && s.score.scored) {
      checksCell.append(
        badge(s.score.genesis_match, "genesis ✓", "genesis ✗"),
        badge(s.score.version_supported, "version ✓", "version ✗"),
        badge(s.score.log_window.covered, "logs ✓", s.score.log_window.detected ? "logs partial" : "logs ✗"),
      );
    }
    row.appendChild(checksCell);

    const manualCell = document.createElement("td");
    manualCell.appendChild(buildScoreForm(s.id));
    row.appendChild(manualCell);

    tbody.appendChild(row);
  }
}

refresh();
setInterval(refresh, 5000);
```

- [ ] **Step 4: Manual verification in a browser**

With the portal running (see Task 17 Step 3) and at least one submission recorded (submit a valid archive through `http://localhost:8080/` first, or reuse fixtures from a prior manual test), open `http://localhost:8080/admin` and verify:
- The table shows a "Score" column ("pending" before an exercise is configured).
- After configuring the exercise (Task 17's form) and refreshing, the score and check badges populate.
- Entering an acknowledgement timestamp and incident response score in a row's form and clicking "Save" updates that row's total score on the next refresh (within 5s).
- Entering an out-of-range incident response score (e.g. `25`) surfaces the server's 400 error text.

- [ ] **Step 5: Commit**

```bash
git add cmd/portal/static/admin.html cmd/portal/static/admin.js cmd/portal/static/portal.css
git commit -m "Add score columns, check badges, and manual score entry to admin dashboard"
```

---

### Task 19: Admin frontend — generate summary view

**Files:**
- Modify: `cmd/portal/static/admin.html`
- Modify: `cmd/portal/static/admin.js`

**Interfaces:**
- Consumes: `GET /admin/summary` (Task 14).
- Produces: a button that fetches and displays the generated Markdown summary in a copyable `<pre>` block.

- [ ] **Step 1: Add the markup**

In `cmd/portal/static/admin.html`, add a new section after `</table>` and the existing `<p id="admin-error">`:

```html
<section id="summary-section" class="step">
  <h2>Summary</h2>
  <button id="generate-summary">Generate summary</button>
  <pre id="summary-output" hidden></pre>
</section>
```

- [ ] **Step 2: Add the JS wiring**

Append to `cmd/portal/static/admin.js`:

```javascript
document.getElementById("generate-summary").addEventListener("click", async () => {
  const output = document.getElementById("summary-output");
  let resp;
  try {
    resp = await fetch("/admin/summary");
  } catch (err) {
    document.getElementById("admin-error").textContent = "Network error: " + err.message;
    return;
  }
  if (!resp.ok) {
    document.getElementById("admin-error").textContent = "Unable to generate summary (status " + resp.status + ").";
    return;
  }
  document.getElementById("admin-error").textContent = "";
  output.textContent = await resp.text();
  output.hidden = false;
});
```

- [ ] **Step 3: Manual verification in a browser**

With the portal running and at least one submission recorded, open `http://localhost:8080/admin`, click "Generate summary", and verify the `<pre>` block shows the Markdown text (participation count, per-submission moniker + score/status, any warnings, and the observations text entered in Task 17's form) — confirm it reads as directly copy-pasteable into Discord.

- [ ] **Step 4: Commit**

```bash
git add cmd/portal/static/admin.html cmd/portal/static/admin.js
git commit -m "Add generated-summary view to admin dashboard"
```

---

## Self-Review Notes

- **Spec coverage:** `exercise.Config`/`FileStore`/`ConfigHandler` ✓ (Tasks 1-3); `submission.Result.LogGz` reuse ✓ (Task 4); tiered time formula + log quality formula ✓ (Task 5); genesis/version/log-window auto checks with bounded inner decompression ✓ (Task 6); `scoring.Result`/`TotalScore`/`Store` ✓ (Task 7); `clamav.Scanner`/`Verdict`/`NoopScanner` ✓ (Task 8); `ClamdScanner` INSTREAM client + fail-closed behavior ✓ (Task 9); `Entry.ID` ✓ (Task 10); `SubmitHandler` AV-scan + scoring wiring, fail-closed on scanner errors, "not yet scored" when exercise unconfigured ✓ (Task 11); `POST /admin/submissions/{id}/score` ✓ (Task 12); joined `AdminSubmissionsHandler` response ✓ (Task 13); `GET /admin/summary` ✓ (Task 14); `cmd/portal` flags/routing ✓ (Task 15); `docker-compose.yml` ClamAV service ✓ (Task 16); admin frontend (exercise form, score columns/badges, manual entry, summary view) ✓ (Tasks 17-19).
- **No placeholders:** every step has literal code, exact file paths, or literal commands with expected output; no "add appropriate handling"-style steps.
- **Type/naming consistency checked across tasks:** `exercise.Config` field names (`AnnouncedAt`, `DeadlineAt`, `InvestigationWindowStart/End`, `ExpectedGenesisSHA256`, `SupportedGnolandVersions`, `Observations`) are identical from Task 1 through Task 19's JS (snake_case JSON tags matching). `scoring.Result` field names (`Scored`, `GenesisMatch`, `VersionSupported`, `LogWindow`, `UploadTimeScore`, `MetadataScore`, `LogQualityScore`, `AcknowledgedAt`, `AckTimeScore`, `IncidentResponseQualityScore`) are consistent from Task 7 through Tasks 11-14 and the JS in Task 18. `clamav.Scanner`/`Verdict{Infected, Signature}` consistent from Task 8 through Task 11. `AdminSubmissionsHandler`'s signature change (Task 13) is reflected in its one call site in `cmd/portal/main.go`, itself superseded cleanly by Task 15's full rewrite of that section.
- **Note on scope:** per the spec's explicit user decision ("Inclure dans ce plan"), this plan intentionally bundles two subsystems that don't depend on each other (Phase 3 scoring, and ClamAV scanning) because they share one integration point (`SubmitHandler`) that's cheaper to modify once. Tasks 1-7 (exercise + scoring) and Tasks 8-9 (clamav) have no interdependency and could be executed in either order or in parallel; Task 11 is the only point where both threads converge.
