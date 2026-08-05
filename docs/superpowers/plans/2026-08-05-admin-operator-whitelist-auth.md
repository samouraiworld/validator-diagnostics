# Admin Auth — Operator Address Whitelist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the admin dashboard's single shared `ADMIN_PASSWORD` (HTTP Basic Auth) with the existing challenge-tx operator-key authentication, gated by a whitelist of admin operator addresses — so admins sign in the same way validators do, and every admin action is attributable to a real operator address.

**Architecture:** A new `portal.RequireAdminSession` middleware wraps every `/admin/*` route, checking a Bearer session token (via the existing `auth.RequireSession`) and then checking the bound operator address against an allowlist. `cmd/portal/main.go` gets a second, separate `auth.SessionSigner` (own secret, own — longer — TTL) for admin sessions, and a new `ADMIN_OPERATOR_ADDRESSES` env var. The frontend admin page gains a login screen that reuses the exact challenge/sign/verify flow already built for validator uploads (`cmd/portal/static/portal.js`), storing the resulting session token in memory and attaching it as `Authorization: Bearer` to every admin API call.

**Tech Stack:** Go 1.x standard library (`net/http`), `github.com/gnolang/gno/tm2/pkg/crypto` (bech32 address parsing, already a dependency), vanilla JS/CSS frontend (no framework).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-05-admin-operator-whitelist-auth-design.md`. Every task below implements a section of it — follow it for anything not spelled out here.
- No new dependencies. `auth.ChallengeHandler`, `auth.VerifyHandler`, `auth.SessionSigner`, and `auth.RequireSession` are reused as-is — this plan does not modify `auth/challenge.go`, `auth/session.go`, or `auth/http.go`.
- `ADMIN_OPERATOR_ADDRESSES` is required at startup (comma-separated bech32 addresses); an empty list or any invalid address is a fatal startup error — same posture as the `ADMIN_PASSWORD` check it replaces.
- `ADMIN_SESSION_SECRET` is optional, matching `SESSION_SECRET`'s existing behavior: a random secret is generated per run if unset, logged as a warning.
- Admin sessions use their own `auth.SessionSigner` (separate secret and TTL from the validator upload flow's), default TTL 1 hour via `--admin-session-ttl`, so restarting the portal or expiring one session type doesn't affect the other.
- `portal.AdminAuth` (HTTP Basic Auth) and `ADMIN_PASSWORD` are deleted, not kept as a fallback.
- This repo has no automated frontend tests — frontend changes are verified with a manual smoke test (end of Task 3), per this project's existing convention.
- Follow this repo's existing patterns exactly: `http.Error` for handler failures, `log.Printf`/`log.Fatalf` for server-side diagnostics, comment-heavy tests matching the style already in `*_test.go` files (see e.g. `auth/session_test.go`, `portal/admin_test.go`).

---

### Task 1: `portal.RequireAdminSession` middleware

**Files:**
- Modify: `portal/admin.go` (add `RequireAdminSession`; `AdminAuth` stays for now — removed in Task 2 once `main.go` no longer references it)
- Test: `portal/admin_test.go`

**Interfaces:**
- Consumes: `auth.SessionSigner` (`auth.NewSessionSigner`, `.Issue`), `auth.RequireSession(sessions *auth.SessionSigner, r *http.Request) (crypto.Address, error)` — both already implemented in `auth/session.go` and `auth/http.go`.
- Produces: `func RequireAdminSession(sessions *auth.SessionSigner, allowlist map[string]bool, next http.Handler) http.Handler`. Task 2 wires this into every `/admin/*` route in `cmd/portal/main.go`, passing a `map[string]bool` keyed by `crypto.Address.String()` (bech32).

- [ ] **Step 1: Write the failing tests**

In `portal/admin_test.go`, replace the import block:

```go
import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samourai/validator-diagnostics/scoring"
)
```

with:

```go
import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gnolang/gno/tm2/pkg/crypto"
	"github.com/samourai/validator-diagnostics/auth"
	"github.com/samourai/validator-diagnostics/scoring"
)
```

Then append to the same file:

```go
func TestRequireAdminSession(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	sessions := auth.NewSessionSigner([]byte("test-secret"), time.Hour)

	var whitelisted, other crypto.Address
	copy(whitelisted[:], []byte("01234567890123456789")) // 20 bytes
	copy(other[:], []byte("98765432109876543210"))        // 20 bytes

	allowlist := map[string]bool{whitelisted.String(): true}
	handler := RequireAdminSession(sessions, allowlist, inner)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	t.Run("no token", func(t *testing.T) {
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		expiredSigner := auth.NewSessionSigner([]byte("test-secret"), -1*time.Minute)
		token := expiredSigner.Issue(whitelisted)

		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("valid session, non-whitelisted address", func(t *testing.T) {
		token := sessions.Issue(other)

		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("valid session, whitelisted address", func(t *testing.T) {
		token := sessions.Issue(whitelisted)

		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 (request should reach the wrapped handler)", resp.StatusCode)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./portal/... -run TestRequireAdminSession -v`
Expected: FAIL with `undefined: RequireAdminSession`

- [ ] **Step 3: Implement `RequireAdminSession`**

In `portal/admin.go`, add `"github.com/samourai/validator-diagnostics/auth"` to the import block, then insert this function after `AdminAuth`'s closing brace (before the `AdminSubmission` struct):

```go
// RequireAdminSession wraps next, accepting only requests bearing a
// valid admin session token (see auth.RequireSession) whose bound
// operator address is present in allowlist. allowlist keys are bech32
// address strings (crypto.Address.String()) — the same identity/session
// machinery the validator upload flow uses, restricted to a fixed set
// of admin addresses.
func RequireAdminSession(sessions *auth.SessionSigner, allowlist map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, err := auth.RequireSession(sessions, r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !allowlist[addr.String()] {
			log.Printf("admin: rejected non-whitelisted operator address %s", addr)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./portal/... -run TestRequireAdminSession -v`
Expected: PASS (all four subtests)

- [ ] **Step 5: Run the full portal test suite to confirm nothing else broke**

Run: `go test ./portal/...`
Expected: PASS (existing `TestAdminAuth` and friends untouched, still green — `AdminAuth` isn't removed until Task 2)

- [ ] **Step 6: Commit**

```bash
git add portal/admin.go portal/admin_test.go
git commit -m "Add RequireAdminSession middleware for operator-whitelist admin auth"
```

---

### Task 2: Wire `cmd/portal/main.go`, remove `AdminAuth`/`ADMIN_PASSWORD`

**Files:**
- Modify: `cmd/portal/main.go`
- Modify: `cmd/portal/main_test.go`
- Modify: `portal/admin.go` (delete `AdminAuth`)
- Modify: `portal/admin_test.go` (delete `TestAdminAuth`)
- Modify: `.env.example`
- Modify: `.env`

**Interfaces:**
- Consumes: `portal.RequireAdminSession` from Task 1.
- Produces: `parseAdminAllowlist(csv string) (map[string]bool, error)` and `loadOrGenerateSecret(envVar string) ([]byte, error)`, both package-private to `cmd/portal`. No other task depends on these.

- [ ] **Step 1: Write the failing tests**

In `cmd/portal/main_test.go`, replace the whole file with:

```go
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
```

(`g1xqcnyve5x5mrwwpexqcnyve5x5mrwwpemgh56f` and `g18yurwd34xsenyvfs8yurwd34xsenyvfsaffa87` are the bech32 encodings of the fixed 20-byte test addresses `"01234567890123456789"` and `"98765432109876543210"` used elsewhere in this repo's tests, e.g. `auth/session_test.go` — not real keys, just deterministic fixtures.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go build ./... && go test ./cmd/portal/... -v`
Expected: build failure — `portal.RequireAdminSession` call compiles fine (Task 1 done), but `parseAdminAllowlist` is undefined, and the old `main.go` still calls `portal.AdminAuth(adminPassword, ...)` which is untouched so far. This step just confirms the new test file doesn't silently pass against stale code.

- [ ] **Step 3: Rewrite `cmd/portal/main.go`**

Replace the whole file with:

```go
// Command portal is the validator fire drill submission portal: the
// challenge-tx auth endpoints, the archive upload endpoint, the admin
// submissions dashboard, and the static frontend, all in one binary.
//
// Storage backend: pass either -upload-dir (local disk, for testing) or
// -s3-bucket (+ -s3-region/-s3-endpoint, with credentials from the
// S3_ACCESS_KEY/S3_SECRET_KEY environment variables) for production.
//
// Uploads are streamed to clamd for a malware scan before being stored
// when -clamav-addr is set; the scan fails closed, so keep
// -max-upload-size at or below clamd's own StreamMaxLength (the bundled
// clamd.conf sets both to 2 GiB) or real uploads are rejected with 503.
//
// Required environment variables:
//   - ADMIN_OPERATOR_ADDRESSES — comma-separated bech32 operator
//     addresses allowed to authenticate against every admin route:
//     /admin, /admin/submissions, /admin/exercise,
//     /admin/submissions/{id}/score, /admin/submissions/{id} (DELETE),
//     and /admin/summary. Admins sign in the same challenge-tx way
//     validators do (see /auth/challenge, /auth/verify) — an address
//     not in this list gets a 403 even with a valid signature.
//   - SESSION_SECRET (optional) — hex-encoded HMAC secret for validator
//     upload session tokens. If unset, a random one is generated for
//     this run (sessions won't survive a restart — fine for a single
//     exercise, not for a long-lived deployment).
//   - ADMIN_SESSION_SECRET (optional) — same as SESSION_SECRET, for the
//     separate admin session tokens, so restarting the portal doesn't
//     also invalidate in-flight validator upload sessions (or vice
//     versa).
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gnolang/gno/tm2/pkg/crypto"
	"github.com/samourai/validator-diagnostics/auth"
	"github.com/samourai/validator-diagnostics/clamav"
	"github.com/samourai/validator-diagnostics/exercise"
	"github.com/samourai/validator-diagnostics/portal"
	"github.com/samourai/validator-diagnostics/scoring"
	"github.com/samourai/validator-diagnostics/storage"
	"github.com/samourai/validator-diagnostics/submission"
)

//go:embed static
var staticFiles embed.FS

// defaultMaxUploadSize is the accepted-upload ceiling this deployment
// standardises on, and it is deliberately *not* prd.md's "for example
// 10 GB": every upload is streamed to clamd before it is stored, and
// clamd refuses anything past its own StreamMaxLength (25 MiB out of the
// box). The bundled clamd.conf raises that limit to this same 2 GiB, so
// the two bounds agree; raising one without the other turns oversized
// uploads into 503s instead of a clean rejection.
const defaultMaxUploadSize = 2 << 30 // 2 GiB

// defaultMaxLogSize caps the gnoland.log.gz entry inside the archive.
// submission's own default is 2 GiB, which was harmless while those
// bytes were freed as soon as ValidateArchive returned — but Phase 3
// keeps them alive through the AV scan and the upload to storage, so
// they now cost up to that much resident memory per concurrent request.
// 64 MiB of gzip is on the order of a gigabyte of plaintext log, far
// more than the 8 MiB scoring.scanLogWindow will ever decompress, while
// keeping per-request retention bounded. Raise it with -max-log-size if
// real submissions ever bump into it (they are rejected with a clear
// message when they do).
const defaultMaxLogSize = 64 << 20 // 64 MiB

func main() {
	remote := flag.String("remote", "", "gno.land RPC endpoint to verify operator pubkeys against, e.g. https://rpc.test13.testnets.gno.land:443")
	addr := flag.String("addr", "localhost:8080", "address to listen on")
	sessionTTL := flag.Duration("session-ttl", 5*time.Minute, "how long an issued validator upload session token stays valid")
	adminSessionTTL := flag.Duration("admin-session-ttl", time.Hour, "how long an issued admin session token stays valid")
	uploadDir := flag.String("upload-dir", "", "local directory to save submitted archives into (use this OR the -s3-* flags)")
	s3Bucket := flag.String("s3-bucket", "", "S3-compatible bucket to save submitted archives into")
	s3Region := flag.String("s3-region", "", "S3-compatible region")
	s3Endpoint := flag.String("s3-endpoint", "", "S3-compatible endpoint (leave empty for real AWS S3)")
	logPath := flag.String("log-path", "./submissions.jsonl", "path to the submission log file, read by the admin dashboard")
	exercisePath := flag.String("exercise-path", "./exercise.json", "path to the Phase 3 exercise config file, managed via POST /admin/exercise")
	scoresPath := flag.String("scores-path", "./scores.json", "path to the Phase 3 scoring records file")
	clamavAddr := flag.String("clamav-addr", "", "clamd address to scan uploads against (host:port, or unix:/path/to/socket); leave empty to disable AV scanning (NOT recommended for production)")
	clamavTimeout := flag.Duration("clamav-timeout", 15*time.Minute, "how long a single clamd scan may take, dial included; must comfortably cover streaming a whole -max-upload-size archive to clamd")
	maxUploadSize := flag.Int64("max-upload-size", defaultMaxUploadSize, "maximum accepted upload size in bytes; keep this <= clamd's StreamMaxLength (see clamd.conf) or scannable uploads will be rejected with 503")
	maxLogSize := flag.Int64("max-log-size", defaultMaxLogSize, "maximum accepted size in bytes of the gnoland.log.gz entry inside the archive; these bytes are held in memory for the whole request")
	flag.Parse()

	if *remote == "" {
		log.Fatal("-remote is required (see docs/resources/gnoland-networks.md in gnolang/gno for known endpoints)")
	}

	adminAllowlist, err := parseAdminAllowlist(os.Getenv("ADMIN_OPERATOR_ADDRESSES"))
	if err != nil {
		log.Fatalf("invalid ADMIN_OPERATOR_ADDRESSES: %v", err)
	}

	store, err := configureStore(*uploadDir, *s3Bucket, *s3Region, *s3Endpoint)
	if err != nil {
		log.Fatalf("unable to configure storage: %v", err)
	}

	sessionSecret, err := loadOrGenerateSecret("SESSION_SECRET")
	if err != nil {
		log.Fatalf("unable to prepare session secret: %v", err)
	}
	sessions := auth.NewSessionSigner(sessionSecret, *sessionTTL)

	adminSessionSecret, err := loadOrGenerateSecret("ADMIN_SESSION_SECRET")
	if err != nil {
		log.Fatalf("unable to prepare admin session secret: %v", err)
	}
	adminSessions := auth.NewSessionSigner(adminSessionSecret, *adminSessionTTL)

	nonces := auth.NewNonceStore()
	verifier := &auth.Verifier{Remote: *remote, Nonces: nonces}
	submissionLog := portal.NewFileLog(*logPath)
	exerciseStore := exercise.NewFileStore(*exercisePath)
	scoresStore := scoring.NewStore(*scoresPath)

	var avScanner clamav.Scanner = clamav.NoopScanner{}
	if *clamavAddr != "" {
		avScanner = clamav.ClamdScanner{Addr: *clamavAddr, Timeout: *clamavTimeout}
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
		Sessions:      sessions,
		Store:         store,
		Log:           submissionLog,
		AVScanner:     avScanner,
		Exercise:      exerciseStore,
		Scores:        scoresStore,
		MaxUploadSize: *maxUploadSize,

		ArchiveOptions: submission.Options{MaxLogSize: *maxLogSize},
	})
	mux.Handle("/admin", portal.RequireAdminSession(adminSessions, adminAllowlist, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, staticFS, "admin.html")
	})))
	mux.Handle("/admin/submissions", portal.RequireAdminSession(adminSessions, adminAllowlist, portal.AdminSubmissionsHandler(submissionLog, scoresStore)))
	mux.Handle("/admin/exercise", portal.RequireAdminSession(adminSessions, adminAllowlist, exercise.ConfigHandler(exerciseStore)))
	mux.Handle("POST /admin/submissions/{id}/score", portal.RequireAdminSession(adminSessions, adminAllowlist, portal.AdminScoreHandler(submissionLog, scoresStore)))
	mux.Handle("DELETE /admin/submissions/{id}", portal.RequireAdminSession(adminSessions, adminAllowlist, portal.AdminDeleteSubmissionHandler(submissionLog, store, scoresStore)))
	mux.Handle("/admin/summary", portal.RequireAdminSession(adminSessions, adminAllowlist, portal.AdminSummaryHandler(submissionLog, exerciseStore, scoresStore)))
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

// loadOrGenerateSecret loads a hex-encoded HMAC secret from envVar, or
// generates a random 32-byte one for this run if envVar is unset —
// sessions issued with a generated secret won't survive a restart,
// which is fine for a single exercise but not a long-lived deployment.
func loadOrGenerateSecret(envVar string) ([]byte, error) {
	if hexSecret := os.Getenv(envVar); hexSecret != "" {
		return hex.DecodeString(hexSecret)
	}

	log.Printf("%s not set: generating a random one for this run (sessions won't survive a restart)", envVar)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// parseAdminAllowlist parses a comma-separated list of bech32 operator
// addresses into an allowlist set keyed by crypto.Address.String(). An
// empty list or any invalid address is an error — an admin surface with
// no valid credentials configured is a misconfiguration, not a
// degraded-but-running state.
func parseAdminAllowlist(csv string) (map[string]bool, error) {
	allowlist := map[string]bool{}
	for _, raw := range strings.Split(csv, ",") {
		addrStr := strings.TrimSpace(raw)
		if addrStr == "" {
			continue
		}
		addr, err := crypto.AddressFromBech32(addrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid admin operator address %q: %w", addrStr, err)
		}
		allowlist[addr.String()] = true
	}
	if len(allowlist) == 0 {
		return nil, errors.New("no admin operator addresses configured (ADMIN_OPERATOR_ADDRESSES is required)")
	}
	return allowlist, nil
}
```

- [ ] **Step 4: Delete `AdminAuth` and its test**

In `portal/admin.go`, remove the `AdminAuth` function (lines 12–26 of the original file) and the now-unused `"crypto/subtle"` import.

In `portal/admin_test.go`, remove the `TestAdminAuth` function (the whole `func TestAdminAuth(t *testing.T) { ... }` block, including its three `t.Run` subtests).

- [ ] **Step 5: Run the full test suite**

Run: `go build ./... && go test ./...`
Expected: PASS everywhere. `TestDeleteSubmissionRouteRequiresAdminAuth` and `TestParseAdminAllowlist` (new) pass; there is no more `TestAdminAuth` to fail; every other package is untouched.

- [ ] **Step 6: Update `.env.example`**

Replace:

```
# Protects the admin API — /admin, /admin/submissions,
# /admin/exercise, /admin/summary and the per-submission score endpoint
# (HTTP Basic Auth, any username).
ADMIN_PASSWORD=changeme
```

with:

```
# Comma-separated bech32 operator addresses allowed to authenticate
# against the admin API — /admin, /admin/submissions, /admin/exercise,
# /admin/summary, the per-submission score endpoint, and the delete
# endpoint. Admins sign in the same challenge-tx way validators do (see
# REMOTE above); an address not in this list gets a 403 even with a
# valid signature.
ADMIN_OPERATOR_ADDRESSES=g1...,g1...
```

And immediately after the existing `SESSION_SECRET` block:

```
# Optional: hex-encoded HMAC secret for admin session tokens, kept
# separate from SESSION_SECRET so restarting the portal doesn't also
# invalidate in-flight validator upload sessions (or vice versa). Leave
# unset to generate a random one per run.
#ADMIN_SESSION_SECRET=
```

- [ ] **Step 7: Update `.env`**

Replace:

```
# Protects /admin and /admin/submissions (HTTP Basic Auth, any username)
ADMIN_PASSWORD=changeme
```

with:

```
# Comma-separated bech32 operator addresses allowed into the admin
# dashboard. This default is a deterministic non-secret test fixture
# (bech32 of the byte string "01234567890123456789", the same one used
# in this repo's Go tests) — nobody holds its private key, so replace it
# with real address(es) you can actually sign in with.
ADMIN_OPERATOR_ADDRESSES=g1xqcnyve5x5mrwwpexqcnyve5x5mrwwpemgh56f
```

And immediately after the existing `SESSION_SECRET` block:

```
# Optional: hex-encoded HMAC secret for admin session tokens. Leave
# unset to generate a random one per run.
#ADMIN_SESSION_SECRET=
```

- [ ] **Step 8: Commit**

```bash
git add cmd/portal/main.go cmd/portal/main_test.go portal/admin.go portal/admin_test.go .env.example .env
git commit -m "Wire admin routes to operator-whitelist auth, remove ADMIN_PASSWORD"
```

---

### Task 3: Admin login UI

**Files:**
- Modify: `cmd/portal/static/admin.html`
- Modify: `cmd/portal/static/admin.js`

**Interfaces:**
- Consumes: `POST /auth/challenge`, `POST /auth/verify` (unchanged, from `auth/http.go`), every existing `/admin/*` endpoint from Task 2.
- Produces: nothing consumed by later tasks — this is the last task.

- [ ] **Step 1: Add login markup to `admin.html`**

Insert this immediately after the `</header>` closing tag (before the existing `<div class="tabs" ...>`):

```html
<section id="admin-step-address" class="step">
  <h2>Admin sign-in</h2>
  <label for="admin-operator-address">Your valopers operator address</label>
  <input type="text" id="admin-operator-address" placeholder="g1...">
  <button id="admin-get-challenge">Get challenge</button>
  <p class="error" id="admin-address-error"></p>
</section>

<section id="admin-step-sign" class="step" hidden>
  <h2>Sign the challenge</h2>
  <p>Run this command locally, with your operator key:</p>
  <pre id="admin-sign-command"></pre>
  <p><a id="admin-download-challenge" download="challenge.json">Download challenge.json</a></p>
  <label for="admin-sig-file">Upload the resulting sig.json</label>
  <input type="file" id="admin-sig-file" accept=".json">
  <button id="admin-verify-signature">Verify</button>
  <p class="error" id="admin-sign-error"></p>
</section>

<div id="admin-dashboard" hidden>
```

Then wrap the rest of the page in that new div: insert a closing `</div>` immediately after `<p id="admin-error" class="error"></p>` and before `</main>`.

The `<div class="tabs" ...>` through `<p id="admin-error" class="error"></p>` block (including both tab panels and the delete-confirm dialog) is otherwise **unchanged** — it's now just nested one level deeper, inside `#admin-dashboard`.

- [ ] **Step 2: Add login logic to `admin.js`**

Insert at the very top of `admin.js`, right after `"use strict";`:

```javascript
let adminSessionToken = null;
let adminCurrentNonce = null;
let adminCurrentOperatorAddress = null;
let dashboardStarted = false;

function setError(id, message) {
  document.getElementById(id).textContent = message || "";
}

// The server always returns JSON, but a response from something else
// entirely (a proxy's plain-text error page) might not be — .json()
// throws on that, so every non-network-error response goes through
// this instead of a bare `await resp.json()`.
async function parseJSONResponse(resp) {
  try {
    return await resp.json();
  } catch (err) {
    return { error: `Unexpected response from server (status ${resp.status}).` };
  }
}

// showLogin resets to the login screen, clearing any session in memory.
// message, if given, explains why (e.g. an expired session) — left
// blank on the very first page load.
function showLogin(message) {
  adminSessionToken = null;
  document.getElementById("admin-dashboard").hidden = true;
  document.getElementById("admin-step-address").hidden = false;
  document.getElementById("admin-step-sign").hidden = true;
  setError("admin-address-error", message || "");
}

// adminFetch wraps fetch with the admin session's Authorization header,
// and falls back to the login screen on 401/403 — an expired or
// no-longer-whitelisted session should never leave the dashboard's
// buttons failing silently against every subsequent click.
async function adminFetch(url, options = {}) {
  const headers = Object.assign({}, options.headers, {
    Authorization: "Bearer " + adminSessionToken,
  });
  const resp = await fetch(url, Object.assign({}, options, { headers }));
  if (resp.status === 401 || resp.status === 403) {
    showLogin("Session expired or no longer authorized — please sign in again.");
  }
  return resp;
}

// startDashboard is called once, right after a successful admin
// verification. dashboardStarted guards against double-starting
// setInterval if verify were somehow triggered twice.
function startDashboard() {
  if (dashboardStarted) return;
  dashboardStarted = true;
  refresh();
  setInterval(() => refresh(), 5000);
  loadExerciseConfig();
}

document.getElementById("admin-get-challenge").addEventListener("click", async () => {
  setError("admin-address-error", "");
  const address = document.getElementById("admin-operator-address").value.trim();
  if (!address) {
    setError("admin-address-error", "Enter your operator address.");
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
    setError("admin-address-error", "Network error: " + err.message);
    return;
  }

  const data = await parseJSONResponse(resp);
  if (!resp.ok) {
    setError("admin-address-error", data.error || "Unable to get a challenge.");
    return;
  }

  adminCurrentNonce = data.nonce;
  adminCurrentOperatorAddress = address;

  const challengeJSON = JSON.stringify(data.challenge_tx, null, 2);
  const blob = new Blob([challengeJSON], { type: "application/json" });
  const link = document.getElementById("admin-download-challenge");
  link.href = URL.createObjectURL(blob);

  document.getElementById("admin-sign-command").textContent =
    `gnokey sign --tx-path challenge.json \\\n` +
    `  --chainid ${data.chainid} \\\n` +
    `  --account-number ${data.account_number} --account-sequence ${data.account_sequence} \\\n` +
    `  --output-document sig.json <your-operator-key-name>`;

  document.getElementById("admin-step-sign").hidden = false;
});

document.getElementById("admin-verify-signature").addEventListener("click", async () => {
  setError("admin-sign-error", "");
  const fileInput = document.getElementById("admin-sig-file");
  const file = fileInput.files[0];
  if (!file) {
    setError("admin-sign-error", "Choose the sig.json file produced by gnokey sign.");
    return;
  }

  let sigDoc;
  try {
    sigDoc = JSON.parse(await file.text());
  } catch (err) {
    setError("admin-sign-error", "sig.json is not valid JSON: " + err.message);
    return;
  }
  if (!sigDoc.signature) {
    setError("admin-sign-error", 'sig.json has no "signature" field.');
    return;
  }

  let resp;
  try {
    resp = await fetch("/auth/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        operator_address: adminCurrentOperatorAddress,
        nonce: adminCurrentNonce,
        signature: sigDoc.signature,
      }),
    });
  } catch (err) {
    setError("admin-sign-error", "Network error: " + err.message);
    return;
  }

  const data = await parseJSONResponse(resp);
  if (!resp.ok || !data.ok) {
    setError("admin-sign-error", data.error || "Verification failed.");
    return;
  }

  adminSessionToken = data.session_token;
  document.getElementById("admin-step-address").hidden = true;
  document.getElementById("admin-step-sign").hidden = true;
  document.getElementById("admin-dashboard").hidden = false;
  startDashboard();
});
```

- [ ] **Step 3: Route every existing `/admin/*` call through `adminFetch`, and drop the old unconditional startup calls**

In the rest of `admin.js` (unchanged otherwise), make these six substitutions:

1. In `buildScoreForm`'s click handler:
   ```javascript
   resp = await fetch(`/admin/submissions/${encodeURIComponent(id)}/score`, {
   ```
   →
   ```javascript
   resp = await adminFetch(`/admin/submissions/${encodeURIComponent(id)}/score`, {
   ```

2. In `refresh`:
   ```javascript
   resp = await fetch("/admin/submissions");
   ```
   →
   ```javascript
   resp = await adminFetch("/admin/submissions");
   ```

3. Delete these two now-obsolete top-level statements (they're replaced by the call to `startDashboard()` inside the verify handler from Step 2):
   ```javascript
   refresh();
   setInterval(() => refresh(), 5000);
   ```

4. In `loadExerciseConfig`:
   ```javascript
   resp = await fetch("/admin/exercise");
   ```
   →
   ```javascript
   resp = await adminFetch("/admin/exercise");
   ```

5. In the `save-exercise` click handler:
   ```javascript
   resp = await fetch("/admin/exercise", {
   ```
   →
   ```javascript
   resp = await adminFetch("/admin/exercise", {
   ```

6. Delete this now-obsolete top-level statement (calling it unconditionally at load time would hit `/admin/exercise` before any admin has signed in):
   ```javascript
   loadExerciseConfig();
   ```

7. In the `generate-summary` click handler:
   ```javascript
   resp = await fetch("/admin/summary");
   ```
   →
   ```javascript
   resp = await adminFetch("/admin/summary");
   ```

8. In the delete-confirm button's click handler:
   ```javascript
   resp = await fetch(`/admin/submissions/${encodeURIComponent(id)}`, { method: "DELETE" });
   ```
   →
   ```javascript
   resp = await adminFetch(`/admin/submissions/${encodeURIComponent(id)}`, { method: "DELETE" });
   ```

(The existing `activateTab(location.hash.slice(1));` call at the bottom of the file stays exactly as-is — it only toggles `hidden` on elements that are already inside the hidden `#admin-dashboard`, so running it before sign-in is harmless.)

- [ ] **Step 4: Manual smoke test**

This project has no automated frontend tests — verify by hand, following its existing convention (see `docs/superpowers/plans/2026-08-04-admin-delete-submission.md`'s Task 6):

1. Generate a real test operator key and its address if you don't have one handy:
   ```bash
   gnokey add mytestkey --recover=false
   ```
   Note the `g1...` address it prints.
2. Set `ADMIN_OPERATOR_ADDRESSES=<that g1... address>` in `.env` (or export it directly).
3. Start the portal: `go run ./cmd/portal -remote https://rpc.topaz.testnets.gno.land -upload-dir /tmp/portal-uploads` (adjust flags to match your local setup — see `README.md`).
4. Open `http://localhost:8080/admin` in a browser. Confirm you see the "Admin sign-in" screen, not the dashboard, and not a browser-native Basic Auth popup.
5. Enter the operator address, click "Get challenge", follow the printed `gnokey sign` command, upload the resulting `sig.json`, click "Verify". Confirm the dashboard (Configuration / Validators tabs) appears and the submissions table loads.
6. Reload the page. Confirm it goes back to the sign-in screen (session token is in-memory only, not persisted).
7. Sign in again with an address that is **not** in `ADMIN_OPERATOR_ADDRESSES` (any other valid `gnokey` key). Confirm you get a clear "Session expired or no longer authorized" message rather than a silent failure or a misleading "wrong signature" error.
8. With a whitelisted session active, confirm the existing admin actions still work end-to-end: save exercise config, delete a submission (via the confirmation dialog), generate a summary.

- [ ] **Step 5: Commit**

```bash
git add cmd/portal/static/admin.html cmd/portal/static/admin.js
git commit -m "Add operator-address sign-in screen to the admin dashboard"
```
