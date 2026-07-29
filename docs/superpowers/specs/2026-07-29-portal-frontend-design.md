# Validator Fire Drill Portal — Frontend & Admin Design

Status: approved (design), pending implementation plan.

## Context

The backend (see `prd.md`) already implements, and has tested (unit tests + a
live smoke test against the `topaz-1` testnet):

- `auth` — challenge-tx operator-key authentication (`/auth/challenge`,
  `/auth/verify`), stateless session tokens (`SessionSigner`,
  `RequireSession`).
- `submission` — archive naming, structure/security validation, metadata
  schema validation.
- `storage` — a `Store` interface with `S3Store` (S3-compatible object
  storage) and `LocalStore` (local disk, for dev/testing) implementations.
- `portal.SubmitHandler` — wires the three together into `POST /submit`.

There is currently no frontend: everything has been exercised via `curl`
and Go tests. There is also no way for organizers to see, during the fire
drill, who has submitted. This design covers both gaps.

## Goals

1. A validator-facing web page to walk through the full submission flow
   without hand-crafting `curl` requests.
2. An admin-facing page to see submissions arrive in near-real-time during
   the exercise.
3. Ship as a single deployable Go binary — no separate frontend build
   pipeline, no new runtime dependency, deployable by Monday.

## Non-goals (explicitly deferred)

- Browser-wallet (Adena) signing — the validator flow stays file-based
  (`gnokey sign` locally, upload the resulting signature). The session
  token / `RequireSession` boundary is wallet-agnostic, so adding Adena
  later doesn't require touching `auth` or `portal.SubmitHandler`.
- Phase 3 (automated scoring, Discord summary) — out of scope; the fire
  drill's post-mortem/scoring stays manual for this first run.
- "One successful submission per validator" enforcement — still open per
  `prd.md`; not blocking for a first exercise where organizers can
  eyeball the admin list.

## Architecture

Replace `cmd/portal-dev` with `cmd/portal`: the one binary that serves the
existing API handlers (`auth.ChallengeHandler`, `auth.VerifyHandler`,
`portal.SubmitHandler`), the new admin endpoints, and the static
frontend — embedded via `embed.FS` so the whole thing ships as a single
binary with no separate asset deployment step.

```text
cmd/portal/
  main.go        — wiring (same flags as portal-dev, plus admin auth + log path)
  static/
    index.html   — validator flow
    admin.html   — admin dashboard
    portal.js    — shared fetch/DOM logic, split by page via small page-specific scripts
    portal.css
```

## Validator flow (`/`, `index.html`)

A single page, three sequential steps, plain JS (`fetch`, no framework):

1. **Address** — input for `operator_address`; "Get challenge" button calls
   `POST /auth/challenge`. Response renders:
   - a copy-pasteable `gnokey sign ...` command (using the returned
     `chainid`/`account_number`/`account_sequence`),
   - a "Download challenge.json" link (client-side Blob from
     `challenge_tx`).
2. **Signature** — file input for `sig.json`; on selection, parse it
   client-side (it's the Amino JSON signature document — already
   understood, since `auth/http.go`'s `verifyRequest.Signature` expects
   the base64 `signature` field the same way `sig.json` stores it),
   extract `.signature`, call `POST /auth/verify` with
   `{operator_address, nonce, signature}`. On `ok:true`, keep
   `session_token` in a JS variable (never `localStorage`/cookies — it's
   short-lived and single-purpose) and unlock step 3.
3. **Archive** — file input for the `.tar.gz`; "Submit" builds a
   `multipart/form-data` request to `POST /submit` with
   `Authorization: Bearer <session_token>`, field name `archive`. Renders
   the JSON response's `ok`/`error`/`moniker`/`submitted_at` directly —
   `SubmitHandler`'s error strings are already written to be
   human-readable, so no client-side error-message translation layer is
   needed.

No client-side archive validation beyond checking a file was selected —
all real validation stays server-side in `submission`, which is already
tested; duplicating it in JS would be a second, weaker copy of the same
logic.

## Admin flow (`/admin`, `admin.html`)

Protected by HTTP Basic Auth: a single admin password from an
`ADMIN_PASSWORD` environment variable, compared server-side with
`subtle.ConstantTimeCompare`. Chosen over a custom login form because
it's zero JS, handled natively by every browser, and "real" enough for a
single internal exercise — not meant to survive being publicly exposed
long-term.

The page polls `GET /admin/submissions` (also Basic-Auth-protected) every
5 seconds and renders a table: moniker, operator address, submitted-at,
archive filename.

### Submission log (new, backend)

`SubmitHandler` gains an optional `Log` field: an interface with one
method, `Record(ctx, Entry) error`, called after a successful
`Store.Save`. A `FileLog` implementation appends one JSON line per
submission to a configurable file (`submissions.jsonl`). `GET
/admin/submissions` reads and returns that file's contents as a JSON
array. No database: a single append-only file is enough for one exercise
and keeps the "no new dependency" constraint from the Goals section.

```go
type Entry struct {
    Moniker         string    `json:"moniker"`
    OperatorAddress string    `json:"operator_address"`
    Filename        string    `json:"filename"`
    SubmittedAt     time.Time `json:"submitted_at"`
}

type Log interface {
    Record(ctx context.Context, e Entry) error
}
```

`Log` being optional (nil-safe, skipped if unset) keeps every existing
`SubmitHandler` test passing unchanged — this is an additive field, not a
breaking change to the struct.

## What doesn't change

`auth`, `submission`, `storage`, and `portal.SubmitHandler`'s core
validation logic are untouched. This phase adds: static asset serving,
the submission log + admin listing endpoint, admin Basic Auth, and the
`cmd/portal` binary that wires it all together (replacing
`cmd/portal-dev`).

## Testing approach

- `portal`: extend existing handler tests to cover `Log.Record` being
  called on success and skipped on failure; a `FileLog` test verifying
  JSONL round-trip.
- `cmd/portal`: no unit tests for `main.go` wiring itself (consistent with
  `cmd/portal-dev` today) — verified via the same live smoke-test pattern
  already used against `topaz-1`, plus a manual run-through of the full
  UI flow in a browser before calling this done.
- Frontend JS: no test framework introduced (would conflict with the
  zero-build-step goal); verified by manually exercising the golden path
  and the failure paths (bad filename, wrong signature, expired session)
  in a real browser, per this project's standing instruction to test UI
  changes in-browser rather than only asserting the backend logic.
