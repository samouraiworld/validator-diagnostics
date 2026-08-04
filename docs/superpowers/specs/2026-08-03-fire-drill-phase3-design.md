# Fire Drill Phase 3 — Analysis, Scoring & AV Scanning

## Overview

`prd.md` defines three phases for the fire drill. Phase 1 (announcement) and
Phase 2 (artifact collection & submission) are implemented and tested. Phase 3
("Analysis & Scoring") is not: there is no automatic verification of genesis
hash / gnoland version / log time window, no scoring against the PRD's
5×20-point rubric, and no generated summary. Separately, `prd.md`'s Security
Considerations section lists a ClamAV scan as a "not yet implemented" defense
layer.

This spec covers both: closing the Phase 3 gap, and adding the ClamAV scan,
since the ClamAV scan sits directly in the same submission path this work
already touches.

Out of scope (explicitly deferred, unchanged from `prd.md`'s existing notes):
sandboxed/ephemeral extraction environment, "one submission per validator"
enforcement, automated Discord posting (this spec generates a ready-to-paste
summary; posting it is a manual admin action).

## Data model

### `exercise.Config`

New. Holds the values needed to score a live exercise. Configured by the
admin via `POST /admin/exercise`, persisted to a JSON file so it survives a
portal restart mid-exercise.

```go
type Config struct {
    AnnouncedAt              time.Time
    DeadlineAt                time.Time
    InvestigationWindowStart  time.Time
    InvestigationWindowEnd    time.Time
    ExpectedGenesisSHA256     string
    SupportedGnolandVersions  []string
    Observations              string // free text, included verbatim in the generated summary
}
```

Validation on write: `DeadlineAt` must be after `AnnouncedAt`;
`InvestigationWindowEnd` must be after `InvestigationWindowStart`. Rejected
with 400 otherwise.

### `scoring.Result`

New. One record per submission, keyed by `Entry.ID` (see below). Split into
fields computed automatically at submit time and fields entered manually by
the admin afterward (nil/unset until entered).

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

type LogWindowCheck struct {
    Detected bool // false if no recognizable timestamp was found at all
    Covered  bool // true if detected timestamps span the full investigation window
    FirstSeen, LastSeen time.Time // zero if !Detected
}
```

`Result.TotalScore()` sums all four sub-scores, treating an unset manual
field as "pending" (surfaced distinctly in the dashboard/summary, not
silently counted as 0).

### `Entry` (`portal/log.go`)

Gains an `ID` field (opaque random string, generated in `SubmitHandler` at
record time) — the join key between the append-only submission log and the
scoring store, which needs to support updates that `FileLog`'s append-only
model doesn't.

### `submission.Result` (`submission/archive.go`)

Gains a `LogGz []byte` field: the same bounded bytes `ValidateArchive`
already reads to check `gnoland.log.gz`'s magic bytes, now also returned
instead of discarded. This lets `scoring.AutoChecks` reuse the one
already-validated read of the archive instead of opening a second,
independent parse of the raw upload (see Security section for why that
matters).

## Components

### `exercise/` (new package)

- `config.go` — `Config` struct and its validation.
- `store.go` — `FileStore`: JSON file, mutex-guarded read-modify-write
  (unlike `portal.FileLog`, this needs updates, not just appends).
- `http.go` — `ConfigHandler(store) http.HandlerFunc`, GET (current config)
  and POST (replace it, running validation). Wrapped in `AdminAuth` at the
  `cmd/portal` wiring level, same as the existing admin dashboard.

### `scoring/` (new package)

Pure logic, no HTTP:

- `score.go` — the tiered time-based formula (upload completion time),
  `LogQualityScore`, `Result.TotalScore()`.
- `checks.go` — `AutoChecks(meta submission.Metadata, logGz []byte, cfg exercise.Config) (GenesisMatch, VersionSupported bool, LogWindow LogWindowCheck)`. Decompresses `logGz` under its own bounded reader (independent
  cap from archive-level validation — see Security section) and scans for a
  recognizable timestamp prefix on each line, tracking the earliest and
  latest seen, until the log ends or the cap is hit.

  > **Corrected after implementation.** This originally said the scan
  > "stops as soon as both a first and last recognizable timestamp are
  > found". That is not implementable: the latest timestamp is only known
  > once the stream has been read to the end, so there is nothing to stop
  > early *on*. The cap is therefore what bounds the work, and it is set
  > generously (1 GiB of plaintext) rather than tightly, because a scan
  > that stops early cannot establish end-of-window coverage — see
  > "Log quality" below.
- `store.go` — `Store`: JSON file, mutex-guarded read-modify-write, keyed by
  `SubmissionID`. Same shape as `exercise.FileStore`.

### `clamav/` (new package)

- `scanner.go` — `Scanner` interface: `Scan(ctx context.Context, r io.Reader) (Verdict, error)`. A returned `error` means the scan itself could not be
  completed (unreachable, timeout, protocol error) — distinct from a clean
  `Verdict{Infected: false}` or an infected `Verdict{Infected: true, Signature: "..."}`. Callers must not conflate the two.
- `clamd.go` — `ClamdScanner`: hand-rolled `INSTREAM` client over TCP or a
  Unix socket (length-prefixed chunks, terminating zero-length chunk, single
  response line). No new dependency — the protocol is small enough that a
  minimal client is easier to audit than pulling in a third-party wrapper.
- `noop.go` — `NoopScanner`: always returns a clean verdict. Used by
  `cmd/portal-dev` and in tests that don't need a real `clamd`.

### `portal/` wiring

- `log.go` — `Entry` gains `ID`; a small `newSubmissionID()` helper
  (crypto/rand, hex-encoded) generates it.
- `submit.go` — `SubmitHandler` gains two dependencies (`clamav.Scanner`,
  `scoring.AutoChecker` via `exercise.Config` + `scoring.Store`) and two new
  steps in the existing flow, inserted after archive/metadata validation and
  before storage:
  1. AV scan on the raw uploaded bytes (`Seek(0)` first, since the
     `multipart.File` was already consumed by `ValidateArchive`) — infected
     → 422; scan error (unreachable/timeout) → 503, fail-closed.
  2. `scoring.AutoChecks` against `Result.LogGz` + parsed metadata + the
     current `exercise.Config` — if no exercise is configured yet, the
     submission still proceeds (Phase 2 must not depend on Phase 3 config);
     the `scoring.Result` is recorded with an explicit "not yet scored"
     marker instead of zeros.
  After a successful `Store.Save`, both `Log.Record` (existing) and the new
  `scoring.Store` write happen.
- `score.go` (new) — `AdminScoreHandler`: `POST /admin/submissions/{id}/score`, body `{incident_response_quality_score: int}`. Validates the score is
  0-25 (400 otherwise) and updates the `scoring.Result`. 404 on an unknown
  ID; 409 if the submission was never auto-scored (nothing to complete).
- `admin.go` — `AdminSubmissionsHandler` extended to join each `Entry` with
  its `scoring.Result` in the JSON response, so the dashboard has everything
  in one call.
- `summary.go` (new) — `AdminSummaryHandler`: `GET /admin/summary`, renders
  a Markdown-formatted summary (participation count, per-submission
  moniker/status/total score, validation warnings such as genesis/version
  mismatches or an uncovered log window, and the free-text `Observations`
  field from the exercise config) — ready to paste into Discord or
  elsewhere. No outbound webhook; publishing stays a manual admin action.

### `cmd/portal/main.go`

New flags: `-exercise-path` (default `./exercise.json`), `-scores-path`
(default `./scores.json`), `-clamav-addr` (optional; if unset, wires
`clamav.NoopScanner` — matching how `cmd/portal-dev` already works without
real S3 credentials). New admin routes registered under the existing
`AdminAuth` wrapper: `/admin/exercise`, `/admin/submissions/{id}/score`,
`/admin/summary`.

### `docker-compose.yml`

New `clamav` service using the official `clamav/clamav` image, on the same
Docker network as the portal. Portal's `CLAMAV_ADDR` env var points at
`clamd:3310`.

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

`Covered` means *verified* coverage on both sides, which takes a scan that
reached the end of the log. A scan that stopped at its own cap, or on an
over-long line, therefore lands in the middle tier (5) and is reported in
the summary as "could not be fully verified" — never as full marks it
didn't earn, and never as the ⚠️ warning that the validator's logs fall
short. Those are three distinct states and the summary emits exactly one
line for whichever applies.

**Genesis hash / gnoland version** — pass/fail checks, not part of the
100-point score. `prd.md` lists them under Phase 3's "Automatic validation
may verify," separate from the "Evaluation Criteria" table. Surfaced as
badges in the dashboard and as warnings in the generated summary.

## Security

Two risks specific to this work, beyond what `submission.ValidateArchive`
already handles:

**Reusing the validated read, not re-parsing.** `ValidateArchive` today
reads and bounds `gnoland.log.gz`'s bytes but discards them after checking
the magic bytes — only `Metadata` survives in its `Result`. If
`scoring.AutoChecks` opened a second, independent read of the raw upload to
get at the log content, two different parsers would be interpreting the same
untrusted archive, which is exactly the shape of a parser-differential bug
(a file crafted so two parsers disagree about its contents). Fix: `submission.Result` also returns the already-bounded `LogGz` bytes; `scoring.AutoChecks` consumes those, never the raw upload directly.

**A second-layer decompression bomb.** `gnoland.log.gz`'s *content* is
itself gzip-compressed plain text — `ValidateArchive` bounds the compressed
bytes but never decompresses them. `scoring.AutoChecks` has to, to scan for
timestamps, which reopens exactly the kind of bomb risk `prd.md` already
calls out for the outer archive ("decompressed-size limit, independent from
the compressed upload size limit"). Fix: the inner gunzip read in
`scoring.checks.go` goes through its own `io.LimitReader`, independent of
the archive-level cap, and stops as soon as both a first and last
recognizable timestamp are found (it doesn't need to read to EOF).

Both of these only produce **structured** output (`bool`/`time.Time`) that
the dashboard and generated summary consume — raw log line content is never
stored, displayed, or included in the summary text, which sidesteps the
"sanitize before rendering" concern from `prd.md`'s Security Considerations
rather than relying on sanitizing it after the fact.

**ClamAV as a third layer, not a replacement.** The AV scan happens on the
raw uploaded bytes, after structural/security validation already passed —
it's defense in depth, not the primary gate. Fail-closed on scanner
unavailability (503) rather than fail-open: a scan that can be bypassed by
cutting network access to `clamd` isn't a real guarantee. Known operational
cost: if `clamd` is down, uploads are blocked until it recovers — accepted
tradeoff, per this spec's earlier discussion with the user.

Unchanged from `prd.md`: the sandboxed/ephemeral extraction environment
remains not implemented; this work doesn't add or remove that gap.

## Frontend (`cmd/portal/static/`)

`admin.html`/`admin.js`:
- A form to view/edit the exercise config (genesis hash, supported versions,
  investigation window, announce/deadline timestamps, observations).
- The submissions table gains score columns and pass/fail badges (genesis
  match, version supported, log window coverage).
- A per-row form for the one manual field (incident response quality
  score).
- A "Generate summary" view that displays the Markdown output of
  `GET /admin/summary` in a copyable text block.

## Error handling

- `POST /admin/exercise`: 400 on `DeadlineAt <= AnnouncedAt` or
  `InvestigationWindowEnd <= InvestigationWindowStart`.
- `POST /admin/submissions/{id}/score`: 400 on a score outside 0-25; 404 on
  an unknown submission ID; 409 if the submission was never auto-scored.
- AV scan: infected → 422; scanner unreachable/timeout → 503 (fail-closed).
- Genesis/version/log-window mismatches never block an upload — informational only, consistent with `prd.md`'s split between Phase 2 (blocking,
  security/structure) and Phase 3 (informational, analysis).
- If a submission arrives before the exercise is configured, it's still
  accepted; its `scoring.Result` is marked "not yet scored" rather than
  scored against zero-value config.

## Testing

- `exercise`: config store round-trip; validation rejection cases.
- `scoring`: tiered-formula boundary tests (exactly at 25/50/75/100%, before
  announcement, after deadline); timestamp parsing (mixed recognized/
  unrecognized lines, no timestamps at all, decompression cap reached);
  genesis/version match and mismatch; `LogQualityScore` composite; `Result.TotalScore()` with a pending manual field.
- `clamav`: a fake `INSTREAM` TCP server (same pattern as
  `storage/s3_test.go`'s fake S3-compatible server) exercising clean,
  infected, and malformed-response cases; a `NoopScanner` sanity test.
  Manual smoke test against a real local `clamd` using the standard EICAR
  test string, documented in the package doc comment (not automated in CI).
- `portal`: `submit_test.go` extended for the two new steps (AV clean/infected/unreachable; exercise configured/unconfigured); new `score_test.go`
  (valid, out-of-range, unknown ID, unconfigured exercise); new `summary_test.go`; `admin_test.go` extended for the joined `Entry`+`Result` output.
- Frontend: manual smoke test via `go run ./cmd/portal` + browser, per this
  project's existing convention — no automated frontend tests in this repo
  today.
