# Windowed Antivirus Scanning of Extracted Content

## Overview

A 2.41 GB test archive (`test/samourai-crew-huge-20260805-2232UTC.tar.gz`, built
from 83 copies of `test/samourai-crew-1-24hh.log`) is rejected with a 503.
clamd logs:

```text
LibClamAV Warning: Max file-size was set to N bytes. Unfortunately, scanning
files greater than 2147483647 bytes (2 GiB - 1) is not supported.
```

libclamav has a hard 2 GiB - 1 per-file scan ceiling that no `clamd.conf`
setting lifts — verified on ClamAV 1.5.3, where `clamconf` accepted
`MaxFileSize 32G` and libclamav warned and ignored it. The ceiling applies to
**every file clamd extracts**, including the decompressed log, so at the
observed ~15:1 compression ratio a compressed log past ~140 MB already blows
it. This is documented in the README's "The 2 GiB wall" section.

Validators will routinely submit 2 GB archives. Making that work means
changing what the portal sends clamd, not clamd's configuration.

The measured clamd throughput on the target machine is **~142 MB/s**
(305,818,697 bytes in 2.16 s, via `clamdscan --stream` from a throwaway
container on the compose network). A 25 GB decompressed log therefore costs
about three minutes to scan in full.

### Fixed decisions

These were settled before this spec and are not reopened here:

1. **Approach**: window the decompressed log through clamd, rather than
   flagging large archives as unscanned.
2. **Coverage**: scan under a configurable decompressed-byte budget. Below it
   coverage is total; above it the submission is accepted and recorded as
   partially scanned. Never a silent fail-open.
3. **What clamd receives**: always extracted content, for every submission —
   `metadata.json`, then the decompressed log in windows. One code path, no
   size-conditional branching. This is what `prd.md` line 380 asks for ("Run
   an antivirus scan ... on extracted content"). Accepted trade-off: clamd
   never sees the raw `.tar.gz` again.
4. **Budget default**: 32 GiB (~4 minutes worst case at the measured rate).
   Its real job is `prd.md` line 376's zip/tar bomb defence, not cost control.
5. **Status surfacing**: on the submission log entry (`submissions.jsonl`) and
   as a badge in the admin dashboard — it is a property of the submission, not
   of the score.

### Out of scope

- Raising `MAX_UPLOAD_SIZE`. Once clamd no longer receives the raw archive the
  2 GiB wall stops binding it, but the next real obstacle is
  `storage.S3Store.Save`, which issues a single `PutObject` and is therefore
  capped at S3's 5 GiB single-part limit. Raising the ceiling is a separate
  change with its own disk, timeout, and multipart-upload questions; this spec
  only corrects the documentation that currently blames libclamav for it.
- The Discord summary (`portal/summary.go`). Scan coverage does not appear
  there.
- Making `WindowSize` or `Overlap` operator-configurable.

## 1. The windowed scanner

New file `clamav/windowed.go`.

The `Scanner` interface is unchanged:

```go
Scan(ctx context.Context, r io.Reader) (Verdict, error)
```

`WindowedScanner` **wraps** a `Scanner` rather than implementing one, because
it has to report something `Verdict` cannot carry: how much of the stream was
actually examined.

```go
// Coverage reports what a windowed scan actually examined.
type Coverage struct {
	// Complete is true when the stream reached EOF within the budget.
	Complete bool `json:"complete"`

	// Bytes is how much of the stream was handed to the scanner, with the
	// overlap between consecutive windows counted once.
	Bytes int64 `json:"bytes"`
}

type WindowedScanner struct {
	Scanner    Scanner
	WindowSize int64 // 0 uses defaultWindowSize
	Overlap    int64 // 0 uses defaultOverlap
	Budget     int64 // 0 uses defaultScanBudget
}

func (w WindowedScanner) ScanStream(ctx context.Context, r io.Reader) (Verdict, Coverage, error)
```

Package constants:

```go
defaultWindowSize = 1 << 30 // 1 GiB, comfortably under libclamav's 2 GiB - 1
defaultOverlap    = 1 << 20 // 1 MiB

// DefaultScanBudget is exported because cmd/portal uses it as its own
// flag default: unlike -max-log-size, this deployment has no reason to
// standardise on a different value, and two copies of 32 GiB could drift.
DefaultScanBudget = 32 << 30 // 32 GiB
```

`WindowSize` and `Overlap` are constants rather than operator knobs because
they encode protocol and signature facts, not policy: the window has to stay
under libclamav's hard ceiling, and the overlap has to exceed the longest
signature ClamAV can match. Only `Budget` is a policy choice, so only `Budget`
is configurable.

### Why an overlap

Each window is its own INSTREAM session, so a signature straddling a window
boundary would be split across two independent scans and matched by neither.
Re-sending the last `Overlap` bytes of window N at the head of window N+1
closes that gap. ClamAV signatures are at most a few KB, so 1 MiB is generous;
on a 25 GB log it costs about 25 MiB of re-scanned bytes, roughly 0.1%.

### The loop

Per iteration:

1. **Peek one byte** from the budget-bounded reader. Zero bytes read means the
   stream is exhausted — either the log ended or the budget did — and ends the
   loop. The peek exists so that a stream whose length is an exact multiple of
   the window capacity does not produce a final window containing nothing but
   the previous window's overlap.
2. **Build the window** as
   `io.MultiReader(bytes.NewReader(tail), tee(peek + io.LimitReader(bounded, capacity-1)))`,
   where `capacity` is `WindowSize - len(tail)` and the tee feeds a ring buffer
   holding the last `Overlap` bytes seen. Nothing beyond that ring buffer and
   one 1 MiB tail is retained, so memory is O(`Overlap`) regardless of the
   stream's length.
3. **Scan it**, then **drain whatever the scanner left** into `io.Discard`. The
   scanner is not trusted to have consumed the whole window: without the drain,
   the byte accounting and the alignment of the next window would depend on how
   much the underlying implementation chose to read.
4. Accumulate the fresh (non-overlap) bytes read into `Coverage.Bytes`.
5. If the window came up short of its capacity, the stream ended inside it —
   end the loop. Otherwise carry the ring buffer's contents forward as the next
   `tail`.

Budget enforcement is an `io.LimitedReader` wrapped around `r`. When the loop
ends, `Complete` is true if budget remains; if the budget is exactly spent, one
probe byte is read from `r` itself to tell "the log ended exactly here" from
"the budget cut it short". This mirrors [`scoring.scanHitCap`](../../../scoring/checks.go),
which solves the same problem for the log-window scan.

If `Overlap >= WindowSize` — only reachable via an explicitly wrong caller
configuration — the scanner clamps `Overlap` to `WindowSize / 2` so the window
capacity stays positive and the loop terminates.

### Telling a broken source from a broken scanner

The windows are read *by* the underlying `Scanner`, so a read failure on `r` —
a gzip stream that turns out to be truncated — reaches `ScanStream` as an error
returned by `Scan`, indistinguishable at that point from clamd being down.
`ClamdScanner` even wraps it (`clamav: reading input: %w`). The two must lead to
opposite outcomes: a broken daemon is a 503, a truncated log is an accepted
submission with partial coverage.

`ScanStream` therefore wraps `r` in a reader that records the first read error
it sees. When `Scan` returns an error, the recorder decides:

- **recorder holds an error** → the source broke. End the loop, return a nil
  error and `Complete: false`.
- **recorder is empty** → the scanner failed. Return the error unchanged.

Bytes from the window that was interrupted are **not** counted. That window's
INSTREAM session was aborted mid-write, so clamd never issued a verdict on it;
`Coverage.Bytes` stops at the end of the last window that returned one.

### Return values

| Outcome | Verdict | Coverage | error |
| --- | --- | --- | --- |
| Stream fully scanned, clean | zero | `{Complete: true, Bytes: n}` | nil |
| Budget exhausted, clean so far | zero | `{Complete: false, Bytes: budget}` | nil |
| Source read failed mid-stream | zero | `{Complete: false, Bytes: through the last verdicted window}` | nil |
| Infected in window k | `{Infected, Signature}` | `{Complete: false, Bytes: through window k}` | nil |
| Underlying `Scan` failed | zero | zero | non-nil |
| Context cancelled | zero | zero | `ctx.Err()` |

An infected verdict returns immediately: windows after the detection are never
scanned. Coverage is still reported honestly rather than zeroed, even though
the caller rejects the submission and ignores it.

Note that the two incomplete-but-accepted outcomes stay distinguishable from
the numbers alone, without a third field: `Bytes == Budget` means the budget
ran out, `Bytes < Budget` means the stream broke. That is what lets the portal
log a useful reason without persisting one.

## 2. The scan path in `/submit`

`portal/submit.go` replaces the current single `h.AVScanner.Scan(ctx, file)`
call with a two-step scan of extracted content, in a `scanArchive` helper
alongside the existing `autoChecks` — a function rather than an inline block so
that the `Close` calls fire when the scan ends rather than at the end of the
whole request:

```go
func scanArchive(ctx context.Context, file io.ReadSeeker, opts submission.Options,
	metadata []byte, scanner clamav.Scanner, budget int64) (clamav.Verdict, clamav.Coverage, error)
```

1. **`metadata.json`** — one plain `Scan` over `bytes.NewReader(metadata)`. The
   bytes are already in memory from `ValidateArchive`, so this costs no extra
   pass over the upload. It is small and bounded (64 KiB), so it does not need
   windowing.
2. **The log** — `file.Seek(0, io.SeekStart)`, then `submission.OpenLog`, then
   `gzip.NewReader` over that, then
   `clamav.WindowedScanner{Scanner: scanner, Budget: budget}.ScanStream`.

The overall handler ordering is unchanged: validate → scan → `Store.Save` →
score → record the log entry. The scan stays before `Store.Save`, so infected
content is never stored. `Coverage` is captured in a variable declared before
the scan block and read when the `Entry` is built, which already happens last.

### `AVScanner` nil means no scan, and no claim

The whole block stays behind the existing `if h.AVScanner != nil` guard, and
that guard now carries more weight than it used to: it is what keeps the
dashboard from asserting anything about a submission nothing examined. When it
is nil, no scan runs and `Entry.Scan` stays nil.

`cmd/portal-dev/main.go:55` already builds a `SubmitHandler` with no
`AVScanner`, so nil is a real configuration and not only a test shortcut —
`portal/submit.go`'s field comment, which claims "nil only shows up in tests
that don't care about the AV step", is already wrong and is corrected.

**`cmd/portal` stops falling back to `clamav.NoopScanner`.** With
`-clamav-addr` unset it leaves `AVScanner` nil instead. Without this change the
no-op scanner would return a clean verdict over every window and produce
`Coverage{Complete: true}`, so the dashboard would render `scan ✓` on a
submission no antivirus ever looked at — reintroducing at the presentation
layer exactly the silent fail-open the windowed scan exists to avoid. The
startup warning `log.Println` is unchanged; it is still the thing that tells an
operator scanning is off.

`NoopScanner` stays in the `clamav` package for tests, where a scanner that
reports clean and claims coverage is precisely what is wanted. As a bonus, the
production binary no longer decompresses the whole log to feed a scanner that
discards it.

### Response codes

| Condition | Status | Change |
| --- | --- | --- |
| `metadata.json` or any log window infected | 422 | unchanged shape |
| A `Scan` returns an error not attributable to the source | 503, logged | unchanged |
| `gzip.NewReader` fails on the log entry | **400** | new |
| The log's gzip stream breaks mid-read | 200, coverage incomplete, logged | new |
| Budget exhausted before EOF | 200, coverage incomplete, logged | new |
| `AVScanner` nil | 200, `Entry.Scan` nil | new |

### Corrupt and truncated logs

`ValidateArchive` checks only the two gzip magic bytes of `gnoland.log.gz`; it
never decompresses the entry. A corrupt or truncated inner gzip therefore
passes validation and the AV scan today, and surfaces only as a zero-valued
`LogWindowCheck` at scoring time, because
[`scoring.scanLogWindow`](../../../scoring/checks.go) treats a gzip error as
"no timestamps found" by design.

Once the AV pass actually reads that stream, the two failure shapes stop being
the same thing, and they are handled differently:

- **`gzip.NewReader` fails outright** — the header is not a gzip header, even
  though `ValidateArchive` accepted its first two bytes. Nothing was ever
  readable, so nothing can be scanned, and storing it would be a fail-open on
  a file whose content is entirely unexamined. **400**, naming
  `gnoland.log.gz`.
- **The stream breaks partway through** — the header parsed and some windows
  came back clean before the read failed. This is what a full disk, a killed
  collection process, or an interrupted `tar` actually produces, and it is not
  an exotic case. The submission is **accepted** and recorded with
  `Complete: false`, exactly like an exhausted budget: what was scanned was
  scanned, and the exercise keeps a diagnostic it can still use. Scoring reads
  the same broken stream afterwards and reports `Truncated`, awarding partial
  credit — unchanged from today.

The rule is: accept what could be read, reject what could never be started.
The portal logs the incomplete coverage either way, deriving the reason from
`Bytes` against the configured budget.

## 3. Recording the coverage

`portal.Entry` gains one field:

```go
type Entry struct {
	ID              string    `json:"id"`
	Moniker         string    `json:"moniker"`
	OperatorAddress string    `json:"operator_address"`
	Filename        string    `json:"filename"`
	SubmittedAt     time.Time `json:"submitted_at"`

	// Scan is what the antivirus actually examined. Non-nil is an
	// affirmative claim: a real Scanner was wired and returned a verdict
	// over Bytes bytes of extracted content. Nil claims nothing — either
	// the entry predates windowed scanning, or no scanner was wired at
	// all. Nothing in between: a scan that errors or finds something
	// fails the submission outright, so no Entry is written for it.
	Scan *clamav.Coverage `json:"scan,omitempty"`
}
```

A pointer, not a value, for two reasons that happen to want the same thing.
`submissions.jsonl` is append-only and already holds entries written before
this change; with a flat `bool` those legacy lines would decode as
`complete: false` and render as partially scanned when the old whole-archive
path in fact scanned them in full. And a nil `AVScanner` has to be expressible
as "no claim" rather than as any value of `Complete`, which is what stops the
dashboard from vouching for an unscanned submission. `nil` says "unknown",
the only true statement in both cases. It is the same convention
`AdminSubmission.Score *scoring.Result` already uses for "no record yet".

The field reuses `clamav.Coverage` rather than declaring a parallel
`portal.ScanCoverage`. `portal` already imports `clamav`, and one type with one
set of JSON tags is better than two that must be kept in step. A comment on the
field records that those tags are now a persisted format.

`FileLog.Record`, `FileLog.Entries`, and `FileLog.Delete` need no changes —
they marshal and unmarshal whole `Entry` values, so the new field round-trips
on its own. `AdminSubmission` embeds `Entry`, so `scan` reaches the dashboard's
JSON without touching `portal/admin.go` either.

## 4. Configuration and documentation

### The budget knob

| Where | What |
| --- | --- |
| `cmd/portal/main.go` | `-av-scan-budget`, default `defaultAVScanBudget = 32 << 30` |
| `portal.SubmitHandler` | `AVScanBudget int64`; zero uses the `clamav` package default |
| `cmd/portal` `muxDeps` | `AVScanBudget int64`, wired through to the handler |
| `.env` / `.env.example` | `AV_SCAN_BUDGET=34359738368` |
| `docker-compose.yml` | `- -av-scan-budget=${AV_SCAN_BUDGET:-34359738368}` |

The flag's usage string states what exceeding it does: the submission is
accepted and recorded as partially scanned, not rejected.

### Naming: two decompressed-byte budgets on one log

After this change the same `gnoland.log.gz` is bounded twice in decompressed
bytes, for unrelated reasons and at values 32x apart. They are kept distinct by
name rather than consolidated, because consolidating forces a bad compromise in
either direction: at 1 GiB the AV scan would cover almost nothing of a large
archive, and at 32 GiB the log-window scan would spend minutes of CPU
decompressing to find timestamps the first and last lines already give.

- `scoring.maxLogScanBytes` is renamed **`maxLogWindowBytes`**. "Scan" becomes
  the antivirus's word; the scoring constant is named for what it bounds — the
  investigation-window read — and exceeding it costs partial credit via
  `LogWindowCheck.Truncated`, not a rejection.
- The AV budget is `-av-scan-budget` / `AV_SCAN_BUDGET`, prefixed so it is
  unmistakably the antivirus one.

The rename is mechanical but wider than `scoring/checks.go`. Every site:

| File | Line | What |
| --- | --- | --- |
| `scoring/checks.go` | 15, 31 | the doc comment and the constant |
| `scoring/checks.go` | 69, 79 | the use in `AutoChecks` and a doc comment in `scanLogWindow` |
| `scoring/score.go` | 70 | a comment naming the budget in `LogQualityScore`'s reasoning |
| `scoring/checks_test.go` | 180, 199 | two call sites |
| `cmd/portal/main.go` | 84 | `defaultMaxLogSize`'s comment |

### Text that this change makes wrong

- **`-clamav-timeout`'s usage string** says it "must comfortably cover
  streaming a whole `-max-upload-size` archive to clamd". It now bounds a
  single window — at most 1 GiB, roughly 7 seconds at the measured rate. The
  15-minute default stays (it is harmless, and the request context still bounds
  the whole handler); only the text changes.
- **`clamd.conf`'s comment** explains `StreamMaxLength` in terms of the whole
  upload. It now only has to cover one window plus its overlap. The value stays
  at `2147483647` for headroom; the comment says why that is now slack rather
  than a binding constraint.
- **`cmd/portal/main.go`'s `defaultMaxUploadSize` comment** attributes the odd
  `2147483647` to libclamav's ceiling. That is no longer the reason it is set
  there — the archive is not scanned as a file any more. It becomes: this is
  where the ceiling was left when the wall stopped binding, and raising it is a
  disk/S3/time question, with `storage.S3Store.Save`'s single `PutObject` (5 GiB
  S3 limit) as the first thing to move.
- **`cmd/portal/main.go`'s `defaultMaxLogSize` comment** points at
  `scoring.maxLogScanBytes` by name; it follows the rename and gains the AV
  budget as the other decompressed bound.
- **`.env.example`'s `MAX_UPLOAD_SIZE` and `MAX_LOG_SIZE` comments** both warn
  that clamd's per-file ceiling binds first — `MAX_LOG_SIZE`'s says a compressed
  entry past ~140 MB decompresses beyond what clamd can scan and gets a 503.
  That is precisely what stops being true. Both are rewritten, and
  `AV_SCAN_BUDGET` is added with a comment explaining the partial-coverage
  outcome.
- **README**: rows for `-av-scan-budget` and `AV_SCAN_BUDGET` in the two
  configuration tables, and a rewrite of "Upload size and ClamAV" / "The 2 GiB
  wall". The wall is still real and still worth documenting — it is why the
  window is 1 GiB — but it now bounds a window rather than an upload. The
  section gains a short description of the windowed scan, of what a partially
  scanned submission means, and of the fact that with `-clamav-addr` unset the
  dashboard shows no scan badge at all rather than a reassuring one.

## 5. Admin dashboard

`cmd/portal/static/admin.js` renders a scan badge in `checksCell`, **outside**
the existing `if (s.score && s.score.scored)` guard: coverage is a property of
the submission, not of the score, and must show on a submission that has not
been scored.

| `s.scan` | Badge |
| --- | --- |
| absent | none — legacy entry, or no scanner wired; no claim either way |
| `complete` true | `badge("ok", "scan ✓")` |
| `complete` false | `badge("caution", "scan partiel — 32 GiB")`, with the real byte count |

The complete case gets a badge of its own rather than rendering nothing,
matching how `genesis ✓` and `version ✓` are always shown: an affirmative
badge is what makes its absence unambiguous. The partial badge carries a
`title` explaining that the rest of the log was not examined.

`admin.js` has no byte formatter; the one at `cmd/portal/static/portal.js:39`
is copied into it. The two files serve different pages and the project has no
shared module, so duplicating ten lines is cheaper than introducing one.

## Testing

### `clamav/windowed_test.go`

The centre of the test strategy is a fake `Scanner` that records the exact
bytes of every window it receives, which is what makes the window geometry
assertable at all:

- A stream shorter than one window produces exactly one `Scan` call, and
  `Coverage{Complete: true, Bytes: len}`.
- A stream spanning three windows produces three calls; window N+1 begins with
  the last `Overlap` bytes of window N; concatenating the windows and removing
  the overlaps reconstructs the input exactly.
- A stream whose length is an exact multiple of the window capacity produces no
  trailing overlap-only window.
- Budget exhausted mid-stream: `Complete` false, `Bytes` equal to the budget,
  no further `Scan` calls.
- Budget exactly equal to the stream length: `Complete` true — the probe finds
  EOF rather than reporting a false truncation.
- A marker straddling a window boundary is seen by the fake in window N+1,
  which is the only way to prove the overlap does its job without a real clamd.
- Infected in window 2: returns immediately, window 3 is never scanned.
- A scanner error is propagated and coverage is zero.
- **A source reader that fails mid-window** — the fake scanner surfaces the
  read error just as `ClamdScanner` would — returns a nil error,
  `Complete: false`, and `Bytes` equal to the end of the *previous* window: the
  interrupted one is not credited.
- The same test with the source failing on the very first window yields
  `Bytes: 0` and still no error.
- A scanner that reads only part of its window: windows still align and the
  byte count is unchanged, proving the drain.
- A cancelled context stops the loop and returns `ctx.Err()`.

### `portal/submit_test.go`

- `metadata.json` is scanned first, with exactly the metadata bytes.
- The log is scanned decompressed, not as the raw archive.
- Infected log → 422, and nothing reaches the store.
- A `gnoland.log.gz` whose first two bytes are the gzip magic but whose header
  is otherwise garbage → 400, and nothing reaches the store.
- A truncated `gnoland.log.gz` → 200, stored, `Entry.Scan.Complete` false with
  `Bytes` below the budget.
- Scanner error on a log window → 503, and nothing reaches the store.
- Happy path → 200, `Entry.Scan.Complete` true and `Bytes` equal to the
  decompressed log length.
- Budget exhausted → 200, `Entry.Scan.Complete` false with `Bytes` equal to the
  budget.
- **`AVScanner` nil → 200, no scan attempted, `Entry.Scan` nil.** This is the
  regression guard for the dashboard vouching for an unscanned submission, and
  it is also what the existing handler tests built without an `AVScanner`
  exercise implicitly.
- The existing end-to-end scoring test still produces the same
  `scoring.Result`: the AV pass and the scoring pass read the archive
  independently and must not interfere.

### Elsewhere

- `portal/log_test.go`: an `Entry` with a `Scan` round-trips through
  `Record`/`Entries`, a legacy line without `scan` decodes to `nil`, and
  `Delete` preserves the field on the entries it rewrites.
- `scoring/checks_test.go`: rename only, no behavioural change.
- `cmd/portal/main_test.go`: `-av-scan-budget` reaches the handler.
- `go test ./...` for the repo, then a manual end-to-end run against
  `test/samourai-crew-huge-20260805-2232UTC.tar.gz` with a real clamd on the
  compose network — the archive that motivated this work must be accepted, and
  the dashboard must show `scan ✓`.
