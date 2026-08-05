# Configurable Upload Limits, Streamed Log Scanning, and Upload Progress

## Overview

A real 100 MB test archive (`test/samourai-crew-big-20260804-2059UTC.tar.gz`,
whose `gnoland.log.gz` entry is ~101 MB) is rejected by the portal with
`archive entry "gnoland.log.gz" exceeds the 67108864 byte limit`. Three
distinct problems surface from that one failure, and this spec addresses all
three together because they all live on the same upload path.

1. **The limits aren't operator-configurable.** `cmd/portal/main.go` already
   has `-max-upload-size` and `-max-log-size` flags, but `docker-compose.yml`
   hardcodes the former and never passes the latter — so `-max-log-size`
   silently falls back to its 64 MiB Go default, which is what rejected the
   archive. Neither is reachable from `.env`.

2. **Raising `-max-log-size` costs resident memory.** `submission.Result`
   carries the whole compressed `gnoland.log.gz` in memory from the moment
   `ValidateArchive` returns until the request ends — across the ClamAV scan
   and the S3 upload, which together can take minutes on a large archive —
   even though the bytes are only read at the very end, by
   `scoring.AutoChecks`, which streams them and never needed a slice in the
   first place. With no concurrency cap on `/submit`, worst-case memory is
   `max-log-size × concurrent requests`, unbounded.

3. **A large upload gives the validator no feedback.** `portal.js` posts the
   archive with `fetch()` and simply awaits the response. On a 100 MB archive
   over a slow link, followed by a ClamAV scan that may take minutes, the page
   sits inert with no indication that anything is happening.

Out of scope: a concurrency cap (semaphore) on `/submit` — section 2 removes
the per-request memory that would have motivated one; client-side file size
pre-checks; resumable or multipart uploads; serving the configured limits to
the frontend dynamically.

## 1. Configurable limits

### `.env` / `.env.example`

Two new variables, both in bytes, following the commenting style already used
in `.env`:

```bash
# Maximum accepted size of the whole upload, in bytes. Must stay <=
# clamd.conf's StreamMaxLength (also 2 GiB) or scannable uploads are
# rejected with 503 instead of a clean error.
MAX_UPLOAD_SIZE=2147483648

# Maximum accepted size of the compressed gnoland.log.gz entry inside the
# archive, in bytes. The entry is streamed, never buffered, so this costs
# decompression time rather than memory — but see MAX_UPLOAD_SIZE, which
# bounds the archive containing it, and scoring's own 1 GiB decompressed
# scan budget.
MAX_LOG_SIZE=268435456
```

`MAX_UPLOAD_SIZE` keeps the current 2 GiB value. `MAX_LOG_SIZE` is **raised
from 64 MiB to 256 MiB**: ~2.5x headroom over the real 101 MB test archive,
while staying well under `scoring.maxLogScanBytes` (1 GiB of *decompressed*
plaintext), which is the separate inner bound on the log-window scan.

### `docker-compose.yml`

In the `portal` service's `command:` list:

- `- -max-upload-size=2147483648` becomes
  `- -max-upload-size=${MAX_UPLOAD_SIZE:-2147483648}`
- add `- -max-log-size=${MAX_LOG_SIZE:-268435456}`

The `:-` defaults keep `docker compose up` working with an `.env` that
predates this change.

### `cmd/portal/main.go`

`defaultMaxLogSize` changes from `64 << 20` to `256 << 20`, so the flag
default matches the compose default for anyone running the binary directly.

Its doc comment needs a full rewrite, not a value bump. It currently justifies
the 64 MiB figure on memory grounds ("these bytes are held in memory for the
whole request", "far more than the 8 MiB `scoring.scanLogWindow` will ever
decompress") and both halves of that are wrong after this spec: section 2
removes the buffering entirely, and `scoring.maxLogScanBytes` is `1 << 30`
(1 GiB), not 8 MiB. The replacement comment states what the cap actually does
now — bound the *compressed* bytes streamed out of the archive, with
`maxLogScanBytes` as the separate bound on *decompressed* bytes read during
the scan. The `-max-log-size` flag's usage string loses "these bytes are held
in memory for the whole request" for the same reason.

No other Go changes are needed for this section; the flags already exist and
are already wired through `muxDeps`.

### `README.md`

The flag table's `-max-log-size` row says "default 64 MiB. These bytes stay in
memory for the whole request" — both halves change. The environment-variable
table gains `MAX_UPLOAD_SIZE` and `MAX_LOG_SIZE` rows, noting they are read by
`docker-compose.yml` and passed through as the corresponding flags (unlike the
other rows, which the binary reads directly from the environment). The "Upload
size and ClamAV" section already explains the `clamd.conf` coupling correctly
and needs only to name `MAX_UPLOAD_SIZE` alongside `-max-upload-size`.

## 2. Streaming the log instead of buffering it

The buffer turns out to be avoidable entirely, not merely shortenable.
`Result.LogGz` has exactly one consumer, and the first thing it does is turn
the slice back into a stream: `gzip.NewReader(bytes.NewReader(logGz))`
(`scoring/checks.go`). Nothing indexes it, measures it, or needs random
access. So the buffer exists only to be converted back into what it already
was on the way out of the tar reader.

Removing it makes memory **O(1) regardless of `MAX_LOG_SIZE`**, which is a
stronger result than deferring the allocation: the limit stops being a memory
knob at all and becomes purely a decompression-time knob.

### `submission/archive.go`

`Result` drops its `LogGz` field:

```go
type Result struct {
	Metadata []byte
}
```

`ValidateArchive` still enforces the size limit and the gzip magic-byte check
on `gnoland.log.gz`, but it stops materialising the entry to do so. Dropping
the `Result` field alone would not have been enough: the entry was read with
`io.ReadAll(io.LimitReader(tr, limit+1))`, so the whole thing was allocated
just to measure it and inspect two bytes. That path becomes a fixed two-byte
read for the magic check followed by a counted drain to `io.Discard` under the
same `limit+1` bound — the boundary semantics are unchanged (exactly `limit`
accepted, `limit+1` rejected), and so are the error messages, but peak memory
for the log entry is now O(1) instead of O(`MaxLogSize`).

`metadata.json` keeps its `io.ReadAll`: it is bounded to 64 KiB and its
content is what the caller actually needs.

Every existing structural guarantee (allowlisted names, no duplicates, regular
files only, both entries present) is unchanged. `ValidateArchive` remains the
sole validation gate; what follows is a read path, not a second gate.

A new exported function opens the log as a stream:

```go
// OpenLog walks r — which must be a rewound reader over an archive
// ValidateArchive has already accepted — and returns a reader over the
// gnoland.log.gz entry, bounded to opts.MaxLogSize. The bytes are never
// buffered: callers stream them, so an archive at the size limit costs
// decompression time rather than that much resident memory.
//
// The returned ReadCloser owns the underlying gzip reader; callers must
// Close it. It is only valid until Close, and reading it consumes r.
//
// OpenLog does not re-run ValidateArchive's structural checks (allowed
// names, duplicates, file types, required entries) — those are that
// function's job and are not duplicated here. A missing log entry is
// reported as an error rather than an empty stream, since for an archive
// ValidateArchive accepted it can only mean the caller passed a different
// reader.
func OpenLog(ctx context.Context, r io.Reader, opts Options) (io.ReadCloser, error)
```

It builds the same `gzip.NewReader` + `tar.NewReader` pair, advances to
`LogFileName`, and returns a `ReadCloser` wrapping
`io.LimitReader(tr, opts.MaxLogSize)` whose `Close` closes the gzip reader.
The tar reader's per-entry reader stays valid as long as `Next` isn't called
again, which it isn't — so the returned stream reads straight through from
the archive with no intermediate copy.

Note the returned reader is bounded by `MaxLogSize` exactly (not `limit+1`):
overflow detection is `ValidateArchive`'s job and has already happened by
this point, so here the bound is pure defense in depth against a caller that
skipped validation.

### `scoring/checks.go`

`AutoChecks` and `scanLogWindow` take an `io.Reader` instead of a `[]byte`:

```go
func AutoChecks(meta submission.Metadata, logGz io.Reader, cfg exercise.Config) (genesisMatch, versionSupported bool, window LogWindowCheck)

func scanLogWindow(logGz io.Reader, cfg exercise.Config, budget int64) LogWindowCheck
```

The body change is one line — `gzip.NewReader(bytes.NewReader(logGz))` becomes
`gzip.NewReader(logGz)` — which drops the `bytes` import, its only use in the
file. Everything downstream (the `io.LimitedReader` budget, the
`bufio.Scanner`, `scanHitCap`, the truncation semantics) already worked on
streams and is untouched. The doc comments on both functions, which currently
describe `logGz` as "submission.Result.LogGz — the same bounded bytes
ValidateArchive already read", are updated to describe the
`submission.OpenLog` stream instead, keeping the existing warning that this
must not become a second independent read of the raw upload.

### `portal/submit.go`

Inside the existing `if h.Exercise != nil` block, the `cfg.Configured()`
branch opens the stream rather than reading a field:

```go
if cfg.Configured() {
	genesisMatch, versionSupported, window, err := autoChecks(r.Context(), file, h.ArchiveOptions, metadata, cfg)
	if err != nil {
		log.Printf("scoring: unable to re-read log for %s: %v", header.Filename, err)
	} else {
		result.Scored = true
		// ... unchanged: GenesisMatch, VersionSupported, LogWindow,
		// TieredTimeScore, MetadataScore, LogQualityScore
	}
}
```

`autoChecks` is a small unexported helper in `portal/submit.go` that seeks
`file` back to 0, calls `submission.OpenLog`, `defer`s its `Close`, and
forwards to `scoring.AutoChecks`. Keeping it a function rather than inlining
the four steps is what makes the `defer Close` fire promptly, at the end of
the scoring work, instead of at the end of the whole handler.

Three consequences worth stating explicitly:

- When the exercise is **not** configured for Phase 3 scoring, the log is
  never opened at all — the archive is validated, scanned, and stored without
  a second pass over the entry.
- This happens **after** `Store.Save`, so a failure here cannot cost the
  validator a successful submission. It is logged and scoring is skipped for
  that submission, matching how an `h.Exercise.Get()` failure is already
  handled directly above.
- `result.Scored` moves inside the success branch. Today it is set
  unconditionally within `cfg.Configured()`; with a failure path that can
  now skip the checks, a `Scored: true` record carrying zero-valued checks
  would claim a submission was scored when it wasn't.

### Effect

The log entry is never held in memory at any point in the request — not
during the AV scan, not during the S3 upload, not during scoring. Worst-case
memory for `/submit` no longer scales with `MAX_LOG_SIZE`, which is why no
concurrency cap is needed to make raising that limit safe. The cost is one
additional bounded gzip+tar pass over an already-seekable `multipart.File`:
CPU and I/O, not memory.

### Operational note: what actually binds if you want much larger logs

`MAX_LOG_SIZE` alone does not decide whether a large log is accepted. Raising
it toward, say, 2 GiB requires moving four other things, and this is the list
to check before changing it:

1. **`MAX_UPLOAD_SIZE`** — `gnoland.log.gz` is already compressed, so the
   archive's outer gzip barely shrinks it. A 2 GiB log means a ~2 GiB upload,
   which `http.MaxBytesReader` rejects first.
2. **`clamd.conf`** — `StreamMaxLength`, `MaxFileSize`, and `MaxScanSize` are
   all `2G`. The AV step fails closed (503), so exceeding these produces
   "antivirus unavailable" rather than a clear size error.
3. **`scoring.maxLogScanBytes`** — 1 GiB of *decompressed* plaintext. A
   multi-GiB compressed log decompresses well past it, so the window scan
   stops early and reports `Truncated`, costing partial credit on
   `LogQualityScore`. This degrades quietly: the submission succeeds, the
   score is just lower.
4. **Disk** — the multipart form spills past 32 MiB to a temp file, and clamd
   spools its own copy in `TemporaryDirectory`. Budget roughly twice the
   archive size in free disk per concurrent submission.

## 3. Upload progress UI

### Why `XMLHttpRequest`

`fetch()` exposes no progress events for the *request* body, so the `/submit`
call in `portal.js` moves to `XMLHttpRequest`, which does
(`xhr.upload.onprogress`, with `loaded` and `total`). The `/auth/challenge`
and `/auth/verify` calls stay on `fetch` — small JSON requests with nothing
to report. A small `parseJSONText(text, status)` helper mirrors the existing
`parseJSONResponse` guard so a non-JSON response (a proxy error page) still
produces a readable message instead of throwing.

### Markup (`index.html`, inside `#step-upload`, after the Submit button)

```html
<div id="upload-progress" hidden>
  <progress id="upload-bar" max="100"></progress>
  <p id="upload-status" aria-live="polite"></p>
</div>
```

The native `<progress>` element is deliberate: it is announced by screen
readers without extra ARIA, and **omitting its `value` attribute renders it
indeterminate**, which gives the server-processing state its animation for
free.

### States

| State | `<progress>` | `#upload-status` |
| --- | --- | --- |
| Idle | container hidden | — |
| Transferring | `value` set from `loaded/total` | `Uploading — 43.2 / 96.2 MB (45%)` |
| Server processing | `value` removed (indeterminate) | `Upload complete. The server is scanning and validating your archive — this can take several minutes for a large file. Keep this tab open.` |
| Done / error | container hidden | — |

Transitions: `xhr.upload.onprogress` drives the transferring state;
`xhr.upload.onload` (last byte handed to the network) switches to server
processing; `xhr.onload` / `xhr.onerror` hides the container and hands off to
the existing `#step-done` or `#upload-error` paths.

The 100% point means "bytes handed to the network stack", not "received and
processed by the server". The server-processing state exists precisely to
make that gap explicit rather than let a full bar look like a hang.

The Submit button is `disabled` while transferring and processing (a
double-click must not start a second 100 MB upload) and re-enabled on error
so a retry is possible. Byte counts are rendered via a small `formatBytes`
helper (MB/GB, one decimal) rather than raw byte counts.

### CSS (`portal.css`)

Style `progress` with the existing tokens — `--brand` fill, `--surface`
track, `border-radius: 6px`, ~0.5rem tall, full width — using
`::-webkit-progress-bar` / `::-webkit-progress-value` and `::-moz-progress-bar`
so both engines match. Because it uses the existing custom properties, dark
mode follows automatically. `#upload-status` is `var(--muted)` at 0.85rem.

## 4. Correcting the stale limits help text

`index.html` currently tells validators "Size limits: `gnoland.log.gz` ≤ 2
GiB, `metadata.json` ≤ 64 KiB, total upload ≤ 10 GiB" — none of which matched
the deployed configuration even before this change. It becomes
"`gnoland.log.gz` ≤ 256 MiB, `metadata.json` ≤ 64 KiB, total upload ≤ 2 GiB
(deployment defaults — your organizer may configure different values)".

The parenthetical is the honest fix for a static string describing a
configurable value: the server's rejection message already reports the real
limit in bytes, so a validator who exceeds a customized limit is never left
guessing.

## Testing

- `submission/archive_test.go`: the existing `Result.LogGz` assertions move to
  `OpenLog`. New cases: `OpenLog` streams the same bytes the archive holds;
  its reader is bounded by `MaxLogSize`; it errors when the log entry is
  absent; it errors on non-gzip input. Existing
  `ValidateArchive` structural tests are unchanged apart from no longer
  reading `LogGz` — including the oversized-log and bad-magic-bytes cases,
  which stay on `ValidateArchive` because that is still where those are
  enforced.
- `scoring/checks_test.go`: mechanical — the helpers that build a `logGz`
  `[]byte` now wrap it in `bytes.NewReader` at the `AutoChecks` /
  `scanLogWindow` call sites. Assertions are unchanged; the truncation and
  non-gzip cases in particular must still behave identically, since they are
  what prove the stream bound and the best-effort error handling survived the
  signature change.
- `portal/submit_test.go`: the two existing scoring tests
  (`TestSubmitHandler_RecordsScoreWhenExerciseConfigured` and
  `TestSubmitHandler_ScoresPendingWhenExerciseNotConfigured`) must pass
  unchanged through the streaming path — they are the regression net for this
  section, since they exercise the full handler end to end.

  The `OpenLog`-failure branch is deliberately **not** covered here. Reaching
  it would require `OpenLog` to fail on the very reader `ValidateArchive` just
  accepted, which cannot happen through the handler — both read the same
  seekable `multipart.File` under the same `Options`. Adding a test seam to
  force it would put production indirection in place solely to reach an
  unreachable branch. `OpenLog`'s error behavior is covered directly at the
  unit level in `submission/archive_test.go` instead, and the branch remains
  worth writing because it is what keeps `result.Scored` honest if the two
  call sites ever diverge.
- `go test ./...` for the whole repo; the frontend has no test harness, so
  the progress UI is verified manually against the large test archive
  (`test/samourai-crew-big-20260804-2059UTC.tar.gz`) with a real ClamAV scan
  in the loop, confirming both the transferring and processing states appear.
