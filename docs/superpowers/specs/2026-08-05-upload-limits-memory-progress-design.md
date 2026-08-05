# Upload Limits, Log Buffer Retention, and Upload Progress

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
   even though the bytes are only read at the very end, by `scoring.AutoChecks`.
   With no concurrency cap on `/submit`, worst-case memory is
   `max-log-size × concurrent requests`, unbounded.

3. **A large upload gives the validator no feedback.** `portal.js` posts the
   archive with `fetch()` and simply awaits the response. On a 100 MB archive
   over a slow link, followed by a ClamAV scan that may take minutes, the page
   sits inert with no indication that anything is happening.

Out of scope: a concurrency cap (semaphore) on `/submit`; client-side file
size pre-checks; resumable or multipart uploads; serving the configured
limits to the frontend dynamically.

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
# archive, in bytes. These bytes are read into memory to run the Phase 3
# log-window scan, so raising this raises peak memory per concurrent
# submission.
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
Its doc comment is corrected while we're there: it currently claims
`scoring.scanLogWindow` "will ever decompress" 8 MiB, but
`scoring.maxLogScanBytes` is `1 << 30` (1 GiB). The revised comment states the
real relationship — this cap bounds *compressed* bytes held in memory,
`maxLogScanBytes` bounds *decompressed* bytes streamed during the scan.

No other Go changes are needed for this section; the flags already exist and
are already wired through `muxDeps`.

## 2. Lazy log extraction

### `submission/archive.go`

`Result` drops its `LogGz` field:

```go
type Result struct {
	Metadata []byte
}
```

`ValidateArchive` still reads the `gnoland.log.gz` entry through the same
`io.LimitReader(tr, limit+1)` bound and still enforces the size limit and the
gzip magic-byte check — it simply stops retaining the bytes past that check,
so they become garbage the moment the loop iteration ends. Every existing
structural guarantee (allowlisted names, no duplicates, regular files only,
both entries present) is unchanged.

A new exported function extracts the log on demand:

```go
// ExtractLog re-reads the gnoland.log.gz entry out of r, which must be a
// rewound reader over an archive ValidateArchive already accepted. It
// exists so callers that need the log bytes (the scoring package) can hold
// them only for as long as they use them, rather than for the whole
// lifetime of the request — see the portal package's submit handler.
//
// It deliberately re-checks only what it must to return trustworthy bytes
// (the size bound and the gzip magic bytes); the structural checks are
// ValidateArchive's job and are not repeated.
func ExtractLog(ctx context.Context, r io.Reader, opts Options) ([]byte, error)
```

`ExtractLog` walks the tar the same way, returns the bounded bytes for
`LogFileName`, and errors if the entry is absent (which cannot happen for an
archive `ValidateArchive` accepted, but is reported rather than returning
nil). The bounded-read-and-check block is factored into a small unexported
helper shared with `ValidateArchive` so the limit semantics (`limit+1`, then
compare) exist in exactly one place.

### `portal/submit.go`

Inside the existing `if h.Exercise != nil` block, the `cfg.Configured()`
branch changes from using `archiveResult.LogGz` to extracting on demand:

```go
if cfg.Configured() {
	logGz, err := rewindAndExtractLog(r.Context(), file, h.ArchiveOptions)
	if err != nil {
		log.Printf("scoring: unable to re-read log for %s: %v", header.Filename, err)
	} else {
		genesisMatch, versionSupported, window := scoring.AutoChecks(metadata, logGz, cfg)
		// ... unchanged: result fields, TieredTimeScore, MetadataScore,
		// LogQualityScore
	}
}
```

where `rewindAndExtractLog` is a small unexported helper in
`portal/submit.go` that seeks `file` back to 0 and calls
`submission.ExtractLog`, so the seek-then-extract pair reads as one step
alongside the two `file.Seek(0, io.SeekStart)` calls already in the handler.
Two consequences worth stating explicitly:

- When the exercise is **not** configured for Phase 3 scoring, the log is
  never extracted at all — the archive is validated, scanned, and stored
  without the bytes ever being retained.
- The extraction happens **after** `Store.Save`, so a failure here cannot
  cost the validator a successful submission. It is logged and scoring is
  skipped for that submission, matching how an `h.Exercise.Get()` failure is
  already handled directly above.

### Effect

Peak retention of the (now up to 256 MiB) log buffer drops from "the entire
request, including the AV scan and the S3 upload" to "a single scoring call
near the end". The cost is one additional bounded gzip+tar pass over an
already-seekable `multipart.File` — CPU and I/O, not memory.

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

- `submission/archive_test.go`: existing assertions on `Result.LogGz` move to
  `ExtractLog`. New cases: `ExtractLog` returns the same bytes
  `ValidateArchive` accepted; it enforces `MaxLogSize`; it rejects a
  non-gzip log entry; it errors when the entry is missing. Existing
  `ValidateArchive` structural tests are unchanged apart from no longer
  reading `LogGz`.
- `portal/submit_test.go`: the end-to-end scoring test must still produce the
  same `scoring.Result` through the new extraction path. New case: a
  submission with an unconfigured exercise succeeds and records an unscored
  result without extracting the log.
- `go test ./...` for the whole repo; the frontend has no test harness, so
  the progress UI is verified manually against the large test archive
  (`test/samourai-crew-big-20260804-2059UTC.tar.gz`) with a real ClamAV scan
  in the loop, confirming both the transferring and processing states appear.
