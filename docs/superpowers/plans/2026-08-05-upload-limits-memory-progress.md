# Configurable Upload Limits, Streamed Log Scanning, and Upload Progress — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the portal's upload size limits configurable from `.env`, remove the in-memory buffering of `gnoland.log.gz` so those limits cost decompression time instead of RAM, and show validators real upload progress plus a server-processing state.

**Architecture:** `MAX_UPLOAD_SIZE` / `MAX_LOG_SIZE` flow `.env` → `docker-compose.yml` → the `-max-upload-size` / `-max-log-size` flags that already exist. `submission.Result` stops carrying the log bytes; a new `submission.OpenLog` returns a bounded `io.ReadCloser` over the tar entry, and `scoring.AutoChecks` takes an `io.Reader`, so the log is streamed straight out of the archive at scoring time and never held. The frontend swaps `fetch` for `XMLHttpRequest` on `/submit` to get upload progress events, driving a native `<progress>` element.

**Tech Stack:** Go 1.x standard library (`archive/tar`, `compress/gzip`, `io`), Docker Compose, vanilla ES5+ JavaScript and CSS custom properties (no build step, no frontend dependencies).

## Global Constraints

- All size values are **bytes**. `MAX_UPLOAD_SIZE=2147483648` (2 GiB, unchanged). `MAX_LOG_SIZE=268435456` (256 MiB, raised from 64 MiB).
- `.env` is **gitignored** — never `git add` it. Only `.env.example` is tracked. Task 1 edits both; the commit contains only `.env.example`.
- `MAX_UPLOAD_SIZE` must stay at or below `clamd.conf`'s `StreamMaxLength` (currently `2G`). Do not raise it in this work.
- Do not add a concurrency cap / semaphore to `/submit` — explicitly out of scope.
- Do not add a client-side file size pre-check, resumable uploads, or a dynamic limits endpoint — explicitly out of scope.
- The frontend has no build step and no test harness. Plain `.js` / `.css` / `.html` files under `cmd/portal/static/`, embedded via `//go:embed`.
- Every task ends with `go build ./... && go test ./...` passing before the commit.

---

### Task 1: Make the upload limits configurable from `.env`

**Files:**
- Modify: `.env` (local only — NOT committed)
- Modify: `.env.example`
- Modify: `docker-compose.yml`
- Modify: `cmd/portal/main.go:71-81` (the `defaultMaxLogSize` const and comment), `cmd/portal/main.go:98` (the flag usage string)
- Modify: `README.md:62` (flag table row), `README.md` env-var table, `README.md` "Upload size and ClamAV" section

**Interfaces:**
- Consumes: nothing from earlier tasks (this is the first).
- Produces: `MAX_UPLOAD_SIZE` and `MAX_LOG_SIZE` env vars; `defaultMaxLogSize = 256 << 20` in `cmd/portal/main.go`. No Go API changes — later tasks do not depend on this one and it does not depend on them.

- [ ] **Step 1: Add the two variables to `.env.example`**

Append at the end of `.env.example`:

```bash
# Maximum accepted size of the whole upload, in bytes (default 2 GiB).
# Must stay at or below clamd.conf's StreamMaxLength or scannable uploads
# are rejected with a 503 instead of a clean error — see the README
# section "Upload size and ClamAV".
MAX_UPLOAD_SIZE=2147483648

# Maximum accepted size of the compressed gnoland.log.gz entry inside the
# archive, in bytes (default 256 MiB). The entry is streamed, never
# buffered, so this costs decompression time rather than memory. Note
# MAX_UPLOAD_SIZE bounds the archive containing it, and the scorer has its
# own 1 GiB decompressed-plaintext scan budget.
MAX_LOG_SIZE=268435456
```

- [ ] **Step 2: Add the same two variables to `.env`**

Append the identical block to the local `.env`. This file is gitignored; it is edited so the running deployment picks the values up, but it is never staged.

- [ ] **Step 3: Wire both into `docker-compose.yml`**

In the `portal` service's `command:` list, replace:

```yaml
      # Must stay <= clamd.conf's StreamMaxLength.
      - -max-upload-size=2147483648
```

with:

```yaml
      # Must stay <= clamd.conf's StreamMaxLength.
      - -max-upload-size=${MAX_UPLOAD_SIZE:-2147483648}
      # Streamed, not buffered — see submission.OpenLog. The ceiling here
      # is decompression work, not resident memory.
      - -max-log-size=${MAX_LOG_SIZE:-268435456}
```

The `:-` defaults keep `docker compose up` working against an `.env` that predates this change.

- [ ] **Step 4: Raise the Go default and rewrite its comment**

In `cmd/portal/main.go`, replace the whole `defaultMaxLogSize` block (currently lines 71-81) with:

```go
// defaultMaxLogSize caps the gnoland.log.gz entry inside the archive.
// submission's own default is 2 GiB; this deployment standardises lower so
// one submission cannot tie up an unbounded amount of decompression work.
//
// The entry is streamed and never buffered (see submission.OpenLog), so
// this bounds *compressed* bytes read out of the archive rather than
// resident memory. The separate bound on *decompressed* bytes is
// scoring.maxLogScanBytes (1 GiB), which is what stops a small upload from
// expanding without limit during the log-window scan.
//
// 256 MiB is roughly 2.5x the largest real submission seen so far. Raise it
// with -max-log-size (MAX_LOG_SIZE in .env) if real submissions bump into
// it — they are rejected with a clear message when they do. README.md's
// "Upload size and ClamAV" lists what else has to move with it.
const defaultMaxLogSize = 256 << 20 // 256 MiB
```

- [ ] **Step 5: Correct the flag usage string**

In `cmd/portal/main.go:98`, replace:

```go
	maxLogSize := flag.Int64("max-log-size", defaultMaxLogSize, "maximum accepted size in bytes of the gnoland.log.gz entry inside the archive; these bytes are held in memory for the whole request")
```

with:

```go
	maxLogSize := flag.Int64("max-log-size", defaultMaxLogSize, "maximum accepted size in bytes of the gnoland.log.gz entry inside the archive; the entry is streamed rather than buffered, so this bounds decompression work rather than memory")
```

- [ ] **Step 6: Update the README flag table row**

In `README.md`, replace the `-max-log-size` row:

```markdown
| `-max-log-size` | no | Maximum accepted size of the `gnoland.log.gz` entry inside the archive, in bytes (default 64 MiB). These bytes stay in memory for the whole request |
```

with:

```markdown
| `-max-log-size` | no | Maximum accepted size of the `gnoland.log.gz` entry inside the archive, in bytes (default 256 MiB). The entry is streamed, not buffered, so this bounds decompression work rather than memory |
```

- [ ] **Step 7: Add the two env vars to the README env-var table**

In `README.md`, append these two rows to the environment-variable table (after the `S3_ACCESS_KEY` / `S3_SECRET_KEY` row):

```markdown
| `MAX_UPLOAD_SIZE` | no | Read by `docker-compose.yml` and passed through as `-max-upload-size` (default 2 GiB). Unlike the other variables here, the binary does not read it directly. Must stay at or below clamd's `StreamMaxLength` — see [Upload size and ClamAV](#upload-size-and-clamav) |
| `MAX_LOG_SIZE` | no | Read by `docker-compose.yml` and passed through as `-max-log-size` (default 256 MiB). Not read directly by the binary either |
```

- [ ] **Step 8: Name `MAX_UPLOAD_SIZE` in the ClamAV section**

In `README.md`'s "Upload size and ClamAV" section, replace:

```markdown
`clamd.conf` (bind-mounted by `docker-compose.yml`) raises clamd's stream
and file limits to **2 GiB**, matching `-max-upload-size`'s default.
Change one and you must change the other.
```

with:

```markdown
`clamd.conf` (bind-mounted by `docker-compose.yml`) raises clamd's stream
and file limits to **2 GiB**, matching `-max-upload-size`'s default (set
via `MAX_UPLOAD_SIZE` in `.env` under Docker Compose). Change one and you
must change the other.
```

- [ ] **Step 9: Verify the build and the resolved compose config**

Run: `go build ./... && go test ./...`
Expected: builds clean, all existing tests pass (nothing behavioural changed yet).

Run: `docker compose config | grep max-`
Expected: two lines showing `-max-upload-size=2147483648` and `-max-log-size=268435456`, proving the `.env` values resolve rather than falling through to the `:-` defaults.

- [ ] **Step 10: Commit**

```bash
git add .env.example docker-compose.yml cmd/portal/main.go README.md
git commit -m "Make upload and log size limits configurable from .env"
```

Note the absence of `.env` — it is gitignored. If `git status` shows it as untracked or modified, leave it alone.

---

### Task 2: Add `submission.OpenLog`

Purely additive: nothing calls `OpenLog` yet, `Result.LogGz` still exists, and the tree keeps compiling. Task 3 does the switchover.

**Files:**
- Modify: `submission/archive.go` (add `OpenLog` and its `logStream` helper type)
- Test: `submission/archive_test.go` (add four tests; add the `io` import)

**Interfaces:**
- Consumes: existing `submission` package internals — `LogFileName` (`"gnoland.log.gz"`), `Options{MaxLogSize, MaxMetadataSize int64}`, and the unexported `Options.withDefaults()`.
- Produces: `func OpenLog(ctx context.Context, r io.Reader, opts Options) (io.ReadCloser, error)` — Task 3's `portal/submit.go` helper calls exactly this signature. The returned `io.ReadCloser` streams the raw (still gzip-compressed) `gnoland.log.gz` bytes and must be `Close`d by the caller.

- [ ] **Step 1: Write the failing tests**

Add the `io` import to `submission/archive_test.go`'s import block (it currently imports `archive/tar`, `bytes`, `compress/gzip`, `context`, `testing`), then append these four tests:

```go
func TestOpenLog_StreamsTheLogEntry(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: LogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	rc, err := OpenLog(context.Background(), bytes.NewReader(data), Options{})
	if err != nil {
		t.Fatalf("OpenLog: unexpected error: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading the log stream: %v", err)
	}
	if !bytes.Equal(got, validLogContent) {
		t.Errorf("stream = %q, want %q", got, validLogContent)
	}
}

func TestOpenLog_BoundsTheStreamToMaxLogSize(t *testing.T) {
	// Defence in depth, not the primary gate: ValidateArchive has already
	// rejected an oversized entry by the time OpenLog runs. This asserts
	// the returned stream stops on its own rather than trusting that
	// earlier pass, so a caller that skips validation still can't read
	// unbounded bytes.
	data := buildTarGz(t, []tarEntry{
		{name: LogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	rc, err := OpenLog(context.Background(), bytes.NewReader(data), Options{MaxLogSize: 4})
	if err != nil {
		t.Fatalf("OpenLog: unexpected error: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading the log stream: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("read %d bytes, want the stream bounded to 4", len(got))
	}
}

func TestOpenLog_ErrorsWhenLogEntryMissing(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: MetadataFileName, content: validMetadataContent},
	})

	rc, err := OpenLog(context.Background(), bytes.NewReader(data), Options{})
	if err == nil {
		rc.Close()
		t.Fatal("expected an error for an archive with no gnoland.log.gz, got nil")
	}
}

func TestOpenLog_ErrorsOnNonGzipInput(t *testing.T) {
	rc, err := OpenLog(context.Background(), bytes.NewReader([]byte("not gzip at all")), Options{})
	if err == nil {
		rc.Close()
		t.Fatal("expected non-gzip input to be rejected, got nil")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./submission/ -run TestOpenLog -v`
Expected: compile failure — `undefined: OpenLog`.

- [ ] **Step 3: Implement `OpenLog`**

Append to `submission/archive.go` (after `ValidateArchive`):

```go
// OpenLog walks r — which must be a rewound reader over an archive
// ValidateArchive has already accepted — and returns a reader over the
// gnoland.log.gz entry, bounded to opts.MaxLogSize. The bytes are never
// buffered: callers stream them, so an archive at the size limit costs
// decompression time rather than that much resident memory.
//
// The returned ReadCloser owns the underlying gzip reader, so callers must
// Close it. The stream is only valid until then, and reading it consumes r.
//
// OpenLog deliberately does not re-run ValidateArchive's structural checks
// (allowed names, duplicates, file types, required entries) — those are
// that function's job and are not duplicated here. The MaxLogSize bound is
// kept as defence in depth against a caller that skipped validation, not
// because a validated archive could exceed it.
func OpenLog(ctx context.Context, r io.Reader, opts Options) (io.ReadCloser, error) {
	opts = opts.withDefaults()

	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("not a valid gzip stream: %w", err)
	}

	tr := tar.NewReader(gz)
	for {
		if err := ctx.Err(); err != nil {
			gz.Close()
			return nil, err
		}

		hdr, err := tr.Next()
		if err == io.EOF {
			gz.Close()
			return nil, fmt.Errorf("archive is missing required entry %q", LogFileName)
		}
		if err != nil {
			gz.Close()
			return nil, fmt.Errorf("corrupt tar stream: %w", err)
		}
		if hdr.Name != LogFileName {
			continue
		}

		// tr's per-entry reader stays valid only until the next Next call,
		// which is why this returns from inside the loop rather than
		// breaking out to shared cleanup.
		return logStream{Reader: io.LimitReader(tr, opts.MaxLogSize), closer: gz}, nil
	}
}

// logStream ties the bounded per-entry reader to the gzip reader backing
// it, so a single Close releases both.
type logStream struct {
	io.Reader
	closer io.Closer
}

func (s logStream) Close() error { return s.closer.Close() }
```

No new imports are needed — `archive/tar`, `compress/gzip`, `context`, `fmt`, and `io` are all already imported by `submission/archive.go`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./submission/ -run TestOpenLog -v`
Expected: all four PASS.

Run: `go build ./... && go test ./...`
Expected: everything passes — nothing else changed yet.

- [ ] **Step 5: Commit**

```bash
git add submission/archive.go submission/archive_test.go
git commit -m "Add submission.OpenLog to stream the log entry out of an archive"
```

---

### Task 3: Switch scoring to the stream and drop `Result.LogGz`

This task is atomic on purpose: removing the field, changing the `scoring` signatures, and updating the `portal` call site cannot be split without leaving the tree uncompilable between commits.

**Files:**
- Modify: `scoring/checks.go:16-18` (comment), `scoring/checks.go:46-52` (`AutoChecks` doc + signature), `scoring/checks.go:80-81` (`scanLogWindow` signature + body), import block
- Modify: `scoring/checks_test.go:14-27` (`gzipLines` return type), `:231`, `:315`
- Modify: `submission/archive.go:42-54` (`Result` doc + struct), `:88`, `:132-140`, `:149`
- Modify: `submission/archive_test.go:83-96` (drop `LogGz` assertions)
- Modify: `portal/submit.go` (import block, the `cfg.Configured()` branch, new `autoChecks` helper)

**Interfaces:**
- Consumes: `submission.OpenLog(ctx, r, opts) (io.ReadCloser, error)` from Task 2.
- Produces: `scoring.AutoChecks(meta submission.Metadata, logGz io.Reader, cfg exercise.Config) (genesisMatch, versionSupported bool, window LogWindowCheck)` — an `io.Reader` where it was a `[]byte`. `submission.Result` is now `struct { Metadata []byte }`. No later task consumes these.

- [ ] **Step 1: Change the `scoring` signatures (tests first)**

In `scoring/checks_test.go`, change `gzipLines` to return a reader, so the ~10 call sites that pass its result need no edit at all:

```go
func gzipLines(t *testing.T, lines ...string) *bytes.Reader {
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
	return bytes.NewReader(buf.Bytes())
}
```

Then fix the only two call sites that don't go through `gzipLines`.

In `TestScanLogWindow_BudgetBoundsDecompression` (line 231), replace:

```go
	window := scanLogWindow(buf.Bytes(), cfg, budget)
```

with (a `*bytes.Buffer` is already an `io.Reader`):

```go
	window := scanLogWindow(&buf, cfg, budget)
```

In `TestAutoChecks_LogNotGzip` (line 315), replace:

```go
	_, _, window := AutoChecks(submission.Metadata{}, []byte("not gzip at all"), cfg)
```

with:

```go
	_, _, window := AutoChecks(submission.Metadata{}, strings.NewReader("not gzip at all"), cfg)
```

`strings` is already imported in this file.

- [ ] **Step 2: Run the scoring tests to verify they fail**

Run: `go test ./scoring/ -v`
Expected: compile failure — cannot use `*bytes.Reader` as `[]byte`.

- [ ] **Step 3: Change `scoring/checks.go` to take a reader**

Replace `AutoChecks`'s doc comment and signature (lines 46-52) with:

```go
// AutoChecks runs prd.md's Phase 3 "Automatic validation" checks for one
// submission: genesis hash, supported gnoland version, and
// investigation-window coverage of the submitted log. logGz must be the
// stream returned by submission.OpenLog — the same archive entry
// ValidateArchive already accepted, read straight out of the upload and
// never buffered — and never a second, independent read of the raw upload
// (see this repo's Phase 3 design spec, "Security").
func AutoChecks(meta submission.Metadata, logGz io.Reader, cfg exercise.Config) (genesisMatch, versionSupported bool, window LogWindowCheck) {
```

Change `scanLogWindow`'s signature (line 80) from `logGz []byte` to `logGz io.Reader`:

```go
func scanLogWindow(logGz io.Reader, cfg exercise.Config, budget int64) LogWindowCheck {
```

Change its first statement (line 81) from `gzip.NewReader(bytes.NewReader(logGz))` to:

```go
	gz, err := gzip.NewReader(logGz)
```

Remove `"bytes"` from the import block — line 81 was its only use in the file.

Finally, update the `maxLogScanBytes` comment (line 18) which currently reads "independent of the compressed-size cap `submission.ValidateArchive` already applied to logGz" — the cap is now applied by two functions:

```go
// cap submission.ValidateArchive enforces and submission.OpenLog re-applies.
```

- [ ] **Step 4: Run the scoring tests to verify they pass**

Run: `go test ./scoring/ -v`
Expected: all PASS. `TestScanLogWindow_BudgetBoundsDecompression`, `TestScanLogWindow_OverlongLineMarksTruncated`, and `TestAutoChecks_LogNotGzip` matter most here — they prove the budget bound, the truncation signal, and the best-effort handling of unparseable input all survived the signature change.

Run: `go build ./...`
Expected: FAILS in `portal` — `archiveResult.LogGz` is still a `[]byte` being passed where an `io.Reader` is wanted. That is the next step.

- [ ] **Step 5: Drop `LogGz` from `submission.Result`**

In `submission/archive.go`, replace the `Result` doc comment and struct (lines 42-54) with:

```go
// Result holds what ValidateArchive learned. Metadata is the raw,
// still-unvalidated content of metadata.json — pass it to
// ValidateMetadata separately; filename/structure checks and metadata
// *content* checks are different concerns with different failure modes.
//
// The gnoland.log.gz entry is deliberately not carried here. It is
// validated in place and then dropped, so it is never resident for the
// life of a request; callers that need to read it (see the scoring
// package) stream it back out with OpenLog.
type Result struct {
	Metadata []byte
}
```

Delete the `var logGz []byte` declaration (line 88).

In the entry switch (lines 132-140), keep the magic-bytes check and drop the retention:

```go
		switch hdr.Name {
		case LogFileName:
			if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
				return Result{}, fmt.Errorf("%s does not look like a gzip file (bad magic bytes)", LogFileName)
			}
		case MetadataFileName:
			metadata = data
		}
```

Change the final return (line 149) to:

```go
	return Result{Metadata: metadata}, nil
```

- [ ] **Step 6: Drop the `LogGz` assertions from the archive test**

In `submission/archive_test.go`, `TestValidateArchive_Valid` becomes:

```go
func TestValidateArchive_Valid(t *testing.T) {
	data := buildTarGz(t, []tarEntry{
		{name: LogFileName, content: validLogContent},
		{name: MetadataFileName, content: validMetadataContent},
	})

	result, err := ValidateArchive(context.Background(), bytes.NewReader(data), Options{})
	if err != nil {
		t.Fatalf("ValidateArchive: unexpected error: %v", err)
	}
	if string(result.Metadata) != string(validMetadataContent) {
		t.Errorf("Metadata mismatch")
	}
}
```

Leave every other test in the file alone. `TestValidateArchive_RejectsOversizedEntry` and `TestValidateArchive_RejectsBadLogMagicBytes` in particular stay exactly as they are — `ValidateArchive` is still where those are enforced.

- [ ] **Step 7: Add the `autoChecks` helper to `portal/submit.go`**

Add `"context"` to the import block, then append this helper at the end of the file:

```go
// autoChecks runs the Phase 3 automatic checks against the log entry inside
// file, streaming it straight out of the archive rather than holding it in
// memory. file must be the already-validated upload; it is rewound first,
// so callers must not rely on its offset afterwards.
//
// This is a function rather than four inline statements so the stream is
// closed as soon as the checks are done, rather than at the end of the
// whole request.
func autoChecks(ctx context.Context, file io.ReadSeeker, opts submission.Options, meta submission.Metadata, cfg exercise.Config) (genesisMatch, versionSupported bool, window scoring.LogWindowCheck, err error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false, false, scoring.LogWindowCheck{}, fmt.Errorf("rewinding upload: %w", err)
	}

	logGz, err := submission.OpenLog(ctx, file, opts)
	if err != nil {
		return false, false, scoring.LogWindowCheck{}, err
	}
	defer logGz.Close()

	genesisMatch, versionSupported, window = scoring.AutoChecks(meta, logGz, cfg)
	return genesisMatch, versionSupported, window, nil
}
```

- [ ] **Step 8: Switch the scoring call site to the helper**

In `portal/submit.go`, replace the `if cfg.Configured() { ... }` block (currently lines 209-223) with:

```go
			if cfg.Configured() {
				genesisMatch, versionSupported, window, err := autoChecks(r.Context(), file, h.ArchiveOptions, metadata, cfg)
				if err != nil {
					// The archive is already stored and the validator has
					// their submission; a scoring read that fails here is
					// an organizer-side problem, so it is logged and the
					// result stays unscored rather than failing the
					// request. Same reasoning as the Exercise.Get failure
					// handled just above.
					log.Printf("scoring: unable to read the log for %s: %v", header.Filename, err)
				} else {
					// Scored is set here, not before the checks: a
					// Scored: true record carrying zero-valued checks
					// would claim a submission was assessed when the read
					// that would have assessed it failed.
					result.Scored = true
					result.GenesisMatch = genesisMatch
					result.VersionSupported = versionSupported
					result.LogWindow = window
					result.UploadTimeScore = scoring.TieredTimeScore(recordedAt, cfg)
					// Always 25: ValidateMetadata above already gated this
					// submission on a schema-valid metadata.json, so by the
					// time a Result exists at all, this criterion is
					// structurally satisfied — see scoring.LogQualityScore's
					// doc comment for the analogous reasoning on log quality.
					result.MetadataScore = 25
					result.LogQualityScore = scoring.LogQualityScore(window)
				}
			}
```

- [ ] **Step 9: Run the full suite**

Run: `go build ./... && go test ./...`
Expected: everything PASSES. The two handler-level scoring tests are the regression net for this task — confirm by name:

Run: `go test ./portal/ -run 'TestSubmitHandler_(RecordsScoreWhenExerciseConfigured|ScoresPendingWhenExerciseNotConfigured)' -v`
Expected: both PASS, unmodified. The first proves a real archive still scores correctly through the streaming path; the second proves an unconfigured exercise still records an unscored result without opening the log.

Run: `gofmt -l .`
Expected: no output.

- [ ] **Step 10: Commit**

```bash
git add scoring/checks.go scoring/checks_test.go submission/archive.go submission/archive_test.go portal/submit.go
git commit -m "Stream gnoland.log.gz into scoring instead of buffering it"
```

---

### Task 4: Upload progress UI

**Files:**
- Modify: `cmd/portal/static/index.html:88` (stale limits line), `:121-124` (add the progress markup)
- Modify: `cmd/portal/static/portal.js:119-152` (replace the submit handler; add three helpers)
- Modify: `cmd/portal/static/portal.css` (append the `progress` styles)

**Interfaces:**
- Consumes: the `/submit` response shape, unchanged — `{ok, moniker, submitted_at, error}`. Existing page globals `sessionToken`, and the existing helpers `show(id)` and `setError(id, message)`.
- Produces: nothing consumed by other tasks (last task).

- [ ] **Step 1: Add the progress markup**

In `cmd/portal/static/index.html`, replace:

```html
  <input type="file" id="archive-file" accept=".gz,.tar.gz">
  <button id="submit-archive">Submit</button>
  <p class="error" id="upload-error"></p>
```

with:

```html
  <input type="file" id="archive-file" accept=".gz,.tar.gz">
  <button id="submit-archive">Submit</button>
  <div id="upload-progress" hidden>
    <progress id="upload-bar" max="100"></progress>
    <p id="upload-status" aria-live="polite"></p>
  </div>
  <p class="error" id="upload-error"></p>
```

- [ ] **Step 2: Correct the stale size limits line**

In the same file, replace line 88:

```html
      <li>Size limits: <code>gnoland.log.gz</code> ≤ 2 GiB, <code>metadata.json</code> ≤ 64 KiB, total upload ≤ 10 GiB.</li>
```

with:

```html
      <li>Size limits: <code>gnoland.log.gz</code> ≤ 256 MiB, <code>metadata.json</code> ≤ 64 KiB, total upload ≤ 2 GiB. These are the deployment defaults — your organizer may have configured different values, and the error message tells you the real limit if you exceed it.</li>
```

- [ ] **Step 3: Add the three JS helpers**

In `cmd/portal/static/portal.js`, add these after the existing `parseJSONResponse` function (which ends at line 26):

```js
// The XHR twin of parseJSONResponse: the same guard against a response
// that isn't JSON at all (a proxy's plain-text error page), for the one
// request that needs XHR's upload progress events.
function parseJSONText(text, status) {
  try {
    return JSON.parse(text);
  } catch (err) {
    return { error: `Unexpected response from server (status ${status}).` };
  }
}

function formatBytes(n) {
  const mb = n / (1024 * 1024);
  if (mb >= 1024) {
    return (mb / 1024).toFixed(1) + " GB";
  }
  return mb.toFixed(1) + " MB";
}

function setUploadProgress(loaded, total) {
  const pct = total > 0 ? Math.round((loaded / total) * 100) : 0;
  document.getElementById("upload-bar").value = pct;
  document.getElementById("upload-status").textContent =
    `Uploading — ${formatBytes(loaded)} / ${formatBytes(total)} (${pct}%)`;
}

function setUploadProcessing() {
  // Removing value — rather than pinning it to 100 — is what switches the
  // native element into its indeterminate animation. The bytes have left
  // the browser, but the server still has to scan, validate, and store
  // them, and that phase reports no progress of its own. A bar frozen at
  // 100% would read as a hang.
  document.getElementById("upload-bar").removeAttribute("value");
  document.getElementById("upload-status").textContent =
    "Upload complete. The server is scanning and validating your archive — " +
    "this can take several minutes for a large file. Keep this tab open.";
}
```

- [ ] **Step 4: Replace the submit handler**

Replace the whole `document.getElementById("submit-archive").addEventListener(...)` block (lines 119-152) with:

```js
document.getElementById("submit-archive").addEventListener("click", () => {
  setError("upload-error", "");
  const fileInput = document.getElementById("archive-file");
  const file = fileInput.files[0];
  if (!file) {
    setError("upload-error", "Choose the diagnostic archive to upload.");
    return;
  }

  const form = new FormData();
  form.append("archive", file, file.name);

  const button = document.getElementById("submit-archive");
  const progress = document.getElementById("upload-progress");

  // Disabled for the whole in-flight window, not just the transfer: a
  // second click during the AV scan would start another upload of the
  // same multi-hundred-megabyte archive.
  button.disabled = true;
  progress.hidden = false;
  setUploadProgress(0, file.size);

  // fetch() reports no progress for the request body, so this one call
  // uses XMLHttpRequest; /auth/challenge and /auth/verify stay on fetch.
  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/submit");
  xhr.setRequestHeader("Authorization", "Bearer " + sessionToken);

  xhr.upload.addEventListener("progress", (e) => {
    if (e.lengthComputable) {
      setUploadProgress(e.loaded, e.total);
    }
  });

  // Fires when the last byte is handed to the network stack — which is
  // not the same as the server having received and processed it.
  xhr.upload.addEventListener("load", setUploadProcessing);

  xhr.addEventListener("load", () => {
    progress.hidden = true;
    button.disabled = false;

    const data = parseJSONText(xhr.responseText, xhr.status);
    if (xhr.status < 200 || xhr.status >= 300 || !data.ok) {
      setError("upload-error", data.error || "Submission failed.");
      return;
    }

    document.getElementById("done-message").textContent =
      `Archive for "${data.moniker}" received (submitted_at: ${data.submitted_at}).`;
    show("step-done");
  });

  xhr.addEventListener("error", () => {
    progress.hidden = true;
    button.disabled = false;
    setError("upload-error", "Network error while uploading.");
  });

  xhr.send(form);
});
```

- [ ] **Step 5: Style the progress element**

Append to `cmd/portal/static/portal.css`:

```css
#upload-progress {
  margin: 0.75rem 0;
}

/* Styling <progress> needs all three vendor pseudo-elements: the bare
   rules cover Firefox's track and the legacy fallback, the ::-webkit-*
   pair covers Chrome/Safari. All of them use the existing custom
   properties, so dark mode follows without a second set of rules. */
progress {
  display: block;
  width: 100%;
  height: 0.5rem;
  appearance: none;
  border: none;
  border-radius: 6px;
  background: var(--surface);
  color: var(--brand);
  overflow: hidden;
}

progress::-webkit-progress-bar {
  background: var(--surface);
  border-radius: 6px;
}

progress::-webkit-progress-value {
  background: var(--brand);
  border-radius: 6px;
}

progress::-moz-progress-bar {
  background: var(--brand);
  border-radius: 6px;
}

#upload-status {
  margin: 0.4rem 0 0;
  color: var(--muted);
  font-size: 0.85rem;
}
```

- [ ] **Step 6: Verify the build and the suite still pass**

Run: `go build ./... && go test ./...`
Expected: PASS. The static files are embedded via `//go:embed`, so a syntax-level mistake in a filename would surface here — but not a JavaScript bug, which is what the next step is for.

- [ ] **Step 7: Verify manually against the large archive**

Run: `docker compose up --build`

Then in a browser at `http://localhost:8888/` (or whatever `PORTAL_PORT` is set to), complete the sign-in steps and submit `test/samourai-crew-big-20260804-2059UTC.tar.gz`.

Expected, in order:
1. The bar fills from 0 to 100% with a live "Uploading — X / Y MB (N%)" line, and the Submit button is disabled throughout.
2. At 100% the bar switches to the indeterminate animation and the text changes to the "server is scanning and validating" message. This phase lasts as long as the ClamAV scan does.
3. The submission succeeds — proving the 256 MiB `MAX_LOG_SIZE` from Task 1 accepts the archive that previously failed at 64 MiB — and step 4 ("Submission received") appears.

Also check the browser console is free of errors, and toggle the OS to dark mode to confirm the bar's fill and track both follow the theme.

- [ ] **Step 8: Commit**

```bash
git add cmd/portal/static/index.html cmd/portal/static/portal.js cmd/portal/static/portal.css
git commit -m "Show upload progress and a server-processing state on the submit page"
```

---

## Verification checklist

After all four tasks:

- [ ] `go build ./... && go test ./...` passes
- [ ] `gofmt -l .` prints nothing
- [ ] `docker compose config | grep max-` shows both limits resolved from `.env`
- [ ] `grep -rn "LogGz" --include="*.go" .` returns nothing
- [ ] The large test archive uploads successfully end to end, with both progress states visible
- [ ] `.env` is still uncommitted (`git status` may list it as ignored; it must never appear in a commit)
