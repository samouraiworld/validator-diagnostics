# Validator Fire Drill

A submission portal for the gno.land validator fire drill: validators
authenticate by proving ownership of their `valopers` operator address,
then upload a diagnostic archive for automated validation and storage.

See [`prd.md`](prd.md) for the full product spec, security rationale, and
implementation status of every piece below.

## Quick start

```bash
export PATH="/usr/local/go/bin:$PATH"   # if the Go toolchain isn't already on PATH

ADMIN_OPERATOR_ADDRESSES=<comma-separated bech32 admin addresses> go run ./cmd/portal \
  -remote https://rpc.topaz.testnets.gno.land \
  -addr localhost:8080 \
  -upload-dir ./portal-uploads
```

Then open `http://localhost:8080/` for the validator submission flow, and
`http://localhost:8080/admin` for the live submissions dashboard — admins
sign in the same challenge-tx way validators do (see
[Admin endpoints](#admin-endpoints)), restricted to the addresses listed
in `ADMIN_OPERATOR_ADDRESSES`.

### Docker (fastest way to start everything)

No Go toolchain or real AWS credentials needed — `docker compose` starts
the portal, a local S3-compatible backend (MinIO), and ClamAV for malware scanning:

```bash
cp .env.example .env   # fill in REMOTE and ADMIN_OPERATOR_ADDRESSES at minimum
docker compose up --build
```

**The first `up` takes several extra minutes**, and looks like a hang: the
clamav service downloads its ~1 GB signature database before it reports
healthy, and the portal waits for that. Subsequent starts reuse the cached
`clamav-data` volume and are fast.

The URLs are the same as above, but on `PORTAL_PORT` rather than a fixed
8080 — with the `.env.example` default that is `http://localhost:8080/`
and `http://localhost:8080/admin`; set `PORTAL_PORT=8888` and it is
`http://localhost:8888/` instead.

Everything — the RPC endpoint, the admin operator address whitelist,
storage credentials, published port, and the upload size limits
(`MAX_UPLOAD_SIZE` / `MAX_LOG_SIZE`, see
[Upload size and ClamAV](#upload-size-and-clamav) before changing either) —
is configured through `.env`. See [`.env.example`](.env.example) for the
full list of variables and defaults. Uploaded archives and the submission
log persist across `docker compose down` / `up` in named volumes.

### Flags and environment variables

| Flag | Required | Description |
|------|----------|-------------|
| `-remote` | yes | gno.land RPC endpoint used to verify operator public keys (e.g. `https://rpc.topaz.testnets.gno.land`) |
| `-addr` | no | Address to listen on (default `localhost:8080`) |
| `-session-ttl` | no | How long an issued session token stays valid (default `5m`) |
| `-admin-session-ttl` | no | How long an issued admin session token stays valid (default `1h`) |
| `-upload-dir` | one of `-upload-dir` / `-s3-bucket` | Local directory to save archives into |
| `-s3-bucket` | one of `-upload-dir` / `-s3-bucket` | S3-compatible bucket to save archives into (AWS S3, Scaleway, Cloudflare R2, ...) |
| `-s3-region` | with `-s3-bucket` | S3-compatible region |
| `-s3-endpoint` | with `-s3-bucket`, optional | Custom S3-compatible endpoint (leave empty for real AWS S3) |
| `-log-path` | no | Path to the submission log file the admin dashboard reads (default `./submissions.jsonl`) |
| `-exercise-path` | no | Path to the exercise config file written by the admin dashboard (default `./exercise.json`) |
| `-scores-path` | no | Path to the scoring records file (default `./scores.json`) |
| `-clamav-addr` | no (recommended) | clamd address to scan uploads against — `host:port`, or `unix:/path/to/socket`. Unset disables scanning: fine for local dev, **not** for production |
| `-clamav-timeout` | no | Time budget for one clamd scan, dial included (default `15m`). Bounds a single scan window now (at most 1 GiB, roughly 7s at the measured rate), not the whole upload |
| `-max-upload-size` | no | Maximum accepted upload, in bytes (default 2147483647 — a legacy value, not a scan limit: clamd never sees more than one 1 GiB window at a time now). Raising it is a disk/S3/time question — see [Upload size and ClamAV](#upload-size-and-clamav) |
| `-max-log-size` | no | Maximum accepted size of the `gnoland.log.gz` entry inside the archive, in bytes (default 256 MiB). The entry is streamed, not buffered, so this bounds decompression work rather than memory |
| `-av-scan-budget` | no | Maximum decompressed bytes of `gnoland.log.gz` the antivirus examines per submission (default 34359738368 — 32 GiB). Exceeding it records partial scan coverage rather than rejecting the submission — see [Upload size and ClamAV](#upload-size-and-clamav) |

| Environment variable | Required | Description |
|-----------------------|----------|-------------|
| `ADMIN_OPERATOR_ADDRESSES` | yes | Comma-separated bech32 operator addresses allowed to authenticate against the admin dashboard. Admins sign in the same challenge-tx way validators do (`/auth/challenge`, `/auth/admin/verify`) — an address not in this list gets a 403 even with a valid signature. Replaces the old `ADMIN_PASSWORD` Basic Auth; existing deployments must set this before upgrading or the portal will refuse to start |
| `SESSION_SECRET` | no | Hex-encoded HMAC secret for session tokens. If unset, a random one is generated for the run — fine for a single exercise, not for a long-lived deployment (sessions won't survive a restart) |
| `ADMIN_SESSION_SECRET` | no | Hex-encoded HMAC secret for admin session tokens, kept separate from `SESSION_SECRET` so restarting the portal or rotating one secret doesn't affect the other session type. If unset, a random one is generated for the run |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | with `-s3-bucket` | Credentials for the S3-compatible backend |
| `MAX_UPLOAD_SIZE` | no | Read by `docker-compose.yml` and passed through as `-max-upload-size` (default 2147483647 — a legacy value now: clamd never sees more than one 1 GiB scan window at a time, so raising this is a disk/S3/time question instead). Unlike the other variables here, the binary does not read it directly — see [Upload size and ClamAV](#upload-size-and-clamav) |
| `MAX_LOG_SIZE` | no | Read by `docker-compose.yml` and passed through as `-max-log-size` (default 256 MiB). Not read directly by the binary either. Bounds the *compressed* entry; the antivirus no longer caps the decompressed size — that's `AV_SCAN_BUDGET` (coverage) and `scoring.maxLogWindowBytes` (partial credit for automatic scoring only) — see [Upload size and ClamAV](#upload-size-and-clamav) |
| `AV_SCAN_BUDGET` | no | Read by `docker-compose.yml` and passed through as `-av-scan-budget` (default 34359738368, i.e. 32 GiB of decompressed log bytes). Exceeding it records partial scan coverage rather than rejecting the submission — see [Upload size and ClamAV](#upload-size-and-clamav) |

### Upload size and ClamAV

clamd never sees the raw archive. Before anything is stored, the upload is
taken apart and its extracted content is streamed to clamd: `metadata.json`
whole, then the decompressed `gnoland.log.gz` in 1 GiB windows with a 1 MiB
overlap between consecutive windows, so a signature straddling a window
boundary is still caught (`clamav.WindowedScanner`). The scan still fails
closed: an infected verdict *or* the scanner itself failing rejects the
submission and stores nothing.

`clamd.conf` (bind-mounted by `docker-compose.yml`) raises clamd's stream
and file limits to **2147483647 bytes — 2 GiB minus one**. That is
headroom for one window plus its overlap, not a bound tied to
`-max-upload-size` / `MAX_UPLOAD_SIZE` — the two no longer have to agree.

#### The 2 GiB wall

That odd-looking number is a hard ceiling, not a tuning choice. libclamav
cannot scan any single file of 2147483648 bytes or more. Configure a
larger `MaxFileSize` and clamd accepts the value, logs

```text
LibClamAV Warning: Max file-size was set to N bytes. Unfortunately, scanning
files greater than 2147483647 bytes (2 GiB - 1) is not supported.
```

and then rejects oversized input at scan time with
`Heuristics.Limits.Exceeded.MaxFileSize`, which the portal reports as a 503.
Raising the limits does not buy headroom; it only moves the failure later.
(Verified against ClamAV 1.5.3.)

The ceiling applies to **every file clamd extracts**, not just what is
handed to it directly — which is exactly why a scan window is 1 GiB
rather than something closer to the wall: there has to be room left for
the 1 MiB overlap on top without the total ever approaching
2147483647. A validator's `gnoland.log.gz` — however large it decompresses
to — is scanned in bounded pieces instead of as one stream, so it never
reaches this ceiling; a genuinely huge log just means more windows, not a
rejection.

What now bounds a submission's antivirus coverage is `-av-scan-budget` /
`AV_SCAN_BUDGET` (default 32 GiB of decompressed log): once that much has
been examined, scanning stops — not because clamd rejects anything, but as
the tar/zip-bomb defence `prd.md` asks for. See
[What a partial scan means](#what-a-partial-scan-means) below for what
happens to a submission when it does.

It also sets `AlertExceedsMax yes`, which is what stops the AV layer from
failing *open*. By default clamd silently skips content that exceeds
`MaxScanSize`/`MaxFileSize` and still answers `stream: OK` — the portal
would store an unscanned window as clean. With the setting on, clamd
reports a `Heuristics.Limits.Exceeded` pseudo-signature instead, which the
portal treats as a failed scan (503, logged for the operator), not as
malware. If you see those 503s, raise the limits in `clamd.conf`; don't
turn the setting off.

#### What a partial scan means

A submission's antivirus coverage can end early two ways: the budget
(`-av-scan-budget`) runs out, or the log stream itself breaks partway
through — a truncated `gnoland.log.gz`, or clamd disconnecting mid-window.
Either way the submission is **accepted, stored, and badged** — never
silently treated as fully scanned, and never rejected for this reason
alone. Only an actual malware verdict, or the scanner itself being
unreachable, rejects a submission. What was and wasn't examined travels
with the record (`Entry.Scan`, a `Coverage{Complete, Bytes}`), and the
admin dashboard shows it: `scan ✓` for complete coverage, `scan partiel`
with a byte count for partial.

A `gnoland.log.gz` that cannot be decompressed **at all** is different:
nothing in it was ever readable, so nothing in it could be scanned, and
the upload is rejected outright (400) rather than stored unscanned.

With `-clamav-addr` unset, none of this runs: no scanner means no
`Entry.Scan` is ever recorded, and the dashboard shows **no scan badge at
all** on that row — not a reassuring one, none. Scanning is opt-in per
deployment, but a deployment that opts out gets silence, not a false
"clean".

### Admin endpoints

All of these (except `GET /admin` itself, which serves the sign-in screen
and contains no data) sit behind operator-address-whitelist auth: admins
sign in via `POST /auth/challenge` + `POST /auth/admin/verify`, the same
challenge-tx flow validators use, restricted to the addresses in
`ADMIN_OPERATOR_ADDRESSES`. The `POST` routes accept
`Content-Type: application/json` only.

| Route | Purpose |
|-------|---------|
| `GET /admin` | The dashboard itself |
| `GET /admin/submissions` | Recorded submissions joined with their scores, as JSON |
| `GET`/`POST /admin/exercise` | Read or replace the exercise config (announce/deadline times, investigation window, expected genesis hash, supported versions, observations) |
| `POST /admin/submissions/{id}/score` | Enter the one manually judged criterion: incident response quality |
| `GET /admin/summary` | Generate the Markdown participation/score summary to publish on Discord |

### Running an exercise

1. **Configure the exercise before announcing it.** Open `/admin`, fill in
   the exercise form (announce time, deadline, investigation window,
   expected `genesis_sha256`, supported gnoland versions) and save.
   Submissions that arrive while no config exists are stored and logged
   but recorded as "not yet scored" — automatic scoring has nothing to
   score against, and it is not retroactive.
2. Announce the drill and collect submissions.
3. Enter the manual incident response quality score per submission from
   the dashboard. A total is shown as pending until it's in — the score
   is required, and leaving the box empty is rejected rather than
   recorded as a 0 (which is itself a valid score).
4. Generate the summary and publish it. A submission whose log scan
   stopped early is reported as "could not be fully verified" rather than
   as failing to cover the investigation window: the two are different
   claims, and only the second is about the validator.

> **There is no rescore.** Automatic scores are computed once, at submit
> time, from the config in force at that moment — the log bytes they were
> derived from are not retained. So:
>
> - A submission that arrived before the exercise was configured is
>   permanently "not yet scored", and the portal will refuse manual
>   scores for it (409) rather than record a total made only of the
>   manual half.
> - Editing `announced_at`, `deadline_at`, the investigation window, the
>   expected genesis hash or the supported versions **after** submissions
>   have landed leaves every existing score computed against the old
>   values, with no warning and no way to recompute.
>
> Both are recoverable by hand — the archives are still in object storage
> — but nothing in the portal does it for you. Get step 1 right before
> step 2.

## How it works

1. **Authentication** (`auth/`) — a validator proves ownership of their
   `valopers` operator address by signing a server-issued, never-broadcast
   "challenge" transaction with `gnokey sign` (no wallet integration, no
   private key ever touches the server). A verified signature mints a
   short-lived, stateless session token.
2. **Validation** (`submission/`) — the uploaded archive is checked
   against the required naming convention, structure, and security rules
   (no path traversal, no symlinks, bounded decompression, schema-checked
   metadata) before anything is trusted.
3. **Storage** (`storage/`) — the original archive bytes are saved
   unchanged, either to local disk (`LocalStore`, for testing) or
   S3-compatible object storage (`S3Store`).
4. **Orchestration** (`portal/`) — `SubmitHandler` wires the three
   together into `POST /submit`, cross-checking that the archive's claimed
   identity actually matches the authenticated session. Successful
   submissions are recorded to an append-only log that the admin dashboard
   (`portal.AdminAuth`, `portal.AdminSubmissionsHandler`) reads.
5. **Scanning and scoring** (`clamav/`, `exercise/`, `scoring/`) — the
   archive's extracted content is streamed to clamd (fail-closed: an
   infected verdict or a failed scan rejects the submission and stores
   nothing; a scan that stops early because of a stream break or its
   budget is accepted, stored, and recorded as partial — see
   [Upload size and ClamAV](#upload-size-and-clamav)), then
   scored against the configured exercise: genesis hash, gnoland version,
   investigation-window coverage of the submitted log, and upload
   timeliness. The one criterion no code can observe — incident response
   quality — is entered by an admin afterwards.
6. **Frontend** (`cmd/portal/static/`) — a small, framework-free HTML/JS
   UI for both the validator flow and the admin dashboard, embedded into
   the `cmd/portal` binary at build time (`embed.FS`) — one binary, no
   separate deploy step.

## Development

```bash
export PATH="/usr/local/go/bin:$PATH"
go build ./...
go vet ./...
go test ./...
```

Design and implementation history for the frontend/admin work live in
[`docs/superpowers/specs/`](docs/superpowers/specs/) and
[`docs/superpowers/plans/`](docs/superpowers/plans/).
