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
| `-clamav-timeout` | no | Time budget for one clamd scan, dial included (default `15m`). Must cover streaming a whole `-max-upload-size` archive to clamd |
| `-max-upload-size` | no | Maximum accepted upload, in bytes (default 2 GiB). Keep it at or below clamd's `StreamMaxLength` — see [Upload size and ClamAV](#upload-size-and-clamav) |
| `-max-log-size` | no | Maximum accepted size of the `gnoland.log.gz` entry inside the archive, in bytes (default 256 MiB). The entry is streamed, not buffered, so this bounds decompression work rather than memory |

| Environment variable | Required | Description |
|-----------------------|----------|-------------|
| `ADMIN_OPERATOR_ADDRESSES` | yes | Comma-separated bech32 operator addresses allowed to authenticate against the admin dashboard. Admins sign in the same challenge-tx way validators do (`/auth/challenge`, `/auth/admin/verify`) — an address not in this list gets a 403 even with a valid signature. Replaces the old `ADMIN_PASSWORD` Basic Auth; existing deployments must set this before upgrading or the portal will refuse to start |
| `SESSION_SECRET` | no | Hex-encoded HMAC secret for session tokens. If unset, a random one is generated for the run — fine for a single exercise, not for a long-lived deployment (sessions won't survive a restart) |
| `ADMIN_SESSION_SECRET` | no | Hex-encoded HMAC secret for admin session tokens, kept separate from `SESSION_SECRET` so restarting the portal or rotating one secret doesn't affect the other session type. If unset, a random one is generated for the run |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | with `-s3-bucket` | Credentials for the S3-compatible backend |
| `MAX_UPLOAD_SIZE` | no | Read by `docker-compose.yml` and passed through as `-max-upload-size` (default 2 GiB). Unlike the other variables here, the binary does not read it directly. Must stay at or below clamd's `StreamMaxLength` — see [Upload size and ClamAV](#upload-size-and-clamav) |
| `MAX_LOG_SIZE` | no | Read by `docker-compose.yml` and passed through as `-max-log-size` (default 256 MiB). Not read directly by the binary either |

### Upload size and ClamAV

Every accepted upload is streamed to clamd before it is stored, and the
scan fails closed: an infected verdict *or* any scan failure rejects the
submission. clamd refuses to scan a stream larger than its own
`StreamMaxLength`, which the stock `clamav/clamav` image sets far below
what this portal accepts, so the two limits have to agree or real uploads
get rejected with a 503.

`clamd.conf` (bind-mounted by `docker-compose.yml`) raises clamd's stream
and file limits to **2 GiB**, matching `-max-upload-size`'s default (set
via `MAX_UPLOAD_SIZE` in `.env` under Docker Compose). Change one and you
must change the other.

It also sets `AlertExceedsMax yes`, which is what stops the AV layer from
failing *open*. By default clamd silently skips content that exceeds
`MaxScanSize`/`MaxFileSize` and still answers `stream: OK` — the portal
would store an unscanned archive as clean. With the setting on, clamd
reports a `Heuristics.Limits.Exceeded` pseudo-signature instead, which the
portal treats as a failed scan (503, logged for the operator), not as
malware. If you see those 503s, raise the limits in `clamd.conf`; don't
turn the setting off.

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
5. **Scanning and scoring** (`clamav/`, `exercise/`, `scoring/`) — an
   accepted archive is streamed to clamd (fail-closed: an infected verdict
   or a failed scan rejects the submission and stores nothing), then
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
