# Validator Fire Drill

A submission portal for the gno.land validator fire drill: validators
authenticate by proving ownership of their `valopers` operator address,
then upload a diagnostic archive for automated validation and storage.

See [`prd.md`](prd.md) for the full product spec, security rationale, and
implementation status of every piece below.

## Quick start

```bash
export PATH="/usr/local/go/bin:$PATH"   # if the Go toolchain isn't already on PATH

ADMIN_PASSWORD=<choose-a-password> go run ./cmd/portal \
  -remote https://rpc.topaz.testnets.gno.land \
  -addr localhost:8080 \
  -upload-dir ./portal-uploads
```

Then open `http://localhost:8080/` for the validator submission flow, and
`http://localhost:8080/admin` (HTTP Basic Auth — any username, password =
`ADMIN_PASSWORD`) for the live submissions dashboard.

### Docker (fastest way to start everything)

No Go toolchain or real AWS credentials needed — `docker compose` starts
the portal, a local S3-compatible backend (MinIO), and ClamAV for malware scanning:

```bash
cp .env.example .env   # fill in REMOTE and ADMIN_PASSWORD at minimum
docker compose up --build
```

Same URLs as above (`http://localhost:8080/` and `http://localhost:8080/admin`).
Everything — the RPC endpoint, admin password, storage credentials, and
published port — is configured through `.env` (see
[`.env.example`](.env.example) for the full list of variables and
defaults). Uploaded archives and the submission log persist across
`docker compose down` / `up` in named volumes.

### Flags and environment variables

| Flag | Required | Description |
|------|----------|-------------|
| `-remote` | yes | gno.land RPC endpoint used to verify operator public keys (e.g. `https://rpc.topaz.testnets.gno.land`) |
| `-addr` | no | Address to listen on (default `localhost:8080`) |
| `-session-ttl` | no | How long an issued session token stays valid (default `5m`) |
| `-upload-dir` | one of `-upload-dir` / `-s3-bucket` | Local directory to save archives into |
| `-s3-bucket` | one of `-upload-dir` / `-s3-bucket` | S3-compatible bucket to save archives into (AWS S3, Scaleway, Cloudflare R2, ...) |
| `-s3-region` | with `-s3-bucket` | S3-compatible region |
| `-s3-endpoint` | with `-s3-bucket`, optional | Custom S3-compatible endpoint (leave empty for real AWS S3) |
| `-log-path` | no | Path to the submission log file the admin dashboard reads (default `./submissions.jsonl`) |

| Environment variable | Required | Description |
|-----------------------|----------|-------------|
| `ADMIN_PASSWORD` | yes | Protects `/admin` and `/admin/submissions` (HTTP Basic Auth, any username) |
| `SESSION_SECRET` | no | Hex-encoded HMAC secret for session tokens. If unset, a random one is generated for the run — fine for a single exercise, not for a long-lived deployment (sessions won't survive a restart) |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | with `-s3-bucket` | Credentials for the S3-compatible backend |

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
5. **Frontend** (`cmd/portal/static/`) — a small, framework-free HTML/JS
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
