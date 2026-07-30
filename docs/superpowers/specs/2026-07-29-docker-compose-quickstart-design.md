# Docker Compose quick start — design

## Purpose

Let a developer start the whole submission portal stack (the `cmd/portal`
binary plus a local S3-compatible backend) with a single `docker compose up`,
without needing a Go toolchain or real AWS credentials.

## Scope

- New `Dockerfile` (multi-stage: Go build → minimal runtime image) for
  `cmd/portal`.
- New `docker-compose.yml` with three services:
  - `portal` — built from the new Dockerfile, runs with `-s3-bucket`
    pointing at the `minio` service.
  - `minio` — official `minio/minio` image, local S3-compatible storage.
    `storage.S3Store` already uses path-style addressing
    (`storage/s3.go`), so it works against MinIO unmodified.
  - `minio-init` — one-shot `minio/mc` container that creates the bucket
    on startup (`mc mb`) and exits.
- New `.env.example` documenting required/optional variables; actual
  `.env` is gitignored.
- `.dockerignore` to keep the build context small.

Out of scope: `cmd/portal-dev` (not containerized — it's a manual
testing tool against a real operator key, not part of "start everything").
Real AWS S3 / Scaleway / R2 usage (still supported by running the binary
directly per the README, unaffected by this change).

## Configuration (`.env`)

| Variable | Required | Notes |
|---|---|---|
| `REMOTE` | yes, no default | gno.land RPC endpoint, passed as `-remote` |
| `ADMIN_PASSWORD` | yes | passed through as-is |
| `SESSION_SECRET` | no | passed through as-is; if unset, portal generates a random one per run |
| `MINIO_ROOT_USER` | yes | MinIO admin user; also used as `S3_ACCESS_KEY` for the portal |
| `MINIO_ROOT_PASSWORD` | yes | MinIO admin password; also used as `S3_SECRET_KEY` for the portal |
| `S3_BUCKET` | no, default `submissions` | bucket name, created by `minio-init` and passed as `-s3-bucket` |
| `PORTAL_PORT` | no, default `8080` | host port mapped to the portal container |

## Persistence

Two named volumes:
- `minio-data` — MinIO's storage backend, so uploaded archives survive
  `docker compose down` / restarts.
- `portal-logs` — mounted at a fixed path inside the `portal` container,
  holding `submissions.jsonl` (the file the admin dashboard reads via
  `-log-path`), so submission history survives restarts.

## Networking

Docker Compose's default network; `portal` reaches MinIO via the service
name (`http://minio:9000`) passed as `-s3-endpoint`. Only `portal`'s port
is published to the host by default.

## Startup

```bash
cp .env.example .env   # fill in REMOTE, ADMIN_PASSWORD, MinIO creds
docker compose up --build
```

Then `http://localhost:8080/` (submission flow) and
`http://localhost:8080/admin` (dashboard, HTTP Basic Auth,
password = `ADMIN_PASSWORD`).

## Testing

No new automated tests — this is deployment tooling, not application
code. Verification is manual: build the stack, confirm the portal serves
`/`, confirm a test upload lands in the MinIO bucket, confirm
`/admin/submissions` reflects it.
