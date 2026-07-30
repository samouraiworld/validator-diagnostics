# Docker Compose Quick Start Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a developer start the full portal stack (the `cmd/portal` binary plus a local S3-compatible backend) with `docker compose up`, no Go toolchain or real AWS credentials required.

**Architecture:** A `Dockerfile` builds `cmd/portal` into a small runtime image. `docker-compose.yml` wires together three services — `minio` (S3-compatible storage), `minio-init` (one-shot bucket creation), and `portal` (built from the Dockerfile, configured against `minio`) — with config coming from a gitignored `.env` file.

**Tech Stack:** Docker, Docker Compose, `golang:1.26-alpine` build stage, `alpine:3.20` runtime, `minio/minio` + `minio/mc` images.

## Global Constraints

- `REMOTE` (the gno.land RPC endpoint) has no hardcoded default anywhere — it must come from `.env` and fail loudly if unset, matching `cmd/portal`'s own `-remote` requirement.
- Only the `portal` service's port is published to the host; `minio` is reachable only on the compose-internal network.
- `cmd/portal-dev` is out of scope — not containerized.
- Two named volumes for persistence: `minio-data` (uploaded archives) and `portal-logs` (`submissions.jsonl`).

---

### Task 1: Dockerfile and .dockerignore

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`

**Interfaces:**
- Produces: a `portal` image, built from repo root, exposing port `8080`, entrypoint runs the `portal` binary and forwards CLI args from `docker-compose.yml`'s `command:`.

- [ ] **Step 1: Write `Dockerfile`**

```dockerfile
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/portal ./cmd/portal

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/portal /usr/local/bin/portal
EXPOSE 8080
ENTRYPOINT ["portal"]
```

- [ ] **Step 2: Write `.dockerignore`**

```
.git
docs
portal-uploads
portal-dev-uploads
*.jsonl
challenge.json
challenge_response.json
sig.json
.superpowers
```

- [ ] **Step 3: Build the image and verify it runs**

Run: `docker build -t portal-diagnostics-test .`
Expected: build succeeds (no errors from `go build`).

Run: `docker run --rm portal-diagnostics-test -remote=https://rpc.topaz.testnets.gno.land`
Expected: process starts and logs `-upload-dir or -s3-bucket is required` then exits (proves the binary runs inside the container and its own flag validation works) — `ADMIN_PASSWORD` isn't set either, so it may fail on that check first instead; either failure message is acceptable proof the binary runs.

- [ ] **Step 4: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "Add Dockerfile for cmd/portal"
```

---

### Task 2: docker-compose.yml and .env.example

**Files:**
- Create: `docker-compose.yml`
- Create: `.env.example`
- Modify: `.gitignore` (add `.env`)

**Interfaces:**
- Consumes: the `portal` image built by Task 1's `Dockerfile`.
- Produces: three running services (`minio`, `minio-init`, `portal`) reachable at `http://localhost:${PORTAL_PORT:-8080}`.

- [ ] **Step 1: Write `.env.example`**

```
# gno.land RPC endpoint used to verify operator public keys (required, no default)
REMOTE=https://rpc.topaz.testnets.gno.land

# Protects /admin and /admin/submissions (HTTP Basic Auth, any username)
ADMIN_PASSWORD=changeme

# Optional: hex-encoded HMAC secret for session tokens. Leave unset to
# generate a random one per run (fine for local dev; sessions won't
# survive a restart).
#SESSION_SECRET=

# MinIO (local S3-compatible storage) admin credentials — also used as
# the portal's S3_ACCESS_KEY / S3_SECRET_KEY.
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin123

# Bucket name, created automatically on startup.
S3_BUCKET=submissions

# Host port the portal is published on.
PORTAL_PORT=8080
```

- [ ] **Step 2: Write `docker-compose.yml`**

```yaml
services:
  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
    volumes:
      - minio-data:/data

  minio-init:
    image: minio/mc:latest
    depends_on:
      - minio
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
      S3_BUCKET: ${S3_BUCKET:-submissions}
    entrypoint: >
      sh -c "
      until mc alias set local http://minio:9000 \"$$MINIO_ROOT_USER\" \"$$MINIO_ROOT_PASSWORD\"; do sleep 1; done &&
      mc mb --ignore-existing local/$$S3_BUCKET
      "

  portal:
    build:
      context: .
      dockerfile: Dockerfile
    depends_on:
      minio-init:
        condition: service_completed_successfully
    environment:
      ADMIN_PASSWORD: ${ADMIN_PASSWORD}
      SESSION_SECRET: ${SESSION_SECRET:-}
      S3_ACCESS_KEY: ${MINIO_ROOT_USER}
      S3_SECRET_KEY: ${MINIO_ROOT_PASSWORD}
    command:
      - -remote=${REMOTE}
      - -addr=0.0.0.0:8080
      - -s3-bucket=${S3_BUCKET:-submissions}
      - -s3-region=us-east-1
      - -s3-endpoint=http://minio:9000
      - -log-path=/data/submissions.jsonl
    volumes:
      - portal-logs:/data
    ports:
      - "${PORTAL_PORT:-8080}:8080"

volumes:
  minio-data:
  portal-logs:
```

- [ ] **Step 3: Add `.env` to `.gitignore`**

Add a new section at the end of [.gitignore](.gitignore):

```
# Local docker-compose configuration (contains ADMIN_PASSWORD, MinIO creds)
.env
```

- [ ] **Step 4: Bring the stack up and verify end to end**

```bash
cp .env.example .env
docker compose up --build
```

Expected, in order: `minio` starts, `minio-init` logs a successful `mc alias set` and `mc mb` (or "already own it" if re-run) then exits 0, `portal` starts and logs `listening on 0.0.0.0:8080, verifying operator pubkeys against https://rpc.topaz.testnets.gno.land`.

Then, in another terminal:
- `curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/` → expect `200`.
- `curl -s -u any:changeme http://localhost:8080/admin/submissions` → expect `200` with an empty/valid JSON body (proves `ADMIN_PASSWORD` and the log path wiring both work).

- [ ] **Step 5: Tear down and confirm persistence**

```bash
docker compose down
docker compose up
```

Expected: no rebuild needed, `minio-init` reports the bucket already exists, `portal` starts cleanly — proves `minio-data` and `portal-logs` volumes persisted.

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yml .env.example .gitignore
git commit -m "Add docker-compose stack for local quick start"
```

---

## Self-Review Notes

- Spec coverage: Dockerfile ✓ (Task 1), compose services + volumes + networking ✓ (Task 2), `.env`/`.env.example` ✓ (Task 2), `.dockerignore` ✓ (Task 1), manual verification in place of automated tests ✓ (Task 1 Step 3, Task 2 Steps 4–5), `cmd/portal-dev` explicitly out of scope per spec — no task touches it.
- No placeholders: every step has literal file contents or literal commands and expected output.
- Type/naming consistency: `S3_BUCKET`, `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`, `REMOTE`, `PORTAL_PORT` are used identically across `.env.example` and `docker-compose.yml`.
