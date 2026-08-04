# Validator Fire Drill

## Overview

The purpose of the Validator Fire Drill is to evaluate how quickly and effectively validators can respond to an operational incident.

The goal is to collect diagnostic artifacts in a consistent and machine-readable format so that incident investigations can be automated as much as possible while minimizing manual work for both validators and investigators.

The exercise measures not only response time, but also the quality, completeness, and consistency of the information provided during an investigation.

This exercise is **not intended to identify or punish validators**. Its objective is to improve the operational readiness of the network and establish a standardized incident-response procedure that can be reused during real incidents.

---

# Objectives

The fire drill evaluates several aspects of validator operations:

- Time required to submit the requested artifacts.
- Ability to follow a standardized incident-response procedure.
- Completeness and accuracy of the submitted information.
- Quality and usability of the collected logs.
- Overall operational readiness.

---

# Standard Submission Format

To simplify investigations, every validator should submit the same archive structure.

The archive **must** be named using the following convention:

```
<moniker>-<YYYYMMDD-HHMMUTC>.tar.gz
```

Example:

```
samourai-20260709-1830UTC.tar.gz
```

Archive structure:


```
<moniker>-<YYYYMMDD-HHMMUTC>.tar.gz
├── gnoland.log.gz
└── metadata.json
```

Where:

- `gnoland.log.gz` contains the node logs covering the requested investigation time window.
- `metadata.json` contains the information required to identify the validator and its environment.

---

# Metadata

Each submission should include a `metadata.json` file.

Example:

```json
{
  "validator_address": "...",
  "moniker": "...",

  "chain_id": "...",
  "gnoland_version": "...",
  "genesis_sha256": "...",

  "operating_system": "Debian 12",
  "architecture": "amd64",

  "sentry_enabled": true,
  "backup_node": true,

  "hosting_provider": "Scaleway",
  "deployment_method": "docker",

  "recent_operations": "None"
}
```

Using a machine-readable metadata file makes automated validation significantly easier.

## Metadata Schema

Some fields should only accept predefined values.

| Field | Type | Allowed values |
|------|------|----------------|
| architecture | enum | `amd64`, `arm64`, `x86` |
| deployment_method | enum | `docker`, `systemd`, `binary`, `kubernetes` |
| sentry_enabled | boolean | `true`, `false` |
| backup_node | boolean | `true`, `false` |

Additional enum values may be added in future versions.

---

# Required Artifacts

## Mandatory

- `gnoland.log.gz`
- `metadata.json`

---
# Submission Platform

Several submission methods are possible.

## Option 1 — Web Upload Portal (Recommended)

A dedicated web portal allows validators to upload their diagnostic package through a simple interface.

Possible workflow:

1. Authenticate.
2. Upload the archive.
3. Automatic validation.
4. Immediate confirmation.

The portal may automatically validate:

- Archive naming
- Archive structure
- Required files
- Maximum upload size
- JSON format
- Metadata schema
- Allowed enum values

### Authentication

One possible authentication mechanism would be to authenticate validators using the operator key already registered on the `valopers` realm.

This would avoid managing usernames or passwords while proving ownership of the validator identity.

**Note:** this authentication mechanism has been implemented and validated end-to-end against a live network — a real operator address, registered on `valopers` on the `topaz-1` testnet, successfully completed the full challenge/sign/verify flow using an unmodified `gnokey sign` (see "Authentication for the submission pipeline" under Security Considerations for the protocol and implementation). Remaining work before production use: wiring it to the actual archive-upload endpoint (session/token binding), and testing against Betanet.

Additional restrictions may also be enforced:

- One successful submission per validator.
- Maximum upload size (for example 10 GB).
- Submission deadline enforcement.
- Automatic rejection of invalid archives or metadata.

Advantages

- Very easy to use
- No command-line upload tools required
- Immediate validation feedback
- Automatic metadata validation
- Automatic archive validation
- Easy integration with Object Storage
- Easy to automate and extend

Disadvantages

- Requires development and maintenance of a web application

---

## Option 2 — Object Storage

Example providers:

- Scaleway Object Storage
- AWS S3
- Cloudflare R2

Each validator receives temporary write-only credentials or a pre-signed upload URL.

Advantages

- Highly scalable
- Easy automation
- Versioning support
- Large file uploads
- Minimal server maintenance

Disadvantages

- Requires validators to use an S3-compatible client or upload tool

**Status: selected for v1.** Behind the web upload portal (Option 1) rather than exposed directly to validators as raw pre-signed URLs — the portal accepts the archive and forwards it to Object Storage server-side, so validators only ever interact with the portal, not with S3 credentials. Implemented as a small `Store` interface (`storage/store.go`) with one concrete backend (`storage/s3.go`, S3-compatible: AWS S3, Scaleway, or R2 via `Endpoint`), so a future SFTP backend — if ever needed — would be a second implementation of the same interface, not a rewrite of the portal. Verified against a fake S3-compatible HTTP server (`storage/s3_test.go`); not yet tested against real Scaleway/AWS credentials.

---

## Option 3 — SFTP

Advantages

- Simple and well-known protocol
- Supports large files
- Compatible with many tools

Disadvantages

- Credential management
- Central server maintenance
- More difficult to automate validation

# Fire Drill Procedure

## Phase 1 — Incident Announcement

Validators receive an incident notification containing all the information required to perform the investigation.

Example:

```text
🚨 VALIDATOR FIRE DRILL

This is a scheduled validator fire drill designed to evaluate incident-response readiness.

Please submit the requested diagnostic package.

Investigation window (UTC):

2026-07-08 18:00
↓

2026-07-09 18:30

Submission deadline (UTC):

2026-07-09 19:30

Required artifacts:

- gnoland.log.gz
- metadata.json

Upload portal:

https://...

The metadata file must include:

- Validator address
- Validator moniker
- Gnoland version
- Genesis SHA256 hash
- Operating system
- CPU architecture
- Any recent operations that may be relevant
```

## Phase 2 — Artifact Collection & Submission

Validators collect the requested diagnostic artifacts corresponding to the investigation window.

Typical workflow:

- Collect the requested logs.
- Generate `metadata.json`.
- Package the archive.
- Authenticate on the upload portal (if applicable).
- Upload the archive before the submission deadline.

During the upload process, the portal may automatically validate:

- Archive integrity.
- Archive naming convention.
- Required files.
- JSON syntax.
- Metadata schema.
- Allowed enum values.
- Maximum upload size.

Successful uploads immediately receive a confirmation.

---

## Phase 3 — Analysis & Scoring

After the submission deadline, all received artifacts are analyzed.

Automatic validation may verify:

- Archive integrity.
- Required files.
- Metadata validity.
- Genesis SHA256 hash.
- Supported Gnoland version.
- Metadata completeness.
- Requested log time window.

This significantly reduces manual review.
Each validator receives a score based on the predefined evaluation criteria.

Once the analysis is complete, a summary is published on Discord (or another communication channel), including:

- Overall participation.
- Individual submission status.
- Final score.
- Validation errors (if any).
- General observations and recommendations.

The objective of this phase is to provide actionable feedback and continuously improve validator operational readiness.

---

# Evaluation Criteria

Each exercise can be scored.

| Metric | Score |
|---------|------:|
| Upload completion time | 25 |
| Metadata completeness | 25 |
| Log quality | 25 |
| Incident response quality | 25 |

Maximum score:

**100 points**

---

# Possible Future Scenarios

Once the process is established, different incident scenarios can be tested.

Examples include:

- Double-sign investigation
- Missed blocks investigation
- Unexpected validator restart
- Performance degradation
- Consensus instability

Each scenario may request additional artifacts while using the same standardized submission process.

---

# Recommendations

- Do not announce the exact date of the exercise.
- Trigger the drill randomly within a predefined period.
- Prefer a web upload portal backed by Object Storage or pre-signed upload URLs.
- Encourage structured JSON logging.
- Automate validation whenever possible.
- Publish a post-mortem after each exercise.

---

# Future Improvements

Future versions of the fire drill may request additional diagnostic artifacts such as:

- `journalctl` logs
- `config.toml`
- `app.toml`
- Prometheus metrics
- System resource usage
- Network diagnostics

A helper script (`collect-validator-artifacts.sh`) could also be provided to automatically collect logs, generate `metadata.json`, package the archive, and verify its integrity before upload.

---

# Security Considerations

Submitted archives come from third parties and **must be treated as untrusted input**, regardless of the submission method used.

## Handling of submitted archives

- Never execute, source, or interpret any content of a submitted archive. Processing must be limited to reading bytes (extraction, JSON parsing, log parsing).
- Extract and process archives inside an isolated, ephemeral, network-restricted environment (container/sandbox) with minimal privileges. Destroy the environment after processing.
- Enforce a strict decompressed-size limit, independent from the compressed upload size limit, to mitigate zip/tar bombs. Apply CPU, memory, and time limits to extraction and parsing.
- Reject archive entries with path traversal (`..`, absolute paths), and reject symlinks, hardlinks, and device files. Only regular files are accepted.
- Only accept the exact expected entries (`gnoland.log.gz`, `metadata.json`); reject archives containing unexpected additional files.
- Validate file types using content signatures (magic bytes), not just file extensions.
- Run an antivirus scan (e.g. ClamAV) on extracted content as defense in depth.
- Treat log content as untrusted text when displayed or re-injected elsewhere (dashboards, Discord, terminals): sanitize/escape control characters, ANSI sequences, and HTML/markdown before rendering.
- Log and surface validation failures rather than silently discarding or ignoring malformed submissions.

**Status: implemented.** The `submission` package enforces the naming convention, structural, and anti-abuse rules above:

- `submission/name.go` — `ValidateFilename` checks the `<moniker>-<YYYYMMDD-HHMMUTC>.tar.gz` convention.
- `submission/archive.go` — `ValidateArchive` streams the tar.gz and enforces: only the two expected entries (fail-closed on anything else, including path-traversal names — blocked by exact-name allowlisting rather than a traversal blocklist), regular files only (symlinks/hardlinks/directories/devices rejected), no duplicate entries, per-entry size caps enforced via a bounded reader regardless of what the archive's headers or compression ratio claim (zip/tar-bomb protection), and gzip magic-byte verification on `gnoland.log.gz`.
- `submission/metadata.go` — `ValidateMetadata` enforces the Metadata Schema table's enum constraints (`architecture`, `deployment_method`) and required fields, rejecting unknown fields outright.
- Covered by `submission/*_test.go` (22 test cases), including explicit path-traversal, symlink/hardlink, oversized-entry, and bad-magic-bytes cases — not just the happy path.

The ClamAV defense-in-depth scan is also implemented: `clamav/clamd.go` streams every accepted upload to a clamd daemon over INSTREAM before it is stored, and `portal.SubmitHandler` fails closed — an infected verdict *or* any scan failure (daemon down, size limit, timeout) rejects the submission and stores nothing. `clamd.conf` in the repo root keeps clamd's stream limit and the portal's `-max-upload-size` in agreement; `-clamav-addr` selects the daemon (unset disables scanning, for local dev only).

Not yet implemented: the sandboxed/ephemeral extraction environment — a deployment/infra concern layered on top of this validation logic, not something the Go package itself can provide.

## Authentication for the submission pipeline

- Any authentication mechanism gating this pipeline (e.g. the proposed `valopers` operator-key authentication) must be implemented and verified before being trusted with production submissions — signature verification correctness, nonce/replay protection, and challenge expiration all need explicit testing against real signed messages.
- Until such a mechanism is implemented and verified, prefer a simpler, already-trusted distribution channel (e.g. per-validator pre-signed upload URLs distributed individually through an existing trusted channel) rather than delaying the exercise on unproven authentication.

### Proposed protocol: challenge-tx operator-key authentication

Validated by inspecting `gno`'s source (`gnolang/gno`). The primitives below already exist and are reused as-is, not reimplemented:

- `OperatorAddress` (the stable identity registered via `Register()` in [`r/gnops/valopers/valopers.gno`](https://github.com/gnolang/gno/blob/master/examples/gno.land/r/gnops/valopers/valopers.gno)) is distinct from the validator's consensus `SigningPubKey`. Authenticating with the operator key never touches the live consensus signing key.
- `gnokey sign` / `gnokey verify` (`tm2/pkg/crypto/keys/client/sign.go`, `verify.go`) wrap generic byte-signing primitives (`Keybase.Sign`, `Keybase.Verify`), not tx-specific cryptography.
- An address's on-chain public key is fetched today via an `auth/accounts/<addr>` ABCI query (see `fetchAccount` in `verify.go`) — no local keybase needed server-side. Since registering on `valopers` is itself a tx signed by `OperatorAddress`, that address is guaranteed to already have a pubkey on-chain.
- `crypto.PubKey.VerifyBytes(msg, sig)` (`tm2/pkg/crypto/crypto.go`) verifies a raw signature against arbitrary bytes and a pubkey directly — no keybase required.
- `std.Tx.Memo` (`tm2/pkg/std/tx.go`) is included in `GetSignBytes()`, giving a ready-made place to embed a random nonce.

Flow:

1. Validator submits their `OperatorAddress` to the portal.
2. Portal generates a random single-use nonce (TTL ~5 min) and builds an **unsigned challenge tx**: a 1ugnot self-send (`OperatorAddress` → `OperatorAddress`) with `Memo = "validator-fire-drill-auth:v1:" + nonce`. The tx is never broadcast.
3. Portal fixes the `chainID`/`account-number`/`account-sequence` used to compute `GetSignBytes()` to sentinel values that do **not** match the operator's real account — this guarantees the resulting signature can never be replayed as a valid on-chain transaction, even if leaked.
4. Portal serves the unsigned challenge tx (JSON) for download.
5. Validator signs it locally and never uploads a private key:

   ```bash
   gnokey sign --tx-path challenge.json \
     --chainid fire-drill-auth-only \
     --account-number 0 --account-sequence 0 \
     --output-document sig.json <operator-key-name>
   ```

6. Validator uploads `sig.json` (and the archive) to the portal.
7. Portal reconstructs the same challenge tx from the stored nonce, recomputes `GetSignBytes()`, fetches `OperatorAddress`'s pubkey from chain, and calls `PubKey.VerifyBytes(signBytes, sig)`. The nonce is burned on first use regardless of outcome.

**Status: implemented and validated end-to-end.** `auth/challenge.go`, `auth/http.go` (`POST /auth/challenge`, `POST /auth/verify`) and the `cmd/portal-dev` local test server implement steps 2, 3, and 7. Confirmed against a live network (`topaz-1`): a real `valopers`-registered operator address signed a server-issued challenge with unmodified `gnokey sign`, and the portal's `/auth/verify` correctly accepted it (and rejects invalid signatures / replayed nonces — covered by `auth/challenge_test.go` and `auth/http_test.go`).

One implementation detail worth flagging: `fetchOperatorPubKey`'s account-lookup response schema had to be corrected to match the real `auth/accounts/<addr>` response (`amino.UnmarshalJSON` rejects unknown fields, and the live response includes an `attributes` field not present in a naive first draft) — a good reminder that "reuses existing primitives" still needs a real network round-trip to catch these details, not just a read of the source.

### Binding a verified session to the upload

A successful `/auth/verify` needs to authorize the *subsequent* archive upload without re-running the challenge flow per request. Implemented as a short-lived, stateless, HMAC-signed token (`auth/session.go`, `SessionSigner`) rather than a JWT library or a server-side session store — a fixed-layout token has less attack surface for this one narrow use case (no algorithm negotiation, no claims-parsing ambiguity), and statelessness avoids needing session infra for a v1. Trade-off: a token can't be revoked before it expires, so the TTL is kept short (default 5 min in `cmd/portal-dev`).

- `/auth/verify` now returns `session_token` alongside `ok: true`.
- Covered by `auth/session_test.go` (round-trip, tampering, wrong secret, expiry, garbage input) and `auth/http_test.go` (issuance via `/auth/verify`, consumption via `RequireSession`).

### The submission endpoint

**Status: implemented and wired end-to-end.** `portal/submit.go` (`SubmitHandler`, served as `POST /submit` by `cmd/portal-dev`) composes the three pieces above into the actual upload flow from "Phase 2 — Artifact Collection & Submission":

1. `auth.RequireSession` — reject unauthenticated requests (401).
2. `submission.ValidateFilename` on the uploaded file's name (400 on mismatch).
3. `submission.ValidateArchive` on the multipart file directly — no extra buffering needed, since a `multipart.File` is always seekable regardless of whether Go held it in memory or spilled it to its own temp file (400 on any structural/security violation).
4. `submission.ValidateMetadata` on the extracted `metadata.json` (400 on schema/enum violations).
5. Cross-check: `metadata.json`'s `validator_address` must equal the session's authenticated operator address (403 on mismatch) — otherwise the challenge-tx auth's whole purpose ("proving ownership of the validator identity") would be disconnected from what's actually being asserted in the submitted data. Its `moniker` must also match the archive filename's moniker (400 on mismatch). Neither cross-check is explicitly spelled out in the PRD text above; flagging them here as an implementation decision rather than a silently-assumed requirement.
6. Only on success: `storage.Store.Save` with the original, unmodified uploaded bytes.

A `storage.LocalStore` (writes to a local directory, refuses to overwrite an existing key) was added alongside `S3Store` purely so `cmd/portal-dev` can exercise the full flow locally without needing real Scaleway/AWS credentials yet — swapping in `S3Store` for production is a one-line change at the `portal-dev`/deployment wiring level, not a code change to `SubmitHandler`.

Verified: `portal/submit_test.go` drives the handler end-to-end (valid submission, missing session, identity mismatch, bad filename, malformed archive) against an in-memory fake `Store`; `cmd/portal-dev` was smoke-tested live against `topaz-1` (auth rejection and challenge issuance both confirmed working through the fully-wired binary).

Still open: no enforcement yet of "one successful submission per validator" (Option 1's "Additional restrictions") — would need some persistence beyond the current in-memory `NonceStore`/`SessionSigner`, deferred until the storage-backend/deployment story is settled.
