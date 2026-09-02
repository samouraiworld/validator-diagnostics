# Fire drill — 2026-09-02

Announcement planned for 12:00 Chile time. Chile is still on standard time
(UTC-4) until the DST switch on 2026-09-06, so **12:00 Chile = 16:00 UTC**
today.

## 1. "Exercise configuration" form (portal `/admin`)

| Field | Value |
|---|---|
| Announced at (UTC) | `2026-09-02T16:00:00Z` |
| Deadline at (UTC) | `2026-09-03T16:00:00Z` |
| Investigation window start (UTC) | `2026-09-01T12:00:00Z` |
| Investigation window end (UTC) | `2026-09-01T14:00:00Z` |
| Expected genesis SHA256 | `c45fe60c8c8a1f859d9e4d5aad7ce4d100ff0eb78302e71318ba0de481a8dc91` |
| Supported gnoland versions | `chain/pearl` |
| Observations | (free text — optional) |

Things to double-check before submitting:
- The investigation window (Sept 1, 12:00-14:00 UTC) precedes the
  announcement (Sept 2, 16:00 UTC) — confirmed intentional, and the form
  allows it (no code-level constraint between the two), but validators will
  need to supply logs from before the exercise starts, not logs generated
  during it.
- `chain/pearl` as "supported gnoland versions" is an unusual shape for this
  field (normally a semver-like version string, compared literally against
  `gnoland_version` in the submitted `metadata.json`). Confirm this matches
  exactly what validators will actually put in their `metadata.json`,
  otherwise the "version supported" check will fail for everyone even on an
  otherwise-correct submission.
- Genesis hash to cross-check against `https://rpc.pearl.testnets.gno.land`
  if you want to re-verify before launching.

## 2. Discord message — Phase 1 (announcement)

Template from `prd.md`, values filled in, updated to the current archive
format (`validator.log.gz` + optional `sentry.log.gz`, per
`submission/archive.go`) and with the `metadata.json` format spelled out:

```text
🚨 VALIDATOR FIRE DRILL

This is a scheduled validator fire drill designed to evaluate incident-response readiness.

Please submit the requested diagnostic package.

Investigation window (UTC):

2026-09-01 12:00
↓
2026-09-01 14:00

Submission deadline (UTC):

2026-09-03 16:00

Archive structure:

<moniker>-<YYYYMMDD-HHMMUTC>.tar.gz
├── validator.log.gz
├── sentry.log.gz (optional)
└── metadata.json

- validator.log.gz — the node logs covering the requested investigation window (must be a valid gzip file).
- sentry.log.gz — optional; your sentry node's logs for the same window (must be a valid gzip file if included). Expected when sentry_enabled is true in metadata.json, and submitting one that covers the investigation window is worth 4 of the log-quality score's 25 points.
- metadata.json — validator and environment metadata; schema and example below. Unknown fields are rejected.
- Only these files at the top level of the archive — no subfolders, no symlinks, no extra files.
- validator_address must match your operator address; moniker must match the archive's filename.
- Size limits: validator.log.gz and sentry.log.gz ≤ 4 GiB each, metadata.json ≤ 64 KiB, total upload ≤ 4 GiB. These are the deployment defaults — your organizer may have configured different values, and the error message tells you the real limit if you exceed it.

Please prepare the full archive (logs collected, metadata.json written and checked against the schema below) BEFORE starting authentication on the portal. Authenticate only once everything is ready to upload.

Upload portal:

https://gno.report

Example metadata.json:

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

Field / Allowed values:
- architecture: amd64, arm64, x86
- deployment_method: docker, systemd, binary, kubernetes
- sentry_enabled: true, false
- backup_node: true, false
```

## 3. After the deadline (tomorrow 16:00 UTC)

`GET /admin/summary` on the portal generates the Markdown summary
(participation, per-submission status, score, warnings) ready to paste into
Discord — publishing stays a manual action, no auto-post.
