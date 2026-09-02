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

Ready to paste as two consecutive Discord messages:

### Message 1/2 — Announcement and upload instructions

~~~text
🚨 **VALIDATOR FIRE DRILL**

This is a scheduled validator fire drill designed to evaluate incident-response readiness.

Please submit the requested diagnostic package.

**Investigation window (UTC):**
2026-09-01 12:00
↓
2026-09-01 14:00

**Submission deadline (UTC):**
2026-09-03 16:00

**Archive structure:**
```text
<moniker>-<YYYYMMDD-HHMMUTC>.tar.gz
├── validator.log.gz
├── sentry.log.gz (optional)
└── metadata.json
```

- `validator.log.gz` — node logs covering the requested investigation window; must be a valid gzip file.
- `sentry.log.gz` — optional sentry logs for the same window; must be valid gzip if included. It is expected when `sentry_enabled` is `true` and is worth 4 of the 25 log-quality points.
- `metadata.json` — validator and environment metadata; use the format in the next message. Unknown fields are rejected.
- Keep all files at the archive root: no subfolders, symlinks or extra files.
- `validator_address` must match the authenticated operator address; `moniker` must match the archive filename.
- Limits: each log ≤ 4 GiB; `metadata.json` ≤ 64 KiB; total upload < 4 GiB.

**Important:**
- Include only the requested 2-hour log window. Do not submit your complete node log history.
- Set `gnoland_version` exactly to `chain/pearl` (case-sensitive).
- Prepare and verify the archive before starting authentication.
- If the portal is busy, wait a few minutes and submit the same archive again.

🌐 **Upload portal:** https://gno.report
~~~

### Message 2/2 — `metadata.json`

~~~text
📋 **METADATA FORMAT**

Use this structure for `metadata.json`:

```json
{
  "validator_address": "g1...",
  "moniker": "...",
  "chain_id": "pearl-1",
  "gnoland_version": "chain/pearl",
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

**Allowed values:**
- `architecture`: `amd64`, `arm64`, `x86`
- `deployment_method`: `docker`, `systemd`, `binary`, `kubernetes`
- `sentry_enabled`: `true`, `false`
- `backup_node`: `true`, `false`

Replace the example values with your own information. Do not add unknown fields.
~~~

## 3. After the deadline (tomorrow 16:00 UTC)

`GET /admin/summary` on the portal generates the Markdown summary
(participation, per-submission status, score, warnings) ready to paste into
Discord — publishing stays a manual action, no auto-post.
