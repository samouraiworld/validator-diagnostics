# Merge Acknowledgement Time into Upload Completion Time

## Overview

`prd.md`'s Phase 3 rubric (implemented per
[2026-08-03-fire-drill-phase3-design.md](2026-08-03-fire-drill-phase3-design.md))
scores "Acknowledgement time" as a manual admin field: the admin looks up
when a validator first responded to the drill announcement (e.g. on
Discord) and types that timestamp in. In practice this lookup never
happens — the only automatic timing signal the portal has is
`submitted_at`, already scored separately as "Upload completion time".

This spec drops the acknowledgement criterion entirely and lets upload
completion time stand as the rubric's only timing signal, removing a
manual step that adds admin burden without adding real information. It
supersedes the parts of the Phase 3 spec that cover `AcknowledgedAt` /
`AckTimeScore` and the 5×20-point rubric; everything else in that spec
(exercise config, AV scanning, automatic checks, summary generation)
is unchanged.

## Rubric (`prd.md`)

Four criteria at 25 points each, replacing the previous five at 20:

| Metric | Score |
|---|---:|
| Upload completion time | 25 |
| Metadata completeness | 25 |
| Log quality | 25 |
| Incident response quality | 25 |
| **Total** | **100** |

The label stays "Upload completion time" (not renamed) — the underlying
signal and formula are unchanged, only the point cap and the removal of
the sibling criterion. The Objectives bullet "Time required to
acknowledge the incident." is removed, since that event is no longer
tracked or scored separately from submission.

## Data model (`scoring.Result`)

`AcknowledgedAt` and `AckTimeScore` are removed. `IncidentResponseQualityScore`
remains the only manual field.

```go
type Result struct {
    SubmissionID string

    Scored           bool
    GenesisMatch     bool
    VersionSupported bool
    LogWindow        LogWindowCheck
    UploadTimeScore  int // 0-25
    MetadataScore    int // 0-25, effectively always 25 for a logged submission
    LogQualityScore  int // 0-25

    IncidentResponseQualityScore *int // 0-25, manual
}
```

`Pending()` reports `IncidentResponseQualityScore == nil` only.
`TotalScore()` sums `UploadTimeScore + MetadataScore + LogQualityScore`
plus `*IncidentResponseQualityScore` when set.

## Scoring formulas (`scoring/score.go`)

**Tiered time score** (now used only by upload completion time), same
quarter-of-window shape, rescaled to a 25-point cap using the nearest
integer at each tier (100%/75%/50%/25%/0% of 25):

```
pct = (t - announced_at) / (deadline_at - announced_at)
pct <= 25%  → 25
pct <= 50%  → 19
pct <= 75%  → 13
pct <= 100% → 6
pct > 100%  → 0
```

**Metadata completeness** — always 25 (was 20), same rationale as before:
`SubmitHandler` already rejects invalid metadata before a submission is
ever recorded.

**Log quality** (0-25, was 0-20) — structural base rescaled to 13
(was 10), plus up to 12 more from `LogWindowCheck`: `Covered` → +12
(total 25), `Detected && !Covered` → +6 (total 19), `!Detected` → +0
(total 13).

**Incident response quality** — unchanged in kind (manual admin
judgment), rescaled range 0-25 (was 0-20).

Genesis hash / gnoland version checks are unaffected — they were never
part of the 100-point score.

## API (`portal/score.go`)

`scoreRequest` drops `AcknowledgedAt`; the body becomes:

```json
{"incident_response_quality_score": 0}
```

Bounds check moves from 0-20 to 0-25. `AdminScoreHandler` no longer
computes `AckTimeScore` or reads `exercise.Config`, so the `exerciseStore`
parameter is removed from its signature; `cmd/portal/main.go`'s wiring of
`AdminScoreHandler(log, exerciseStore, scores)` drops that argument. The
existing `!ok || !result.Scored` guard (a submission must already have
been auto-scored) is unchanged and remains sufficient — it no longer
needs `cfg.Configured()` as a second, now-redundant guard, since
auto-scoring already implies the exercise was configured at submit time.

## Frontend (`cmd/portal/static/admin.js`)

The "Acknowledged at (UTC)" input and its label are removed from
`buildScoreForm`. The remaining "Incident response" input's `max`
changes from `20` to `25`, its placeholder from `0-20` to `0-25`, and
the client-side error message text updates to match. The POST body no
longer includes `acknowledged_at`.

## Summary (`portal/summary.go`)

`pendingNote` collapses to a single check — no more three-way switch on
two manual fields:

```go
func pendingNote(r scoring.Result) string {
    if r.IncidentResponseQualityScore == nil {
        return " (incident response pending)"
    }
    return ""
}
```

## Testing

- `scoring/result_test.go` — update/remove cases referencing
  `AckTimeScore`/`AcknowledgedAt`; `Pending()` and `TotalScore()` cases
  reflect the single remaining manual field and new point values.
- `scoring/score_test.go` (or wherever `TieredTimeScore`/`LogQualityScore`
  are tested) — boundary values updated to 25/19/13/6/0 and the new
  `LogQualityScore` breakdown.
- `portal/score_test.go` — drop cases for `acknowledged_at` parsing/
  validation and the removed `exerciseStore` dependency; bounds test
  moves to 0-25.
- `portal/summary_test.go` — `pendingNote` cases updated for the
  single-field switch.
- `portal/admin_test.go` — any expected JSON shape checks updated to
  drop `acknowledged_at`/`ack_time_score`.

## Out of scope

No change to AV scanning, automatic checks (genesis/version/log window),
exercise config, or the summary's overall structure beyond `pendingNote`.
