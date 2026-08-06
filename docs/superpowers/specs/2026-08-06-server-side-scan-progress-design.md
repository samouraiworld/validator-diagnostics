# Server-Side Progress for the Submission Handler

## Overview

A 2.41 GB archive now uploads and scans successfully, and it takes about eight
minutes end to end. Measured on the target machine against the real stack:

| Phase | Cost |
| --- | --- |
| Transfer + multipart spill to disk | seconds to a minute, already shown by the upload bar |
| `ValidateArchive` | a full pass over the outer gzip |
| Antivirus scan | **5m23s** — 24 windows of 1 GiB, 25.4 GB decompressed at ~140 MiB/s |
| `Store.Save` to S3 | 2.4 GB, minutes |
| Scoring | a bounded pass, 1 GiB at most |

For every second after the last byte leaves the browser, `portal.js` shows one
frozen indeterminate bar and a sentence that says this "can take several
minutes". That is indistinguishable from a hang, and it was in fact mistaken
for one: an earlier attempt was abandoned at about 3m30, cancelling the
request — the portal logged
`antivirus scan for samourai-crew-huge-...tar.gz failed: context canceled`.

The scan was not stuck. It was working, and nothing on the page could say so.

This spec adds a second connection carrying real server-side progress, so the
validator can see the work advancing.

### What this is not

The obvious alternative — acknowledge the submission immediately and scan
afterwards — was considered and rejected. It would either store content the
antivirus has not examined, which is the exact fail-open this codebase's
windowed scanning exists to prevent, or tell a validator "received" for a
submission that a later scan rejects. Validators have no account and no email:
there is no channel to correct that claim afterwards. Keeping the request
synchronous keeps "received" meaning received.

### Out of scope

- Any change to the order validate → scan → store → score.
- Any change to `clamav.WindowedScanner`'s API. The byte counting is done by a
  decorator in `portal`, which already knows how to wrap a `Scanner`.
- Reporting progress for the transfer itself. `xhr.upload.onprogress` already
  covers it.
- Server-Sent Events or a streaming response body (see "Why polling").

## 1. The progress channel

### Why polling, on a second connection

The response to `POST /submit` cannot carry progress: its status code is not
decided until the very end — 422 for an infected archive, 503 for a scanner
failure, 400 for an unreadable log — and a streaming body would force the
status to be written first, collapsing every one of those into a 200 whose
real outcome lives in the body. That would break the endpoint's contract and
every test that asserts on it.

So progress travels on its own request: `GET /submit/progress`, polled every
two seconds while the upload is in flight. Browsers allow six concurrent
connections per host over HTTP/1.1, so the poll never contends with the
upload.

Server-Sent Events would also work and would push instead of poll, but it
costs a long-lived connection and reconnection handling for a value that
changes every few seconds at most. Polling is smaller and sufficient.

### Keyed by operator, not by a generated ID

The tracker is keyed by the **authenticated operator address**, so there is no
identifier to generate in the browser, pass as a header, and thread through
the handler. `GET /submit/progress` reads the session it already requires,
looks up that operator's in-flight submission, and returns it — or 404.

This also settles authorization for free: an operator can only ever read their
own progress, because their session is what selects the row.

The one degraded case is a single operator running two submissions at once:
the second `Begin` overwrites the first, and the displayed progress becomes
whichever wrote last. Both submissions still complete correctly and record
correctly — only the display is wrong, for a case that should not arise.
Paying for it with an ID plumbed through five layers is not worth it.

### `portal/progress.go` (new)

```go
// Phase names the server-side stage a submission has reached. The transfer
// itself is deliberately absent: the browser observes that directly through
// XMLHttpRequest's upload progress events.
type Phase string

const (
	PhaseValidating Phase = "validating"
	PhaseScanning   Phase = "scanning"
	PhaseStoring    Phase = "storing"
	PhaseScoring    Phase = "scoring"
)

// Progress is one in-flight submission's server-side state.
type Progress struct {
	Phase Phase `json:"phase"`

	// Bytes is work completed in the current phase, reset at each
	// transition. Total is the phase's expected size, or 0 when it cannot
	// be known ahead of time — see "No invented percentage".
	Bytes int64 `json:"bytes"`
	Total int64 `json:"total,omitempty"`

	// PhaseStartedAt lets the page compute elapsed time and throughput
	// without assuming it started polling when the phase did.
	PhaseStartedAt time.Time `json:"phase_started_at"`
}

// ProgressTracker holds progress for in-flight submissions, keyed by
// authenticated operator address. The zero value is not usable; call
// NewProgressTracker.
type ProgressTracker struct { /* mu sync.Mutex; inflight map[string]*entry; ttl time.Duration */ }

func NewProgressTracker() *ProgressTracker

// Begin starts tracking a submission for operator, replacing any entry that
// operator already had. Callers must defer Handle.Done.
func (t *ProgressTracker) Begin(operator string) *ProgressHandle

// Get returns operator's current progress. ok is false when nothing is in
// flight — which includes the window between the browser finishing its
// upload and the server finishing reading the request body.
func (t *ProgressTracker) Get(operator string) (Progress, bool)

// Phase moves to p and resets the byte counter. total is the phase's
// expected size, or 0 when unknown.
func (h *ProgressHandle) Phase(p Phase, total int64)

// Add accumulates bytes within the current phase.
func (h *ProgressHandle) Add(n int64)

// Done removes the entry. Safe to call twice.
func (h *ProgressHandle) Done()
```

**Nil is usable throughout.** `Begin` on a nil `*ProgressTracker` returns a
nil `*ProgressHandle`, and every `ProgressHandle` method tolerates a nil
receiver by doing nothing. So a handler built without a tracker needs no
guard at any of the five call sites — the reporting simply evaporates. Both
nil receivers are load-bearing and both are tested.

**Staleness.** `Done` runs from a `defer`, so it survives a panic and covers
essentially every exit. The tracker additionally drops an entry that has not
been updated for five minutes, which bounds what a killed goroutine can leave
behind. Five minutes rather than something tighter because the validating
phase reports nothing while it runs and can legitimately be silent for a
minute on a large archive; the scan updates every window, roughly every seven
seconds.

### The endpoint

```go
func ProgressHandler(sessions *auth.SessionSigner, tracker *ProgressTracker) http.HandlerFunc
```

`GET` only. `auth.RequireSession` for the operator address, 401 without one.
404 when nothing is in flight. 200 with the `Progress` JSON otherwise.

Note `/submit` is registered as an exact pattern (no trailing slash), so
`/submit/progress` does not collide with it. This is worth stating because
adding a trailing slash to either registration silently changes which handler
wins.

## 2. Instrumenting the handler

`SubmitHandler` gains one field, following the same nil-disables convention as
`Log` and `Exercise`:

```go
// Progress publishes server-side progress for the page to poll. Optional —
// a nil Progress disables reporting and changes nothing else.
Progress *ProgressTracker
```

`Begin` is called once the server-side work starts — after
`ParseMultipartForm` returns, not before. The browser starts polling earlier
than that, at `xhr.upload.onload`, so it will get 404s during the gap while
the server is still reading and spilling the request body. That is correct and
the page handles it by leaving its current message in place.

Then, at each transition:

| Before | Call |
| --- | --- |
| `ValidateArchive` | `handle.Phase(PhaseValidating, 0)` |
| `scanArchive` | `handle.Phase(PhaseScanning, 0)` |
| `Store.Save` | `handle.Phase(PhaseStoring, header.Size)` |
| the scoring block | `handle.Phase(PhaseScoring, 0)` |

Nothing about the ordering changes. These are observations placed alongside
work that already happened in this sequence.

### Counting scanned bytes without touching `clamav`

`portal` wraps its `clamav.Scanner` in a decorator that counts what it hands
to the inner scanner:

```go
// countingScanner reports how much of each window reaches the wrapped
// Scanner, so a scan in progress can be shown advancing rather than as a
// frozen bar.
//
// It counts bytes streamed to the antivirus, which includes the 1 MiB
// re-sent at each window boundary — roughly 0.1% more than the Coverage the
// submission finally records. The skew is deliberate: this is a liveness
// indicator, and Coverage.Bytes stays the authoritative number, on the log
// entry and on the dashboard badge.
type countingScanner struct {
	inner clamav.Scanner
	add   func(int64)
}
```

It takes a callback rather than the handle, which keeps it independent of the
tracker and testable with a plain counter.

`Store.Save`'s progress uses the same idea, wrapping the `io.Reader` it is
given in a counting reader.

## 3. What the page shows

### No invented percentage

The log's decompressed size is not known until it has been decompressed, so
the scanning phase has no denominator. Bounding it by the budget would produce
a bar that advances smoothly and then jumps to done at 75% — a different lie
from the frozen one it replaces.

So the scan reports **absolute numbers that move**, which is what actually
proves the work is alive, under an indeterminate bar:

```text
Antivirus scan — 14.2 GiB streamed · 2m 31s · 141 MiB/s
```

Storing is the opposite case: `header.Size` is known, so it gets a real
percentage and a determinate bar. Two slow phases, two treatments, because one
can be honest about its progress and the other cannot.

| Phase | Bar | Text |
| --- | --- | --- |
| `validating` | indeterminate | Checking the archive's structure… |
| `scanning` | indeterminate | Antivirus scan — *bytes* streamed · *elapsed* · *rate* |
| `storing` | determinate, `bytes/total` | Storing the archive — 1.2 / 2.2 GiB (54%) |
| `scoring` | indeterminate | Scoring your submission… |

Strings stay in English, matching the rest of the page.

### Markup and accessibility

`#upload-progress` gains one element:

```html
<p id="upload-detail" aria-live="off"></p>
```

The separation `portal.js` already established is preserved exactly:
`#upload-status` carries the running sentence, `#upload-detail` carries the
numbers, both with `aria-live="off"`, and `#upload-phase` remains the polite
live region that only changes at phase transitions. Phase changes are
announced; a byte count refreshing every two seconds is not.

### Polling lifecycle

Start on `xhr.upload.onload` — the moment the page currently goes blind. Stop
on `xhr.onload`, `xhr.onerror` and `xhr.onabort`, with a guard so a poll
response that lands after completion cannot resurrect the display.

**A polling failure must be invisible.** On 404, on any error status, or on a
network failure, the page keeps whatever it is showing and tries again on the
next tick. The submission is entirely decided on the other connection;
progress is a comfort, and its failure must never look like a problem with the
upload. If polling never succeeds at all, the page degrades exactly to today's
behaviour.

## 4. Wiring

`cmd/portal/main.go` constructs one `ProgressTracker`, passes it through
`muxDeps` to both `submitHandlerFor` and the new route:

```go
mux.Handle("/submit/progress", portal.ProgressHandler(d.Sessions, d.ProgressTracker))
```

`cmd/portal-dev` is left alone: it builds a `SubmitHandler` with most fields
nil already, and a nil `Progress` disables reporting.

## Testing

### `portal/progress_test.go`

- `Begin` then `Get` returns the entry; `Done` then `Get` reports not found.
- `Phase` resets the byte counter and sets `Total`; `Add` accumulates.
- **Isolation**: two operators tracked at once, each `Get` returns only its
  own. This is the authorization property, so it is asserted directly rather
  than inferred from the handler.
- A second `Begin` for the same operator replaces the first.
- An entry not updated for longer than the staleness window is reported as
  absent.
- A nil `*ProgressHandle` accepts `Phase`, `Add` and `Done` without panicking.

### The endpoint tests

- No session → 401. Wrong method → 405.
- Session with nothing in flight → 404.
- Session with an entry → 200 and the phase, bytes and total.
- Operator A's session never returns operator B's progress.

### `portal/submit_test.go`

The assertion that matters is the one a naive test gets wrong: **progress must
be visible while the scan runs, not after it.** Checking the tracker once the
handler has returned proves nothing, because `Done` has already fired.

So: a scanner that blocks on a channel, a test that reads
`GET /submit/progress` while it is blocked and asserts `phase: "scanning"`
with a non-zero byte count, then releases it. Anything weaker is not testing
this feature.

Also: the entry is gone after the handler returns; and a submission with a nil
`Progress` behaves exactly as before.

### Elsewhere

- The counting scanner: bytes counted match what the inner scanner received,
  and the inner scanner's verdict and error pass through untouched.
- `cmd/portal/main_test.go`: the tracker reaches the handler, and
  `/submit/progress` is routed.
- `go test ./... -race`, since the tracker is written by the submit handler's
  goroutine and read by the poll handler's.
- Manual verification against `test/samourai-crew-huge-20260805-2232UTC.tar.gz`
  with the real stack, where the target is known: four phases in sequence, the
  scanning phase counting up to roughly 25.4 GB over about 5m23s, and the
  storing phase showing a real percentage over 2.4 GB.
