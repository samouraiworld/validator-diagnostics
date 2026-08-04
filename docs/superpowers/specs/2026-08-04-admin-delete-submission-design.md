# Admin — Delete a Single Submission

## Overview

The admin dashboard (`cmd/portal/static/admin.html`) has no way to remove a
submission once recorded. In practice a validator sometimes uploads the wrong
archive, or an admin wants to drop a test/duplicate entry made while
exercising the portal — today the only fix is editing `submissions.jsonl` /
`scores.json` by hand on the server, or deleting the archive directly from
storage.

This spec adds a per-row delete action to the admin table: a button per
submission, a confirmation modal, and a backend endpoint that removes the
submission's log entry, its score record, and its uploaded archive together.

Out of scope: bulk/"delete all" reset (considered and explicitly rejected in
favor of this narrower, per-row action — see prior discussion), undo/soft
delete, and an audit trail of what was deleted and by whom (this portal has a
single shared admin password, not per-admin accounts, so there's no "by whom"
to record).

## Components

### `storage.Store` (`storage/store.go`, `storage/local.go`, `storage/s3.go`)

`Store` gains:

```go
type Store interface {
    Save(ctx context.Context, key string, body io.Reader, size int64) error
    Delete(ctx context.Context, key string) error
}
```

Idempotent: deleting a key that doesn't exist is **not** an error, in both
implementations. `LocalStore.Delete` treats `os.ErrNotExist` from `os.Remove`
as success; `S3Store.Delete` relies on `DeleteObject`'s existing
not-found-is-success semantics. This matters because a submission can reach
this handler with its archive already gone (e.g. a prior delete attempt
succeeded at the storage step but failed before the log/score cleanup — see
Error handling), and retrying that case must not get stuck on a 404 from the
store.

### `portal.FileLog` (`portal/log.go`)

Gains:

```go
// Delete removes the entry with the given ID. found reports whether an
// entry with that ID existed.
func (l *FileLog) Delete(id string) (found bool, err error)
```

Implementation: under the existing mutex, read all entries (reusing the same
parse path as `Entries`), filter out the matching ID, and rewrite the file
via `atomicfile.Write` (already used by `exercise.FileStore` and
`scoring.Store` for the same reason: a torn write must not corrupt the
remaining entries). This changes `FileLog` from strictly append-only to
append-or-delete-by-id; `Record` and `Entries` are unaffected.

### `scoring.Store` (`scoring/store.go`)

Gains:

```go
// Delete removes the record for id, if any. Deleting an id with no
// record is a no-op, not an error — a submission may not have been
// scored yet.
func (s *Store) Delete(id string) error
```

Same read-modify-write-under-mutex shape as `Set`.

### `portal/delete.go` (new)

```go
func AdminDeleteSubmissionHandler(log *FileLog, store storage.Store, scores *scoring.Store) http.HandlerFunc
```

`DELETE /admin/submissions/{id}`:

1. Look up the entry via `log.Entries()` to get its `Filename`. Not found →
   404.
2. `store.Delete(ctx, entry.Filename)`. Failure → 502, entry/score untouched
   (see Error handling — this ordering is deliberate).
3. `scores.Delete(id)`. Failure → 500.
4. `log.Delete(id)`. Failure → 500.
5. 204 on success.

### `cmd/portal/main.go`

New route registration, same pattern as the existing per-submission score
route:

```go
mux.Handle("DELETE /admin/submissions/{id}", portal.AdminAuth(adminPassword, portal.AdminDeleteSubmissionHandler(submissionLog, store, scoresStore)))
```

## Frontend (`cmd/portal/static/`)

`admin.html`: submissions table gains an eighth column ("") holding a delete
button per row (rendered in `admin.js`, matching how the existing score-form
cell is built — no static markup per row since rows are generated). A single
`<dialog id="delete-confirm">` element, shared across rows, added once near
the end of `#panel-validators`.

`admin.js`:
- Each row's delete button, on click, records the row's `id`/`moniker`/
  `operator_address` on the dialog (e.g. a small module-level variable) and
  calls `dialog.showModal()`. Using the native `<dialog>` element gets focus
  trapping, `Esc`-to-close, and a backdrop for free — no hand-rolled overlay
  logic.
- Dialog body text is filled in from the recorded moniker/operator address
  before showing: "Delete the submission from **{moniker}** ({operator
  address})? Its score and uploaded archive will also be deleted.
  **This cannot be undone.**"
- Cancel button: plain `<button>` with `formmethod="dialog"` (or a click
  handler calling `dialog.close()`) — no network call.
- Confirm button: `DELETE /admin/submissions/{id}`; on success, close the
  dialog and `refresh({force: true})`; on failure, close the dialog and show
  the error in the existing `#admin-error` element, same pattern as every
  other admin action on this page.

`portal.css`: style `dialog` and `dialog::backdrop` with the existing color
tokens (`--surface` background, `--border` border, `--error` for the confirm
button — reusing `button` styles isn't right here since the default button
is branded green, and this action is destructive). New `.icon-button` (or
similar) for the compact per-row trigger, sized to sit comfortably in a table
cell.

## Error handling

- Unknown `id` → 404, surfaced in `#admin-error`.
- Storage delete failure (e.g. S3 unreachable) → 502; **the log entry and
  score are left in place**, so the row stays in the table and the admin can
  retry, rather than the dashboard showing the submission as gone while its
  archive still exists somewhere with nothing pointing at it.
- Score/log deletion failure after a successful storage delete → 500. This
  is the one state that can leave a dangling reference (archive already
  gone, log/score not yet cleaned up) — accepted, since a retry is exactly
  the fix (`store.Delete` on an already-missing key is a no-op, so the retry
  just finishes the remaining steps).

## Testing

- `storage`: `Delete` for both `LocalStore` and `S3Store` — deletes an
  existing key, and deleting a missing key succeeds (not an error).
- `portal`: `FileLog.Delete` — removes only the matching entry, leaves
  others' order/content intact, `found=false` on an unknown id, empty log
  file case. `scoring.Store.Delete` — removes an existing record, no-op on
  an unknown id.
- `portal`: new `delete_test.go` for `AdminDeleteSubmissionHandler` — success
  (204, verify all three stores/log no longer reference the id), unknown id
  (404), storage delete failure (502, log/score unchanged), missing auth.
- Frontend: manual smoke test via `go run ./cmd/portal` + browser (this
  project's existing convention) — open the dialog, cancel (row unchanged),
  confirm (row removed, archive gone from the configured storage dir),
  `Esc` closes without deleting.
