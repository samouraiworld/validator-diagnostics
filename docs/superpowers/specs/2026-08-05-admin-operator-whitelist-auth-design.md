# Admin Auth — Operator Address Whitelist

## Overview

The admin dashboard (`cmd/portal/static/admin.html` and every `/admin/*`
route) is currently protected by `portal.AdminAuth`: HTTP Basic Auth checked
against a single shared `ADMIN_PASSWORD` (any username accepted). That's a
password known to everyone with admin access, with no per-admin identity —
which is also why the delete-submission spec explicitly noted there was "no
'by whom' to record" for audit purposes.

This spec replaces that with the same challenge-tx operator-key
authentication already built and validated end-to-end for the validator
submission flow (`auth/challenge.go`, `auth/http.go`), gated by a whitelist of
admin operator addresses. Admins are drawn from the same population as
validators (they already have a `valopers`-registered operator address), so
no new identity system or external dependency is introduced. As a side
effect, every admin action is now attributable to a real operator address.

Out of scope: an in-app UI for managing the whitelist (it's a fixed env var,
same operational model as `ADMIN_PASSWORD` today), and reusing the whitelist
check as a general-purpose authorization system beyond `/admin/*`.

## Components

### `auth` package — second `SessionSigner` instance

No code changes to `auth/session.go` or `auth/http.go`. `ChallengeHandler`,
`VerifyHandler`, and `RequireSession` are already identity-agnostic and are
reused as-is for admin login. What changes is that `cmd/portal/main.go`
constructs a **second** `SessionSigner` (own secret, own TTL) dedicated to
admin sessions, so lengthening the admin session lifetime doesn't also
lengthen the validator upload session's lifetime.

### `portal/admin.go`

`AdminAuth` (HTTP Basic Auth) is deleted. Replaced with:

```go
// RequireAdminSession wraps next, accepting only requests bearing a valid
// session token (see auth.RequireSession) whose bound operator address is
// in allowlist. allowlist keys are bech32 address strings
// (crypto.Address.String()).
func RequireAdminSession(sessions *auth.SessionSigner, allowlist map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, err := auth.RequireSession(sessions, r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !allowlist[addr.String()] {
			log.Printf("admin: rejected non-whitelisted operator address %s", addr)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

401 for missing/invalid/expired token (same failure mode as any other
session-protected endpoint), 403 for a valid session whose address just isn't
whitelisted — kept distinct so a legitimate operator who isn't an admin gets
a meaningful error instead of looking like a bad signature.

### `cmd/portal/main.go`

- New flags/env vars:
  - `ADMIN_SESSION_SECRET` (env, required) — HMAC secret for the admin
    `SessionSigner`. Same handling as the existing session secret: loaded
    from env, fatal at startup if empty.
  - `--admin-session-ttl` (flag, default `1h`) — separate from
    `--session-ttl` (which stays at its existing 5m default for the
    validator upload flow).
  - `ADMIN_OPERATOR_ADDRESSES` (env, required) — comma-separated bech32
    addresses. Parsed at startup with `crypto.AddressFromBech32` per entry;
    any invalid address or an empty list is a fatal startup error (same
    posture as the existing `ADMIN_PASSWORD == ""` check — an admin surface
    with no valid credentials configured is a misconfiguration, not a
    degraded-but-running state).
- `ADMIN_PASSWORD` and the `adminPassword` variable are removed entirely.
- Every `/admin*` route registration switches from
  `portal.AdminAuth(adminPassword, …)` to
  `portal.RequireAdminSession(adminSessions, adminAllowlist, …)`.

### `.env.example` / `.env`

Replace the `ADMIN_PASSWORD` block with `ADMIN_SESSION_SECRET` and
`ADMIN_OPERATOR_ADDRESSES`, documented the same way (which routes they
protect).

## Frontend (`cmd/portal/static/`)

### `admin.html`

Today the page has no login markup — the browser's native Basic Auth prompt
handled it. That's replaced with an explicit login step, structurally the
same as steps 1–2 already in `index.html` (address input → "Get challenge" →
`gnokey sign` command + `sig.json` upload → "Verify"). The existing
`#panel-config` / `#panel-validators` tabs are wrapped so they stay `hidden`
until a valid admin session exists in memory.

### `admin.js` (new)

Currently `admin.html` has no dedicated script — actions in the dashboard hit
`/admin/*` directly and relied on the browser having already satisfied Basic
Auth. `admin.js` now owns:

- The login flow, ported from `portal.js`'s `get-challenge` /
  `verify-signature` handlers (`cmd/portal/static/portal.js:28-117`) —
  same request/response shapes, since it's hitting the same
  `/auth/challenge` and `/auth/verify` endpoints.
- Holding `session_token` in a module-level variable only (not
  `localStorage`), matching the validator flow's existing choice.
- Attaching `Authorization: Bearer <token>` to every existing `/admin/*`
  fetch call (submissions polling, exercise config save, score submission,
  delete, summary generation).
- On a 401/403 from any `/admin/*` call: clear the in-memory token and
  re-show the login step (session expired mid-use), instead of leaving the
  dashboard in a state where every action silently fails.

### `portal.css`

Login step reuses the existing `.step`/`.field` styles already used for the
same UI shape in `index.html` — no new classes expected.

## Error handling

- No/invalid/expired Bearer token on `/admin/*` → 401, login screen shown
  again.
- Valid session, non-whitelisted address → 403, distinct error message
  ("this operator address is not authorized for admin access") so a
  validator who mistakenly lands here understands why, rather than assuming
  their signature was rejected.
- Startup misconfiguration (`ADMIN_OPERATOR_ADDRESSES` empty or containing an
  invalid address, `ADMIN_SESSION_SECRET` empty) → fatal at startup, same as
  the existing `ADMIN_PASSWORD` check.

## Testing

- `portal/admin_test.go`: `RequireAdminSession` — no token (401), expired
  token (401), valid token for a non-whitelisted address (403), valid token
  for a whitelisted address (200, request reaches `next`).
- `cmd/portal/main_test.go`: `TestDeleteSubmissionRouteRequiresAdminAuth`
  updated to assert a request without an admin Bearer token is rejected on
  `DELETE /admin/submissions/{id}` — same regression guard as today, updated
  for the new auth mechanism.
- New test for `ADMIN_OPERATOR_ADDRESSES` parsing at startup: valid list
  parses into the expected allowlist set; an invalid address in the list is
  a fatal error.
- Frontend: manual smoke test via `go run ./cmd/portal` + browser — sign in
  with a whitelisted address (existing `gnokey` test key from the validator
  flow works, provided it's added to `ADMIN_OPERATOR_ADDRESSES`), confirm the
  dashboard loads; sign in with a non-whitelisted address, confirm the 403
  message; let the session expire (short TTL override for the manual test)
  and confirm the dashboard falls back to the login screen instead of
  failing silently.
