# Validator Fire Drill Portal — gno.land Visual Restyle

Status: approved (design), pending implementation plan.

## Context

The portal (`cmd/portal/static/`) ships two functional-but-unstyled pages:
`index.html` (the validator submission wizard) and `admin.html` (the
submissions table). Both use `system-ui` fonts, a bare gray/white palette,
and no branding — see `docs/superpowers/specs/2026-07-29-portal-frontend-design.md`
for how the flow itself was designed; this spec only covers the visual
layer on top of that existing structure.

The goal is to make the portal visually consistent with https://gno.land/
— same typography, same brand color, same logo mark — without adopting
gno.land's full site chrome (nav, footer, marketing layout), which doesn't
fit a two-page internal tool.

## Design tokens (sourced from gno.land's shipped CSS, 2026-07-29)

Pulled from `https://gno.land/public/main.css` and the page `<head>`:

- **Fonts**: `Inter` (variable font, body/UI text) and `Roboto` a.k.a.
  Roboto Mono (monospace: addresses, signing commands, table data).
  gno.land self-hosts these as `.woff2` — we do the same rather than
  linking Google Fonts, so the portal has no external runtime dependency
  (matches the "single deployable binary" constraint from the original
  frontend design).
- **Brand green**: `#226c57` (primary / buttons / focus rings), `#144134`
  (hover/dark accent), `#e7efed` (light success-tint background),
  dark-mode equivalents `#277b63` / `#60ab96`.
- **Neutrals**: gray scale `#0e0e0e` (darkest) through `#f0f0f0`
  (lightest), used for text/borders/surfaces in both themes.
- **State colors**: error `#c95c3e` (light) / `#eb6c49` (dark), warning
  `#facc32`. Success reuses the brand green.
- **Type rhythm**: `line-height: 1.5` for body copy, `1.25` for headings.
- **Radius**: kept at the existing `6px` (already close to gno.land's own
  scale; no need to change).

## Logo

gno.land's header logo is an inline SVG — a gnome mascot glyph plus a
"gno.land" wordmark, `viewBox="0 0 116 27"`, drawn entirely in
`currentColor` (no raster asset, no separate file to host). We embed the
same SVG markup directly in `index.html` and `admin.html`, so it inherits
the page's text color and works in both themes automatically. Next to it,
a small text label distinguishes this portal from the main site: the logo
links nowhere (no `<a>` wrapper — this isn't gno.land's site), and is
followed by "Validator Fire Drill" as the page's actual heading.

## Components

1. **Shared header** — new markup block (logo + "Validator Fire Drill"
   heading), duplicated at the top of `index.html` and `admin.html`. No
   shared templating exists in this project (plain static HTML, no
   build step — see original frontend design's "no separate frontend
   build pipeline" goal), so duplication here matches the existing
   pattern (`portal.css` is already shared via `<link>`, but markup is
   copy-pasted between the two pages today).
2. **Wizard steps** (`index.html`) — each `.step` section gets a visible
   step-number badge (circular, brand-green background, white numeral)
   next to its `<h2>`. Primary actions (`Get challenge`, `Verify`,
   `Submit`) become solid brand-green buttons with a darker hover state;
   there are no secondary/outline actions in the current flow, so no
   outline-button variant is needed. Text inputs get a subtle border that
   turns brand-green on focus. `<pre>` (the `gnokey sign` command) uses
   Roboto Mono on a faint tinted background.
3. **Admin table** (`admin.html`) — header row in uppercase, letter-spaced,
   muted-gray text; row borders lightened; alternating-row tint using the
   existing `--s-color-bg-surface-secondary`-equivalent gray.
4. **Status text** — `.error`/`.success` classes keep their current
   role but pick up the new red/green token values instead of the current
   ad hoc `#b00020`/`#0a7d2c`.

## Theming

`portal.css` already branches on `prefers-color-scheme` for `--fg`/`--bg`/
`--border`. We extend the same `:root` + `@media (prefers-color-scheme:
dark)` pattern with the new tokens above, rather than introducing a
theme-switcher or a new CSS architecture — this is a value swap, not a
structural change.

## Files touched

- `cmd/portal/static/portal.css` — token variables reworked to the
  gno.land values above; new rules for the header, step badges, buttons,
  inputs, table striping.
- `cmd/portal/static/fonts/` (new) — `inter-var.woff2`,
  `roboto-mono.woff2`, plus `@font-face` declarations added to
  `portal.css`. Font files fetched from gno.land's public font URLs
  (`/public/fonts/intervar/Intervar.woff2`,
  `/public/fonts/roboto/roboto-mono-normal.woff2`); both are open-license
  fonts (Inter: OFL, Roboto Mono: Apache 2.0), so self-hosting a copy is
  license-compliant.
- `cmd/portal/static/index.html`, `admin.html` — add the shared header
  markup (inline SVG logo + heading), add step-number badges to
  `index.html`'s three `.step` sections.

## What doesn't change

`portal.js`, `admin.js`, and all backend Go code are untouched — this is
a pure CSS/markup restyle. The wizard's step logic, polling behavior, and
API calls are unaffected.

## Testing approach

Visual-only change, no new logic: verified by running `cmd/portal`
locally and checking both pages in a real browser, in both light and dark
OS theme, per this project's standing instruction to test UI changes
in-browser rather than only relying on any automated check. No unit tests
apply (no behavior change to verify).
