# gno.land Visual Restyle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restyle the two portal pages (`cmd/portal/static/index.html`, `admin.html`) to visually match gno.land — same fonts, brand green palette, and logo — without changing any JS behavior or backend code.

**Architecture:** Pure CSS/markup change against the existing zero-build-step static site. `portal.css` gains vendored `@font-face` declarations and a reworked token set; both HTML pages get a shared header block (inline SVG logo) inserted in place of their bare `<h1>`.

**Tech Stack:** Plain HTML/CSS, no framework, no build step (spec: `docs/superpowers/specs/2026-07-29-gnoland-visual-restyle-design.md`).

## Global Constraints

- No build pipeline, no new runtime dependency — everything ships inside the existing `//go:embed static` binary (`cmd/portal/main.go:34`).
- No external network calls at runtime — fonts are self-hosted, not linked from Google Fonts or gno.land.
- `portal.js` and `admin.js` are not modified — this is a visual-only change.
- Keep the existing `prefers-color-scheme` theming pattern (a `:root` block plus one `@media (prefers-color-scheme: dark)` override) rather than introducing a theme switcher.
- Border radius stays `6px` throughout (already gno.land-adjacent, per spec).
- No unit tests apply (no behavior change). Verification is manual, in a real browser, in both light and dark OS theme — per this project's standing instruction to test UI changes in-browser.

---

### Task 1: Vendor gno.land's fonts and wire up `@font-face`

**Files:**
- Create: `cmd/portal/static/fonts/inter-var.woff2`
- Create: `cmd/portal/static/fonts/roboto-mono.woff2`
- Create: `cmd/portal/static/fonts/LICENSES.md`
- Modify: `cmd/portal/static/portal.css`

**Interfaces:**
- Produces: CSS custom properties `--font-sans` and `--font-mono`, usable by every later task's selectors.

- [ ] **Step 1: Create the fonts directory and fetch the two font files**

```bash
mkdir -p cmd/portal/static/fonts
curl -sL -A "Mozilla/5.0" -o cmd/portal/static/fonts/inter-var.woff2 \
  "https://gno.land/public/fonts/intervar/Intervar.woff2"
curl -sL -A "Mozilla/5.0" -o cmd/portal/static/fonts/roboto-mono.woff2 \
  "https://gno.land/public/fonts/roboto/roboto-mono-normal.woff2"
```

- [ ] **Step 2: Verify both files downloaded as real font binaries, not error pages**

Run: `file cmd/portal/static/fonts/*.woff2`
Expected: both report `Web Open Font Format (Version 2)`, non-trivial size (`ls -la` — Inter should be ~70KB, Roboto Mono ~12KB). If either is a few hundred bytes of HTML/JSON, the fetch failed — check the URL and re-run Step 1.

- [ ] **Step 3: Add attribution/license file for the vendored fonts**

Create `cmd/portal/static/fonts/LICENSES.md`:

```markdown
# Vendored fonts

- `inter-var.woff2` — Inter, by Rasmus Andersson. Licensed under the SIL
  Open Font License 1.1. Source: https://gno.land/public/fonts/intervar/Intervar.woff2
  (self-hosted here to avoid a runtime dependency on gno.land or Google
  Fonts). Full license text: https://openfontlicense.org
- `roboto-mono.woff2` — Roboto Mono, by Google. Licensed under the Apache
  License 2.0. Source: https://gno.land/public/fonts/roboto/roboto-mono-normal.woff2
  Full license text: https://www.apache.org/licenses/LICENSE-2.0
```

- [ ] **Step 4: Add `@font-face` declarations and font-family tokens to `portal.css`**

At the top of `cmd/portal/static/portal.css`, before the existing `:root` block, add:

```css
@font-face {
  font-family: "Inter";
  font-style: normal;
  font-weight: 100 900;
  font-display: swap;
  src: url("fonts/inter-var.woff2") format("woff2");
}

@font-face {
  font-family: "Roboto Mono";
  font-style: normal;
  font-weight: 400;
  font-display: swap;
  src: url("fonts/roboto-mono.woff2") format("woff2");
}
```

Inside the existing `:root { ... }` block, add these two lines (keep everything else in that block unchanged for now — Task 2 reworks the rest):

```css
  --font-sans: "Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Ubuntu, Cantarell, "Noto Sans", sans-serif;
  --font-mono: "Roboto Mono", ui-monospace, Menlo, Consolas, "DejaVu Sans Mono", monospace;
```

Change the `body` rule's `font-family` from `system-ui, sans-serif` to `var(--font-sans)`, and the `pre` rule to add `font-family: var(--font-mono);`.

- [ ] **Step 5: Verify the fonts load in a real browser**

Open `cmd/portal/static/index.html` directly in a browser (`file://` path — no server needed for this check). Open devtools → Network tab, reload, filter by "Font": both `inter-var.woff2` and `roboto-mono.woff2` should show a `200`/`(disk cache)` status, not `404`. Then select the `<pre>` command block with devtools → Computed styles → confirm `font-family` resolves to `Roboto Mono`.

- [ ] **Step 6: Commit**

```bash
git add cmd/portal/static/fonts cmd/portal/static/portal.css
git commit -m "Vendor gno.land's Inter and Roboto Mono fonts"
```

---

### Task 2: Rework the color token palette to match gno.land

**Files:**
- Modify: `cmd/portal/static/portal.css`

**Interfaces:**
- Consumes: nothing from Task 1 beyond the file already being open for editing.
- Produces: CSS custom properties `--fg`, `--bg`, `--border`, `--muted`, `--surface`, `--brand`, `--brand-hover`, `--brand-tint`, `--brand-contrast`, `--error`, `--success` — every later task's component styles reference these instead of hardcoded colors.

- [ ] **Step 1: Replace the `:root` and dark-mode blocks with the gno.land palette**

Replace the current `:root { ... }` block (color-related lines only — keep the `--font-sans`/`--font-mono` lines added in Task 1) with:

```css
:root {
  color-scheme: light dark;

  --font-sans: "Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Ubuntu, Cantarell, "Noto Sans", sans-serif;
  --font-mono: "Roboto Mono", ui-monospace, Menlo, Consolas, "DejaVu Sans Mono", monospace;

  --gray-50: #f0f0f0;
  --gray-100: #e2e2e2;
  --gray-400: #7c7c7c;
  --gray-500: #696969;
  --gray-700: #292929;
  --gray-800: #141414;
  --gray-850: #0e0e0e;

  --green-400: #60ab96;
  --green-600: #226c57;
  --green-900: #144134;

  --red-400: #eb6c49;
  --red-600: #c95c3e;

  --fg: var(--gray-800);
  --bg: #ffffff;
  --border: var(--gray-100);
  --muted: var(--gray-500);
  --surface: var(--gray-50);

  --brand: var(--green-600);
  --brand-hover: var(--green-900);
  --brand-contrast: #ffffff;

  --error: var(--red-600);
  --success: var(--green-600);
}

@media (prefers-color-scheme: dark) {
  :root {
    --fg: var(--gray-50);
    --bg: var(--gray-850);
    --border: var(--gray-700);
    --muted: var(--gray-400);
    --surface: var(--gray-800);

    --brand: var(--green-400);
    --brand-hover: #7fc2ac;
    --brand-contrast: var(--gray-850);

    --error: var(--red-400);
    --success: var(--green-400);
  }
}
```

This replaces the old 3-variable palette (`--fg`, `--bg`, `--border`, `--error`, `--success`) — every one of those names is preserved so the rest of the file (which references them) keeps working unchanged.

- [ ] **Step 2: Verify no leftover references to removed variables**

Run: `grep -n "var(--" cmd/portal/static/portal.css`
Expected: every variable used is one defined above (`--fg`, `--bg`, `--border`, `--error`, `--success`, `--font-sans`, `--font-mono`). None of the new-but-unused-yet ones (`--muted`, `--surface`, `--brand`, `--brand-hover`, `--brand-contrast`) need consumers yet — Tasks 3–5 add those.

- [ ] **Step 3: Verify visually in both themes**

Open `cmd/portal/static/index.html` in a browser. In devtools, open the Rendering tab → "Emulate CSS media feature prefers-color-scheme" → toggle between `light` and `dark`. Confirm the page background and text color change (page will still look plain — Task 2 only changes tokens, not component styles yet — but background/border/text colors should visibly shift between the two themes without any console errors).

- [ ] **Step 4: Commit**

```bash
git add cmd/portal/static/portal.css
git commit -m "Rework portal.css color tokens to gno.land's palette"
```

---

### Task 3: Add the shared gno.land logo header to both pages

**Files:**
- Modify: `cmd/portal/static/index.html`
- Modify: `cmd/portal/static/admin.html`
- Modify: `cmd/portal/static/portal.css`

**Interfaces:**
- Consumes: `--fg` (Task 2) for the logo's `currentColor` fill and `--muted` for the header heading color.
- Produces: `header.site-header` selector, styled here, unused by other tasks.

- [ ] **Step 1: Replace `index.html`'s `<h1>` with the header block**

In `cmd/portal/static/index.html`, replace:

```html
<h1>Validator Fire Drill — Submission</h1>
```

with:

```html
<header class="site-header">
  <svg class="logo" viewBox="0 0 116 27" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <g clip-path="url(#clip0_210_682)">
      <path
        d="M15.7782 18.1953C15.5729 17.4557 15.1344 16.8048 14.5394 16.3075C14.3097 16.1152 14.0591 15.9332 13.7854 15.7636C13.5534 15.6191 13.261 15.8319 13.3283 16.0936L13.493 16.7331C13.7018 17.5456 12.8133 18.2044 12.0732 17.7868L10.0838 16.6648C8.77648 15.9275 7.16872 15.9275 5.8614 16.6648L3.872 17.7868C3.13192 18.2044 2.24336 17.5444 2.45216 16.7331L2.62152 16.0754C2.6888 15.8148 2.39764 15.602 2.16564 15.7454C1.86172 15.932 1.58564 16.1346 1.33508 16.3474C0.749278 16.8458 0.342118 17.5149 0.151878 18.2522L0.144918 18.2795C-0.338802 20.1639 0.412879 22.145 2.03456 23.2612L7.05736 26.717C7.6072 27.0948 8.33916 27.0948 8.889 26.717L13.9118 23.2612C15.5578 22.129 16.3072 20.1047 15.7782 18.1965V18.1953Z"
        fill="currentColor"></path>
      <path
        d="M15.5711 14.0394C15.1326 10.4459 13.3358 6.84558 11.5981 4.08732L14.1803 1.55437C14.7649 0.980866 14.3508 0 13.5237 0H7.96265C7.53345 0 7.10309 0.185477 6.81309 0.555293C4.85501 3.05525 1.02121 8.55584 0.351893 14.0394C0.291573 14.5389 0.888973 14.845 1.27177 14.5105C2.60809 13.343 4.69261 12.5078 7.96149 12.5078C11.2304 12.5078 13.3137 13.3441 14.6512 14.5105C15.034 14.845 15.6314 14.5378 15.5711 14.0394Z"
        fill="currentColor"></path>
      <path
        d="M22.1331 22.9892L23.7188 20.5064C24.8034 21.6522 26.2499 22.1153 27.918 22.1153C29.5861 22.1153 31.6451 21.4064 31.6451 18.7324V17.45C30.5883 18.7597 29.1418 19.4959 27.4737 19.4959C24.1364 19.4959 21.5508 17.2042 21.5508 12.8119C21.5508 8.41962 24.0819 6.10059 27.4737 6.10059C29.0873 6.10059 30.5605 6.75488 31.6451 8.11921V6.4283H35.1773V18.7312C35.1773 23.7232 31.2287 24.951 27.9192 24.951C25.6386 24.951 23.8313 24.4332 22.1343 22.987V22.9892H22.1331ZM31.6439 14.9409V10.6579C31.0315 9.8124 29.7531 9.18428 28.6129 9.18428C26.5829 9.18428 25.192 10.5486 25.192 12.813C25.192 15.0774 26.5829 16.4418 28.6129 16.4418C29.7531 16.4418 31.0326 15.7875 31.6439 14.9409Z"
        fill="currentColor"></path>
      <path
        d="M46.09 19.6061V11.6408C46.09 9.81338 45.1168 9.18526 43.6146 9.18526C42.2237 9.18526 41.167 9.94879 40.5556 10.7135V19.6073H37.0234V6.42928H40.5556V8.12019C41.4175 7.13819 43.0868 6.10156 45.256 6.10156C48.2314 6.10156 49.65 7.73786 49.65 10.3027V19.605H46.09V19.6061Z"
        fill="currentColor"></path>
      <path
        d="M50.8945 13.0039C50.8945 9.26703 53.5637 6.10254 57.9856 6.10254C62.4075 6.10254 65.1045 9.26703 65.1045 13.0039C65.1045 16.7407 62.4354 19.9325 57.9856 19.9325C53.5359 19.9325 50.8945 16.7407 50.8945 13.0039ZM61.4343 13.0039C61.4343 10.9579 60.2105 9.1851 57.9856 9.1851C55.7607 9.1851 54.5648 10.9579 54.5648 13.0039C54.5648 15.0498 55.7886 16.85 57.9856 16.85C60.1827 16.85 61.4343 15.0771 61.4343 13.0039Z"
        fill="currentColor"></path>
      <path
        d="M65.5859 18.3778C65.5859 17.5597 66.2808 16.877 67.116 16.877C67.9512 16.877 68.646 17.5586 68.646 18.3778C68.646 19.1971 67.9512 19.8787 67.116 19.8787C66.2808 19.8787 65.5859 19.1971 65.5859 18.3778Z"
        fill="currentColor"></path>
      <path
        d="M70.2188 16.8503V1.41016H72.3044V16.4145C72.3044 17.3965 72.7499 18.1054 73.6674 18.1054C74.2509 18.1054 74.8077 17.8323 75.0583 17.533L75.6974 19.0885C75.1418 19.5789 74.418 19.934 73.1942 19.934C71.2198 19.934 70.2188 18.8154 70.2188 16.8514V16.8503Z"
        fill="currentColor"></path>
      <path
        d="M86.4924 19.6058V17.6418C85.4913 18.9788 83.8511 19.9335 81.9591 19.9335C78.4548 19.9335 75.9805 17.3152 75.9805 13.0322C75.9805 8.74912 78.4559 6.10352 81.9591 6.10352C83.7664 6.10352 85.4078 6.97628 86.4924 8.42255V6.43123H88.5781V19.6069H86.4924V19.6058ZM86.4924 16.0043V10.0577C85.7697 8.91184 84.1283 7.92984 82.4881 7.92984C79.7632 7.92984 78.1497 10.1123 78.1497 13.031C78.1497 15.9497 79.7632 18.1049 82.4881 18.1049C84.1283 18.1049 85.7697 17.1502 86.4924 16.0043Z"
        fill="currentColor"></path>
      <path
        d="M99.8706 19.6061V10.9854C99.8706 8.63907 98.6468 7.93016 96.8395 7.93016C95.1993 7.93016 93.6692 8.91217 92.863 9.9761V19.6061H90.7773V6.42928H92.863V8.33867C93.8084 7.22011 95.6435 6.10156 97.6735 6.10156C100.454 6.10156 101.928 7.49321 101.928 10.3573V19.605H99.8706V19.6061Z"
        fill="currentColor"></path>
      <path
        d="M113.914 19.6063V17.6422C112.913 18.9793 111.273 19.934 109.381 19.934C105.877 19.934 103.402 17.3157 103.402 13.0326C103.402 8.74959 105.878 6.10398 109.381 6.10398C111.188 6.10398 112.83 6.97674 113.914 8.42301V1.41016H116V19.6063H113.914ZM113.914 16.0048V10.0582C113.192 8.91231 111.55 7.9303 109.91 7.9303C107.185 7.9303 105.572 10.1128 105.572 13.0315C105.572 15.9502 107.185 18.1054 109.91 18.1054C111.55 18.1054 113.192 17.1507 113.914 16.0048Z"
        fill="currentColor"></path>
    </g>
    <defs>
      <clipPath id="clip0_210_682">
        <rect width="116" height="27" fill="white"></rect>
      </clipPath>
    </defs>
  </svg>
  <h1>Validator Fire Drill — Submission</h1>
</header>
```

Note: the two "beard"/"hat" mascot paths lost their `class="beard"`/`class="hat"` attributes and gained `fill="currentColor"` — on gno.land those two paths are colored via a separate CSS rule (`.beard`/`.hat`) that isn't part of what we vendored; giving them `fill="currentColor"` directly makes the whole mark render as one flat-colored logo, which is what we want here (it must follow `--fg` in both themes, not a hardcoded brand color).

- [ ] **Step 2: Apply the same replacement to `admin.html`**

Same header block, but with `<h1>Validator Fire Drill — Submissions</h1>` (plural, matching the existing text) instead of the `index.html` heading text.

- [ ] **Step 3: Style the header in `portal.css`**

Add:

```css
header.site-header {
  display: flex;
  align-items: baseline;
  gap: 0.75rem;
  margin-bottom: 1.5rem;
}

header.site-header .logo {
  width: 92px;
  height: auto;
  color: var(--fg);
  flex-shrink: 0;
}

header.site-header h1 {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0;
  color: var(--muted);
}
```

- [ ] **Step 4: Verify visually**

Open both `index.html` and `admin.html` in a browser. Confirm: the gnome mascot + "gno.land"-style wordmark renders at the top of each page, at a small size (~92px wide), followed by the page's original heading text in muted gray. Toggle dark mode (devtools Rendering tab, as in Task 2 Step 3) and confirm the logo's color follows the page text color (it's `currentColor`, driven by `--fg`).

- [ ] **Step 5: Commit**

```bash
git add cmd/portal/static/index.html cmd/portal/static/admin.html cmd/portal/static/portal.css
git commit -m "Add gno.land logo header to both portal pages"
```

---

### Task 4: Style the submission wizard (step badges, buttons, inputs, code block)

**Files:**
- Modify: `cmd/portal/static/portal.css`

**Interfaces:**
- Consumes: `--brand`, `--brand-hover`, `--brand-contrast`, `--border`, `--fg`, `--bg`, `--surface`, `--font-mono` (all from Task 2/1).
- Produces: nothing consumed by later tasks — this is leaf styling.

- [ ] **Step 1: Add step-number badges**

Add to `portal.css`:

```css
main {
  counter-reset: step;
}

.step h2 {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  font-size: 1rem;
}

.step h2::before {
  counter-increment: step;
  content: counter(step);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 1.5rem;
  height: 1.5rem;
  border-radius: 50%;
  background: var(--brand);
  color: var(--brand-contrast);
  font-size: 0.8rem;
  font-weight: 600;
  flex-shrink: 0;
}
```

This numbers every `.step` section's `<h2>` in document order (1, 2, 3, 4 — including the final "Submission received" step), since `main` wraps all four `.step` sections in `index.html`.

- [ ] **Step 2: Style buttons, inputs, and the code block**

Replace the existing `input[type="text"], input[type="file"]` and `button` and `pre` rules with:

```css
input[type="text"], input[type="file"] {
  display: block;
  width: 100%;
  margin: 0.5rem 0;
  padding: 0.5rem;
  box-sizing: border-box;
  font-family: inherit;
  font-size: 1rem;
  color: var(--fg);
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
}

input[type="text"]:focus, input[type="file"]:focus {
  outline: none;
  border-color: var(--brand);
}

button {
  padding: 0.5rem 1.25rem;
  font-family: inherit;
  font-size: 1rem;
  font-weight: 600;
  color: var(--brand-contrast);
  background: var(--brand);
  border: none;
  border-radius: 6px;
  cursor: pointer;
}

button:hover {
  background: var(--brand-hover);
}

pre {
  font-family: var(--font-mono);
  background: var(--surface);
  padding: 0.75rem;
  border-radius: 6px;
  overflow-x: auto;
  white-space: pre-wrap;
}
```

- [ ] **Step 3: Verify visually**

Open `index.html` in a browser. Confirm: each step heading has a small filled-green circular badge with its number (1–4); the "Get challenge" button is solid brand green and darkens on hover; clicking into the address text input shows a green focus border; the `<pre>` signing-command block (visible after getting a challenge — or just inspect it in devtools since it's populated by JS) uses the monospace font on a faint tinted background.

- [ ] **Step 4: Commit**

```bash
git add cmd/portal/static/portal.css
git commit -m "Style submission wizard steps, buttons, inputs, and code block"
```

---

### Task 5: Style the admin submissions table

**Files:**
- Modify: `cmd/portal/static/portal.css`

**Interfaces:**
- Consumes: `--border`, `--muted`, `--surface`, `--font-sans`, `--font-mono` (from Task 1/2).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Replace the table rules**

Replace the existing `table`, `th, td` rules with:

```css
table {
  width: 100%;
  border-collapse: collapse;
  font-family: var(--font-mono);
  font-size: 0.9rem;
}

th, td {
  border-bottom: 1px solid var(--border);
  padding: 0.6rem 0.5rem;
  text-align: left;
}

th {
  font-family: var(--font-sans);
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

tbody tr:nth-child(even) {
  background: var(--surface);
}
```

- [ ] **Step 2: Verify visually**

Open `admin.html` in a browser. The table starts empty (no submissions yet, and `admin.js`'s `fetch("/admin/submissions")` will fail over `file://` — that's expected and unrelated to this task). Confirm via devtools that the header row (`<thead>`) renders in small uppercase muted-gray text with letter-spacing, and that the `<table>` picks up the monospace font in Computed styles. To see actual striped data rows, run the full server (see Task 6) and submit at least one entry, or temporarily add a couple of `<tr><td>...</td></tr>` rows to `admin.html`'s `<tbody>` in devtools' Elements panel (don't commit that — it's just for the visual check) to confirm alternating-row tinting.

- [ ] **Step 3: Commit**

```bash
git add cmd/portal/static/portal.css
git commit -m "Style the admin submissions table"
```

---

### Task 6: Full cross-page, cross-theme QA

**Files:** none (verification only).

**Interfaces:** none.

- [ ] **Step 1: Run the real server**

From the repo root:

```bash
ADMIN_PASSWORD=test go run ./cmd/portal -remote https://rpc.test13.testnets.gno.land:443 -upload-dir /tmp/portal-uploads
```

(Any known gno.land testnet RPC endpoint works here — this only needs to start the server, not actually complete a submission.)

- [ ] **Step 2: Walk the submission page end-to-end, light theme**

Visit `http://localhost:8080/`. With the OS/browser in light mode: confirm the header logo, step badges, green buttons, and input focus states all render as designed; type a bogus address into step 1 and click "Get challenge" to confirm the `.error` text still renders (now in the new red token) and doesn't regress any existing JS behavior.

- [ ] **Step 3: Walk the admin page end-to-end, light theme**

Visit `http://localhost:8080/admin` (Basic Auth: any username, password `test`). Confirm the header renders, the table (even if empty) shows the styled header row, and `admin.js`'s 5-second polling still runs without console errors.

- [ ] **Step 4: Repeat both pages in dark theme**

Toggle the OS theme to dark (or devtools → Rendering → emulate `prefers-color-scheme: dark`) and repeat Steps 2–3. Confirm every color token flips (background, text, borders, buttons, badges, logo) with no element left on a hardcoded light-mode color, and no contrast issue (e.g., dark text on dark background).

- [ ] **Step 5: Confirm no console errors on either page in either theme**

Open devtools console on both pages; there should be no new errors introduced by this change (pre-existing network errors from `admin.js` polling with no backend data are not a regression — only new JS/CSS errors count).

- [ ] **Step 6: Stop the server**

`Ctrl-C` the `go run` process from Step 1.

No commit for this task — it's verification only, confirming Tasks 1–5's commits are correct together.
