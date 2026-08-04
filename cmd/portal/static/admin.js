"use strict";

// state is "ok", "caution", or "warn". Caution exists because some
// checks have a real middle outcome — a log the scan could only
// partially verify is not the same as one that failed.
function badge(state, text) {
  const span = document.createElement("span");
  span.className = "badge badge-" + state;
  span.textContent = text;
  return span;
}

// isEditing reports whether the admin currently has focus inside the
// submissions table, i.e. is part-way through entering a manual score.
function isEditing() {
  const table = document.getElementById("submissions");
  const active = document.activeElement;
  return Boolean(table && active && table.contains(active));
}

// buildLabeledInput wraps input in a <label> with visible text above it
// — the previous version relied on placeholder text alone to say what
// each box was for, which disappears the moment the admin starts
// typing (and never appears at all once a value is prefilled).
function buildLabeledInput(labelText, input) {
  const label = document.createElement("label");
  label.className = "score-field";
  const span = document.createElement("span");
  span.className = "score-field-label";
  span.textContent = labelText;
  label.append(span, input);
  return label;
}

function buildScoreForm(id, score) {
  const form = document.createElement("div");
  form.className = "score-form";

  const ackInput = document.createElement("input");
  ackInput.type = "text";
  ackInput.placeholder = "2026-07-08T19:00:00Z";

  const irqInput = document.createElement("input");
  irqInput.type = "number";
  irqInput.min = "0";
  irqInput.max = "20";
  irqInput.placeholder = "0-20";

  // Prefill from what was already recorded, so the form shows the
  // current values instead of looking permanently unfilled.
  if (score) {
    if (score.acknowledged_at) ackInput.value = score.acknowledged_at;
    if (typeof score.incident_response_quality_score === "number") {
      irqInput.value = String(score.incident_response_quality_score);
    }
  }

  const actions = document.createElement("div");
  actions.className = "score-form-actions";

  const button = document.createElement("button");
  button.type = "button";
  button.className = "btn-sm";
  button.textContent = "Save";

  // Errors from a Save land next to the form that produced them —
  // the shared #admin-error banner lives below the whole table, easy
  // to miss on a page with many rows, and previously the only place
  // this exact error ever appeared.
  const error = document.createElement("span");
  error.className = "error form-error";

  button.addEventListener("click", async () => {
    // An empty box gives Number("") === 0 and junk gives NaN, which
    // JSON.stringify writes as null. Both used to reach the server as a
    // score the admin never entered, so catch them here too rather than
    // relying on the 400 alone.
    const irq = Number(irqInput.value.trim());
    if (irqInput.value.trim() === "" || !Number.isInteger(irq)) {
      error.textContent = "Incident response quality score is required (whole number, 0-20).";
      return;
    }

    let resp;
    try {
      resp = await fetch(`/admin/submissions/${encodeURIComponent(id)}/score`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          acknowledged_at: ackInput.value.trim(),
          incident_response_quality_score: irq,
        }),
      });
    } catch (err) {
      error.textContent = "Network error: " + err.message;
      return;
    }
    if (!resp.ok) {
      error.textContent = await resp.text();
      return;
    }
    error.textContent = "";
    // force: this refresh is the point of the click, and focus is still
    // inside the table (on this button) when it runs.
    refresh({ force: true });
  });

  actions.append(button, error);
  form.append(
    buildLabeledInput("Acknowledged at (UTC)", ackInput),
    buildLabeledInput("Incident response (0–20)", irqInput),
    actions,
  );
  return form;
}

function buildDeleteButton(id, moniker, operatorAddress) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "icon-button";
  button.textContent = "Delete";
  button.setAttribute("aria-label", `Delete submission from ${moniker}`);
  button.addEventListener("click", () => openDeleteConfirm(id, moniker, operatorAddress));
  return button;
}

async function refresh({ force = false } = {}) {
  // Rebuilding the table throws away whatever is typed into a score
  // form, so the periodic refresh stands down while an admin is mid-entry
  // (half-written RFC3339 timestamps are easy to lose and annoying to
  // retype). Explicit refreshes — after a save — still go through.
  if (!force && isEditing()) return;

  let resp;
  try {
    resp = await fetch("/admin/submissions");
  } catch (err) {
    document.getElementById("admin-error").textContent = "Network error: " + err.message;
    return;
  }

  if (!resp.ok) {
    // The body carries the reason (e.g. an unreadable scores file), which
    // is the difference between a diagnosable failure and a table that
    // just silently shows everything as pending.
    const detail = (await resp.text()).trim();
    document.getElementById("admin-error").textContent =
      "Unable to load submissions (status " + resp.status + ")" + (detail ? ": " + detail : ".");
    return;
  }
  document.getElementById("admin-error").textContent = "";

  const submissions = await resp.json();
  const tbody = document.querySelector("#submissions tbody");
  tbody.innerHTML = "";
  for (const s of submissions) {
    const row = document.createElement("tr");

    // Identity used to be four separate columns (moniker, operator
    // address, filename, submitted at), which left barely any width for
    // the columns admins actually act on. Everything below the moniker
    // is secondary, so it's demoted to a muted subline instead of
    // competing for its own column.
    const validatorCell = document.createElement("td");
    const monikerEl = document.createElement("div");
    monikerEl.className = "validator-name";
    monikerEl.textContent = s.moniker; // never innerHTML — validator-controlled strings
    const addressEl = document.createElement("div");
    addressEl.className = "validator-meta";
    addressEl.textContent = s.operator_address;
    const fileEl = document.createElement("div");
    fileEl.className = "validator-meta";
    fileEl.textContent = `${s.filename} · ${s.submitted_at}`;
    validatorCell.append(monikerEl, addressEl, fileEl);
    row.appendChild(validatorCell);

    // total_score/pending come from the server (portal.AdminSubmission)
    // — the rubric lives in the scoring package, never in here.
    const scoreCell = document.createElement("td");
    if (!s.score || !s.score.scored) {
      const notYetScored = document.createElement("span");
      notYetScored.className = "validator-meta";
      notYetScored.textContent = "not yet scored";
      scoreCell.appendChild(notYetScored);
    } else {
      const totalEl = document.createElement("div");
      totalEl.className = "score-total";
      totalEl.textContent = `${s.total_score}/100`;
      scoreCell.append(
        totalEl,
        s.pending ? badge("caution", "pending") : badge("ok", "final"),
      );
    }
    row.appendChild(scoreCell);

    const checksCell = document.createElement("td");
    checksCell.className = "checks-cell";
    if (s.score && s.score.scored) {
      const w = s.score.log_window;
      let logState = "warn";
      let logText = "logs ✗";
      if (w.covered) {
        logState = "ok";
        logText = "logs ✓";
      } else if (w.truncated) {
        // Our scan stopped early, so coverage is unknown rather than
        // missing — don't render it as the validator's failure.
        logState = "caution";
        logText = "logs unverified";
      } else if (w.detected) {
        logState = "caution";
        logText = "logs partial";
      }

      checksCell.append(
        badge(s.score.genesis_match ? "ok" : "warn", s.score.genesis_match ? "genesis ✓" : "genesis ✗"),
        badge(s.score.version_supported ? "ok" : "warn", s.score.version_supported ? "version ✓" : "version ✗"),
        badge(logState, logText),
      );
    }
    row.appendChild(checksCell);

    const manualCell = document.createElement("td");
    manualCell.appendChild(buildScoreForm(s.id, s.score));
    row.appendChild(manualCell);

    const deleteCell = document.createElement("td");
    deleteCell.appendChild(buildDeleteButton(s.id, s.moniker, s.operator_address));
    row.appendChild(deleteCell);

    tbody.appendChild(row);
  }
}

refresh();
setInterval(() => refresh(), 5000);

async function loadExerciseConfig() {
  let resp;
  try {
    resp = await fetch("/admin/exercise");
  } catch (err) {
    document.getElementById("exercise-error").textContent = "Network error: " + err.message;
    return;
  }
  if (!resp.ok) {
    // Saving replaces the config wholesale, so a form that silently
    // failed to load is a loaded gun: fill in two fields, save, and
    // everything else is wiped. Say so instead of leaving it blank.
    document.getElementById("exercise-error").textContent =
      "Unable to load the current exercise config (status " +
      resp.status +
      "). Saving now would replace it with whatever this form contains.";
    return;
  }

  const cfg = await resp.json();
  const setIfPresent = (id, value) => {
    if (value) document.getElementById(id).value = value;
  };
  setIfPresent("ex-announced-at", cfg.announced_at?.startsWith("0001") ? "" : cfg.announced_at);
  setIfPresent("ex-deadline-at", cfg.deadline_at?.startsWith("0001") ? "" : cfg.deadline_at);
  setIfPresent("ex-window-start", cfg.investigation_window_start?.startsWith("0001") ? "" : cfg.investigation_window_start);
  setIfPresent("ex-window-end", cfg.investigation_window_end?.startsWith("0001") ? "" : cfg.investigation_window_end);
  setIfPresent("ex-genesis", cfg.expected_genesis_sha256);
  setIfPresent("ex-versions", (cfg.supported_gnoland_versions || []).join(", "));
  setIfPresent("ex-observations", cfg.observations);
}

document.getElementById("save-exercise").addEventListener("click", async () => {
  document.getElementById("exercise-error").textContent = "";
  document.getElementById("exercise-saved").hidden = true;

  const body = {
    announced_at: document.getElementById("ex-announced-at").value.trim(),
    deadline_at: document.getElementById("ex-deadline-at").value.trim(),
    investigation_window_start: document.getElementById("ex-window-start").value.trim(),
    investigation_window_end: document.getElementById("ex-window-end").value.trim(),
    expected_genesis_sha256: document.getElementById("ex-genesis").value.trim(),
    supported_gnoland_versions: document
      .getElementById("ex-versions")
      .value.split(",")
      .map((v) => v.trim())
      .filter(Boolean),
    observations: document.getElementById("ex-observations").value,
  };

  let resp;
  try {
    resp = await fetch("/admin/exercise", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (err) {
    document.getElementById("exercise-error").textContent = "Network error: " + err.message;
    return;
  }

  if (!resp.ok) {
    const text = await resp.text();
    document.getElementById("exercise-error").textContent = text || "Unable to save exercise config.";
    return;
  }

  document.getElementById("exercise-saved").hidden = false;
});

loadExerciseConfig();

// Tabs: aria-selected/hidden drive the visuals, the URL hash makes each
// tab linkable/bookmarkable (e.g. sharing a link straight to Validators).
const tabs = Array.from(document.querySelectorAll(".tab"));
const panels = {
  config: document.getElementById("panel-config"),
  validators: document.getElementById("panel-validators"),
};

function activateTab(name) {
  if (!panels[name]) name = "config";
  for (const tab of tabs) {
    const selected = tab.dataset.tab === name;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
  }
  for (const [key, panel] of Object.entries(panels)) {
    panel.hidden = key !== name;
  }
}

tabs.forEach((tab, index) => {
  tab.addEventListener("click", () => {
    location.hash = tab.dataset.tab;
  });

  // Roving tabindex + arrow keys, per the WAI-ARIA tabs pattern.
  tab.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    const next = tabs[(index + (event.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    next.focus();
    location.hash = next.dataset.tab;
  });
});

window.addEventListener("hashchange", () => activateTab(location.hash.slice(1)));
activateTab(location.hash.slice(1));

document.getElementById("generate-summary").addEventListener("click", async () => {
  const output = document.getElementById("summary-output");
  let resp;
  try {
    resp = await fetch("/admin/summary");
  } catch (err) {
    document.getElementById("admin-error").textContent = "Network error: " + err.message;
    return;
  }
  if (!resp.ok) {
    document.getElementById("admin-error").textContent = "Unable to generate summary (status " + resp.status + ").";
    return;
  }
  document.getElementById("admin-error").textContent = "";
  output.textContent = await resp.text();
  output.hidden = false;
});

// Delete confirmation dialog: shared across all rows, filled in with
// the target submission each time a row's delete button is clicked.
const deleteDialog = document.getElementById("delete-confirm");
const deleteDialogBody = document.getElementById("delete-confirm-body");
const deleteCancelButton = document.getElementById("delete-cancel");
const deleteConfirmButton = document.getElementById("delete-confirm-button");
let pendingDeleteID = null;

function openDeleteConfirm(id, moniker, operatorAddress) {
  pendingDeleteID = id;
  deleteDialogBody.textContent =
    `Delete the submission from ${moniker} (${operatorAddress})? Its score and uploaded archive will also be deleted. This cannot be undone.`;
  deleteDialog.showModal();
}

deleteCancelButton.addEventListener("click", () => {
  pendingDeleteID = null;
  deleteDialog.close();
});

deleteConfirmButton.addEventListener("click", async () => {
  const id = pendingDeleteID;
  if (!id) return;

  let resp;
  try {
    resp = await fetch(`/admin/submissions/${encodeURIComponent(id)}`, { method: "DELETE" });
  } catch (err) {
    deleteDialog.close();
    document.getElementById("admin-error").textContent = "Network error: " + err.message;
    return;
  }

  deleteDialog.close();
  pendingDeleteID = null;

  if (!resp.ok) {
    const detail = (await resp.text()).trim();
    document.getElementById("admin-error").textContent =
      "Unable to delete submission (status " + resp.status + ")" + (detail ? ": " + detail : ".");
    return;
  }
  document.getElementById("admin-error").textContent = "";
  refresh({ force: true });
});
