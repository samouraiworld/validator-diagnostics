"use strict";

function badge(ok, okText, warnText) {
  const span = document.createElement("span");
  span.className = "badge " + (ok ? "badge-ok" : "badge-warn");
  span.textContent = ok ? okText : warnText;
  return span;
}

// isEditing reports whether the admin currently has focus inside the
// submissions table, i.e. is part-way through entering a manual score.
function isEditing() {
  const table = document.getElementById("submissions");
  const active = document.activeElement;
  return Boolean(table && active && table.contains(active));
}

function buildScoreForm(id, score) {
  const form = document.createElement("span");
  form.className = "score-form";

  const ackInput = document.createElement("input");
  ackInput.type = "text";
  ackInput.placeholder = "ack RFC3339";

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

  const button = document.createElement("button");
  button.textContent = "Save";
  button.addEventListener("click", async () => {
    // An empty box gives Number("") === 0 and junk gives NaN, which
    // JSON.stringify writes as null. Both used to reach the server as a
    // score the admin never entered, so catch them here too rather than
    // relying on the 400 alone.
    const irq = Number(irqInput.value.trim());
    if (irqInput.value.trim() === "" || !Number.isInteger(irq)) {
      document.getElementById("admin-error").textContent =
        "Incident response quality score is required (whole number, 0-20).";
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
      document.getElementById("admin-error").textContent = "Network error: " + err.message;
      return;
    }
    if (!resp.ok) {
      document.getElementById("admin-error").textContent = await resp.text();
      return;
    }
    document.getElementById("admin-error").textContent = "";
    // force: this refresh is the point of the click, and focus is still
    // inside the table (on this button) when it runs.
    refresh({ force: true });
  });

  form.append(ackInput, irqInput, button);
  return form;
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

    for (const value of [s.moniker, s.operator_address, s.filename, s.submitted_at]) {
      const cell = document.createElement("td");
      cell.textContent = value; // never innerHTML — these are validator-controlled strings
      row.appendChild(cell);
    }

    // total_score/pending come from the server (portal.AdminSubmission)
    // — the rubric lives in the scoring package, never in here.
    const scoreCell = document.createElement("td");
    if (!s.score || !s.score.scored) {
      scoreCell.textContent = "not yet scored";
    } else if (s.pending) {
      scoreCell.textContent = `${s.total_score}/100 (manual scores pending)`;
    } else {
      scoreCell.textContent = `${s.total_score}/100`;
    }
    row.appendChild(scoreCell);

    const checksCell = document.createElement("td");
    if (s.score && s.score.scored) {
      checksCell.append(
        badge(s.score.genesis_match, "genesis ✓", "genesis ✗"),
        badge(s.score.version_supported, "version ✓", "version ✗"),
        badge(s.score.log_window.covered, "logs ✓", s.score.log_window.detected ? "logs partial" : "logs ✗"),
      );
    }
    row.appendChild(checksCell);

    const manualCell = document.createElement("td");
    manualCell.appendChild(buildScoreForm(s.id, s.score));
    row.appendChild(manualCell);

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
