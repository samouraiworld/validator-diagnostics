"use strict";

function badge(ok, okText, warnText) {
  const span = document.createElement("span");
  span.className = "badge " + (ok ? "badge-ok" : "badge-warn");
  span.textContent = ok ? okText : warnText;
  return span;
}

function buildScoreForm(id) {
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

  const button = document.createElement("button");
  button.textContent = "Save";
  button.addEventListener("click", async () => {
    let resp;
    try {
      resp = await fetch(`/admin/submissions/${id}/score`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          acknowledged_at: ackInput.value.trim(),
          incident_response_quality_score: Number(irqInput.value),
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
    refresh();
  });

  form.append(ackInput, irqInput, button);
  return form;
}

async function refresh() {
  let resp;
  try {
    resp = await fetch("/admin/submissions");
  } catch (err) {
    document.getElementById("admin-error").textContent = "Network error: " + err.message;
    return;
  }

  if (!resp.ok) {
    document.getElementById("admin-error").textContent =
      "Unable to load submissions (status " + resp.status + ").";
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

    const scoreCell = document.createElement("td");
    scoreCell.textContent = s.score && s.score.scored ? `${s.score.upload_time_score + s.score.metadata_score + s.score.log_quality_score + (s.score.ack_time_score || 0) + (s.score.incident_response_quality_score || 0)}/100` : "pending";
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
    manualCell.appendChild(buildScoreForm(s.id));
    row.appendChild(manualCell);

    tbody.appendChild(row);
  }
}

refresh();
setInterval(refresh, 5000);

async function loadExerciseConfig() {
  let resp;
  try {
    resp = await fetch("/admin/exercise");
  } catch (err) {
    document.getElementById("exercise-error").textContent = "Network error: " + err.message;
    return;
  }
  if (!resp.ok) return;

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
