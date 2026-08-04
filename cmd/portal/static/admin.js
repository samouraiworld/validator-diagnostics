"use strict";

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

  const entries = await resp.json();
  const tbody = document.querySelector("#submissions tbody");
  tbody.innerHTML = "";
  for (const e of entries) {
    const row = document.createElement("tr");
    for (const value of [e.moniker, e.operator_address, e.filename, e.submitted_at]) {
      const cell = document.createElement("td");
      cell.textContent = value; // never innerHTML — these are validator-controlled strings
      row.appendChild(cell);
    }
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
