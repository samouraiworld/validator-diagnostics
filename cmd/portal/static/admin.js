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
