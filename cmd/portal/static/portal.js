"use strict";

let currentNonce = null;
let currentOperatorAddress = null;
let sessionToken = null;

function show(id) {
  document.getElementById(id).hidden = false;
}

function setError(id, message) {
  document.getElementById(id).textContent = message || "";
}

// The server always returns JSON, but a response from something else
// entirely (a proxy's plain-text error page, a static file server
// during local testing) might not be — .json() throws on that, so every
// non-network-error response goes through this instead of a bare
// `await resp.json()`.
async function parseJSONResponse(resp) {
  try {
    return await resp.json();
  } catch (err) {
    return { error: `Unexpected response from server (status ${resp.status}).` };
  }
}

// The XHR twin of parseJSONResponse: the same guard against a response
// that isn't JSON at all (a proxy's plain-text error page), for the one
// request that needs XHR's upload progress events.
function parseJSONText(text, status) {
  try {
    return JSON.parse(text);
  } catch (err) {
    return { error: `Unexpected response from server (status ${status}).` };
  }
}

function formatBytes(n) {
  // Divides by 1024, so the labels are the binary units (MiB/GiB), not
  // the decimal ones (MB/GB) — matches the README, .env.example, and this
  // page's own help text, which all quote limits in MiB/GiB.
  //
  // Below 1 MiB this used to floor to "0.0 MiB" for any value; bytes and
  // KiB get their own bands instead of being rounded away. 1 MiB and up
  // is unchanged from before. Duplicated in admin.js — keep both copies
  // identical.
  if (n < 1024) {
    return n + " B";
  }
  const kib = n / 1024;
  if (kib < 1024) {
    return kib.toFixed(1) + " KiB";
  }
  const mib = kib / 1024;
  if (mib >= 1024) {
    return (mib / 1024).toFixed(1) + " GiB";
  }
  return mib.toFixed(1) + " MiB";
}

function setUploadProgress(loaded, total) {
  const pct = total > 0 ? Math.round((loaded / total) * 100) : 0;
  document.getElementById("upload-bar").value = pct;
  // Visual only — upload-status is aria-live="off" in the markup — since
  // this fires many times per second for a large upload. upload-phase
  // (see announcePhase) is the screen-reader-facing surface and is left
  // untouched here.
  document.getElementById("upload-status").textContent =
    `Uploading — ${formatBytes(loaded)} / ${formatBytes(total)} (${pct}%)`;
}

// announcePhase updates the polite live region that only changes at phase
// transitions (upload started, upload complete). Kept separate from the
// continuously-updating upload-status text so a screen reader announces
// twice per submission instead of once per progress event.
function announcePhase(message) {
  document.getElementById("upload-phase").textContent = message;
}

function setUploadProcessing() {
  // Removing value — rather than pinning it to 100 — is what switches the
  // native element into its indeterminate animation. The bytes have left
  // the browser, but the server still has to scan, validate, and store
  // them, and that phase reports no progress of its own. A bar frozen at
  // 100% would read as a hang.
  document.getElementById("upload-bar").removeAttribute("value");
  const message =
    "Upload complete. The server is scanning and validating your archive — " +
    "this can take several minutes for a large file. Keep this tab open.";
  document.getElementById("upload-status").textContent = message;
  announcePhase(message);
}

function formatDuration(seconds) {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) {
    return s + "s";
  }
  return Math.floor(s / 60) + "m " + (s % 60) + "s";
}

// PHASE_SENTENCES is what the validator reads for each server-side phase
// (portal.Phase). A phase this page does not know about falls back to the
// generic message rather than rendering a raw identifier.
const PHASE_SENTENCES = {
  validating: "Checking the archive's structure.",
  scanning: "Antivirus scan in progress.",
  storing: "Storing the archive.",
  scoring: "Scoring your submission.",
};

let announcedPhase = null;

// renderServerProgress paints one poll result. The scanning phase gets an
// indeterminate bar and absolute numbers on purpose: the log's decompressed
// size is not known until it has been decompressed, so there is no honest
// denominator, and a bar driven by the budget instead would glide along and
// then jump to done. Storing is the opposite case — its total is the
// archive's own size — so it gets a real percentage.
function renderServerProgress(p) {
  const bar = document.getElementById("upload-bar");
  const status = document.getElementById("upload-status");
  const detail = document.getElementById("upload-detail");

  const sentence = PHASE_SENTENCES[p.phase] || "The server is processing your archive.";
  let detailText = "";

  if (p.phase === "storing" && p.total > 0) {
    const pct = Math.round((p.bytes / p.total) * 100);
    bar.value = pct;
    detailText = `${formatBytes(p.bytes)} / ${formatBytes(p.total)} (${pct}%)`;
  } else {
    bar.removeAttribute("value");
    if (p.phase === "scanning") {
      const elapsed = (Date.now() - Date.parse(p.phase_started_at)) / 1000;
      const rate = elapsed > 0 ? p.bytes / elapsed : 0;
      detailText =
        `${formatBytes(p.bytes)} streamed · ${formatDuration(elapsed)} · ${formatBytes(rate)}/s`;
    }
  }

  status.textContent = sentence + " Keep this tab open.";
  detail.textContent = detailText;

  // Announced only when the phase itself changes — the byte count beside it
  // refreshes every two seconds and must never reach the live region.
  if (p.phase !== announcedPhase) {
    announcedPhase = p.phase;
    announcePhase(sentence);
  }
}

let progressTimer = null;

// startProgressPolling opens the second connection this page needs: the
// submission's own response cannot report progress without freezing its
// status code, so progress arrives on its own request.
//
// Every failure path here returns silently. A 404 is normal — it is the
// answer until the server finishes reading the request body, and again once
// it has responded — and a network error on a poll says nothing about the
// upload, which is being decided on the other connection entirely. If polling
// never succeeds, the page simply keeps the message setUploadProcessing left.
function startProgressPolling(token) {
  stopProgressPolling();
  announcedPhase = null;

  progressTimer = setInterval(async () => {
    let resp;
    try {
      resp = await fetch("/submit/progress", {
        headers: { Authorization: "Bearer " + token },
      });
    } catch (err) {
      return;
    }
    if (!resp.ok) {
      return;
    }

    let p;
    try {
      p = await resp.json();
    } catch (err) {
      return;
    }

    // The submission may have completed while this poll was in flight;
    // painting now would resurrect a panel the load handler just hid.
    if (progressTimer === null) {
      return;
    }
    renderServerProgress(p);
  }, 2000);
}

function stopProgressPolling() {
  if (progressTimer !== null) {
    clearInterval(progressTimer);
    progressTimer = null;
  }
}

document.getElementById("get-challenge").addEventListener("click", async () => {
  setError("address-error", "");
  const address = document.getElementById("operator-address").value.trim();
  if (!address) {
    setError("address-error", "Enter your operator address.");
    return;
  }

  let resp;
  try {
    resp = await fetch("/auth/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operator_address: address }),
    });
  } catch (err) {
    setError("address-error", "Network error: " + err.message);
    return;
  }

  const data = await parseJSONResponse(resp);
  if (!resp.ok) {
    setError("address-error", data.error || "Unable to get a challenge.");
    return;
  }

  currentNonce = data.nonce;
  currentOperatorAddress = address;

  const challengeJSON = JSON.stringify(data.challenge_tx, null, 2);
  const blob = new Blob([challengeJSON], { type: "application/json" });
  const link = document.getElementById("download-challenge");
  link.href = URL.createObjectURL(blob);

  document.getElementById("sign-command").textContent =
    `gnokey sign --tx-path challenge.json \\\n` +
    `  --chainid ${data.chainid} \\\n` +
    `  --account-number ${data.account_number} --account-sequence ${data.account_sequence} \\\n` +
    `  --output-document sig.json <your-operator-key-name>`;

  show("step-sign");
});

document.getElementById("verify-signature").addEventListener("click", async () => {
  setError("sign-error", "");
  const fileInput = document.getElementById("sig-file");
  const file = fileInput.files[0];
  if (!file) {
    setError("sign-error", "Choose the sig.json file produced by gnokey sign.");
    return;
  }

  let sigDoc;
  try {
    sigDoc = JSON.parse(await file.text());
  } catch (err) {
    setError("sign-error", "sig.json is not valid JSON: " + err.message);
    return;
  }
  if (!sigDoc.signature) {
    setError("sign-error", 'sig.json has no "signature" field.');
    return;
  }

  let resp;
  try {
    resp = await fetch("/auth/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        operator_address: currentOperatorAddress,
        nonce: currentNonce,
        signature: sigDoc.signature,
      }),
    });
  } catch (err) {
    setError("sign-error", "Network error: " + err.message);
    return;
  }

  const data = await parseJSONResponse(resp);
  if (!resp.ok || !data.ok) {
    setError("sign-error", data.error || "Verification failed.");
    return;
  }

  sessionToken = data.session_token;
  document.getElementById("authenticated-address").textContent = currentOperatorAddress;
  show("step-upload");
});

document.getElementById("submit-archive").addEventListener("click", () => {
  setError("upload-error", "");
  const fileInput = document.getElementById("archive-file");
  const file = fileInput.files[0];
  if (!file) {
    setError("upload-error", "Choose the diagnostic archive to upload.");
    return;
  }

  const form = new FormData();
  form.append("archive", file, file.name);

  const button = document.getElementById("submit-archive");
  const progress = document.getElementById("upload-progress");

  // Disabled for the whole in-flight window, not just the transfer: a
  // second click during the AV scan would start another upload of the
  // same multi-hundred-megabyte archive.
  button.disabled = true;
  progress.hidden = false;
  setUploadProgress(0, file.size);
  announcePhase("Upload started.");

  // fetch() reports no progress for the request body, so this one call
  // uses XMLHttpRequest; /auth/challenge and /auth/verify stay on fetch.
  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/submit");
  xhr.setRequestHeader("Authorization", "Bearer " + sessionToken);

  xhr.upload.addEventListener("progress", (e) => {
    if (e.lengthComputable) {
      setUploadProgress(e.loaded, e.total);
    }
  });

  // Fires when the last byte is handed to the network stack — which is
  // not the same as the server having received and processed it.
  xhr.upload.addEventListener("load", () => {
    setUploadProcessing();
    startProgressPolling(sessionToken);
  });

  xhr.addEventListener("load", () => {
    stopProgressPolling();
    progress.hidden = true;
    button.disabled = false;

    const data = parseJSONText(xhr.responseText, xhr.status);
    if (xhr.status < 200 || xhr.status >= 300 || !data.ok) {
      setError("upload-error", data.error || "Submission failed.");
      return;
    }

    document.getElementById("done-message").textContent =
      `Archive for "${data.moniker}" received (submitted_at: ${data.submitted_at}).`;
    show("step-done");
  });

  xhr.addEventListener("error", () => {
    stopProgressPolling();
    progress.hidden = true;
    button.disabled = false;
    setError("upload-error", "Network error while uploading.");
  });

  xhr.addEventListener("abort", () => {
    stopProgressPolling();
    progress.hidden = true;
    button.disabled = false;
  });

  xhr.send(form);
});
