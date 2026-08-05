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
  const mb = n / (1024 * 1024);
  if (mb >= 1024) {
    return (mb / 1024).toFixed(1) + " GB";
  }
  return mb.toFixed(1) + " MB";
}

function setUploadProgress(loaded, total) {
  const pct = total > 0 ? Math.round((loaded / total) * 100) : 0;
  document.getElementById("upload-bar").value = pct;
  document.getElementById("upload-status").textContent =
    `Uploading — ${formatBytes(loaded)} / ${formatBytes(total)} (${pct}%)`;
}

function setUploadProcessing() {
  // Removing value — rather than pinning it to 100 — is what switches the
  // native element into its indeterminate animation. The bytes have left
  // the browser, but the server still has to scan, validate, and store
  // them, and that phase reports no progress of its own. A bar frozen at
  // 100% would read as a hang.
  document.getElementById("upload-bar").removeAttribute("value");
  document.getElementById("upload-status").textContent =
    "Upload complete. The server is scanning and validating your archive — " +
    "this can take several minutes for a large file. Keep this tab open.";
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
  xhr.upload.addEventListener("load", setUploadProcessing);

  xhr.addEventListener("load", () => {
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
    progress.hidden = true;
    button.disabled = false;
    setError("upload-error", "Network error while uploading.");
  });

  xhr.send(form);
});
