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

document.getElementById("submit-archive").addEventListener("click", async () => {
  setError("upload-error", "");
  const fileInput = document.getElementById("archive-file");
  const file = fileInput.files[0];
  if (!file) {
    setError("upload-error", "Choose the diagnostic archive to upload.");
    return;
  }

  const form = new FormData();
  form.append("archive", file, file.name);

  let resp;
  try {
    resp = await fetch("/submit", {
      method: "POST",
      headers: { Authorization: "Bearer " + sessionToken },
      body: form,
    });
  } catch (err) {
    setError("upload-error", "Network error: " + err.message);
    return;
  }

  const data = await parseJSONResponse(resp);
  if (!resp.ok || !data.ok) {
    setError("upload-error", data.error || "Submission failed.");
    return;
  }

  document.getElementById("done-message").textContent =
    `Archive for "${data.moniker}" received (submitted_at: ${data.submitted_at}).`;
  show("step-done");
});
