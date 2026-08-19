// MoorAI Browser Guard — options page logic. Stores config in chrome.storage.sync and, when a server
// URL is set, requests the runtime host permission for that origin so the content script can POST to it
// (kept out of the always-on host_permissions to honor least privilege).

const DEFAULTS = { mode: "coach", serverUrl: "", installToken: "", reportEnabled: true };

function load() {
  chrome.storage.sync.get(DEFAULTS, (cfg) => {
    document.getElementById(cfg.mode === "block" ? "mode-block" : "mode-coach").checked = true;
    document.getElementById("serverUrl").value = cfg.serverUrl || "";
    document.getElementById("installToken").value = cfg.installToken || "";
    document.getElementById("reportEnabled").checked = cfg.reportEnabled !== false;
  });
}

function originPattern(url) {
  try { return new URL(url).origin + "/*"; } catch { return null; }
}

// Ask for the report endpoint's host permission (optional_host_permissions in the manifest).
function ensureHostPermission(serverUrl) {
  return new Promise((resolve) => {
    const pat = serverUrl ? originPattern(serverUrl) : null;
    if (!pat) return resolve(true);
    try {
      chrome.permissions.request({ origins: [pat] }, (granted) => resolve(!!granted));
    } catch { resolve(false); }
  });
}

async function save() {
  const mode = document.querySelector("input[name='mode']:checked")?.value || "coach";
  const serverUrl = document.getElementById("serverUrl").value.trim();
  const installToken = document.getElementById("installToken").value;
  const reportEnabled = document.getElementById("reportEnabled").checked;

  const status = document.getElementById("status");
  let permNote = "";
  if (serverUrl && reportEnabled) {
    const ok = await ensureHostPermission(serverUrl);
    if (!ok) permNote = " (reporting host permission not granted — signals will not be sent)";
  }

  chrome.storage.sync.set({ mode, serverUrl, installToken, reportEnabled }, () => {
    status.textContent = "Saved." + permNote;
    setTimeout(() => (status.textContent = ""), 4000);
  });
}

document.addEventListener("DOMContentLoaded", load);
document.getElementById("save").addEventListener("click", save);
