// MoorAI Browser Guard — options page logic. Stores the user's config in chrome.storage.sync and, when a
// server URL is set, requests the runtime host permission for that origin so the background worker can
// POST to it (kept out of the always-on host_permissions to honor least privilege).
// Values an administrator set through browser policy (chrome.storage.managed, see config.js) are shown
// and win over anything saved here; with lockSettings they are read-only.

const FIELDS = { serverUrl: "serverUrl", installToken: "installToken", reportEnabled: "reportEnabled" };

function load() {
  globalThis.MoorAIConfig.load((cfg) => {
    document.getElementById(cfg.mode === "block" ? "mode-block" : "mode-coach").checked = true;
    document.getElementById("serverUrl").value = cfg.serverUrl || "";
    document.getElementById("installToken").value = cfg.installToken || "";
    document.getElementById("reportEnabled").checked = cfg.reportEnabled !== false;
    const managed = new Set(cfg.managedKeys || []);
    const note = document.getElementById("managed");
    if (managed.size) note.hidden = false;
    if (cfg.locked) note.textContent = "These settings are managed by your organization and cannot be changed here.";
    const lock = (id) => { const el = document.getElementById(id); if (el) el.disabled = true; };
    if (cfg.locked || managed.has("mode")) { lock("mode-block"); lock("mode-coach"); }
    for (const [k, id] of Object.entries(FIELDS)) if (cfg.locked || managed.has(k)) lock(id);
    if (cfg.locked) lock("save");
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
