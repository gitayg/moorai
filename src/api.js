// Client ↔ server bridge. Offline-tolerant: failures never block the user.
const BASE = (localStorage.getItem("raiseme.server") || "https://moorai.glick.run").replace(/\/+$/, "");
const CLIENT_ID = (() => {
  let id = localStorage.getItem("raiseme.clientId");
  if (!id) { id = "c-" + Math.abs(hashStr(navigator.userAgent + screen.width)).toString(16); localStorage.setItem("raiseme.clientId", id); }
  return id;
})();

function hashStr(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = (h << 5) + h + s.charCodeAt(i);
  return h | 0;
}

// Who/what generated the alert. Native OS identity inside the Tauri host; best-effort in a browser.
let identity = { user: "(browser)", device: navigator.platform || "web", platform: "web", tenant: localStorage.getItem("raiseme.tenant") || "unprovisioned", installToken: localStorage.getItem("raiseme.installToken") || "" };
// The install token authenticates the client to the server for policy + event reporting only.
function installTok() { return identity.installToken || localStorage.getItem("raiseme.installToken") || ""; }
export async function loadIdentity() {
  const invoke = window.__TAURI__?.core?.invoke;
  if (invoke) {
    try { identity = await invoke("identity"); } catch {}
  }
  return identity;
}

export function serverBase() { return BASE; }
export async function appVersion() {
  const invoke = window.__TAURI__?.core?.invoke;
  if (invoke) { try { return await invoke("app_version"); } catch {} }
  return "";
}

export async function restartApp() {
  const invoke = window.__TAURI__?.core?.invoke;
  if (invoke) { try { await invoke("restart_app"); return true; } catch {} }
  return false;
}

export async function aboutInfo() {
  const invoke = window.__TAURI__?.core?.invoke;
  if (invoke) { try { return await invoke("about_info"); } catch {} }
  return { version: "", identifier: "run.glick.curaiq", platform: "web", arch: "", authority: "—", signed: false };
}

// Silently check the update server, and if a newer signed build exists, download + install it in
// place. Returns true when an update was installed (caller then restarts to apply).
export async function checkAndInstallUpdate() {
  const invoke = window.__TAURI__?.core?.invoke;
  if (invoke) { try { return await invoke("check_and_install_update"); } catch { return false; } }
  return false;
}

function cmpVer(a, b) {
  const pa = String(a).split("."), pb = String(b).split(".");
  for (let i = 0; i < 3; i++) {
    const x = Number(pa[i]) || 0, y = Number(pb[i]) || 0;
    if (x > y) return 1; if (x < y) return -1;
  }
  return 0;
}

// On startup, compare this build to the server's published version. The host + server ship
// together, so server > host means a newer build is available to download.
export async function checkUpdate() {
  try {
    const current = await appVersion();
    if (!current) return null;
    const h = await fetch(`${BASE}/api/health`, { signal: AbortSignal.timeout(8000) }).then((r) => r.json());
    const latest = h.version;
    return { current, latest, updateAvailable: !!latest && cmpVer(latest, current) > 0, url: `${BASE}/download/app` };
  } catch {
    return null;
  }
}
export function getAuthMethod() { return localStorage.getItem("raiseme.authMethod") || "oauth"; }
export function setAuthMethod(m) { localStorage.setItem("raiseme.authMethod", m); }

// Save the agent auth (method: "oauth" | "apikey", + optional token).
export async function setAgentAuth(method, token) {
  localStorage.setItem("raiseme.authMethod", method);
  if (token) localStorage.setItem("raiseme.agentToken", token);
  else localStorage.removeItem("raiseme.agentToken");
  const invoke = window.__TAURI__?.core?.invoke;
  if (invoke) { await invoke("set_agent_auth", { method, token: token || "" }); return true; }
  return false;
}

export async function openLoginTerminal() {
  const invoke = window.__TAURI__?.core?.invoke;
  if (invoke) { await invoke("open_login_terminal"); return true; }
  return false;
}

export async function openUrl(url) {
  const invoke = window.__TAURI__?.core?.invoke;
  if (invoke) { try { await invoke("open_url", { url }); return; } catch {} }
  window.open(url, "_blank", "noopener");
}

async function callAnthropic(prompt, token, method) {
  const model = localStorage.getItem("raiseme.model") || "claude-sonnet-4-6";
  const headers = {
    "content-type": "application/json",
    "anthropic-version": "2023-06-01",
    "anthropic-dangerous-direct-browser-access": "true"
  };
  if (method === "oauth") { headers["authorization"] = `Bearer ${token}`; headers["anthropic-beta"] = "oauth-2025-04-20"; }
  else headers["x-api-key"] = token;

  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers,
    body: JSON.stringify({ model, max_tokens: 1024, messages: [{ role: "user", content: prompt }] })
  });
  if (!r.ok) throw new Error(`Anthropic API ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const d = await r.json();
  return (d.content || []).map((b) => b.text || "").join("") || "(empty response)";
}
export function currentTenant() { return identity.tenant; }

// Enroll the device by pasting an installation token: fetch its provision and persist it.
export async function enroll(token, serverUrl) {
  const base = (serverUrl || BASE).replace(/\/+$/, "");
  const prov = await fetch(`${base}/d/${encodeURIComponent(token)}`).then((r) => (r.ok ? r.json() : Promise.reject(new Error("invalid or unknown token"))));
  const invoke = window.__TAURI__?.core?.invoke;
  // Persist the install token alongside the provision — the client uses it to authenticate
  // policy fetches and event reports to the server.
  if (invoke) await invoke("save_provision", { config: { ...prov, installToken: token } });
  // Always persist so BASE resolves to the enrolled server on next boot (Tauri or browser).
  localStorage.setItem("raiseme.tenant", prov.tenant);
  if (prov.serverUrl) localStorage.setItem("raiseme.server", prov.serverUrl);
  localStorage.setItem("raiseme.installToken", token);
  identity.tenant = prov.tenant;
  identity.installToken = token;
  return prov;
}

// Lightweight, scan-independent beacon: lands identity + agent version on the server immediately at
// boot, without waiting for the slower device/browser scans (which can be slow or hang).
export function reportIdentity() {
  fetch(`${BASE}/api/device-report`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Client-Id": CLIENT_ID, "X-Install-Token": installTok() },
    body: JSON.stringify({ ...identity }),
    keepalive: true
  }).catch(() => {});
}

// Once the client runs, report the device's other AI tools + OS to the MoorAI server.
export async function reportDevice() {
  const invoke = window.__TAURI__?.core?.invoke;
  if (!invoke) return null;
  try {
    const dev = await invoke("device_ai_tools");
    let browsers = [];
    try { browsers = await invoke("device_browsers"); } catch {}
    let mcp = [];
    try { mcp = (await invoke("device_mcp")).servers || []; } catch {}
    let posture = null;
    try { const p = await invoke("device_posture"); if (p && Object.keys(p).length) posture = p; } catch {}
    let accounts = [];
    try { accounts = (await invoke("device_accounts")).accounts || []; } catch {}
    let aiAssets = null; // #7 — models/providers + local models (config metadata only)
    try { aiAssets = await invoke("device_ai_assets"); } catch {}
    const full = { ...dev, browsers, mcp, posture, accounts, aiAssets };
    fetch(`${BASE}/api/device-report`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Client-Id": CLIENT_ID, "X-Install-Token": installTok() },
      body: JSON.stringify({ ...identity, ...full }),
      keepalive: true
    }).catch(() => {});
    return full;
  } catch { return null; }
}

// Slower OS-patch posture check, sent as a follow-up device report (keeps tools+os from `dev`).
export async function reportPatches(dev) {
  const invoke = window.__TAURI__?.core?.invoke;
  if (!invoke) return null;
  try {
    const patches = await invoke("os_patch_status");
    fetch(`${BASE}/api/device-report`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Client-Id": CLIENT_ID, "X-Install-Token": installTok() },
      body: JSON.stringify({ ...identity, ...(dev || {}), patches }),
      keepalive: true
    }).catch(() => {});
    return patches;
  } catch { return null; }
}

export async function getPolicy() {
  try {
    const q = `tenant=${encodeURIComponent(identity.tenant)}&user=${encodeURIComponent(identity.user)}&device=${encodeURIComponent(identity.device)}`;
    const r = await fetch(`${BASE}/api/policy?${q}`, { headers: { "X-Install-Token": installTok() }, signal: AbortSignal.timeout(8000) });
    return r.ok ? await r.json() : null;
  } catch {
    return null;
  }
}

// #23 — OCR a base64 image via the server's BYO-vision key (key stays server-side; only the
// extracted text returns, then the host runs the same PII/secret policy on it). Throws on failure so
// the caller can fall back to the "not inspected" card.
export async function ocrImage(base64, mime) {
  const r = await fetch(`${BASE}/api/ocr`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Client-Id": CLIENT_ID, "X-Install-Token": installTok() },
    body: JSON.stringify({ image: base64, mime: mime || "image/png" }),
    signal: AbortSignal.timeout(30000)
  });
  if (!r.ok) { let e = `ocr ${r.status}`; try { e = (await r.json()).error || e; } catch {} throw new Error(e); }
  return (await r.json()).text || "";
}

// Send an approved prompt to the agent. Primary path: direct Anthropic API with the saved key
// (works without the claude CLI). Fallback: the local claude CLI in the native host.
export async function runAgent(prompt) {
  const method = getAuthMethod();
  const token = localStorage.getItem("raiseme.agentToken");
  const invoke = window.__TAURI__?.core?.invoke;

  // API key → direct API call (works without the claude CLI).
  if (method === "apikey" && token) {
    try { return { ok: true, text: await callAnthropic(prompt, token, "apikey") }; }
    catch (e) { return { ok: false, text: String(e.message || e) }; }
  }

  // OAuth → the claude CLI (it holds the subscription login and manages tokens/refresh).
  if (invoke) {
    try { return { ok: true, text: await invoke("run_agent", { prompt }) }; }
    catch (e) { return { ok: false, text: `${e}\n\nOAuth runs through the claude CLI — run \`claude\` to log in, or switch to API key in setup.` }; }
  }
  return {
    ok: false,
    text: method === "apikey"
      ? "Add an API key in setup (the tenant chip)."
      : "OAuth needs the claude CLI — install it and run `claude` to log in, or switch to API key in setup."
  };
}

// When running inside the Tauri host, also persist to the native on-device audit sink.
export function nativeLog(entry) {
  const invoke = window.__TAURI__?.core?.invoke;
  if (invoke) invoke("native_log", { entry }).catch(() => {});
}

// Fire-and-forget: sends only the redacted alert metadata + who/what generated it.
export function postAlert(alert) {
  if (!alert) return;
  fetch(`${BASE}/api/alerts`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Client-Id": CLIENT_ID, "X-Install-Token": installTok() },
    body: JSON.stringify({ ...alert, ...identity }),
    keepalive: true
  }).catch(() => {});
}

// Counts a prompt the user pushed to the agent. Metadata only — no prompt content.
// outcome: "sent" (reached the agent) | "blocked" (stopped by policy).
export function reportPrompt(outcome, findings = 0) {
  fetch(`${BASE}/api/prompt-event`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Client-Id": CLIENT_ID, "X-Install-Token": installTok() },
    body: JSON.stringify({ outcome, findings, ts: new Date().toISOString(), ...identity }),
    keepalive: true
  }).catch(() => {});
}
