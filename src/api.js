// Client ↔ server bridge. Offline-tolerant: failures never block the user.
import { startSignup, pollClaim } from "./signup.js";
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
    try {
      identity = await invoke("identity");
      // Mirror the native provision into localStorage the same way enroll() does. An MDM-provisioned
      // install (Jamf/Intune writes ~/.curaiq/config.json directly) never runs enroll(), and the
      // content-hash key is derived from these two values — without them the renderer would emit the
      // non-correlatable NO_KEY sentinel on a device that is in fact enrolled.
      if (identity.tenant) localStorage.setItem("raiseme.tenant", identity.tenant);
      if (identity.installToken) localStorage.setItem("raiseme.installToken", identity.installToken);
    } catch {}
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

// In-app signup: create the management account and get back the claim token used to wait for the
// verification click. The protocol lives in ./signup.js; this only binds the real fetch + BASE.
export function signUp(name, email) {
  return startSignup({ base: BASE, name, email, fetchImpl: (u, o) => fetch(u, o) });
}

// Wait for the verification click, then provision through the SAME enroll() the paste-a-token path
// uses — so there is exactly one place that persists a provision.
export async function awaitClaim(claimToken, onPending) {
  const ready = await pollClaim({
    base: BASE,
    claimToken,
    fetchImpl: (u, o) => fetch(u, o),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    onPending
  });
  return await enroll(ready.installToken, ready.serverUrl);
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
    let aiShadow = null; // Feature 2 — shadow-AI: catalog-matched AI apps + AI browser extensions (names/ids/flags only)
    try { aiShadow = await invoke("device_ai_shadow"); } catch {}
    const full = { ...dev, browsers, mcp, posture, accounts, aiAssets, aiShadow };
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

// #23 — image OCR deliberately does NOT live here. It is a native, on-device call (see src/ocr.js →
// src-tauri/src/ocr.rs): the raw image must never reach the MoorAI console, so there is no image
// endpoint in this module. Where the OS ships no text-recognition engine, the host talks to the
// developer's own AI provider directly with the key already on the device — still not through us.

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
