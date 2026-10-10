// Client ↔ server bridge. Offline-tolerant: failures never block the user.
import { startSignup, pollClaim } from "./signup.js";
import { contentHash } from "./content-hash.js";
import { enforcementAllowed } from "../data/enforcement.js";
// The MoorAI cloud console. Only an unprovisioned consumer install falls back to it (serverBase()).
const CLOUD_BASE = "https://app.moorai.dev";
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
// Who, as the console may store it: the tenant-keyed hash of user@device — byte-identical to the CLI
// senders' actorHash() — so one machine is one actor across the hook, the MCP proxy and this app.
// `user`/`device` still travel so per-device policy resolves; the console pseudonymises them on ingest.
// The install token is not part of it: it authenticates in the X-Install-Token header only.
function reported() { const { installToken: _tok, ...who } = identity; return { ...who, actor: contentHash(`${identity.user}@${identity.device}`) }; }
// The install token authenticates the client to the server for policy + event reporting only.
function installTok() { return identity.installToken || localStorage.getItem("raiseme.installToken") || ""; }
// Where the install token may go. Inside the desktop host that is identity.console: the origin the host
// recorded at enrolment (src-tauri/src/console_binding.rs) — null when it refused one, and then nothing
// credentialed is sent. localStorage ("raiseme.server") and ~/.moorai/config.json are writable by other
// software running as the user, so neither decides it. A host too old to report the field, and the
// plain-browser build, keep serverBase().
let hostConsole, hostConsoleWarning = null, hostProvisioned = null;
function credBase() { return hostConsole === undefined ? serverBase() : hostConsole; }
export function consoleWarning() { return hostConsoleWarning; }
export function consoleBound() { return credBase() != null; }
// Every request that carries a credential: never follow a redirect with it.
const CRED = { redirect: "error" };
// https, or http to localhost only — the same rule the host applies (normalize_origin).
export function safeConsoleOrigin(u) {
  try {
    const x = new URL(u);
    if (x.username || x.password) return null;
    if (x.protocol === "https:" || (x.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(x.hostname))) return x.origin;
  } catch {}
  return null;
}
// Coach vs enforce, and post vs stay local — the shared rule (data/enforcement.js). An unenrolled app
// has no console: it coaches in the UI and posts nothing.
export function enrolled() { return enforcementAllowed({ installToken: installTok() }); }
export async function loadIdentity() {
  const invoke = window.__TAURI__?.core?.invoke;
  if (invoke) {
    try {
      identity = await invoke("identity");
      if ("console" in identity) { hostConsole = identity.console || null; hostConsoleWarning = identity.consoleWarning || null; }
      hostProvisioned = safeConsoleOrigin(identity.serverUrl || "");
      // Mirror the native provision into localStorage the same way enroll() does. An MDM-provisioned
      // install (Jamf/Intune writes ~/.moorai/config.json directly) never runs enroll(), and the
      // content-hash key is derived from these two values — without them the renderer would emit the
      // non-correlatable NO_KEY sentinel on a device that is in fact enrolled.
      if (identity.tenant) localStorage.setItem("raiseme.tenant", identity.tenant);
      if (identity.installToken) localStorage.setItem("raiseme.installToken", identity.installToken);
    } catch {}
  }
  return identity;
}

// The console this app talks to: the one the host recorded at enrolment, else the provisioned
// serverUrl (an MDM-written ~/.moorai/config.json), else a localStorage override, else the MoorAI cloud.
// A provisioned device therefore never falls back to the cloud, before or after enrolment.
export function serverBase() {
  return hostConsole || hostProvisioned || safeConsoleOrigin(localStorage.getItem("raiseme.server") || "") || CLOUD_BASE;
}

// One console call. In the desktop host it goes through the host (src-tauri/src/console_http.rs): the
// host picks the origin for credentialed calls and attaches the install token itself, so the webview's
// CSP names no console and a self-hosted console works at any origin. The plain-browser build fetches.
// → { ok, status, body }; throws on a refused call, a network failure or a timeout.
export async function consoleCall({ method = "GET", path, body, credentialed = false, base }) {
  const invoke = window.__TAURI__?.core?.invoke;
  if (invoke) {
    const r = await invoke("console_fetch", { req: { method, path, body: body ?? null, credentialed, base: credentialed ? null : base, clientId: CLIENT_ID } });
    return { ok: r.status >= 200 && r.status < 300, status: r.status, body: r.body };
  }
  const origin = credentialed ? credBase() : base;
  if (!origin) throw new Error("no console");
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (credentialed) { headers["X-Client-Id"] = CLIENT_ID; headers["X-Install-Token"] = installTok(); }
  const r = await fetch(`${origin}${path}`, { ...CRED, method, headers, body: body !== undefined ? JSON.stringify(body) : undefined, keepalive: method === "POST", signal: AbortSignal.timeout(8000) });
  return { ok: r.ok, status: r.status, body: await r.json().catch(() => null) };
}
// fetch-shaped adapter over consoleCall for ./signup.js, which builds `${base}/path` URLs itself.
function consoleFetchImpl(base) {
  return async (u, o = {}) => {
    const r = await consoleCall({ method: o.method || "GET", path: String(u).slice(base.length), body: o.body ? JSON.parse(o.body) : undefined, base });
    return { ok: r.ok, status: r.status, json: async () => r.body ?? {} };
  };
}
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
  return { version: "", identifier: "run.glick.moorai", platform: "web", arch: "", authority: "—", signed: false };
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
    const base = serverBase();
    const h = await fetch(`${base}/api/health`, { signal: AbortSignal.timeout(8000) }).then((r) => r.json());
    const latest = h.version;
    return { current, latest, updateAvailable: !!latest && cmpVer(latest, current) > 0, url: `${base}/download/app` };
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
    ...CRED,
    method: "POST",
    headers,
    body: JSON.stringify({ model, max_tokens: 1024, messages: [{ role: "user", content: prompt }] })
  });
  if (!r.ok) throw new Error(`Anthropic API ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const d = await r.json();
  return (d.content || []).map((b) => b.text || "").join("") || "(empty response)";
}
export function currentTenant() { return identity.tenant; }

// What the user pasted: a bare installation token (enrolls against serverBase()), or the console's
// enrolment link https://<console>/d/<token>, which names a self-hosted console as well.
export function parseEnrollInput(input, serverUrl) {
  const s = String(input || "").trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    let u;
    try { u = new URL(s); } catch { throw new Error("that link is not a URL"); }
    const m = u.pathname.match(/^\/d\/([^/]+)\/?$/);
    if (!m) throw new Error("paste an installation token, or a link of the form https://<console>/d/<token>");
    const base = safeConsoleOrigin(u.href);
    if (!base) throw new Error("the console must be an https URL");
    return { token: decodeURIComponent(m[1]), base };
  }
  const base = safeConsoleOrigin(String(serverUrl || serverBase()).replace(/\/+$/, ""));
  if (!base) throw new Error("the console must be an https URL");
  return { token: s, base };
}

// Enroll the device by pasting an installation token: fetch its provision and persist it.
export async function enroll(token, serverUrl) {
  const parsed = parseEnrollInput(token, serverUrl);
  token = parsed.token;
  const base = parsed.base;
  const r = await consoleCall({ method: "GET", path: `/d/${encodeURIComponent(token)}`, base });
  if (!r.ok || !r.body) throw new Error("invalid or unknown token");
  const prov = { ...r.body, serverUrl: r.body.serverUrl || base };
  const invoke = window.__TAURI__?.core?.invoke;
  // Persist the install token alongside the provision — the client uses it to authenticate
  // policy fetches and event reports to the server.
  if (invoke) await invoke("save_provision", { config: { ...prov, installToken: token } });
  // Always persist so serverBase() resolves to the enrolled server on next boot (Tauri or browser).
  localStorage.setItem("raiseme.tenant", prov.tenant);
  if (prov.serverUrl) localStorage.setItem("raiseme.server", prov.serverUrl);
  localStorage.setItem("raiseme.installToken", token);
  identity.tenant = prov.tenant;
  identity.installToken = token;
  return prov;
}

// In-app signup: create the management account and get back the claim token used to wait for the
// verification click. The protocol lives in ./signup.js; this only binds the console transport + serverBase().
export function signUp(name, email) {
  const base = serverBase();
  return startSignup({ base, name, email, fetchImpl: consoleFetchImpl(base) });
}

// Wait for the verification click, then provision through the SAME enroll() the paste-a-token path
// uses — so there is exactly one place that persists a provision.
export async function awaitClaim(claimToken, onPending) {
  const base = serverBase();
  const ready = await pollClaim({
    base,
    claimToken,
    fetchImpl: consoleFetchImpl(base),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    onPending
  });
  return await enroll(ready.installToken, ready.serverUrl);
}

// Lightweight, scan-independent beacon: lands identity + agent version on the server immediately at
// boot, without waiting for the slower device/browser scans (which can be slow or hang).
export function reportIdentity() {
  const base = credBase();
  if (!enrolled() || !base) return;
  consoleCall({ method: "POST", path: "/api/device-report", body: reported(), credentialed: true }).catch(() => {});
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
    const base = credBase();
    if (enrolled() && base) consoleCall({ method: "POST", path: "/api/device-report", body: { ...reported(), ...full }, credentialed: true }).catch(() => {});
    return full;
  } catch { return null; }
}

// Coverage integrity: when each agent host was last used (session-log mtimes, hour-rounded), posted to
// /api/agent-posture on its own and independent of every hook, so the console can compare agent use
// with the MoorAI hooks' daily heartbeats. Host ids and timestamps only.
export async function reportActivity() {
  const invoke = window.__TAURI__?.core?.invoke;
  const base = credBase();
  if (!invoke || !enrolled() || !base) return;
  try {
    const r = await invoke("device_agent_activity");
    const activity = (r.activity || []).map((a) => ({ host: a.host, lastActive: new Date(a.lastActiveEpoch * 1000).toISOString() }));
    if (!activity.length) return;
    const { user, device, platform } = reported();
    consoleCall({ method: "POST", path: "/api/agent-posture", body: { user, device, platform, activity }, credentialed: true }).catch(() => {});
  } catch { /* evidence, never enforcement */ }
}

// Slower OS-patch posture check, sent as a follow-up device report (keeps tools+os from `dev`).
export async function reportPatches(dev) {
  const invoke = window.__TAURI__?.core?.invoke;
  if (!invoke) return null;
  try {
    const patches = await invoke("os_patch_status");
    const base = credBase();
    if (enrolled() && base) consoleCall({ method: "POST", path: "/api/device-report", body: { ...reported(), ...(dev || {}), patches }, credentialed: true }).catch(() => {});
    return patches;
  } catch { return null; }
}

export async function getPolicy() {
  // Unenrolled, nothing credentialed rides this request, so the default base serves the default policy.
  const credentialed = !!installTok();
  const base = credentialed ? credBase() : serverBase();
  if (!base) return null;
  try {
    const q = `tenant=${encodeURIComponent(identity.tenant)}&user=${encodeURIComponent(identity.user)}&device=${encodeURIComponent(identity.device)}`;
    const r = await consoleCall({ method: "GET", path: `/api/policy?${q}`, credentialed, base });
    return r.ok ? r.body : null;
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
  const base = credBase();
  if (!alert || !enrolled() || !base) return;
  consoleCall({ method: "POST", path: "/api/alerts", body: { ...alert, ...reported() }, credentialed: true }).catch(() => {});
}

// Counts a prompt the user pushed to the agent. Metadata only — no prompt content.
// outcome: "sent" (reached the agent) | "blocked" (stopped by policy).
export function reportPrompt(outcome, findings = 0) {
  const base = credBase();
  if (!enrolled() || !base) return;
  consoleCall({ method: "POST", path: "/api/prompt-event", body: { outcome, findings, ts: new Date().toISOString(), ...reported() }, credentialed: true }).catch(() => {});
}
