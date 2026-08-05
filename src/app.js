import { DETECTORS } from "../data/detectors.js";
import { compilePacks } from "../data/detector-packs.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { TIER_OF } from "../data/data-tiers.js";
import { APPROVAL_THREATS } from "../data/human-approval.js";
import { DetectionEngine } from "./engine.js";
import { Audit } from "./audit.js";
import { getPolicy, postAlert, nativeLog, loadIdentity, enroll, serverBase, currentTenant, setAgentAuth, getAuthMethod, setAuthMethod, openUrl, reportDevice, reportPatches, reportPrompt, appVersion, checkUpdate, restartApp, checkAndInstallUpdate, reportIdentity, aboutInfo, ocrImage } from "./api.js";
import { BUILD } from "./buildinfo.js";

// Which agent CLI the user is driving. Constrained to the admin's per-policy allow-list.
const TOOL_LABELS = { claude: "Claude", codex: "Codex", copilot: "Copilot CLI" };
let TOOL = localStorage.getItem("raiseme.tool") || "claude";
const audit = new Audit();
let engine;
let policy = null;
let pendingUpdate = null;

function report(entry) {
  if (!entry) return;
  nativeLog(entry);
  if (entry.alert) postAlert(entry.alert);
}

const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// #9 — inline Lucide-style SVG icons (currentColor) instead of emoji, which render inconsistently
// across macOS versions. Sized to sit inline with 13px text.
const svg = (body) => `<svg class="ic" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`;
const ICON = {
  check: svg('<polyline points="20 6 9 17 4 12"/>'),
  warn: svg('<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>'),
  info: svg('<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>')
};

async function boot() {
  const threatData = await fetch("./data/threats.json").then((r) => r.json());
  engine = new DetectionEngine(threatData, DETECTORS, CONTENT_RULES);

  const msg = $("msg");
  $("send").addEventListener("click", sendMessage);
  msg.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } });
  $("file").addEventListener("change", (e) => { for (const f of e.target.files) handleFile(f, "upload"); e.target.value = ""; });
  $("clear-log").addEventListener("click", (e) => { e.stopPropagation(); audit.clear(); renderLog(); });
  wireDropAndPaste();
  wireDetectionDrawer();
  wireIdleTimeout();
  wireAbout();

  await loadIdentity();
  refreshEnrollChip();
  reportIdentity(); // fast version/identity beacon, independent of the slow device scans below
  appVersion().then((v) => { $("bb-version").textContent = v ? "v" + v : "—"; });

  // Connect to the server first so the status reflects reachability fast — before the slower
  // local device scans (apps, browsers, OS patches) run.
  $("sb-server").className = "sb-item";
  $("sb-server").innerHTML = '<span class="dot"></span> connecting…';
  startPolling();

  // Auto-update. Native: silently download + install a newer signed build in the background, then
  // apply on restart (the idle timer restarts automatically). Browser: just offer the download.
  if (window.__TAURI__) {
    checkAndInstallUpdate().then((installed) => { if (installed) { pendingUpdate = { installed: true }; showUpdate({ installed: true }); } });
  } else {
    checkUpdate().then((u) => { if (u && u.updateAvailable) { pendingUpdate = u; showUpdate(u); } });
  }

  // Device reporting runs in the background; its scans take a few seconds.
  reportDevice().then((dev) => {
    renderDeviceInfo(dev);
    reportPatches(dev).then((p) => { if (p) renderDeviceInfo({ ...dev, patches: p }); });
  });

  wireEnrollment();
  initTerminal();
  renderLog();
}

function renderDeviceInfo(dev) {
  const el = $("device-info");
  if (!el) return;
  if (!dev) { el.innerHTML = `<span class="enroll-label">This device</span><div class="di-sub">AI-tool scan runs in the native app.</div>`; return; }
  const tools = dev.tools || [];
  const p = dev.patches;
  const patchLine = !p ? '<span class="di-none">checking for OS updates…</span>'
    : p.upToDate ? `<span class="di-ok">${ICON.check} OS up to date</span>`
    : `<span class="di-warn">${ICON.warn} ${p.count} OS update${p.count === 1 ? "" : "s"} pending</span>${p.titles && p.titles.length ? ` — ${esc(p.titles.join("; "))}` : ""}`;
  el.innerHTML = `<span class="enroll-label">This device — ${esc(dev.os)} ${esc(dev.osVersion || "")}</span>
    <div class="di-sub">OS patches: ${patchLine}</div>
    <div class="di-sub">Other AI tools detected on this device (reported to MoorAI):</div>
    <div class="di-tools">${tools.length
      ? tools.map((t) => `<span class="tool-chip">${esc(t)}</span>`).join("")
      : '<span class="di-none">none detected</span>'}</div>
    ${renderBrowsers(dev.browsers)}`;
}

function renderBrowsers(browsers) {
  if (!browsers || !browsers.length) return "";
  const rows = browsers.map((b) => {
    const ex = b.extensions || [];
    const chips = ex.length
      ? ex.map((e) => `<span class="tool-chip${e.broad ? " broad" : ""}">${e.broad ? ICON.warn + " " : ""}${esc(e.name)}</span>`).join("")
      : '<span class="di-none">no extensions</span>';
    return `<div style="margin-top:6px"><b>${esc(b.browser)}</b> <span class="di-none">(${ex.length})</span><div class="di-tools" style="margin-top:4px">${chips}</div></div>`;
  }).join("");
  return `<div class="di-sub" style="margin-top:12px">Browsers &amp; extensions:</div>${rows}`;
}

function updateStatusbar(reachable) {
  const ok = reachable !== undefined ? reachable : !!policy;
  const srv = $("sb-server");
  srv.className = "sb-item " + (ok ? "ok" : "off");
  srv.innerHTML = `<span class="dot"></span> ${ok ? "server connected" : "server offline"}`;
  $("sb-posture").textContent = policy ? (policy.posture || "warn + override") : "bundled policy";
  $("bb-policy").textContent = policy ? (policy.policyName || "Default") : "—";
  // #5 — consent-visible capture indicator. Persistent and un-dismissable while the tier is elevated,
  // so there is no silent surveillance on the device (content-free stays the default; nothing shows then).
  { const t = policy && policy.captureTier, c = $("sb-capture");
    if (c) {
      if (t && t !== "content-free") {
        c.hidden = false;
        c.textContent = t === "full-capture" ? "● capture: FULL — prompt text is recorded" : "● capture: metadata+";
        c.style.color = t === "full-capture" ? "#ff4f5e" : "#f5a623";
        c.style.fontWeight = "600";
      } else { c.hidden = true; }
    }
  }
}

// Re-fetch policy and reflect real reachability. Keeps the last good policy on a transient miss
// (so enforcement stays intact) while the status dot tracks the latest fetch.
async function refreshPolicy() {
  const p = await getPolicy();
  if (p) policy = p;
  updateStatusbar(!!p);
  renderToolPicker();
  // #22 — merge the admin's custom detector packs (distributed via policy) on top of the built-ins.
  if (engine) engine.applyPacks(compilePacks(policy?.detectorPacks));
  // Cache the allow-list to config so the host can enforce (offline fallback) even if a later
  // policy fetch fails. The server remains authoritative when reachable.
  if (window.__TAURI__ && policy && Array.isArray(policy.allowedTools)) {
    window.__TAURI__.core?.invoke("save_provision", { config: { allowedTools: policy.allowedTools, isolateAgent: !!policy.isolateAgent } }).catch(() => {});
  }
}

// Populate the agent picker from the admin's per-policy allow-list. Native only — the browser
// fallback terminal is Claude-only. Hidden when only one agent is allowed.
function renderToolPicker() {
  const bar = $("term-bar"), sel = $("tool-picker");
  if (!bar || !sel) return;
  if (!window.__TAURI__) { bar.style.display = "none"; return; }
  const allowed = (policy && Array.isArray(policy.allowedTools) && policy.allowedTools.length)
    ? policy.allowedTools : ["claude", "codex", "copilot"];
  let forced = false;
  if (!allowed.includes(TOOL)) { TOOL = allowed[0]; localStorage.setItem("raiseme.tool", TOOL); forced = true; }
  bar.style.display = allowed.length > 1 ? "" : "none";
  sel.innerHTML = allowed.map((t) => `<option value="${t}"${t === TOOL ? " selected" : ""}>${TOOL_LABELS[t] || t}</option>`).join("");
  if (!sel.dataset.wired) { sel.dataset.wired = "1"; sel.addEventListener("change", () => switchTool(sel.value)); }
  // Admin revoked the agent the user was on → move them to an allowed one and relaunch.
  if (forced && nativeTerm) reconnectTerminal();
}

function switchTool(t) {
  if (t === TOOL) return;
  TOOL = t;
  localStorage.setItem("raiseme.tool", TOOL);
  if (term) { term.reset(); term.write(`\x1b[2m[MoorAI] switching to ${TOOL_LABELS[TOOL] || TOOL}…\x1b[0m\r\n`); }
  reconnectTerminal();
}

// Self-rescheduling poll. Interval comes from the server (policy.pollSeconds), so admins can
// tune fleet request volume centrally; clamped to a 15s floor.
let pollTimer;
function startPolling() {
  clearTimeout(pollTimer);
  const tick = async () => {
    await refreshPolicy();
    const secs = Math.max(15, Number(policy?.pollSeconds) || 60);
    pollTimer = setTimeout(tick, secs * 1000);
  };
  tick();
}

function closeAbout() { $("about-dialog").hidden = true; $("about-backdrop").hidden = true; }
async function openAbout() {
  const a = await aboutInfo();
  const released = BUILD?.date ? new Date(BUILD.date).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—";
  const sig = a.signed
    ? `<span class="sig-ok">Signed &amp; notarized</span>`
    : `<span class="sig-warn">Ad-hoc (unsigned)</span>`;
  const rows = [
    ["Version", "v" + esc(a.version || BUILD?.version || "")],
    ["Released", esc(released)],
    ["Signature", sig],
    ["Identifier", esc(a.identifier || "")],
    ["Platform", esc((a.platform || "") + (a.arch ? " · " + a.arch : ""))],
    ["Server", esc(serverBase())],
    ["Tenant", esc(currentTenant() || "—")]
  ];
  $("about-rows").innerHTML = rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("");
  $("about-dialog").hidden = false; $("about-backdrop").hidden = false;
}
function wireAbout() {
  const btn = $("about-btn"); if (!btn) return;
  btn.addEventListener("click", openAbout);
  $("about-close")?.addEventListener("click", closeAbout);
  $("about-backdrop")?.addEventListener("click", closeAbout);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && $("about-dialog") && !$("about-dialog").hidden) closeAbout(); });
}

function showUpdate(u) {
  const bar = $("update-bar");
  if (!bar) return;
  if (u.installed) {
    // Native: the new build is already downloaded, verified and installed — just relaunch.
    bar.innerHTML = `<span>An update was installed in the background.</span>`
      + `<span class="up-actions"><button id="upd-btn">Restart now</button><button id="upd-x">Later</button></span>`;
    bar.hidden = false;
    $("upd-btn").addEventListener("click", () => restartApp());
    $("upd-x").addEventListener("click", () => { bar.hidden = true; });
    return;
  }
  bar.innerHTML = `<span>A newer version <b>v${esc(u.latest)}</b> is available — you have v${esc(u.current)}.</span>`
    + `<span class="up-actions"><button id="upd-btn">Download update</button><button id="upd-x">Later</button></span>`;
  bar.hidden = false;
  $("upd-btn").addEventListener("click", () => openUrl(u.url));
  $("upd-x").addEventListener("click", () => { bar.hidden = true; });
}

// 30-minute inactivity timeout. If a newer build is available, an idle host relaunches to apply it
// (the claude session resumes via --continue); otherwise it locks until the user resumes.
function wireIdleTimeout() {
  let last = Date.now();
  ["mousemove", "keydown", "click", "scroll", "touchstart"].forEach((e) => document.addEventListener(e, () => { last = Date.now(); }, { passive: true }));
  setInterval(() => {
    if (Date.now() - last <= 30 * 60 * 1000 || document.getElementById("idle-lock")) return;
    if (pendingUpdate) { restartApp(); return; }
    const d = document.createElement("div");
    d.id = "idle-lock";
    d.className = "idle-lock";
    d.innerHTML = `<div class="il-title">Session timed out</div><div class="il-sub">Locked after 30 minutes of inactivity.</div><button id="il-resume" class="il-btn">Resume</button>`;
    document.body.appendChild(d);
    document.getElementById("il-resume").addEventListener("click", () => location.reload());
  }, 15000);
}

function wireDetectionDrawer() {
  const open = () => { $("det-drawer").hidden = false; $("det-backdrop").hidden = false; };
  const close = () => { $("det-drawer").hidden = true; $("det-backdrop").hidden = true; };
  $("det-btn").addEventListener("click", open);
  $("det-close").addEventListener("click", close);
  $("det-backdrop").addEventListener("click", close);
}

// ----- live claude terminal -----
// In the app, claude runs DIRECTLY on the device (native PTY via Tauri, no server).
// In the browser preview, it falls back to the server's ws PTY so the UI stays testable.
const TAURI = window.__TAURI__;
let term, fit, sock, nativeTerm = false, lastCols = 0, lastRows = 0;

function initTerminal() {
  term = new window.Terminal({
    convertEol: false, cursorBlink: true, scrollback: 10000,
    fontFamily: "ui-monospace, Menlo, monospace", fontSize: 12,
    theme: { background: "#0e1116", foreground: "#e6edf3", cursor: "#4c8dff" }
  });
  fit = new window.FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open($("term"));
  term.onData(handleTermInput);
  renderToolPicker();

  // Only open the PTY once the monospace font is loaded AND the layout has settled, so the first
  // fit measures the cell width correctly. A wrong initial width makes claude's PTY render one
  // column off, so its TUI repaints smear over the scrollback (the ghosting bug).
  const startPty = () => {
    try { fit.fit(); } catch {}
    if (TAURI?.core?.invoke && TAURI?.event?.listen) {
      nativeTerm = true;
      TAURI.event.listen("term-data", (e) => { term.write(e.payload); reviewOutput(e.payload); });
      TAURI.event.listen("term-exit", () => term.write(`\r\n\x1b[2m[MoorAI] ${TOOL_LABELS[TOOL] || TOOL} exited.\x1b[0m\r\n`));
      TAURI.core.invoke("term_open", { cols: term.cols, rows: term.rows, tool: TOOL }).catch((e) => term.write(`\r\n[MoorAI] ${e}\r\n`));
    } else {
      connectTerminal();
    }
    setTimeout(() => term.focus(), 50);
  };
  const ready = (document.fonts && document.fonts.ready) ? document.fonts.ready : Promise.resolve();
  ready.then(() => requestAnimationFrame(() => requestAnimationFrame(startPty)));

  // Debounced refit: rapid layout changes must not resize the PTY mid-repaint (also a ghosting source).
  let refit;
  new ResizeObserver(() => { clearTimeout(refit); refit = setTimeout(() => { try { fit.fit(); pushSize(); } catch {} }, 120); }).observe($("term"));
}

// Control & navigation keys (arrows, Tab, Enter, Ctrl-C, Esc, the ← agents/fan-out key) pass
// straight to the CLI — they carry no data. Printable text is redirected to the guarded composer
// so prompt content can't bypass the review.
function isControlInput(d) {
  if (!d) return false;
  // Single keystroke: control chars, backspace, plus "/" and "?" (claude's slash/shortcut menus).
  if (d.length === 1) {
    const c = d.charCodeAt(0);
    return c === 0x1b || c < 0x20 || c === 0x7f || d === "/" || d === "?";
  }
  // Multi-byte input passes straight to the terminal ONLY if it is composed *entirely* of terminal
  // control sequences — arrow/fn keys (CSI/SS3), mouse-tracking bursts (\x1b[<…M/m), and control
  // chars — with no printable text payload. That lets mouse/scroll and key sequences through while
  // still preventing a control-char prefix from smuggling a real prompt to the agent unreviewed.
  // CR/LF/Tab or bracketed-paste markers mean real input → send to the composer for review.
  if (/[\r\n\t]/.test(d) || /\x1b\[20[01]~/.test(d)) return false;
  return /^(?:\x1b\[[0-9;:<>?]*[ -/]*[@-~]|\x1bO[@-~]|[\x00-\x1f\x7f])+$/.test(d);
}

let nudgeTimer;
function handleTermInput(d) {
  if (isControlInput(d)) { sendRaw(d); return; }
  const m = $("msg");
  m.value += d;
  m.focus();
  m.classList.add("nudge");
  clearTimeout(nudgeTimer);
  nudgeTimer = setTimeout(() => m.classList.remove("nudge"), 500);
}

function sendRaw(d) {
  if (nativeTerm) { TAURI.core.invoke("term_input", { data: d }).catch(() => {}); return; }
  if (sock && sock.readyState === 1) sock.send(d);
}

function connectTerminal() {
  const u = new URL(serverBase());
  const proto = u.protocol === "https:" ? "wss" : "ws";
  const token = localStorage.getItem("raiseme.agentToken") || "";
  sock = new WebSocket(`${proto}://${u.host}/ws?token=${encodeURIComponent(token)}`);
  sock.binaryType = "arraybuffer";
  sock.onmessage = (e) => { const d = typeof e.data === "string" ? e.data : new Uint8Array(e.data); term.write(d); if (typeof e.data === "string") reviewOutput(e.data); };
  sock.onopen = () => { lastCols = 0; lastRows = 0; pushSize(); };
  sock.onclose = () => term.write("\r\n\x1b[2m[MoorAI] terminal disconnected.\x1b[0m\r\n");
}

function reconnectTerminal() {
  if (nativeTerm) { term.reset(); TAURI.core.invoke("term_open", { cols: term.cols, rows: term.rows, tool: TOOL }).catch(() => {}); return; }
  try { sock && sock.close(); } catch {}
  if (term) { term.reset(); connectTerminal(); }
}

function pushSize() {
  if (nativeTerm) { TAURI.core.invoke("term_resize", { cols: term.cols, rows: term.rows }).catch(() => {}); return; }
  if (sock && sock.readyState === 1 && (term.cols !== lastCols || term.rows !== lastRows)) {
    lastCols = term.cols; lastRows = term.rows;
    sock.send(`\x00resize:${term.cols}:${term.rows}`);
  }
}

function toAgent(text) { sendRaw(text + "\r"); }

// ----- policy review -----
// Actions: "disabled" (off) · "alert" (report to dashboard, silent for the user) ·
//          "notify" (report + show the user a warning they can override) ·
//          "justify" (report + gate the prompt, logged distinctly so the user must consciously
//                     proceed with a business justification) · "block" (report + hard block).
// Per-threat action wins; else the data-tier default (policy.tierPolicy) for the threat's tier;
// else "notify". Lets an admin govern by data class without losing any per-threat override.
function threatAction(id) {
  const explicit = policy?.threatPolicy?.[id];
  if (explicit) return explicit;
  const tier = TIER_OF[id];
  const tierAct = tier && policy?.tierPolicy?.[tier];
  if (tierAct) return tierAct;
  if (APPROVAL_THREATS.has(id)) return "justify"; // high-impact actions require human approval
  return "notify";
}
let lastFound = 0; // detections (incl. silent) from the most recent review — for prompt stats.

function reviewContent(text, reviewStage, mount) {
  const cp = policy?.contentPolicy || {};
  const enabled = Object.keys(cp).filter((id) => cp[id] && cp[id] !== "disabled");
  if (!enabled.length) return false;
  let blocked = false;
  for (const c of engine.scanContent(text, enabled)) {
    const act = cp[c.ruleId] || "disabled";
    if (act === "disabled") continue;
    lastFound++;
    const gate = act === "block" || act === "justify"; // both hold the prompt; justify is recoverable
    const pseudo = { mode: gate ? "block" : "warn", threat: { id: 0, category: `Content: ${c.label}`, riskLevel: gate ? "Blocked" : "High" } };
    // Visibility for every active action; local log + user-facing card only for notify/justify/block.
    report(audit.record({ action: act === "block" ? "blocked" : act, stage: reviewStage, tool: TOOL, finding: pseudo, content: c.match }, act !== "alert"));
    if (act !== "alert") mount.appendChild(contentCard(c, reviewStage, gate));
    blocked = blocked || gate;
  }
  return blocked;
}

function renderFindings(text, stage, mount) {
  let blocked = false;
  for (const f of engine.scan(text, stage)) {
    const act = threatAction(f.threat.id);
    if (act === "disabled") continue;
    lastFound++;
    const gate = act === "block" || act === "justify"; // both hold the prompt; justify is recoverable
    report(audit.record({ action: act === "block" ? "blocked" : act, stage, tool: TOOL, finding: f, content: f.match }, act !== "alert"));
    if (act !== "alert") mount.appendChild(card(f, gate));
    blocked = blocked || gate;
  }
  return blocked;
}

// AI output review (#4) — non-destructive. The reply streams through a full-screen TUI, so masking
// it inline would corrupt the display; instead we watch a line-buffered, ANSI-stripped copy and raise
// findings (a secret the model echoed back, licensed code, a risky command) into the same dashboard
// pipeline as prompts — never altering what the terminal shows. Best-effort on a repainting TUI; the
// clean redaction path is the `claude -p` guard. Opt out with policy.outputReview === false.
const OUT_ANSI = /[\u001b\u009b][[\]()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g;
let outBuf = "";
function reviewOutput(chunk) {
  if (policy?.outputReview === false || typeof chunk !== "string") return;
  outBuf += chunk;
  const nl = outBuf.lastIndexOf("\n");
  if (nl < 0) { if (outBuf.length > 8192) outBuf = outBuf.slice(-4096); return; }
  const text = outBuf.slice(0, nl).replace(OUT_ANSI, "");
  outBuf = outBuf.slice(nl + 1);
  if (!text.trim()) return;
  let found = false;
  for (const f of engine.scan(text, "output")) {
    if (threatAction(f.threat.id) === "disabled") continue;
    // Output is already on screen — record as a silent detection, never gate.
    report(audit.record({ action: "alert", stage: "output", tool: TOOL, finding: f, content: f.match }, false));
    found = true;
  }
  if (found) renderLog();
}

// Blocking findings in `text` (content rules + threats) as {match,label} — pure, no UI/audit.
// Used to decide whether a blocked prompt can be salvaged by redaction.
function blocksIn(text) {
  const out = [];
  const cp = policy?.contentPolicy || {};
  const enabled = Object.keys(cp).filter((id) => cp[id] && cp[id] !== "disabled");
  for (const c of engine.scanContent(text, enabled)) { const a = cp[c.ruleId] || "disabled"; if (a === "block" || a === "justify") out.push({ match: c.match, label: c.label }); }
  for (const f of engine.scan(text, "prompt")) { const a = threatAction(f.threat.id); if (a === "block" || a === "justify") out.push({ match: f.match, label: f.threat.category }); }
  return out;
}

// Replace each flagged span with a placeholder (literal match, all occurrences). Longest matches
// first, so a shorter match nested inside a longer one (e.g. digits inside a full key) doesn't
// corrupt the longer span before it can be stripped.
function redactText(text, blocks) {
  let out = text;
  for (const b of [...blocks].filter((b) => b.match).sort((a, z) => z.match.length - a.match.length)) {
    out = out.split(b.match).join("[REDACTED]");
  }
  return out;
}

// ----- composer: guarded send into the terminal -----
function banner(mount, text, cls) {
  const b = document.createElement("div");
  b.className = cls === "block" ? "blocked-banner" : "clean";
  b.textContent = text;
  mount.appendChild(b);
}

function sendMessage() {
  const msg = $("msg");
  const text = msg.value;
  if (!text.trim()) return;
  const review = $("review-area");
  review.innerHTML = "";

  lastFound = 0;
  const cb = reviewContent(text, "shared", review);
  const fb = renderFindings(text, "prompt", review);
  renderLog();

  if (cb || fb) {
    reportPrompt("blocked", lastFound);
    banner(review, "✗ Blocked by policy — not sent to the agent.", "block");
    // Redact & send when possible: if stripping every flagged span clears policy, offer it so the
    // user can still send the safe remainder instead of being fully stuck.
    const blocks = blocksIn(text);
    if (blocks.length && blocks.every((b) => b.match)) {
      const redacted = redactText(text, blocks);
      if (redacted !== text && blocksIn(redacted).length === 0) {
        const note = document.createElement("div");
        note.className = "dz-hint";
        note.style.marginTop = "8px";
        note.textContent = "The flagged content can be removed. “Send redacted” replaces it with [REDACTED] and passes policy:";
        const prev = document.createElement("div");
        prev.style.cssText = "font-family:var(--mono);font-size:12px;background:var(--bg);border:1px solid var(--border);border-radius:var(--r-sm);padding:8px 10px;margin-top:6px;white-space:pre-wrap;word-break:break-word;color:var(--text)";
        prev.textContent = redacted.length > 240 ? redacted.slice(0, 240) + "…" : redacted;
        const bar = document.createElement("div");
        bar.className = "actions";
        bar.append(
          button("Send redacted", "danger", () => { report(audit.record({ action: "redacted", stage: "shared", tool: TOOL })); deliver(redacted); }),
          button("Cancel", "ghost", () => { review.innerHTML = ""; })
        );
        review.append(note, prev, bar);
      }
    }
    return;
  }

  if (review.children.length) {
    const bar = document.createElement("div");
    bar.className = "actions";
    bar.append(
      button("Send anyway", "danger", () => { report(audit.record({ action: "override", stage: "shared", tool: TOOL })); deliver(text); }),
      button("Cancel", "ghost", () => { review.innerHTML = ""; })
    );
    review.appendChild(bar);
    return;
  }
  deliver(text);
}

function deliver(text) {
  reportPrompt("sent", lastFound);
  toAgent(text);
  $("msg").value = "";
  $("review-area").innerHTML = "";
  term.focus();
}

// ----- files (drag-drop / paste / picker) — scanned, logged -----
const TEXTUAL = /\.(txt|md|csv|tsv|json|js|ts|jsx|tsx|py|rb|go|java|c|cpp|h|html|xml|yml|yaml|log|sql|sh|conf|ini|env)$/i;
const isTextual = (file) => file.type.startsWith("text/") || file.type === "application/json" || TEXTUAL.test(file.name || "");

async function handleFile(file, source) {
  const kb = Math.max(1, Math.round((file.size || 0) / 1024));
  const label = file.name || (file.type || "file");
  const review = $("review-area");
  review.innerHTML = "";

  const uf = { mode: "warn", hint: `${source}: "${label}" (${file.type || "file"}, ${kb}KB) — scanned before you reference it.`, match: label, threat: engine.threat(18) };
  report(audit.record({ action: "alert", stage: "upload", tool: TOOL, finding: uf, content: label }));
  review.appendChild(card(uf, false));

  if (isTextual(file)) {
    const text = (await file.text()).slice(0, 200000);
    const cb = reviewContent(text, "shared", review);
    const fb = renderFindings(text, "file", review);
    if (cb || fb) {
      banner(review, "✗ Blocked by policy — file not shared with the agent.", "block");
    } else {
      const act = document.createElement("div");
      act.className = "actions";
      act.append(button("Insert into prompt", "ghost", () => {
        $("msg").value += `${$("msg").value ? "\n\n" : ""}--- ${label} ---\n${text}`;
        $("msg").focus();
        review.innerHTML = "";
      }));
      review.appendChild(act);
    }
  } else if ((file.type || "").startsWith("image/")) {
    // #23 — if the tenant enabled image inspection (BYO vision key), OCR the image server-side and
    // run the extracted text through the SAME PII/secret policy as any file. The vision key stays on
    // the server; only text comes back. Falls back to the informational card when disabled/unavailable.
    const note = document.createElement("div");
    note.className = "card coach";
    note.innerHTML = `<div class="top"><span class="chip lvl coach">Image</span><span class="name">Image ${esc(source)}</span></div><div class="hint"></div>`;
    review.appendChild(note);
    const hint = note.querySelector(".hint");
    if (policy?.imageInspection?.enabled && (file.size || 0) <= 4 * 1024 * 1024) {
      hint.textContent = "Extracting text (OCR) to scan for secrets & PII…";
      try {
        const text = (await ocrImage(await fileToBase64(file), file.type)).slice(0, 200000);
        if (text.trim()) {
          hint.textContent = "OCR text scanned against policy.";
          const cb = reviewContent(text, "shared", review);
          const fb = renderFindings(text, "file", review);
          if (cb || fb) banner(review, "✗ Blocked by policy — image not shared with the agent.", "block");
          else banner(review, "✓ OCR clean — no secrets or PII found in the image.", "clean");
        } else { hint.textContent = "OCR found no readable text in the image. Upload event logged."; }
      } catch (e) { hint.textContent = `Couldn't inspect the image (${e.message}). Upload event logged.`; }
    } else {
      hint.textContent = (file.size || 0) > 4 * 1024 * 1024
        ? "Image too large to inspect (over 4MB). Upload event logged."
        : "Image content is not inspected — enable image inspection (BYO vision key) in your policy. Upload event logged.";
    }
  }
  renderLog();
}

// Read a File as base64 (no data-URL prefix) for the OCR endpoint.
function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).replace(/^data:[^;]+;base64,/, ""));
    r.onerror = () => reject(new Error("read failed"));
    r.readAsDataURL(file);
  });
}

function wireDropAndPaste() {
  const zone = $("host-panel");
  ["dragenter", "dragover"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("dragging"); }));
  ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); if (ev === "dragleave" && zone.contains(e.relatedTarget)) return; zone.classList.remove("dragging"); }));
  zone.addEventListener("drop", (e) => { for (const f of e.dataTransfer.files) handleFile(f, "drop"); });
  document.addEventListener("paste", (e) => {
    if (e.target && (e.target.id === "msg" || e.target.closest("#term"))) return;
    for (const it of e.clipboardData?.items || []) {
      if (it.kind === "file") { const f = it.getAsFile(); if (f) handleFile(f, "paste"); }
    }
  });
}

// ----- cards -----
function card(f, blocked) {
  const t = f.threat;
  const cls = blocked ? "blocked" : f.mode === "coach" ? "coach" : t.riskLevel;
  const chip = blocked ? "BLOCKED" : f.mode === "coach" ? "Coach" : t.riskLevel;
  const el = document.createElement("div");
  el.className = `card ${cls}`;
  const links = engine.sourceLinks(t)
    .filter((s) => s.url)
    .map((s) => `<a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.key)}</a>`)
    .join("");
  el.innerHTML = `
    <div class="top">
      <span class="chip lvl ${esc(cls)}">${esc(chip)}</span>
      <span class="name">${esc(t.threat)}</span>
      <span class="chip">${esc(t.category)}</span>
    </div>
    <div class="hint">${esc(f.hint)}</div>
    <div class="match">matched: ${esc(f.match)}</div>
    <div class="guidance">${blocked ? "Blocked by policy — cannot be sent. " : ""}${esc(t.response)}</div>
    <div>${links}</div>`;
  return el;
}

function contentCard(c, stage, block) {
  const cls = block ? "blocked" : c.severity === "high" ? "High" : "Medium";
  const el = document.createElement("div");
  el.className = `card ${cls}`;
  el.innerHTML = `
    <div class="top">
      <span class="chip lvl ${cls}">${block ? "BLOCKED" : "Content"}</span>
      <span class="name">${esc(c.label)}</span>
      <span class="chip">Parental control · ${esc(stage)}</span>
    </div>
    <div class="match">matched: ${esc(c.match)}</div>
    <div class="guidance">${block
      ? "Blocked by your organization's content policy — this cannot be sent."
      : "Flagged by content policy — review before continuing."}</div>`;
  return el;
}

function button(label, cls, onClick) {
  const b = document.createElement("button");
  b.className = cls;
  b.textContent = label;
  b.addEventListener("click", onClick);
  return b;
}

// ----- enrollment + agent auth -----
function wireEnrollment() {
  $("enroll-cmd").textContent = `curl -s "${serverBase()}/d/<TOKEN>" -o ~/.curaiq/config.json`;
  refreshEnrollChip();

  $("enroll-toggle").addEventListener("click", () => {
    const e = $("enroll");
    e.style.display = e.style.display === "none" ? "block" : "none";
  });
  $("enroll-copy").addEventListener("click", () => {
    navigator.clipboard?.writeText($("enroll-cmd").textContent);
    $("enroll-copy").textContent = "Copied";
    setTimeout(() => ($("enroll-copy").textContent = "Copy"), 1500);
  });
  $("enroll-btn").addEventListener("click", async () => {
    const token = $("enroll-token").value.trim();
    const status = $("enroll-status");
    if (!token) { status.className = "enroll-status err"; status.textContent = "paste a token"; return; }
    status.className = "enroll-status"; status.textContent = "enrolling…";
    try {
      const prov = await enroll(token);
      status.className = "enroll-status ok"; status.textContent = `enrolled → ${prov.tenant}`;
      $("enroll-token").value = "";
      refreshEnrollChip();
      // Re-report immediately so the device moves to the enrolled tenant without an app restart.
      await loadIdentity();
      const dev = await reportDevice();
      reportPatches(dev);
    } catch (e) {
      status.className = "enroll-status err"; status.textContent = String(e.message || e);
    }
  });

  $("open-console").addEventListener("click", () => openUrl("https://console.anthropic.com/settings/keys"));
  $("oauth-copy").addEventListener("click", () => {
    navigator.clipboard?.writeText("claude setup-token");
    $("oauth-copy").textContent = "Copied";
    setTimeout(() => ($("oauth-copy").textContent = "Copy"), 1500);
  });

  const applyAuthMethod = (method) => {
    $("help-oauth").hidden = method !== "oauth";
    $("help-apikey").hidden = method !== "apikey";
    $("agent-token").placeholder = method === "oauth" ? "sk-ant-oat01-…" : "sk-ant-…";
  };
  $("auth-method").value = getAuthMethod();
  applyAuthMethod(getAuthMethod());
  $("auth-method").addEventListener("change", (e) => { setAuthMethod(e.target.value); applyAuthMethod(e.target.value); });

  $("agent-key-btn").addEventListener("click", async () => {
    const token = $("agent-token").value.trim();
    const method = $("auth-method").value;
    const status = $("agent-key-status");
    try {
      await setAgentAuth(method, token);
      status.className = "enroll-status ok"; status.textContent = token ? "saved — reconnecting agent" : "cleared";
      $("agent-token").value = "";
      reconnectTerminal();
    } catch (e) {
      status.className = "enroll-status err"; status.textContent = String(e.message || e);
    }
  });
}

function refreshEnrollChip() {
  const t = currentTenant();
  const provisioned = t && t !== "unprovisioned";
  // The chip is now a gears (settings) icon; it glows amber until the device is enrolled.
  $("enroll-toggle").classList.toggle("warn", !provisioned);
  $("enroll").style.display = provisioned ? "none" : "block";
  $("bb-tenant").textContent = provisioned ? t : "not enrolled";
}

// ----- detection table -----
function renderLog() {
  const log = $("log");
  const items = audit.all().filter((i) => i.threatId != null || i.action === "override");
  $("det-count").textContent = items.length;
  if (!items.length) { log.innerHTML = `<tr class="empty-row"><td colspan="5">No detections yet.</td></tr>`; return; }
  log.innerHTML = items.map(logRow).join("");
}

function logRow(i) {
  const time = esc(i.ts.slice(11, 19));
  const detection = i.threatId ? esc(i.category || "") : esc(i.stage);
  return `<tr>
    <td>${time}</td>
    <td><span class="act ${esc(i.action)}">${esc(i.action)}</span></td>
    <td>${detection}</td>
    <td>${esc(i.riskLevel || "–")}</td>
    <td>${esc(i.stage || "–")}</td>
  </tr>`;
}

boot();
