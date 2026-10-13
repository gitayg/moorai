// Clipboard guard, webview half (the host half is src-tauri/src/clip_guard*.rs).
//
// 1. The scanner. When an AI app the organisation has not approved is in front and the clipboard holds
//    text, the host sends that text here ("clipguard-scan") and this runs the app's own secret and PII
//    detectors over it, the same DetectionEngine and data/detectors.js the prompt box and OCR use. The
//    answer is detector ids, threat ids and risk levels only. The text is not logged, stored or posted.
// 2. The status line: whether the guard is on and its mode, never any content.
// 3. The in-app banner that repeats the OS notification in coach and clear mode.
const DATA_DETECTOR = (id) => (id.startsWith("secret-") || id.startsWith("dlp-")) && id !== "secret-file-upload";

// → [{ detectorId, threatId, riskLevel }] for every secret/PII detector that matches.
export function clipScan(engine, text) {
  const out = [];
  for (const d of engine.detectors) {
    if (!DATA_DETECTOR(d.detectorId) || !engine._inStage(d, ["prompt"])) continue;
    if (!engine._matchDetector(text, d)) continue;
    const t = engine.threat(d.threatId);
    out.push({ detectorId: d.detectorId, threatId: d.threatId, riskLevel: t ? t.riskLevel : "High" });
  }
  return out;
}

export function statusText(st) {
  if (!st) return "";
  if (!st.supported) return st.policyMode && st.policyMode !== "off" ? `Clipboard guard: not supported on ${st.platform}` : "";
  if (st.mode === "off") return "Clipboard guard: off";
  return `Clipboard guard: ${st.mode}`;
}

export function wireClipGuard(getEngine, $) {
  const T = window.__TAURI__;
  if (!T?.event?.listen || !T?.core?.invoke) return;
  T.event.listen("clipguard-scan", (e) => {
    const { id, text } = e.payload || {};
    let findings = null;
    try { const engine = getEngine(); if (engine && typeof text === "string") findings = clipScan(engine, text); } catch { findings = null; }
    T.core.invoke("clipguard_result", { id, findings }).catch(() => {});
  });
  const render = (st) => {
    const el = $("sb-clip");
    if (!el) return;
    const t = statusText(st);
    el.hidden = !t;
    el.textContent = t;
    el.className = "sb-item" + (st && st.supported && st.mode !== "off" ? " ok" : "");
    el.title = st ? `Clipboard guard — policy: ${st.policy}${st.pasteboardAccess ? `; pasteboard access: ${st.pasteboardAccess}` : ""}` : "";
  };
  T.event.listen("clipguard-status", (e) => render(e.payload));
  T.core.invoke("clipguard_status").then(render).catch(() => {});
  T.event.listen("clipguard-notice", (e) => {
    const box = $("clip-notice");
    if (!box || !e.payload) return;
    box.querySelector(".cn-title").textContent = e.payload.title || "";
    box.querySelector(".cn-body").textContent = e.payload.body || "";
    box.hidden = false;
  });
  const close = $("clip-notice-close");
  if (close) close.addEventListener("click", () => { $("clip-notice").hidden = true; });
}
