// MoorAI Browser Guard — content script.
//
// Runs in each supported AI site's page (isolated world; shares globals with detectors.js + report.js,
// which are listed before it in manifest content_scripts). It:
//   1. locates the site's prompt composer (textarea / contenteditable),
//   2. intercepts the send action (Enter-without-Shift, and the send button click),
//   3. scans the typed text LOCALLY with MoorAIDetectors before it is sent,
//   4. on a finding, shows an inline, non-blocking COACH banner (proceed / cancel), and in block mode
//      PREVENTS the send on a high-severity finding,
//   5. emits a CONTENT-FREE signal via MoorAIReport (category + risk + one-way hash only).
//
// CONTENT-FREE: the prompt text is read only to run local regex + compute a one-way hash. It is never
// stored and never transmitted. Fail-open: any error here must not break the user's ability to send.

(function () {
  "use strict";

  const D = globalThis.MoorAIDetectors;
  const R = globalThis.MoorAIReport;
  if (!D) return; // detectors failed to load — fail open (do nothing)

  // ---- which AI site are we on ----
  function siteOf() {
    const h = location.host;
    if (h === "chatgpt.com" || h === "chat.openai.com") return "chatgpt";
    if (h === "claude.ai") return "claude";
    if (h === "copilot.microsoft.com") return "copilot";
    return "unknown";
  }
  const SITE = siteOf();

  // ---- per-site selectors (ordered fallbacks — DOM drifts, so each has multiple candidates) ----
  const SELECTORS = {
    chatgpt: {
      composer: ["#prompt-textarea", "div[contenteditable='true']#prompt-textarea", "textarea[data-id]", "main form textarea", "main div[contenteditable='true']"],
      send: ["button[data-testid='send-button']", "button[aria-label='Send prompt']", "button[aria-label*='Send']"]
    },
    claude: {
      composer: ["div[contenteditable='true'].ProseMirror", "div.ProseMirror[contenteditable='true']", "[data-testid='chat-input'] div[contenteditable='true']", "div[contenteditable='true']"],
      send: ["button[aria-label='Send message']", "button[aria-label='Send Message']", "button[aria-label*='Send']", "fieldset button[type='submit']"]
    },
    copilot: {
      composer: ["textarea#userInput", "textarea[data-testid='composer-input']", "textarea[placeholder]", "div[contenteditable='true']"],
      send: ["button[data-testid='submit-button']", "button[aria-label='Submit']", "button[title='Submit']", "button[aria-label*='Send']", "button[type='submit']"]
    },
    unknown: { composer: ["textarea", "div[contenteditable='true']"], send: ["button[type='submit']"] }
  };
  const SEL = SELECTORS[SITE] || SELECTORS.unknown;

  function firstMatch(list) {
    for (const s of list) { try { const el = document.querySelector(s); if (el) return el; } catch { /* bad selector */ } }
    return null;
  }
  function getComposer() { return firstMatch(SEL.composer); }
  function getSendButton() { return firstMatch(SEL.send); }

  function textOf(el) {
    if (!el) return "";
    const tag = (el.tagName || "").toLowerCase();
    if (tag === "textarea" || tag === "input") return el.value || "";
    return el.innerText || el.textContent || "";
  }
  function composerText() { return textOf(getComposer()); }

  function isInComposer(node) {
    const c = getComposer();
    if (!c || !node) return false;
    return node === c || (c.contains && c.contains(node)) || (node.closest && !!node.closest(SEL.composer.join(",")));
  }

  // ---- config ----
  let CONFIG = { mode: "coach" };
  function loadConfig() {
    try {
      chrome.storage.sync.get({ mode: "coach", serverUrl: "", installToken: "", reportEnabled: true }, (cfg) => { CONFIG = cfg || CONFIG; });
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== "sync") return;
        for (const k in changes) CONFIG[k] = changes[k].newValue;
      });
    } catch { /* storage unavailable — keep defaults (coach) */ }
  }
  loadConfig();

  // ---- inline coach / block banner ----
  let bannerEl = null;
  function removeBanner() { if (bannerEl && bannerEl.parentNode) bannerEl.parentNode.removeChild(bannerEl); bannerEl = null; }

  function showBanner({ worst, count, blocking }, onProceed, onCancel) {
    removeBanner();
    const b = document.createElement("div");
    b.className = "moorai-guard-banner" + (blocking ? " moorai-guard-block" : "");
    b.setAttribute("role", "alertdialog");
    b.setAttribute("aria-live", "assertive");

    const more = count > 1 ? ` (+${count - 1} more)` : "";
    const msg = document.createElement("div");
    msg.className = "moorai-guard-msg";
    const strong = document.createElement("strong");
    strong.textContent = "MoorAI:";
    msg.appendChild(strong);
    msg.appendChild(document.createTextNode(
      blocking
        ? ` this prompt looks like it contains ${worst.label}${more}. Sending is blocked by policy.`
        : ` this looks like it contains ${worst.label}${more} — are you sure you want to send it?`
    ));

    const actions = document.createElement("div");
    actions.className = "moorai-guard-actions";

    if (!blocking) {
      const proceed = document.createElement("button");
      proceed.className = "moorai-guard-proceed";
      proceed.textContent = "Send anyway";
      proceed.addEventListener("click", () => { removeBanner(); onProceed && onProceed(); });
      actions.appendChild(proceed);
    }
    const cancel = document.createElement("button");
    cancel.className = "moorai-guard-cancel";
    cancel.textContent = blocking ? "Dismiss" : "Cancel";
    cancel.addEventListener("click", () => { removeBanner(); onCancel && onCancel(); });
    actions.appendChild(cancel);

    b.appendChild(msg);
    b.appendChild(actions);
    document.documentElement.appendChild(b);
    bannerEl = b;
  }

  // ---- the gate ----
  // bypass lets an approved ("Send anyway") re-issue pass straight through without re-prompting.
  let bypass = false;
  let pending = false; // a banner is currently shown for this composer

  // Re-issue the send after the user approves. Prefer clicking the real send button; fall back to a
  // synthetic Enter on the composer. bypass suppresses our own interception during the re-issue.
  function reissueSend() {
    bypass = true;
    try {
      const btn = getSendButton();
      if (btn && !btn.disabled) { btn.click(); }
      else {
        const c = getComposer();
        if (c) {
          c.focus();
          for (const type of ["keydown", "keypress", "keyup"]) {
            c.dispatchEvent(new KeyboardEvent(type, { key: "Enter", code: "Enter", keyCode: 13, which: 13, bubbles: true, cancelable: true }));
          }
        }
      }
    } catch { /* best effort */ }
    setTimeout(() => { bypass = false; }, 600);
  }

  // Returns true if the send should proceed immediately, false if we intercepted it.
  function gate() {
    if (bypass) return true;
    if (pending) return false; // banner already up — swallow duplicate triggers
    let findings = [];
    try { findings = D.scan(composerText()); } catch { return true; } // scan error → fail open
    if (!findings.length) return true; // clean → allow

    const worst = D.worst(findings);
    const high = D.isHighSeverity(worst.riskLevel);
    const blocking = CONFIG.mode === "block" && high;

    pending = true;
    // content-free report — blocked flag mirrors the agent's "Blocked" relabel
    try { R && R.send(findings, SITE, blocking); } catch { /* telemetry is best-effort */ }

    showBanner(
      { worst, count: findings.length, blocking },
      () => { pending = false; reissueSend(); },   // proceed
      () => { pending = false; }                    // cancel
    );
    return false; // always intercept this original attempt; proceed re-issues via reissueSend()
  }

  // ---- interception: Enter-without-Shift on the composer ----
  document.addEventListener("keydown", (e) => {
    try {
      if (bypass) return;
      if (e.key !== "Enter" || e.shiftKey || e.isComposing) return; // Shift+Enter = newline; IME compose
      if (!isInComposer(e.target)) return;
      if (!gate()) { e.preventDefault(); e.stopImmediatePropagation(); }
    } catch { /* fail open */ }
  }, true); // capture — run before the site's own handler

  // ---- interception: send-button click ----
  document.addEventListener("click", (e) => {
    try {
      if (bypass) return;
      const btn = e.target && e.target.closest && e.target.closest(SEL.send.join(","));
      if (!btn) return;
      if (!gate()) { e.preventDefault(); e.stopImmediatePropagation(); }
    } catch { /* fail open */ }
  }, true); // capture
})();
