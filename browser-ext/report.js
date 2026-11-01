// MoorAI Browser Guard — content-free reporting (content-script side).
//
// Builds a CONTENT-FREE signal per finding, shaped like the agent's alerts (cli/moorai-hook.mjs
// `report()` / `post()`):
//   { threatId, category, riskLevel, stage:"browser", tool:"browser:<site>", ts, contentHash, host, source }
// and hands the batch to the background worker (background.js), which posts it to
// <serverUrl>/api/alerts with X-Install-Token. A content script cannot post it itself: its fetch runs
// under the page's origin and same-origin policy.
//
// GUARANTEE: the prompt text NEVER leaves the browser. Only { category, riskLevel, contentHash (a keyed
// HMAC-SHA-256 of the matched span, not the span), host-only URL, ts } are sent. Fail-open and SILENT on
// any error or missing config: this is governance telemetry, never a blocker.
//
// Exposes globalThis.MoorAIReport.send(findings, site, blocked) for content.js (same isolated world).

(function (root) {
  "use strict";

  function alertsFor(findings, site, blocked) {
    const host = (() => { try { return location.host; } catch { return ""; } })();
    const ts = new Date().toISOString();
    const out = [];
    for (const f of findings) {
      out.push({
        threatId: f.threatId,
        category: f.category,
        riskLevel: blocked ? "Blocked" : f.riskLevel,
        stage: "browser",              // browser-AI coverage stage (distinct from the agent's file/egress)
        tool: `browser:${site}`,       // e.g. browser:chatgpt / browser:claude / browser:copilot
        ts,
        contentHash: f.contentHash,    // keyed one-way hash of the matched span, never the span itself
        host,                          // host only; never the full URL, never query strings
        source: "browser-ext"
      });
      // Coach-as-literacy (EU AI Act Art. 4): the in-page banner shown for this finding is a just-in-time
      // literacy touchpoint. Mirrors literacyTouchpoint() in cli/hook-core.mjs; the extension is a separate
      // runtime and cannot import it, so the shape is kept in sync by hand.
      if (blocked || f.riskLevel === "High" || f.riskLevel === "Critical") {
        out.push({ threatId: f.threatId, category: `Literacy: ${f.category}`, riskLevel: "Info", stage: "coach", tool: `browser:${site}`, ts, contentHash: "coach:" + f.threatId, host, source: "browser-ext" });
      }
    }
    return out;
  }

  async function send(findings, site, blocked) {
    try {
      if (!findings || !findings.length) return;
      const alerts = alertsFor(findings, site, blocked);
      chrome.runtime.sendMessage({ type: "moorai-alerts", alerts }, () => { try { void chrome.runtime.lastError; } catch { /* ignore */ } });
    } catch { /* fail-open, silent: telemetry must never break the page */ }
  }

  root.MoorAIReport = { send };
})(typeof globalThis !== "undefined" ? globalThis : this);
