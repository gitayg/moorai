// MoorAI Browser Guard — content-free reporting.
//
// Posts a CONTENT-FREE signal to the same console ingestion contract the agent uses:
//   POST <serverUrl>/api/alerts   with header  X-Install-Token: <token>
// The alert object mirrors cli/moorai-hook.mjs `report()` / `post()`:
//   { threatId, category, riskLevel, stage:"browser", tool:"browser:<site>", ts, contentHash, ... }
//
// GUARANTEE: the prompt text NEVER leaves the browser. Only { category, riskLevel, contentHash (djb2),
// host-only URL, ts } are sent. Fail-open and SILENT on any error or missing config — this is
// governance telemetry, never a blocker.
//
// Exposes globalThis.MoorAIReport.send(findings, site) for content.js (same content-script isolated world).

(function (root) {
  "use strict";

  function getConfig() {
    return new Promise((resolve) => {
      try {
        chrome.storage.sync.get(
          { serverUrl: "", installToken: "", mode: "coach", reportEnabled: true },
          (cfg) => resolve(cfg || {})
        );
      } catch { resolve({}); }
    });
  }

  // One content-free alert per finding. `blocked` re-labels riskLevel to "Blocked" like the agent does.
  async function send(findings, site, blocked) {
    try {
      if (!findings || !findings.length) return;
      const cfg = await getConfig();
      if (!cfg.reportEnabled) return;
      if (!cfg.serverUrl) return; // nothing configured → nothing sent (fail-open, silent)

      const host = (() => { try { return location.host; } catch { return ""; } })();
      const ts = new Date().toISOString();
      const headers = { "Content-Type": "application/json" };
      if (cfg.installToken) headers["X-Install-Token"] = cfg.installToken;

      for (const f of findings) {
        const alert = {
          threatId: f.threatId,
          category: f.category,
          riskLevel: blocked ? "Blocked" : f.riskLevel,
          stage: "browser",              // browser-AI coverage stage (distinct from the agent's file/egress)
          tool: `browser:${site}`,       // e.g. browser:chatgpt / browser:claude / browser:copilot
          ts,
          contentHash: f.contentHash,    // djb2 one-way hash of the matched span — never the span itself
          host,                          // host only; never the full URL, never query strings
          source: "browser-ext"
        };
        // fetch bypasses page CORS because the extension holds host permission for serverUrl's origin.
        fetch(`${cfg.serverUrl.replace(/\/$/, "")}/api/alerts`, {
          method: "POST",
          headers,
          body: JSON.stringify(alert),
          // keepalive lets the POST survive a navigation away right after the user hits send
          keepalive: true
        }).catch(() => {}); // fail-open, silent
      }
    } catch { /* fail-open, silent — telemetry must never break the page */ }
  }

  root.MoorAIReport = { send };
})(typeof globalThis !== "undefined" ? globalThis : this);
