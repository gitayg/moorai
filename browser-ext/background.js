// MoorAI Browser Guard — background service worker: the only place that talks to the MoorAI console.
//
// WHY A WORKER. A content script's fetch is made on behalf of the page it runs in, so it is subject to
// that page's same-origin policy even when the extension holds host permission for the destination
// (Chrome extension docs, "Cross-origin network requests"). Requests from the extension's service worker
// may reach a host the extension has host permission for. So the content script hands content-free
// alerts here (report.js → chrome.runtime.sendMessage) and this worker posts them.
//
// WHAT IT ACCEPTS. Messages from this extension only (sender.id), type "moorai-alerts", at most 32
// alerts, each rebuilt from an allow-list of content-free fields with type and length checks; anything
// else is dropped. It posts only when a console URL is configured (managed policy or options page),
// reporting is on, the URL is https (or http on loopback), and the extension holds host permission for
// that origin (granted on the options page, or built in by `scripts/browser-ext-package.mjs
// --console-origin`). Fail-open and silent: telemetry never affects the page.

(function (root) {
  "use strict";
  if (typeof importScripts === "function" && !root.MoorAIConfig) { try { importScripts("config.js"); } catch { /* config missing */ } }

  const MAX_ALERTS = 32;
  const RISK = ["Info", "Low", "Medium", "High", "Critical", "Blocked"];
  const FIELDS = {
    threatId: (v) => (typeof v === "string" && v.length <= 64) || (typeof v === "number" && Number.isFinite(v)),
    category: (v) => typeof v === "string" && v.length > 0 && v.length <= 120,
    riskLevel: (v) => RISK.includes(v),
    stage: (v) => v === "browser" || v === "coach",
    tool: (v) => typeof v === "string" && /^browser:[a-z0-9-]{1,32}$/.test(v),
    ts: (v) => typeof v === "string" && v.length <= 40 && !Number.isNaN(Date.parse(v)),
    contentHash: (v) => typeof v === "string" && v.length <= 80,
    host: (v) => typeof v === "string" && /^[a-z0-9.-]{0,253}(:\d{1,5})?$/i.test(v),
    source: (v) => v === "browser-ext"
  };

  // → a fresh object holding only the allowed fields, or null when any field is missing or invalid.
  function sanitize(a) {
    if (!a || typeof a !== "object") return null;
    const out = {};
    for (const [k, ok] of Object.entries(FIELDS)) {
      if (!(k in a) || !ok(a[k])) return null;
      out[k] = a[k];
    }
    return out;
  }

  function endpoint(serverUrl) {
    try {
      const u = new URL(String(serverUrl));
      const loop = u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost");
      if (u.protocol !== "https:" && !loop) return null;
      return { origin: u.origin, url: `${u.origin}${u.pathname.replace(/\/+$/, "")}/api/alerts` };
    } catch { return null; }
  }

  function post(alerts) {
    root.MoorAIConfig.load((cfg) => {
      if (!cfg.reportEnabled || !cfg.serverUrl) return;
      const ep = endpoint(cfg.serverUrl);
      if (!ep) return;
      try {
        chrome.permissions.contains({ origins: [`${ep.origin}/*`] }, (granted) => {
          if (!granted) return;
          const headers = { "Content-Type": "application/json" };
          if (cfg.installToken) headers["X-Install-Token"] = cfg.installToken;
          for (const a of alerts) {
            try { fetch(ep.url, { method: "POST", headers, body: JSON.stringify(a), keepalive: true }).catch(() => {}); } catch { /* silent */ }
          }
        });
      } catch { /* silent */ }
    });
  }

  function handle(msg, sender) {
    try {
      if (!sender || sender.id !== chrome.runtime.id) return;
      if (!msg || msg.type !== "moorai-alerts" || !Array.isArray(msg.alerts)) return;
      const alerts = msg.alerts.slice(0, MAX_ALERTS).map(sanitize).filter(Boolean);
      if (alerts.length) post(alerts);
    } catch { /* silent */ }
  }

  try { chrome.runtime.onMessage.addListener((msg, sender) => { handle(msg, sender); }); } catch { /* not in an extension */ }
  root.MoorAIBackground = { sanitize, endpoint, handle };
})(typeof globalThis !== "undefined" ? globalThis : this);
