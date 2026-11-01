// MoorAI Browser Guard — configuration. Shared by the content script, the background worker and the
// options page. Two sources, in order of precedence:
//   1. chrome.storage.managed — set by an administrator through browser policy (managed-schema.json:
//      Chrome/Edge 3rdparty extension policy, pushed with the force-install templates in policy/).
//   2. chrome.storage.sync    — what the user saved on the options page.
// A managed value always wins; with lockSettings the options page shows managed values read-only.
// On an unmanaged browser managed storage is empty (or unavailable) and the user's values apply.
//
// Exposes globalThis.MoorAIConfig = { DEFAULTS, merge, load }.

(function (root) {
  "use strict";

  const DEFAULTS = { mode: "coach", serverUrl: "", installToken: "", reportEnabled: true, lockSettings: false };
  const TYPES = { mode: "string", serverUrl: "string", installToken: "string", reportEnabled: "boolean", lockSettings: "boolean" };
  const MODES = ["coach", "block"];

  function valid(k, v) {
    if (!(k in TYPES) || typeof v !== TYPES[k]) return false;
    return k !== "mode" || MODES.includes(v);
  }

  // managed + sync → effective config. Invalid or mistyped values from either source are ignored.
  function merge(managed, sync) {
    const out = { ...DEFAULTS };
    for (const [k, v] of Object.entries(sync || {})) if (valid(k, v) && k !== "lockSettings") out[k] = v;
    const managedKeys = [];
    for (const [k, v] of Object.entries(managed || {})) if (valid(k, v)) { out[k] = v; managedKeys.push(k); }
    out.locked = out.lockSettings === true && managedKeys.includes("lockSettings");
    out.managedKeys = managedKeys;
    return out;
  }

  function getArea(name, defaults) {
    return new Promise((resolve) => {
      try {
        const area = chrome.storage && chrome.storage[name];
        if (!area) return resolve({});
        area.get(defaults, (v) => {
          // managed storage throws or sets lastError where no policy schema is loaded (unmanaged browser).
          try { if (chrome.runtime && chrome.runtime.lastError) return resolve({}); } catch { /* ignore */ }
          resolve(v || {});
        });
      } catch { resolve({}); }
    });
  }

  function load(cb) {
    Promise.all([getArea("managed", null), getArea("sync", { mode: "coach", serverUrl: "", installToken: "", reportEnabled: true })])
      .then(([managed, sync]) => cb(merge(managed, sync)))
      .catch(() => cb(merge({}, {})));
  }

  root.MoorAIConfig = { DEFAULTS, merge, load };
})(typeof globalThis !== "undefined" ? globalThis : this);
