// What a MoorAI surface does when it cannot reach a decision: an engine error or timeout, an item past
// the scan cap, or no policy at all. The administrator chooses, never the user.
//
// Precedence: the root-owned admin binding (/etc/moorai/config.json, %ProgramData% via cli/machine-dir.mjs)
// wins; then the signed policy's failMode[surface], then failMode.default; then the surface's own
// built-in default. User-writable state is never read here.
//
// Policy shape (signed): { failMode: { default?: "open"|"closed", hook?, modelProxy?, mcpGateway?, inferenceHook? } }
// Admin binding shape: the same object under the key "failMode".
//
// `admin` is the parsed admin binding (cli/server-mode.mjs systemConfig(), which reads the file only when
// it is root-owned and not group/world-writable). Its "failMode" table is read; an object that has no
// "failMode" key but does carry a surface or "default" key is taken as the table itself. Only exact
// lowercase "open" / "closed" count. Anything else is ignored with a warning naming the source and key
// (never the value), and the next source decides. Never throws.
export const FAIL_SURFACES = Object.freeze(["hook", "modelProxy", "mcpGateway", "inferenceHook"]);
export const FAIL_MODES = Object.freeze(["open", "closed"]);

const TABLE_KEYS = [...FAIL_SURFACES, "default"];
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
function defaultWarn(m) { try { process.stderr.write(`moorai: ${m}\n`); } catch { /* a warning, never a decision */ } }

function tableOf(src, label, warn, { bare = false } = {}) {
  if (!isObj(src)) return null;
  if (own(src, "failMode")) {
    if (isObj(src.failMode)) return src.failMode;
    if (src.failMode != null) warn(`failMode in the ${label} is not an object; ignored`);
    return null;
  }
  return bare && TABLE_KEYS.some((k) => own(src, k)) ? src : null;
}

function pick(table, keys, label, warn) {
  if (!table) return null;
  for (const k of keys) {
    if (!own(table, k)) continue;
    const v = table[k];
    if (FAIL_MODES.includes(v)) return v;
    warn(`failMode.${k} in the ${label} is not "open" or "closed"; ignored`);
  }
  return null;
}

// Returns { mode: "open"|"closed", source: "admin"|"policy"|"default" }.
export function resolveFailMode(policy, surface, { admin = null, fallback = "open", warn = defaultWarn } = {}) {
  const w = typeof warn === "function" ? (m) => { try { warn(m); } catch { /* never throws */ } } : () => {};
  try {
    let keys = ["default"];
    if (FAIL_SURFACES.includes(surface)) keys = [surface, "default"];
    else w(`unknown fail surface; only failMode.default applies`);
    const a = pick(tableOf(admin, "admin binding", w, { bare: true }), keys, "admin binding", w);
    if (a) return { mode: a, source: "admin" };
    const p = pick(tableOf(policy, "signed policy", w), keys, "signed policy", w);
    if (p) return { mode: p, source: "policy" };
    if (FAIL_MODES.includes(fallback)) return { mode: fallback, source: "default" };
    w(`fail-mode fallback is not "open" or "closed"; open applies`);
  } catch { /* never throws: the built-in default below */ }
  return { mode: "open", source: "default" };
}

// Every surface at once, for the posture heartbeat and the doctor. `fallbacks` holds a surface's own
// built-in default where it is not "open" (e.g. the Inference hooks server's --fail flag).
export function effectiveFailModes(policy, { admin = null, fallbacks = {}, warn } = {}) {
  const out = {};
  for (const s of FAIL_SURFACES) out[s] = resolveFailMode(policy, s, { admin, fallback: (fallbacks && fallbacks[s]) || "open", ...(warn ? { warn } : {}) });
  return out;
}
