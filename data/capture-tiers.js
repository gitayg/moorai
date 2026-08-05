// #5 — capture tiers. "content-free" is the DEFAULT everywhere; higher tiers are admin-gated, explicit,
// and consent-visible. Each tier only ADDS the whitelisted fields to the base content-free signal
// (category, risk, one-way hash, actor hash, tool, stage). Nothing here changes enforcement.
//
// Shared, identical copy on the agent and the server so both sides agree on the contract. Two backstops
// enforce the invariant: (1) the agent's applyCaptureTier whitelists fields at every emit site; (2) the
// server re-resolves the device's stored tier on ingest and strips anything above it, failing closed.
export const CAPTURE_TIERS = ["content-free", "metadata-plus", "full-capture"];
export const CAPTURE_RANK = { "content-free": 0, "metadata-plus": 1, "full-capture": 2 };

// Fields each tier may add beyond the base content-free signal.
//   metadata-plus: file paths, tool names, and command SHAPE (verb + flags + arg count — never values).
//   full-capture:  the matched span / argument text (actual content) — opt-in only.
export const CAPTURE_FIELDS = {
  "content-free": [],
  "metadata-plus": ["filePath", "toolName", "cmdShape"],
  "full-capture": ["filePath", "toolName", "cmdShape", "matchText", "argText"]
};

const ALL_FIELDS = [...new Set(Object.values(CAPTURE_FIELDS).flat())];

export function captureRank(tier) { return CAPTURE_RANK[tier] || 0; }

// Return `base` merged with ONLY the extras allowed at `tier`. content-free (or an unknown tier) →
// base is returned untouched — the off-by-default guarantee lives here.
export function applyCaptureTier(base, extras, tier) {
  const allowed = CAPTURE_FIELDS[tier] || [];
  const out = { ...base };
  if (!allowed.length || !extras) return out;
  for (const k of allowed) if (extras[k] != null && extras[k] !== "") out[k] = extras[k];
  return out;
}

// Server-side strip: remove any capture field above `tier` from an object. Unknown tier → content-free.
export function stripAboveTier(obj, tier) {
  const allowed = new Set(CAPTURE_FIELDS[tier] || []);
  const out = { ...obj };
  for (const k of ALL_FIELDS) if (!allowed.has(k)) delete out[k];
  return out;
}

// Best-effort command SHAPE (metadata-plus): the verb + flag names + arg/redirect counts, no values.
export function commandShape(cmd) {
  const s = String(cmd || "").trim();
  if (!s) return "";
  const toks = s.split(/\s+/);
  const verb = toks[0] || "";
  const flags = toks.filter((t) => t.startsWith("-")).map((t) => t.split("=")[0]);
  const args = toks.slice(1).filter((t) => !t.startsWith("-")).length;
  const redirs = (s.match(/[|><]|&&|\|\|/g) || []).length;
  return `${verb} ${flags.join(" ")} [${args} args${redirs ? ", " + redirs + " redir" : ""}]`.trim();
}
