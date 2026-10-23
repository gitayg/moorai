// Just-in-time approval routing, device side (CONTRACT-F28 §3).
//
// The signed policy may carry `approvalRouting` ({ v: 1, rules: [...] }): which held verdicts go to a human
// approver group instead of standing as a block or an ask. An older agent ignores the key, so a block stays a block
// and an ask stays an ask (safe by direction). This agent:
//   1. answers the host at once with a deny (it never waits on the network): "Held for approval: <label> (request
//      apr_…). Retry after it is approved." A Claude Code ask is not shown locally;
//   2. generates the request id on the device ("apr_" + 26 Crockford base32 characters, 128 random bits);
//   3. posts one content-free APPROVAL_REQUESTED alert through the existing alert path (post() and the outbox),
//      with a keyed actionHash of the exact call (contentHash, per tenant), and reuses a pending request for the
//      same rule and action, without a new alert, until it expires;
//   4. learns the decision from the signed `approvals` list in its next /api/policy response. Only a policy whose
//      ed25519 signature verifies under the anchor or the pinned key (status "ok") is read for approvals: an
//      unsigned body, a tampered body, and a device with no key yet (first contact) give no grant;
//   5. allows the identical action (same rule, same actionHash) while an approve grant is valid: once (the request
//      id is recorded as used in approvals.json, APPROVAL_USED posted) or until validUntil (grant "ttl"). A deny
//      grant answers "Denied by approver (<label>)". A request past its expiry with no decision is denied and
//      APPROVAL_EXPIRED is posted once; the next identical call raises a new request.
//
// Known limit, stated and not hidden: approvals.json is in the agent user's write scope, so a "once" grant can be
// replayed for the identical action until its validUntil. validUntil (signed) is the bound.
//
// Pending requests and used grants live in ~/.moorai/approvals.json (0600, at most 256 pending entries).
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, renameSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson, verifyPolicySignature } from "./hook-core.mjs";
import { WIRE_RE, receiptActionHashInput } from "./approval-receipts.mjs";

export const APPROVAL_REQUESTED = "APPROVAL_REQUESTED";
export const APPROVAL_USED = "APPROVAL_USED";
export const APPROVAL_EXPIRED = "APPROVAL_EXPIRED";
// Local provenance only (the ledger row of a call an approver denied); never sent as an alert reason code.
export const APPROVAL_DENIED = "APPROVAL_DENIED";
export const APPROVALS_FILE = "approvals.json";
export const RULES_MAX = 64;
export const LIST_MAX = 64;
export const GRANTS_MAX = 64;
export const PENDING_MAX = 256;
export const USED_MAX = 256;
export const HOLDS = Object.freeze(["block", "ask"]);
export const GRANTS = Object.freeze(["once", "ttl"]);
export const ROUTABLE_REASON_CODES = Object.freeze(["OT_PROTOCOL_CLIENT", "EGRESS_RULE", "MCP_TOOL_ARGS"]);
export const OT_OPS = Object.freeze(["read", "write", "unknown"]);
export const MATCH_KEYS = Object.freeze(["threatId", "functionTool", "mcpTool", "egressRuleId", "reasonCode", "otOp"]);
const RULE_KEYS = ["id", "label", "match", "holds", "group", "timeoutSec", "onTimeout", "grant", "grantTtlSec"];
export const SLUG_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MCP_TOOL_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\/[A-Za-z0-9_.:-]{1,128}$/;
// Same name syntax as functionToolActions keys (model-proxy/function-rules.mjs NAME_RE), with an optional trailing *.
const FUNCTION_NAME_RE = /^[A-Za-z0-9_.:\-]{1,128}$/;
const CONTROL_RE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const LABEL_MAX = 80;
export const REQUEST_ID_RE = /^apr_[0-9A-HJKMNP-TV-Z]{26}$/;
const ACTION_HASH_RE = /^h2:[0-9a-f]{16,64}$/;
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const intIn = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function list(v, ok, what) {
  if (!Array.isArray(v) || !v.length) return { error: `match.${what}: a non-empty list` };
  if (v.length > LIST_MAX) return { error: `match.${what}: at most ${LIST_MAX} entries` };
  if (!v.every(ok)) return { error: `match.${what}: an entry is not valid` };
  return { value: [...new Set(v)] };
}
const MATCHERS = {
  threatId: (v) => list(v, (x) => intIn(x, 1, 9999), "threatId"),
  functionTool: (v) => list(v, (x) => typeof x === "string" && FUNCTION_NAME_RE.test(x.endsWith("*") ? x.slice(0, -1) : x), "functionTool"),
  mcpTool: (v) => list(v, (x) => typeof x === "string" && MCP_TOOL_RE.test(x), "mcpTool"),
  egressRuleId: (v) => list(v, (x) => typeof x === "string" && SLUG_RE.test(x), "egressRuleId"),
  reasonCode: (v) => list(v, (x) => ROUTABLE_REASON_CODES.includes(x), "reasonCode"),
  otOp: (v) => list(v, (x) => OT_OPS.includes(x), "otOp")
};

// The same rule validation as the console (server/approval-routing.js). → { value } | { error } (the error never
// echoes a value).
export function validateRule(r) {
  if (!isObj(r)) return { error: "a rule is an object" };
  if (Object.keys(r).some((k) => !RULE_KEYS.includes(k))) return { error: "unknown key in rule" };
  if (typeof r.id !== "string" || !SLUG_RE.test(r.id)) return { error: "id: not a valid slug" };
  const label = typeof r.label === "string" ? r.label.trim() : "";
  if (!label || [...label].length > LABEL_MAX || CONTROL_RE.test(label)) return { error: `label: 1-${LABEL_MAX} characters of plain text` };
  if (!isObj(r.match)) return { error: "match: an object" };
  const keys = Object.keys(r.match);
  if (!keys.length) return { error: "match: at least one key" };
  if (keys.some((k) => !MATCH_KEYS.includes(k))) return { error: "match: unknown key" };
  const match = {};
  for (const k of MATCH_KEYS) {
    if (!(k in r.match)) continue;
    const v = MATCHERS[k](r.match[k]);
    if (v.error) return { error: v.error };
    match[k] = v.value;
  }
  if (match.otOp && !(match.reasonCode || []).includes("OT_PROTOCOL_CLIENT")) return { error: "match.otOp: only with reasonCode OT_PROTOCOL_CLIENT" };
  if (!Array.isArray(r.holds) || !r.holds.length || !r.holds.every((h) => HOLDS.includes(h))) return { error: "holds: block and/or ask" };
  if (typeof r.group !== "string" || !SLUG_RE.test(r.group)) return { error: "group: an approver group id" };
  const timeoutSec = r.timeoutSec === undefined ? 600 : r.timeoutSec;
  if (!intIn(timeoutSec, 60, 3600)) return { error: "timeoutSec: 60 to 3600" };
  const onTimeout = r.onTimeout === undefined ? "deny" : r.onTimeout;
  if (onTimeout !== "deny") return { error: "onTimeout: deny only" };
  const grant = r.grant === undefined ? "once" : r.grant;
  if (!GRANTS.includes(grant)) return { error: "grant: once or ttl" };
  const grantTtlSec = r.grantTtlSec === undefined ? 900 : r.grantTtlSec;
  if (!intIn(grantTtlSec, 60, 86400)) return { error: "grantTtlSec: 60 to 86400" };
  return { value: { id: r.id, label, match, holds: HOLDS.filter((h) => r.holds.includes(h)), group: r.group, timeoutSec, onTimeout, grant, grantTtlSec } };
}

const stderrWarn = (m) => { try { process.stderr.write(`moorai: ${m}\n`); } catch { /* best effort */ } };
// The valid rules of a policy's approvalRouting. A malformed rule is dropped with a warning that names the rule id
// (or its index when the id itself is not valid), never a value; a dropped rule leaves the original verdict in force.
export function approvalRules(policy, { warn = stderrWarn } = {}) {
  const ar = isObj(policy) ? policy.approvalRouting : undefined;
  if (ar === undefined || ar === null) return [];
  if (!isObj(ar) || ar.v !== 1 || !Array.isArray(ar.rules)) { warn("approvalRouting ignored: not { v: 1, rules: [...] }"); return []; }
  const out = [], ids = new Set();
  ar.rules.forEach((r, i) => {
    const name = isObj(r) && typeof r.id === "string" && SLUG_RE.test(r.id) ? `"${r.id}"` : `#${i}`;
    if (out.length >= RULES_MAX) { warn(`approvalRouting rule ${name} dropped: at most ${RULES_MAX} rules`); return; }
    const v = validateRule(r);
    if (v.error) { warn(`approvalRouting rule ${name} dropped: ${v.error}`); return; }
    if (ids.has(v.value.id)) { warn(`approvalRouting rule ${name} dropped: duplicate rule id`); return; }
    ids.add(v.value.id);
    out.push(v.value);
  });
  return out;
}

// functionTool syntax: an exact name, or a prefix ending in *. Case-insensitive, `-` read as `_` (as the model proxy
// folds names). No surface in this file supplies a function name; the model proxy does.
function functionToolMatches(keys, name) {
  if (typeof name !== "string" || !name) return false;
  const f = (s) => s.toLowerCase().replace(/-/g, "_");
  const n = f(name);
  return keys.some((k) => (k.endsWith("*") ? n.startsWith(f(k.slice(0, -1))) : n === f(k)));
}
const allIn = (vals, allowed) => Array.isArray(vals) && vals.length > 0 && vals.every((v) => allowed.includes(v));

// facts: { threatIds: [driving threat ids], functionTool, mcpTool: "server/tool", egressRuleIds: [...], reasonCode,
// otOp }. Every key the rule sets must match. Threat ids and egress rule ids must ALL be covered by the rule, so an
// approval for one threat never lifts a second, unrelated one on the same call.
export function ruleMatches(rule, verdict, facts = {}) {
  if (!rule || !rule.holds.includes(verdict)) return false;
  const m = rule.match;
  if (m.threatId && !allIn(facts.threatIds, m.threatId)) return false;
  if (m.functionTool && !functionToolMatches(m.functionTool, facts.functionTool)) return false;
  if (m.mcpTool && !m.mcpTool.includes(facts.mcpTool)) return false;
  if (m.egressRuleId && !allIn(facts.egressRuleIds, m.egressRuleId)) return false;
  if (m.reasonCode && !m.reasonCode.includes(facts.reasonCode)) return false;
  if (m.otOp && !m.otOp.includes(facts.otOp)) return false;
  return true;
}
export function matchRule(rules, verdict, facts) { return (rules || []).find((r) => ruleMatches(r, verdict, facts)) || null; }

// "apr_" + 26 Crockford base32 characters of 128 random bits (two leading zero bits pad 128 to 130).
export function newRequestId(bytes = randomBytes(16)) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = "";
  for (let i = 0; i < 26; i++) { s = CROCKFORD[Number(n & 31n)] + s; n >>= 5n; }
  return `apr_${s}`;
}

// contentHash("approval\0" + tool + "\0" + canonicalJson(normalizedInput)): keyed per tenant, never reversible.
// An MCP call covered by approvalReceipts (receiptFor set) hashes { argsSha256, aud, tool } instead, so the console can
// check the request and the receipt it mints agree (cli/approval-receipts.mjs receiptActionHashInput).
export function actionHashOf(tool, input, hash, receiptFor = null) {
  if (receiptFor) return hash(receiptActionHashInput(receiptFor.tool, receiptFor.argsSha256, receiptFor.aud));
  return hash(`approval\u0000${tool}\u0000${canonicalJson(input ?? null)}`);
}

// "mcp__server__tool" → "server/tool"; anything else → "".
export function mcpToolOf(tool) {
  const m = /^mcp__(.+?)__(.+)$/.exec(String(tool || ""));
  return m ? `${m[1]}/${m[2]}` : "";
}

// The decided approvals of a policy, only when its signature verifies under a key the device holds (anchor or pin):
// status "ok". An unanchored device (no key yet) and a body that does not verify give [] — a grant LOOSENS a verdict,
// so it is read from signed bytes only (CONTRACT-F28 §0.6). Invalid entries are skipped.
export function signedApprovals(policy, { keys = [], tenant = "" } = {}) {
  if (!isObj(policy) || !Array.isArray(policy.approvals) || !keys.length) return [];
  let v;
  try { v = verifyPolicySignature(policy, { keys, tenant }); } catch { return []; }
  if (!v || v.status !== "ok") return [];
  const out = [];
  for (const a of policy.approvals.slice(0, GRANTS_MAX)) {
    if (!isObj(a) || typeof a.requestId !== "string" || !REQUEST_ID_RE.test(a.requestId)) continue;
    if (typeof a.ruleId !== "string" || !SLUG_RE.test(a.ruleId)) continue;
    if (typeof a.actionHash !== "string" || !ACTION_HASH_RE.test(a.actionHash)) continue;
    if (a.decision !== "approve" && a.decision !== "deny") continue;
    const until = Date.parse(a.validUntil);
    if (!Number.isFinite(until)) continue;
    const decided = Date.parse(a.decidedAt);
    // receipt: the console's approval receipt for this grant (docs/approval-receipts.md), passed on unchanged.
    const receipt = a.decision === "approve" && typeof a.receipt === "string" && WIRE_RE.test(a.receipt) ? a.receipt : null;
    out.push({ requestId: a.requestId, ruleId: a.ruleId, actionHash: a.actionHash, decision: a.decision, grant: GRANTS.includes(a.grant) ? a.grant : "once", decidedAtMs: Number.isFinite(decided) ? decided : 0, validUntilMs: until, ...(receipt ? { receipt } : {}) });
  }
  return out.sort((x, y) => y.decidedAtMs - x.decidedAtMs);
}

// ---- approvals.json ----
export function emptyState() { return { v: 1, pending: [], used: [] }; }
export function readApprovalState(dir) {
  try {
    const s = JSON.parse(readFileSync(join(dir, APPROVALS_FILE), "utf8"));
    if (!isObj(s)) return emptyState();
    const ok = (e) => isObj(e) && typeof e.requestId === "string" && REQUEST_ID_RE.test(e.requestId);
    return { v: 1, pending: Array.isArray(s.pending) ? s.pending.filter(ok) : [], used: Array.isArray(s.used) ? s.used.filter(ok) : [] };
  } catch { return emptyState(); }
}
export function writeApprovalState(dir, state) {
  try {
    mkdirSync(dir, { recursive: true });
    const p = join(dir, APPROVALS_FILE);
    const tmp = `${p}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ v: 1, pending: state.pending.slice(-PENDING_MAX), used: state.used.slice(-USED_MAX) }), { mode: 0o600 });
    try { chmodSync(tmp, 0o600); } catch { /* Windows */ }
    renameSync(tmp, p);
    return true;
  } catch { return false; }
}

const heldReason = (rule, id) => `Held for approval: ${rule.label} (request ${id}). Retry after it is approved.`;

// The pure state machine for one held verdict. Never does I/O.
//   rule, verdict ("block" | "ask"), actionHash, threatId (the first driving threat, for the alert), grants (from
//   signedApprovals, newest first), state (approvals.json), nowMs, allowGrant (false where the held verdict came
//   before the rest of the call was judged: the grant is then honoured at the earlier check, never here), newId.
// → { outcome: "allow" | "deny", reasonCode, reason, requestId, events: [{ kind, requestId, ruleId, actionHash, ... }],
//     state, changed }
export function decideHeld({ rule, verdict, actionHash, threatId = 0, grants = [], state = emptyState(), nowMs = Date.now(), allowGrant = true, newId = newRequestId, receiptFor = null }) {
  const st = { v: 1, pending: [...state.pending], used: state.used.filter((u) => !(Number(u.validUntilMs) <= nowMs)) };
  let changed = st.used.length !== state.used.length;
  const events = [];
  const grantFor = new Set(grants.map((g) => g.requestId));
  // Expiry: a pending request past its expiry with no decision in the signed list is denied; APPROVAL_EXPIRED once.
  st.pending = st.pending.filter((p) => {
    if (!(Date.parse(p.expiresAt) <= nowMs) || grantFor.has(p.requestId)) return true;
    events.push({ kind: APPROVAL_EXPIRED, requestId: p.requestId, ruleId: p.ruleId, actionHash: p.actionHash, threatId: p.threatId || 0 });
    changed = true;
    return false;
  });
  const done = (o) => ({ ...o, events, state: st, changed });
  const dropPending = (id) => { const n = st.pending.length; st.pending = st.pending.filter((p) => p.requestId !== id); if (st.pending.length !== n) changed = true; };
  for (const g of grants) {
    if (g.ruleId !== rule.id || g.actionHash !== actionHash || !(g.validUntilMs > nowMs)) continue;
    if (g.decision === "deny") {
      dropPending(g.requestId);
      return done({ outcome: "deny", reasonCode: APPROVAL_DENIED, reason: `Denied by approver (${rule.label}, request ${g.requestId}).`, requestId: g.requestId });
    }
    if (!allowGrant) continue;
    const once = g.grant === "once" || rule.grant === "once";
    const seen = st.used.some((u) => u.requestId === g.requestId);
    if (once && seen) continue;
    dropPending(g.requestId);
    if (!seen) {
      st.used.push({ requestId: g.requestId, grant: once ? "once" : "ttl", validUntilMs: g.validUntilMs });
      changed = true;
      events.push({ kind: APPROVAL_USED, requestId: g.requestId, ruleId: rule.id, actionHash, threatId });
    }
    // The console's receipt rides only on the grant's first use: it is single-use at the hub.
    return done({ outcome: "allow", reasonCode: APPROVAL_USED, reason: `Approved by approver (${rule.label}, request ${g.requestId}).`, requestId: g.requestId, grant: once ? "once" : "ttl", receipt: !seen && g.receipt ? g.receipt : null });
  }
  const pending = st.pending.find((p) => p.ruleId === rule.id && p.actionHash === actionHash);
  if (pending) return done({ outcome: "deny", reasonCode: APPROVAL_REQUESTED, reason: heldReason(rule, pending.requestId), requestId: pending.requestId, reused: true });
  const requestId = newId();
  const requestedAt = new Date(nowMs).toISOString();
  const expiresAt = new Date(nowMs + rule.timeoutSec * 1000).toISOString();
  st.pending.push({ requestId, ruleId: rule.id, actionHash, threatId, requestedAt, expiresAt });
  if (st.pending.length > PENDING_MAX) st.pending = st.pending.slice(-PENDING_MAX);
  changed = true;
  events.push({ kind: APPROVAL_REQUESTED, requestId, ruleId: rule.id, actionHash, threatId, verdict, requestedAt, expiresAt, ...(receiptFor ? { receiptFor } : {}) });
  return done({ outcome: "deny", reasonCode: APPROVAL_REQUESTED, reason: heldReason(rule, requestId), requestId });
}

// The content-free alert for one event. surface "hook"; the caller adds ts and identity.
// A request for an MCP call covered by approvalReceipts adds approval.receiptArgsDigest (the tenant-keyed digest of
// argsSha256, safe to store) and approval.receiptRequest { aud, tool, argsSha256 }: the raw hash the console needs
// to mint a receipt, which it must strip before alert storage and SIEM (docs/approval-receipts.md §5).
export function approvalAlert(ev, { tool = "", surface = "hook", destClass, hash } = {}) {
  const base = { threatId: Number.isInteger(ev.threatId) ? ev.threatId : 0, stage: "PreToolUse", tool: tool ? `hook:${tool}` : "hook", contentHash: ev.actionHash };
  if (ev.kind === APPROVAL_REQUESTED) {
    return { ...base, category: "Approval requested", riskLevel: "High", decision: "deny", reasonCode: APPROVAL_REQUESTED,
      approval: { v: 1, requestId: ev.requestId, ruleId: ev.ruleId, surface, verdict: ev.verdict, actionHash: ev.actionHash, requestedAt: ev.requestedAt, expiresAt: ev.expiresAt, ...(destClass ? { destClass } : {}), ...(ev.receiptFor && hash ? { receiptArgsDigest: hash(ev.receiptFor.argsSha256), receiptRequest: { aud: ev.receiptFor.aud, tool: ev.receiptFor.tool, argsSha256: ev.receiptFor.argsSha256 } } : {}) } };
  }
  if (ev.kind === APPROVAL_USED) return { ...base, category: "Approval used", riskLevel: "Info", decision: "allow", reasonCode: APPROVAL_USED, approval: { v: 1, requestId: ev.requestId, ruleId: ev.ruleId, surface } };
  return { ...base, category: "Approval expired", riskLevel: "Info", decision: "deny", reasonCode: APPROVAL_EXPIRED, approval: { v: 1, requestId: ev.requestId, ruleId: ev.ruleId, surface } };
}

// The verdict reasons a hold may follow: the call was judged in full (detectors, content rules) or stopped at an
// egress rule. Fail-closed, tamper, containment, kill, decoy, circuit breaker and the other early stops are never
// routed: a grant would otherwise release a call that was not judged.
const ROUTABLE_BASIS = new Set(["", "DETECTOR_MATCH", "CONTENT_RULE", "EGRESS_RULE"]);
const ENFORCING = new Set(["block", "justify", "ask", "kill", "mask"]);

// The hook's gate. deps:
//   load()          → { policy, trust } — the verified policy load of this invocation (trust.keys: anchor or pin)
//   tenant, enabled (enrolled device), hash (cli/content-hash.mjs contentHash), threatAction(id), post(alert)
//   stateDir        where approvals.json lives; now() → ms; warn(msg); newId()
export function approvalGate({ load, tenant = "", enabled = true, hash, threatAction = () => "notify", post = () => {}, stateDir, now = () => Date.now(), warn = stderrWarn, newId = newRequestId } = {}) {
  let ctx = null;
  let egress = null;
  let granted = null; // { requestId, receipt } of the approval this invocation used to allow its call

  async function context() {
    if (ctx) return ctx;
    let policy = null, trust = null;
    try { ({ policy, trust } = (await load()) || {}); } catch { policy = null; }
    const rules = enabled ? approvalRules(policy, { warn }) : [];
    return (ctx = { policy, rules, grants: rules.length ? signedApprovals(policy, { keys: (trust && trust.keys) || [], tenant }) : [] });
  }
  function run(c, rule, verdict, actionHash, threatId, tool, allowGrant, receiptFor = null) {
    const r = decideHeld({ rule, verdict, actionHash, threatId, grants: c.grants, state: readApprovalState(stateDir), nowMs: now(), allowGrant, newId, receiptFor });
    if (r.outcome === "allow") granted = { requestId: r.requestId, receipt: r.receipt || null };
    // A request whose pending record cannot be written is still held (deny); its alert is still sent.
    if (r.changed) writeApprovalState(stateDir, r.state);
    for (const ev of r.events) { try { post(approvalAlert(ev, { tool, hash })); } catch { /* delivery is the outbox's job */ } }
    return r;
  }
  return {
    // The approval that allowed this invocation's call, or null: { requestId, receipt (the console's, first use) }.
    granted() { return granted; },
    // The early egress stop (cli/workload-profile.mjs deny with reasonCode EGRESS_RULE): an approve grant for the
    // identical action lifts it and the call goes on to the rest of the checks. → true when lifted.
    async liftEgress(wp, { tool, ti, receiptFor = null } = {}) {
      egress = null;
      try {
        if (!wp || wp.reasonCode !== "EGRESS_RULE") return false;
        const ids = [...new Set((wp.alerts || []).filter((a) => a && a.reasonCode === "EGRESS_RULE" && a.egressAction === "block").map((a) => a.egressRuleId))];
        // A default-block (no rule id) leaves no id to match.
        egress = { egressRuleIds: ids.every((x) => typeof x === "string" && x) ? ids : [] };
        const c = await context();
        if (!c.rules.length) return false;
        const rule = matchRule(c.rules, "block", { reasonCode: "EGRESS_RULE", egressRuleIds: egress.egressRuleIds, mcpTool: mcpToolOf(tool) });
        if (!rule) return false;
        const r = run(c, rule, "block", actionHashOf(tool, ti, hash, receiptFor), 0, tool, true, receiptFor);
        if (r.outcome === "allow") { egress = null; return true; }
        return false;
      } catch { return false; }
    },
    // A deny or ask about to go to the host. v: { decision, reason, alternatives, rewrite }; call: { tool, ti, found
    // (threat ids reported on this call), basis (VERDICT.reason), killOnCritical }. → null (not routed) or the new
    // { decision, reason, alternatives, rewrite, reasonCode }.
    async overlay(v, { tool = "", ti = {}, found = [], basis = "", killOnCritical = false, receiptFor = null } = {}) {
      try {
        if (!v || (v.decision !== "deny" && v.decision !== "ask")) return null;
        const b = basis || "";
        if (!ROUTABLE_BASIS.has(b)) return null;
        const verdict = v.decision === "deny" ? "block" : "ask";
        const ids = [...found].filter((id) => Number.isInteger(id) && id > 0);
        const acts = ids.map((id) => [id, threatAction(id)]);
        if (acts.some(([, a]) => a === "kill") || (verdict === "block" && killOnCritical)) return null;
        const c = await context();
        if (!c.rules.length) return null;
        const facts = { threatIds: acts.filter(([, a]) => ENFORCING.has(a)).map(([id]) => id), mcpTool: mcpToolOf(tool) };
        if (b === "EGRESS_RULE") { facts.reasonCode = "EGRESS_RULE"; facts.egressRuleIds = egress ? egress.egressRuleIds : []; }
        const rule = matchRule(c.rules, verdict, facts);
        if (!rule) return null;
        const r = run(c, rule, verdict, actionHashOf(tool, ti, hash, receiptFor), facts.threatIds[0] || 0, tool, b !== "EGRESS_RULE", receiptFor);
        if (r.outcome === "allow") return { decision: "allow", reason: "", alternatives: [], rewrite: v.rewrite ?? null, reasonCode: r.reasonCode, requestId: r.requestId };
        return { decision: "deny", reason: r.reason, alternatives: [], rewrite: null, reasonCode: r.reasonCode, requestId: r.requestId };
      } catch { return null; }
    }
  };
}
