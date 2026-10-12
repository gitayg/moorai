// The decisions, made by the MoorAI runtime the sidecar uses (packages/agent-sdk/src/runtime.mjs), so a
// verdict here is the verdict moorai-serve's /v1/scan and /v1/tool-call reach for the same input.
//
//   outbound  each new piece of content a request sends — prompt / system text at stage "prompt", a tool
//             result or document fed back to the model at stage "output" with ctx {inbound: true} (the
//             Agent SDK's PostToolUse scan) — through runtime.scan.
//   inbound   each tool call the model asks the agent to run, mapped to the hook's tool vocabulary (below)
//             and decided by runtime.toolCall; a function the hook has no branch for gets its argument
//             JSON content-scanned at stage "prompt" instead of being allowed unread.
//
// A request re-sends the whole conversation every turn, so each item is scanned once: an HMAC of
// (policy id, stage, text) → verdict, in a bounded LRU. A repeat is neither re-scanned nor re-reported,
// and in enforce mode a denied item stays denied. Content past the caps (more than maxItems new items in
// one request, an item longer than itemCap) is reported unevaluated; enforce mode refuses the request.
//
// Two rules on top of the hook's decision (README "Function names and wrapped arguments"):
//   policy.functionToolActions  block / ask / alert a function by its exact name (function-rules.mjs);
//                               applied before the arguments are read, the stricter verdict winning.
//   unwrapArgs                  {"function": "<name>", "arguments": {...}} (or parameters / args / input)
//                               is unwrapped before mapTool when the call does not map as sent.
import { createHmac, randomBytes } from "node:crypto";
import { REASON } from "../cli/provenance.mjs";
import { settleHeadlessAsk } from "../cli/server-mode.mjs";
import { rulesOf, functionActionFor } from "./function-rules.mjs";

export const ITEM_CAP = 524288;        // characters of one item that are scanned
export const MAX_NEW_ITEMS = 256;      // new items scanned per request
export const CACHE_SIZE = 4096;

const KNOWN = new Set(["Bash", "PowerShell", "Shell", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "Task", "Agent"]);
const SHELL_RE = /(^|[_\-.])(bash|sh|zsh|shell|terminal|exec|execute|run|run_command|command|cmd|powershell|pwsh)([_\-.]|$)/;
const EDITOR_RE = /str_replace|text_editor|edit_tool|editor/;
const str = (v) => (typeof v === "string" ? v : "");

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const WRAPPERS = new Set(["arguments", "parameters", "args", "input"]);
const NAME_KEYS = new Set(["function", "name", "tool", "tool_name"]);
// Some small models (reported for nemotron-mini) wrap a call's real arguments once more:
// {"function": "<name>", "arguments": {...}}. The wrapper is removed, up to 4 levels, only when ALL of:
//   * exactly one key is a wrapper (arguments | parameters | args | input), and its value is an object;
//   * every other key is a name key (function | name | tool | tool_name) whose value equals the tool name.
// So a tool whose real schema has an `arguments` field beside any other field, or a wrapper beside a
// different name, is left as sent. Returns `input` itself when nothing was unwrapped. Unwrapping only
// changes how the call is DECIDED; what is forwarded is always the provider's bytes.
export function unwrapArgs(name, input) {
  let cur = input;
  for (let d = 0; d < 4 && isObj(cur); d++) {
    const keys = Object.keys(cur);
    const w = keys.filter((k) => WRAPPERS.has(k));
    if (w.length !== 1 || !isObj(cur[w[0]])) break;
    if (!keys.every((k) => k === w[0] || (NAME_KEYS.has(k) && cur[k] === name))) break;
    cur = cur[w[0]];
  }
  return cur;
}

// { tool, input } in the hook's vocabulary, or null when the hook has no branch for this function. A call
// that does not map as sent is tried once more with its arguments unwrapped (unwrapArgs).
export function mapTool(name, input = {}) {
  const m = mapDirect(name, input);
  if (m) return m;
  const u = unwrapArgs(String(name || ""), input);
  return u === input ? null : mapDirect(name, u);
}

function mapDirect(name, input = {}) {
  const n = String(name || "");
  const i = input && typeof input === "object" ? input : {};
  if (KNOWN.has(n) || n.startsWith("mcp__")) return { tool: n, input: i };
  const lower = n.toLowerCase();
  const path = str(i.file_path) || str(i.path) || str(i.filename) || str(i.file);
  // Anthropic's text editor tool (name str_replace_based_edit_tool): command view | create | str_replace | insert.
  if (EDITOR_RE.test(lower) && path) {
    if (i.command === "view") return { tool: "Read", input: { file_path: path } };
    if (i.command === "create") return { tool: "Write", input: { file_path: path, content: str(i.file_text) } };
    if (i.command === "str_replace" || i.command === "insert") return { tool: "Edit", input: { file_path: path, new_string: str(i.new_str) || str(i.insert_text) } };
  }
  const cmd = Array.isArray(i.command) ? i.command.filter((x) => typeof x === "string").join(" ") : str(i.command) || (Array.isArray(i.cmd) ? i.cmd.filter((x) => typeof x === "string").join(" ") : str(i.cmd));
  // Anthropic's bash tool (name "bash", input {command}), and any shell-named function with a command.
  if (cmd && SHELL_RE.test(lower)) return { tool: /powershell|pwsh/.test(lower) ? "PowerShell" : "Bash", input: { command: cmd } };
  if (path) {
    const content = str(i.content) || str(i.contents) || str(i.text) || str(i.file_text);
    if (content && /write|create|save|put|append/.test(lower)) return { tool: "Write", input: { file_path: path, content } };
    if (/read|view|open|cat|load|get_file/.test(lower)) return { tool: "Read", input: { file_path: path } };
  }
  if (str(i.url) && /fetch|http|browse|web|url|download/.test(lower)) return { tool: "WebFetch", input: { url: str(i.url), prompt: str(i.prompt) } };
  return null;
}

export function createChecker(rt, { enforce, cwd, onUnevaluated, maxItems = MAX_NEW_ITEMS, itemCap = ITEM_CAP }) {
  const cache = new Map();
  const remember = (k, v) => { cache.delete(k); cache.set(k, v); if (cache.size > CACHE_SIZE) cache.delete(cache.keys().next().value); return v; };
  const settle = enforce;
  // The cache key is this process's own HMAC, not the runtime's content hash: that one is a constant when
  // the device is not enrolled (cli/content-hash.mjs: no install token → NO_KEY), which would make every
  // item a cache hit of the first. Full digest, random per-process key; it never leaves the process.
  const cacheKey = randomBytes(32);
  const keyOf = (s) => createHmac("sha256", cacheKey).update(s, "utf8").digest("base64");

  async function checkRequest(items) {
    const s = await rt.ready();
    const denied = [];
    let fresh = 0, skipped = 0;
    for (const it of items) {
      const key = keyOf(`${s.policyId}\0${it.stage}\0${it.text}`);
      let v = cache.get(key);
      if (v) remember(key, v);
      else {
        if (fresh >= maxItems) { skipped++; continue; }
        fresh++;
        if (it.text.length > itemCap) {
          onUnevaluated(it.kind, "request");
          // Enforce does not forward what it did not read. Chunk-scanning instead is not bounded: ≈100 ms of
          // blocked event loop per 512 K characters (measured), ≈6 s for a 32 MB body.
          if (enforce) { denied.push({ kind: it.kind, reasons: [`not evaluated: over the ${itemCap}-character scan cap`] }); continue; }
        }
        const r = await rt.scan(it.text.slice(0, itemCap), it.stage, it.ctx, { tool: it.kind, event: "ModelRequest", settle });
        v = remember(key, { decision: r.decision, reasons: r.reasons });
      }
      if (v.decision === "deny") denied.push({ kind: it.kind, reasons: v.reasons });
    }
    if (skipped) {
      onUnevaluated("request", "request");
      if (enforce) denied.push({ kind: "request", reasons: [`not evaluated: more than ${maxItems} new items`] });
    }
    return { decision: denied.length ? "deny" : "allow", denied };
  }

  // policy.functionToolActions for this call's name: null (no rule, or "alert", which is reported here),
  // or the verdict the rule alone reaches — "deny" for block, and for ask once server mode's headless rule
  // has settled it (enforce); report mode passes the ask through as configured, like every other ask.
  // Content-free: the alert names the function and the rule kind, never an argument.
  async function nameRule(name) {
    const s = await rt.ready();
    const act = functionActionFor(rulesOf(s.policy), name);
    if (!act) return null;
    const label = String(name).replace(/[^A-Za-z0-9_.:\-]/g, "_").slice(0, 64);
    const prov = { prov: { policyId: s.policyId, policySource: s.source, event: "PreToolUse" } };
    const base = { threatId: 0, stage: "tool", tool: `model-proxy:${label}`, contentHash: rt.hash(`function-rule:${act}:${name}`) };
    if (act === "alert") {
      rt.reporter.post({ ...base, category: "Model proxy: function reported by name (functionToolActions)", riskLevel: "Medium", decision: "notify", reasonCode: REASON.OBSERVATION_ONLY }, prov);
      return null;
    }
    if (act === "block") {
      rt.reporter.post({ ...base, category: "Model proxy: function denied by name (functionToolActions)", riskLevel: "Blocked", decision: "deny" }, prov);
      return { decision: "deny", reasons: [`function ${label} blocked by policy (functionToolActions)`] };
    }
    rt.reporter.post({ ...base, category: "Model proxy: function requires approval by name (functionToolActions)", riskLevel: "High", decision: "ask" }, prov);
    const reason = `needs justification function ${label} requires approval (functionToolActions)`;
    if (rt.settings.passThrough) return { decision: "ask", reasons: [reason.replace(/^needs justification /, "")] };
    const h = settleHeadlessAsk({ active: true, headless: rt.settings.headless }, s.policy, { decision: "ask", reason, tool: label });
    if (h.alert) rt.reporter.post({ ...h.alert, tool: `model-proxy:${label}`, reasonCode: REASON.HEADLESS_ASK, enforcement: h.decision === "deny" ? "STRENGTHENED" : "LIMITED" }, prov);
    return { decision: h.decision, reasons: [h.reason] };
  }

  async function checkOne(c) {
    const named = await nameRule(c.name);
    if (named && named.decision === "deny") return named;
    const v = await checkArgs(c);
    return named && named.decision === "ask" && v.decision !== "deny" ? named : v;
  }

  async function checkArgs(c) {
    if (c.over) {
      onUnevaluated(c.name, "response");
      return enforce ? { decision: "deny", reasons: ["tool call arguments exceed the scan cap"] } : { decision: "allow", reasons: [] };
    }
    const m = c.raw == null ? mapTool(c.name, c.input) : null;
    if (m) {
      const v = await rt.toolCall({ tool: m.tool, input: m.input, cwd });
      return { decision: v.decision, reasons: v.reasons };
    }
    const text = c.raw != null ? c.raw : JSON.stringify(c.input);
    // Past the scan cap only a prefix would be read: reported unevaluated, and enforce refuses it, as the
    // request side does.
    if (text.length > itemCap) {
      onUnevaluated(c.name || "function", "response");
      if (enforce) return { decision: "deny", reasons: [`not evaluated: over the ${itemCap}-character scan cap`] };
    }
    const v = await rt.scan(text.slice(0, itemCap), "prompt", {}, { tool: c.name || "function", event: "PreToolUse", settle });
    // Arguments that are not a JSON object never reached the tool decision (hook branch, workload profile),
    // and an SDK may still parse them leniently and run the call. Enforce refuses them; report mode keeps
    // the content scan above.
    if (enforce && c.raw != null && v.decision !== "deny") return { decision: "deny", reasons: [c.rawReason || "tool call arguments are not a valid JSON object"] };
    return { decision: v.decision, reasons: v.reasons };
  }

  async function checkToolCalls(calls) {
    const denied = [];
    for (const c of calls) {
      const v = await checkOne(c);
      if (v.decision === "deny") denied.push({ name: c.name, reasons: v.reasons });
    }
    return { decision: denied.length ? "deny" : "allow", denied };
  }

  // Report-only scan of the model's own output text (Ollama /api/generate `response`): never settled, never
  // a verdict the caller acts on; filed as a PostToolUse observation, so a deny-level finding is stamped
  // enforcement LIMITED. Past the scan cap only the prefix is read, and the rest is reported unevaluated.
  async function observe(items) {
    for (const it of items) {
      if (it.text.length > itemCap) onUnevaluated(it.kind, "response");
      await rt.scan(it.text.slice(0, itemCap), it.stage, it.ctx, { tool: it.kind, event: "PostToolUse", settle: false });
    }
  }

  return { checkRequest, checkToolCalls, observe, cacheSize: () => cache.size };
}
