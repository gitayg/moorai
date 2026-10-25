// The decisions, made by the MoorAI runtime the sidecar uses (packages/agent-sdk/src/runtime.mjs), so a
// verdict here is the verdict moorai-serve's /v1/scan and /v1/tool-call reach for the same input.
//
//   outbound  each new piece of content a request sends — prompt / system text at stage "prompt" (operator
//             context, `context: true`, is judged the same way unless the verified signed policy or the
//             admin binding opts in to report its PII-class findings at stage "context": context.mjs), a tool
//             result or document fed back to the model at stage "output" with ctx {inbound: true} (the
//             Agent SDK's PostToolUse scan) — through runtime.scan.
//   inbound   each tool call the model asks the agent to run, mapped to the hook's tool vocabulary (below)
//             and decided by runtime.toolCall; a function the hook has no branch for gets its argument
//             JSON content-scanned at stage "prompt" instead of being allowed unread.
//
// A request re-sends the whole conversation every turn, so each item is scanned once: an HMAC of
// (policy id, stage, text) → verdict, in a bounded LRU. A repeat is neither re-scanned nor re-reported,
// and in enforce mode a denied item stays denied. Content past the caps (more than maxItems new items in
// one request, an item longer than itemCap) is reported unevaluated, and refused when the fail mode is closed
// (failClosed: enforce mode's default; cli/fail-mode.mjs decides, server.mjs asks).
//
// Two rules on top of the hook's decision (README "Function names and wrapped arguments"):
//   policy.functionToolActions  block / ask / alert a function by its exact name (function-rules.mjs);
//                               applied before the arguments are read, the stricter verdict winning.
//   businessToolActions         a function with no functionToolActions key of its own is classed by name
//                               (money, bulk-data, identity, destructive, delegation: business-tools.mjs);
//                               built-in action alert, raised or silenced per class by the policy.
//   intent alignment            a call that maps to a hook tool and is not denied is judged against the
//                               person's task (intent.mjs, passed in by server.mjs) on EVERY reading below
//                               that maps (the as-sent mapping, a `cmd` alias read as `command`, the tool a
//                               dispatcher names inside its arguments …), each with its own findings; the
//                               strictest verdict replaces this one (an ask or a deny, in --mode enforce only).
//   unwrapArgs                  {"function": "<name>", "arguments": {...}} (or parameters / args / input)
//                               is unwrapped before mapTool when the call does not map as sent.
//   readings                    every other way a client could read the same call (an object, or a JSON
//                               object string, under a wrapper key; a name key; an alias key such as `cmd`
//                               beside `command`, also on a hook tool's own name; a normalized name) is
//                               decided too, and the strictest verdict wins. The call has ONE canonical
//                               reading or none: two readings with different decision fields, or a reading
//                               that is not strict JSON, are refused as ambiguous in enforce and replace
//                               mode and reported UNEVALUATED_BAD_INPUT in report mode (README "Parser
//                               differentials").
import { createHmac, randomBytes } from "node:crypto";
import { REASON } from "../cli/provenance.mjs";
import { settleHeadlessAsk } from "../cli/server-mode.mjs";
import { rulesOf, functionActionFor, specificActionFor, normalizeName, foldName, ACTION_RANK } from "./function-rules.mjs";
import { businessActionFor } from "./business-tools.mjs";
import { parseArgs } from "./json-strict.mjs";
import { scanContext } from "./context.mjs";

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

// ---- readings: what a client other than this checker could take the call to be ----
// A client may read a wrapped object instead of the top-level fields (or the reverse), dispatch on a name key
// inside the arguments, take `cmd` where this checker takes `command`, or resolve a name in another case or
// with padding. Each reading that maps to a hook call is decided; nothing here ever loosens a verdict.
const KNOWN_FOLDED = new Map([...KNOWN].map((k) => [k.toLowerCase(), k]));
const ALIASES = [["command", "cmd"], ["file_path", "path", "filename", "file"], ["content", "contents", "text", "file_text"], ["new_str", "insert_text"]];
const MAX_LAYERS = 16, MAX_VARIANTS = 16;
const aliasVal = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string").join(" ") : str(v));
// The names a client could resolve `name` to: as sent, normalizeName's form, and a hook tool name in
// another case as the hook's own.
function namesOf(name) {
  const raw = String(name || ""), n = normalizeName(raw);
  return [...new Set([raw, n, KNOWN_FOLDED.get(n.toLowerCase()) || n])].filter(Boolean);
}
// The argument object with each set of alias keys that disagree narrowed to one of them, every way.
function variants(i) {
  let out = [i];
  for (const g of ALIASES) {
    const present = g.filter((k) => aliasVal(i[k]));
    if (new Set(present.map((k) => aliasVal(i[k]))).size < 2) continue;
    out = out.flatMap((v) => present.map((k) => { const c = { ...v }; for (const o of present) if (o !== k) delete c[o]; return c; }));
  }
  return out;
}
const identityTool = (n) => KNOWN.has(n) || n.startsWith("mcp__");
// A hook tool's own input read the way a client that declared the alias would: an alias the hook does not
// read (`cmd`, `path`, `text` …) under the hook's key, when the hook's key is empty. `Bash {"cmd": …}` has a
// command to decide.
const HOOK_KEYS = [["command", "cmd"], ["file_path", "path", "filename", "file"], ["content", "contents", "text", "file_text"]];
function canonical(v) {
  let c = v;
  for (const [k, ...alts] of HOOK_KEYS) {
    if (aliasVal(c[k])) continue;
    const a = alts.find((x) => aliasVal(c[x]));
    if (a) c = { ...c, [k]: aliasVal(c[a]) };
  }
  return c;
}
// What a hook call is decided on, per hook tool: two readings with different decision fields are two
// different calls. An MCP tool's input goes to its server whole (no client reading of its own), so its
// readings are decided but never make a call ambiguous. null when the reading has no decision field.
const FIELDS = { Bash: ["command"], PowerShell: ["command"], Shell: ["command"], Read: ["file_path"], Write: ["file_path", "content"], Edit: ["file_path", "new_string"], MultiEdit: ["file_path"], NotebookEdit: ["notebook_path"], WebFetch: ["url"], Task: ["prompt"], Agent: ["prompt"] };
function decisionKey(m) {
  if (!m || m.tool.startsWith("mcp__")) return null;
  const f = FIELDS[m.tool];
  if (!f) return `${m.tool}\0${JSON.stringify(m.input)}`;
  const vals = f.map((k) => aliasVal(m.input[k]));
  return vals.some(Boolean) ? `${m.tool}\0${vals.join("\0")}` : null;
}
function mapping(name, input) {
  const m = mapDirect(name, input);
  return m && { ...m, identity: identityTool(String(name || "")) };
}
const sameMap = (a, b) => a.tool === b.tool && a.identity === b.identity && (a.identity ? a.input === b.input
  : Object.keys(a.input).length === Object.keys(b.input).length && Object.keys(a.input).every((k) => a.input[k] === b.input[k]));
// { maps, innerNames, overflow, problem, ambiguous }: the distinct hook calls the call's readings map to;
// the names found in name keys at any level (a dispatcher could run that function instead: beside an
// object, beside a JSON string of arguments, or with no arguments at all); overflow when there were more
// readings than are examined; problem when a wrapper's JSON string is not strict JSON (json-strict.mjs);
// ambiguous when any of those, or two readings with different decision fields (decisionKey).
export function readings(name, input) {
  const layers = [], innerNames = new Set();
  let overflow = false, problem = false;
  const walk = (obj, names, depth) => {
    if (!isObj(obj)) return;
    if (layers.length >= MAX_LAYERS) { overflow = true; return; }
    layers.push({ obj, names });
    const inner = [...names];
    for (const k of NAME_KEYS) if (typeof obj[k] === "string" && obj[k]) { innerNames.add(obj[k]); inner.push(...namesOf(obj[k])); }
    // A wrapper holding a JSON object as a string (OpenAI-style `arguments`) is a wrapped object too.
    const wrapped = [];
    for (const w of WRAPPERS) {
      const v = obj[w];
      if (isObj(v)) wrapped.push(v);
      else if (typeof v === "string" && /^\s*\{/.test(v)) {
        const r = parseArgs(v);
        if (r.ok) wrapped.push(r.value);
        else if (r.problem !== "not-json") problem = true;
      }
    }
    if (!wrapped.length) return;
    if (depth >= 4) { overflow = true; return; }
    for (const w of wrapped) walk(w, [...new Set(inner)], depth + 1);
  };
  walk(unwrapArgs(String(name || ""), input), namesOf(name), 0);
  const maps = [];
  for (const { obj, names } of layers) {
    const vs = variants(obj);
    if (vs.length > MAX_VARIANTS) overflow = true;
    for (const nm of names) {
      const list = nm.startsWith("mcp__") ? [obj] : KNOWN.has(nm) ? [obj, ...vs.slice(0, MAX_VARIANTS).map(canonical)] : vs.slice(0, MAX_VARIANTS);
      for (const v of list) {
        const m = mapping(nm, v);
        if (m && !maps.some((x) => sameMap(x, m))) maps.push(m);
      }
    }
  }
  const keys = new Set(maps.map(decisionKey).filter(Boolean));
  return { maps, innerNames: [...innerNames], overflow, problem, ambiguous: overflow || problem || keys.size > 1 };
}
const RANK = { allow: 0, ask: 1, deny: 2 };
// A user turn is prose: it runs nothing itself, and what the model runs because of it comes back as a tool call
// (checkToolCalls). Detectors that judge a command about to run read ctx.prose (#43, data/destructive-mention.js).
// A system turn (operator or injected context), a tool result and a tool call's arguments are never marked.
const PROSE_KINDS = new Set(["prompt"]);
const proseItem = (it) => (PROSE_KINDS.has(it.kind) ? { ...it, ctx: { ...it.ctx, prose: true } } : it);
const AMBIGUOUS = "tool call arguments can be read more than one way (a wrapped, repeated or alias field disagrees), so a client may run something other than what was checked";

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
  // `command` that is empty (an empty array, or one with no string) does not hide `cmd`: the same notion of
  // "present" as the alias readings (aliasVal).
  const cmd = aliasVal(i.command) || aliasVal(i.cmd);
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

// failClosed(policy): whether content this checker cannot judge (an item past the scan cap, more new items than
// one request scans, tool-call arguments past the cap) is refused — server.mjs asks cli/fail-mode.mjs. The
// default is enforce mode's own behaviour.
// contextPrivacy(state): "report" when operator context's PII-class findings are report-only, else "enforce"
// (the default) — server.mjs asks context.mjs operatorContextMode with the runtime's policy, its source and
// the admin binding.
export function createChecker(rt, { enforce, cwd, onUnevaluated, maxItems = MAX_NEW_ITEMS, itemCap = ITEM_CAP, failClosed = () => enforce, contextPrivacy = () => "enforce" }) {
  const cache = new Map();
  const remember = (k, v) => { cache.delete(k); cache.set(k, v); if (cache.size > CACHE_SIZE) cache.delete(cache.keys().next().value); return v; };
  const settle = enforce;
  // The cache key is this process's own HMAC, not the runtime's content hash: that one is a constant when
  // the device is not enrolled (cli/content-hash.mjs: no install token → NO_KEY), which would make every
  // item a cache hit of the first. Full digest, random per-process key; it never leaves the process.
  const cacheKey = randomBytes(32);
  const keyOf = (s) => createHmac("sha256", cacheKey).update(s, "utf8").digest("base64");
  const reportContext = (s, it) => Boolean(it.context) && contextPrivacy(s) === "report";
  const itemKey = (s, it) => keyOf(`${s.policyId}\0${it.stage}${reportContext(s, it) ? ":context" : ""}\0${it.text}`);

  async function checkRequest(items) {
    const s = await rt.ready();
    const closed = failClosed(s.policy);
    const denied = [];
    let fresh = 0, skipped = 0;
    for (const it of items) {
      // Operator context under the report opt-in is its own key: the same text in a user turn is the user's,
      // and judged as such.
      const key = itemKey(s, it);
      let v = cache.get(key);
      if (v) remember(key, v);
      else {
        if (fresh >= maxItems) { skipped++; continue; }
        fresh++;
        if (it.text.length > itemCap) {
          onUnevaluated(it.kind, "request");
          // Enforce does not forward what it did not read. Chunk-scanning instead is not bounded: ≈100 ms of
          // blocked event loop per 512 K characters (measured), ≈6 s for a 32 MB body.
          if (closed) { denied.push({ kind: it.kind, reasons: [`not evaluated: over the ${itemCap}-character scan cap`] }); continue; }
        }
        const pi = proseItem(it);
        const r = reportContext(s, it) ? await scanContext(rt, pi, it.text.slice(0, itemCap), { settle }) : await rt.scan(it.text.slice(0, itemCap), it.stage, pi.ctx, { tool: it.kind, event: "ModelRequest", settle });
        v = remember(key, { decision: r.decision, reasons: r.reasons });
      }
      if (v.decision === "deny") denied.push({ kind: it.kind, reasons: v.reasons });
    }
    if (skipped) {
      onUnevaluated("request", "request");
      if (closed) denied.push({ kind: "request", reasons: [`not evaluated: more than ${maxItems} new items`] });
    }
    return { decision: denied.length ? "deny" : "allow", denied };
  }

  // What checkRequest could not judge, found without scanning anything (lengths and the cache only): for report
  // mode under a closed fail mode, which must refuse before forwarding while its scans run after the response.
  async function unjudged(items) {
    const s = await rt.ready();
    const denied = [];
    let fresh = 0, skipped = 0;
    for (const it of items) {
      if (cache.has(itemKey(s, it))) continue;
      if (fresh >= maxItems) { skipped++; continue; }
      fresh++;
      if (it.text.length > itemCap) { onUnevaluated(it.kind, "request"); denied.push({ kind: it.kind, reasons: [`not evaluated: over the ${itemCap}-character scan cap`] }); }
    }
    if (skipped) { onUnevaluated("request", "request"); denied.push({ kind: "request", reasons: [`not evaluated: more than ${maxItems} new items`] }); }
    return denied;
  }
  const closedNow = async () => failClosed((await rt.ready()).policy);

  // policy.functionToolActions for this call's name, or its business-impact class (business-tools.mjs) when no
  // key names the function itself: null (no rule, or "alert", which is reported here), or the verdict the rule
  // alone reaches — "deny" for block, and for ask once server mode's headless rule has settled it (enforce);
  // report mode passes the ask through as configured, like every other ask. A namespace-only wildcard and a
  // class combine, the stricter winning. Content-free: the alert names the function, the rule kind and the
  // class, never an argument.
  async function nameRule(name) {
    const s = await rt.ready();
    const fn = functionActionFor(rulesOf(s.policy), name);
    const biz = specificActionFor(s.policy, name) ? null : businessActionFor(s.policy, name);
    const byClass = Boolean(biz) && biz.act !== "allow" && (!fn || ACTION_RANK[biz.act] >= ACTION_RANK[fn]);
    const act = byClass ? biz.act : fn;
    if (!act || act === "allow") return null;
    const label = String(name).replace(/[^A-Za-z0-9_.:\-]/g, "_").slice(0, 64);
    const why = byClass ? `businessToolActions: ${biz.cls}` : "functionToolActions";
    const kind = (verb) => (byClass ? `Model proxy: business-impact function ${verb} (${biz.cls})` : `Model proxy: function ${verb} by name (functionToolActions)`);
    const prov = { prov: { policyId: s.policyId, policySource: s.source, event: "PreToolUse" } };
    const base = { threatId: 0, stage: "tool", tool: `model-proxy:${label}`, contentHash: rt.hash(byClass ? `business-tool:${biz.cls}:${act}:${name}` : `function-rule:${act}:${name}`),
      ...(byClass ? { businessClass: biz.cls, functionName: foldName(name).replace(/[^a-z0-9_.:\-]/g, "_").slice(0, 64) } : {}) };
    if (act === "alert") {
      rt.reporter.post({ ...base, category: kind("reported"), riskLevel: "Medium", decision: "notify", reasonCode: REASON.OBSERVATION_ONLY }, prov);
      return null;
    }
    if (act === "block") {
      rt.reporter.post({ ...base, category: kind("denied"), riskLevel: "Blocked", decision: "deny" }, prov);
      return { decision: "deny", reasons: [`function ${label} blocked by policy (${why})`] };
    }
    rt.reporter.post({ ...base, category: byClass ? kind("requires approval") : "Model proxy: function requires approval by name (functionToolActions)", riskLevel: "High", decision: "ask" }, prov);
    const reason = `needs justification function ${label} requires approval (${why})`;
    if (rt.settings.passThrough) return { decision: "ask", reasons: [reason.replace(/^needs justification /, "")] };
    const h = settleHeadlessAsk({ active: true, headless: rt.settings.headless }, s.policy, { decision: "ask", reason, tool: label });
    if (h.alert) rt.reporter.post({ ...h.alert, tool: `model-proxy:${label}`, reasonCode: REASON.HEADLESS_ASK, enforcement: h.decision === "deny" ? "STRENGTHENED" : "LIMITED" }, prov);
    return { decision: h.decision, reasons: [h.reason] };
  }

  // The function-name rule runs on the name the model sent and on every name a dispatcher could take from
  // the arguments (readings.innerNames); a deny on any of them denies the call.
  // intent(tool, input, findings, name, verdict): intent alignment (intent.mjs), for a call that maps to a hook
  // tool and is not already denied; a verdict it returns replaces this one.
  // bound(name, input, verdict): the task-bound checks (intent.mjs judgeBound) on the call as the model sent it,
  // after intent alignment and not on a deny; a stricter (or equally strict, with more reasons) verdict replaces it.
  async function checkOne(c, intent, bound) {
    const rd = c.raw == null && !c.over ? readings(c.name, c.input) : null;
    const names = [c.name];
    for (const n of rd ? rd.innerNames : []) if (!names.some((x) => foldName(x) === foldName(n))) names.push(n);
    let ask = null;
    for (const n of names) {
      const named = await nameRule(n);
      if (named && named.decision === "deny") return named;
      if (named && named.decision === "ask" && !ask) ask = named;
    }
    const v = await checkArgs(c, rd);
    const out = ask && v.decision !== "deny" ? ask : v;
    if ((!intent && !bound) || out.decision === "deny" || c.raw != null || c.over) return out;
    // Every reading that maps to a hook tool, each with the findings its own decision produced; the strictest
    // intent verdict wins (deny over ask over none).
    let best = null;
    if (intent) for (const j of v.judged || []) {
      const iv = await intent(j.tool, j.input, j.findings, c.name, out);
      if (iv && RANK[iv.decision] > RANK[best ? best.decision : "allow"]) best = iv;
      if (best && best.decision === "deny") break;
    }
    const cur = best || out;
    if (!bound || cur.decision === "deny") return cur;
    const bv = await bound(c.name, c.input, cur);
    return bv && RANK[bv.decision] >= RANK[cur.decision] ? bv : cur;
  }

  const decideMapped = async (m) => { const v = await rt.toolCall({ tool: m.tool, input: m.input, cwd }); return { decision: v.decision, reasons: v.reasons, findings: v.findings || [] }; };

  async function checkArgs(c, rd) {
    if (c.over) {
      onUnevaluated(c.name, "response");
      return (await closedNow()) ? { decision: "deny", reasons: ["tool call arguments exceed the scan cap"] } : { decision: "allow", reasons: [] };
    }
    const mt = c.raw == null ? mapTool(c.name, c.input) : null;
    const m = mt && { ...mt, identity: identityTool(String(c.name || "")) && mt.tool === String(c.name || "") };
    const alts = rd ? rd.maps.filter((a) => !(m && sameMap(a, m))) : [];
    // No one canonical reading (two readings with different decision fields, a wrapped JSON string that is
    // not strict JSON, more readings than are examined): the client could run either, so enforce (and
    // replace, which is enforce) runs neither; report mode reports it and decides every reading below.
    if (rd && (rd.ambiguous || new Set([m, ...alts].map(decisionKey).filter(Boolean)).size > 1)) {
      if (enforce) return { decision: "deny", reasons: [AMBIGUOUS] };
      onUnevaluated("tool-call-ambiguous", "response", "input");
    }
    let out = m ? await decideMapped(m) : await scanArgs(c);
    if (out.decision === "deny") return out;
    // judged: each mapped reading and the findings of its own decision, for intent alignment (checkOne).
    const judged = m ? [{ tool: m.tool, input: m.input, findings: out.findings || [] }] : [];
    for (const a of alts) {
      const v = await decideMapped(a);
      if (v.decision === "deny") return v;
      judged.push({ tool: a.tool, input: a.input, findings: v.findings });
      if (out.decision === "allow" && v.decision !== "allow") out = v;
    }
    return { ...out, judged };
  }

  async function scanArgs(c) {
    // JSON.stringify rounds a number past 2^53; the digits as sent (`numbers`: json-strict.mjs `large`, from
    // the argument string and from the response) are scanned with it, one per line (a digit-run pattern never
    // joins two of them), so a digit run is matched as sent.
    const text = c.raw != null ? c.raw : Array.isArray(c.numbers) && c.numbers.length ? `${JSON.stringify(c.input)}\n${c.numbers.join("\n")}` : JSON.stringify(c.input);
    // Past the scan cap only a prefix would be read: reported unevaluated, and enforce refuses it, as the
    // request side does.
    if (text.length > itemCap) {
      onUnevaluated(c.name || "function", "response");
      if (await closedNow()) return { decision: "deny", reasons: [`not evaluated: over the ${itemCap}-character scan cap`] };
    }
    const v = await rt.scan(text.slice(0, itemCap), "prompt", {}, { tool: c.name || "function", event: "PreToolUse", settle });
    // Arguments that are not a JSON object never reached the tool decision (hook branch, workload profile),
    // and an SDK may still parse them leniently and run the call. Enforce refuses them; report mode keeps
    // the content scan above.
    if (enforce && c.raw != null && v.decision !== "deny") return { decision: "deny", reasons: [c.rawReason || "tool call arguments are not a valid JSON object"] };
    if (!enforce && c.raw != null) onUnevaluated("tool-call-arguments", "response", "input");
    return { decision: v.decision, reasons: v.reasons };
  }

  async function checkToolCalls(calls, { intent, bound } = {}) {
    const denied = [];
    for (const c of calls) {
      const v = await checkOne(c, intent, bound);
      if (v.decision === "deny") denied.push({ name: c.name, reasons: v.reasons });
    }
    return { decision: denied.length ? "deny" : "allow", denied };
  }

  // Report-only scan of the model's own output text (Ollama /api/generate `response`): never settled, never
  // a verdict the caller acts on; filed as a PostToolUse observation, so a deny-level finding is stamped
  // enforcement LIMITED. Past the scan cap only the prefix is read, and the rest is reported unevaluated.
  async function observe(items) {
    for (const it of items) {
      if (it.text.length > itemCap || it.over) onUnevaluated(it.kind, "response");
      await rt.scan(it.text.slice(0, itemCap), it.stage, it.ctx, { tool: it.kind, event: "PostToolUse", settle: false });
    }
  }

  return { checkRequest, unjudged, checkToolCalls, observe, cacheSize: () => cache.size };
}
