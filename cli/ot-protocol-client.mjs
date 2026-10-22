// OT protocol clients run from an agent's shell (CONTRACT-F28 §6.3): a Bash or PowerShell tool call that
// runs mbpoll / modpoll / modbus-cli, an OPC UA or BACnet command-line client, or Python / Node code that
// imports an industrial-protocol library (pymodbus, asyncua, snap7, pycomm3, BAC0, pydnp3, c104,
// modbus-serial, node-opcua, ...). The list is data/ot-protocol-clients.js.
//
// MoorAI governs the agents that can REACH controllers; it never sits inside a PLC or a safety system.
// This check names the protocol and whether the command reads or writes, and the policy decides:
//
//   otProtocol  modbus | dnp3 | opcua | s7 | bacnet | enip | iec104
//   otOp        read | write | unknown    (a write anywhere in the command wins; a library imported with
//                                          no listed call, or a tool whose arguments do not say, is unknown)
//
// ACTION. Two threat ids, because a threat carries one policy action and the contract wants read and
// unknown to alert while write can block: OT_THREAT.read (read and unknown) and OT_THREAT.write. Both
// resolve through policy.threatPolicy[id]; with no entry the action is "notify" (report, allow). The
// built-in default is not raised to block, by the repository's rule for built-in blocks (cli/hook-core.mjs
// BUILTIN_DEFAULT_ACTIONS: zero benign fires measured first); the Industrial/OT preset sets
// threatPolicy[OT_THREAT.write] = "block", which is what its approvalRouting rule "ot-shell-write"
// (match reasonCode OT_PROTOCOL_CLIENT, otOp write, holds block) holds for approval on a new agent.
// The two ids are PROPOSED (81, 82) and not yet in data/threats.json: the orchestrator assigns them.
//
// CONTENT-FREE. The alert carries the two enums, a fixed contentHash token and the threat id. Never the
// command, a host, a register, a tag, a value or a script path. The command text and any script it runs
// are read in this process only.
//
// Network side: connections into OT subnets are the egress rule `cidr` field (CONTRACT-F28 §6.1, owned by
// cli/egress-rules.mjs, rule id "ot-subnets"); this file does not judge destinations.
import { statSync, readFileSync, openSync, readSync, closeSync } from "node:fs";
import { resolve, relative, isAbsolute } from "node:path";
import { splitShell, commandOf, scanArgs, normBinary, SHELLS, PWSH, MAX_CMD, MAX_DEPTH } from "../data/shell-parse.js";
import { OT_PROTOCOLS, OT_OPS, OT_BINARIES, OT_PY_LIBS, OT_NODE_LIBS, OT_PY_MODULES, PY_INTERPRETERS, NODE_INTERPRETERS, RUNNERS } from "../data/ot-protocol-clients.js";

export { OT_PROTOCOLS, OT_OPS };
export const OT_PROTOCOL_CLIENT = "OT_PROTOCOL_CLIENT";
export const OT_THREAT = Object.freeze({ read: 81, write: 82 });
export const OT_CATEGORY = "OT protocol client run from a shell";

const ACTIONS = new Set(["notify", "justify", "block", "disabled"]);
const DECISION = { notify: "allow", justify: "ask", block: "deny" };
const ALERT_DECISION = { notify: "notify", justify: "ask", block: "deny" };
const OP_RANK = { unknown: 0, read: 1, write: 2 };
const SCRIPT_MAX_BYTES = 65536;
const SCRIPT_MAX_FILE = 1 << 20;
const SCRIPT_EXT = /\.(?:py|pyw|js|mjs|cjs|ts|mts|cts)$/i;

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const callRe = (names) => (names.length ? new RegExp(`(?<![\\w$])(?:${names.map(esc).join("|")})\\s*\\(`) : null);
const compile = (libs, importRe) => Object.entries(libs).map(([name, l]) => ({ name, protocol: l.protocol, imp: importRe(name), write: callRe(l.write || []), read: callRe(l.read || []) }));
const PY = compile(OT_PY_LIBS, (n) => new RegExp(`(?:^|[\\n;])[ \\t]*(?:import[ \\t]+[^\\n;]*(?<![\\w.])${esc(n)}(?![\\w])|from[ \\t]+${esc(n)}(?:\\.[\\w.]+)?[ \\t]+import\\b)|__import__\\(\\s*['"]${esc(n)}['".]`));
const NODE = compile(OT_NODE_LIBS, (n) => new RegExp(`(?:require|import)\\s*\\(\\s*['"\`]${esc(n)}(?:/[^'"\`]*)?['"\`]\\s*\\)|\\bfrom\\s+['"]${esc(n)}(?:/[^'"]*)?['"]`));

// Libraries a piece of code imports, each with the op its calls show.
function codeHits(code, lang, hits) {
  const text = String(code || "").slice(0, MAX_CMD);
  if (!text) return;
  for (const l of lang === "py" ? PY : NODE) {
    if (!l.imp.test(text)) continue;
    const op = l.write && l.write.test(text) ? "write" : l.read && l.read.test(text) ? "read" : "unknown";
    hits.push({ protocol: l.protocol, op, client: l.name });
  }
}

// A bounded reader for a script the command runs: inside `cwd` only, a regular file of at most 1 MiB,
// the first 64 KiB read. Returns the text or null. The hook passes scriptReader(<session cwd>).
export function scriptReader(cwd) {
  const base = resolve(String(cwd || "."));
  return (p) => {
    try {
      const raw = String(p || "");
      if (!raw || /[\0\r\n]/.test(raw)) return null;
      const full = resolve(base, raw);
      const rel = relative(base, full);
      if (!rel || rel.startsWith("..") || isAbsolute(rel)) return null;
      const st = statSync(full);
      if (!st.isFile() || st.size > SCRIPT_MAX_FILE) return null;
      const fd = openSync(full, "r");
      try {
        const buf = Buffer.alloc(Math.min(st.size, SCRIPT_MAX_BYTES));
        const n = readSync(fd, buf, 0, buf.length, 0);
        return buf.subarray(0, n).toString("utf8");
      } finally { closeSync(fd); }
    } catch { return null; }
  };
}

function scriptHits(path, lang, readScript, hits) {
  if (typeof readScript !== "function" || !path || path.includes("$")) return;
  const text = readScript(path);
  if (typeof text === "string") codeHits(text, lang, hits);
}

// mbpoll / modpoll / modbus-cli / OPC UA and BACnet tools. Native tools take POSIX-style options on every
// platform, so their arguments are scanned without the PowerShell grammar.
function binaryHit(def, binary, rest) {
  let op = def.op;
  if (op === "values-after-target") {
    const { positional } = scanArgs(rest, { shortValued: def.shortValued || "" });
    op = positional.length >= 2 ? "write" : positional.length === 1 ? "read" : "unknown";
  } else if (op === "subcommand") {
    const { positional } = scanArgs(rest, {});
    const sub = String(positional[0] || "").toLowerCase();
    op = def.write.includes(sub) ? "write" : def.read.includes(sub) ? "read" : "unknown";
  }
  return { protocol: def.protocol, op, client: binary };
}

function pyModuleHit(mod, args, hits) {
  const def = OT_PY_MODULES[mod];
  if (def) {
    let op = def.op;
    if (op === "tag-assign") {
      const { positional } = scanArgs(args, { shortValued: "atmrdp", longValued: ["--address", "--timeout", "--depth", "--multiple", "--repeat", "--route-path", "--send-path", "--priority-time-tick", "--timeout-ticks"] });
      op = positional.some((t) => t.includes("=")) ? "write" : positional.length ? "read" : "unknown";
    }
    hits.push({ protocol: def.protocol, op, client: mod.split(".")[0] });
    return;
  }
  const root = mod.split(".")[0];
  const lib = OT_PY_LIBS[root];
  if (lib) hits.push({ protocol: lib.protocol, op: "unknown", client: root });
}

function pythonHits(rest, seg, readScript, hits) {
  for (let i = 0; i < rest.length; i++) {
    const t = rest[i];
    if (t === "-c") { codeHits(rest[i + 1], "py", hits); return; }
    if (t.startsWith("-c") && t.length > 2 && !t.startsWith("--")) { codeHits(t.slice(2), "py", hits); return; }
    if (t === "-m") { if (rest[i + 1]) pyModuleHit(rest[i + 1], rest.slice(i + 2), hits); return; }
    if (t === "-W" || t === "-X") { i++; continue; }
    if (t === "-") break;
    if (t.startsWith("-")) continue;
    scriptHits(t, "py", readScript, hits);
    return;
  }
  if (seg.heredoc != null) codeHits(seg.heredoc, "py", hits);
}

function nodeHits(binary, rest, seg, readScript, hits) {
  let i = 0;
  if ((binary === "deno" || binary === "bun") && rest[0] === "run") i = 1;
  if (binary === "deno" && rest[0] === "eval") { codeHits(rest[1], "node", hits); return; }
  for (; i < rest.length; i++) {
    const t = rest[i];
    if (t === "-e" || t === "--eval" || t === "-p" || t === "--print") { codeHits(rest[i + 1], "node", hits); return; }
    if (t === "-r" || t === "--require" || t === "--import" || t === "--loader") { i++; continue; }
    if (t === "-") break;
    if (t.startsWith("-")) continue;
    scriptHits(t, "node", readScript, hits);
    return;
  }
  if (seg.heredoc != null) codeHits(seg.heredoc, "node", hits);
}

// One command word (after env assignments and wrappers) and its arguments.
function commandHits(tokens, seg, ps, depth, readScript, hits) {
  const cw = commandOf(tokens.map((t) => (/^\.{1,2}[/\\]/.test(t) ? "_" + t : t)), ps);
  if (!cw) return;
  const word = tokens[cw.at];
  const binary = cw.binary.replace(/^_/, "");
  const rest = tokens.slice(cw.at + 1);
  if (RUNNERS.includes(binary)) {
    const k = rest[0] === "run" || rest[0] === "exec" ? 1 : binary === "npx" ? 0 : -1;
    if (k >= 0 && rest.length > k) commandHits(rest.slice(k), seg, ps, depth, readScript, hits);
    return;
  }
  if (depth < MAX_DEPTH && SHELLS.has(binary)) {
    const ci = rest.findIndex((t) => /^-[a-z]*c$/.test(t));
    if (ci >= 0 && rest[ci + 1] != null) walk(rest[ci + 1], false, depth + 1, readScript, hits);
    else if (seg.heredoc != null) walk(seg.heredoc, false, depth + 1, readScript, hits);
    return;
  }
  if (depth < MAX_DEPTH && PWSH.has(binary)) {
    const ci = rest.findIndex((t) => /^-c(ommand)?$/i.test(t));
    if (ci >= 0) walk(rest.slice(ci + 1).join(" "), true, depth + 1, readScript, hits);
    return;
  }
  const def = Object.prototype.hasOwnProperty.call(OT_BINARIES, binary) ? OT_BINARIES[binary] : null;
  if (def) { hits.push(binaryHit(def, binary, rest)); return; }
  if (PY_INTERPRETERS.test(binary)) { pythonHits(rest, seg, readScript, hits); return; }
  if (NODE_INTERPRETERS.test(binary)) { nodeHits(binary, rest, seg, readScript, hits); return; }
  // A script run directly (./tool.py, ./poll.mjs): read by extension.
  const bare = String(word || "");
  if (SCRIPT_EXT.test(bare)) scriptHits(bare, /\.pyw?$/i.test(bare) ? "py" : "node", readScript, hits);
}

function walk(cmd, ps, depth, readScript, hits) {
  const parsed = splitShell(String(cmd || "").slice(0, MAX_CMD), ps, depth, { segs: [], heredocs: [] });
  for (const seg of parsed.segs || []) commandHits(seg.tokens || [], seg, ps, depth, readScript, hits);
}

// → null, or { otProtocol, otOp, client } where client names the tool or library (kept in process; it is
// not an alert field). shell: "sh" (Bash, the default) or "ps" (PowerShell). Never throws.
export function otShellFacts(command, { shell = "sh", readScript = null } = {}) {
  if (typeof command !== "string" || !command.trim()) return null;
  const hits = [];
  try { walk(command, shell === "ps", 0, readScript, hits); } catch { return null; }
  if (!hits.length) return null;
  let best = hits[0];
  for (const h of hits) if (OP_RANK[h.op] > OP_RANK[best.op]) best = h;
  return { otProtocol: best.protocol, otOp: best.op, client: best.client };
}

function actionFor(policy, id) {
  const act = policy && typeof policy === "object" && policy.threatPolicy && typeof policy.threatPolicy === "object" ? policy.threatPolicy[id] : undefined;
  if (ACTIONS.has(act)) return act;
  if (act === "mask" && ["notify", "justify", "block"].includes(policy.maskFallback)) return policy.maskFallback;
  return "notify";
}

// The hook's check for one command tool call. → null (no OT client, or the policy disabled the threat), or
// { decision: "allow"|"ask"|"deny", action, otProtocol, otOp, reason, alert }. The caller posts `alert`
// (adding ts and identity) and raises its verdict to `decision` when that ranks higher.
export function otShellCheck({ command, shell = "sh", policy = null, readScript = null, tool = "Bash" } = {}) {
  const f = otShellFacts(command, { shell, readScript });
  if (!f) return null;
  const threatId = f.otOp === "write" ? OT_THREAT.write : OT_THREAT.read;
  const action = actionFor(policy, threatId);
  if (action === "disabled") return null;
  const decision = DECISION[action];
  const what = `an OT protocol client (${f.otProtocol} ${f.otOp})`;
  const reason = decision === "deny"
    ? `blocked via ${tool} — runs ${what}; the MoorAI policy does not let agents send this to industrial equipment`
    : decision === "ask"
      ? `needs justification — runs ${what} (needs sign-off)`
      : `runs ${what}`;
  const alert = {
    threatId,
    category: OT_CATEGORY,
    riskLevel: decision === "deny" ? "Blocked" : f.otOp === "write" ? "High" : "Medium",
    stage: "prompt",
    tool: `hook:${tool}`,
    decision: ALERT_DECISION[action],
    reasonCode: OT_PROTOCOL_CLIENT,
    otProtocol: f.otProtocol,
    otOp: f.otOp,
    contentHash: `ot:${f.otProtocol}:${f.otOp}`
  };
  return { decision, action, otProtocol: f.otProtocol, otOp: f.otOp, reason, alert };
}
