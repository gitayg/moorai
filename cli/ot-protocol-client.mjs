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
// resolve through cli/hook-core.mjs threatActionFor, like every other threat (threatPolicy, tierPolicy,
// the mask fallback, then the built-in table); with no entry the action is "notify" (report, allow).
// "kill" denies the call and asks the host to end the session. A value that is not an action
// (a typo in a hand-edited policy) fails closed to "block". The built-in default is not raised to block, by the repository's rule for built-in blocks (cli/hook-core.mjs
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
import { statSync, openSync, readSync, closeSync } from "node:fs";
import { resolve, relative, isAbsolute } from "node:path";
import { splitShell, commandOf, scanArgs, normBinary, SHELLS, PWSH, MAX_CMD, MAX_DEPTH } from "../data/shell-parse.js";
import { OT_PROTOCOLS, OT_OPS, OT_BINARIES, OT_PY_LIBS, OT_NODE_LIBS, OT_PY_MODULES, PY_INTERPRETERS, NODE_INTERPRETERS, RUNNERS } from "../data/ot-protocol-clients.js";
import { threatActionFor } from "./hook-core.mjs";

export { OT_PROTOCOLS, OT_OPS };
export const OT_PROTOCOL_CLIENT = "OT_PROTOCOL_CLIENT";
export const OT_THREAT = Object.freeze({ read: 81, write: 82 });
export const OT_CATEGORY = "OT protocol client run from a shell";

const ACTION_RANK = { disabled: 0, notify: 1, justify: 2, block: 3, kill: 4 };
const DECISION = { notify: "allow", justify: "ask", block: "deny", kill: "deny" };
const ALERT_DECISION = { notify: "notify", justify: "ask", block: "deny", kill: "deny" };
const OP_RANK = { unknown: 0, read: 1, write: 2 };
// A script is read whole up to SCRIPT_MAX_BYTES. A larger one is never treated as clean: up to
// SCRIPT_SCAN_MAX it is streamed for the library names alone (each named library is an "unknown" hit,
// marked incomplete so the verdict takes the stricter of the read and write actions).
const SCRIPT_MAX_BYTES = 8 << 20;
const SCRIPT_SCAN_MAX = 256 << 20;
const SCAN_CHUNK = 1 << 20;
const LIB_NAMES = [...new Set([...Object.keys(OT_PY_LIBS), ...Object.keys(OT_NODE_LIBS)])];
const NAME_OVERLAP = Math.max(...LIB_NAMES.map((n) => n.length));
const SCRIPT_EXT = /\.(?:py|pyw|js|mjs|cjs|ts|mts|cts)$/i;

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const callRe = (names) => (names.length ? new RegExp(`(?<![\\w$])(?:${names.map(esc).join("|")})\\s*\\(`) : null);
const compile = (libs, importRe) => Object.entries(libs).map(([name, l]) => ({ name, protocol: l.protocol, imp: importRe(name), write: callRe(l.write || []), read: callRe(l.read || []) }));
const PY = compile(OT_PY_LIBS, (n) => new RegExp(`(?:^|[\\n;])[ \\t]*(?:import[ \\t]+[^\\n;]*(?<![\\w.])${esc(n)}(?![\\w])|from[ \\t]+${esc(n)}(?:\\.[\\w.]+)?[ \\t]+import\\b)|__import__\\(\\s*['"]${esc(n)}['".]`));
const NODE = compile(OT_NODE_LIBS, (n) => new RegExp(`(?:require|import)\\s*\\(\\s*['"\`]${esc(n)}(?:/[^'"\`]*)?['"\`]\\s*\\)|\\bfrom\\s+['"]${esc(n)}(?:/[^'"]*)?['"]`));

// Libraries a piece of code imports, each with the op its calls show.
function codeHits(code, lang, hits, max = MAX_CMD) {
  const text = String(code || "").slice(0, max);
  if (!text) return;
  for (const l of lang === "py" ? PY : NODE) {
    if (!l.imp.test(text)) continue;
    const op = l.write && l.write.test(text) ? "write" : l.read && l.read.test(text) ? "read" : "unknown";
    hits.push({ protocol: l.protocol, op, client: l.name });
  }
}

// Library names written anywhere in a file too large to read whole, streamed in chunks that overlap by
// the longest name. → the names found, and whether the file ran past SCRIPT_SCAN_MAX.
function streamNames(fd, size) {
  const found = new Set();
  const buf = Buffer.alloc(SCAN_CHUNK + NAME_OVERLAP);
  let carry = "", pos = 0;
  while (pos < size && pos < SCRIPT_SCAN_MAX) {
    const n = readSync(fd, buf, 0, SCAN_CHUNK, pos);
    if (n <= 0) break;
    pos += n;
    const text = carry + buf.subarray(0, n).toString("latin1");
    for (const name of LIB_NAMES) if (!found.has(name) && text.includes(name)) found.add(name);
    carry = text.slice(-NAME_OVERLAP);
  }
  return { names: [...found], beyond: pos < size };
}

// A bounded reader for a script the command runs: inside `cwd` only, a regular file. → null (not read),
// the whole text (at most SCRIPT_MAX_BYTES), or for a larger file { truncated: true, names } (the
// library names streamed from it). The hook passes scriptReader(<session cwd>).
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
      if (!st.isFile()) return null;
      const fd = openSync(full, "r");
      try {
        if (st.size > SCRIPT_MAX_BYTES) return { truncated: true, ...streamNames(fd, st.size) };
        const buf = Buffer.alloc(st.size);
        let n = 0;
        while (n < buf.length) { const k = readSync(fd, buf, n, buf.length - n, n); if (k <= 0) break; n += k; }
        return buf.subarray(0, n).toString("utf8");
      } finally { closeSync(fd); }
    } catch { return null; }
  };
}

function scriptHits(path, lang, readScript, hits) {
  if (typeof readScript !== "function" || !path || path.includes("$")) return;
  const got = readScript(path);
  if (typeof got === "string") { codeHits(got, lang, hits, SCRIPT_MAX_BYTES); return; }
  if (!got || !got.truncated) return;
  const libs = lang === "py" ? OT_PY_LIBS : OT_NODE_LIBS;
  for (const name of got.names || []) {
    if (!Object.prototype.hasOwnProperty.call(libs, name)) continue;
    hits.push({ protocol: libs[name].protocol, op: "unknown", client: name });
    hits.incomplete = true;
  }
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

// CPython's options, read character by character as getopt does: `-Ic code`, `-Im mod`, `-Wignore`.
const PY_NOARG = new Set([..."bBdEhiIOPqRsSuvVx?"]);
const PY_LONG_NOARG = new Set(["--version", "--help", "--help-env", "--help-xoptions", "--help-all"]);
const PY_LONG_VALUED = new Set(["--check-hash-based-pycs"]);
const PY_LAUNCHER_VERSION = /^-(?:\d+(?:\.\d+)?)?(?:-(?:32|64|arm64))?$/;

// Arguments the parser cannot read fail closed: every argument is scanned as code, as a module name and
// as a script path.
function pythonFallback(rest, readScript, hits) {
  for (const t of rest) {
    codeHits(t, "py", hits);
    if (/^[A-Za-z_][\w.]*$/.test(t)) pyModuleHit(t, [], hits);
    if (/\.pyw?$/i.test(t)) scriptHits(t, "py", readScript, hits);
  }
}

function pythonHits(binary, rest, seg, readScript, hits) {
  for (let i = 0; i < rest.length; i++) {
    const t = rest[i];
    if (t === "-") break;
    if (t === "--") { if (rest[i + 1] != null && rest[i + 1] !== "-") { scriptHits(rest[i + 1], "py", readScript, hits); return; } break; }
    if (binary === "py" && PY_LAUNCHER_VERSION.test(t) && t !== "-") continue;
    if (t.startsWith("--")) {
      if (PY_LONG_NOARG.has(t)) continue;
      const eq = t.indexOf("=");
      if (PY_LONG_VALUED.has(eq > 0 ? t.slice(0, eq) : t)) {
        if (eq < 0) { if (rest[i + 1] == null) return pythonFallback(rest, readScript, hits); i++; }
        continue;
      }
      return pythonFallback(rest, readScript, hits);
    }
    if (t.startsWith("-")) {
      for (let k = 1; k < t.length; k++) {
        const ch = t[k];
        if (ch === "c" || ch === "m") {
          const attached = k + 1 < t.length;
          const v = attached ? t.slice(k + 1) : rest[i + 1];
          if (v == null) return pythonFallback(rest, readScript, hits);
          if (ch === "c") codeHits(v, "py", hits);
          else pyModuleHit(v, rest.slice(attached ? i + 1 : i + 2), hits);
          return;
        }
        if (ch === "W" || ch === "X") {
          if (k + 1 === t.length) { if (rest[i + 1] == null) return pythonFallback(rest, readScript, hits); i++; }
          break;
        }
        if (!PY_NOARG.has(ch)) return pythonFallback(rest, readScript, hits);
      }
      continue;
    }
    scriptHits(t, "py", readScript, hits);
    return;
  }
  if (seg.heredoc != null) codeHits(seg.heredoc, "py", hits);
}

// Node options: --eval= / --print=, short flags combined and ending in e or p (`-pe`), and modules loaded
// before the script (-r / --require / --import / --loader), each checked against OT_NODE_LIBS.
const NODE_PRELOAD = new Set(["-r", "--require", "--import", "--loader", "--experimental-loader"]);
const NODE_VALUED = new Set(["-C", "--conditions", "--input-type", "--title", "--env-file", "--disable-warning", "--watch-path", "--test-name-pattern", "--test-reporter", "--test-reporter-destination", "--redirect-warnings", "--stack-size"]);
function preloadHit(spec, hits) {
  const s = String(spec || "");
  const root = s.startsWith("@") ? s.split("/").slice(0, 2).join("/") : s.split("/")[0];
  if (Object.prototype.hasOwnProperty.call(OT_NODE_LIBS, root)) hits.push({ protocol: OT_NODE_LIBS[root].protocol, op: "unknown", client: root });
}

function nodeHits(binary, rest, seg, readScript, hits) {
  let i = 0;
  if ((binary === "deno" || binary === "bun") && rest[0] === "run") i = 1;
  if (binary === "deno" && rest[0] === "eval") { codeHits(rest[1], "node", hits); return; }
  for (; i < rest.length; i++) {
    const t = rest[i];
    const eq = t.startsWith("--") ? t.indexOf("=") : -1;
    const name = eq > 0 ? t.slice(0, eq) : t;
    const inline = eq > 0 ? t.slice(eq + 1) : null;
    if (name === "--eval" || name === "--print") { codeHits(inline != null ? inline : rest[i + 1], "node", hits); return; }
    if (/^-[A-Za-z]*[ep]$/.test(t)) { codeHits(rest[i + 1], "node", hits); return; }
    if (NODE_PRELOAD.has(name)) { preloadHit(inline != null ? inline : rest[i + 1], hits); if (inline == null) i++; continue; }
    if (NODE_VALUED.has(name)) { if (inline == null) i++; continue; }
    if (t === "-") break;
    if (t === "--") { if (rest[i + 1] != null) scriptHits(rest[i + 1], "node", readScript, hits); return; }
    if (t.startsWith("-")) continue;
    scriptHits(t, "node", readScript, hits);
    return;
  }
  if (seg.heredoc != null) codeHits(seg.heredoc, "node", hits);
}

// PowerShell's command line (cli/egress-rules.mjs reads it the same way): a parameter is written with
// -, -- or /, and any unambiguous prefix names it. -EncodedCommand (-e, -ec, -enc, ...) carries a base64
// UTF-16LE script; -Command (any prefix, or -CommandWithArgs) the rest of the line; -File a script file;
// and a first bare argument is the command (Windows PowerShell) or a script (pwsh), read as a command.
const PS_PARAM = /^(?:--?|\/)([A-Za-z]+)$/;
const isPrefix = (p, full, min = 1) => p.length >= min && full.startsWith(p);
const PS_VALUED = ["executionpolicy", "windowstyle", "workingdirectory", "configurationname", "configurationfile", "custompipename", "inputformat", "outputformat", "psconsolefile", "settingsfile", "version"];
const PS_VALUED_SHORT = new Set(["ep", "ex", "w", "wd", "if", "of", "o", "v", "config"]);
function decodeEncoded(b64) {
  try { return Buffer.from(String(b64 || ""), "base64").toString("utf16le"); } catch { return ""; }
}
function pwshHits(rest, seg, depth, readScript, hits) {
  for (let i = 0; i < rest.length; i++) {
    const m = PS_PARAM.exec(rest[i]);
    if (!m) { walk(rest.slice(i).join(" "), true, depth + 1, readScript, hits); return; }
    const p = m[1].toLowerCase();
    if (p === "e" || p === "ec" || isPrefix(p, "encodedcommand", 2)) { if (rest[i + 1]) walk(decodeEncoded(rest[i + 1]), true, depth + 1, readScript, hits); return; }
    if (p === "cwa" || isPrefix(p, "commandwithargs", 1)) {
      if (rest[i + 1] === "-" && seg.heredoc != null) walk(seg.heredoc, true, depth + 1, readScript, hits);
      else walk(rest.slice(i + 1).join(" "), true, depth + 1, readScript, hits);
      return;
    }
    if (isPrefix(p, "file", 1)) return;
    if (PS_VALUED_SHORT.has(p) || PS_VALUED.some((v) => isPrefix(p, v, 2))) { i++; continue; }
  }
  if (seg.heredoc != null) walk(seg.heredoc, true, depth + 1, readScript, hits);
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
  if (depth < MAX_DEPTH && PWSH.has(binary)) { pwshHits(rest, seg, depth, readScript, hits); return; }
  if (depth < MAX_DEPTH && binary === "cmd") {
    const ci = rest.findIndex((t) => /^\/[ck]$/i.test(t));
    if (ci >= 0) walk(rest.slice(ci + 1).join(" "), false, depth + 1, readScript, hits);
    return;
  }
  if (depth < MAX_DEPTH && (binary === "eval" || binary === "invoke-expression" || binary === "iex")) {
    walk(rest.join(" "), ps || binary !== "eval", depth + 1, readScript, hits);
    return;
  }
  if (depth < MAX_DEPTH && binary === "find" && rest.some((t) => /^-(?:exec|execdir|ok|okdir)$/.test(t))) {
    for (let k = 0; k < rest.length; k++) {
      if (!/^-(?:exec|execdir|ok|okdir)$/.test(rest[k])) continue;
      let end = rest.findIndex((t, j) => j > k && (t === ";" || t === "+"));
      if (end < 0) end = rest.length;
      commandHits(rest.slice(k + 1, end), { tokens: rest.slice(k + 1, end) }, false, depth + 1, readScript, hits);
      k = end;
    }
    return;
  }
  const def = Object.prototype.hasOwnProperty.call(OT_BINARIES, binary) ? OT_BINARIES[binary] : null;
  if (def) { hits.push(binaryHit(def, binary, rest)); return; }
  if (PY_INTERPRETERS.test(binary)) { pythonHits(binary, rest, seg, readScript, hits); return; }
  if (NODE_INTERPRETERS.test(binary)) { nodeHits(binary, rest, seg, readScript, hits); return; }
  // A script run directly (./tool.py, ./poll.mjs): read by extension.
  const bare = String(word || "");
  if (SCRIPT_EXT.test(bare)) scriptHits(bare, /\.pyw?$/i.test(bare) ? "py" : "node", readScript, hits);
}

function walk(cmd, ps, depth, readScript, hits) {
  const parsed = splitShell(String(cmd || "").slice(0, MAX_CMD), ps, depth, { segs: [], heredocs: [] });
  for (const seg of parsed.segs || []) commandHits(seg.tokens || [], seg, ps, depth, readScript, hits);
}

// → null, or { otProtocol, otOp, client, incomplete } where client names the tool or library (kept in
// process; it is not an alert field) and incomplete is true when a script was too large to read whole.
// shell: "sh" (Bash, the default) or "ps" (PowerShell). scripts: further scripts the caller decoded from
// the command ([{ text, shell }], the hook's -EncodedCommand / Invoke-Expression / base64-into-a-shell
// payloads), read into the same result. Never throws.
export function otShellFacts(command, { shell = "sh", readScript = null, scripts = [] } = {}) {
  const hits = [];
  const sources = [{ text: command, shell }, ...(Array.isArray(scripts) ? scripts : [])];
  for (const s of sources) {
    if (!s || typeof s.text !== "string" || !s.text.trim()) continue;
    try { walk(s.text, s.shell === "ps", 0, readScript, hits); } catch { /* one source that cannot be read does not hide another */ }
  }
  if (!hits.length) return null;
  let best = hits[0];
  for (const h of hits) if (OP_RANK[h.op] > OP_RANK[best.op]) best = h;
  return { otProtocol: best.protocol, otOp: best.op, client: best.client, incomplete: !!hits.incomplete };
}

// The policy action for one threat id, resolved by threatActionFor; a value that is not an action fails
// closed to "block".
function actionFor(policy, id) {
  const act = threatActionFor(policy && typeof policy === "object" ? policy : null, id);
  return Object.prototype.hasOwnProperty.call(ACTION_RANK, act) ? act : "block";
}

// The hook's check for one command tool call. → null (no OT client, or the policy disabled the threat), or
// { decision: "allow"|"ask"|"deny", action, otProtocol, otOp, reason, alert }. The caller posts `alert`
// (adding ts and identity) and raises its verdict to `decision` when that ranks higher.
export function otShellCheck({ command, shell = "sh", policy = null, readScript = null, scripts = [], tool = "Bash" } = {}) {
  const f = otShellFacts(command, { shell, readScript, scripts });
  if (!f) return null;
  const threatId = f.otOp === "write" ? OT_THREAT.write : OT_THREAT.read;
  let action = actionFor(policy, threatId);
  // A script read only in part may hold a write in the part not read: the stricter action of the two.
  if (f.incomplete && f.otOp !== "write") { const wa = actionFor(policy, OT_THREAT.write); if (ACTION_RANK[wa] > ACTION_RANK[action]) action = wa; }
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
  const kill = action === "kill";
  return { decision, action, kill, killIds: kill ? [threatId] : [], otProtocol: f.otProtocol, otOp: f.otOp, reason, alert };
}
