// AML.T0092 "Manipulate User LLM Chat History" — the endpoint half: a tool call that deletes, truncates,
// rewrites, moves or fabricates the agent's OWN transcripts. ATLAS's definition ("delete or edit
// existing messages or create new threads as part of their coverup") names the backend API too; that
// half is not observable here. What is observable is the local store every coding agent keeps.
//
// THE STORE, one entry per agent, each checked against the tool's own docs or a live install:
//   Claude Code  ~/.claude/projects/<project>/<session>.jsonl (+ <session>/ subagent dirs),
//                ~/.claude/history.jsonl, ~/.claude/file-history/ (rewind checkpoints). Measured on disk.
//                ~/.claude/projects/<project>/memory/ is EXCLUDED: auto-memory is written by the agent by
//                design, and memory content is #22 / rules-file territory, not a transcript.
//                ~/.claude.json is NOT a transcript store in current builds (measured: settings, MCP
//                servers, per-project counters; no message history), so it is not listed.
//   Codex        $CODEX_HOME/sessions/** (rollout-*.jsonl), history.jsonl (config reference:
//                "history.persistence ... history.jsonl"); session_index.jsonl and
//                thread_history_<n>.sqlite measured on disk.
//   Cursor       ~/.cursor/chats/** and ~/.cursor/prompt_history.json (cursor-agent, measured on disk);
//                the IDE's Cursor/User/{globalStorage,workspaceStorage/<id>}/state.vscdb (measured).
//   Gemini CLI   ~/.gemini/tmp/<project_hash>/chats/ (docs: session management).
//   Copilot CLI  ~/.copilot/session-state and ~/.copilot/history-session-state (CLI changelog 0.0.342).
//   Not listed:  VS Code Copilot Chat's storage — not confirmed from a primary source.
//
// A HISTORY path is any of the above; a CONTAINER is a directory that holds one (the tool's home dir,
// ~/.gemini/tmp) and counts only for a delete or a move, because writing a new file into ~/.codex is
// not a transcript edit while `rm -rf ~/.codex` destroys every one. A container must be HOME-ANCHORED
// (~, $HOME, /Users/<u>, C:\Users\<u>, ...): a project-local `.claude/` holds settings, not history.
//
// WHAT COUNTS AS A WRITE. Parsed per shell segment, never a keyword scan of the whole string, so a path
// merely named in prose or in a read (`cat`, `tail`, `grep`, `jq`, `cp <history> backup/`) stays
// silent: a delete/truncate verb with the path as an operand, an in-place edit (`sed -i`, `perl -pi`),
// `tee`, a redirect target, the DESTINATION of cp/ln/install, either side of mv, `dd of=`, `find
// <history> -delete|-exec rm`, `find <history> | xargs rm`, `sqlite3 <db> "<DML>"`, the PowerShell
// equivalents, and an interpreter one-liner naming the path next to a write API. MCP arguments arrive
// as JSON: a history path in a path-like key PLUS a write-intent key (content, edits, destination).
//
// Browser-safe and pure (the extension bundles data/detectors.js), so it cannot reuse cli/hook-core's
// tokenizer; it mirrors data/deletion-volume.js's segmenting, which it cannot import either (that module
// imports DETECTORS, which would close a cycle through this file). Content-free: booleans only.

const MAX = 16_384;

const HOME_SEG = /^(?:~|\$home|\$\{home\}|\$env:userprofile|%userprofile%|\$env:home)$/i;
const VAR_DIR = { "$claude_config_dir": ".claude", "${claude_config_dir}": ".claude", "$codex_home": ".codex", "${codex_home}": ".codex", "$copilot_home": ".copilot", "${copilot_home}": ".copilot" };

function segmentsOf(raw) {
  let p = String(raw).replace(/^file:\/\//i, "").replace(/\\ /g, " ").replace(/\\/g, "/");
  return p.split("/").filter((s) => s && s !== ".");
}

// Are segs[0..i) a home directory? ~ / $HOME / /Users/<u> / /home/<u> / /root / C:/Users/<u>.
function homeAnchored(segs, i) {
  const pre = segs.slice(0, i).map((s) => s.toLowerCase());
  if (pre.length === 1) return HOME_SEG.test(pre[0]) || pre[0] === "root";
  if (pre.length === 2) return pre[0] === "users" || pre[0] === "home";
  if (pre.length === 3) return /^[a-z]:$/.test(pre[0]) && pre[1] === "users";
  return false;
}

// "history" | "container" | null
export function agentStateKind(path) {
  if (typeof path !== "string" || !path || path.length > 1024) return null;
  const segs = segmentsOf(path.replace(/^["']|["']$/g, ""));
  for (let i = 0; i < segs.length; i++) {
    let s = segs[i].toLowerCase();
    let anchored;
    if (VAR_DIR[s]) { s = VAR_DIR[s]; anchored = true; } else anchored = homeAnchored(segs, i);
    const n1 = (segs[i + 1] || "").toLowerCase(), n2 = segs[i + 2], n3 = (segs[i + 3] || "").toLowerCase();
    const rootOnly = !n1 || n1 === "*";
    if (s === ".claude") {
      if (n1 === "history.jsonl" || n1 === "file-history") return "history";
      if (n1 === "projects") return n3 === "memory" ? null : "history";
      return rootOnly && anchored ? "container" : null;
    }
    if (s === ".codex") {
      if (n1 === "sessions" || n1 === "history.jsonl" || n1 === "session_index.jsonl" || /^thread_history_\d{1,4}\.sqlite(?:-wal|-shm)?$/.test(n1)) return "history";
      return rootOnly && anchored ? "container" : null;
    }
    if (s === ".cursor") {
      if (n1 === "chats" || n1 === "prompt_history.json") return "history";
      return rootOnly && anchored ? "container" : null;
    }
    if (s === ".gemini") {
      if (n1 === "tmp" && n3 === "chats") return "history";
      if (n1 === "tmp" && anchored && (!n2 || n2 === "*" || !n3)) return "container";
      return rootOnly && anchored ? "container" : null;
    }
    if (s === ".copilot") {
      if (n1 === "session-state" || n1 === "history-session-state") return "history";
      return rootOnly && anchored ? "container" : null;
    }
    if (s === "cursor" && n1 === "user") {
      const tail = segs.slice(i + 2).map((x) => x.toLowerCase());
      if (tail[0] === "globalstorage" && /^state\.vscdb/.test(tail[1] || "")) return "history";
      if (tail[0] === "workspacestorage" && /^state\.vscdb/.test(tail[2] || "")) return "history";
    }
  }
  return null;
}

const hist = (t) => agentStateKind(t) === "history";
const any = (t) => agentStateKind(t) !== null;

// ---- shell parsing (bounded) ----
const PREFIX = new Set(["sudo", "doas", "command", "builtin", "exec", "nohup", "time", "nice", "env", "then", "do", "else"]);
const DELETE = new Set(["rm", "unlink", "rmdir", "shred", "srm", "trash", "del", "erase", "rd", "remove-item", "ri"]);
const TRUNC = new Set(["truncate", "clear-content", "clc", "tee", "set-content", "sc", "add-content", "ac", "out-file"]);
const MOVE = new Set(["mv", "move", "move-item", "mi", "rename-item", "rni", "ren", "rename"]);
const DEST = new Set(["cp", "copy", "copy-item", "cpi", "install", "ditto", "rsync", "ln"]);
const INPLACE = new Set(["sed", "gsed", "perl"]);
const INTERP = /\b(?:python[23]?(?:\.\d{1,2})?|node|nodejs|deno|bun|perl|ruby|php|osascript|pwsh|powershell)\b/i;
const WRITE_API = /\bopen\s{0,4}\([^)]{0,300}?,\s{0,4}(?:mode\s{0,4}=\s{0,4})?["'][^"']{0,4}[wax+]|\bos\.(?:remove|unlink|rename|replace|truncate)\b|\bshutil\.(?:rmtree|move)\b|\.(?:unlink|write_text|write_bytes|rename|replace)\s{0,4}\(|\b(?:writeFile|appendFile|unlink|rm|rmdir|truncate|rename)(?:Sync)?\s{0,4}\(|\bFile\.(?:delete|write)\b|\bFileUtils\.rm\b|\bunlink\s{0,4}\(|\bRemove-Item\b|\bSet-Content\b/i;
const SQL_WRITE = /\b(?:delete|update|insert|replace|drop|alter|vacuum)\b/i;

const base = (t) => String(t).replace(/^["'(){}]+|["'(){};]+$/g, "").split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, "");
const unq = (t) => String(t).replace(/^["']|["']$/g, "");
function tokens(seg) { return seg.match(/"[^"]{0,2048}"|'[^']{0,2048}'|[^\s"']{1,2048}(?:(?:"[^"]{0,2048}"|'[^']{0,2048}')[^\s"']{0,2048})?/g) || []; }
function verbAt(toks) {
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i].replace(/^[({]+/, "");
    if (!t || /^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) continue;
    if (PREFIX.has(base(t))) { while (i + 1 < toks.length && toks[i + 1].startsWith("-")) i++; continue; }
    return i;
  }
  return -1;
}
const isOpt = (a) => /^-/.test(a) || /^\/[a-z?]$/i.test(a);

// Redirect targets anywhere in the segment: `> f`, `>>f`, `1> f`, `&> f`, `>| f`. `<` is a read.
function redirectTargets(toks) {
  const out = [];
  for (let i = 0; i < toks.length; i++) {
    const m = /^(?:\d|&)?>>?\|?(.*)$/.exec(toks[i]);
    if (!m) continue;
    if (m[1]) { if (!m[1].startsWith("&")) out.push(m[1]); }
    else if (i + 1 < toks.length) out.push(toks[i + 1]);
  }
  return out;
}

function operandsOf(args) { return args.filter((a) => !isOpt(a) && !/^\d?[<>]/.test(a) && !/^&>/.test(a)); }

function segmentHit(toks) {
  if (redirectTargets(toks).some((t) => hist(unq(t)))) return true;
  const vi = verbAt(toks);
  if (vi < 0) return false;
  const verb = base(toks[vi]);
  // Operands stop at the first redirect.
  const rest = [];
  for (const a of toks.slice(vi + 1)) { if (/^(?:\d|&)?[<>]/.test(a)) break; rest.push(a); }
  const ops = operandsOf(rest).map(unq);
  if (DELETE.has(verb)) return ops.some(any);
  if (TRUNC.has(verb)) return ops.some(hist);
  if (MOVE.has(verb)) return ops.some(any);
  if (DEST.has(verb)) {
    const t = rest.findIndex((a) => a === "-t" || a === "--target-directory" || a === "-Destination");
    if (t >= 0 && rest[t + 1]) return hist(unq(rest[t + 1]));
    return ops.length >= 2 && hist(ops[ops.length - 1]);
  }
  if (INPLACE.has(verb)) {
    const inplace = rest.some((a) => /^-[a-zA-Z]{0,3}i/.test(a) || /^--in-place/.test(a));
    return inplace && ops.some(hist);
  }
  if (verb === "dd") return rest.some((a) => /^of=/.test(a) && hist(unq(a.slice(3))));
  if (verb === "find") {
    const del = rest.some((a) => a === "-delete") || rest.some((a, i) => /^-exec(?:dir)?$/.test(a) && (DELETE.has(base(rest[i + 1] || "")) || TRUNC.has(base(rest[i + 1] || ""))));
    return del && ops.some(any);
  }
  if (verb === "sqlite3" || verb === "sqlite") {
    return ops.length >= 2 && hist(ops[0]) && ops.slice(1).some((q) => SQL_WRITE.test(q));
  }
  if (verb === "xargs") return false; // handled at the pipeline level
  return false;
}

// `find <history> ... | xargs rm` — the operand is on the left of the pipe, the verb on the right.
function pipelineHit(cmds) {
  let source = false;
  for (const toks of cmds) {
    const vi = verbAt(toks);
    if (vi < 0) continue;
    const verb = base(toks[vi]);
    if (source && verb === "xargs") {
      const j = toks.slice(vi + 1).findIndex((a) => !isOpt(a));
      const v = j >= 0 ? base(toks[vi + 1 + j]) : "";
      if (DELETE.has(v) || TRUNC.has(v) || MOVE.has(v)) return true;
    }
    if ((verb === "find" || verb === "ls" || verb === "fd" || verb === "get-childitem" || verb === "gci") && operandsOf(toks.slice(vi + 1)).map(unq).some(any)) source = true;
  }
  return false;
}

// Interpreter one-liner or heredoc: an interpreter, a history path literal and a write API, all in
// the same command. Checked on the whole (capped) text because the program text spans quotes and lines.
const PATH_LITERAL = /[^\s"'`(),;]{0,200}\.(?:claude|codex|cursor|gemini|copilot)\/[^\s"'`(),;]{0,300}|[^\s"'`(),;]{0,200}Cursor\/User\/[^\s"'`(),;]{0,300}/gi;
function interpreterHit(text) {
  if (!INTERP.test(text) || !WRITE_API.test(text)) return false;
  PATH_LITERAL.lastIndex = 0;
  let m, n = 0;
  while ((m = PATH_LITERAL.exec(text)) !== null && n++ < 64) {
    // `process.env.HOME + '/.claude/...'` leaves the literal unanchored; any history path is enough.
    if (hist(m[0]) || hist("~/" + m[0].replace(/^[^.]*?(?=\.(?:claude|codex|cursor|gemini|copilot)\/)/i, ""))) return true;
  }
  return false;
}

const PATH_KEY = /^(?:path|paths|file_?path|filename|file|target|target_?path|source|src|destination|dest|new_?path|old_?path|uri)$/i;
const WRITE_KEY = /^(?:content|contents|text|data|edits|new_?string|new_?text|new_?source|destination|dest|new_?path|body|patch|append|overwrite)$/i;
function jsonHit(text) {
  const t = text.trim();
  if (!t.startsWith("{")) return false;
  let o;
  try { o = JSON.parse(t); } catch { return false; }
  if (!o || typeof o !== "object" || Array.isArray(o)) return false;
  const keys = Object.keys(o);
  if (!keys.some((k) => WRITE_KEY.test(k))) return false;
  const paths = [];
  for (const k of keys) if (PATH_KEY.test(k)) {
    const v = o[k];
    if (typeof v === "string") paths.push(v);
    else if (Array.isArray(v)) for (const x of v.slice(0, 32)) if (typeof x === "string") paths.push(x);
  }
  return paths.some(hist);
}

function scan(text) {
  if (typeof text !== "string" || !text) return false;
  const s = text.length > MAX ? text.slice(0, MAX) : text;
  if (jsonHit(s)) return true;
  // Protect `-exec rm {} \;` from the segment splitter, then split into pipelines and commands.
  const prot = s.replace(/\\;|';'|";"/g, " \u0000 ");
  for (const pl of prot.split(/\r?\n|;|&&|\|\|/).slice(0, 256)) {
    const cmds = pl.split(/(?<![>&])\|(?!\|)|(?<![>&\d])&(?![>&])/).slice(0, 64).map((c) => tokens(c.replace(/\u0000/g, "\\;")).slice(0, 128));
    for (const toks of cmds) if (toks.length && segmentHit(toks)) return true;
    if (cmds.length > 1 && pipelineHit(cmds)) return true;
  }
  return interpreterHit(s);
}

// Memoised on the last text: the engine re-invokes refine() once per prefilter occurrence.
let lastText = null, lastHit = false;
export function agentStateTamperHit(text) {
  if (text === lastText) return lastHit;
  lastText = text;
  lastHit = scan(text);
  return lastHit;
}

// A Write/Edit/MultiEdit/NotebookEdit carries the target only as tool_input.file_path. The hook can
// probe this detector with the equivalent shell write — the same trick decideCredFileRead uses for a
// Read and #55 — so the write surface gets exactly the verdict `tee <path>` gets, no stricter.
export function agentStateWriteProbe(path) {
  return `tee ${JSON.stringify(String(path || ""))}`;
}
