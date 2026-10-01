// MCP arguments that NAME a local file. Shared by the PreToolUse hook's mcp__* branch
// (cli/moorai-hook.mjs) and the Claude Desktop stdio proxy (mcp-proxy/moorai-mcp-guard.mjs).
//
// THE GAP THIS CLOSES, measured through the real hook in a sandbox HOME before it existed:
// `mcp__drive__upload_file {"path":"<abs>/customers.csv"}` with an AWS key and an SSN in the file
// produced NO finding, because mcpGateway scans the serialized ARGUMENTS and the argument is only a
// path. `cat <abs>/customers.csv` through Bash raised #39, because the Bash branch resolves the paths a
// command reads (extractReadPaths) and scans their content. An MCP tool that takes a path and reads the
// file itself — upload / attach / send / a filesystem server — shipped any file whose NAME is harmless.
//
// A separate file, not hook-core.mjs: hook-core's decision section is pure (text in, verdict out) and
// this one does filesystem I/O on paths an agent chose. It composes hook-core's checks and adds none:
// every resolved file gets exactly what the Bash branch gives a resolved read path — the content scan
// (fileScanText + decideText at "file"), the #72 metadata scan and the #55 credential-location check.
//
// Bounded and fail-open, like extractReadPaths: a capped walk of the argument tree, a capped number of
// stat calls and files, 256 KB read per file (the Bash branch's readFileCapped cap) and 1 MB per call,
// a wall-clock budget checked between files, and a try/catch around all of it. Only REGULAR files are
// opened: devices, FIFOs, sockets and anything under /dev, /proc or /sys are never read; a symlink is
// followed only when its target is a regular file, and the target is what gets checked. UNC paths are
// never touched — on Windows, stat on \\host\share authenticates to that host, which is a leak of its own.
import { lstatSync, statSync, realpathSync, openSync, readSync, fstatSync, closeSync, constants as FS } from "node:fs";
import { resolve, join, basename, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";
import { decideText, decideCredFileRead, decideFileMetadata, fileScanText, isEnvTemplate } from "./hook-core.mjs";

export const MCP_FILE_CAPS = Object.freeze({
  depth: 8,              // nesting levels walked below the arguments object
  leaves: 512,           // string leaves examined
  candidates: 32,        // paths stat'ed
  files: 12,             // files read and scanned (extractReadPaths returns at most 12 as well)
  fileBytes: 262_144,    // per file — the Bash/Read branches' readFileCapped cap
  totalBytes: 1_048_576, // per call
  budgetMs: 1000         // checked before each stat and each read; a read already started finishes
});

const RANK = { allow: 1, ask: 2, deny: 3 };
const EMPTY = () => ({ decision: "allow", reasons: [], alternatives: [], findings: [], kill: false, killIds: [], files: [], text: "", sends: false });

// Mirrors the Bash branch's `uploading` flag. There, a file an UPLOAD command reads carries ctx.egress;
// a file `cat` reads does not. An MCP call has no command grammar, so the tool's own name is the only
// evidence of which kind it is: upload_file / send_email / attach / post_message / create_gist ship the
// file's bytes somewhere, read_file / get_file_info / search_files hand them to the model exactly as the
// Read tool does. ctx.egress only arms instr-leak-egress (#52), so getting this wrong in either direction
// moves one warn-level detector, never a block.
const SEND_VERB = /(?:^|[_\-.])(?:upload|attach|send|post|share|publish|e?mail|submit|transmit|forward|gist)(?:s|es|ed|ment|ments)?(?:[_\-.]|$)/i;
export function mcpToolSends(tool) {
  const t = String(tool || "");
  const local = t.startsWith("mcp__") ? t.split("__").slice(2).join("__") : t;
  return SEND_VERB.test(local.replace(/([a-z0-9])([A-Z])/g, "$1_$2"));
}

// A RELATIVE path is ambiguous in exactly one common case: a repository API. github's
// get_file_contents {owner, repo, path:"README.md"} names a file in the REMOTE repo, and resolving it
// under the agent's cwd scanned the local README instead — measured on this repo, 4 of 5 such calls
// alerted and 3 were raised to ask/deny for a file the tool never opens. So a call that names a remote
// repository or bucket at its top level does not get its relative leaves resolved, unless the tool
// SENDS (upload_file {owner, path} still reads a local path), which is also what keeps an attacker
// from switching the check off by adding an `owner` argument to an upload. Absolute, ~ and file://
// paths are never ambiguous and are always resolved.
const REMOTE_KEYS = ["owner", "repo", "repository", "project_id", "projectId", "bucket"];
export function namesRemoteLocation(args) {
  return !!args && typeof args === "object" && !Array.isArray(args) && REMOTE_KEYS.some((k) => typeof args[k] === "string" || typeof args[k] === "number");
}

const DENY_PREFIX = /^\/(?:dev|proc|sys)(?:\/|$)/;
const WIN_DEVICE = /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9]|conin\$|conout\$)(?:\.[^\\/]*)?$/i;

// The absolute local paths one string leaf could denote, most specific first. [] = not a local path.
//   file:///x (host empty or localhost)  ~ / ~/x  /abs  C:\x  \\?\C:\x  and a relative x/y or x.ext,
//   which is tried against each base (the hook's input.cwd; the proxy's cwd, then its MCP roots).
export function localPathCandidates(s, { bases = [], home = os.homedir(), platform = process.platform } = {}) {
  if (typeof s !== "string" || !s || s.length > 4096 || /[\0\r\n]/.test(s)) return [];
  const win = platform === "win32";
  const P = win ? win32 : { resolve, join };
  let p = s;
  if (/^file:/i.test(p)) {
    try { p = fileURLToPath(p, { windows: win }); } catch { return []; } // file://host/… → UNC on win32, refused below
  } else if (/^[a-z][a-z0-9+.-]+:/i.test(p)) return []; // any other scheme (https:, s3:, mailto:, …)
  if (p === "~" || p.startsWith("~/") || (win && p.startsWith("~\\"))) p = P.join(home, p.slice(1));
  else if (p.startsWith("~")) return []; // ~user — another account's home is not guessed at
  let out;
  if (win) {
    const ext = /^[\\/]{2}\?[\\/]([a-z]:[\\/].*)$/i.exec(p);
    if (ext) p = ext[1];
    if (/^[a-z]:[\\/]/i.test(p)) out = [P.resolve(p)];
    else if (/^[a-z]:/i.test(p) || /^[\\/]/.test(p)) return []; // UNC, \\.\ devices, drive- or root-relative
  } else if (p.startsWith("/")) out = [resolve(p)];
  if (!out) {
    if (p.startsWith("-") || !/[\\/.]/.test(p)) return []; // relative: must look like a path or a file name
    out = [...new Set(bases.filter((b) => typeof b === "string" && b).map((b) => P.resolve(b, p)))];
  }
  return out.filter((x) => (win ? !WIN_DEVICE.test(win32.basename(x)) : !DENY_PREFIX.test(x)));
}

// Walk the arguments (objects and arrays, keys ignored) and return the string leaves, capped.
function stringLeaves(value, caps) {
  const out = [];
  const stack = [[value, 0]];
  let seen = 0;
  while (stack.length && out.length < caps.leaves && seen < caps.leaves * 4) {
    const [v, d] = stack.pop();
    seen++;
    if (typeof v === "string") { out.push(v); continue; }
    if (!v || typeof v !== "object" || d >= caps.depth) continue;
    const kids = Array.isArray(v) ? v : Object.values(v);
    for (let i = kids.length - 1; i >= 0; i--) stack.push([kids[i], d + 1]);
  }
  return out;
}

// → { path, real } for a regular file (following a symlink only to a regular file), else null.
function regularFile(p, win) {
  const l = lstatSync(p, { throwIfNoEntry: false });
  if (!l) return null;
  if (l.isSymbolicLink()) { const t = statSync(p, { throwIfNoEntry: false }); if (!t || !t.isFile()) return null; }
  else if (!l.isFile()) return null;
  const real = realpathSync(p);
  if (win ? WIN_DEVICE.test(win32.basename(real)) || /^[\\/]{2}/.test(real) : DENY_PREFIX.test(real)) return null;
  return { path: p, real };
}

// Read at most `cap` bytes. O_NONBLOCK so a path swapped for a FIFO between stat and open cannot hang
// the call, and fstat on the open descriptor so what gets read is what was checked.
function readHead(p, cap) {
  const fd = openSync(p, FS.O_RDONLY | (FS.O_NONBLOCK || 0));
  try {
    if (!fstatSync(fd).isFile()) return null;
    const buf = Buffer.allocUnsafe(cap);
    let n = 0;
    while (n < cap) { const r = readSync(fd, buf, n, cap - n, n); if (!r) break; n += r; }
    return buf.subarray(0, n);
  } finally { closeSync(fd); }
}

// Resolve the local files an MCP call's arguments name. Never throws.
export function resolveMcpFileArgs(args, { bases = [], home = os.homedir(), platform = process.platform, caps = MCP_FILE_CAPS, now = () => performance.now() } = {}) {
  const files = [];
  const t0 = now();
  try {
    const win = platform === "win32";
    const seen = new Set();
    let stats = 0;
    for (const leaf of stringLeaves(args, caps)) {
      for (const p of localPathCandidates(leaf, { bases, home, platform })) {
        if (files.length >= caps.files || stats >= caps.candidates || now() - t0 > caps.budgetMs) return files;
        stats++;
        let f = null;
        try { f = regularFile(p, win); } catch { f = null; }
        if (!f || seen.has(f.real)) continue;
        seen.add(f.real);
        files.push({ arg: leaf, ...f });
        break; // first base that resolves wins for a relative leaf
      }
    }
  } catch { /* fail open: whatever resolved so far */ }
  return files;
}

// The file half of an MCP call's verdict: every file the arguments name, checked the way the Bash branch
// checks a path a command reads. Returns decideText's shape (decision / reasons / alternatives /
// findings / kill / killIds) plus `files` — one entry per scanned file with its own findings, so the
// caller can report each with its path under the capture tier — `text`, the scanned content, and
// `sends`, whether the tool's name says it ships the file (the ctx.egress decision above).
// `argIds`: threat ids the ARGUMENT scan already raised; a #55 on the path is then the same fact twice
// (the path text is in the arguments) and is not repeated. No `mask` is ever passed: a file referenced
// by path cannot be rewritten, so a "mask" policy resolves to its fallback (threatActionFor).
export function scanMcpFileArgs(engine, policy, { tool, args, bases = [], home, platform, caps = MCP_FILE_CAPS, now, argIds = [] } = {}) {
  const out = EMPTY();
  try {
    const egress = mcpToolSends(tool);
    out.sends = egress;
    const t0 = (now || (() => performance.now()))();
    let budget = caps.totalBytes;
    const relBases = egress || !namesRemoteLocation(args) ? bases : [];
    for (const f of resolveMcpFileArgs(args, { bases: relBases, home, platform, caps, now })) {
      if (budget <= 0 || (now || (() => performance.now()))() - t0 > caps.budgetMs) break;
      let head = null;
      try { head = readHead(f.real, Math.min(caps.fileBytes, budget)); } catch { head = null; }
      if (!head) continue;
      budget -= head.length;
      const text = fileScanText(head);
      const fd = { arg: f.arg, path: f.path, real: f.real, bytes: head.length, findings: [] };
      const merge = (d) => {
        fd.findings.push(...d.findings);
        if (d.kill) { out.kill = true; out.killIds.push(...d.killIds); }
        if (RANK[d.decision] > RANK[out.decision]) { out.decision = d.decision; out.alternatives = d.alternatives; }
        for (const r of d.reasons) out.reasons.push(`${r} (file ${basename(f.real)})`);
      };
      merge(decideText(engine, policy, text, "file", { ctx: { template: isEnvTemplate(f.real), egress } }));
      merge(decideFileMetadata(engine, policy, f.real, () => head));
      if (!argIds.includes(55)) {
        for (const p of [...new Set([f.path, f.real])]) {
          const pd = decideCredFileRead(engine, policy, p);
          if (pd.findings.length) { merge(pd); break; }
        }
      }
      out.findings.push(...fd.findings);
      out.files.push(fd);
      out.text += text + "\n";
    }
  } catch { /* fail open: keep whatever was decided */ }
  return out;
}
