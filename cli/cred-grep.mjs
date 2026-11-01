// #55 for Claude Code's Grep tool ({pattern, path?, glob?, output_mode?, -A/-B/-C/context?, …}): the tool reads
// the files it searches and hands matching lines to the model, so a Grep is a read of what it searches.
// Judged by the same path rules as a Read and a shell command (data/cred-paths.js), structurally, with no
// part of the input reported:
//
//   * the path (or a glob naming one file) is a credential, token, key, browser, keychain or hash store;
//   * the path is a credential directory (~/.ssh, ~/.aws, ~/.docker, …) and the search shows lines
//     (output_mode "content", or a context option) or looks for a secret word; a file list or a count of a
//     non-secret pattern is not a read. Whether a pattern matches every line is not guessed at: any
//     content-mode search of the directory counts;
//   * the path is a shell history file and the pattern is a secret word (T1552.003; a plain history search
//     is allowed, as a whole read of the file is);
//   * the search is rooted at the filesystem root, a home directory or /etc and looks for a secret word or
//     only at key files (`*.pem`, `*.key`, `id_*`) — credential discovery, not code search.
//
// The path is judged as written AND as it resolves: `~` expanded, a relative path joined to the cwd, `.` /
// `..` folded, and symlinks followed when the path exists, so `../.ssh` or a link to ~/.aws reads as what it
// names. Returns the detector id to report, or null. Never throws.
import { realpathSync } from "node:fs";
import { resolve, isAbsolute, win32 } from "node:path";
import { credPathKind, credDirKind, broadRoot, credGlob, SECRET_WORD } from "../data/cred-paths.js";

const str = (v) => (typeof v === "string" ? v : "");
const CONTEXT_KEYS = ["-A", "-B", "-C", "context"];

// Every form of the search path: as written, resolved against cwd / home, and its real path.
export function grepPaths(raw, { cwd = "", home = "" } = {}) {
  const out = [];
  const add = (p) => { if (p && !out.includes(p)) out.push(p); };
  add(raw);
  if (!raw || /[\r\n\0]/.test(raw) || raw.length > 4096) return out;
  let abs = raw;
  if (home && (raw === "~" || /^~[\\/]/.test(raw))) abs = home + raw.slice(1);
  if (win32.isAbsolute(abs) && /^[A-Za-z]:|^\\\\/.test(abs)) { add(win32.normalize(abs)); return out; }
  abs = isAbsolute(abs) ? resolve(abs) : cwd ? resolve(cwd, abs) : abs;
  add(abs);
  try { add(realpathSync(abs)); } catch { /* not there: judged as resolved */ }
  return out;
}

export function grepCredHit(ti, { cwd = "", home = "" } = {}) {
  try {
    if (!ti || typeof ti !== "object") return null;
    const pattern = str(ti.pattern), glob = str(ti.glob);
    const secret = SECRET_WORD.test(pattern);
    const mode = str(ti.output_mode) || "files_with_matches";
    const showsLines = mode === "content" || CONTEXT_KEYS.some((k) => ti[k] != null && ti[k] !== false);
    const paths = grepPaths(str(ti.path) || str(cwd), { cwd: str(cwd), home: str(home) });
    for (const path of paths) {
      const kind = credPathKind(path);
      if (kind && kind !== "history") return "cred-access";
      if (kind === "history" && secret) return "cred-access";
      if (credDirKind(path) && (secret || showsLines)) return "cred-access";
      if (broadRoot(path, home) && (secret || credGlob(glob))) return "cred-access";
    }
    const g = glob.replace(/^\*\*\//, "");
    const gk = g && !/[*?]/.test(g) ? credPathKind(g) : null;
    if (gk && gk !== "history") return "cred-access";
    return null;
  } catch { return null; }
}
