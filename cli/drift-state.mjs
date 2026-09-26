// On-device state for the learned-drift baseline (data/learned-drift.js) and the session deletion
// counter (data/deletion-volume.js), plus the one piece of filesystem discovery learned drift needs:
// which git repository the agent is working in.
//
// Fail-open by construction: every read returns null on any error (missing, unreadable, oversized or
// unparsable file) and every write swallows its error, so a broken state file can never break a tool
// call. Writes are atomic (temp file + rename) so a concurrent hook never reads half a file. Parallel
// hook calls can still lose one another's update (last rename wins); the files hold counters and
// timestamps, so a lost update costs one observation, not correctness of the decision.
import { readFileSync, writeFileSync, renameSync, mkdirSync, statSync, openSync, readSync, closeSync } from "node:fs";
import { join, dirname, resolve, isAbsolute } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";

export const LEARNED_DRIFT_FILE = "learned-drift.json";
export const DELETION_VOLUME_FILE = "deletion-volume.json";
const MAX_STATE_BYTES = 1 << 20;

export function readStateJson(name) {
  try {
    const p = join(STATE_DIR, name);
    if (statSync(p).size > MAX_STATE_BYTES) return null;
    const o = JSON.parse(readFileSync(p, "utf8"));
    return o && typeof o === "object" && !Array.isArray(o) ? o : null;
  } catch { return null; }
}

export function writeStateJson(name, obj) {
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    const p = join(STATE_DIR, name);
    const tmp = `${p}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(obj));
    renameSync(tmp, p);
  } catch { /* state is best-effort; never affects the decision */ }
}

function readHead(p, max = 65536) {
  const fd = openSync(p, "r");
  try { const b = Buffer.alloc(max); const n = readSync(fd, b, 0, max, 0); return b.subarray(0, n).toString("utf8"); } finally { closeSync(fd); }
}

// The URL of remote "origin", else of the first remote, from a git config file's text.
export function remoteFromConfig(text) {
  let section = "", first = "", origin = "";
  for (const line of String(text || "").split(/\r?\n/)) {
    const sec = line.match(/^\s*\[\s*remote\s+"([^"]*)"\s*\]/);
    if (sec) { section = sec[1]; continue; }
    if (/^\s*\[/.test(line)) { section = ""; continue; }
    const u = section && line.match(/^\s*url\s*=\s*(.+?)\s*$/);
    if (!u) continue;
    if (!first) first = u[1];
    if (section === "origin" && !origin) origin = u[1];
  }
  return origin || first;
}

// { root, remote } for the repository containing `cwd`, or null. Walks up at most 64 levels looking for
// `.git`; a `.git` FILE (worktree / submodule) is followed to its gitdir and then to `commondir`, where
// the shared config lives. Reads at most 64 KB of config. No git binary is run.
export function repoIdentity(cwd) {
  try {
    if (!cwd || typeof cwd !== "string" || !isAbsolute(cwd)) return null;
    let d = resolve(cwd);
    for (let i = 0; i < 64; i++) {
      const g = join(d, ".git");
      let st = null;
      try { st = statSync(g); } catch { /* not here */ }
      if (st) {
        let gitDir = g;
        if (st.isFile()) {
          const m = readHead(g, 4096).match(/^gitdir:\s*(.+?)\s*$/m);
          if (!m) return { root: d, remote: "" };
          gitDir = resolve(d, m[1]);
          try { gitDir = resolve(gitDir, readHead(join(gitDir, "commondir"), 4096).trim()); } catch { /* no commondir: a submodule */ }
        }
        let remote = "";
        try { remote = remoteFromConfig(readHead(join(gitDir, "config"))); } catch { /* no config */ }
        return { root: d, remote };
      }
      const up = dirname(d);
      if (up === d) break;
      d = up;
    }
  } catch { /* discovery is best-effort */ }
  return null;
}
