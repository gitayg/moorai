// Where each supported agent keeps its transcripts, and a bounded walk that finds them.
//
// Claude Code: <config>/projects/<project>/<session>.jsonl, plus a session's sub-agents under
//   <session>/subagents/agent-<id>.jsonl (and .../subagents/workflows/<wf>/agent-<id>.jsonl).
//   <config> is $CLAUDE_CONFIG_DIR or ~/.claude. The hooks reference names the file as the
//   `transcript_path` field of every hook input; the layout was read off real files on a developer
//   machine (structure only).
// Codex: $CODEX_HOME (default ~/.codex) /sessions/YYYY/MM/DD/rollout-<ts>-<id>.jsonl and
//   /archived_sessions/. From codex-rs/rollout/src/lib.rs (SESSIONS_SUBDIR = "sessions",
//   ARCHIVED_SESSIONS_SUBDIR = "archived_sessions") and rollout_file_name.rs ("rollout-{ts}-{id}.jsonl").
//   Codex can compress old rollouts to <name>.jsonl.zst (rollout/src/compression.rs, ".zst").
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import os from "node:os";

export const AGENTS = ["claude-code", "codex"];

export function defaultRoots(env = process.env, home = os.homedir()) {
  return {
    "claude-code": [join(env.CLAUDE_CONFIG_DIR || join(home, ".claude"), "projects")],
    codex: [join(env.CODEX_HOME || join(home, ".codex"), "sessions"), join(env.CODEX_HOME || join(home, ".codex"), "archived_sessions")]
  };
}

export function isTranscriptName(agent, name) {
  if (agent === "codex") return /^rollout-.*\.jsonl(\.zst)?$/.test(name);
  return name.endsWith(".jsonl");
}

// Walk `roots` for `agent`'s transcripts. Bounded: at most `maxEntries` directory entries are looked at
// and the walk stops at `deadline`. Returns { files: [{ path, agent, mtimeMs, size }], walkTruncated }.
export function walk(agent, roots, { maxDepth = 6, maxEntries = 200000, deadline = Infinity, clock = Date.now } = {}) {
  const files = [];
  let seen = 0, walkTruncated = false;
  const visit = (dir, depth) => {
    if (walkTruncated) return;
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (++seen > maxEntries || clock() > deadline) { walkTruncated = true; return; }
      const p = join(dir, e.name);
      if (e.isDirectory()) { if (depth < maxDepth) visit(p, depth + 1); continue; }
      if (!e.isFile() || !isTranscriptName(agent, e.name)) continue;
      try { const st = statSync(p); files.push({ path: p, agent, mtimeMs: st.mtimeMs, size: st.size }); } catch { /* vanished */ }
    }
  };
  for (const r of roots) visit(r, 0);
  return { files, walkTruncated };
}

// Newest first, inside the window, at most maxFiles. `explicit` is [{ path, agent }] from the command line.
export function discover({ agents = AGENTS, roots = defaultRoots(), explicit = null, days = 30, maxFiles = 200, now = Date.now(), deadline = Infinity, clock = Date.now } = {}) {
  let files = [], walkTruncated = false;
  if (explicit) {
    for (const { path, agent } of explicit) {
      let st;
      try { st = statSync(path); } catch { continue; }
      if (st.isDirectory()) { const w = walk(agent, [path], { deadline, clock }); files.push(...w.files); walkTruncated ||= w.walkTruncated; }
      else files.push({ path, agent, mtimeMs: st.mtimeMs, size: st.size });
    }
  } else {
    for (const a of agents) { const w = walk(a, roots[a] || [], { deadline, clock }); files.push(...w.files); walkTruncated ||= w.walkTruncated; }
  }
  const cutoff = now - Math.max(0, days) * 86400000;
  const inWindow = days > 0 ? files.filter((f) => f.mtimeMs >= cutoff) : files;
  inWindow.sort((a, b) => b.mtimeMs - a.mtimeMs || (a.path < b.path ? -1 : 1));
  return { files: inWindow.slice(0, maxFiles), found: inWindow.length, outsideWindow: files.length - inWindow.length, walkTruncated };
}
