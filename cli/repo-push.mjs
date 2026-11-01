// Code pushed to a repository the project does not use (ATT&CK T1567.001 Exfiltration to Code Repository),
// judged from a shell command and the project's own git configuration.
//
// A push fires when its destination is none of the project's remotes as they stood before the agent touched
// them, and is not on the signed policy's codeRepoAllow (data/exfil-channels.js codeRepoAllowed):
//   url             `git push <url>` / `git push --repo=<url>` to a URL or scp-style address
//   session-remote  `git push <name>` to a remote this command, or (in the hook) an earlier call of the same
//                   session, added or re-pointed (`git remote add`, `git remote set-url`, `git config
//                   remote.<name>.url|pushurl`); a bare `git push` counts as a push to `origin` when origin was
//                   re-pointed
//   new-repo        `gh repo create … --push`: a repository the agent creates and fills in one step (silent when
//                   its OWNER/NAME is on codeRepoAllow under github.com)
// A local destination (a path, file://, loopback) never fires. The project's remotes are read from the git
// config of the directory the command runs in (`-C`, an earlier `cd` of the same command), a worktree's
// common config included. url.<base>.insteadOf rewriting is not applied: a URL is compared as written.
//
// Content-free: the result is kinds only; no URL, remote name or path leaves this module.
// Never throws: every error reads as "no finding".
import { readFileSync, statSync } from "node:fs";
import { resolve, dirname, join, isAbsolute } from "node:path";
import os from "node:os";
import { repoPushFacts, normRepoUrl, repoKey, codeRepoAllowed } from "../data/exfil-channels.js";

const MAX_CONFIG = 262144;

function readSmall(p) {
  try { const st = statSync(p); if (!st.isFile() || st.size > MAX_CONFIG) return null; return readFileSync(p, "utf8"); } catch { return null; }
}

// The repository a directory belongs to: { root, remotes: Map(name -> [url, …]) }, or null.
export function gitRemotesAt(dir) {
  try {
    let d = resolve(dir);
    for (let i = 0; i < 64; i++) {
      const dot = join(d, ".git");
      let st = null;
      try { st = statSync(dot); } catch { /* not here */ }
      if (st) {
        let gitdir = dot;
        if (st.isFile()) {
          const m = (readSmall(dot) || "").match(/^gitdir:\s*(.+?)\s*$/m);
          if (!m) return null;
          gitdir = isAbsolute(m[1]) ? m[1] : resolve(d, m[1]);
        }
        const common = (readSmall(join(gitdir, "commondir")) || "").trim();
        const cfg = readSmall(join(common ? resolve(gitdir, common) : gitdir, "config"));
        return { root: d, remotes: parseRemotes(cfg || "") };
      }
      const up = dirname(d);
      if (up === d) return null;
      d = up;
    }
  } catch { return null; }
  return null;
}

// `[remote "name"]` sections of a git config: url and pushurl values per remote.
export function parseRemotes(text) {
  const out = new Map();
  let cur = null;
  for (const raw of String(text).split(/\r?\n/).slice(0, 8192)) {
    const line = raw.replace(/^\s+/, "");
    const sec = line.match(/^\[\s*remote\s+"((?:[^"\\]|\\.){1,200})"\s*\]/i);
    if (sec) { cur = sec[1].replace(/\\(.)/g, "$1"); if (!out.has(cur)) out.set(cur, []); continue; }
    if (line.startsWith("[")) { cur = null; continue; }
    if (!cur) continue;
    const kv = line.match(/^(url|pushurl)\s*=\s*(.*?)\s*$/i);
    if (kv) out.get(cur).push(kv[2].replace(/^"(.*)"$/, "$1"));
  }
  return out;
}

const expand = (p, home) => (p === "~" || /^~[\\/]/.test(p) ? home + p.slice(1) : p);

// { hits: [{ kind }], remotes: [{ root, name }] }. `added(root, name)`: true for a remote an earlier call of this
// session added or re-pointed (the hook's session state; the Agent SDK passes none). `remotes` is what this
// command adds or re-points, for the caller to record.
export function repoPushVerdict({ command, ps = false, cwd = "", policy = null, added = () => false, home = os.homedir() } = {}) {
  const res = { hits: [], remotes: [] };
  try {
    const facts = repoPushFacts(command, { ps });
    if (!facts.pushes.length && !facts.remotes.length && !facts.ghPush.length) return res;
    const base = cwd || process.cwd();
    const dirOf = (rel) => resolve(base, expand(rel || ".", home));
    const repos = new Map();
    const repoAt = (dir) => { if (!repos.has(dir)) repos.set(dir, gitRemotesAt(dir)); return repos.get(dir); };
    for (const r of facts.remotes) { const dir = dirOf(r.dir); const g = repoAt(dir); res.remotes.push({ root: g ? g.root : dir, name: r.name }); }
    for (const p of facts.pushes) {
      const dir = dirOf(p.dir);
      const g = repoAt(dir);
      const root = g ? g.root : dir;
      const here = facts.remotes.filter((r) => { const gr = repoAt(dirOf(r.dir)); return (gr ? gr.root : dirOf(r.dir)) === root; });
      const touched = new Set(here.map((r) => r.name));
      if (g) for (const name of g.remotes.keys()) if (added(root, name)) touched.add(name);
      const known = new Set();
      if (g) for (const [name, urls] of g.remotes) if (!touched.has(name)) for (const u of urls) { const k = repoKey(normRepoUrl(u)); if (k) known.add(k); }
      let target = null, kind = "";
      const repo = p.repo || (touched.has("origin") ? "origin" : "");
      if (!repo) continue;
      const asUrl = normRepoUrl(repo);
      if (asUrl) { if (asUrl.local) continue; target = asUrl; kind = "url"; }
      else {
        if (!touched.has(repo)) continue;
        const set = here.filter((r) => r.name === repo).pop();
        const url = set ? set.url : g && g.remotes.get(repo) ? g.remotes.get(repo)[g.remotes.get(repo).length - 1] : null;
        const t = normRepoUrl(url);
        if (!t || t.local) continue;
        target = t; kind = "session-remote";
      }
      if (known.has(repoKey(target)) || codeRepoAllowed(policy, target)) continue;
      res.hits.push({ kind });
    }
    for (const gh of facts.ghPush) {
      if (gh.owner && codeRepoAllowed(policy, { host: "github.com", path: gh.name })) continue;
      res.hits.push({ kind: "new-repo" });
    }
  } catch { return res; }
  return res;
}
