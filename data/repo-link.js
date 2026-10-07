// Does a registry package link to a real repository that is actually its own? The pure half: parse the
// repository a package DECLARES, compare two repositories, read a package name out of a repository's own
// manifest, and propose where a monorepo keeps the package. No I/O (browser-safe, like the rest of
// data/); cli/mcp-repo-link.mjs does the fetching.
//
// What the registries give us, as measured on real responses (2026-09-29):
//   npm   GET registry.npmjs.org/<name>/<version> → `repository`: a string ("owner/repo", "github:o/r",
//         a URL) or {type, url, directory}; `dist.attestations` when published with provenance.
//         @modelcontextprotocol/server-filesystem declares git+https://github.com/modelcontextprotocol/
//         servers.git with NO directory — a monorepo root whose package.json is not the package's.
//   PyPI  GET pypi.org/pypi/<name>/<version>/json → `info.project_urls` (free-form keys: "Source",
//         "Repository", "Homepage", …) and `info.home_page`. mcp-server-fetch's "Repository" is
//         https://github.com/modelcontextprotocol/servers/tree/main/src/fetch — the directory rides in
//         the URL path.

export const REPO_HOSTS = ["github.com", "gitlab.com", "bitbucket.org", "codeberg.org"];
// Hosts cli/mcp-repo-link.mjs can read a manifest from without an API token.
export const VERIFIABLE_HOSTS = ["github.com", "gitlab.com"];

const SHORTHAND_HOST = { github: "github.com", gitlab: "gitlab.com", bitbucket: "bitbucket.org" };
const OWNER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;
const DIR_SEG = /^[A-Za-z0-9._@+-]{1,200}$/;

function cleanDir(d) {
  const segs = String(d || "").replace(/\\/g, "/").split("/").filter((s) => s && s !== ".");
  if (segs.some((s) => s === ".." || !DIR_SEG.test(s))) return null;
  return segs.join("/");
}

// A repository reference → {host, owner, repo, directory} | null. Accepts the forms npm documents for
// `repository` (URL, "github:o/r", bare "o/r" meaning GitHub) and the browse URLs PyPI projects list
// (…/tree/<ref>/<dir>, …/blob/<ref>/<file>, GitLab's /-/tree/). Anything else is null (malformed).
export function parseRepoUrl(raw, { directory = "" } = {}) {
  let s = String(raw || "").trim();
  if (!s || s.length > 500) return null;
  const sh = /^(github|gitlab|bitbucket):([^/\s]+)\/([^/\s#]+)$/i.exec(s);
  if (sh) return finish(SHORTHAND_HOST[sh[1].toLowerCase()], sh[2], sh[3], [], directory);
  if (/^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9._-]+$/.test(s)) {
    const [o, r] = s.split("/");
    return finish("github.com", o, r, [], directory);
  }
  s = s.replace(/^git\+/i, "");
  const scp = /^[\w.-]+@([\w.-]+):(.+)$/.exec(s);          // git@github.com:o/r.git
  if (scp) s = `ssh://${scp[1]}/${scp[2]}`;
  let u;
  try { u = new URL(s); } catch { return null; }
  if (!/^(?:https?|git|ssh|git\+ssh):$/i.test(u.protocol)) return null;
  const host = u.hostname.toLowerCase().replace(/^www\./, "");
  if (!host || !host.includes(".")) return null;
  const segs = decodeURIComponent(u.pathname).split("/").filter(Boolean);
  if (segs.length < 2) return null;
  const tail = segs.slice(2);
  return finish(host, segs[0], segs[1], tail, directory);
}

function finish(host, owner, repo, tail, directory) {
  const r = String(repo).replace(/\.git$/i, "");
  if (!OWNER.test(owner) || !REPO.test(r) || r === "." || r === "..") return null;
  let dir = cleanDir(directory);
  if (dir === null) dir = "";
  if (!dir && tail.length) {
    const t = tail[0] === "-" ? tail.slice(1) : tail;       // GitLab: /-/tree/<ref>/<dir>
    if ((t[0] === "tree" || t[0] === "blob") && t.length > 2) {
      const rest = t.slice(2);
      const d = cleanDir((t[0] === "blob" ? rest.slice(0, -1) : rest).join("/"));
      if (d) dir = d;
    }
  }
  return { host, owner, repo: r, directory: dir };
}

export const repoKey = (r) => r ? `${r.host}/${r.owner}/${r.repo}`.toLowerCase() : "";
export const sameRepo = (a, b) => !!a && !!b && repoKey(a) === repoKey(b);

// npm version document → {status: "ok"|"none"|"malformed", repo}
export function npmDeclaredRepo(doc) {
  const r = doc && doc.repository;
  if (r == null || r === "") return { status: "none", repo: null };
  const url = typeof r === "string" ? r : r && typeof r.url === "string" ? r.url : "";
  if (!url) return { status: "none", repo: null };
  const repo = parseRepoUrl(url, { directory: typeof r === "object" && typeof r.directory === "string" ? r.directory : "" });
  return repo ? { status: "ok", repo } : { status: "malformed", repo: null };
}

const PYPI_SOURCE_KEY = /^(?:source(?:[\s_-]*code)?|repository|repo|code|github|gitlab|git)$/i;

// PyPI `info` → {status, repo, hints: [directory …]}. The source-ish keys first, then any code-host URL
// among the others (Homepage is often the repository). Directories named by OTHER urls into the same
// repository (a CHANGELOG blob link) become monorepo hints.
export function pypiDeclaredRepo(info) {
  const urls = [];
  const pu = info && info.project_urls && typeof info.project_urls === "object" ? info.project_urls : {};
  for (const [k, v] of Object.entries(pu)) if (typeof v === "string") urls.push([k, v]);
  if (info && typeof info.home_page === "string" && info.home_page) urls.push(["home_page", info.home_page]);
  const parsed = urls.map(([k, v]) => [k, parseRepoUrl(v)]).filter(([, r]) => r);
  const onHost = parsed.filter(([, r]) => REPO_HOSTS.includes(r.host));
  const pick = onHost.find(([k]) => PYPI_SOURCE_KEY.test(k)) || onHost[0] || parsed.find(([k]) => PYPI_SOURCE_KEY.test(k));
  if (!pick) {
    const declared = urls.some(([k]) => PYPI_SOURCE_KEY.test(k));
    return { status: declared ? "malformed" : "none", repo: null, hints: [] };
  }
  const repo = pick[1];
  const hints = [...new Set(onHost.filter(([, r]) => sameRepo(r, repo) && r.directory && r.directory !== repo.directory).map(([, r]) => r.directory))];
  return { status: "ok", repo, hints };
}

// PEP 503 normalisation; npm names compare exactly (lower-cased: the registry refuses upper case).
export function normalizeName(eco, n) {
  const s = String(n || "").trim().toLowerCase();
  return eco === "pypi" ? s.replace(/[-_.]+/g, "-") : s;
}
export const sameName = (eco, a, b) => !!a && !!b && normalizeName(eco, a) === normalizeName(eco, b);

function tomlSection(text, header) {
  const lines = String(text).split(/\r?\n/);
  const out = [];
  let inside = false;
  for (const l of lines) {
    const h = /^\s*\[([^\]]+)\]\s*(?:#.*)?$/.exec(l);
    if (h) { inside = h[1].trim() === header; continue; }
    if (inside) out.push(l);
  }
  return out.join("\n");
}
// `(?<!^\s*?\n)` as in manifestInfo below: a line start reached from an earlier one through blank lines alone
// is not a new start (quadratic on a run of blank lines without it).
const tomlString = (sec, key) => { const m = new RegExp(`^(?<!^\\s*?\\n)\\s*${key}\\s*=\\s*["']([^"'\\n]+)["']`, "m").exec(sec); return m ? m[1].trim() : null; };
function tomlArray(sec, key) {
  const m = new RegExp(`^(?<!^\\s*?\\n)\\s*${key}\\s*=\\s*\\[([\\s\\S]*?)\\]`, "m").exec(sec);
  return m ? [...m[1].matchAll(/["']([^"'\n]+)["']/g)].map((x) => x[1]) : [];
}

// A manifest's text → {name, workspaces: [glob …], dynamic}. `workspaces` non-empty marks a monorepo
// root, whose own name is expected to differ from any one package's.
export function manifestInfo(file, text) {
  const f = String(file).split("/").pop();
  if (f === "package.json") {
    let j;
    try { j = JSON.parse(text); } catch { return { name: null, workspaces: [], dynamic: false }; }
    const ws = Array.isArray(j.workspaces) ? j.workspaces : j.workspaces && Array.isArray(j.workspaces.packages) ? j.workspaces.packages : [];
    return { name: typeof j.name === "string" ? j.name : null, workspaces: ws.filter((x) => typeof x === "string"), dynamic: false, private: j.private === true };
  }
  if (f === "pyproject.toml") {
    const project = tomlSection(text, "project");
    const name = tomlString(project, "name") || tomlString(tomlSection(text, "tool.poetry"), "name");
    const ws = tomlArray(tomlSection(text, "tool.uv.workspace"), "members");
    // `(?<!^\s*?\n)`: skip a line start that an earlier line start reaches through blank lines alone (that
    // one was tried first and sees the same text). Without it each line of a blank run was a start whose `\s*`
    // ran to the end of the run: quadratic. Same for setup.cfg below. See test/data-regex-redos.test.mjs.
    const dynamic = !name && /^(?<!^\s*?\n)\s*dynamic\s*=.*\bname\b/m.test(project);
    return { name, workspaces: ws, dynamic };
  }
  if (f === "setup.cfg") {
    const m = /^(?<!^\s*?\n)\s*name\s*=\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*$/m.exec(tomlSection(text, "metadata"));
    return { name: m ? m[1] : null, workspaces: [], dynamic: !m };
  }
  if (f === "setup.py") {
    const i = String(text).search(/\bsetup\s*\(/);
    const m = i >= 0 ? /\bname\s*=\s*["']([^"'\n]+)["']/.exec(String(text).slice(i)) : null;
    return { name: m ? m[1] : null, workspaces: [], dynamic: !m };
  }
  return { name: null, workspaces: [], dynamic: false };
}

// Where a monorepo keeps `name`: every "<dir>/*" workspace glob × the name's likely leaf directories,
// plus directories the registry itself pointed at. Bounded; the caller stops at the first match.
export function candidateDirs(eco, name, workspaces = [], hints = [], max = 6) {
  const base = String(name || "").toLowerCase().replace(/^@[^/]+\//, "").replace(/^[a-z0-9-]+\.(?=[a-z])/, (m) => (eco === "pypi" ? "" : m));
  const leaves = new Set([base]);
  let core = base;
  for (const p of ["mcp-server-", "server-", "mcp-"]) if (core.startsWith(p) && core.length > p.length) { core = core.slice(p.length); break; }
  for (const s of ["-mcp-server", "-server", "-mcp"]) if (core.endsWith(s) && core.length > s.length) { core = core.slice(0, -s.length); break; }
  leaves.add(core);
  if (eco === "pypi") leaves.add(base.replace(/_/g, "-"));
  const out = [...hints.map(cleanDir).filter(Boolean)];
  for (const g of workspaces) {
    const m = /^(?:\.\/)?([A-Za-z0-9._/-]+?)\/\*{1,2}$/.exec(String(g));
    if (!m) continue;
    for (const leaf of leaves) out.push(`${m[1]}/${leaf}`);
  }
  return [...new Set(out)].slice(0, max);
}
