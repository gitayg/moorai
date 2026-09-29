// Does an MCP server's npm / PyPI package link to a real repository that is actually its own? OPT-IN
// network: reached only through cli/mcp-reputation.mjs's registry lookup (policy mcpReputation.lookup =
// "registry", the proxy path). The hook scores offline and never gets here.
//
// ORDER, cheapest proof first:
//   1. the registry's version document (the same public name + version npx/uvx send).
//   2. registry-held PROVENANCE, when the publisher produced it. npm: `dist.attestations` → the SLSA
//      predicate's workflow.repository. npm's docs: "Ensure your package.json is configured with a public
//      repository that matches (case-sensitive) where you are publishing with provenance from." PyPI:
//      GET /integrity/<project>/<version>/<file>/provenance → attestation_bundles[].publisher.repository
//      (Trusted Publishing). The registry checked the link at publish time; we read, we do NOT re-verify
//      the Sigstore signature.
//   3. otherwise the repository's OWN manifest at the declared directory (or the root), read raw from
//      github.com / gitlab.com: package.json "name", pyproject [project] / [tool.poetry] name, setup.cfg,
//      setup.py. A monorepo root (workspaces / [tool.uv.workspace]) is searched at a few bounded
//      candidate directories; not finding the package there is UNVERIFIED, never a mismatch.
//
// Reason codes (weights in data/mcp-reputation.js): repo-missing (nothing declared, or unparseable),
// repo-unreachable (the host says the declared repository is not publicly there), repo-mismatch
// (provenance or the repository's own manifest names a different package). Everything else — timeouts,
// 5xx, rate limits, a host we cannot read, a dynamic name — is evidence only: unknown is not bad.
//
// PRIVACY: requests carry the public package name / version to its public registry and the public
// owner / repo / directory the registry itself published to the code host. No local path, argument,
// environment value or identifying header. Redirects are followed by hand, at most twice, and only
// within the host set below.

import { npmDeclaredRepo, pypiDeclaredRepo, parseRepoUrl, sameRepo, sameName, manifestInfo, candidateDirs, VERIFIABLE_HOSTS } from "../data/repo-link.js";

const NPM = "https://registry.npmjs.org/";
const PYPI = "https://pypi.org/";
const ALLOWED_HOSTS = new Set(["registry.npmjs.org", "pypi.org", "github.com", "raw.githubusercontent.com", "gitlab.com"]);
const MAX_BYTES = 2 * 1024 * 1024;
export const REPO_LINK_LIMITS = { requestMs: 4000, budgetMs: 10000, maxRequests: 12 };

class Budget {
  constructor(fetchImpl, limits, now) {
    this.fetchImpl = fetchImpl; this.limits = limits; this.now = now;
    this.deadline = now() + limits.budgetMs; this.used = 0;
  }
  // → {status, text, location} | {status: 0} on any transport failure, the budget or a disallowed host.
  async get(url, accept, hops = 0) {
    const left = this.deadline - this.now();
    let u;
    try { u = new URL(url); } catch { return { status: 0 }; }
    if (u.protocol !== "https:" || !ALLOWED_HOSTS.has(u.hostname) || left <= 0 || this.used >= this.limits.maxRequests) return { status: 0 };
    this.used++;
    let res;
    try {
      res = await this.fetchImpl(u.href, { method: "GET", redirect: "manual", headers: accept ? { accept } : {}, signal: AbortSignal.timeout(Math.min(this.limits.requestMs, left)) });
    } catch { return { status: 0 }; }
    if (!res) return { status: 0 };
    const location = res.headers && res.headers.get ? res.headers.get("location") : null;
    if (res.status >= 300 && res.status < 400 && location && hops < 2) {
      let next;
      try { next = new URL(location, u.href); } catch { return { status: res.status, location }; }
      if (ALLOWED_HOSTS.has(next.hostname) && !/\/users\/sign_in\b|\/login\b/.test(next.pathname)) return this.get(next.href, accept, hops + 1);
      return { status: res.status, location: next.href };
    }
    if (res.status !== 200) return { status: res.status };
    try {
      const text = await res.text();
      return text.length > MAX_BYTES ? { status: 0 } : { status: 200, text };
    } catch { return { status: 0 }; }
  }
  async json(url, accept = "application/json") {
    const r = await this.get(url, accept);
    if (r.status !== 200) return { status: r.status };
    try { return { status: 200, json: JSON.parse(r.text) }; } catch { return { status: 0 }; }
  }
}

const enc = (s) => encodeURIComponent(s);
const encPath = (p) => String(p).split("/").filter(Boolean).map(enc).join("/");

function rawUrl(repo, path) {
  const p = encPath(path);
  if (repo.host === "github.com") return `https://raw.githubusercontent.com/${enc(repo.owner)}/${enc(repo.repo)}/HEAD/${p}`;
  return `https://gitlab.com/${enc(repo.owner)}/${enc(repo.repo)}/-/raw/HEAD/${p}`;
}
const repoPage = (repo) => `https://${repo.host}/${enc(repo.owner)}/${enc(repo.repo)}`;

// ---- provenance ----------------------------------------------------------------------------------
function b64json(s) {
  try { return JSON.parse(Buffer.from(String(s), "base64").toString("utf8")); } catch { return null; }
}

async function npmProvenanceRepo(doc, b) {
  const att = doc && doc.dist && doc.dist.attestations;
  if (!att || typeof att.url !== "string" || !att.provenance) return null;
  let u;
  try { u = new URL(att.url); } catch { return null; }
  if (u.hostname !== "registry.npmjs.org") return null;
  const r = await b.json(u.href);
  if (r.status !== 200 || !Array.isArray(r.json && r.json.attestations)) return null;
  for (const a of r.json.attestations) {
    if (!a || !/slsa\.dev\/provenance/.test(String(a.predicateType))) continue;
    const env = a.bundle && a.bundle.dsseEnvelope;
    const st = env && b64json(env.payload);
    const wf = st && st.predicate && st.predicate.buildDefinition && st.predicate.buildDefinition.externalParameters && st.predicate.buildDefinition.externalParameters.workflow;
    const repo = wf && typeof wf.repository === "string" ? parseRepoUrl(wf.repository) : null;
    if (repo) return repo;
  }
  return null;
}

const PUBLISHER_HOST = { github: "github.com", gitlab: "gitlab.com" };
async function pypiProvenanceRepo(name, doc, b) {
  const version = doc && doc.info && doc.info.version;
  const file = Array.isArray(doc && doc.urls) ? doc.urls.find((f) => f && typeof f.filename === "string") : null;
  if (!version || !file) return null;
  const r = await b.json(`${PYPI}integrity/${enc(name)}/${enc(version)}/${enc(file.filename)}/provenance`, "application/vnd.pypi.integrity.v1+json");
  if (r.status !== 200 || !Array.isArray(r.json && r.json.attestation_bundles)) return null;
  for (const bundle of r.json.attestation_bundles) {
    const p = bundle && bundle.publisher;
    const host = p && PUBLISHER_HOST[String(p.kind || "").toLowerCase()];
    if (host && typeof p.repository === "string") {
      const repo = parseRepoUrl(`https://${host}/${p.repository}`);
      if (repo) return repo;
    }
  }
  return null;
}

// ---- the repository's own manifest -----------------------------------------------------------------
const MANIFESTS = { npm: ["package.json"], pypi: ["pyproject.toml", "setup.cfg", "setup.py"] };

// → {state: "found", info} | {state: "absent"} | {state: "error"}
async function readManifest(eco, repo, dir, b, files = MANIFESTS[eco]) {
  let sawError = false;
  for (const f of files) {
    const r = await b.get(rawUrl(repo, dir ? `${dir}/${f}` : f));
    if (r.status === 200) {
      const info = manifestInfo(f, r.text);
      if (info.name || info.workspaces.length || f === files[files.length - 1]) return { state: "found", info };
      continue;
    }
    if (r.status !== 404) sawError = true;
  }
  return { state: sawError ? "error" : "absent" };
}

// 404 on github.com, or GitLab bouncing to sign-in (its answer for both "missing" and "private").
async function repoExists(repo, b) {
  const r = await b.get(repoPage(repo));
  if (r.status === 200) return true;
  if (r.status === 404 || r.status === 410) return false;
  if (r.status >= 300 && r.status < 400 && /\/users\/sign_in\b/.test(String(r.location || ""))) return false;
  return null;
}

// ---- entry point ---------------------------------------------------------------------------------
// ref = {ecosystem: "npm"|"pypi", name, version?} → {signals: [code], evidence: [code]}
export async function checkRepoLink(ref, { fetchImpl = globalThis.fetch, limits = REPO_LINK_LIMITS, now = Date.now } = {}) {
  const eco = ref && ref.ecosystem;
  if ((eco !== "npm" && eco !== "pypi") || !ref.name) return { signals: [], evidence: [] };
  const b = new Budget(fetchImpl, { ...REPO_LINK_LIMITS, ...limits }, now);
  const out = (signals, ...evidence) => ({ signals, evidence });

  const meta = eco === "npm"
    ? await b.json(`${NPM}${String(ref.name).replace("/", "%2f")}/${enc(ref.version || "latest")}`)
    : await b.json(`${PYPI}pypi/${enc(ref.name)}/${ref.version ? `${enc(ref.version)}/` : ""}json`);
  if (meta.status === 404) return out([], "repo-registry-404");
  if (meta.status !== 200 || !meta.json) return out([], "repo-check-failed");

  const declared = eco === "npm" ? npmDeclaredRepo(meta.json) : pypiDeclaredRepo(meta.json.info);
  if (declared.status !== "ok") return out(["repo-missing"], declared.status === "none" ? "repo-none-declared" : "repo-malformed");
  const repo = declared.repo;

  const prov = eco === "npm" ? await npmProvenanceRepo(meta.json, b) : await pypiProvenanceRepo(ref.name, meta.json, b);
  if (prov) return sameRepo(prov, repo) ? out([], "repo-provenance") : out(["repo-mismatch"], "repo-provenance-other-repo");

  if (!VERIFIABLE_HOSTS.includes(repo.host)) return out([], "repo-host-unverified");

  const at = await readManifest(eco, repo, repo.directory, b);
  if (at.state === "error") return out([], "repo-check-failed");
  if (at.state === "absent") {
    const exists = await repoExists(repo, b);
    if (exists === false) return out(["repo-unreachable"]);
    if (exists === null) return out([], "repo-check-failed");
    if (repo.directory) return out([], "repo-unverified");
  } else {
    if (sameName(eco, at.info.name, ref.name)) return out([], "repo-verified");
    // The declared directory is the package's own manifest: another name there is a borrowed link.
    if (repo.directory) return at.info.name ? out(["repo-mismatch"]) : out([], "repo-unverified");
  }

  // No directory declared and the root is not the package: look where a monorepo would keep it,
  // stopping at the first manifest that names it.
  const ws = at.state === "found" ? at.info.workspaces : [];
  const dirs = candidateDirs(eco, ref.name, ws.length ? ws : ["packages/*", "src/*"], declared.hints || []);
  for (const d of dirs) {
    const c = await readManifest(eco, repo, d, b, eco === "npm" ? ["package.json"] : ["pyproject.toml"]);
    if (c.state === "found" && sameName(eco, c.info.name, ref.name)) return out([], "repo-verified", "repo-monorepo");
  }
  // Not found. A monorepo root (workspaces, a private npm root, a nameless Python root) may keep it
  // anywhere: unverified. A single-package root that names another package is a borrowed link.
  const info = at.state === "found" ? at.info : null;
  const monorepoRoot = !info || info.workspaces.length > 0 || info.private === true || !info.name;
  return monorepoRoot ? out([], "repo-unverified") : out(["repo-mismatch"]);
}
