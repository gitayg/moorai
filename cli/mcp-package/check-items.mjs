// The ten pre-install checks of `moorai-mcp-check`, as pure functions of facts already gathered
// (cli/mcp-package/check.mjs gathers them). Each returns {id, title, status, reason, codes}:
//   status  "pass" | "warn" | "fail" | "not-checked" — "not-checked" whenever metadata cannot answer;
//           never a pass by default.
//   codes   reputation category codes the check contributed (data/mcp-reputation.js weights).

import { nameFindings, lifecycleFindings } from "./heuristics.mjs";
import { maintainerInfo } from "./maintainers.mjs";
import { pinKind } from "./check-spec.mjs";
import { classifyMcpName } from "../../data/mcp-reputation.js";
import { egressFrom, egressChain, judgeTargets, urlTargets } from "../egress-rules.mjs";

export const NEW_PACKAGE_DAYS = 30; // the same window cli/mcp-package.mjs uses for its new-package note
const DAY_MS = 24 * 3600 * 1000;

const item = (id, title, status, reason, codes = []) => ({ id, title, status, reason, codes });
const NC = "not-checked";

function metaReason(meta) {
  if (!meta) return "registry metadata was not requested";
  if (meta.status === 404) return "the registry has no such package";
  return meta.status ? `registry metadata unavailable (HTTP ${meta.status})` : "registry metadata unavailable (network error or timeout)";
}

// ---- 1. publisher identity and typosquat -----------------------------------------------------------
const FAIL_CODES = new Set(["pkg-known-malicious", "mcp-typosquat", "pkg-typosquat", "repo-mismatch", "name-not-published"]);
const CODE_TEXT = {
  "pkg-known-malicious": "matches a documented malicious package name",
  "mcp-typosquat": "near-miss of a popular MCP server name",
  "pkg-typosquat": "near-miss of a popular library name",
  "pkg-ecosystem-confusion": "a popular name from another ecosystem",
  "name-not-published": "not on the registry: anyone can claim the name",
  "repo-mismatch": "its declared repository publishes a different package",
  "repo-unreachable": "its declared repository is not publicly there",
  "repo-missing": "no repository declared"
};
const POSITIVE = { "catalogue-listed": "on MoorAI's popular MCP server list", "repo-verified": "repository manifest names this package", "repo-provenance": "registry provenance matches the declared repository" };

export function checkPublisher(f) {
  const T = "Publisher identity and typosquat";
  if (f.spec.kind === "remote") return item("publisher", T, NC, "a remote endpoint has no registry publisher; its host is judged under transport");
  const ref = f.spec.ref;
  const codes = nameFindings(ref).map((x) => x.threatId);
  const listed = classifyMcpName(ref.name, ref.ecosystem);
  if (listed === "typosquat") codes.push("mcp-typosquat");
  const scopedNpm = ref.ecosystem === "npm" && ref.name.startsWith("@");
  if (f.meta && f.meta.status === 404 && !scopedNpm) codes.push("name-not-published");
  if (f.repo) codes.push(...f.repo.signals);
  const uniq = [...new Set(codes)];
  const text = (cs) => cs.map((c) => `${CODE_TEXT[c] || c} (${c})`).join("; ");
  const fails = uniq.filter((c) => FAIL_CODES.has(c));
  if (fails.length) return item("publisher", T, "fail", text(fails), uniq);
  if (uniq.length) return item("publisher", T, "warn", text(uniq), uniq);
  if (f.meta && f.meta.status === 404) return item("publisher", T, "warn", "not public on npm (a private scoped package, or an unclaimed scope)", uniq);
  const good = [...(listed === "listed" ? ["catalogue-listed"] : []), ...((f.repo && f.repo.evidence) || []).filter((e) => POSITIVE[e])];
  if (good.length) return item("publisher", T, "pass", `no typosquat; ${good.map((g) => POSITIVE[g]).join("; ")}`, uniq);
  const why = !f.repo ? "the repository link was not checked" : (f.repo.evidence || []).includes("repo-check-failed") ? "the repository check failed" : "the repository link could not be confirmed";
  return item("publisher", T, "warn", `no typosquat, but the publisher is unverified: ${why}`, uniq);
}

// ---- 2. package age -------------------------------------------------------------------------------
export function createdAt(eco, doc) {
  if (!doc) return null;
  if (eco === "npm") { const t = Date.parse(doc.time && doc.time.created); return Number.isFinite(t) ? t : null; }
  let min = null;
  for (const files of Object.values(doc.releases || {})) for (const x of files || []) {
    const t = Date.parse((x && (x.upload_time_iso_8601 || x.upload_time)) || "");
    if (Number.isFinite(t) && (min === null || t < min)) min = t;
  }
  return min;
}

export function checkAge(f) {
  const T = "Package age";
  if (f.spec.kind === "remote") return item("age", T, NC, "a remote endpoint has no publish date");
  if (!f.meta || f.meta.status !== 200) return item("age", T, NC, metaReason(f.meta));
  const t = createdAt(f.spec.kind, f.meta.doc);
  if (t === null) return item("age", T, NC, "the registry metadata carries no first-publish time");
  const days = Math.max(0, Math.floor((f.now - t) / DAY_MS));
  if (days < NEW_PACKAGE_DAYS) return item("age", T, "warn", `first published ${days} day(s) ago, under ${NEW_PACKAGE_DAYS} (new-package)`, ["new-package"]);
  return item("age", T, "pass", `first published ${days} days ago`);
}

// ---- 3. maintainers -----------------------------------------------------------------------------
export function checkMaintainerCount(f) {
  const T = "Maintainers";
  if (f.spec.kind === "remote") return item("maintainers", T, NC, "a remote endpoint has no registry maintainers");
  if (!f.meta || f.meta.status !== 200) return item("maintainers", T, NC, metaReason(f.meta));
  const info = maintainerInfo(f.spec.kind, f.meta.doc);
  if (!info || info.count === 0) {
    return item("maintainers", T, NC, f.spec.kind === "pypi" ? "PyPI returned no ownership roles for this project" : "the packument has no maintainers list");
  }
  if (info.org) return item("maintainers", T, "pass", `owned by a PyPI organization (${info.count} role(s) listed; team access is not listed)`);
  if (info.count === 1) return item("maintainers", T, "warn", "one account can publish (single-maintainer): common for small projects, a weak signal alone", ["single-maintainer"]);
  return item("maintainers", T, "pass", `${info.count} accounts can publish`);
}

// ---- 4. install scripts -------------------------------------------------------------------------
export function checkInstallScripts(f) {
  const T = "Install scripts";
  if (f.spec.kind === "remote") return item("install-scripts", T, NC, "nothing is installed for a remote endpoint");
  if (!f.meta || f.meta.status !== 200) return item("install-scripts", T, NC, metaReason(f.meta));
  if (f.spec.kind === "pypi") {
    const files = (f.meta.doc.releases || {})[f.version] || f.meta.doc.urls || [];
    const wheel = files.some((x) => x && x.packagetype === "bdist_wheel");
    return item("install-scripts", T, NC, `PyPI's JSON API does not expose install-time code (setup.py, build backend)${files.length && !wheel ? "; this release is sdist-only, so installing it builds it from source" : ""}`);
  }
  if (!f.manifest) return item("install-scripts", T, NC, f.version ? `version ${f.version} is not in the packument` : "no version manifest to read");
  const fs = lifecycleFindings(f.manifest.scripts);
  const at = f.versionNote ? ` (${f.versionNote})` : "";
  if (!fs.length) return item("install-scripts", T, "pass", `no preinstall, install or postinstall script in ${f.version}${at}`);
  const codes = [...new Set(fs.map((x) => x.threatId))];
  const hooks = ["preinstall", "install", "postinstall"].filter((k) => typeof (f.manifest.scripts || {})[k] === "string" && f.manifest.scripts[k].trim());
  if (codes.includes("pkg-install-script-remote")) return item("install-scripts", T, "fail", `${hooks.join(", ")} fetches or pipes remote code at install (pkg-install-script-remote)${at}`, codes);
  return item("install-scripts", T, "warn", `${hooks.join(", ")} runs code at install (pkg-install-script)${at}`, codes);
}

// ---- server.json helpers (checks 5 and 7) ---------------------------------------------------------
function sjReason(sj) {
  switch (sj && sj.state) {
    case "none-declared": return "the package declares no MCP Registry name (npm mcpName / PyPI mcp-name:), so there is no published server.json";
    case "not-found": return "the MCP Registry has no server.json under the name the package declares";
    case "mismatch": return "the published server.json does not list this package";
    case "failed": return "the MCP Registry lookup failed";
    default: return "no published server.json was looked up";
  }
}
const inputs = (list) => (Array.isArray(list) ? list.filter((x) => x && typeof x.name === "string" && x.name) : []);
const SAFE_NAME = /^[A-Za-z0-9_.-]{1,64}$/;
const shown = (names) => names.filter((n) => SAFE_NAME.test(n)).join(", ");

// ---- 5. authentication --------------------------------------------------------------------------
export function checkAuth(f) {
  const T = "Authentication";
  if (f.spec.kind === "remote") return item("auth", T, NC, "no published server.json for a bare URL; MCP OAuth is negotiated at connect time and is not probed");
  if (!f.serverJson || f.serverJson.state !== "found") return item("auth", T, NC, sjReason(f.serverJson));
  const pkg = f.serverJson.pkg;
  const tr = (pkg.transport && pkg.transport.type) || "stdio";
  const secrets = [...inputs(pkg.environmentVariables), ...inputs(pkg.transport && pkg.transport.headers)].filter((x) => x.isSecret === true).map((x) => x.name);
  if (secrets.length) return item("auth", T, "pass", `expects a token: ${shown(secrets) || `${secrets.length} secret input(s)`} (isSecret in server.json)`);
  if (tr === "stdio") return item("auth", T, "pass", "stdio transport: no network listener to authenticate, and server.json declares no secret");
  return item("auth", T, "warn", `${tr} transport with no token documented in server.json; OAuth, if any, is discovered at connect time and is not checked`);
}

// ---- 6. transport and egress ---------------------------------------------------------------------
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

function endpointOf(f) {
  if (f.spec.kind === "remote") return { url: f.spec.url, type: null };
  const t = f.serverJson && f.serverJson.state === "found" && f.serverJson.pkg.transport;
  if (t && (t.type === "streamable-http" || t.type === "sse") && typeof t.url === "string") return { url: t.url, type: t.type };
  return null;
}

export function checkTransport(f) {
  const T = "Transport and egress";
  const ep = endpointOf(f);
  if (!ep) {
    const why = f.serverJson && f.serverJson.state === "found" ? "stdio package" : "no published server.json and no URL";
    return item("transport", T, NC, `${why}: the hosts it connects to are not declared in registry metadata`);
  }
  if (/\{[A-Za-z_][A-Za-z0-9_]*\}/.test(ep.url)) return item("transport", T, NC, "the endpoint is a URL template resolved at configuration time");
  let u;
  try { u = new URL(ep.url); } catch { return item("transport", T, "fail", "the endpoint is not a valid URL"); }
  const host = u.hostname.toLowerCase();
  const loop = LOOPBACK.has(host);
  const codes = f.spec.kind === "remote" ? ["remote-server"] : [];
  const problems = [];
  if (IPV4.test(host) && !loop || host.startsWith("[") && !loop) problems.push("a bare IP address, not a hostname");
  if (u.protocol !== "https:" && !loop) problems.push("plain HTTP, not HTTPS");
  if (problems.length) return item("transport", T, "fail", `endpoint ${host} is ${problems.join(" and ")}`, codes);
  const eg = egressFrom({ policy: f.policy, system: f.system });
  const base = loop ? `loopback endpoint ${host}` : `HTTPS to hostname ${host}`;
  if (!eg.sources.length && !eg.defaults.length) return item("transport", T, "pass", `${base}; no egressRules in policy to fit`, codes);
  const targets = urlTargets(u.href, { method: ep.type === "sse" ? "GET" : "POST" });
  const { verdicts, worst } = judgeTargets(targets, egressChain(null, eg));
  const v = verdicts.find((x) => x.action === worst) || verdicts[0];
  const by = v ? (v.ref === "default" ? "egressDefault" : v.ruleId ? `rule "${v.ruleId}" (${v.ref})` : v.ref) : "egressDefault";
  if (worst === "block") return item("transport", T, "fail", `${base}, but egress to it is blocked by ${by}`, codes);
  if (worst === "alert") return item("transport", T, "warn", `${base}; egress to it alerts under ${by}`, codes);
  return item("transport", T, "pass", `${base}; allowed by ${by}`, codes);
}

// ---- 7. permissions and credential scope ----------------------------------------------------------
// Names that, by convention, carry account-, cluster-, database- or wallet-wide authority rather than a
// scoped API token. A token whose scope depends on how it was minted (GITHUB_TOKEN, *_API_KEY) is not
// flagged: its name cannot tell a fine-grained token from a classic one.
export const BROAD_CREDENTIAL = [
  /^AWS_(SECRET_ACCESS_KEY|SESSION_TOKEN)$/, /^AZURE_CLIENT_SECRET$/, /^GOOGLE_APPLICATION_CREDENTIALS$/, /^KUBECONFIG$/,
  /(^|_)(ADMIN|ROOT|MASTER|SUPERUSER|SERVICE_ROLE)(_|$)/, /(^|_)PASS(WORD|WD)?(_|$)/,
  /(^|_)(DATABASE_URL|DSN|CONNECTION_STRING)$/, /(^|_)PRIVATE_KEY(_|$)/, /(^|_)(MNEMONIC|SEED_PHRASE)(_|$)/
];

export function checkCredentials(f) {
  const T = "Permissions and credential scope";
  if (f.spec.kind === "remote") return item("credentials", T, NC, "no published server.json for a bare URL");
  if (!f.serverJson || f.serverJson.state !== "found") return item("credentials", T, NC, sjReason(f.serverJson));
  const pkg = f.serverJson.pkg;
  const names = [...new Set([...inputs(pkg.environmentVariables), ...inputs(pkg.transport && pkg.transport.headers)].map((x) => x.name))];
  if (!names.length) return item("credentials", T, "pass", "server.json declares no environment variables or headers");
  const broad = names.filter((n) => BROAD_CREDENTIAL.some((re) => re.test(n.toUpperCase())));
  if (broad.length) return item("credentials", T, "warn", `broad credential(s): ${shown(broad) || broad.length}; needs ${shown(names) || `${names.length} variable(s)`}`);
  return item("credentials", T, "pass", `needs ${shown(names) || `${names.length} variable(s)`} (names only); none is a broad credential`);
}

// ---- 8. tool descriptions ------------------------------------------------------------------------
export function checkTools(f) {
  const T = "Tool descriptions";
  if (!f.toolScan) return item("tools", T, NC, "the tool list is only advertised by a running server; pass --tools <tools/list JSON> to scan one you already have (the proxy and gateway scan it at runtime)");
  const { tools, codes } = f.toolScan;
  if (!tools) return item("tools", T, NC, "the --tools file has no tools");
  const uniq = [...new Set(codes)];
  if (uniq.includes("tool-poisoning") || uniq.includes("tool-hidden-content")) return item("tools", T, "fail", `${tools} tool(s) scanned: ${uniq.join(", ")}`, uniq);
  if (uniq.length) return item("tools", T, "warn", `${tools} tool(s) scanned: ${uniq.join(", ")}`, uniq);
  return item("tools", T, "pass", `${tools} tool(s) scanned at the tool stage, no finding`);
}

// ---- 9. version pinning --------------------------------------------------------------------------
export function checkPinning(f) {
  const T = "Version pinning";
  if (f.spec.kind === "remote") return item("pinning", T, NC, "a remote endpoint has no installable version; what runs behind the URL can change at any time");
  const k = pinKind(f.spec);
  if (k === "exact") return item("pinning", T, "pass", `pinned to ${f.spec.ref.version}`);
  const runner = f.spec.kind === "npm" ? "npx" : "uvx";
  if (k === "tag-or-range") return item("pinning", T, "warn", `a tag or range resolves at launch, so ${runner} may run a different version each time (unpinned-version)`, ["unpinned-version"]);
  return item("pinning", T, "warn", `no version: ${runner} runs whatever is latest at launch (unpinned-version)`, ["unpinned-version"]);
}

// ---- 10. runtime checkpoint ----------------------------------------------------------------------
export function checkRuntime(f) {
  const T = "Runtime checkpoint";
  const r = f.runtime;
  if (!r) return item("runtime", T, NC, "this machine's configuration was not read");
  const routes = [];
  if (r.proxied) routes.push(`${r.proxied} of ${r.servers} configured MCP server(s) wrapped by the stdio proxy`);
  if (r.gateway) routes.push(`${r.gateway} via the MCP gateway`);
  if (r.hooks.length || r.plugin) {
    const on = [...r.hooks, ...(r.plugin && !r.hooks.includes("claude-code") ? ["claude-code (plugin)"] : [])];
    return item("runtime", T, "pass", `MoorAI hook registered on ${on.join(", ")}${routes.length ? `; ${routes.join("; ")}` : ""}`);
  }
  if (routes.length) return item("runtime", T, "warn", `no MoorAI hook; ${routes.join("; ")}: wrap this server too when you add it (mcp-proxy/install.mjs)`);
  return item("runtime", T, "fail", "no MoorAI hook, stdio proxy or gateway is configured here: nothing would inspect this server's calls at runtime");
}

export const CHECKS = [checkPublisher, checkAge, checkMaintainerCount, checkInstallScripts, checkAuth, checkTransport, checkCredentials, checkTools, checkPinning, checkRuntime];
