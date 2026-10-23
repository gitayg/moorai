// The device report's MCP package details: `pkg` on each `mcp` entry the desktop host sends
// (src-tauri/src/mcp_pkg.rs builds it there, from the same rules and the same fixture). It lets the
// console show single-maintainer, unpinned, package version and package-scan data.
//
//   pkg = { eco: "npm"|"pypi"|"docker"|"local"|"other", name, version, pinned, maintainers, maintainersOrg,
//           scan: { verdict: "clean"|"warn"|"block", findings: [code] } | null }
//
// CONTENT-FREE. The launch command, its arguments, env and any path or URL are parsed here and dropped:
// only the registry package name and the version spec as configured leave (public registry metadata).
// A local script or file package is eco "local" with no name; a docker image on a registry that is not a
// public one keeps no name or tag; a URL, git or remote launch is eco "other" with no name. Every field is
// validated and bounded (clampPkg) before it is sent, and again when read back from the cache.
//
// The maintainer count and the scan verdict come from ~/.moorai/mcp-pkg.json, written by the reputation
// path (cli/mcp-reputation.mjs): the count by its opt-in registry lookup, the verdict whenever a server's
// package code was read (the installed npx copy, or the registry artifact). Keyed per eco:name@version,
// each value with a 7-day TTL. Nothing here makes a network request.

import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { launchSpec, unwrapGuard, splitCommand, isPathLike } from "./resolve.mjs";
import { EXACT_SEMVER } from "./check-spec.mjs";
import { STATE_DIR } from "../state-dirs.mjs";

export const PKG_CACHE_FILE = "mcp-pkg.json";
export const PKG_META_TTL_MS = 7 * 24 * 3600 * 1000;
const PKG_REFRESH_MS = 24 * 3600 * 1000;
const FUTURE_SKEW_MS = 24 * 3600 * 1000;
const MAX_ENTRIES = 512;
export const MAX_NAME = 214, MAX_VERSION = 64, MAX_FINDINGS = 32, MAX_MAINTAINERS = 1000;

const VOCAB = new Set(JSON.parse(readFileSync(new URL("../../data/mcp-pkg-findings.json", import.meta.url), "utf8")).codes);
const ECOS = new Set(["npm", "pypi", "docker", "local", "other"]);
const VERDICTS = new Set(["clean", "warn", "block"]);
const NAME_RE = {
  npm: /^(@[a-z0-9][\w.~-]*\/)?[a-z0-9][\w.~-]*$/i,
  pypi: /^[A-Za-z0-9][A-Za-z0-9._-]*$/,
  // repo[:tag]@sha256:<64 hex> for a digest reference (the whole reference: the digest is over the
  // version limit), else the repository alone.
  docker: /^[a-z0-9]+(?:[._-]+[a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?$/
};
// The console's rule: no whitespace, backslash or "://", and no leading "/" or "." (a value shaped like a
// path or URL drops the whole pkg there). A version may start with "~" (`~1.4.2`, `~=1.4` are ordinary
// specs, pinned false); a name may not (the NAME_RE patterns above never allow it). A spec with
// whitespace is sent as version null.
const VERSION_RE = /^[0-9A-Za-z.+_~^<>=!*|,-]+$/;
const BAD_LEAD = /^[/.]/;
const PY_EXACT = /^[A-Za-z0-9.!+_-]+$/;
const THREAT_RE = /^threat-\d{1,4}$/;
// Registries whose image names are public. An image on any other host keeps no name or tag: the host
// can be an internal one.
const PUBLIC_REGISTRIES = new Set(["docker.io", "index.docker.io", "registry-1.docker.io", "ghcr.io", "quay.io", "gcr.io", "mcr.microsoft.com", "public.ecr.aws", "registry.gitlab.com", "registry.k8s.io"]);

// ---- validation ----------------------------------------------------------------------------------

function cleanName(eco, v) {
  return typeof v === "string" && v.length <= MAX_NAME && NAME_RE[eco] && NAME_RE[eco].test(v) ? v : null;
}
function cleanVersion(v) {
  return typeof v === "string" && v.length >= 1 && v.length <= MAX_VERSION && VERSION_RE.test(v) && !BAD_LEAD.test(v) ? v : null;
}
function cleanCount(v) {
  return Number.isInteger(v) && v >= 1 ? Math.min(v, MAX_MAINTAINERS) : null;
}
function cleanScan(s) {
  if (!s || typeof s !== "object" || !VERDICTS.has(s.verdict)) return null;
  const f = Array.isArray(s.findings) ? s.findings.filter((c) => typeof c === "string" && (VOCAB.has(c) || THREAT_RE.test(c))) : [];
  return { verdict: s.verdict, findings: [...new Set(f)].sort().slice(0, MAX_FINDINGS) };
}

// Any object → the contract's pkg, every field validated; null for a non-object.
export function clampPkg(p) {
  if (!p || typeof p !== "object") return null;
  const eco = ECOS.has(p.eco) ? p.eco : "other";
  const reg = eco === "npm" || eco === "pypi" || eco === "docker";
  const meta = eco === "npm" || eco === "pypi";
  return {
    eco,
    name: reg ? cleanName(eco, p.name) : null,
    version: reg ? cleanVersion(p.version) : null,
    pinned: reg && typeof p.pinned === "boolean" ? p.pinned : null,
    maintainers: meta ? cleanCount(p.maintainers) : null,
    maintainersOrg: meta && typeof p.maintainersOrg === "boolean" ? p.maintainersOrg : null,
    scan: meta ? cleanScan(p.scan) : null
  };
}

// ---- derivation from the launch config (parsed here, never sent) -----------------------------------

function declArgv(d) {
  if (typeof d.command !== "string" || !d.command.trim()) return null;
  const args = Array.isArray(d.args) ? d.args.filter((x) => typeof x === "string") : [];
  return d.args === undefined && /\s/.test(d.command.trim()) ? splitCommand(d.command) : [d.command, ...args];
}

// PyPI: the version spec after the name (and extras), as configured. `==X` / `===X` / uv's `name@X` give
// X; anything else (a range, `~=`, a list) is kept with its operator. Exact only for ==, === or @ with a
// literal version (not `latest`, no wildcard, no list).
export function pypiVersionSpec(token) {
  const m = /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?\s*([\s\S]*)$/.exec(String(token || "").trim());
  const rest = m ? m[1].trim() : "";
  if (!rest) return { version: null, pinned: false };
  const op = rest.startsWith("===") ? 3 : rest.startsWith("==") || rest.startsWith("@") ? (rest[0] === "@" ? 1 : 2) : 0;
  if (!op) return { version: rest, pinned: false };
  const v = rest.slice(op).trim();
  return { version: v || null, pinned: !!v && v !== "latest" && PY_EXACT.test(v) };
}

// image[:tag][@sha256:<64 hex>] → docker pkg. Pinned only by a full sha256 digest (a tag can be moved);
// a digest reference is sent whole as the name, with version null.
export function dockerPkg(image) {
  let s = String(image || "").trim();
  let digest = null;
  const at = s.indexOf("@");
  if (at >= 0) { digest = s.slice(at + 1); s = s.slice(0, at); }
  let tag = null;
  const colon = s.lastIndexOf(":");
  if (colon > s.lastIndexOf("/")) { tag = s.slice(colon + 1); s = s.slice(0, colon); }
  const first = s.split("/")[0];
  const host = s.includes("/") && (first.includes(".") || first.includes(":") || first === "localhost");
  const pub = !host || PUBLIC_REGISTRIES.has(first.toLowerCase());
  const pinned = !!digest && /^sha256:[0-9a-f]{64}$/.test(digest);
  if (!pub) return { eco: "docker", name: null, version: null, pinned };
  const repo = s.toLowerCase();
  if (pinned) return { eco: "docker", name: `${repo}${tag !== null ? `:${tag}` : ""}@${digest}`, version: null, pinned };
  return { eco: "docker", name: repo, version: tag, pinned };
}

// A registry runner's token that did not parse as a registry name: a local path / file package, or
// something remote (URL, git, alias) that is reported as "other" without a name.
function unparsedEco(spec) {
  const t = String(spec || "").trim();
  if (!t) return "other";
  if (/^file:/i.test(t)) return "local";
  if (t.includes("://") || /^(git\+|git:|github:|gitlab:|bitbucket:|npm:)/i.test(t)) return "other";
  if (isPathLike(t) || /\.(tgz|tar\.gz|whl|zip)$/i.test(t)) return "local";
  return "other";
}

// decl = an MCP server config entry ({command, args, env} | {url}) → pkg (maintainers / scan null).
export function derivePkg(decl) {
  const d = decl && typeof decl === "object" ? decl : {};
  if (typeof d.url === "string" && d.url) return clampPkg({ eco: "other" });
  const argv = declArgv(d);
  if (!argv) return clampPkg({ eco: "other" });
  const { ref, spec } = launchSpec(unwrapGuard(argv));
  if (ref.ecosystem === "npm") return clampPkg({ eco: "npm", name: ref.name, version: ref.version, pinned: ref.version ? EXACT_SEMVER.test(ref.version) : false });
  if (ref.ecosystem === "pypi" && !ref.inferred) return clampPkg({ eco: "pypi", name: ref.name, ...pypiVersionSpec(spec) });
  if (ref.ecosystem === "docker") return clampPkg(dockerPkg(ref.name));
  if (ref.ecosystem === "local") return clampPkg({ eco: "local" });
  // An inferred PyPI name (`python -m some_mcp_module`) is a module name, not a verified package.
  return clampPkg({ eco: ref.ecosystem === "unknown" ? unparsedEco(spec) : "other" });
}

// ---- the cache: ~/.moorai/mcp-pkg.json ----------------------------------------------------------------

export function pkgKey(pkg) {
  if (!pkg || (pkg.eco !== "npm" && pkg.eco !== "pypi") || typeof pkg.name !== "string" || !pkg.name) return null;
  return `${pkg.eco}:${pkg.name.toLowerCase()}@${pkg.version ?? ""}`;
}

export function readPkgMeta(stateDir = STATE_DIR) {
  try {
    const c = JSON.parse(readFileSync(join(stateDir, PKG_CACHE_FILE), "utf8"));
    if (c && c.v === 1 && c.entries && typeof c.entries === "object" && !Array.isArray(c.entries)) return c;
  } catch { /* absent or unreadable: no data */ }
  return { v: 1, entries: {} };
}

function writeAtomic(path, obj) {
  try {
    mkdirSync(dirname(path), { recursive: true });
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(obj));
    renameSync(tmp, path);
  } catch { /* an optimisation: a failed write only means the report says unknown */ }
}

const fresh = (x, now) => !!x && typeof x === "object" && Number.isFinite(x.at) && now - x.at <= PKG_META_TTL_MS && x.at - now <= FUTURE_SKEW_MS;

// meta = { maintainers?: {count, org} ({count: null} = looked up, unknown), scan?: {verdict, findings} }. Writes only on a change, or when the
// stored value is a day old (so a stable server never ages out of its TTL). → true when written.
export function recordPkgMeta(stateDir = STATE_DIR, pkg, meta = {}, now = Date.now()) {
  const key = pkgKey(pkg);
  if (!key) return false;
  const cache = readPkgMeta(stateDir);
  const prev = cache.entries[key] && typeof cache.entries[key] === "object" ? cache.entries[key] : {};
  const e = { ...prev };
  let changed = false;
  const m = meta.maintainers;
  const count = m ? cleanCount(m.count) : null;
  if (count !== null) {
    const org = m.org === true;
    if (!prev.m || prev.m.count !== count || prev.m.org !== org || !(now - prev.m.at < PKG_REFRESH_MS)) { e.m = { count, org, at: now }; changed = true; }
  } else if (m && !fresh(prev.m, now)) {
    // Looked up, count unknown: remember the attempt so the next lookup waits for the TTL.
    e.m = { count: null, org: null, at: now }; changed = true;
  }
  const s = meta.scan ? cleanScan(meta.scan) : null;
  if (s) {
    const same = prev.s && prev.s.verdict === s.verdict && JSON.stringify(prev.s.findings) === JSON.stringify(s.findings);
    if (!same || !(now - prev.s.at < PKG_REFRESH_MS)) { e.s = { ...s, at: now }; changed = true; }
  }
  if (!changed) return false;
  cache.entries[key] = e;
  const keys = Object.keys(cache.entries);
  if (keys.length > MAX_ENTRIES) {
    const at = (k) => Math.max(Number(cache.entries[k]?.m?.at) || 0, Number(cache.entries[k]?.s?.at) || 0);
    keys.sort((a, b) => at(a) - at(b));
    for (const k of keys.slice(0, keys.length - MAX_ENTRIES)) delete cache.entries[k];
  }
  writeAtomic(join(stateDir, PKG_CACHE_FILE), cache);
  return true;
}

// Was this pkg's maintainer count looked up within the TTL (known or not)?
export function maintainersChecked(pkg, cache, now = Date.now()) {
  const key = pkgKey(pkg);
  const e = key && cache && cache.entries ? cache.entries[key] : null;
  return !!e && typeof e === "object" && fresh(e.m, now);
}

// pkg + the cache → pkg with the fresh maintainer count and scan verdict filled in, clamped again.
export function withPkgMeta(pkg, cache, now = Date.now()) {
  const key = pkgKey(pkg);
  const e = key && cache && cache.entries && typeof cache.entries[key] === "object" ? cache.entries[key] : null;
  if (!e) return pkg;
  const m = fresh(e.m, now) && cleanCount(e.m.count) !== null ? e.m : null;
  const s = fresh(e.s, now) ? cleanScan(e.s) : null;
  return clampPkg({ ...pkg, maintainers: m ? m.count : pkg.maintainers, maintainersOrg: m ? e.m.org === true : pkg.maintainersOrg, scan: s || pkg.scan });
}

// A reputation result → the scan part of pkg, or null when no package code was read (the name check alone
// is not a scan). Band good → clean, fair / poor → warn, bad (a block-tier finding) → block.
const BAND_VERDICT = { good: "clean", fair: "warn", poor: "warn", bad: "block" };
export function scanOfReputation(rep) {
  if (!rep || !Array.isArray(rep.evidence)) return null;
  if (!rep.evidence.includes("installed-copy-scanned") && !rep.evidence.includes("registry-analysed")) return null;
  return cleanScan({ verdict: BAND_VERDICT[rep.band], findings: rep.reasons });
}
