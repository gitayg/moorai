// Known-compromised package releases: a registry package version (or, for a package that is malicious in
// every release, every version) that must not be installed or launched. The pure half: the shipped list,
// the signed-policy list and the match. No I/O (browser-safe). The shell reader is data/package-installs.js;
// the hook and the MCP guard decide with cli/package-known-bad.mjs and cli/mcp-package-policy.mjs.
//
// SIGNED POLICY ONLY. The org adds entries and chooses the action under one key:
//
//   "knownBadPackages": {
//     "action":   "block" | "ask" | "report",          default "block"
//     "packages": [{ "ecosystem": "npm" | "pypi" | "url", "name": "<name, or host/path for url>",
//                    "versions": ["1.2.3", …] | "*" }, …]
//   }
//
// The shipped list always applies; the policy's packages are added to it, never subtracted from it. An
// action that is not one of the three exact values reads as "block" (the strict reading). An entry with an
// unknown ecosystem, no name, or no versions is skipped. A version entry matches only that exact version:
// a range, a dist-tag or an unpinned install of the package is not matched (the registry has usually pulled
// the release; what an unpinned install resolves to is not known before it runs). "*" matches every
// version, unpinned installs included.

export const KNOWN_BAD_CATEGORY = "Known-compromised package release";
export const KNOWN_BAD_ACTIONS = Object.freeze(["block", "ask", "report"]);
export const KNOWN_BAD_ECOSYSTEMS = Object.freeze(["npm", "pypi", "url"]);

// Each entry names its public source.
export const SHIPPED_KNOWN_BAD = Object.freeze([
  // https://docs.litellm.ai/blog/security-incident-oct-21-2026: "A malicious `litellm==1.107.0` package was
  // published to PyPI and was live for approximately 2 hours". The Docker images are not package installs.
  { ecosystem: "pypi", name: "litellm", versions: ["1.107.0"] },
  // https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack
  // (2025-09-08, with the 2025-09-09 additions).
  { ecosystem: "npm", name: "debug", versions: ["4.4.2"] },
  { ecosystem: "npm", name: "chalk", versions: ["5.6.1"] },
  { ecosystem: "npm", name: "ansi-styles", versions: ["6.2.2"] },
  { ecosystem: "npm", name: "ansi-regex", versions: ["6.2.1"] },
  { ecosystem: "npm", name: "strip-ansi", versions: ["7.1.1"] },
  { ecosystem: "npm", name: "supports-color", versions: ["10.2.1"] },
  { ecosystem: "npm", name: "wrap-ansi", versions: ["9.0.1"] },
  { ecosystem: "npm", name: "slice-ansi", versions: ["7.1.1"] },
  { ecosystem: "npm", name: "has-ansi", versions: ["6.0.1"] },
  { ecosystem: "npm", name: "color", versions: ["5.0.1"] },
  { ecosystem: "npm", name: "color-name", versions: ["2.0.1"] },
  { ecosystem: "npm", name: "color-convert", versions: ["3.1.1"] },
  { ecosystem: "npm", name: "color-string", versions: ["2.1.1"] },
  { ecosystem: "npm", name: "is-arrayish", versions: ["0.3.3"] },
  { ecosystem: "npm", name: "error-ex", versions: ["1.3.3"] },
  { ecosystem: "npm", name: "simple-swizzle", versions: ["0.2.3"] },
  { ecosystem: "npm", name: "backslash", versions: ["0.2.1"] },
  { ecosystem: "npm", name: "chalk-template", versions: ["1.1.1"] },
  { ecosystem: "npm", name: "supports-hyperlinks", versions: ["4.1.1"] },
  { ecosystem: "npm", name: "duckdb", versions: ["1.3.3"] },
  { ecosystem: "npm", name: "@duckdb/node-api", versions: ["1.3.3"] },
  { ecosystem: "npm", name: "@duckdb/node-bindings", versions: ["1.3.3"] },
  { ecosystem: "npm", name: "@duckdb/duckdb-wasm", versions: ["1.29.2"] },
  { ecosystem: "npm", name: "proto-tinker-wc", versions: ["0.1.87"] }
]);

const own = (o, k) => o !== null && typeof o === "object" && !Array.isArray(o) && Object.prototype.hasOwnProperty.call(o, k);
const pep503 = (s) => s.replace(/[-_.]+/g, "-");

// A name as its registry compares it: npm lower-case, PyPI PEP 503, a url entry as lower-case host + path.
export function normName(ecosystem, name) {
  const n = String(name || "").trim().toLowerCase();
  if (!n) return "";
  if (ecosystem === "pypi") return pep503(n);
  if (ecosystem === "url") return n.replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/[?#].*$/, "").replace(/\/+$/, "");
  return n;
}

const PEP440 = /^(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?(?:-(\d+)|[-_.]?(?:post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$/;
const PRE = { a: "a", alpha: "a", b: "b", beta: "b", c: "rc", rc: "rc", pre: "rc", preview: "rc" };

// PEP 440 normal form: epoch 0 dropped, numeric segments compared as numbers (01 = 1), trailing zero release
// segments dropped (1.107.0 = 1.107), pre/post/dev spellings unified. A `1.107.*` wildcard comes back as "*1.107"
// and matches the listed releases under it; a version PEP 440 cannot parse comes back as "?<text>", which
// matchKnownBad treats as matching every listed release of that package (fail closed).
function pep440(s) {
  const w = /^(\d+(?:\.\d+)*)\.\*$/.exec(s);
  if (w) return "*" + pep440(w[1]);
  const m = PEP440.exec(s);
  if (!m) return "?" + s;
  const rel = m[2].split(".").map((x) => String(Number(x)));
  while (rel.length > 1 && rel[rel.length - 1] === "0") rel.pop();
  let out = (m[1] && Number(m[1]) !== 0 ? Number(m[1]) + "!" : "") + rel.join(".");
  if (m[3]) out += PRE[m[3]] + Number(m[4] || 0);
  if (m[5] != null || m[6] != null) out += ".post" + Number(m[5] ?? m[6] ?? 0);
  if (m[7]) out += ".dev" + Number(m[8] || 0);
  if (m[9]) out += "+" + m[9].replace(/[-_]/g, ".");
  return out;
}

// A version as written in a pin: no leading "v", "=" or "==". PyPI in PEP 440 normal form; npm without build
// metadata, which semver ignores when it compares.
export function normVersion(ecosystem, v) {
  if (v == null) return null;
  let s = String(v).trim().toLowerCase().replace(/^={1,3}\s*/, "").replace(/^v(?=\d)/, "");
  if (!s) return null;
  if (ecosystem === "pypi") return pep440(s);
  if (ecosystem === "npm") s = s.replace(/\+.*$/, "");
  return s;
}

function entryOf(raw) {
  if (!raw || typeof raw !== "object" || !KNOWN_BAD_ECOSYSTEMS.includes(raw.ecosystem)) return null;
  const name = normName(raw.ecosystem, raw.name);
  if (!name || name.length > 512) return null;
  if (raw.versions === "*" || (Array.isArray(raw.versions) && raw.versions.includes("*"))) return { ecosystem: raw.ecosystem, name, versions: "*" };
  if (!Array.isArray(raw.versions)) return null;
  const versions = raw.versions.map((x) => normVersion(raw.ecosystem, x)).filter(Boolean).slice(0, 256);
  return versions.length ? { ecosystem: raw.ecosystem, name, versions } : null;
}

// policy: the verified signed policy (or null). Never throws.
// → { action, invalid, entries: [{ecosystem, name, versions, source: "shipped"|"policy"}] }
export function resolveKnownBad(policy) {
  const entries = SHIPPED_KNOWN_BAD.map((e) => ({ ...entryOf(e), source: "shipped" }));
  let action = "block", invalid = false;
  try {
    if (own(policy, "knownBadPackages")) {
      const kb = policy.knownBadPackages;
      if (!kb || typeof kb !== "object" || Array.isArray(kb)) invalid = true;
      else {
        if (own(kb, "action")) { if (KNOWN_BAD_ACTIONS.includes(kb.action)) action = kb.action; else invalid = true; }
        if (own(kb, "packages")) {
          if (!Array.isArray(kb.packages)) invalid = true;
          else for (const raw of kb.packages.slice(0, 2000)) { const e = entryOf(raw); if (e) entries.push({ ...e, source: "policy" }); else invalid = true; }
        }
      }
    }
  } catch { invalid = true; }
  return { action, invalid, entries };
}

// ref = { ecosystem, name, version (null when not pinned to an exact version) } → the matching entry, or null.
export function matchKnownBad(kb, ref) {
  if (!kb || !ref || !KNOWN_BAD_ECOSYSTEMS.includes(ref.ecosystem)) return null;
  const name = normName(ref.ecosystem, ref.name);
  if (!name) return null;
  const ver = normVersion(ref.ecosystem, ref.version);
  for (const e of kb.entries) {
    if (e.ecosystem !== ref.ecosystem || e.name !== name) continue;
    if (e.versions === "*") return e;
    if (ver && (e.versions.includes(ver) || (ref.ecosystem === "pypi" && ver.startsWith("?")))) return e;
    if (ver && ref.ecosystem === "pypi" && ver.startsWith("*") && e.versions.some((x) => x === ver.slice(1) || x.startsWith(ver.slice(1) + "."))) return e;
  }
  return null;
}

// The verdict a match gets: "deny" | "ask" | "allow" (report).
export const knownBadDecision = (action) => (action === "ask" ? "ask" : action === "report" ? "allow" : "deny");
