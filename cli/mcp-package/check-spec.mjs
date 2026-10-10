// `moorai-mcp-check <package>` argument → what to check. Offline and pure.
//
//   npm:@scope/pkg@1.2.3 · pypi:mcp-server-fetch==1.0 · @scope/pkg@1.2.3 (bare = npm)
//   "npx -y pkg@1.2.3" · "uvx mcp-server-fetch" (a launch command, as it would appear in a config)
//   https://mcp.example.com/mcp (a remote server)

import { parsePackageArg, parseNpmSpec, splitCommand, resolveLaunch } from "./resolve.mjs";

// → {kind: "npm"|"pypi", ref, raw} | {kind: "remote", url, raw} | {error}
export function parseCheckSpec(arg) {
  const raw = String(arg || "").trim();
  if (!raw) return { error: "no package given" };
  if (/^https?:\/\//i.test(raw)) {
    try { return { kind: "remote", url: new URL(raw).href, raw }; } catch { return { error: "not a valid URL" }; }
  }
  let ref = null;
  if (/^(npm|pypi|github):/i.test(raw)) ref = parsePackageArg(raw);
  else if (/\s/.test(raw)) ref = resolveLaunch(splitCommand(raw));
  else ref = parseNpmSpec(raw);
  if (!ref || (ref.ecosystem !== "npm" && ref.ecosystem !== "pypi") || !ref.name) {
    return { error: "not an npm or PyPI package spec, launch command or https URL (github: specs are not supported)" };
  }
  return { kind: ref.ecosystem, ref: { ecosystem: ref.ecosystem, name: ref.name, version: ref.version || null }, raw };
}

const EXACT_SEMVER = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

// → "exact" | "tag-or-range" | "none". PyPI's parser only yields a version for `==` / `@`, i.e. exact.
export function pinKind(spec) {
  if (!spec || spec.kind === "remote") return "none";
  const v = spec.ref.version;
  if (spec.kind === "pypi") return v ? "exact" : /[<>=~!]/.test(spec.raw.replace(/^pypi:/i, "")) ? "tag-or-range" : "none";
  if (!v) return "none";
  return EXACT_SEMVER.test(v) ? "exact" : "tag-or-range";
}
