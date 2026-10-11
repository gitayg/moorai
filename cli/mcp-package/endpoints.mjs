// Where the package checkers send their requests, and whether they may send any. Read from the
// environment at call time, so `--offline` (which sets MOORAI_OFFLINE=1 for the process) and a mirror set
// for one run both apply to every module below without being threaded through each call.
//
//   MOORAI_NPM_REGISTRY         npm registry root            (default https://registry.npmjs.org/)
//   MOORAI_PYPI_URL             PyPI root, JSON API at pypi/  (default https://pypi.org/)
//   MOORAI_MCP_REGISTRY         MCP Registry root            (default https://registry.modelcontextprotocol.io/)
//   MOORAI_GITHUB_RAW_URL       raw file host root           (default https://raw.githubusercontent.com/)
//   MOORAI_GITHUB_CODELOAD_URL  archive host root            (default https://codeload.github.com/)
//   MOORAI_OFFLINE=1            no request at all; every network check reports not-checked (offline)
//
// A mirror must be an https URL with no credentials, query or fragment. An invalid value disables that
// endpoint (null) rather than falling back to the public host, so a typo in an air-gapped setup never
// sends a package name to the internet; the CLIs refuse to start on one (invalidMirrors).
//
// Every one of these names is read under the hook's trusted-environment rule (cli/server-mode.mjs
// trustedEnv): a value that a user, project or local Claude Code settings file sets in its `env` block is
// treated as unset. Claude Code applies that block to the session, so the hook and the stdio MCP servers
// it starts (the MCP guard, whose reputation lookup uses these endpoints) inherit it, and a cloned
// repository or the agent could otherwise point the lookup at a mirror that vouches for a malicious
// package, or switch it off. Set mirrors in the shell environment or in managed settings.
import { trustedEnv } from "../server-mode.mjs";

const envValue = (name, env) => trustedEnv(name, { env });

export const DEFAULT_ENDPOINTS = Object.freeze({
  npm: "https://registry.npmjs.org/",
  pypi: "https://pypi.org/",
  mcpRegistry: "https://registry.modelcontextprotocol.io/",
  githubRaw: "https://raw.githubusercontent.com/",
  githubCodeload: "https://codeload.github.com/"
});
export const MIRROR_ENV = Object.freeze({
  npm: "MOORAI_NPM_REGISTRY",
  pypi: "MOORAI_PYPI_URL",
  mcpRegistry: "MOORAI_MCP_REGISTRY",
  githubRaw: "MOORAI_GITHUB_RAW_URL",
  githubCodeload: "MOORAI_GITHUB_CODELOAD_URL"
});

// → "https://host[:port]/path/" (always a trailing slash) | null
export function mirrorUrl(v) {
  let u;
  try { u = new URL(String(v).trim()); } catch { return null; }
  if (u.protocol !== "https:" || !u.hostname || u.username || u.password || u.search || u.hash) return null;
  return `${u.origin}${u.pathname.replace(/\/*$/, "/")}`;
}

// The base URL for one endpoint, or null when its mirror variable is set but invalid.
export function endpoint(name, env = process.env) {
  const v = envValue(MIRROR_ENV[name], env);
  if (v === undefined || v === "") return DEFAULT_ENDPOINTS[name];
  return mirrorUrl(v);
}

// Whether a mirror is in effect for this endpoint (set, and from a trusted source).
export function mirrored(name, env = process.env) {
  const v = envValue(MIRROR_ENV[name], env);
  return v !== undefined && v !== "";
}

export function endpointHost(name, env = process.env) {
  const e = endpoint(name, env);
  return e ? new URL(e).hostname : null;
}

// Mirror variables that are set but invalid, by name, for a CLI to refuse on.
export function invalidMirrors(env = process.env) {
  return Object.keys(MIRROR_ENV).filter((k) => { const v = envValue(MIRROR_ENV[k], env); return v !== undefined && v !== "" && !mirrorUrl(v); }).map((k) => MIRROR_ENV[k]);
}

export function isOffline(env = process.env) {
  return envValue("MOORAI_OFFLINE", env) === "1";
}

export const OFFLINE_REASON = "not-checked (offline)";
