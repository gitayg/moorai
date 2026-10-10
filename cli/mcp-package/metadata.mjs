// Registry METADATA only — never the package artifact. Used by the opt-in reputation lookup (maintainer
// count) and by `moorai-mcp-check` (age, maintainers, install scripts, the published server.json).
//
// Every request is a bare GET to a fixed public host, bounded by the same per-request timeout as the
// repository-link lookup (REPO_LINK_LIMITS.requestMs), size-capped, redirects refused. Anything that goes
// wrong returns {status: 0}: callers treat that as "no signal", never as a finding.
//
// What leaves the device: the public package name (npm, PyPI) and the public MCP Registry server name the
// package itself published (`mcpName` / `mcp-name:`). No path, argument, environment value or header.

import { REPO_LINK_LIMITS } from "../mcp-repo-link.mjs";

const NPM = "https://registry.npmjs.org/";
const PYPI = "https://pypi.org/pypi/";
export const MCP_REGISTRY = "https://registry.modelcontextprotocol.io/v0.1/servers/";
const MAX_BYTES = 32 * 1024 * 1024;

// → {status, doc?}. status 0 = transport failure, timeout, oversize, bad JSON.
export async function getJson(url, { fetchImpl = globalThis.fetch, timeoutMs = REPO_LINK_LIMITS.requestMs } = {}) {
  let res;
  try {
    res = await fetchImpl(url, { method: "GET", redirect: "error", headers: { accept: "application/json" }, signal: AbortSignal.timeout(timeoutMs) });
  } catch { return { status: 0 }; }
  if (!res) return { status: 0 };
  if (res.status !== 200) return { status: res.status };
  try {
    const text = await res.text();
    if (text.length > MAX_BYTES) return { status: 0 };
    return { status: 200, doc: JSON.parse(text) };
  } catch { return { status: 0 }; }
}

// The npm FULL packument (top-level `maintainers` and `time` are only in the full document, not the
// abbreviated install document), or PyPI's project-level JSON (`ownership`, `releases`).
export function registryMetaUrl(ref) {
  if (ref.ecosystem === "npm") return NPM + String(ref.name).replace("/", "%2f");
  if (ref.ecosystem === "pypi") return `${PYPI}${encodeURIComponent(ref.name)}/json`;
  return null;
}

export async function fetchRegistryMeta(ref, opts = {}) {
  const url = ref && registryMetaUrl(ref);
  if (!url) return { status: 0 };
  return getJson(url, opts);
}

// The server's published server.json from the official MCP Registry, by the name the package declares.
export async function fetchServerJson(serverName, opts = {}) {
  if (!/^[A-Za-z0-9.-]+\/[A-Za-z0-9._-]+$/.test(String(serverName || ""))) return { status: 0 };
  return getJson(`${MCP_REGISTRY}${encodeURIComponent(serverName)}/versions/latest`, opts);
}
