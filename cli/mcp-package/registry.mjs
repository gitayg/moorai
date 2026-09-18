// Public-registry access for `moorai scan --packages`. PRIVACY CONTRACT: the only thing that leaves the
// device is the package NAME (and version) in a registry URL. No config, no path, no file content, no
// identifying header. Artifact URLs taken from registry metadata are pinned to the registry's own
// file host and fetched with redirects refused, so hostile metadata cannot point the scanner elsewhere.

import { envMb } from "./archive.mjs";

const NPM_REGISTRY = "https://registry.npmjs.org/";
const NPM_FILE_HOST = "registry.npmjs.org";
const PYPI_API = "https://pypi.org/pypi/";
const PYPI_FILE_HOST = "files.pythonhosted.org";
const MAX_META_BYTES = 64 * 1024 * 1024;
// The artifact is streamed to a temp file, never buffered, so the compressed cap can be generous. Both
// are overridable: MOORAI_SCAN_MAX_ARTIFACT_MB / MOORAI_SCAN_MAX_REPO_MB (and the EXTRACTED cap lives
// in archive.mjs as MOORAI_SCAN_MAX_EXTRACT_MB).
export const MAX_ARTIFACT_BYTES = envMb("MOORAI_SCAN_MAX_ARTIFACT_MB", 128 * 1024 * 1024);
export const MAX_REPO_BYTES = envMb("MOORAI_SCAN_MAX_REPO_MB", 250 * 1024 * 1024);   // a whole public repo tarball (codeload.github.com)

export class RegistryError extends Error {
  constructor(code) { super(code); this.code = code; }
}

async function readCapped(res, cap) {
  const len = Number(res.headers && res.headers.get && res.headers.get("content-length"));
  if (len > cap) throw new RegistryError("too-large");
  if (res.body && typeof res.body.getReader === "function") {
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > cap) { try { await reader.cancel(); } catch {} throw new RegistryError("too-large"); }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > cap) throw new RegistryError("too-large");
  return buf;
}

async function get(fetchImpl, url, cap, accept) {
  let res;
  try {
    res = await fetchImpl(url, { redirect: "error", headers: accept ? { accept } : {} });
  } catch { throw new RegistryError("network-error"); }
  if (!res || !res.ok) throw new RegistryError(`http-${res ? res.status : 0}`);
  return readCapped(res, cap);
}

async function getJson(fetchImpl, url) {
  const buf = await get(fetchImpl, url, MAX_META_BYTES, "application/json");
  try { return JSON.parse(buf.toString("utf8")); } catch { throw new RegistryError("bad-metadata"); }
}

function pinnedUrl(u, host) {
  let url;
  try { url = new URL(u); } catch { throw new RegistryError("bad-artifact-url"); }
  if (url.protocol !== "https:" || url.hostname !== host || url.username || url.password) throw new RegistryError("artifact-off-registry");
  return url.href;
}

// → {version, url, kind, integrity:{algorithm, expected:[…]}, createdAt}
export async function resolveNpm(ref, fetchImpl) {
  const meta = await getJson(fetchImpl, NPM_REGISTRY + ref.name.replace("/", "%2f"));
  const tags = meta["dist-tags"] || {};
  const versions = meta.versions || {};
  const version = !ref.version ? tags.latest : versions[ref.version] ? ref.version : tags[ref.version];
  const man = version && versions[version];
  if (!man || !man.dist || !man.dist.tarball) throw new RegistryError("version-not-found");
  const expected = String(man.dist.integrity || "").split(/\s+/).filter((s) => s.startsWith("sha512-")).map((s) => s.slice(7));
  return {
    version,
    url: pinnedUrl(man.dist.tarball, NPM_FILE_HOST),
    kind: "tarball",
    integrity: { algorithm: "sha512", expected },
    createdAt: meta.time && meta.time.created ? Date.parse(meta.time.created) : null
  };
}

function pickPypiFile(files) {
  const usable = (files || []).filter((f) => f && f.url && f.digests && f.digests.sha256 && !f.yanked);
  return usable.find((f) => f.packagetype === "sdist")
    || usable.find((f) => f.packagetype === "bdist_wheel" && /-none-any\.whl$/.test(f.filename || ""))
    || usable.find((f) => f.packagetype === "bdist_wheel")
    || null;
}

export async function resolvePypi(ref, fetchImpl) {
  const name = encodeURIComponent(ref.name);
  const meta = await getJson(fetchImpl, ref.version ? `${PYPI_API}${name}/${encodeURIComponent(ref.version)}/json` : `${PYPI_API}${name}/json`);
  const version = meta.info && meta.info.version;
  const file = pickPypiFile(meta.urls);
  if (!version || !file) throw new RegistryError("version-not-found");
  let createdAt = null;
  for (const rel of Object.values(meta.releases || {})) {
    for (const f of rel || []) {
      const t = Date.parse(f.upload_time_iso_8601 || f.upload_time || "");
      if (t && (createdAt === null || t < createdAt)) createdAt = t;
    }
  }
  return {
    version,
    url: pinnedUrl(file.url, PYPI_FILE_HOST),
    kind: file.packagetype === "sdist" ? "sdist" : "wheel",
    integrity: { algorithm: "sha256", expected: [String(file.digests.sha256).toLowerCase()] },
    createdAt
  };
}

// The artifact digest is computed by download.mjs while the body streams (so the artifact is never
// buffered just to be hashed); this only compares it against what the registry published.
export function matchesIntegrity(digest, integrity) {
  if (!integrity.expected.length || !digest) return false;
  return integrity.expected.includes(digest);
}
