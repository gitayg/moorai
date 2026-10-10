// How many accounts can publish this package? From registry metadata only, counted and then dropped:
// no name, username or email is returned, cached or reported.
//
// npm — docs/responses/package-metadata.md in github.com/npm/registry, full metadata format:
//   "`maintainers`: array of [human](#human) objects for people with permission to publish this package;
//   not authoritative but informational", and a human object has "at least one of" `name`, `email`, `url`.
//   Read from the TOP-LEVEL packument (the current set). Each version object carries its own copy as of
//   that publish, which can differ (measured: @modelcontextprotocol/server-filesystem, 6 vs 7).
//
// PyPI — docs.pypi.org/api/json/, "Ownership": "roles: A list of {"role": "<role>", "user": "<username>"}
//   objects representing the project's owners and maintainers ... This is an empty list when the project
//   has no roles assigned. organization: The URL slug of the organization that owns the project ... or
//   null if the project is not owned by an organization."
//   NOT used: `info.author` / `info.maintainer` (and their _email twins). They are free text from the
//   uploaded metadata, written by whoever built the package, and say nothing about who can publish.
//   What PyPI cannot tell us: team access granted through an organization is not documented as appearing
//   in `roles`, so an organization-owned project is never called single-maintainer; and an empty `roles`
//   list (or a response without `ownership`) is unknown, not one.

import { fetchRegistryMeta } from "./metadata.mjs";

// → {count, org} | null (unknown).
export function maintainerInfo(ecosystem, doc) {
  if (!doc || typeof doc !== "object") return null;
  if (ecosystem === "npm") {
    if (!Array.isArray(doc.maintainers)) return null;
    const ids = new Set();
    for (const m of doc.maintainers) {
      const id = m && typeof m === "object" ? m.name || m.email : typeof m === "string" ? m : null;
      if (id) ids.add(String(id).toLowerCase());
    }
    return { count: ids.size, org: false };
  }
  if (ecosystem === "pypi") {
    const o = doc.ownership;
    if (!o || typeof o !== "object" || !Array.isArray(o.roles)) return null;
    const users = new Set(o.roles.filter((r) => r && typeof r.user === "string" && r.user).map((r) => r.user.toLowerCase()));
    return { count: users.size, org: typeof o.organization === "string" && o.organization.length > 0 };
  }
  return null;
}

// → {signals: [code], evidence: [code]}. Category codes only.
export function maintainerSignals(info) {
  if (!info || info.count === 0) return { signals: [], evidence: ["maintainers-unknown"] };
  if (info.org) return { signals: [], evidence: ["maintainers-org"] };
  if (info.count === 1) return { signals: ["single-maintainer"], evidence: [] };
  return { signals: [], evidence: ["maintainers-multiple"] };
}

// The reputation lookup's entry point. Fail-open: any error is evidence only.
export async function checkMaintainers(ref, { fetchImpl = globalThis.fetch, timeoutMs } = {}) {
  if (!ref || (ref.ecosystem !== "npm" && ref.ecosystem !== "pypi") || !ref.name) return { signals: [], evidence: [] };
  const r = await fetchRegistryMeta(ref, { fetchImpl, ...(timeoutMs ? { timeoutMs } : {}) });
  if (r.status !== 200) return { signals: [], evidence: ["maintainers-check-failed"] };
  return maintainerSignals(maintainerInfo(ref.ecosystem, r.doc));
}
