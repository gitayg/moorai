// GitHub-hosted skills for `moorai scan --package github:owner/repo/path[@ref]`.
//
// PRIVACY CONTRACT (same as registry.mjs): only owner/repo/ref leave the device, in a codeload URL. The
// path is never sent; the whole public repo tarball is fetched and only that path is extracted.
// Redirects are refused. There is no registry digest for a git archive, so integrity is recorded as
// "none" and the commit the archive was cut from (its pax global header) is reported instead.

import { RegistryError } from "./registry.mjs";

const CODELOAD = "https://codeload.github.com/";
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;
const REF = /^[A-Za-z0-9._/-]{1,200}$/;
const SEGMENT = /^[A-Za-z0-9._+-]{1,200}$/;

// "owner/repo/some/path@ref" → {ecosystem:"github", name:"owner/repo", path:"some/path", version:ref|null}
export function parseGithubSpec(spec) {
  let s = String(spec || "").trim().replace(/^https:\/\/github\.com\//i, "");
  let version = null;
  const at = s.lastIndexOf("@");
  if (at > 0) {
    const ref = s.slice(at + 1);
    if (!REF.test(ref) || ref.split("/").some((p) => p === ".." || p === "")) return null;
    version = ref;
    s = s.slice(0, at);
  }
  const parts = s.split("/").filter((p) => p !== "");
  if (parts.length < 2) return null;
  const [owner, repo, ...rest] = parts;
  if (!OWNER.test(owner) || !REPO.test(repo) || repo === "." || repo === "..") return null;
  if (rest.some((p) => p === "." || p === ".." || !SEGMENT.test(p))) return null;
  return { ecosystem: "github", name: `${owner}/${repo.replace(/\.git$/, "")}`, path: rest.join("/"), version };
}

export function githubArchiveUrl(ref) {
  const [owner, repo] = ref.name.split("/");
  const r = ref.version || "HEAD";
  return `${CODELOAD}${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/tar.gz/${r.split("/").map(encodeURIComponent).join("/")}`;
}

export function resolveGithub(ref) {
  if (!ref || !ref.name || !/^[^/]+\/[^/]+$/.test(ref.name)) throw new RegistryError("bad-github-ref");
  return {
    version: ref.version || "HEAD",
    url: githubArchiveUrl(ref),
    kind: "repo-tarball",
    integrity: { algorithm: "none", expected: [] },
    createdAt: null
  };
}
