// Maintainer-count signal for MCP server reputation (cli/mcp-package/maintainers.mjs, weight in
// data/mcp-reputation.js). Fake registry only: every route is a table entry, anything else is a 599.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-maintainers.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { maintainerInfo, maintainerSignals, checkMaintainers } from "../cli/mcp-package/maintainers.mjs";
import { assessServer } from "../cli/mcp-reputation.mjs";
import { REASON_WEIGHTS, reputationAlert } from "../data/mcp-reputation.js";
import { rmTree } from "./fs-cleanup.mjs";

const NAME_A = "alice-q7-maintainer", MAIL_A = "alice-q7@example.com";
const NAME_B = "bob-z3-maintainer", MAIL_B = "bob-z3@example.com";
const PKG = "weather-relay-mcp";

function sandbox() {
  const root = mkdtempSync(join(tmpdir(), "moorai-maint-"));
  const home = join(root, "home"), stateDir = join(root, "state");
  mkdirSync(home, { recursive: true }); mkdirSync(stateDir, { recursive: true });
  return { root, home, stateDir, done: () => rmTree(root) };
}

function recorder(routes = {}) {
  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    calls.push({ url: String(url), method: opts.method || "GET" });
    const hit = routes[String(url)];
    if (!hit) return new Response("", { status: 599 });
    return typeof hit === "function" ? hit(opts) : new Response(JSON.stringify(hit), { status: 200 });
  };
  return { calls, fetchImpl };
}

const packument = (maintainers) => ({
  name: PKG, "dist-tags": { latest: "1.0.0" },
  time: { created: "2024-01-01T00:00:00.000Z", "1.0.0": "2024-01-01T00:00:00.000Z" },
  maintainers,
  versions: { "1.0.0": { name: PKG, version: "1.0.0", maintainers, dist: { tarball: `https://registry.npmjs.org/${PKG}/-/${PKG}-1.0.0.tgz`, integrity: "sha512-AAAA" } } }
});

test("npm: the top-level maintainers array is counted; one is single-maintainer, two is not", () => {
  assert.deepEqual(maintainerInfo("npm", { maintainers: [{ name: NAME_A, email: MAIL_A }] }), { count: 1, org: false });
  assert.deepEqual(maintainerInfo("npm", { maintainers: [{ name: NAME_A, email: MAIL_A }, { name: NAME_B, email: MAIL_B }] }), { count: 2, org: false });
  assert.deepEqual(maintainerInfo("npm", { maintainers: [{ name: NAME_A }, { name: NAME_A.toUpperCase() }] }), { count: 1, org: false }, "the same account twice is one");
  assert.equal(maintainerInfo("npm", { name: PKG }), null, "no maintainers field = unknown, not zero");
  assert.deepEqual(maintainerSignals({ count: 1, org: false }), { signals: ["single-maintainer"], evidence: [] });
  assert.deepEqual(maintainerSignals({ count: 2, org: false }), { signals: [], evidence: ["maintainers-multiple"] });
  assert.deepEqual(maintainerSignals(null), { signals: [], evidence: ["maintainers-unknown"] });
});

test("PyPI: ownership.roles is counted; free-text author/maintainer is ignored; org-owned and empty are not single", () => {
  const one = { info: { author: "Many People", maintainer: "A Team" }, ownership: { roles: [{ role: "Owner", user: NAME_A }], organization: null } };
  assert.deepEqual(maintainerInfo("pypi", one), { count: 1, org: false });
  assert.deepEqual(maintainerSignals(maintainerInfo("pypi", one)).signals, ["single-maintainer"]);
  const two = { ownership: { roles: [{ role: "Owner", user: NAME_A }, { role: "Maintainer", user: NAME_B }], organization: null } };
  assert.deepEqual(maintainerSignals(maintainerInfo("pypi", two)).signals, []);
  const org = { ownership: { roles: [{ role: "Owner", user: NAME_A }], organization: "acme" } };
  assert.deepEqual(maintainerSignals(maintainerInfo("pypi", org)), { signals: [], evidence: ["maintainers-org"] }, "team access via an organization is not listed in roles");
  assert.deepEqual(maintainerSignals(maintainerInfo("pypi", { ownership: { roles: [], organization: null } })), { signals: [], evidence: ["maintainers-unknown"] });
  const noOwnership = { info: { author: NAME_A, author_email: MAIL_A, maintainer: "", maintainer_email: "" } };
  assert.equal(maintainerInfo("pypi", noOwnership), null, "a single author string is not a maintainer count");
});

test("reputation: single vs multiple maintainers changes the score by exactly the single-maintainer weight", async () => {
  assert.equal(REASON_WEIGHTS["single-maintainer"], 5, "weight is pinned: a change must be deliberate");
  const url = `https://registry.npmjs.org/${PKG}`;
  const scores = {};
  for (const [label, m] of [["one", [{ name: NAME_A, email: MAIL_A }]], ["two", [{ name: NAME_A, email: MAIL_A }, { name: NAME_B, email: MAIL_B }]]]) {
    const s = sandbox();
    try {
      const { fetchImpl } = recorder({ [url]: packument(m) });
      const rep = await assessServer({ command: "npx", args: ["-y", `${PKG}@1.0.0`] }, { stateDir: s.stateDir, home: s.home, fetchImpl, policy: { lookup: "registry" } });
      scores[label] = rep;
      if (label === "one") {
        assert.ok(rep.reasons.includes("single-maintainer"), JSON.stringify(rep));
        const cache = readFileSync(join(s.stateDir, "mcp-reputation.json"), "utf8");
        for (const leak of [NAME_A, MAIL_A]) assert.equal(cache.includes(leak), false, `cache leaked ${leak}`);
      } else {
        assert.equal(rep.reasons.includes("single-maintainer"), false, JSON.stringify(rep));
        assert.ok(rep.evidence.includes("maintainers-multiple"));
      }
    } finally { s.done(); }
  }
  assert.equal(scores.two.score - scores.one.score, REASON_WEIGHTS["single-maintainer"], JSON.stringify(scores));
});

test("content-free: the reputation alert names no package, maintainer or email", async () => {
  const s = sandbox();
  try {
    const { fetchImpl } = recorder({ [`https://registry.npmjs.org/${PKG}`]: packument([{ name: NAME_A, email: MAIL_A }]) });
    const rep = await assessServer({ command: "npx", args: ["-y", `${PKG}@1.0.0`] }, { stateDir: s.stateDir, home: s.home, fetchImpl, policy: { lookup: "registry" } });
    assert.ok(rep.reasons.includes("single-maintainer"));
    const alert = JSON.stringify(reputationAlert(rep, { server: "weather", decision: "alert", identityHash: "h" }));
    for (const leak of [PKG, NAME_A, MAIL_A, "example.com"]) assert.equal(alert.includes(leak), false, `alert leaked ${leak}`);
    for (const r of rep.reasons) assert.match(r, /^[a-z0-9-]+$/, "reasons are category codes");
  } finally { s.done(); }
});

test("fail open: a thrown fetch, a 500 and a timeout give no signal and never throw", async () => {
  const ref = { ecosystem: "npm", name: PKG, version: "1.0.0" };
  const thrower = async () => { throw new Error("ECONNRESET"); };
  assert.deepEqual(await checkMaintainers(ref, { fetchImpl: thrower }), { signals: [], evidence: ["maintainers-check-failed"] });
  const five = async () => new Response("", { status: 500 });
  assert.deepEqual(await checkMaintainers(ref, { fetchImpl: five }), { signals: [], evidence: ["maintainers-check-failed"] });
  const hang = (_u, o) => new Promise((_, rej) => o.signal.addEventListener("abort", () => rej(o.signal.reason)));
  const t0 = Date.now();
  const keepAlive = setTimeout(() => {}, 5000); // AbortSignal.timeout's timer is unref'd; a real socket holds the loop
  try {
    assert.deepEqual(await checkMaintainers(ref, { fetchImpl: hang, timeoutMs: 50 }), { signals: [], evidence: ["maintainers-check-failed"] });
  } finally { clearTimeout(keepAlive); }
  assert.ok(Date.now() - t0 < 2000, "bounded by the timeout");
  const s = sandbox();
  try {
    const rep = await assessServer({ command: "npx", args: ["-y", `${PKG}@1.0.0`] }, { stateDir: s.stateDir, home: s.home, fetchImpl: thrower, policy: { lookup: "registry" } });
    assert.equal(rep.reasons.includes("single-maintainer"), false);
  } finally { s.done(); }
});

test("bounded: the maintainer lookup uses the repository-link per-request timeout by default", async () => {
  const { REPO_LINK_LIMITS } = await import("../cli/mcp-repo-link.mjs");
  let seen = null, ms = null;
  const orig = AbortSignal.timeout;
  AbortSignal.timeout = (n) => { ms = n; return orig.call(AbortSignal, n); };
  try {
    const spy = async (_u, o) => { seen = o; return new Response("{}", { status: 200 }); };
    await checkMaintainers({ ecosystem: "pypi", name: "x-mcp" }, { fetchImpl: spy });
  } finally { AbortSignal.timeout = orig; }
  assert.ok(seen.signal instanceof AbortSignal, "every request carries an abort signal");
  assert.equal(seen.redirect, "error");
  assert.equal(ms, REPO_LINK_LIMITS.requestMs);
});
