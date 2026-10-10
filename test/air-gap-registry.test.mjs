// Registry mirrors, offline mode and request timeouts for the package checkers (moorai-mcp-check,
// moorai-scan --package/--packages, and the reputation lookup behind policy mcpReputation.lookup).
// Measured before: every registry host was hardcoded, there was no offline switch (moorai-mcp-check 10.1s,
// moorai-scan --package 10.6s on a host with no route out), and registry.mjs / download.mjs had no
// timeout at all. Every fetch here is a fake; the spawned CLIs point their mirrors at a closed loopback
// port, so even a regression cannot reach a real registry.
//
//   node --test --import ./test/hermetic-env.mjs test/air-gap-registry.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { mirrorUrl, endpoint, invalidMirrors, MIRROR_ENV } from "../cli/mcp-package/endpoints.mjs";
import { fetchRegistryMeta, fetchServerJson } from "../cli/mcp-package/metadata.mjs";
import { resolveNpm, resolvePypi } from "../cli/mcp-package/registry.mjs";
import { githubArchiveUrl } from "../cli/mcp-package/github.mjs";
import { downloadToFile } from "../cli/mcp-package/download.mjs";
import { checkRepoLink } from "../cli/mcp-repo-link.mjs";
import { parseCheckSpec } from "../cli/mcp-package/check-spec.mjs";
import { mcpCheck } from "../cli/mcp-package/check.mjs";
import { runMcpCheck } from "../cli/mcp-package/check-cli.mjs";
import { analyzePackage } from "../cli/mcp-package.mjs";
import { assessServer, feedVerdict } from "../cli/mcp-reputation.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const NOW = Date.parse("2026-10-01T00:00:00Z");
const ALL_ENV = [...Object.values(MIRROR_ENV), "MOORAI_OFFLINE"];

async function withEnv(vars, fn) {
  const saved = Object.fromEntries(ALL_ENV.map((k) => [k, process.env[k]]));
  for (const k of ALL_ENV) delete process.env[k];
  Object.assign(process.env, vars);
  try { return await fn(); } finally {
    for (const k of ALL_ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  }
}

function recorder(routes = {}) {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(String(url));
    const hit = routes[String(url)];
    if (hit === undefined) return new Response("", { status: 599 });
    if (typeof hit === "function") return hit();
    return new Response(typeof hit === "string" ? hit : JSON.stringify(hit), { status: 200 });
  };
  return { calls, fetchImpl };
}
const forbidden = () => { const calls = []; return { calls, fetchImpl: async (url) => { calls.push(String(url)); throw new Error("network attempted"); } }; };
// A fetch that only ever settles by its abort signal.
const hanging = async (url, opts = {}) => new Promise((_, rej) => {
  if (opts.signal) opts.signal.addEventListener("abort", () => rej(opts.signal.reason || new Error("aborted")));
});
const settlesWithin = (ms, p) => Promise.race([p.then((v) => ({ v }), (e) => ({ e })), new Promise((r) => setTimeout(() => r({ hung: true }), ms))]);

function sandbox() {
  const root = mkdtempSync(join(tmpdir(), "moorai-airgap-"));
  const home = join(root, "home"), stateDir = join(root, "state"), cwd = join(root, "proj");
  for (const d of [home, stateDir, cwd]) mkdirSync(d, { recursive: true });
  return { root, home, stateDir, cwd, done: () => rmTree(root) };
}

// ---- mirror URLs ----------------------------------------------------------------------------------

test("mirror URLs: https only, no credentials, query or fragment; normalised to a trailing slash", () => {
  assert.equal(mirrorUrl("https://npm.corp.example/api/npm/remote"), "https://npm.corp.example/api/npm/remote/");
  assert.equal(mirrorUrl("https://npm.corp.example:8443/"), "https://npm.corp.example:8443/");
  for (const bad of ["http://npm.corp.example/", "https://u:p@npm.corp.example/", "https://npm.corp.example/?t=1", "https://npm.corp.example/#x", "npm.corp.example", "file:///etc/passwd"]) {
    assert.equal(mirrorUrl(bad), null, bad);
  }
  assert.deepEqual(invalidMirrors({ MOORAI_NPM_REGISTRY: "http://x.example/", MOORAI_PYPI_URL: "https://ok.example/" }), ["MOORAI_NPM_REGISTRY"]);
  assert.equal(endpoint("npm", {}), "https://registry.npmjs.org/");
  assert.equal(endpoint("npm", { MOORAI_NPM_REGISTRY: "http://x.example/" }), null, "an invalid mirror disables the endpoint, never falls back to the public host");
});

test("metadata: npm, PyPI and MCP Registry requests go to the configured mirrors", () => withEnv({
  MOORAI_NPM_REGISTRY: "https://npm.mirror.example/npm/", MOORAI_PYPI_URL: "https://pypi.mirror.example/root/", MOORAI_MCP_REGISTRY: "https://mcp.mirror.example/"
}, async () => {
  const { calls, fetchImpl } = recorder({
    "https://npm.mirror.example/npm/@acme%2fweather": { name: "@acme/weather" },
    "https://pypi.mirror.example/root/pypi/weather-mcp/json": { info: {} },
    "https://mcp.mirror.example/v0.1/servers/io.github.acme%2Fweather/versions/latest": { server: {} }
  });
  assert.equal((await fetchRegistryMeta({ ecosystem: "npm", name: "@acme/weather" }, { fetchImpl })).status, 200);
  assert.equal((await fetchRegistryMeta({ ecosystem: "pypi", name: "weather-mcp" }, { fetchImpl })).status, 200);
  assert.equal((await fetchServerJson("io.github.acme/weather", { fetchImpl })).status, 200);
  assert.ok(calls.every((u) => /mirror\.example/.test(u)), calls.join("\n"));
}));

test("metadata: an invalid mirror makes no request at all", () => withEnv({ MOORAI_NPM_REGISTRY: "http://npm.mirror.example/" }, async () => {
  const f = forbidden();
  assert.equal((await fetchRegistryMeta({ ecosystem: "npm", name: "weather" }, { fetchImpl: f.fetchImpl })).status, 0);
  assert.deepEqual(f.calls, []);
}));

test("registry: artifacts are pinned to the mirror's own host when a mirror is set", () => withEnv({
  MOORAI_NPM_REGISTRY: "https://npm.mirror.example/npm/", MOORAI_PYPI_URL: "https://pypi.mirror.example/"
}, async () => {
  const meta = (tarball) => ({ "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { dist: { tarball, integrity: "sha512-AA" } } } });
  const ok = recorder({ "https://npm.mirror.example/npm/weather": meta("https://npm.mirror.example/npm/weather/-/weather-1.0.0.tgz") });
  assert.equal((await resolveNpm({ ecosystem: "npm", name: "weather" }, ok.fetchImpl)).url, "https://npm.mirror.example/npm/weather/-/weather-1.0.0.tgz");
  const pub = recorder({ "https://npm.mirror.example/npm/weather": meta("https://registry.npmjs.org/weather/-/weather-1.0.0.tgz") });
  await assert.rejects(resolveNpm({ ecosystem: "npm", name: "weather" }, pub.fetchImpl), (e) => e.code === "artifact-off-registry", "a mirror's metadata must not send the download to the public host");
  const py = recorder({ "https://pypi.mirror.example/pypi/weather-mcp/json": { info: { version: "1.0" }, urls: [{ url: "https://pypi.mirror.example/packages/w-1.0.tar.gz", packagetype: "sdist", digests: { sha256: "ab" } }], releases: {} } });
  assert.equal((await resolvePypi({ ecosystem: "pypi", name: "weather-mcp" }, py.fetchImpl)).url, "https://pypi.mirror.example/packages/w-1.0.tar.gz");
}));

test("github: archive and raw-manifest requests use MOORAI_GITHUB_CODELOAD_URL / MOORAI_GITHUB_RAW_URL", () => withEnv({
  MOORAI_GITHUB_CODELOAD_URL: "https://codeload.mirror.example/gh/", MOORAI_GITHUB_RAW_URL: "https://raw.mirror.example/", MOORAI_NPM_REGISTRY: "https://npm.mirror.example/"
}, async () => {
  assert.equal(githubArchiveUrl({ name: "acme/weather", version: "v1" }), "https://codeload.mirror.example/gh/acme/weather/tar.gz/v1");
  const man = { name: "weather", version: "1.0.0", repository: { type: "git", url: "git+https://github.com/acme/weather.git" } };
  const { calls, fetchImpl } = recorder({
    "https://npm.mirror.example/weather/1.0.0": man,
    "https://raw.mirror.example/acme/weather/HEAD/package.json": JSON.stringify({ name: "weather" })
  });
  const r = await checkRepoLink({ ecosystem: "npm", name: "weather", version: "1.0.0" }, { fetchImpl });
  assert.ok(calls.includes("https://raw.mirror.example/acme/weather/HEAD/package.json"), calls.join("\n"));
  assert.ok(r.evidence.includes("repo-verified"), JSON.stringify(r));
}));

// ---- offline ------------------------------------------------------------------------------------

test("offline: no module makes a request with MOORAI_OFFLINE=1", () => withEnv({ MOORAI_OFFLINE: "1" }, async () => {
  const f = forbidden();
  assert.equal((await fetchRegistryMeta({ ecosystem: "npm", name: "weather" }, { fetchImpl: f.fetchImpl })).status, 0);
  assert.equal((await fetchServerJson("io.github.acme/weather", { fetchImpl: f.fetchImpl })).status, 0);
  await checkRepoLink({ ecosystem: "npm", name: "weather" }, { fetchImpl: f.fetchImpl });
  await assert.rejects(resolveNpm({ ecosystem: "npm", name: "weather" }, f.fetchImpl), (e) => e.code === "offline");
  const s = sandbox();
  try {
    const e = await analyzePackage({ ecosystem: "npm", name: "weather", version: "1.0.0" }, { fetchImpl: f.fetchImpl, workDir: s.root });
    assert.equal(e.verdict, "REVIEW", "a package that was not analysed stays fail-closed");
    assert.equal(e.reason, "not-checked (offline)");
    const fv = await feedVerdict({ ecosystem: "npm", name: "weather" }, { policy: { feed: true }, fetchImpl: f.fetchImpl, stateDir: s.stateDir });
    assert.equal(fv.available, false);
    assert.equal(fv.offline, true);
  } finally { s.done(); }
  assert.deepEqual(f.calls, []);
}));

test("offline: moorai-mcp-check --offline reports not-checked (offline), makes no request and does not wait", async () => {
  const f = forbidden();
  let out = "";
  const t0 = Date.now();
  await withEnv({}, () => runMcpCheck(["npm:weather-mcp@1.0.0", "--json", "--no-policy", "--offline"], { out: { write: (t) => { out += t; } }, err: { write() {} }, fetchImpl: f.fetchImpl }));
  const ms = Date.now() - t0;
  assert.deepEqual(f.calls, []);
  assert.ok(ms < 2000, `took ${ms}ms`);
  const r = JSON.parse(out);
  const by = Object.fromEntries(r.checks.map((c) => [c.id, c]));
  for (const id of ["age", "maintainers", "install-scripts", "auth", "credentials"]) {
    assert.equal(by[id].status, "not-checked", id);
    assert.match(by[id].reason, /not-checked \(offline\)/, `${id}: ${by[id].reason}`);
  }
  assert.match(by.publisher.reason, /not-checked \(offline\)/);
  assert.equal(by.pinning.status, "pass", "offline checks still run");
  assert.equal(process.env.MOORAI_OFFLINE, undefined, "--offline must not leak into the caller's environment");
});

test("offline: mcpCheck with MOORAI_OFFLINE=1 and an enabled feed says the feed was not checked", () => withEnv({ MOORAI_OFFLINE: "1" }, async () => {
  const s = sandbox();
  try {
    const f = forbidden();
    const r = await mcpCheck(parseCheckSpec("npm:weather-mcp@1.0.0"), { fetchImpl: f.fetchImpl, policy: { mcpReputation: { feed: true } }, home: s.home, cwd: s.cwd, platform: "linux", env: {}, stateDir: s.stateDir, now: NOW });
    assert.match(r.skilltriage.reason, /not-checked \(offline\)/);
    assert.deepEqual(f.calls, []);
  } finally { s.done(); }
}));

test("offline: the reputation registry lookup (policy lookup=registry) makes no request", () => withEnv({ MOORAI_OFFLINE: "1" }, async () => {
  const s = sandbox();
  try {
    const f = forbidden();
    const rep = await assessServer({ command: "npx", args: ["-y", "some-new-mcp@1.0.0"] }, { stateDir: s.stateDir, home: s.home, fetchImpl: f.fetchImpl, policy: { lookup: "registry", feed: true } });
    assert.deepEqual(f.calls, []);
    assert.ok(rep.evidence.includes("registry-not-checked-offline"), JSON.stringify(rep.evidence));
  } finally { s.done(); }
}));

test("mirrors: the reputation registry lookup sends every request to the mirrors", () => withEnv({
  MOORAI_NPM_REGISTRY: "https://npm.mirror.example/", MOORAI_GITHUB_RAW_URL: "https://raw.mirror.example/"
}, async () => {
  const s = sandbox();
  try {
    const { calls, fetchImpl } = recorder({});
    await assessServer({ command: "npx", args: ["-y", "some-new-mcp@1.0.0"] }, { stateDir: s.stateDir, home: s.home, fetchImpl, policy: { lookup: "registry" } });
    assert.ok(calls.length >= 1);
    assert.ok(calls.every((u) => u.startsWith("https://npm.mirror.example/")), calls.join("\n"));
  } finally { s.done(); }
}));

// ---- timeouts -----------------------------------------------------------------------------------

test("timeouts: registry metadata and artifact downloads give up instead of hanging", () => withEnv({}, async () => {
  const meta = await settlesWithin(3000, resolveNpm({ ecosystem: "npm", name: "weather" }, hanging, { timeoutMs: 200 }));
  assert.ok(!meta.hung, "resolveNpm never settled against an upstream that does not answer");
  assert.equal(meta.e && meta.e.code, "timeout");
  const s = sandbox();
  try {
    const dl = await settlesWithin(3000, downloadToFile(hanging, "https://registry.npmjs.org/w/-/w-1.tgz", join(s.root, "a"), { cap: 1024, timeoutMs: 200 }));
    assert.ok(!dl.hung, "downloadToFile never settled against an upstream that does not answer");
    assert.equal(dl.e && dl.e.code, "timeout");
    // Headers arrive, then the body stalls: the idle timer covers the body too.
    const stall = async (url, opts = {}) => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1, 2, 3])); opts.signal.addEventListener("abort", () => c.error(new Error("aborted"))); } }), { status: 200 });
    const st = await settlesWithin(3000, downloadToFile(stall, "https://registry.npmjs.org/w/-/w-1.tgz", join(s.root, "b"), { cap: 1024, timeoutMs: 200 }));
    assert.ok(!st.hung, "a stalled body never settled");
    assert.equal(st.e && st.e.code, "timeout");
    assert.equal(existsSync(join(s.root, "b")), false, "the partial file is removed");
  } finally { s.done(); }
}));

// ---- the CLIs, end to end -----------------------------------------------------------------------

// Mirrors at a closed loopback port: a broken --offline fails fast with a network error, never a real call.
const CLOSED = { MOORAI_NPM_REGISTRY: "https://127.0.0.1:9/", MOORAI_PYPI_URL: "https://127.0.0.1:9/", MOORAI_MCP_REGISTRY: "https://127.0.0.1:9/", MOORAI_GITHUB_RAW_URL: "https://127.0.0.1:9/", MOORAI_GITHUB_CODELOAD_URL: "https://127.0.0.1:9/" };
const cliEnv = (home, extra = {}) => { const e = { ...process.env, HOME: home, USERPROFILE: home, ...CLOSED }; delete e.MOORAI_OFFLINE; return { ...e, ...extra }; };

test("moorai-scan --package --offline: REVIEW with not-checked (offline), no request, no wait", () => {
  const s = sandbox();
  try {
    for (const [args, extra] of [[["--package", "npm:weather-mcp@1.0.0", "--offline"], {}], [["--package", "npm:weather-mcp@1.0.0"], { MOORAI_OFFLINE: "1" }]]) {
      const t0 = Date.now();
      const r = spawnSync(process.execPath, [join(ROOT, "cli", "moorai-scan.mjs"), ...args], { encoding: "utf8", env: cliEnv(s.home, extra) });
      const ms = Date.now() - t0;
      assert.equal(r.status, 1, r.stderr);
      const doc = JSON.parse(r.stdout);
      assert.equal(doc.verdict, "REVIEW");
      assert.equal(doc.packages[0].reason, "not-checked (offline)", JSON.stringify(doc.packages[0]));
      assert.ok(ms < 5000, `took ${ms}ms`);
    }
  } finally { s.done(); }
});

test("moorai-scan <path> --packages --offline lists each package as not-checked (offline)", () => {
  const s = sandbox();
  try {
    writeFileSync(join(s.cwd, ".mcp.json"), JSON.stringify({ mcpServers: { w: { command: "npx", args: ["-y", "weather-mcp@1.0.0"] } } }));
    const r = spawnSync(process.execPath, [join(ROOT, "cli", "moorai-scan.mjs"), s.cwd, "--packages", "--offline"], { encoding: "utf8", env: cliEnv(s.home) });
    const doc = JSON.parse(r.stdout);
    assert.equal(doc.packages[0].reason, "not-checked (offline)", JSON.stringify(doc.packages[0]));
    assert.equal(doc.packages[0].analysed, false);
  } finally { s.done(); }
});

test("moorai-mcp-check and moorai-scan refuse an invalid mirror instead of using the public host", () => {
  const s = sandbox();
  try {
    const a = spawnSync(process.execPath, [join(ROOT, "cli", "moorai-mcp-check.mjs"), "npm:weather-mcp@1.0.0", "--no-policy"], { encoding: "utf8", env: cliEnv(s.home, { MOORAI_NPM_REGISTRY: "http://npm.mirror.example/" }) });
    assert.equal(a.status, 2, a.stdout + a.stderr);
    assert.match(a.stderr, /MOORAI_NPM_REGISTRY/);
    const b = spawnSync(process.execPath, [join(ROOT, "cli", "moorai-scan.mjs"), "--package", "npm:weather-mcp@1.0.0"], { encoding: "utf8", env: cliEnv(s.home, { MOORAI_PYPI_URL: "https://u:p@pypi.mirror.example/" }) });
    assert.equal(b.status, 64, b.stdout + b.stderr);
    assert.match(b.stderr, /MOORAI_PYPI_URL/);
  } finally { s.done(); }
});
