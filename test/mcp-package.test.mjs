// analyzePackage / scanPathWithPackages — MCP server package code analysis, hermetic (registry stubbed).
//
// Properties pinned:
//   1. Each crafted package lands on the expected verdict via the expected heuristic id.
//   2. Integrity mismatch and registry failures FAIL CLOSED (REVIEW or worse) with a clear note.
//   3. Privacy: only registry hosts are contacted, redirects are refused, and only the name/version
//      appears in the request URLs.
//   4. Without --packages, a config scan resolves packages and lists them as not analysed, and does
//      not call fetch at all.
//   5. Cache by name@version + integrity.
//
//   node --test test/mcp-package.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { analyzePackage, scanPathWithPackages, packagesEnabled } from "../cli/mcp-package.mjs";
import { resolveMcpPackages as barrelResolve, analyzePackage as barrelAnalyze } from "../scan.mjs";
import { buildEngine } from "../cli/hook-core.mjs";
import { makeTgz, NPM_FIXTURES, PYPI_FIXTURES, registryStub, makeZip } from "./fixtures/mcp-package/build.mjs";

const CLI = fileURLToPath(new URL("../cli/moorai-scan.mjs", import.meta.url));
const engine = buildEngine({});
const npm = (name) => ({ ecosystem: "npm", artifact: makeTgz(NPM_FIXTURES[name]) });
const ids = (r) => r.findings.map((f) => f.threatId);

function stubAll(extra = {}) {
  return registryStub({
    "clean-mcp-server": npm("clean-mcp-server"),
    "postinstall-mcp-server": npm("postinstall-mcp-server"),
    "harvest-mcp-server": npm("harvest-mcp-server"),
    "blob-mcp-server": npm("blob-mcp-server"),
    "mcp-server-evilsetup": { ecosystem: "pypi", artifact: makeTgz(PYPI_FIXTURES["mcp-server-evilsetup"]) },
    ...extra
  });
}

test("barrel exports resolveMcpPackages and analyzePackage", () => {
  assert.equal(typeof barrelResolve, "function");
  assert.equal(typeof barrelAnalyze, "function");
});

test("clean package → CLEAN, integrity verified, analysed", async () => {
  const { fetchImpl } = stubAll();
  const r = await analyzePackage({ ecosystem: "npm", name: "clean-mcp-server", version: null }, { fetchImpl, engine });
  assert.equal(r.analysed, true);
  assert.equal(r.verdict, "CLEAN", JSON.stringify(r.findings));
  assert.equal(r.package, "clean-mcp-server@1.0.0");
  assert.deepEqual(r.integrity, { algorithm: "sha512", verified: true });
  assert.equal(r.summary.filesTotal, 3);
});

test("postinstall `curl | sh` → DO-NOT-INSTALL via pkg-install-script-remote", async () => {
  const { fetchImpl } = stubAll();
  const r = await analyzePackage({ ecosystem: "npm", name: "postinstall-mcp-server", version: "1.0.0" }, { fetchImpl, engine });
  assert.ok(ids(r).includes("pkg-install-script-remote"), JSON.stringify(ids(r)));
  assert.equal(r.verdict, "DO-NOT-INSTALL");
  const f = r.findings.find((x) => x.threatId === "pkg-install-script-remote");
  assert.equal(f.package, "postinstall-mcp-server@1.0.0");
  assert.equal(f.ecosystem, "npm");
  assert.equal(f.relativePath, "package.json");
});

test("a benign postinstall is REVIEW (pkg-install-script), not DO-NOT-INSTALL", async () => {
  const files = [
    { name: "package/package.json", data: JSON.stringify({ name: "build-mcp", version: "1.0.0", scripts: { postinstall: "node scripts/build.js" } }) },
    { name: "package/index.js", data: "module.exports = 1;\n" }
  ];
  const { fetchImpl } = registryStub({ "build-mcp": { ecosystem: "npm", artifact: makeTgz(files) } });
  const r = await analyzePackage({ ecosystem: "npm", name: "build-mcp", version: null }, { fetchImpl, engine });
  assert.ok(ids(r).includes("pkg-install-script"));
  assert.equal(r.verdict, "REVIEW");
});

test("env dump + POST → DO-NOT-INSTALL via pkg-env-dump-egress", async () => {
  const { fetchImpl } = stubAll();
  const r = await analyzePackage({ ecosystem: "npm", name: "harvest-mcp-server", version: null }, { fetchImpl, engine });
  assert.ok(ids(r).includes("pkg-env-dump-egress"), JSON.stringify(ids(r)));
  assert.equal(r.verdict, "DO-NOT-INSTALL");
});

test("eval of a base64 blob → DO-NOT-INSTALL via pkg-obfuscated-exec", async () => {
  const { fetchImpl } = stubAll();
  const r = await analyzePackage({ ecosystem: "npm", name: "blob-mcp-server", version: null }, { fetchImpl, engine });
  assert.ok(ids(r).includes("pkg-obfuscated-exec"), JSON.stringify(ids(r)));
  assert.equal(r.verdict, "DO-NOT-INSTALL");
  assert.equal(r.findings.find((f) => f.threatId === "pkg-obfuscated-exec").relativePath, "lib/init.js");
});

test("PyPI sdist whose setup.py cmdclass spawns a shell → DO-NOT-INSTALL via pkg-setup-cmdclass-exec", async () => {
  const { fetchImpl } = stubAll();
  const r = await analyzePackage({ ecosystem: "pypi", name: "mcp-server-evilsetup", version: null }, { fetchImpl, engine });
  assert.ok(ids(r).includes("pkg-setup-cmdclass-exec"), JSON.stringify(ids(r)));
  assert.equal(r.verdict, "DO-NOT-INSTALL");
  assert.deepEqual(r.integrity, { algorithm: "sha256", verified: true });
  assert.equal(r.artifact.kind, "sdist");
});

test("PyPI wheel (zip) with an import-bearing .pth → REVIEW via pkg-pth-autoexec", async () => {
  const whl = makeZip([
    { name: "pthmcp/__init__.py", data: "x = 1\n" },
    { name: "pthmcp-0.1.0.pth", data: "import os; os.getcwd()\n" }
  ]);
  const { fetchImpl } = registryStub({ pthmcp: { ecosystem: "pypi", kind: "wheel", artifact: whl } });
  const r = await analyzePackage({ ecosystem: "pypi", name: "pthmcp", version: null }, { fetchImpl, engine });
  assert.equal(r.artifact.kind, "wheel");
  assert.ok(ids(r).includes("pkg-pth-autoexec"), JSON.stringify(ids(r)));
  assert.equal(r.verdict, "REVIEW");
});

test("typosquat name → pkg-typosquat (REVIEW) even for otherwise clean code", async () => {
  const { fetchImpl } = registryStub({ expresss: { ecosystem: "npm", artifact: makeTgz(NPM_FIXTURES["clean-mcp-server"]) } });
  const r = await analyzePackage({ ecosystem: "npm", name: "expresss", version: null }, { fetchImpl, engine });
  assert.ok(ids(r).includes("pkg-typosquat"));
  assert.equal(r.verdict, "REVIEW");
});

test("a package first published < 30 days ago gets a new-package NOTE, not a worse verdict", async () => {
  const now = Date.parse("2026-09-16T00:00:00Z");
  const { fetchImpl } = registryStub({ "clean-mcp-server": { ...npm("clean-mcp-server"), createdAt: "2026-09-10T00:00:00Z" } });
  const r = await analyzePackage({ ecosystem: "npm", name: "clean-mcp-server", version: null }, { fetchImpl, engine, now });
  assert.deepEqual(r.notes, [{ id: "new-package", ageDays: 6 }]);
  assert.equal(r.verdict, "CLEAN");
});

test("INTEGRITY MISMATCH fails closed: REVIEW, not analysed, clear note", async () => {
  const { fetchImpl } = registryStub({ "clean-mcp-server": { ...npm("clean-mcp-server"), tamper: true } });
  const r = await analyzePackage({ ecosystem: "npm", name: "clean-mcp-server", version: null }, { fetchImpl, engine });
  assert.equal(r.verdict, "REVIEW");
  assert.equal(r.analysed, false);
  assert.ok(r.notes.some((n) => n.id === "integrity-mismatch"), JSON.stringify(r.notes));
  assert.equal(r.integrity.verified, false);
});

test("registry 404 / network error / off-registry tarball URL all fail closed", async () => {
  const { fetchImpl } = registryStub({});
  const r404 = await analyzePackage({ ecosystem: "npm", name: "nope-mcp", version: null }, { fetchImpl, engine });
  assert.equal(r404.verdict, "REVIEW");
  assert.deepEqual(r404.notes, [{ id: "registry-http-404" }]);

  const boom = async () => { throw new Error("offline"); };
  const rNet = await analyzePackage({ ecosystem: "pypi", name: "mcp-server-fetch", version: null }, { fetchImpl: boom, engine });
  assert.equal(rNet.verdict, "REVIEW");
  assert.deepEqual(rNet.notes, [{ id: "registry-network-error" }]);

  const off = registryStub({ "clean-mcp-server": { ...npm("clean-mcp-server"), tarballUrl: "https://evil.example/clean.tgz" } });
  const rOff = await analyzePackage({ ecosystem: "npm", name: "clean-mcp-server", version: null }, { fetchImpl: off.fetchImpl, engine });
  assert.equal(rOff.verdict, "REVIEW");
  assert.deepEqual(rOff.notes, [{ id: "registry-artifact-off-registry" }]);
  assert.ok(!off.urls.some((u) => u.url.includes("evil.example")), "must never fetch an off-registry URL");
});

test("PRIVACY: only registry hosts, redirects refused, URL carries only the package name/version", async () => {
  const stub = stubAll();
  await analyzePackage({ ecosystem: "npm", name: "harvest-mcp-server", version: null }, { fetchImpl: stub.fetchImpl, engine });
  await analyzePackage({ ecosystem: "pypi", name: "mcp-server-evilsetup", version: null }, { fetchImpl: stub.fetchImpl, engine });
  assert.ok(stub.urls.length >= 4);
  for (const { url, opts } of stub.urls) {
    assert.ok(["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"].includes(new URL(url).hostname), url);
    assert.equal(opts.redirect, "error");
    assert.ok(!opts.body, "no request body");
    assert.deepEqual(Object.keys(opts.headers || {}).filter((h) => h !== "accept"), []);
  }
});

test("scanPathWithPackages WITHOUT --packages: resolves, lists as not analysed, never fetches", async () => {
  const d = mkdtempSync(join(tmpdir(), "moorai-pkgcfg-"));
  writeFileSync(join(d, ".mcp.json"), JSON.stringify({ mcpServers: {
    a: { command: "npx", args: ["-y", "postinstall-mcp-server"] },
    b: { command: "docker", args: ["run", "-i", "img/x"] },
    c: { command: "node", args: [join(d, "secret-dir", "server.js")] }
  } }));
  let called = 0;
  const r = await scanPathWithPackages(d, { policy: {}, engine, packages: false, fetchImpl: async () => { called++; } });
  assert.equal(called, 0);
  assert.equal(r.packages.length, 3);
  const a = r.packages.find((p) => p.ecosystem === "npm");
  assert.equal(a.analysed, false);
  assert.match(a.reason, /--packages/);
  assert.deepEqual(a.configs, [".mcp.json"]);
  assert.equal(r.packages.find((p) => p.ecosystem === "docker").analysed, false);
  assert.equal(r.packages.find((p) => p.ecosystem === "local").package, "server.js");
  assert.ok(!JSON.stringify(r).includes(d), "no absolute path leaks from a local launch path");
  assert.deepEqual(r.summary.packages, { total: 3, analysed: 0 });
});

test("scanPathWithPackages WITH --packages: the package verdict drives the overall verdict", async () => {
  const d = mkdtempSync(join(tmpdir(), "moorai-pkgcfg-"));
  writeFileSync(join(d, ".mcp.json"), JSON.stringify({ mcpServers: { a: { command: "npx", args: ["-y", "postinstall-mcp-server"] } } }));
  const { fetchImpl } = stubAll();
  const r = await scanPathWithPackages(d, { policy: {}, engine, packages: true, fetchImpl });
  assert.equal(r.packages[0].analysed, true);
  assert.equal(r.verdict, "DO-NOT-INSTALL");
  assert.ok(r.drivers.includes("package:postinstall-mcp-server@1.0.0"), JSON.stringify(r.drivers));
});

test("cache: second analysis of the same name@version+integrity does not download again", async () => {
  const cacheDir = mkdtempSync(join(tmpdir(), "moorai-pkgcache-"));
  const stub = stubAll();
  const first = await analyzePackage({ ecosystem: "npm", name: "blob-mcp-server", version: null }, { fetchImpl: stub.fetchImpl, engine, cacheDir });
  const downloads = () => stub.urls.filter((u) => u.url.endsWith(".tgz")).length;
  assert.equal(downloads(), 1);
  const second = await analyzePackage({ ecosystem: "npm", name: "blob-mcp-server", version: null }, { fetchImpl: stub.fetchImpl, engine, cacheDir });
  assert.equal(downloads(), 1);
  assert.equal(second.cached, true);
  assert.equal(second.verdict, first.verdict);
  assert.equal(readdirSync(join(cacheDir, "mcp-packages")).length, 1);
});

test("packagesEnabled: --packages flag or MOORAI_SCAN_PACKAGES=1 only", () => {
  assert.equal(packagesEnabled(["x"], {}), false);
  assert.equal(packagesEnabled(["x", "--packages"], {}), true);
  assert.equal(packagesEnabled(["x"], { MOORAI_SCAN_PACKAGES: "1" }), true);
  assert.equal(packagesEnabled(["x"], { MOORAI_SCAN_PACKAGES: "0" }), false);
});

test("CLI: config scan lists packages (json + md) without network; bad --package exits 64", () => {
  const d = mkdtempSync(join(tmpdir(), "moorai-pkgcli-"));
  writeFileSync(join(d, ".mcp.json"), JSON.stringify({ mcpServers: { a: { command: "uvx", args: ["mcp-server-fetch"] } } }));
  const env = { ...process.env };
  delete env.MOORAI_SCAN_PACKAGES;
  const j = spawnSync(process.execPath, [CLI, d], { encoding: "utf8", env });
  assert.equal(j.status, 0, j.stderr);
  const doc = JSON.parse(j.out || j.stdout);
  assert.equal(doc.packages[0].package, "mcp-server-fetch");
  assert.equal(doc.packages[0].analysed, false);
  const md = spawnSync(process.execPath, [CLI, d, "--format", "md"], { encoding: "utf8", env });
  assert.match(md.stdout, /## MCP server packages/);
  assert.match(md.stdout, /mcp-server-fetch/);
  const bad = spawnSync(process.execPath, [CLI, "--package", "cargo:serde"], { encoding: "utf8", env });
  assert.equal(bad.status, 64);
});
