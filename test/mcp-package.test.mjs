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
import { mkdtempSync, writeFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { analyzePackage, scanPathWithPackages, packagesEnabled } from "../cli/mcp-package.mjs";
import { resolveMcpPackages as barrelResolve, analyzePackage as barrelAnalyze } from "../scan.mjs";
import { buildEngine } from "../cli/hook-core.mjs";
import { LIMITS } from "../cli/mcp-package/archive.mjs";
import { downloadToFile } from "../cli/mcp-package/download.mjs";
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

// ---- streamed download + extraction ----
//
// Every test below serves the artifact in chunks far smaller than the artifact, so an implementation
// that buffered the body and hashed it at the end would still pass — but one that hashed only the FIRST
// chunk, or dropped the traversal guard once entries stopped arriving whole, would not.

test("STREAMED: a chunked body is hashed across chunk boundaries and still verifies", async () => {
  const workDir = mkdtempSync(join(tmpdir(), "moorai-stream-"));
  const { fetchImpl } = registryStub({ "clean-mcp-server": npm("clean-mcp-server") }, { chunkBytes: 64 });
  const r = await analyzePackage({ ecosystem: "npm", name: "clean-mcp-server", version: null }, { fetchImpl, engine, workDir });
  assert.equal(r.analysed, true);
  assert.equal(r.verdict, "CLEAN", JSON.stringify(r.findings));
  assert.deepEqual(r.integrity, { algorithm: "sha512", verified: true });
  assert.equal(r.summary.filesTotal, 3);
  assert.ok(r.artifact.bytes > 0);
  assert.deepEqual(readdirSync(workDir), [], "artifact file and extraction dir both removed");
});

test("STREAMED: an integrity mismatch mid-stream fails closed and leaves no temp file", async () => {
  const workDir = mkdtempSync(join(tmpdir(), "moorai-stream-"));
  const { fetchImpl } = registryStub({ "clean-mcp-server": { ...npm("clean-mcp-server"), tamper: true } }, { chunkBytes: 512 });
  const r = await analyzePackage({ ecosystem: "npm", name: "clean-mcp-server", version: null }, { fetchImpl, engine, workDir });
  assert.equal(r.verdict, "REVIEW");
  assert.equal(r.analysed, false);
  assert.equal(r.integrity.verified, false);
  assert.ok(r.notes.some((n) => n.id === "integrity-mismatch"), JSON.stringify(r.notes));
  assert.deepEqual(readdirSync(workDir), [], "the downloaded artifact is deleted even on an integrity failure");
});

test("STREAMED: a traversal entry is still rejected when the archive arrives in chunks", async () => {
  const workDir = mkdtempSync(join(tmpdir(), "moorai-stream-"));
  const { fetchImpl } = registryStub({ "traversal-mcp-server": npm("traversal-mcp-server") }, { chunkBytes: 256 });
  const r = await analyzePackage({ ecosystem: "npm", name: "traversal-mcp-server", version: null }, { fetchImpl, engine, workDir });
  assert.deepEqual(r.notes, [{ id: "unsafe-archive-entries", count: 3 }]);
  assert.equal(r.summary.archive.skipped, 1, "the symlink entry is skipped, never created");
  assert.ok(["REVIEW", "DO-NOT-INSTALL"].includes(r.verdict), r.verdict);
  assert.deepEqual(readdirSync(workDir), []);
});

test("STREAMED: an artifact over the extracted-size cap reports archive-limits-exceeded, not a verdict", async () => {
  const workDir = mkdtempSync(join(tmpdir(), "moorai-stream-"));
  const files = [
    { name: "package/package.json", data: JSON.stringify({ name: "big-mcp", version: "1.0.0" }) },
    { name: "package/a.js", data: "a".repeat(300 * 1024) },
    { name: "package/b.js", data: "b".repeat(300 * 1024) }
  ];
  const { fetchImpl } = registryStub({ "big-mcp": { ecosystem: "npm", artifact: makeTgz(files) } }, { chunkBytes: 4096 });
  const r = await analyzePackage({ ecosystem: "npm", name: "big-mcp", version: null },
    { fetchImpl, engine, workDir, limits: { ...LIMITS, maxTotalBytes: 400 * 1024 } });
  assert.ok(r.notes.some((n) => n.id === "archive-limits-exceeded"), JSON.stringify(r.notes));
  assert.equal(r.summary.archive.truncated, true);
  assert.equal(r.verdict, "REVIEW", "a partial read is never reported as CLEAN");
  assert.deepEqual(readdirSync(workDir), []);
});

// Resolves once a `moorai-pkg-*/artifact` under workDir holds at least `bytes` bytes on disk.
async function partialOnDisk(workDir, bytes) {
  const deadline = Date.now() + 10_000;
  for (;;) {
    for (const d of readdirSync(workDir)) {
      try { if (statSync(join(workDir, d, "artifact")).size >= bytes) return; } catch {}
    }
    if (Date.now() > deadline) throw new Error("the downloader never wrote the first chunk to disk");
    await new Promise((r) => setTimeout(r, 2));
  }
}

// The over-cap bytes are held back until the first chunk is ON DISK, so the breach happens mid-download
// with a real partial file to delete — the order a network download always has. Served as one burst, the
// breach landed before the temp file's async open: the file usually did not exist yet (so "the partial
// download is deleted" proved nothing), and under load the late open raced analyzePackage's recursive
// cleanup into ENOTEMPTY. That race is pinned on its own by the downloadToFile test below.
test("STREAMED: a body over the download cap fails closed before anything is extracted", async () => {
  const workDir = mkdtempSync(join(tmpdir(), "moorai-stream-"));
  const artifact = makeTgz(NPM_FIXTURES["clean-mcp-server"]);
  const stub = registryStub({ "clean-mcp-server": { ecosystem: "npm", artifact } });
  const HEAD = 64, CAP = 128;
  let partialWritten = false;
  const fetchImpl = async (url, opts) => {
    if (!url.endsWith(".tgz")) return stub.fetchImpl(url, opts);
    let sent = 0;
    return new Response(new ReadableStream({
      async pull(c) {
        if (sent === 0) { c.enqueue(new Uint8Array(artifact.subarray(0, HEAD))); sent = HEAD; return; }
        await partialOnDisk(workDir, HEAD);
        partialWritten = true;
        for (let i = HEAD; i < artifact.length; i += 64) c.enqueue(new Uint8Array(artifact.subarray(i, Math.min(i + 64, artifact.length))));
        c.close();
      }
    }), { status: 200 });
  };
  assert.ok(artifact.length > CAP, "the artifact must exceed the cap");
  const r = await analyzePackage({ ecosystem: "npm", name: "clean-mcp-server", version: null }, { fetchImpl, engine, workDir, downloadCap: CAP });
  assert.ok(partialWritten, "the cap was breached after a partial download reached disk");
  assert.equal(r.verdict, "REVIEW");
  assert.equal(r.analysed, false);
  assert.deepEqual(r.notes, [{ id: "download-too-large" }]);
  assert.deepEqual(readdirSync(workDir), [], "the partial download is deleted");
});

// pipeline() rejects as soon as the source throws, without waiting for the destination WriteStream's
// async open; download.mjs therefore awaits the stream's 'close' before removing the file. Measured on
// the code without that wait: 193-196 of 200 cap breaches left the file 20ms after the rejection.
test("downloadToFile: a cap breach before the temp file is open leaves no partial file behind", async () => {
    for (let i = 0; i < 20; i++) {
      const dest = join(mkdtempSync(join(tmpdir(), "moorai-dl-")), "artifact");
      const body = new ReadableStream({ start(c) { for (let k = 0; k < 4; k++) c.enqueue(new Uint8Array(64)); c.close(); } });
      await assert.rejects(downloadToFile(async () => new Response(body, { status: 200 }), "https://registry.npmjs.org/x.tgz", dest, { cap: 128 }), { code: "too-large" });
      await new Promise((r) => setTimeout(r, 20));
      assert.equal(existsSync(dest), false, `iteration ${i}: the partial file exists after the rejection`);
    }
  });

test("STREAMED: a PyPI wheel (zip) is read by offset from the temp file, with the same guards", async () => {
  const whl = makeZip([
    { name: "zipmcp/__init__.py", data: "x = 1\n" },
    { name: "../zip-escape.txt", data: "nope" },
    { name: "zipmcp/link", data: "/etc/passwd", symlink: true },
    { name: "zipmcp-0.1.0.pth", data: "import os; os.getcwd()\n" }
  ]);
  const { fetchImpl } = registryStub({ zipmcp: { ecosystem: "pypi", kind: "wheel", artifact: whl } }, { chunkBytes: 32 });
  const r = await analyzePackage({ ecosystem: "pypi", name: "zipmcp", version: null }, { fetchImpl, engine });
  assert.equal(r.artifact.kind, "wheel");
  assert.equal(r.summary.archive.format, "zip");
  assert.equal(r.summary.archive.rejected, 1, "the ../ entry is refused");
  assert.equal(r.summary.archive.skipped, 1, "the symlink entry is skipped");
  assert.ok(ids(r).includes("pkg-pth-autoexec"), JSON.stringify(ids(r)));
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

// ---- known-bad indicators: Knostic advisory on the malicious PyPI MCP server iflow-mcp_cmpxchg16-reddit-mcp ----

test("known-bad PyPI name: every PEP 503 spelling of iflow-mcp_cmpxchg16-reddit-mcp is malicious", async () => {
  const { classifyPackage, inspectInstall } = await import("../data/popular-packages.js");
  const { nameFindings } = await import("../cli/mcp-package/heuristics.mjs");
  for (const n of ["iflow-mcp_cmpxchg16-reddit-mcp", "iflow-mcp-cmpxchg16-reddit-mcp", "IFLOW_MCP.cmpxchg16_reddit-mcp", "iflow-mcp__cmpxchg16--reddit-mcp"]) {
    assert.equal(classifyPackage(n, "pypi"), "malicious", n);
  }
  const f = nameFindings({ ecosystem: "pypi", name: "iflow_mcp_cmpxchg16_reddit_mcp" });
  assert.deepEqual(f.map((x) => [x.threatId, x.tier]), [["pkg-known-malicious", "block"]]);
  assert.equal((inspectInstall("pip install iflow-mcp-cmpxchg16-reddit-mcp==0.1.0") || {}).verdict, "malicious");
  assert.equal(classifyPackage("iflow-mcp-cmpxchg16-reddit-mcp-pro", "pypi"), "ok", "only the documented name, not a prefix");
});

test("known-bad artifact list holds exactly the five full sha256 values the advisory published", async () => {
  const { KNOWN_BAD_SHA256, isKnownBadSha256 } = await import("../data/known-bad-artifacts.js");
  const vals = [...KNOWN_BAD_SHA256.keys()].sort();
  assert.deepEqual(vals, [
    "0012b35b2dc2213c720c92476aa2abca4c6a08052ed4d20692a6c0b970ba847e",
    "163293b10474b29f53e568c6c070de287b057ad1acf89fa755d224262af39478",
    "5e77fa2a506e1ce6f0726faa502a5bdd0fccd598bd835c7cd6b69963de550198",
    "7568ca4fd110561020373fbfeb0fa6a36aaf241a59cd5e621a275199e64aa520",
    "970659f5132d021aaf2ff12dfcf1b098a3a956c5c4dbc608da229b40d94a8453"
  ]);
  assert.equal(isKnownBadSha256("5E77FA2A506E1CE6F0726FAA502A5BDD0FCCD598BD835C7CD6B69963DE550198"), true, "case-insensitive");
  assert.equal(isKnownBadSha256("5e77fa2a"), false, "a prefix is never a match");
  assert.equal(isKnownBadSha256(""), false);
});

test("a downloaded artifact whose sha256 is on the known-bad list → pkg-known-malicious (block), wheel and npm tarball", async () => {
  const { sha256hex } = await import("./fixtures/mcp-package/build.mjs");
  const whl = makeZip([{ name: "benignmcp/__init__.py", data: "x = 1\n" }]);
  const tgz = makeTgz(NPM_FIXTURES["clean-mcp-server"]);
  const { fetchImpl } = registryStub({ benignmcp: { ecosystem: "pypi", kind: "wheel", artifact: whl }, "clean-mcp-server": { ecosystem: "npm", artifact: tgz } });
  const clean = await analyzePackage({ ecosystem: "pypi", name: "benignmcp", version: null }, { fetchImpl, engine });
  assert.equal(clean.verdict, "CLEAN", JSON.stringify(clean.findings));
  for (const [ref, art] of [[{ ecosystem: "pypi", name: "benignmcp", version: null }, whl], [{ ecosystem: "npm", name: "clean-mcp-server", version: null }, tgz]]) {
    const r = await analyzePackage(ref, { fetchImpl, engine, knownBadSha256: new Set([sha256hex(art)]) });
    const hit = r.findings.filter((f) => f.threatId === "pkg-known-malicious");
    assert.deepEqual(hit.map((f) => [f.relativePath, f.tier]), [[null, "block"]], `${ref.name}: ${JSON.stringify(r.findings)}`);
    assert.equal(r.verdict, "DO-NOT-INSTALL");
  }
});

test("an extracted file whose sha256 is on the known-bad list → pkg-known-malicious (block) on that path, never capped", async () => {
  const { packageHeuristics } = await import("../cli/mcp-package/heuristics.mjs");
  const { sha256hex } = await import("./fixtures/mcp-package/build.mjs");
  const { mkdirSync } = await import("node:fs");
  const { dirname } = await import("node:path");
  const SERVER = "def main():\n    return 1\n";
  const root = mkdtempSync(join(tmpdir(), "moorai-kbf-"));
  const files = { "reddit_mcp/server.py": SERVER, "tests/fixture.py": SERVER, "reddit_mcp/other.py": "y = 2\n", "assets/logo.png": "\x89PNG not really" };
  for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(root, f)), { recursive: true }); writeFileSync(join(root, f), t); }
  const abs = Object.keys(files).map((f) => join(root, f));
  const hit = (set) => packageHeuristics(root, abs, { knownBadSha256: set }).filter((f) => f.threatId === "pkg-known-malicious").map((f) => [f.relativePath, f.tier]).sort();
  assert.deepEqual(hit(new Set([sha256hex(Buffer.from(SERVER))])), [["reddit_mcp/server.py", "block"], ["tests/fixture.py", "block"]]);
  assert.deepEqual(hit(new Set([sha256hex(Buffer.from("\x89PNG not really"))])), [["assets/logo.png", "block"]], "any file, not only code");
  assert.deepEqual(hit(new Set(["0".repeat(64)])), []);
  assert.deepEqual(packageHeuristics(root, abs).filter((f) => f.threatId === "pkg-known-malicious"), [], "the bundled list does not match benign files");
});
