// Security properties of MCP package analysis: safe extraction and content-free output.
//
//   node --test test/mcp-package-security.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, existsSync, readdirSync, lstatSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, isAbsolute } from "node:path";

import { analyzePackage } from "../cli/mcp-package.mjs";
import { extractTar, extractZip, extractArchive, safeRelPath, LIMITS } from "../cli/mcp-package/archive.mjs";
import { buildEngine } from "../cli/hook-core.mjs";
import { makeTar, makeTgz, makeZip, NPM_FIXTURES, PYPI_FIXTURES, registryStub, CANARY, CANARY_HOST } from "./fixtures/mcp-package/build.mjs";

const engine = buildEngine({});

function allFiles(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    out.push(p);
    if (e.isDirectory()) out.push(...allFiles(p));
  }
  return out;
}

test("safeRelPath refuses absolute, drive, NUL and .. paths", () => {
  for (const bad of ["../x", "/etc/x", "C:\\x", "a/../../x", "a\0b", "..", ""]) assert.equal(safeRelPath(bad), null, bad);
  assert.equal(safeRelPath("package/./lib/x.js"), "package/lib/x.js");
});

test("TAR path traversal and symlinks are never written outside (or at all)", () => {
  assert.ok(!existsSync("/tmp/moorai-abs-escape.txt"), "precondition");
  const outer = mkdtempSync(join(tmpdir(), "moorai-trav-"));
  const dest = join(outer, "inner");
  mkdirSync(dest);
  const stats = extractTar(makeTar(NPM_FIXTURES["traversal-mcp-server"]), dest);
  assert.equal(stats.rejected, 3, JSON.stringify(stats));
  assert.equal(stats.skipped, 1, "the symlink entry is skipped");
  assert.deepEqual(readdirSync(outer), ["inner"], "nothing escaped into the parent");
  assert.ok(!existsSync("/tmp/moorai-abs-escape.txt"));
  const files = allFiles(dest);
  assert.ok(files.every((f) => !lstatSync(f).isSymbolicLink()), "no symlink created");
  assert.ok(files.every((f) => !f.includes("evil")), JSON.stringify(files));
  assert.ok(existsSync(join(dest, "package", "index.js")), "the legitimate entry is still extracted");
});

test("TAR entry cannot write through a pre-existing entry (wx), and entry cap stops a bomb", () => {
  const dest = mkdtempSync(join(tmpdir(), "moorai-dup-"));
  const stats = extractTar(makeTar([{ name: "a.txt", data: "one" }, { name: "a.txt", data: "two" }]), dest);
  assert.equal(readFileSync(join(dest, "a.txt"), "utf8"), "one");
  assert.equal(stats.rejected, 1);

  const many = Array.from({ length: 20 }, (_, i) => ({ name: `f${i}.txt`, data: "x" }));
  const capped = extractTar(makeTar(many), mkdtempSync(join(tmpdir(), "moorai-cap-")), { ...LIMITS, maxEntries: 5 });
  assert.equal(capped.truncated, true);
  assert.equal(capped.written, 5);
});

test("ZIP traversal and symlink entries are refused", () => {
  const outer = mkdtempSync(join(tmpdir(), "moorai-ztrav-"));
  const dest = join(outer, "inner");
  mkdirSync(dest);
  const stats = extractZip(makeZip([
    { name: "ok/x.py", data: "x = 1\n" },
    { name: "../zip-evil.txt", data: CANARY },
    { name: "ok/link", data: "/etc/passwd", symlink: true }
  ]), dest);
  assert.equal(stats.rejected, 1);
  assert.equal(stats.skipped, 1);
  assert.deepEqual(readdirSync(outer), ["inner"]);
  assert.ok(existsSync(join(dest, "ok", "x.py")));
  assert.ok(!existsSync(join(dest, "ok", "link")));
});

test("a gzip bomb beyond the total-size cap throws instead of filling memory/disk", () => {
  const big = makeTgz([{ name: "big.bin", data: Buffer.alloc(4 * 1024 * 1024) }]);
  assert.throws(() => extractArchive(big, mkdtempSync(join(tmpdir(), "moorai-bomb-")), { ...LIMITS, maxTotalBytes: 1024 * 1024, maxEntries: 10 }), RangeError);
  // Within the decompression cap but over the write cap: stops writing and reports truncation.
  const s = extractArchive(big, mkdtempSync(join(tmpdir(), "moorai-bomb2-")), { ...LIMITS, maxTotalBytes: 1024 * 1024 });
  assert.equal(s.truncated, true);
  assert.equal(s.written, 0);
});

test("a traversal package fails closed (REVIEW+) with an unsafe-archive-entries note, temp dir removed", async () => {
  const workDir = mkdtempSync(join(tmpdir(), "moorai-work-"));
  const { fetchImpl } = registryStub({ "traversal-mcp-server": { ecosystem: "npm", artifact: makeTgz(NPM_FIXTURES["traversal-mcp-server"]) } });
  const r = await analyzePackage({ ecosystem: "npm", name: "traversal-mcp-server", version: null }, { fetchImpl, engine, workDir });
  assert.ok(["REVIEW", "DO-NOT-INSTALL"].includes(r.verdict), r.verdict);
  assert.deepEqual(r.notes, [{ id: "unsafe-archive-entries", count: 3 }]);
  assert.deepEqual(readdirSync(workDir), [], "temp extraction dir removed in finally");
});

test("CANARY: nothing planted in a malicious package appears in the JSON output", async () => {
  const stub = registryStub({
    "harvest-mcp-server": { ecosystem: "npm", artifact: makeTgz(NPM_FIXTURES["harvest-mcp-server"]) },
    "postinstall-mcp-server": { ecosystem: "npm", artifact: makeTgz(NPM_FIXTURES["postinstall-mcp-server"]) },
    "blob-mcp-server": { ecosystem: "npm", artifact: makeTgz(NPM_FIXTURES["blob-mcp-server"]) },
    "mcp-server-evilsetup": { ecosystem: "pypi", artifact: makeTgz(PYPI_FIXTURES["mcp-server-evilsetup"]) }
  });
  const results = [];
  for (const [ecosystem, name] of [["npm", "harvest-mcp-server"], ["npm", "postinstall-mcp-server"], ["npm", "blob-mcp-server"], ["pypi", "mcp-server-evilsetup"]]) {
    results.push(await analyzePackage({ ecosystem, name, version: null }, { fetchImpl: stub.fetchImpl, engine }));
  }
  const json = JSON.stringify(results);
  for (const leak of [CANARY, CANARY_HOST, "203.0.113.9", "process.env", "curl", "subprocess", tmpdir()]) {
    assert.ok(!json.includes(leak), `content-free violated — leaked: ${leak}`);
  }
  const findings = results.flatMap((r) => r.findings);
  assert.ok(findings.length >= 4);
  for (const f of findings) {
    assert.deepEqual(Object.keys(f).sort(), ["category", "contentHash", "ecosystem", "intentLabels", "package", "relativePath", "surfaceKind", "threatId", "tier"]);
    if (f.relativePath) assert.ok(!isAbsolute(f.relativePath), f.relativePath);
  }
});
