// The device report's MCP package details (`pkg` on each mcp entry): what the console shows as
// single-maintainer, unpinned, package version and package scan. Derived on the device from the launch
// config (parsed locally, never sent) plus the maintainer count and scan verdict the reputation path
// caches. src-tauri/src/mcp_pkg.rs builds the same object for the desktop host's report and is held to
// the same fixture (test/fixtures/mcp-pkg-cases.json) by `cargo test`.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-pkg-report.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { derivePkg, clampPkg, pkgKey, recordPkgMeta, readPkgMeta, withPkgMeta, scanOfReputation, PKG_CACHE_FILE, PKG_META_TTL_MS } from "../cli/mcp-package/pkg-report.mjs";
import { assessServer, assessServerSync } from "../cli/mcp-reputation.mjs";
import { REASON_WEIGHTS } from "../data/mcp-reputation.js";
import { HEURISTICS } from "../cli/mcp-package/heuristics.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const CASES = JSON.parse(readFileSync(new URL("./fixtures/mcp-pkg-cases.json", import.meta.url), "utf8")).cases;
const VOCAB = JSON.parse(readFileSync(new URL("../data/mcp-pkg-findings.json", import.meta.url), "utf8"));
const byId = Object.fromEntries(CASES.map((c) => [c.id, c]));
const four = (p) => ({ eco: p.eco, name: p.name, version: p.version, pinned: p.pinned });
const NOW = Date.parse("2026-10-20T00:00:00Z");

function sandbox() {
  const root = mkdtempSync(join(tmpdir(), "moorai-pkg-"));
  const home = join(root, "home"), stateDir = join(root, "state");
  mkdirSync(home, { recursive: true }); mkdirSync(stateDir, { recursive: true });
  return { root, home, stateDir, done: () => rmTree(root) };
}

test("shared fixture: every case derives the expected {eco, name, version, pinned}; the rest starts null", () => {
  assert.ok(CASES.length >= 40);
  for (const c of CASES) {
    const p = derivePkg(c.decl);
    assert.deepEqual(four(p), c.pkg, c.id);
    assert.deepEqual(Object.keys(p).sort(), ["eco", "maintainers", "maintainersOrg", "name", "pinned", "scan", "version"], c.id);
    assert.equal(p.maintainers, null, c.id); assert.equal(p.maintainersOrg, null, c.id); assert.equal(p.scan, null, c.id);
  }
});

test("pinned: exact versions and docker digests only; ^, ~, latest, partial and none are unpinned", () => {
  const pin = (id) => derivePkg(byId[id].decl).pinned;
  assert.equal(pin("npm-exact"), true);
  assert.equal(pin("npm-prerelease"), true);
  assert.equal(pin("npm-caret"), false);
  assert.equal(pin("npm-tilde"), false);
  assert.equal(pin("npm-latest"), false);
  assert.equal(pin("npm-partial"), false);
  assert.equal(pin("npm-none"), false);
  assert.equal(pin("pypi-exact"), true);
  assert.equal(pin("pypi-at-latest"), false);
  assert.equal(pin("pypi-wildcard"), false);
  assert.equal(pin("docker-digest"), true);
  assert.equal(pin("docker-tag"), false, "a docker tag is mutable");
  assert.equal(pin("docker-short-digest"), false, "only a full sha256 digest pins");
  assert.equal(pin("local-node"), null, "a local script has no registry version: unknown");
  assert.equal(pin("other-remote"), null);
});

test("local and file packages: eco local, name null, version null", () => {
  for (const id of ["local-node", "local-python", "local-binary", "local-npx-dir", "local-npx-file", "local-npx-tgz", "local-uv-run"]) {
    assert.deepEqual(four(derivePkg(byId[id].decl)), { eco: "local", name: null, version: null, pinned: null }, id);
  }
});

test("content-free: no command, argument, path, URL, env name or value reaches pkg", () => {
  const decl = {
    command: "/usr/local/bin/npx",
    args: ["-y", "--registry", "https://registry.internal.corp/npm", "@acme/weather-mcp@2.1.0", "--token", "SECRET-ARG-9Z", "/Users/alice/clients/merger", "https://intranet.acme.corp/x?key=K1"],
    env: { ACME_API_KEY: "sk-live-ENVVALUE-3", HOME_DIR: "/Users/alice" }
  };
  const p = derivePkg(decl);
  assert.deepEqual(four(p), { eco: "npm", name: "@acme/weather-mcp", version: "2.1.0", pinned: true });
  const s = JSON.stringify(p);
  for (const leak of ["npx", "/usr/local", "--registry", "internal.corp", "--token", "SECRET-ARG-9Z", "/Users", "intranet", "key=K1", "ACME_API_KEY", "sk-live", "HOME_DIR", "-y"]) {
    assert.equal(s.includes(leak), false, `pkg leaked ${leak}: ${s}`);
  }
  for (const id of ["other-remote", "other-url-tarball", "docker-private-registry", "local-node", "local-uv-run", "other-unknown-binary"]) {
    const t = JSON.stringify(derivePkg(byId[id].decl));
    for (const leak of ["mcp.example.com", "token=abc", "internal.corp", "/Users", "/x/y", "server.py", "my-server-binary", "--port", "5000"]) {
      assert.equal(t.includes(leak), false, `${id} leaked ${leak}: ${t}`);
    }
  }
});

test("clamping: every field is validated and bounded before it is sent", () => {
  const long = "a".repeat(215);
  const good = { eco: "npm", name: "srv", version: "1.0.0", pinned: true, maintainers: 2, maintainersOrg: false, scan: { verdict: "clean", findings: [] } };
  assert.deepEqual(clampPkg(good), good);
  assert.equal(clampPkg({ ...good, eco: "rubygems" }).eco, "other");
  assert.equal(clampPkg({ ...good, eco: "rubygems" }).name, null, "no name outside a registry ecosystem");
  assert.equal(clampPkg({ ...good, name: long }).name, null, "a name over 214 chars is dropped");
  assert.equal(clampPkg({ ...good, name: "a".repeat(214) }).name, "a".repeat(214));
  assert.equal(clampPkg({ ...good, name: "/Users/alice/x" }).name, null, "a path is not a package name");
  assert.equal(clampPkg({ ...good, name: "https://evil.example/x" }).name, null);
  assert.equal(clampPkg({ ...good, version: "1".repeat(65) }).version, null, "a version over 64 chars is dropped");
  assert.equal(clampPkg({ ...good, version: "1".repeat(64) }).version, "1".repeat(64));
  assert.equal(clampPkg({ ...good, version: "/tmp/x" }).version, null);
  assert.equal(clampPkg({ ...good, version: "git+https://x" }).version, null);
  assert.equal(clampPkg({ ...good, pinned: "yes" }).pinned, null);
  assert.equal(clampPkg({ ...good, maintainers: 50000 }).maintainers, 1000, "clamped to 1000");
  for (const bad of [-1, 0, 1.5, "3", NaN, Infinity, null, {}]) assert.equal(clampPkg({ ...good, maintainers: bad }).maintainers, null, String(bad));
  assert.equal(clampPkg({ ...good, maintainersOrg: 1 }).maintainersOrg, null);
  const codes = VOCAB.codes;
  const many = clampPkg({ ...good, scan: { verdict: "warn", findings: [...codes, ...codes, "threat-60", "rm -rf /", "/Users/alice", "x".repeat(40)] } });
  assert.equal(many.scan.findings.length, 32, "findings are cut to 32");
  for (const f of many.scan.findings) assert.ok(codes.includes(f) || /^threat-\d{1,4}$/.test(f), f);
  assert.deepEqual(clampPkg({ ...good, scan: { verdict: "warn", findings: ["threat-60", "not-a-code", "threat-60", "single-maintainer"] } }).scan, { verdict: "warn", findings: ["single-maintainer", "threat-60"] });
  assert.equal(clampPkg({ ...good, scan: { verdict: "evil", findings: [] } }).scan, null);
  assert.equal(clampPkg({ ...good, scan: "clean" }).scan, null);
  const loc = clampPkg({ eco: "local", name: "secret-dir", version: "1.0.0", pinned: true, maintainers: 3, maintainersOrg: true, scan: { verdict: "clean", findings: [] } });
  assert.deepEqual(loc, { eco: "local", name: null, version: null, pinned: null, maintainers: null, maintainersOrg: null, scan: null }, "local carries nothing");
  assert.equal(clampPkg(null), null);
});

test("findings vocabulary: data/mcp-pkg-findings.json is exactly the reputation and heuristic codes", () => {
  const want = [...new Set([...Object.keys(REASON_WEIGHTS), ...Object.keys(HEURISTICS)])].sort();
  assert.deepEqual(VOCAB.codes, want, "regenerate data/mcp-pkg-findings.json when a code is added");
});

test("cache: per name@version with a TTL; tampered entries are clamped on read", () => {
  const s = sandbox();
  try {
    const p = derivePkg(byId["npm-exact"].decl);
    assert.equal(pkgKey(p), "npm:@scope/srv@1.4.2");
    assert.equal(pkgKey(derivePkg(byId["npm-none"].decl)), "npm:@modelcontextprotocol/server-filesystem@");
    assert.equal(pkgKey(derivePkg(byId["local-node"].decl)), null);
    assert.equal(pkgKey(derivePkg(byId["docker-tag"].decl)), null, "maintainers and scan are npm / PyPI only");
    recordPkgMeta(s.stateDir, p, { maintainers: { count: 1, org: false } }, NOW);
    recordPkgMeta(s.stateDir, p, { scan: { verdict: "warn", findings: ["single-maintainer"] } }, NOW + 1000);
    const cache = readPkgMeta(s.stateDir);
    assert.deepEqual(withPkgMeta(p, cache, NOW + 2000), { ...p, maintainers: 1, maintainersOrg: false, scan: { verdict: "warn", findings: ["single-maintainer"] } });
    assert.deepEqual(withPkgMeta(p, cache, NOW + PKG_META_TTL_MS + 5000), p, "expired: back to unknown");
    const other = derivePkg({ command: "npx", args: ["-y", "@scope/srv@1.4.3"] });
    assert.equal(withPkgMeta(other, cache, NOW).maintainers, null, "another version is another key");
    const raw = JSON.parse(readFileSync(join(s.stateDir, PKG_CACHE_FILE), "utf8"));
    raw.entries["npm:@scope/srv@1.4.2"].m.count = "7; rm -rf";
    raw.entries["npm:@scope/srv@1.4.2"].s.findings = ["/Users/alice/secret", "threat-60"];
    writeFileSync(join(s.stateDir, PKG_CACHE_FILE), JSON.stringify(raw));
    const t = withPkgMeta(p, readPkgMeta(s.stateDir), NOW + 2000);
    assert.equal(t.maintainers, null);
    assert.deepEqual(t.scan, { verdict: "warn", findings: ["threat-60"] });
    writeFileSync(join(s.stateDir, PKG_CACHE_FILE), "not json");
    assert.deepEqual(withPkgMeta(p, readPkgMeta(s.stateDir), NOW), p, "an unreadable cache is no data");
  } finally { s.done(); }
});

test("scan verdict from the reputation band, only when the package code was read", () => {
  assert.equal(scanOfReputation({ band: "good", reasons: [], evidence: [] }), null, "nothing scanned: unknown");
  assert.deepEqual(scanOfReputation({ band: "good", reasons: ["unpinned-version"], evidence: ["installed-copy-scanned"] }), { verdict: "clean", findings: ["unpinned-version"] });
  assert.deepEqual(scanOfReputation({ band: "fair", reasons: ["pkg-install-script"], evidence: ["registry-analysed"] }), { verdict: "warn", findings: ["pkg-install-script"] });
  assert.deepEqual(scanOfReputation({ band: "poor", reasons: ["repo-mismatch"], evidence: ["registry-analysed"] }), { verdict: "warn", findings: ["repo-mismatch"] });
  assert.deepEqual(scanOfReputation({ band: "bad", reasons: ["pkg-remote-code"], evidence: ["installed-copy-scanned"] }), { verdict: "block", findings: ["pkg-remote-code"] });
});

const MAINT_PKG = "weather-relay-mcp";
const packument = (maintainers) => ({
  name: MAINT_PKG, "dist-tags": { latest: "1.0.0" },
  time: { created: "2024-01-01T00:00:00.000Z", "1.0.0": "2024-01-01T00:00:00.000Z" },
  maintainers,
  versions: { "1.0.0": { name: MAINT_PKG, version: "1.0.0", maintainers, dist: { tarball: `https://registry.npmjs.org/${MAINT_PKG}/-/${MAINT_PKG}-1.0.0.tgz`, integrity: "sha512-AAAA" } } }
});

test("maintainer count is kept: the reputation registry lookup caches the count, never the names", async () => {
  const s = sandbox();
  try {
    const url = `https://registry.npmjs.org/${MAINT_PKG}`;
    const fetchImpl = async (u) => (String(u) === url ? new Response(JSON.stringify(packument([{ name: "alice-q7-maint", email: "alice-q7@example.com" }])), { status: 200 }) : new Response("", { status: 599 }));
    const decl = { command: "npx", args: ["-y", `${MAINT_PKG}@1.0.0`] };
    await assessServer(decl, { stateDir: s.stateDir, home: s.home, fetchImpl, policy: { lookup: "registry" }, now: NOW });
    const text = readFileSync(join(s.stateDir, PKG_CACHE_FILE), "utf8");
    for (const leak of ["alice-q7-maint", "alice-q7@example.com", "example.com"]) assert.equal(text.includes(leak), false, `pkg cache leaked ${leak}`);
    const p = withPkgMeta(derivePkg(decl), readPkgMeta(s.stateDir), NOW + 1000);
    assert.equal(p.maintainers, 1);
    assert.equal(p.maintainersOrg, false);
    const rep = readFileSync(join(s.stateDir, "mcp-reputation.json"), "utf8");
    assert.equal(/"count"\s*:/.test(rep), false, "the count lives in the pkg cache, not in the reputation cache");
  } finally { s.done(); }
});

test("hook hot path: the offline assessment records the scan with no network call", () => {
  const s = sandbox();
  const orig = globalThis.fetch;
  let fetched = 0;
  globalThis.fetch = async () => { fetched++; return new Response("", { status: 599 }); };
  try {
    const name = "tidy-notes-mcp";
    const dir = join(s.home, ".npm", "_npx", "a1b2c3d4", "node_modules", name);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name, version: "2.0.0" }));
    writeFileSync(join(dir, "index.js"), "console.log('hello')\n");
    const decl = { command: "npx", args: ["-y", `${name}@2.0.0`] };
    const rep = assessServerSync(decl, { stateDir: s.stateDir, home: s.home, now: NOW });
    assert.ok(rep.evidence.includes("installed-copy-scanned"), JSON.stringify(rep));
    assert.equal(fetched, 0, "no request on the hook path");
    assert.ok(existsSync(join(s.stateDir, PKG_CACHE_FILE)));
    const p = withPkgMeta(derivePkg(decl), readPkgMeta(s.stateDir), NOW + 1000);
    assert.deepEqual(p.scan, { verdict: "clean", findings: [] });
    assert.equal(p.maintainers, null, "the hook path never looks maintainers up");
  } finally { globalThis.fetch = orig; s.done(); }
});

test("maintainer TTL: within it the proxy path makes no request; after it only the count is refreshed", async () => {
  const s = sandbox();
  try {
    const url = `https://registry.npmjs.org/${MAINT_PKG}`;
    const calls = [];
    let maint = [{ name: "alice-q7-maint" }];
    const fetchImpl = async (u) => { calls.push(String(u)); return String(u) === url ? new Response(JSON.stringify(packument(maint)), { status: 200 }) : new Response("", { status: 599 }); };
    const decl = { command: "npx", args: ["-y", `${MAINT_PKG}@1.0.0`] };
    const opts = { stateDir: s.stateDir, home: s.home, fetchImpl, policy: { lookup: "registry" } };
    await assessServer(decl, { ...opts, now: NOW });
    const first = calls.length;
    assert.ok(first >= 1);
    await assessServer(decl, { ...opts, now: NOW + 3600 * 1000 });
    assert.equal(calls.length, first, "inside the TTL: served from cache, no request");
    maint = [{ name: "alice-q7-maint" }, { name: "bob-z3-maint" }];
    const later = NOW + PKG_META_TTL_MS + 1000;
    await assessServer(decl, { ...opts, now: later });
    assert.deepEqual(calls.slice(first), [url], "after the TTL: one registry metadata request, nothing else");
    assert.equal(withPkgMeta(derivePkg(decl), readPkgMeta(s.stateDir), later + 1).maintainers, 2);
  } finally { s.done(); }
});

test("shared cache fixture: the same cache file and clock give the same maintainers and scan (Node side of the Rust parity)", () => {
  const fx = JSON.parse(readFileSync(new URL("./fixtures/mcp-pkg-cache.json", import.meta.url), "utf8"));
  for (const c of fx.cases) {
    const p = withPkgMeta(derivePkg(c.decl), fx.cache, fx.now);
    assert.deepEqual({ maintainers: p.maintainers, maintainersOrg: p.maintainersOrg, scan: p.scan }, { maintainers: c.maintainers, maintainersOrg: c.maintainersOrg, scan: c.scan }, c.id);
  }
});

// The console's five acceptance rules for a device report entry (its tests pin them).
function consoleRules(entry) {
  const errs = [];
  const p = entry.pkg;
  if (!p) return ["no pkg"];
  const shaped = (v) => typeof v === "string" && (/\s/.test(v) || v.includes("\\") || v.includes("://") || /^[/.~]/.test(v));
  if (shaped(p.name)) errs.push(`name shaped like a path or URL: ${p.name}`);
  if (shaped(p.version)) errs.push(`version shaped like a path or URL: ${p.version}`);
  if (typeof p.name === "string" && p.name.length > 214) errs.push("name too long");
  if (typeof p.version === "string" && p.version.length > 64) errs.push("version too long");
  if (p.eco === "docker" && typeof p.name === "string" && p.name.includes("@sha256:") && !(p.version === null && p.pinned === true && /@sha256:[0-9a-f]{64}$/.test(p.name))) errs.push("digest reference: whole ref in name, version null, pinned true");
  if (p.maintainers === 0) errs.push("maintainers 0 (send null for unknown)");
  if ((p.eco === "local" || p.eco === "other") && p.name !== null) errs.push("local/other with a name");
  for (const f of (p.scan && p.scan.findings) || []) if (!VOCAB.codes.includes(f) && !/^threat-\d+$/.test(f)) errs.push(`finding outside the vocabulary: ${f}`);
  return errs;
}

test("console contract: sample report entries satisfy all five rules (body.mcp[], digest, maintainers, name/version shape, findings)", () => {
  // 1. The desktop report's body.mcp[] is device_mcp's servers list, which carries pkg (src-tauri/src/lib.rs).
  const api = readFileSync(new URL("../src/api.js", import.meta.url), "utf8");
  assert.match(api, /mcp = \(await invoke\("device_mcp"\)\)\.servers/);
  assert.match(api, /const full = \{[^}]*\bmcp\b/);
  const lib = readFileSync(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  assert.match(lib, /"pkg": mcp_pkg::pkg_for\(cfg, &pkg\.cache, pkg\.now_ms\)/);
  const fx = JSON.parse(readFileSync(new URL("./fixtures/mcp-pkg-cache.json", import.meta.url), "utf8"));
  const entries = [
    ...CASES.map((c) => ({ name: c.id, scope: "claude", transport: "stdio", caps: {}, pkg: derivePkg(c.decl) })),
    ...fx.cases.map((c) => ({ name: c.id, scope: "claude", transport: "stdio", caps: {}, pkg: withPkgMeta(derivePkg(c.decl), fx.cache, fx.now) }))
  ];
  for (const e of entries) assert.deepEqual(consoleRules(e), [], `${e.name}: ${JSON.stringify(e.pkg)}`);
  // 2. digest: the whole reference in name.
  const dg = derivePkg(byId["docker-tag-and-digest"].decl);
  assert.equal(dg.name, "ghcr.io/x/y:2.0@sha256:" + "0123456789abcdef".repeat(4));
  assert.equal(dg.version, null); assert.equal(dg.pinned, true);
  // 3. a registry that lists no maintainers is unknown, never 0.
  assert.equal(clampPkg({ eco: "npm", name: "x", maintainers: 0 }).maintainers, null);
  // 4. shapes the console rejects never leave: ~ ranges and spaced specs lose their version.
  assert.equal(derivePkg(byId["npm-tilde"].decl).version, null);
  assert.equal(derivePkg(byId["pypi-compatible"].decl).version, null);
  for (const v of ["1 .0", "a\\b", "x://y", "/x", ".1", "~1"]) assert.equal(clampPkg({ eco: "npm", name: "x", version: v }).version, null, v);
  // the validator itself rejects each rule's violation
  assert.ok(consoleRules({ pkg: { eco: "npm", name: "x", version: "~1", maintainers: 0, scan: { verdict: "warn", findings: ["nope"] } } }).length >= 3);
});
