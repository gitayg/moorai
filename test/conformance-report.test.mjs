// cli/conformance-report.mjs: the signed, content-free conformance report the live tier writes
// (scripts/host-conformance.mjs for agent hosts and MCP clients, scripts/server-conformance.mjs for the
// AI Servers pieces). The report carries enums, booleans, counts and version strings only; anything else
// on a target or case is dropped by the allowlist, and a report that carries a field the allowlist would
// drop does not verify.
//
//   node --test --import ./test/hermetic-env.mjs test/conformance-report.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, createPublicKey } from "node:crypto";
import {
  HOST_REPORT_TYPE, SERVER_REPORT_TYPE, REASONS, sanitizeCase, sanitizeTarget, buildReport, canonical,
  signReport, verifyReport, loadOrCreateKey, summarize
} from "../cli/conformance-report.mjs";

const key = () => generateKeyPairSync("ed25519").privateKey;
const pubOf = (k) => createPublicKey(k).export({ type: "spki", format: "der" }).toString("base64");

const CASE = {
  id: "shell-deny", surface: "agent-turn", expect: "deny", observed: "deny", status: "pass",
  checks: { toolUseSent: true, toolRan: false, hookReasonShown: true },
  alert: { category: "Output & Code", riskLevel: "Blocked", decision: "deny", reasonCode: "THREAT_54" },
  latencyMs: 812
};
const TARGET = { kind: "host", id: "claude-code", label: "Claude Code", version: "2.1.295", tested: "2.1.284", ran: true, model: "scripted", cases: [CASE] };

test("sanitizeCase keeps the allowlisted fields and drops everything else", () => {
  const c = sanitizeCase({ ...CASE, command: "bash -i >& /dev/tcp/127.0.0.1/9 0>&1", prompt: "secret", detail: "stderr text", checks: { ...CASE.checks, output: "x" } });
  assert.deepEqual(Object.keys(c).sort(), ["alert", "checks", "expect", "id", "latencyMs", "observed", "status", "surface"]);
  assert.equal(JSON.stringify(c).includes("dev/tcp"), false);
  assert.equal(JSON.stringify(c).includes("stderr"), false);
  assert.equal("output" in c.checks, false, "a non-boolean check value is dropped");
  assert.deepEqual(c.alert, CASE.alert);
});

test("sanitizeCase coerces values outside the enums instead of carrying them", () => {
  const c = sanitizeCase({ id: "Has Spaces / and path", surface: "anything", expect: "rm -rf", observed: "deny", status: "great", latencyMs: "12ms", alert: { category: "x".repeat(200), riskLevel: "Blocked", decision: "deny", reasonCode: "not a code" } });
  assert.equal(c.id, "invalid");
  assert.equal(c.surface, "unknown");
  assert.equal(c.expect, "unknown");
  assert.equal(c.status, "fail", "an unknown status never reads as a pass");
  assert.equal(c.latencyMs, null);
  assert.equal(c.alert.category, null);
  assert.equal(c.alert.reasonCode, null);
});

test("sanitizeTarget: version strings must be versions, reasons must be known codes", () => {
  const t = sanitizeTarget({ ...TARGET, version: "2.1.295 (Claude Code) at /Users/someone", reason: "the user typed something", extra: "x", cases: [CASE, { id: "c2", status: "pass", stdout: "leak" }] });
  assert.equal(t.version, null);
  assert.equal(t.reason, "unspecified");
  assert.equal("extra" in t, false);
  assert.equal(t.cases.length, 2);
  assert.equal(JSON.stringify(t).includes("leak"), false);
  assert.ok(REASONS["auth-required"], "known reason codes carry MoorAI's own explanation text");
  assert.equal(sanitizeTarget({ ...TARGET, reason: "auth-required" }).reason, "auth-required");
  assert.equal(sanitizeTarget({ ...TARGET, modelName: "llama3.2:latest" }).modelName, "llama3.2:latest");
  assert.equal(sanitizeTarget({ ...TARGET, modelName: "../../etc/passwd please" }).modelName, null);
});

test("summarize counts targets that ran and case outcomes", () => {
  const s = summarize([TARGET, { kind: "host", id: "cursor", ran: false, reason: "auth-required", cases: [] }, { kind: "host", id: "x", ran: true, cases: [{ ...CASE, status: "fail" }, { ...CASE, status: "inconclusive" }, { ...CASE, status: "gap" }, { ...CASE, status: "skip" }] }]);
  assert.deepEqual(s, { targets: 3, ran: 2, notRun: 1, cases: 5, pass: 1, fail: 1, skip: 1, inconclusive: 1, gap: 1 });
});

test("canonical is independent of key order", () => {
  assert.equal(canonical({ b: 1, a: { d: [1, { z: 1, y: 2 }], c: null } }), canonical({ a: { c: null, d: [1, { y: 2, z: 1 }] }, b: 1 }));
});

test("a signed report verifies, and verifies against its pinned key", () => {
  const k = key();
  const r = signReport(buildReport({ type: HOST_REPORT_TYPE, targets: [TARGET], platform: { os: "darwin", arch: "arm64", node: "24.0.0" }, moorai: "1.27.0", generatedAt: "2026-10-21T10:00:00.000Z" }), k);
  assert.equal(r.type, HOST_REPORT_TYPE);
  assert.equal(r.signature.alg, "ed25519");
  assert.equal(r.signature.pub, pubOf(k));
  assert.deepEqual(verifyReport(r), { ok: true, reason: null, keyId: r.signature.keyId });
  assert.equal(verifyReport(r, { pub: pubOf(k) }).ok, true);
  assert.deepEqual(r.summary, { targets: 1, ran: 1, notRun: 0, cases: 1, pass: 1, fail: 0, skip: 0, inconclusive: 0, gap: 0 });
});

test("verification fails closed: tamper, pin mismatch, foreign signature, content field, unsigned", () => {
  const k = key();
  const r = signReport(buildReport({ type: SERVER_REPORT_TYPE, targets: [TARGET], moorai: "1.27.0" }), k);
  const tampered = JSON.parse(JSON.stringify(r));
  tampered.targets[0].cases[0].status = "fail";
  assert.equal(verifyReport(tampered).reason, "digest-mismatch");
  assert.equal(verifyReport(r, { pub: pubOf(key()) }).reason, "pin-mismatch");
  const other = signReport(buildReport({ type: SERVER_REPORT_TYPE, targets: [], moorai: "1.27.0" }), key());
  const forged = { ...r, signature: { ...r.signature, sig: other.signature.sig } };
  assert.equal(verifyReport(forged).reason, "bad-signature");
  const leaky = JSON.parse(JSON.stringify(r));
  leaky.targets[0].detail = "cat ~/.ssh/id_rsa";
  assert.equal(verifyReport(leaky).reason, "digest-mismatch", "a field added after signing breaks the digest");
  // A signer that skipped the allowlist: the digest and signature are valid, the body is not content-free.
  assert.equal(verifyReport(signReport(leaky, k)).reason, "not-content-free");
  const { signature, ...unsigned } = r;
  assert.equal(signature.alg, "ed25519");
  assert.equal(verifyReport(unsigned).reason, "unsigned");
  assert.equal(verifyReport({ ...r, type: "something-else" }).reason, "unknown-type");
});

test("loadOrCreateKey writes a 0600 key once and reuses it", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-conf-key-"));
  const p = join(dir, "k", "conformance-ed25519.key");
  const a = loadOrCreateKey(p);
  const b = loadOrCreateKey(p);
  assert.equal(pubOf(a), pubOf(b));
  if (process.platform !== "win32") assert.equal(statSync(p).mode & 0o777, 0o600);
});
