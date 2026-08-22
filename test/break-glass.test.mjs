// Break-glass authenticity tests (#33). The break-glass marker forces FAIL-OPEN on a fail-closed
// device, so "the file exists and parses to a future date" is not an acceptable trust test: the agent
// being governed can write that file with an already-permitted Bash call and switch the enforcement
// layer off. These tests pin the replacement contract — an ed25519 marker signed by an OPERATOR key
// that the device holds only outside the agent's own write scope.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { verifyBreakGlass, breakGlassCanonical, parseTrustedKeys, BREAK_GLASS_VERSION } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");

const TENANT = "acme";
const DEVICE = "laptop-17";
const FUTURE = "2099-01-01T00:00:00.000Z";
const PAST = "2000-01-01T00:00:00.000Z";

const operator = generateKeyPairSync("ed25519");
const rogue = generateKeyPairSync("ed25519");
const TRUSTED = [operator.publicKey];
const PUB_B64 = operator.publicKey.export({ type: "spki", format: "der" }).toString("base64");

// Mint a marker exactly the way the documented operator procedure does.
function mint({ tenant = TENANT, device = DEVICE, expires = FUTURE, nonce = "n0", key = operator.privateKey, sigOverride } = {}) {
  const body = { v: BREAK_GLASS_VERSION, tenant, device, expires, nonce };
  const sig = sigOverride ?? edSign(null, Buffer.from(breakGlassCanonical(body)), key).toString("base64");
  return JSON.stringify({ ...body, sig });
}
const ctx = (over = {}) => ({ keys: TRUSTED, tenant: TENANT, device: DEVICE, ...over });

// ---- the vulnerability itself ----

test("FORGED: the legacy unsigned marker an agent can echo does NOT activate break-glass", () => {
  // This is the exact attack: `echo '{"expires":"2030-01-01"}' > ~/.curaiq/break-glass`
  const r = verifyBreakGlass('{"expires":"2030-01-01"}', ctx());
  assert.equal(r.active, false);
  assert.equal(r.status, "unsigned");
});

test("FORGED: a bare future ISO string does NOT activate break-glass", () => {
  const r = verifyBreakGlass("2030-01-01T00:00:00Z", ctx());
  assert.equal(r.active, false);
  assert.equal(r.status, "malformed");
});

test("FORGED: bare epoch-ms does NOT activate break-glass", () => {
  const r = verifyBreakGlass(String(Date.now() + 86400000), ctx());
  assert.equal(r.active, false);
  assert.equal(r.status, "malformed");
});

test("FORGED: a marker signed by a key that is not the operator's is untrusted", () => {
  const r = verifyBreakGlass(mint({ key: rogue.privateKey }), ctx());
  assert.equal(r.active, false);
  assert.equal(r.status, "untrusted");
});

test("FORGED: extending the expiry of a genuinely signed marker breaks the signature", () => {
  const m = JSON.parse(mint({ expires: "2026-01-01T00:00:00.000Z" }));
  m.expires = FUTURE; // attacker edits the field, keeps the operator's signature
  const r = verifyBreakGlass(JSON.stringify(m), ctx());
  assert.equal(r.active, false);
  assert.equal(r.status, "untrusted");
});

test("FORGED: a marker minted for another device does not activate on this one", () => {
  const r = verifyBreakGlass(mint({ device: "someone-elses-mac" }), ctx());
  assert.equal(r.active, false);
  assert.equal(r.status, "mismatch");
});

test("FORGED: a marker minted for another tenant does not activate", () => {
  const r = verifyBreakGlass(mint({ tenant: "other-corp" }), ctx());
  assert.equal(r.active, false);
  assert.equal(r.status, "mismatch");
});

// ---- fail-closed on ambiguity ----

test("ABSENT: no marker file → absent, not active", () => {
  assert.deepEqual(verifyBreakGlass("", ctx()), { active: false, status: "absent" });
  assert.deepEqual(verifyBreakGlass(null, ctx()), { active: false, status: "absent" });
  assert.deepEqual(verifyBreakGlass("   \n", ctx()), { active: false, status: "absent" });
});

test("MALFORMED: unparseable content is not active", () => {
  assert.equal(verifyBreakGlass("{not json", ctx()).status, "malformed");
  assert.equal(verifyBreakGlass("[]", ctx()).status, "malformed");
  assert.equal(verifyBreakGlass(JSON.stringify({ v: BREAK_GLASS_VERSION, tenant: TENANT, device: DEVICE, nonce: "n", sig: "AAAA" }), ctx()).status, "malformed"); // no expiry
});

test("MALFORMED: an unparseable expiry on an otherwise valid signature is not active", () => {
  const r = verifyBreakGlass(mint({ expires: "not-a-date" }), ctx());
  assert.equal(r.active, false);
  assert.equal(r.status, "malformed");
});

test("EXPIRED: a validly signed but expired marker does NOT activate", () => {
  const r = verifyBreakGlass(mint({ expires: PAST }), ctx());
  assert.equal(r.active, false);
  assert.equal(r.status, "expired");
});

test("NO ANCHOR: a perfectly valid marker on a device with no operator key does NOT activate", () => {
  // Fail-closed on ambiguity: without a trust anchor there is nothing to verify against.
  const r = verifyBreakGlass(mint(), ctx({ keys: [] }));
  assert.equal(r.active, false);
  assert.equal(r.status, "no-anchor");
});

test("WRONG VERSION: a marker from an unknown format version is not active", () => {
  const body = { v: 99, tenant: TENANT, device: DEVICE, expires: FUTURE, nonce: "n" };
  const sig = edSign(null, Buffer.from(breakGlassCanonical(body)), operator.privateKey).toString("base64");
  assert.equal(verifyBreakGlass(JSON.stringify({ ...body, sig }), ctx()).active, false);
});

// ---- the legitimate operator flow still works ----

// The canonical string is a WIRE FORMAT: operator tooling mints signatures over it out-of-band, so a
// silent change here would invalidate every marker already issued (and, worse, could be changed to
// something an attacker can also produce). Pinned literally, not derived from the implementation.
const CANON = "moorai-break-glass|v2|acme|laptop-17|2099-01-01T00:00:00.000Z|n0";

test("the signed canonical bytes are a pinned wire format", () => {
  assert.equal(BREAK_GLASS_VERSION, 2);
  assert.equal(breakGlassCanonical({ v: 2, tenant: TENANT, device: DEVICE, expires: FUTURE, nonce: "n0" }), CANON);
});

test("VALID: an operator-signed, unexpired, device-bound marker DOES activate break-glass", () => {
  // Signed over the literal pinned bytes — independent of breakGlassCanonical, so this test proves
  // real interop with operator tooling rather than the implementation agreeing with itself.
  const sig = edSign(null, Buffer.from(CANON), operator.privateKey).toString("base64");
  const marker = JSON.stringify({ v: 2, tenant: TENANT, device: DEVICE, expires: FUTURE, nonce: "n0", sig });
  const r = verifyBreakGlass(marker, ctx());
  assert.equal(r.active, true);
  assert.equal(r.status, "active");
});

test("VALID: an operator may sign a fleet-wide marker with the '*' scope", () => {
  const r = verifyBreakGlass(mint({ device: "*", tenant: "*" }), ctx());
  assert.equal(r.active, true);
});

test("VALID: expiry may also be given as epoch-ms inside the signed marker", () => {
  const r = verifyBreakGlass(mint({ expires: String(Date.now() + 3600000) }), ctx());
  assert.equal(r.active, true);
});

test("parseTrustedKeys accepts PEM, base64 SPKI DER, comments and blank lines", () => {
  const pem = operator.publicKey.export({ type: "spki", format: "pem" });
  assert.equal(parseTrustedKeys(pem).length, 1);
  assert.equal(parseTrustedKeys(PUB_B64).length, 1);
  assert.equal(parseTrustedKeys(`# operator key\n\n${PUB_B64}\n`).length, 1);
  assert.equal(parseTrustedKeys(`${pem}\n${PUB_B64}\n`).length, 2);
  assert.equal(parseTrustedKeys("garbage").length, 0);
  assert.equal(parseTrustedKeys("").length, 0);
});

// ---- end-to-end through the real hook process ----

// Runs cli/moorai-hook.mjs with HOME pointed at a throwaway dir, no reachable policy server, and the
// durable posture forced to fail-closed — the exact situation break-glass exists for. The probe is an
// MCP tool-call, because the offline fail-closed default sets mcpFloor:"ask": the hook's OWN stdout
// therefore states the trust decision. "ask" = enforcement applied, "" (exit 0) = fail-open granted.
// That is the real decision, not a log line that could race process.exit.
async function runHook({ marker, anchorPub, tenant = TENANT }) {
  const home = mkdtempSync(join(tmpdir(), "moorai-bg-"));
  const alerts = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.method === "POST") { try { alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(200, { "Content-Type": "application/json" }); return res.end("{}"); }
      res.writeHead(500); res.end("offline"); // /api/policy → no policy, forcing the offline path
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}`;
  try {
    mkdirSync(join(home, ".curaiq"), { recursive: true });
    writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: url, tenant }));
    if (marker != null) writeFileSync(join(home, ".curaiq", "break-glass"), marker);
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "fail-closed" };
    if (anchorPub) env.MOORAI_BREAKGLASS_PUBKEY = anchorPub; else delete env.MOORAI_BREAKGLASS_PUBKEY;
    const child = spawn(process.execPath, [HOOK], { env, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify({ tool_name: "mcp__probe__ping", tool_input: {} }));
    let stdout = "";
    child.stdout.on("data", (c) => (stdout += c));
    const code = await new Promise((r) => child.on("close", r));
    await new Promise((r) => setTimeout(r, 150)); // let in-flight alert POSTs land
    return { alerts, stdout, code, categories: alerts.map((a) => a.category), hashes: alerts.map((a) => a.contentHash) };
  } finally {
    await new Promise((r) => server.close(r));
    rmSync(home, { recursive: true, force: true });
  }
}

const enforced = (r) => /"permissionDecision":"ask"/.test(r.stdout);

test("E2E: the exact `echo > ~/.curaiq/break-glass` attack does NOT flip the device fail-open", async () => {
  const r = await runHook({ marker: '{"expires":"2030-01-01"}' });
  assert.ok(enforced(r), `device must stay fail-closed; hook stdout was ${JSON.stringify(r.stdout)}`);
  assert.ok(!r.hashes.includes("breakglass:active"));
});

test("E2E: a forged marker raises a Critical tamper alert", async () => {
  const r = await runHook({ marker: '{"expires":"2030-01-01"}' });
  const tamper = r.alerts.find((a) => String(a.contentHash || "").startsWith("breakglass:"));
  assert.ok(tamper, `expected a break-glass tamper alert, got: ${JSON.stringify(r.categories)}`);
  assert.match(tamper.contentHash, /^breakglass:unsigned:/);
  assert.equal(tamper.riskLevel, "Critical");
  assert.equal(tamper.stage, "policy");
  // content-free: only the status and a one-way hash leave the device
  assert.ok(!JSON.stringify(tamper).includes("2030-01-01"));
});

test("E2E: an operator-signed marker DOES activate break-glass, with no tamper alert", async () => {
  const { hostname } = await import("node:os");
  const r = await runHook({ marker: mint({ device: hostname() }), anchorPub: PUB_B64 });
  assert.equal(r.stdout, "", "break-glass means fail-open — the hook must emit no deny/ask");
  assert.equal(r.code, 0);
  assert.ok(r.hashes.includes("breakglass:active"), `expected break-glass to activate, got: ${JSON.stringify(r.hashes)}`);
  assert.ok(!r.hashes.some((h) => /^breakglass:(unsigned|untrusted|malformed|mismatch|expired|no-anchor)/.test(h)));
});

test("E2E: a valid marker with NO trust anchor on the device stays fail-closed", async () => {
  const { hostname } = await import("node:os");
  const r = await runHook({ marker: mint({ device: hostname() }) }); // anchorPub omitted
  assert.ok(enforced(r), `no anchor must not grant fail-open; stdout was ${JSON.stringify(r.stdout)}`);
  const tamper = r.alerts.find((a) => String(a.contentHash || "").startsWith("breakglass:"));
  assert.match(tamper.contentHash, /^breakglass:no-anchor:/);
});

test("E2E: an expired operator-signed marker leaves the device fail-closed and reports it", async () => {
  const { hostname } = await import("node:os");
  const r = await runHook({ marker: mint({ device: hostname(), expires: PAST }), anchorPub: PUB_B64 });
  assert.ok(enforced(r), `expired marker must not grant fail-open; stdout was ${JSON.stringify(r.stdout)}`);
  const tamper = r.alerts.find((a) => String(a.contentHash || "").startsWith("breakglass:"));
  assert.ok(tamper, `expected an expired-marker alert, got: ${JSON.stringify(r.hashes)}`);
  assert.match(tamper.contentHash, /^breakglass:expired:/);
  assert.equal(tamper.riskLevel, "High");
});

test("E2E: with no marker at all the device is fail-closed and posts no break-glass alert", async () => {
  const r = await runHook({ marker: null });
  assert.ok(enforced(r), `stdout was ${JSON.stringify(r.stdout)}`);
  assert.ok(!r.hashes.some((h) => String(h).startsWith("breakglass:")));
});
