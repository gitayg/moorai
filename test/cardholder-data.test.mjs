// #90 cardholder data (v1.43.0): the card detectors moved off #1, a policy written for #1 still governs cards,
// the issuer-range check, and no card number — nor a hash the install token can enumerate back to one — in any
// alert, at any capture tier. The last tests run the real hook against a fake console that signs its policy.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import http from "node:http";
import { DETECTORS } from "../data/detectors.js";
import { DATA_TIERS, TIER_OF } from "../data/data-tiers.js";
import { cardNumberValid, cardNetwork } from "../data/card-iin.js";
import { threatPolicyEntry } from "../data/cardholder.js";
import { applyCaptureTier, stripAboveTier } from "../data/capture-tiers.js";
import { threatActionFor, buildEngine, decideText, policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { inboundActionFor } from "../cli/inbound.mjs";
import { spanHash, processHash } from "../cli/span-hash.mjs";
import { placeholder } from "../cli/mask.mjs";
import { maskResult, maskAlert } from "../cli/result-mask.mjs";
import { deriveKey, hashWithKey } from "../cli/content-hash.mjs";
import { OFFLINE_DEFAULT_POLICY } from "../data/offline-default.js";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const threats = JSON.parse(readFileSync(join(ROOT, "data", "threats.json"), "utf8")).threats;
const det = (id) => DETECTORS.find((d) => d.detectorId === id);

// ---- the rule and its detectors ------------------------------------------------------------------------------

test("#90 is in the rule base, tagged like #1 and #44, and the card detectors report it", () => {
  const t = threats.find((x) => x.id === 90);
  assert.ok(t, "#90 missing");
  assert.equal(t.category, "Information & Privacy");
  assert.equal(t.riskLevel, "Critical");
  assert.equal(t.owasp, "LLM02");
  assert.equal(t.atlas, "AML.T0057");
  assert.equal(t.stride, "Information Disclosure");
  assert.equal(det("dlp-payment-card").threatId, 90);
  assert.equal(det("pci-cvv").threatId, 90);
  // IBAN and clipboard-to-sink stay #1.
  assert.equal(det("dlp-iban").threatId, 1);
  assert.equal(det("clipboard-to-sink").threatId, 1);
  assert.ok(DATA_TIERS.regulated.includes(90));
  assert.equal(TIER_OF[90], "regulated");
});

// ---- detection: 13-19 digits, Luhn, issuer range and length --------------------------------------------------

const VALID = {
  visa: ["4111111111111111", "4222222222222", "4111111111111111110"], mastercard: ["5555555555554444", "2223000048400011"],
  amex: ["378282246310005"], discover: ["6011111111111117"], jcb: ["3530111333300000"], diners: ["30569309025904", "36227206271667"],
  unionpay: ["6200000000000005"], maestro: ["6759649826438453"]
};
test("a Luhn-valid number in each network's issuer range and length is a card", () => {
  for (const [net, nums] of Object.entries(VALID)) for (const n of nums) {
    assert.equal(cardNetwork(n), net, n);
    assert.equal(cardNumberValid(n), true, n);
  }
});
test("a Luhn-valid number outside every issuer range, or at a length its network does not issue, is not a card", () => {
  for (const n of ["1234567812345670", "7111111111111111", "9007199254741055", "0000000000000000", "3782822463100050", "41111111111111115", "55555555555544440"]) {
    assert.equal(cardNumberValid(n), false, n);
  }
  assert.equal(cardNumberValid("4111111111111112"), false, "Luhn fails");
});
test("the engine reports a 19-digit card and a grouped card as #90, and not a Luhn-valid order number", () => {
  const engine = buildEngine({});
  const ids = (t) => decideText(engine, {}, t, "prompt").findings.map((f) => f.threatId);
  assert.ok(ids("card 4111 1111 1111 1111 110 exp 12/26").includes(90));
  assert.ok(ids("pay with 4111111111111111110 today").includes(90), "a contiguous 19-digit card");
  assert.ok(ids("amex 3782-822463-10005").includes(90));
  assert.ok(ids("cvv: 123").includes(90));
  assert.ok(!ids("order 1234 5678 1234 5670 shipped").includes(90));
  assert.ok(ids("IBAN DE89370400440532013000").includes(1));
});

// ---- policy: #1's entry governs #90 until #90 has its own ------------------------------------------------------

test("a policy that sets threatPolicy[1] and not [90] gives #90 #1's action; one that sets [90] decides #90 alone", () => {
  for (const act of ["block", "justify", "notify", "alert", "disabled", "kill"]) {
    assert.equal(threatActionFor({ threatPolicy: { 1: act } }, 90), act, act);
    assert.equal(threatActionFor({ threatPolicy: { "1": act } }, 90), act, `string key ${act}`);
  }
  assert.equal(threatActionFor({ threatPolicy: { 1: "block", 90: "notify" } }, 90), "notify");
  assert.equal(threatActionFor({ threatPolicy: { 90: "block" } }, 1), "notify", "#1 never inherits from #90");
  assert.equal(threatActionFor({ threatPolicy: { 1: "block" }, tierPolicy: { regulated: "notify" } }, 90), "block", "#1's entry outranks the tier, as it did for cards");
  assert.equal(threatActionFor({ tierPolicy: { regulated: "justify" } }, 90), "justify");
  assert.equal(threatPolicyEntry({ threatPolicy: { 1: "block" } }, 15), undefined);
});
test("#90's built-in default is #1's", () => {
  assert.equal(threatActionFor({}, 90), threatActionFor({}, 1));
  assert.equal(threatActionFor(null, 90), threatActionFor(null, 1));
  assert.equal(OFFLINE_DEFAULT_POLICY.threatPolicy[90], OFFLINE_DEFAULT_POLICY.threatPolicy[1]);
});
test("inbound content: #1's entry makes #90 an explicit data-class setting, as it was for cards", () => {
  assert.equal(inboundActionFor({ threatPolicy: { 1: "block" } }, 90), "block");
  assert.equal(inboundActionFor({}, 90), "notify");
});

// ---- evidence: no matched or argument text, no tenant-keyed hash -------------------------------------------

const PAN = "4111 1111 1111 1111";
test("a #90 finding never carries matched or argument text, at any tier; #1 still does at full-capture", () => {
  const extras = { matchText: PAN, argText: `echo ${PAN}`, filePath: "notes.txt", toolName: "Bash", cmdShape: "echo [4 args]" };
  for (const tier of ["content-free", "metadata-plus", "full-capture"]) {
    const a = applyCaptureTier({ threatId: 90, category: "Information & Privacy" }, extras, tier);
    assert.ok(!("matchText" in a) && !("argText" in a), `${tier}: ${JSON.stringify(a)}`);
    const s = stripAboveTier({ threatId: 90, ...extras }, tier);
    assert.ok(!("matchText" in s) && !("argText" in s), `strip ${tier}: ${JSON.stringify(s)}`);
  }
  const full = applyCaptureTier({ threatId: 90 }, extras, "full-capture");
  assert.equal(full.filePath, "notes.txt");
  assert.equal(full.cmdShape, "echo [4 args]");
  assert.equal(applyCaptureTier({ threatId: 1 }, extras, "full-capture").matchText, PAN);
  assert.equal(stripAboveTier({ threatId: "90", ...extras }, "full-capture").matchText, undefined);
});
test("a #90 span hash is process-keyed, never the tenant-keyed hash; other threats keep the tenant key", () => {
  const key = deriveKey("tok-cardholder");
  const tenant = (s) => hashWithKey(key, s);
  const h = spanHash(90, PAN, tenant);
  assert.match(h, /^proc:[0-9a-f]{16}$/);
  for (const f of [PAN, PAN.replace(/\D/g, "")]) assert.ok(!h.includes(tenant(f).slice(3)), f);
  assert.equal(spanHash(90, PAN, tenant), h, "stable within the process");
  assert.equal(spanHash(15, "a@example.com", tenant), tenant("a@example.com"));
});

// A policy that masks cards (here through #1's entry) on a tool result: the placeholder's letters come from the
// process-keyed hash, and the mask record names #90 with no span text and no span hash.
test("mask: a #90 placeholder is built from the process-keyed hash; the result-mask record carries no span or span hash", () => {
  const key = deriveKey("tok-cardholder");
  const tenant = (s) => hashWithKey(key, s);
  const letters = (h) => h.replace(/^(h2|proc):/, "").slice(0, 8).split("").map((c) => "abcdefghijklmnop"[parseInt(c, 16)]).join("");
  assert.equal(placeholder(90, PAN, tenant), `[MOORAI:regulated:${letters(processHash(PAN))}]`);
  assert.notEqual(placeholder(90, PAN, tenant), `[MOORAI:regulated:${letters(tenant(PAN))}]`);
  assert.equal(placeholder(1, "DE89370400440532013000", tenant), `[MOORAI:regulated:${letters(tenant("DE89370400440532013000"))}]`);
  const engine = buildEngine();
  const value = { content: [{ type: "text", text: `order paid with card ${PAN} yesterday` }] };
  const r = maskResult(engine, { threatPolicy: { 1: "mask" } }, value, { stage: "file", hash: tenant });
  assert.deepEqual(r.ids, [90]);
  const out = JSON.stringify(r.value);
  assert.ok(!out.includes(PAN) && !out.includes(PAN.replace(/\D/g, "")), out);
  const tag = (out.match(/\[MOORAI:regulated:([a-p]{8})\]/) || [])[1];
  const spans = [PAN, `${PAN} `, ` ${PAN}`, ` ${PAN} `];
  assert.ok(spans.some((x) => letters(processHash(x)) === tag), out);
  assert.ok(!spans.some((x) => letters(tenant(x)) === tag), out);
  const a = JSON.stringify(maskAlert({ tool: "gateway:t", stage: "result", ids: r.ids, count: r.count }));
  assert.ok(!a.includes(PAN.replace(/\D/g, "").slice(0, 6)) && !a.includes(tenant(PAN)) && !a.includes(processHash(PAN)) && !a.includes("matchText"), a);
});

test("desktop app: the audit record's alert for a #90 finding carries a per-page proc: hash, not the number", async () => {
  const { Audit } = await import("../src/audit.js");
  const store = { m: new Map(), getItem(k) { return this.m.get(k) ?? null; }, setItem(k, v) { this.m.set(k, v); }, removeItem(k) { this.m.delete(k); } };
  const e = new Audit(store).record({ action: "notify", stage: "prompt", tool: "desktop", finding: { threat: { id: 90, category: "Information & Privacy", riskLevel: "Critical" }, mode: "warn" }, content: PAN });
  assert.match(e.alert.contentHash, /^proc:[0-9a-f]{16}$/);
  assert.ok(!JSON.stringify(e).includes(PAN.replace(/\D/g, "").slice(0, 8)));
});

// ---- end to end through the hook -----------------------------------------------------------------------------

const TENANT = "acme";
const TOKEN = "tok-cardholder-e2e";
const key = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) });
function signed(policy) {
  const iat = new Date().toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), key.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
async function consoleServer(policy) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      if (req.method === "POST") {
        try {
          if (req.url === "/api/alerts") alerts.push(JSON.parse(body));
          if (req.url === "/api/alerts/batch") for (const a of JSON.parse(body).alerts || []) alerts.push(a);
        } catch { /* ignore */ }
        res.writeHead(201); return res.end("{}");
      }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(pubkeyBody); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(signed(policy)); }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}
function sandbox(c) {
  const home = mkdtempSync(join(tmpdir(), "moorai-card-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  mkdirSync(join(home, "proj"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: c.url, tenant: TENANT, installToken: TOKEN }));
  return home;
}
function runHook(home, command) {
  const proj = join(home, "proj");
  return new Promise((res) => {
    const c = spawn(process.execPath, [HOOK], { cwd: proj, env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, CLAUDE_PROJECT_DIR: proj } });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", (status) => res({ status, out, err }));
    c.stdin.end(JSON.stringify({ session_id: "sess-card", cwd: proj, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } }));
  });
}
const decision = (r) => { try { return JSON.parse(r.out).hookSpecificOutput?.permissionDecision || "allow"; } catch { return r.out.trim() ? "?" : "allow"; } };
const reasonOf = (r) => { try { return JSON.parse(r.out).hookSpecificOutput?.permissionDecisionReason || ""; } catch { return ""; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 10000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(50); } return fn(); }
// Pin the device to the console's key on first contact, then drop the 60 s policy cache.
async function pin(home) { const r = await runHook(home, "echo pin"); assert.equal(r.status, 0, r.err); rmSync(join(home, ".moorai", "hook-policy.json"), { force: true }); }

const CMD = `printf 'card ${PAN} exp 12/26\\n' >> notes.txt`;
// Every form of the number, and the install-token-keyed hash of each: none may appear in anything posted.
function assertNoPan(alerts) {
  const tenant = (s) => hashWithKey(deriveKey(TOKEN), s);
  const digits = PAN.replace(/\D/g, "");
  const forbidden = [PAN, digits, "1111 1111", ...[PAN, digits, `card ${PAN} exp 12/26`, `${PAN} `].map((f) => tenant(f))];
  for (const a of alerts) { const s = JSON.stringify(a); for (const x of forbidden) assert.ok(!s.includes(x), `alert carries ${x}: ${s}`); }
}

test("hook e2e: a signed policy that blocks only #1 denies a card command as #90, at full-capture with no number or tenant-keyed card hash in any alert", async () => {
  const c = await consoleServer({ captureTier: "full-capture", threatPolicy: { 1: "block" } });
  const home = sandbox(c);
  try {
    await pin(home);
    const r = await runHook(home, CMD);
    assert.equal(r.status, 0, r.err);
    assert.equal(decision(r), "deny", r.out);
    assert.match(reasonOf(r), /#90 Information & Privacy/);
    assert.ok(await until(() => c.alerts.some((a) => a.threatId === 90)), JSON.stringify(c.alerts.map((a) => a.threatId)));
    const card = c.alerts.filter((a) => a.threatId === 90 && a.stage === "file");
    assert.ok(card.length >= 1);
    for (const a of card) {
      assert.match(a.contentHash, /^proc:[0-9a-f]{16}$/, JSON.stringify(a));
      assert.ok(!("matchText" in a) && !("argText" in a), JSON.stringify(a));
      assert.equal(a.toolName, "Bash", "full-capture's other fields still arrive");
    }
    assertNoPan(c.alerts);
  } finally { await c.close(); rmTree(home); }
});

test("hook e2e: the same full-capture policy still sends #1's matched text (an IBAN), so only #90 is barred", async () => {
  const c = await consoleServer({ captureTier: "full-capture", threatPolicy: { 1: "block" } });
  const home = sandbox(c);
  try {
    await pin(home);
    const r = await runHook(home, "printf 'IBAN DE89370400440532013000\\n' >> notes.txt");
    assert.equal(decision(r), "deny", r.out);
    assert.ok(await until(() => c.alerts.some((a) => a.threatId === 1)));
    assert.ok(c.alerts.some((a) => a.threatId === 1 && /DE89370400440532013000/.test(a.matchText || "")), JSON.stringify(c.alerts.filter((a) => a.threatId === 1)));
  } finally { await c.close(); rmTree(home); }
});

test("hook e2e: threatPolicy[90] set apart from [1] decides the card: notify allows it while [1] blocks", async () => {
  const c = await consoleServer({ captureTier: "content-free", threatPolicy: { 1: "block", 90: "notify" } });
  const home = sandbox(c);
  try {
    await pin(home);
    const r = await runHook(home, CMD);
    assert.equal(decision(r), "allow", r.out);
    assert.ok(await until(() => c.alerts.some((a) => a.threatId === 90)));
    assertNoPan(c.alerts);
  } finally { await c.close(); rmTree(home); }
});

test("hook e2e: approval routing match { threatId: [90] } holds a blocked card command and requests approval", async () => {
  const rule = { id: "card-review", label: "Card data needs a reviewer", match: { threatId: [90] }, holds: ["block"], group: "payments", timeoutSec: 60 };
  const c = await consoleServer({ captureTier: "full-capture", threatPolicy: { 1: "block" }, approvalRouting: { v: 1, rules: [rule] } });
  const home = sandbox(c);
  try {
    await pin(home);
    const r = await runHook(home, CMD);
    assert.equal(decision(r), "deny", r.out);
    assert.match(reasonOf(r), /Held for approval: Card data needs a reviewer \(request apr_[0-9A-HJKMNP-TV-Z]{26}\)/);
    assert.ok(await until(() => c.alerts.some((a) => a.reasonCode === "APPROVAL_REQUESTED")), JSON.stringify(c.alerts.map((a) => a.reasonCode)));
    const req = c.alerts.find((a) => a.reasonCode === "APPROVAL_REQUESTED");
    assert.equal(req.threatId, 90);
    assert.equal(req.approval.ruleId, "card-review");
    assertNoPan(c.alerts);
  } finally { await c.close(); rmTree(home); }
});
