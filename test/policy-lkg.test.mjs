// Last-known-good verified policy (Item 1) + pin-absence tamper evidence (Item 2).
//
// ITEM 1 — THE GAP. policy-signature.test.mjs and policy-pin.test.mjs made the device REFUSE a poisoned
// policy cache. But "refused" meant "no policy", and for a FAIL-OPEN org "no policy" means exit(0). So
// `echo '{}' > ~/.curaiq/hook-policy.json` still delivered the attacker's bypass on the majority of
// installs; the device merely alerted about it on the way out. Detection is not enforcement.
//
// The contract pinned here: the device keeps the last policy that ACTUALLY PASSED signature
// verification (delivered fresh over the network), RE-VERIFIES it on load, and enforces with it when
// the live and cached copies are both refused. Precedence: verified fresh → verified cache → verified
// last-known-good → offline default / posture.
//
// ITEM 2 — erasing BOTH pin copies returns an unanchored device to first contact. That is NOT fixed
// here and is not claimed to be: the hook runs as the user. What is added is tamper-EVIDENCE — a
// distinct, content-free alert for "pin gone on a device that has demonstrably held one" — plus a
// window reduction (the 60s cache short-circuit is skipped in that state so every invocation attempts
// the fresh fetch that is the only path back to a pin).
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync, existsSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import {
  policyCanonical, policyDigest, POLICY_SIG_VERSION, POLICY_PIN_VERSION,
  selectLastKnownGood, assessPinAbsence, publicKeyId
} from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "acme";

// A root-owned machine latch on the DEV box would pin every case to fail-closed, so the fail-open E2E
// cases are skipped there rather than asserting something false. Same guard as posture.test.mjs.
const SYSTEM_LATCH = process.platform === "win32"
  ? join(process.env.ProgramData || "C:\\ProgramData", "MoorAI", "offline-posture")
  : "/etc/moorai/offline-posture";
const HOST_LATCHED = existsSync(SYSTEM_LATCH);

const consoleKey = generateKeyPairSync("ed25519");
const rogueKey = generateKeyPairSync("ed25519");
const id = (kp) => publicKeyId(kp.publicKey);
const pubkeyBody = (kp) => JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: id(kp) });

function sign(policy, { tenant = TENANT, iat = "2026-08-21T00:00:00.000Z", key = consoleKey.privateKey } = {}) {
  const digest = policyDigest(policy);
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant, iat, digest })), key).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant, iat, sig } });
}

// STRICT denies the probe server (its own mcpAllow excludes it) → "deny" proves THIS policy applied.
// RELAXED allows it → exit(0) with a policy:lkg:applied alert proves the RELAXED one applied.
const STRICT = (over = {}) => sign({ captureTier: "content-free", mcpAllow: ["something-else"], ...over });
const RELAXED = (over = {}) => sign({ captureTier: "content-free", mcpAllow: ["probe"], ...over });

// ---- unit: the pure selector ----

test("LKG SELECT: the first copy that VERIFIES wins, in the order given", () => {
  const verify = (raw) => (raw === "good" ? { policy: { ok: raw } } : { bad: "untrusted" });
  const r = selectLastKnownGood([
    { source: "system", raw: "bad" },
    { source: "primary", raw: "good" },
    { source: "latch", raw: "good" }
  ], verify);
  assert.equal(r.copy, "primary");
  assert.deepEqual(r.policy, { ok: "good" });
});

test("LKG SELECT: the root-owned system copy is preferred when it verifies", () => {
  const verify = (raw) => ({ policy: { from: raw } });
  assert.equal(selectLastKnownGood([
    { source: "system", raw: "s" }, { source: "primary", raw: "p" }
  ], verify).copy, "system");
});

test("LKG SELECT: blank and unverifiable copies are skipped; nothing verifying is null", () => {
  const never = () => ({ bad: "unsigned" });
  assert.equal(selectLastKnownGood([{ source: "primary", raw: "x" }], never), null);
  assert.equal(selectLastKnownGood([{ source: "primary", raw: "" }, { source: "latch", raw: "   " }], () => ({ policy: {} })), null);
  assert.equal(selectLastKnownGood([], never), null);
  assert.equal(selectLastKnownGood(null, never), null);
});

test("LKG SELECT: a verify() that THROWS on one copy does not abort the scan", () => {
  const verify = (raw) => { if (raw === "boom") throw new Error("bad json"); return { policy: { raw } }; };
  assert.equal(selectLastKnownGood([{ source: "primary", raw: "boom" }, { source: "latch", raw: "ok" }], verify).copy, "latch");
});

// ---- unit: pin-absence classification ----

test("ABSENCE: unpinned + enrolled + evidence of prior PINNING is suspicious", () => {
  const r = assessPinAbsence({ enrolled: true, trustMode: "unpinned", pinningEvidence: ["pin-breadcrumb", "policy-lkg"], operationEvidence: ["action-audit"] });
  assert.equal(r.suspicious, true);
  assert.deepEqual(r.evidence, ["pin-breadcrumb", "policy-lkg"]);
  assert.deepEqual(r.context, ["action-audit"]);
});

test("ABSENCE: prior OPERATION alone is NOT suspicious — the never-signing-fleet false positive", () => {
  // A console that does not sign never forms a pin (the documented no-brick property) while its devices
  // write posture copies and audit lines from their second run onward. Triggering on those would raise a
  // Critical alert on every hook invocation for every device in a perfectly healthy fleet.
  const r = assessPinAbsence({ enrolled: true, trustMode: "unpinned", pinningEvidence: [], operationEvidence: ["posture-sidecar", "posture-latch", "action-audit", "agent-events"] });
  assert.equal(r.suspicious, false);
  assert.deepEqual(r.evidence, []);
});

test("ABSENCE: a genuinely fresh install has no evidence at all and is not suspicious", () => {
  assert.equal(assessPinAbsence({ enrolled: true, trustMode: "unpinned" }).suspicious, false);
});

test("ABSENCE: an unenrolled device cannot be judged, so it never fires", () => {
  assert.equal(assessPinAbsence({ enrolled: false, trustMode: "unpinned", pinningEvidence: ["pin-breadcrumb"] }).suspicious, false);
});

test("ABSENCE: only the UNPINNED trust mode is in this state; the others have their own signals", () => {
  for (const mode of ["anchored", "pinned", "corrupt", "rebind"]) {
    assert.equal(assessPinAbsence({ enrolled: true, trustMode: mode, pinningEvidence: ["pin-breadcrumb"] }).suspicious, false, mode);
  }
});

// ---- end-to-end through the real hook process ----
//
// Same harness contract as policy-pin.test.mjs; HOME persists across runs. The probe is an MCP call:
//   ""    (exit 0) → the call was allowed (no policy on a fail-open device, or a policy that permits it)
//   "ask"          → OFFLINE_DEFAULT_POLICY applied (mcpFloor)
//   "deny"         → a policy whose mcpAllow excludes the probe was applied and ENFORCED

function newHome() {
  const home = mkdtempSync(join(tmpdir(), "moorai-lkg-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true });
  return home;
}
const CACHE = (home) => join(home, ".curaiq", "hook-policy.json");
const PIN_A = (home) => join(home, ".curaiq", "policy-pin.json");
const PIN_B = (home) => join(home, ".moorai", "policy-pin.json");
const LKG_A = (home) => join(home, ".curaiq", "policy-lkg.json");
const LKG_B = (home) => join(home, ".moorai", "policy-lkg.json");
const BREADCRUMB = (home) => join(home, ".config", "moorai", "pinned");

function ageCache(home) { const t = (Date.now() - 2 * 3600 * 1000) / 1000; try { utimesSync(CACHE(home), t, t); } catch { /* no cache */ } }

// `serve`/`pubkey` null → that endpoint is unreachable. `offlineMode` drives MOORAI_OFFLINE_MODE, which
// is what makes a device a fail-OPEN org (the case Item 1 exists for) or a fail-CLOSED one.
async function run(home, { serve = null, pubkey = null, tenant = TENANT, offlineMode = "fail-open", installToken = "tok-1" } = {}) {
  const alerts = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.method === "POST") { try { alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(200, { "Content-Type": "application/json" }); return res.end("{}"); }
      const want = req.url.startsWith("/api/policy/pubkey") ? pubkey : serve;
      if (want == null) { res.writeHead(req.url.startsWith("/api/policy/pubkey") ? 404 : 500); return res.end("offline"); }
      res.writeHead(200, { "Content-Type": "application/json" }); res.end(want);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${server.address().port}`, tenant, installToken }));
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: offlineMode };
    delete env.MOORAI_POLICY_PUBKEY;
    delete env.MOORAI_BREAKGLASS_PUBKEY;
    const child = spawn(process.execPath, [HOOK], { env, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify({ tool_name: "mcp__probe__ping", tool_input: {} }));
    let stdout = "";
    child.stdout.on("data", (c) => (stdout += c));
    const code = await new Promise((r) => child.on("close", r));
    await new Promise((r) => setTimeout(r, 150)); // let in-flight alert POSTs land
    return { alerts, stdout, code, hashes: alerts.map((a) => a.contentHash) };
  } finally {
    await new Promise((r) => server.close(r));
  }
}

const bypassed = (r) => r.stdout === "";
const refused = (r) => /"permissionDecision":"ask"/.test(r.stdout);
const enforced = (r) => /"permissionDecision":"deny"/.test(r.stdout);
const withHome = async (fn) => { const home = newHome(); try { return await fn(home); } finally { rmSync(home, { recursive: true, force: true }); } };

// ---- ITEM 1: the gap ----

test("E2E LKG: a FAIL-OPEN org now ENFORCES through a poisoned cache instead of exiting 0", { skip: HOST_LATCHED && "host has a root-owned posture latch" }, async () => {
  await withHome(async (home) => {
    // 1. A perfectly ordinary fail-open device fetches its signed policy once. It pins, and records the
    //    policy as last-known-good.
    const r1 = await run(home, { serve: STRICT(), pubkey: pubkeyBody(consoleKey) });
    assert.ok(enforced(r1), `the signed policy must apply on first contact; stdout was ${JSON.stringify(r1.stdout)}`);
    assert.ok(existsSync(LKG_A(home)), "a verified fresh policy must become last-known-good");

    // 2. The attack: poison the cache and take the console away. BEFORE this change the poisoned cache
    //    was refused, which meant "no policy", which for a fail-open org meant exit(0) — the attacker's
    //    bypass, delivered with an alert attached.
    writeFileSync(CACHE(home), "{}");
    const r2 = await run(home, {});
    assert.ok(!bypassed(r2), "FAIL-OPEN BYPASS: the poisoned cache still produced exit(0)");
    assert.ok(enforced(r2), `must enforce with last-known-good; stdout was ${JSON.stringify(r2.stdout)}`);
    assert.ok(r2.hashes.includes("policy:lkg:applied"), `expected the lkg signal, got ${JSON.stringify(r2.hashes)}`);
    assert.ok(r2.hashes.includes("policy:cache:unsigned"), `the refusal must still be reported, got ${JSON.stringify(r2.hashes)}`);
    const lkg = r2.alerts.find((a) => a.contentHash === "policy:lkg:applied");
    assert.equal(lkg.lkgReason, "refused", "the alert must say the primary was refused, not merely absent");
    assert.equal(lkg.stage, "policy");
  });
});

test("E2E LKG: the stored copy is RE-VERIFIED — a forged last-known-good is not enforced", async () => {
  await withHome(async (home) => {
    await run(home, { serve: STRICT(), pubkey: pubkeyBody(consoleKey), offlineMode: "fail-closed" });
    // The last-known-good file is in the agent's own write scope. "We wrote it" is not a trust argument:
    // if it were, this whole file would just be a second poisoning surface with extra steps.
    for (const p of [LKG_A(home), LKG_B(home)]) writeFileSync(p, '{"mcpAllow":["probe"]}');
    writeFileSync(CACHE(home), "{}");
    const r = await run(home, { offlineMode: "fail-closed" });
    assert.ok(!bypassed(r), "FORGED LKG ACCEPTED: an unsigned last-known-good must never be enforced");
    assert.ok(refused(r), `must fall through to the offline default; stdout was ${JSON.stringify(r.stdout)}`);
    assert.ok(!r.hashes.includes("policy:lkg:applied"), `nothing verified, so no lkg signal; got ${JSON.stringify(r.hashes)}`);
  });
});

test("E2E LKG: a last-known-good signed by a ROGUE key is refused too", async () => {
  await withHome(async (home) => {
    await run(home, { serve: STRICT(), pubkey: pubkeyBody(consoleKey), offlineMode: "fail-closed" });
    for (const p of [LKG_A(home), LKG_B(home)]) writeFileSync(p, sign({ mcpAllow: ["probe"] }, { key: rogueKey.privateKey }));
    writeFileSync(CACHE(home), "{}");
    const r = await run(home, { offlineMode: "fail-closed" });
    assert.ok(refused(r), `a rogue-signed last-known-good must not apply; stdout was ${JSON.stringify(r.stdout)}`);
  });
});

test("E2E LKG: a verified FRESH policy replaces it — a legitimate relaxation is never resurrected", async () => {
  await withHome(async (home) => {
    // 1. strict policy → last-known-good is strict
    await run(home, { serve: STRICT(), pubkey: pubkeyBody(consoleKey), offlineMode: "fail-closed" });
    // 2. the org legitimately relaxes; the device fetches it fresh and it must replace the stored copy
    ageCache(home);
    const r2 = await run(home, { serve: RELAXED(), pubkey: pubkeyBody(consoleKey), offlineMode: "fail-closed" });
    assert.ok(bypassed(r2), `the relaxed policy must apply; stdout was ${JSON.stringify(r2.stdout)}`);
    // 3. poison the cache and go offline. The last-known-good that applies must be the RELAXED one — if
    //    the strict policy came back, this mechanism would be silently re-imposing retired rules.
    writeFileSync(CACHE(home), "{}");
    const r3 = await run(home, { offlineMode: "fail-closed" });
    assert.ok(r3.hashes.includes("policy:lkg:applied"), `expected the lkg signal, got ${JSON.stringify(r3.hashes)}`);
    assert.ok(!enforced(r3), "the RETIRED strict policy was resurrected");
    assert.ok(bypassed(r3), `the relaxed last-known-good must apply; stdout was ${JSON.stringify(r3.stdout)}`);
  });
});

test("E2E LKG: BOTH copies are written, so erasing one still enforces", async () => {
  await withHome(async (home) => {
    await run(home, { serve: STRICT(), pubkey: pubkeyBody(consoleKey), offlineMode: "fail-closed" });
    assert.ok(existsSync(LKG_A(home)) && existsSync(LKG_B(home)), "both user-scope copies must be written");
    assert.equal(readFileSync(LKG_A(home), "utf8"), readFileSync(LKG_B(home), "utf8"));
    rmSync(LKG_A(home), { force: true }); // `rm ~/.curaiq/policy-lkg.json`
    writeFileSync(CACHE(home), "{}");
    const r = await run(home, { offlineMode: "fail-closed" });
    assert.ok(enforced(r), `the surviving copy must still enforce; stdout was ${JSON.stringify(r.stdout)}`);
    assert.equal(r.alerts.find((a) => a.contentHash === "policy:lkg:applied").lkgCopy, "latch");
  });
});

test("E2E LKG NO BRICK: a console that never signs records no last-known-good", async () => {
  await withHome(async (home) => {
    // An unsigned policy is trusted trivially on an unanchored device ("unanchored", not "ok"). Storing
    // one would be pointless — it could never survive its own re-verification — and would wreck the
    // file's second job as proof that a real signature was once seen (Item 2).
    await run(home, { serve: JSON.stringify({ captureTier: "content-free", mcpAllow: ["something-else"] }) });
    assert.equal(existsSync(LKG_A(home)), false);
    assert.equal(existsSync(LKG_B(home)), false);
  });
});

// ---- ITEM 2: pin absence on a device that has demonstrably held a pin ----

test("E2E ABSENCE: erasing BOTH pin copies raises a distinct, content-free alert", async () => {
  await withHome(async (home) => {
    await run(home, { serve: STRICT(), pubkey: pubkeyBody(consoleKey) });
    assert.ok(existsSync(BREADCRUMB(home)), "a pinned device must leave the third-location breadcrumb");

    // The residual-risk move policy-pin.test.mjs documents: erase both copies, then poison the cache.
    rmSync(PIN_A(home), { force: true });
    rmSync(PIN_B(home), { force: true });
    writeFileSync(CACHE(home), "{}");
    const r = await run(home, {});
    const a = r.alerts.find((x) => x.contentHash === "policy:pin:absent-operational");
    assert.ok(a, `expected the pin-absence alert, got ${JSON.stringify(r.hashes)}`);
    assert.equal(a.riskLevel, "Critical");
    assert.equal(a.stage, "policy");
    assert.ok(a.pinEvidence.includes("pin-breadcrumb"), `evidence was ${JSON.stringify(a.pinEvidence)}`);
    assert.ok(a.pinEvidence.includes("policy-lkg"), `evidence was ${JSON.stringify(a.pinEvidence)}`);
    // Content-free: artifact NAMES only, never a byte of any file.
    assert.ok(!JSON.stringify(a).includes("mcpAllow"));
    assert.ok(!JSON.stringify(a).includes(id(consoleKey)));
  });
});

test("E2E ABSENCE: a genuinely FRESH install raises nothing — no brick, no false page", async () => {
  await withHome(async (home) => {
    const r = await run(home, {}); // enrolled, but nothing has ever run here
    assert.ok(!r.hashes.includes("policy:pin:absent-operational"), `got ${JSON.stringify(r.hashes)}`);
  });
});

test("E2E ABSENCE: a never-signing console fleet raises nothing on its later runs", async () => {
  // The false positive the "prior operation" heuristic would have produced: these devices legitimately
  // never form a pin, yet write posture copies and audit lines from run 2 onward.
  await withHome(async (home) => {
    const unsigned = JSON.stringify({ captureTier: "content-free", mcpAllow: ["something-else"] });
    await run(home, { serve: unsigned });
    ageCache(home);
    const r2 = await run(home, { serve: unsigned });
    assert.ok(!r2.hashes.includes("policy:pin:absent-operational"), `healthy fleet was paged: ${JSON.stringify(r2.hashes)}`);
  });
});

test("E2E ABSENCE: the window shrinks — in this state a FRESH cache no longer short-circuits the fetch", async () => {
  await withHome(async (home) => {
    await run(home, { serve: STRICT(), pubkey: pubkeyBody(consoleKey) });
    rmSync(PIN_A(home), { force: true });
    rmSync(PIN_B(home), { force: true });
    // The cache was written seconds ago, so it is INSIDE the 60s freshness window: normally the hook
    // returns it without touching the network, and a cached policy never re-arms the pin. A device that
    // has lost its pin must not sit in that state for a whole window at a time.
    const r = await run(home, { serve: STRICT(), pubkey: pubkeyBody(consoleKey) });
    assert.ok(existsSync(PIN_A(home)), "the device must re-fetch and re-pin instead of serving the fresh cache");
    assert.ok(r.hashes.includes("policy:pin:absent-operational"), `the state must still be reported, got ${JSON.stringify(r.hashes)}`);
  });
});

test("E2E ABSENCE: the breadcrumb holds no key material and self-heals while a pin exists", async () => {
  await withHome(async (home) => {
    await run(home, { serve: STRICT(), pubkey: pubkeyBody(consoleKey) });
    const crumb = JSON.parse(readFileSync(BREADCRUMB(home), "utf8"));
    assert.equal(crumb.v, POLICY_PIN_VERSION);
    assert.equal(crumb.tenant, TENANT);
    assert.ok(!JSON.stringify(crumb).includes(id(consoleKey)), "the breadcrumb must not carry the pinned key");

    rmSync(BREADCRUMB(home), { force: true }); // deleting it while the pin survives must not stick
    ageCache(home);
    await run(home, { serve: STRICT(), pubkey: pubkeyBody(consoleKey) });
    assert.ok(existsSync(BREADCRUMB(home)), "a run with a live pin must restore the breadcrumb");
  });
});
