// Offline-posture RATCHET tests (#33 follow-up). Sibling of break-glass.test.mjs, same threat model:
// the hook runs AS THE USER, so anything in the user's own write scope is attacker-controlled the
// moment the agent is prompt-injected. Break-glass closed the "forge the override file" door; this
// closes the "forge the POSTURE" door — `echo fail-open > ~/.curaiq/offline-posture` (or exporting
// MOORAI_OFFLINE_MODE=fail-open) silently returning a fail-closed device to fail-open.
//
// The contract these pin: HARDENING is free (fail-open → fail-closed needs no proof), WEAKENING is
// authenticated (only a real server policy or an operator-signed break-glass marker gets you back).
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { tmpdir, hostname } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { ratchetPosture, breakGlassCanonical, BREAK_GLASS_VERSION } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "acme";

// The machine-wide latch is root-provisioned and deliberately NOT overridable by env (an env override
// would reintroduce the very bypass this file closes). A dev box that actually has one would pin every
// case to fail-closed, so the E2E cases that assert fail-open are skipped there rather than lying.
const SYSTEM_LATCH = process.platform === "win32"
  ? join(process.env.ProgramData || "C:\\ProgramData", "MoorAI", "offline-posture")
  : "/etc/moorai/offline-posture";
const HOST_LATCHED = existsSync(SYSTEM_LATCH);

// ---- unit: the pure ratchet ----

test("RATCHET: fail-closed from any single source wins over fail-open from every other", () => {
  for (const k of ["system", "sidecar", "latch", "env"]) {
    const src = { system: "fail-open", sidecar: "fail-open", latch: "fail-open", env: "fail-open", [k]: "fail-closed" };
    const r = ratchetPosture(src);
    assert.equal(r.posture, "fail-closed", `${k}=fail-closed must harden`);
    assert.ok(r.hardenedBy.includes(k));
  }
});

test("RATCHET: a user-scope fail-open is recorded as a refused downgrade, not honored", () => {
  const r = ratchetPosture({ latch: "fail-closed", sidecar: "fail-open", env: "fail-open" });
  assert.equal(r.posture, "fail-closed");
  assert.deepEqual(r.downgradeAttempt.sort(), ["env", "sidecar"]);
});

test("RATCHET: erasing one of the two user-scope copies is evidence-missing, not a downgrade", () => {
  const r = ratchetPosture({ latch: "fail-closed", sidecar: "" });
  assert.equal(r.posture, "fail-closed");
  assert.equal(r.evidenceMissing, true);
  assert.deepEqual(r.downgradeAttempt, []);
});

test("RATCHET: a never-configured device defaults to fail-open with no tamper signal", () => {
  const r = ratchetPosture({});
  assert.equal(r.posture, "fail-open");
  assert.deepEqual(r.hardenedBy, []);
  assert.deepEqual(r.downgradeAttempt, []);
  assert.equal(r.evidenceMissing, false);
});

test("RATCHET: a consistently fail-open device stays fail-open and is not flagged", () => {
  const r = ratchetPosture({ sidecar: "fail-open", latch: "fail-open" });
  assert.equal(r.posture, "fail-open");
  assert.deepEqual(r.downgradeAttempt, []);
  assert.equal(r.evidenceMissing, false);
});

test("RATCHET: junk in a posture source is ignored, never read as fail-open", () => {
  const r = ratchetPosture({ latch: "fail-closed", sidecar: "nonsense", env: "FAIL-OPEN" });
  assert.equal(r.posture, "fail-closed");
  assert.deepEqual(r.downgradeAttempt, []); // junk is not an assertion of anything
  assert.equal(r.evidenceMissing, true);    // ...but the sidecar no longer corroborates the latch
});

// ---- end-to-end through the real hook process ----

// Same harness contract as break-glass.test.mjs: HOME is a throwaway dir and the probe is an MCP
// tool-call, because the offline fail-closed default sets mcpFloor:"ask" — so the hook's OWN stdout
// states the trust decision. "ask" = enforcement applied, "" + exit 0 = fail-open.
const operator = generateKeyPairSync("ed25519");
const PUB_B64 = operator.publicKey.export({ type: "spki", format: "der" }).toString("base64");
function mint({ tenant = TENANT, device = hostname(), expires = "2099-01-01T00:00:00.000Z", nonce = "n0" } = {}) {
  const body = { v: BREAK_GLASS_VERSION, tenant, device, expires, nonce };
  return JSON.stringify({ ...body, sig: edSign(null, Buffer.from(breakGlassCanonical(body)), operator.privateKey).toString("base64") });
}

async function runHook({ sidecar, latch, env, policy, marker, anchorPub } = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-posture-"));
  const alerts = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.method === "POST") { try { alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(200, { "Content-Type": "application/json" }); return res.end("{}"); }
      if (policy) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify(policy)); }
      res.writeHead(500); res.end("offline"); // /api/policy unreachable → the offline path
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}`;
  try {
    mkdirSync(join(home, ".curaiq"), { recursive: true });
    writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: url, tenant: TENANT }));
    if (sidecar != null) writeFileSync(join(home, ".curaiq", "offline-posture"), sidecar);
    if (latch != null) { mkdirSync(join(home, ".moorai"), { recursive: true }); writeFileSync(join(home, ".moorai", "posture"), latch); }
    if (marker != null) writeFileSync(join(home, ".curaiq", "break-glass"), marker);
    const e = { ...process.env, HOME: home, USERPROFILE: home };
    if (env != null) e.MOORAI_OFFLINE_MODE = env; else delete e.MOORAI_OFFLINE_MODE;
    if (anchorPub) e.MOORAI_BREAKGLASS_PUBKEY = anchorPub; else delete e.MOORAI_BREAKGLASS_PUBKEY;
    const child = spawn(process.execPath, [HOOK], { env: e, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify({ tool_name: "mcp__probe__ping", tool_input: {} }));
    let stdout = "";
    child.stdout.on("data", (c) => (stdout += c));
    const code = await new Promise((r) => child.on("close", r));
    await new Promise((r) => setTimeout(r, 150)); // let in-flight alert POSTs land
    return { alerts, stdout, code, hashes: alerts.map((a) => a.contentHash), categories: alerts.map((a) => a.category) };
  } finally {
    await new Promise((r) => server.close(r));
    rmSync(home, { recursive: true, force: true });
  }
}
const enforced = (r) => /"permissionDecision":"ask"/.test(r.stdout);

// ---- the vulnerability itself ----

test("E2E: the exact `echo fail-open > ~/.curaiq/offline-posture` attack does NOT downgrade the device", async () => {
  const r = await runHook({ latch: "fail-closed", sidecar: "fail-open\n" });
  assert.ok(enforced(r), `device must stay fail-closed; hook stdout was ${JSON.stringify(r.stdout)}`);
});

test("E2E: MOORAI_OFFLINE_MODE=fail-open does NOT downgrade a fail-closed device", async () => {
  const r = await runHook({ latch: "fail-closed", sidecar: "fail-closed", env: "fail-open" });
  assert.ok(enforced(r), `env must not relax enforcement; hook stdout was ${JSON.stringify(r.stdout)}`);
});

test("E2E: DELETING the posture sidecar does not downgrade the device", async () => {
  const r = await runHook({ latch: "fail-closed" }); // sidecar omitted entirely
  assert.ok(enforced(r), `a deleted sidecar must not mean fail-open; stdout was ${JSON.stringify(r.stdout)}`);
});

test("E2E: deleting the other copy does not downgrade it either", async () => {
  const r = await runHook({ sidecar: "fail-closed" }); // latch omitted entirely
  assert.ok(enforced(r), `stdout was ${JSON.stringify(r.stdout)}`);
});

test("E2E: a refused downgrade raises a Critical, content-free tamper alert", async () => {
  const r = await runHook({ latch: "fail-closed", sidecar: "fail-open", env: "fail-open" });
  const a = r.alerts.find((x) => String(x.contentHash || "").startsWith("posture:downgrade-refused"));
  assert.ok(a, `expected a downgrade-refused alert, got: ${JSON.stringify(r.hashes)}`);
  assert.equal(a.riskLevel, "Critical");
  assert.equal(a.stage, "policy");
  assert.match(a.contentHash, /^posture:downgrade-refused:/);
  assert.match(a.contentHash, /env/);
  assert.match(a.contentHash, /sidecar/);
});

test("E2E: erasing one copy raises the evidence-missing signal, not a downgrade", async () => {
  const r = await runHook({ latch: "fail-closed" });
  assert.ok(r.hashes.includes("posture:evidence-missing"), `got: ${JSON.stringify(r.hashes)}`);
  assert.ok(!r.hashes.some((h) => String(h).startsWith("posture:downgrade-refused")));
});

// ---- the legitimate paths still work ----

test("E2E: hardening (fail-open → fail-closed) still needs no proof at all", async () => {
  const viaEnv = await runHook({ sidecar: "fail-open", latch: "fail-open", env: "fail-closed" });
  assert.ok(enforced(viaEnv), `env hardening must apply; stdout was ${JSON.stringify(viaEnv.stdout)}`);
  const viaFile = await runHook({ sidecar: "fail-closed" });
  assert.ok(enforced(viaFile), `sidecar hardening must apply; stdout was ${JSON.stringify(viaFile.stdout)}`);
});

test("E2E: a REAL server policy saying fail-open legitimately relaxes a fail-closed device", { skip: HOST_LATCHED && "host has a system posture latch" }, async () => {
  const r = await runHook({ latch: "fail-closed", sidecar: "fail-closed", policy: { offlineMode: "fail-open", captureTier: "content-free" } });
  assert.equal(r.stdout, "", "a real policy is an authorized relaxation — the hook must not enforce the offline default");
  assert.equal(r.code, 0);
});

test("E2E: an operator-signed break-glass marker still grants fail-open on a ratcheted device", { skip: HOST_LATCHED && "host has a system posture latch" }, async () => {
  const r = await runHook({ latch: "fail-closed", sidecar: "fail-closed", marker: mint(), anchorPub: PUB_B64 });
  assert.equal(r.stdout, "", "break-glass means fail-open — the hook must emit no deny/ask");
  assert.equal(r.code, 0);
  assert.ok(r.hashes.includes("breakglass:active"), `expected break-glass to activate, got: ${JSON.stringify(r.hashes)}`);
});

test("E2E: a never-configured device still defaults to fail-open (no implicit hardening)", { skip: HOST_LATCHED && "host has a system posture latch" }, async () => {
  const r = await runHook({}); // no policy, no posture files, no env
  assert.equal(r.stdout, "", `an unconfigured device must stay fail-open; stdout was ${JSON.stringify(r.stdout)}`);
  assert.equal(r.code, 0);
  assert.ok(!r.hashes.some((h) => String(h).startsWith("posture:")), `no tamper signal expected, got ${JSON.stringify(r.hashes)}`);
});

test("E2E: a policy load writes BOTH posture copies, so one erasure still leaves the fact", async () => {
  // The ratchet is only as durable as what gets recorded: prove the hook itself lays down the second
  // copy on a normal fail-closed policy load, rather than relying on the installer to have done it.
  const home = mkdtempSync(join(tmpdir(), "moorai-posture-w-"));
  const server = http.createServer((req, res) => {
    if (req.method === "POST") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end("{}"); }
    res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ offlineMode: "fail-closed", captureTier: "content-free" }));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    mkdirSync(join(home, ".curaiq"), { recursive: true });
    writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${server.address().port}`, tenant: TENANT }));
    const e = { ...process.env, HOME: home, USERPROFILE: home };
    delete e.MOORAI_OFFLINE_MODE; delete e.MOORAI_BREAKGLASS_PUBKEY;
    const child = spawn(process.execPath, [HOOK], { env: e, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify({ tool_name: "mcp__probe__ping", tool_input: {} }));
    await new Promise((r) => child.on("close", r));
    assert.ok(existsSync(join(home, ".curaiq", "offline-posture")), "sidecar must be written");
    assert.ok(existsSync(join(home, ".moorai", "posture")), "second copy must be written outside ~/.curaiq");
  } finally {
    await new Promise((r) => server.close(r));
    rmSync(home, { recursive: true, force: true });
  }
});
