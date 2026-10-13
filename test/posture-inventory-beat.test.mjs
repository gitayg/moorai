// The inventory detectors on the coverage heartbeat, end to end: the real hook in a throwaway HOME fetches a
// policy its stand-in console SIGNED (the device pins the key on first contact), spawns the real detached
// posturebeat worker, and the worker posts localModelServers, aiApiCallers and decoyKeys at the top level of
// the heartbeat plus content-free LOCAL_MODEL_EXPOSED / AI_API_CALLER_UNKNOWN alerts with the agent identity.
//
// The TCP table is the only stand-in: a module loader hook (test-only, --import, inherited by the worker
// through execArgv) hands cli/agent-posture.mjs a cli/local-ai-inventory.mjs whose tcpTable returns
// TEST_SOCKETS. Behind it everything is real: the listener the test opens is probed with a real TCP connect,
// the two node processes the test starts are read with the real ps / /proc, and the provider address comes
// from the resolver's own cache file, seeded so no DNS query leaves the machine.
//
//   node --test --import ./test/hermetic-env.mjs test/posture-inventory-beat.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, statSync, existsSync, unlinkSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import http from "node:http";
import net from "node:net";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const REAL = pathToFileURL(join(ROOT, "cli", "local-ai-inventory.mjs")).href;
const TENANT = "inv-beat";
const PROVIDER_IP = "203.0.113.9"; // TEST-NET-3: never routed

const dataUrl = (src) => `data:text/javascript,${encodeURIComponent(src)}`;
const FAKE = dataUrl(`export * from ${JSON.stringify(REAL)};
export function tcpTable() { return { sockets: JSON.parse(process.env.TEST_SOCKETS || "[]"), source: "test" }; }`);
const HOOKS = dataUrl(`export async function resolve(s, c, next) { if (s === "./local-ai-inventory.mjs" && c.parentURL && c.parentURL.endsWith("/cli/agent-posture.mjs")) return { url: ${JSON.stringify(FAKE)}, shortCircuit: true }; return next(s, c); }`);
const IMPORT = dataUrl(`import { register } from "node:module"; register(${JSON.stringify(HOOKS)});`);

const key = generateKeyPairSync("ed25519");
function signed(policy) {
  const iat = new Date().toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), key.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
const PUBKEY = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 15000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(50); } return false; }

// The console: serves `state.policy` (and the published key while `state.pubkey`), answers alert posts with
// `state.alertStatus`, records the heartbeats and the alerts it accepted.
async function consoleStub(t, state) {
  const posts = [], alerts = [];
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/api/agent-posture") { posts.push(JSON.parse(b)); res.writeHead(201); return res.end("{}"); }
      if (req.method === "POST" && req.url === "/api/alerts") { if (state.alertStatus < 300) alerts.push(JSON.parse(b)); res.writeHead(state.alertStatus); return res.end("{}"); }
      if (req.url.startsWith("/api/policy/pubkey")) { if (!state.pubkey) { res.writeHead(404); return res.end(); } res.writeHead(200, { "Content-Type": "application/json" }); return res.end(PUBKEY); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(state.policy); }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => srv.close(r)));
  return { url: `http://127.0.0.1:${srv.address().port}`, posts, alerts };
}

// A local "model server": a real loopback listener the worker's connect probe reaches.
async function listener(t) {
  const s = net.createServer((c) => c.destroy());
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => s.close(r)));
  return s.address().port;
}
// A long-lived node process running `script` (created under the throwaway HOME).
function nodeProc(t, script) {
  mkdirSync(dirname(script), { recursive: true });
  writeFileSync(script, "setInterval(() => {}, 1000);\n");
  const c = spawn(process.execPath, [script], { stdio: "ignore" });
  t.after(() => { try { c.kill(); } catch { /* gone */ } });
  return String(c.pid);
}

function box(t, url) {
  const home = mkdtempSync(join(tmpdir(), "moorai-inv-beat-"));
  t.after(() => rmTree(home));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: TENANT, installToken: "tok-inv-beat" }));
  // The resolver's own cache (cli/ai-api-callers.mjs CACHE_FILE): the provider address, no DNS.
  writeFileSync(join(home, ".moorai", "ai-api-hosts.json"), JSON.stringify({ at: Date.now(), byIp: { [PROVIDER_IP]: "anthropic" }, ambiguous: [] }));
  return home;
}
const env = (home, sockets) => ({ PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, TEST_SOCKETS: JSON.stringify(sockets) });
function runHook(home, sockets) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, ["--import", IMPORT, HOOK], { cwd: home, env: env(home, sockets), stdio: ["pipe", "ignore", "pipe"] });
    let err = "";
    c.stderr.on("data", (d) => (err += d));
    c.on("error", rej);
    c.on("close", (code) => (code === 0 ? res() : rej(new Error(`hook exit ${code}: ${err}`))));
    c.stdin.end(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "s-inv", cwd: home }));
  });
}
function runWorker(home, sockets) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, ["--import", IMPORT, HOOK, "posturebeat", "claude-code", "", ""], { cwd: home, env: env(home, sockets), stdio: "ignore" });
    c.on("error", rej);
    c.on("close", res);
  });
}
const STATE = (home) => join(home, ".moorai", "inventory-detectors.json");
const mtime = (p) => { try { return statSync(p).mtimeMs; } catch { return 0; } };
// One heartbeat through the real hook: forget today's beat stamp, run the hook, wait for the worker's
// heartbeat AND its once-per-change memory (written after its alert posts settle).
async function beat(home, c, sockets) {
  try { unlinkSync(join(home, ".moorai", "posture-beat-claude-code.json")); } catch { /* first beat */ }
  const before = mtime(STATE(home)), n = c.posts.length;
  await runHook(home, sockets);
  assert.ok(await until(() => c.posts.length > n), "heartbeat posted");
  assert.ok(await until(() => mtime(STATE(home)) > before), "inventory memory written after the posts");
  return c.posts[c.posts.length - 1];
}
const byReason = (alerts, r) => alerts.filter((a) => a.reasonCode === r);
const DECOY_FILES = (home) => [join(home, ".env.backup"), join(home, process.platform === "darwin" ? ".zshrc.bak" : ".bashrc.bak"), join(home, ".config", "gemini", "credentials.bak")];

test("signed policy: the heartbeat carries the three top-level fields; an exposed local model server alerts once on the first beat and not on the second", async (t) => {
  const state = { policy: signed({ captureTier: "content-free", decoyKeys: { mode: "place" } }), pubkey: true, alertStatus: 201 };
  const c = await consoleStub(t, state);
  const home = box(t, c.url);
  const port = await listener(t);
  // A user-prefix npm install (~/.npm-global/lib/node_modules/<pkg>, its package.json naming cli.js as the bin).
  const pkgDir = join(home, ".npm-global", "lib", "node_modules", "@anthropic-ai", "claude-code");
  const known = nodeProc(t, join(pkgDir, "cli.js"));
  writeFileSync(join(pkgDir, "package.json"), JSON.stringify({ name: "@anthropic-ai/claude-code", bin: { claude: "cli.js" } }));
  const rogue = nodeProc(t, join(home, "tmp", "x.js"));
  const sockets = [
    { pid: "1", proc: "ollama", state: "listen", lhost: "127.0.0.1", lport: port, rhost: null, rport: null },
    { pid: known, proc: "node", state: "established", lhost: "10.0.0.5", lport: 50001, rhost: PROVIDER_IP, rport: 443 },
    { pid: rogue, proc: "node", state: "established", lhost: "10.0.0.5", lport: 50002, rhost: PROVIDER_IP, rport: 443 }
  ];

  const b1 = await beat(home, c, sockets);
  assert.deepEqual(b1.localModelServers, [{ runtime: "ollama", port, bind: "loopback", viaProxy: false }]);
  assert.deepEqual(b1.aiApiCallers, [{ processImage: "node", provider: "anthropic", known: false }, { processImage: "node", provider: "anthropic", known: true }]);
  assert.deepEqual(b1.decoyKeys, { placed: 3, source: "agent" }, "decoys placed per the signed policy");
  for (const f of DECOY_FILES(home)) assert.ok(existsSync(f), `decoy placed in the throwaway HOME: ${f}`);
  assert.ok(b1.failMode && b1.aiCliParents, "the other worker fields are unchanged");

  const ex1 = byReason(c.alerts, "LOCAL_MODEL_EXPOSED");
  assert.equal(ex1.length, 1, "exactly one LOCAL_MODEL_EXPOSED on the first beat");
  const a = ex1[0];
  assert.deepEqual([a.category, a.riskLevel, a.runtime, a.port, a.bind, a.stage], ["Local model server reachable without MoorAI", "Medium", "ollama", port, "loopback", "inventory"]);
  for (const f of ["user", "device", "platform", "tenant", "actor", "agentName"]) assert.ok(a[f], `identity field ${f}`);
  assert.equal(a.tenant, TENANT);
  const ca = byReason(c.alerts, "AI_API_CALLER_UNKNOWN");
  assert.equal(ca.length, 1, "the unknown node script alerts, the npm Claude Code does not");
  assert.deepEqual([ca[0].processImage, ca[0].provider, ca[0].connections], ["node", "anthropic", 1]);
  const wire = JSON.stringify([...c.alerts, b1]);
  for (const leak of [home, "x.js", "cli.js", "127.0.0.1", PROVIDER_IP, "sk-"]) assert.ok(!wire.includes(leak), `content-free: no ${leak}`);

  const b2 = await beat(home, c, sockets);
  assert.deepEqual(b2.localModelServers, b1.localModelServers);
  assert.equal(byReason(c.alerts, "LOCAL_MODEL_EXPOSED").length, 1, "none on the second beat");
  assert.equal(byReason(c.alerts, "AI_API_CALLER_UNKNOWN").length, 1, "none on the second beat");
  assert.equal(c.posts.length, 2);
});

test("a failed alert post is not remembered: the exposure is raised again on the next beat", async (t) => {
  const state = { policy: signed({ captureTier: "content-free" }), pubkey: true, alertStatus: 503 };
  const c = await consoleStub(t, state);
  const home = box(t, c.url);
  const port = await listener(t);
  const sockets = [{ pid: "1", proc: "ollama", state: "listen", lhost: "127.0.0.1", lport: port, rhost: null, rport: null }];
  await beat(home, c, sockets);
  assert.equal(byReason(c.alerts, "LOCAL_MODEL_EXPOSED").length, 0, "the console refused it");
  state.alertStatus = 201;
  await beat(home, c, sockets);
  assert.equal(byReason(c.alerts, "LOCAL_MODEL_EXPOSED").length, 1, "raised again once the console accepts it");
  await beat(home, c, sockets);
  assert.equal(byReason(c.alerts, "LOCAL_MODEL_EXPOSED").length, 1, "and then remembered");
});

test("decoys follow only a policy this device verified: an unsigning console places nothing, a tampered cache neither places nor removes, a signed off removes", async (t) => {
  // 1. A console that does not sign: the device never pins, its policy verified nothing → no placement.
  {
    const state = { policy: JSON.stringify({ captureTier: "content-free", decoyKeys: { mode: "place" } }), pubkey: false, alertStatus: 201 };
    const c = await consoleStub(t, state);
    const home = box(t, c.url);
    const b = await beat(home, c, []);
    assert.deepEqual(b.decoyKeys, { placed: 0, source: "none" });
    for (const f of DECOY_FILES(home)) assert.ok(!existsSync(f), `nothing placed: ${f}`);
  }
  // 2. Pinned device, signed "place": placed. Then a same-user rewrite of the cache to an unsigned "off" is
  //    refused (the worker falls back to the verified last-known-good), so the decoys stay.
  const state = { policy: signed({ captureTier: "content-free", decoyKeys: { mode: "place" } }), pubkey: true, alertStatus: 201 };
  const c = await consoleStub(t, state);
  const home = box(t, c.url);
  assert.deepEqual((await beat(home, c, [])).decoyKeys, { placed: 3, source: "agent" });
  const cache = join(home, ".moorai", "hook-policy.json");
  writeFileSync(cache, JSON.stringify({ captureTier: "content-free", decoyKeys: { mode: "off" } }));
  await runWorker(home, []);
  for (const f of DECOY_FILES(home)) assert.ok(existsSync(f), `a tampered cache removes nothing: ${f}`);
  assert.deepEqual(c.posts[c.posts.length - 1].decoyKeys, { placed: 3, source: "agent" });
  // 3. The console signs "off": the next beat fetches it and the decoys MoorAI placed are removed.
  await sleep(5);
  state.policy = signed({ captureTier: "content-free", decoyKeys: { mode: "off" } });
  const old = (Date.now() - 2 * 3600 * 1000) / 1000;
  utimesSync(cache, old, old); // past the 60s cache window, so the hook fetches
  const b = await beat(home, c, []);
  assert.deepEqual(b.decoyKeys, { placed: 0, source: "none" });
  for (const f of DECOY_FILES(home)) assert.ok(!existsSync(f), `removed: ${f}`);
  assert.equal(JSON.parse(readFileSync(STATE(home), "utf8")).exposed.length, 0);
});
