// FIX 2 — the Claude Desktop MCP proxy must verify the policy signature.
//
// mcp-proxy/moorai-mcp-guard.mjs's loadPolicy() was a verbatim copy of the hook's PRE-v0.51 logic:
// `JSON.parse(readFileSync(~/.curaiq/hook-policy.json))` with no signature check, no anchor and no
// pin. v0.51-v0.53 closed `echo '{}' > ~/.curaiq/hook-policy.json` for Claude Code while leaving
// Claude Desktop fully bypassable through the very same file — a fifth door into the same room.
//
// The contract pinned here: a poisoned cache on a PINNED device is treated as NO policy, the proxy
// falls back to the last policy that genuinely verified, and the `tools/call` is STILL blocked. The
// assertion is end-to-end over real stdio against the real fake MCP server, and it checks the real
// server's received-log too — "blocked" means the call never reached it, not merely that the model
// saw an error.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const TENANT = "acme";

const consoleKey = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(consoleKey.publicKey) });

function sign(policy, { tenant = TENANT, iat = "2026-08-21T00:00:00.000Z" } = {}) {
  const digest = policyDigest(policy);
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant, iat, digest })), consoleKey.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant, iat, sig } });
}

// The enforcing policy: deny any `echo` call whose serialized args contain BLOCKME (#18).
const STRICT = sign({ captureTier: "content-free", mcpToolRules: { echo: { deny: ["BLOCKME"] } } });

// Drive one proxy process over stdio and return the responses by JSON-RPC id, plus what the REAL
// server actually received.
async function driveProxy(home, recvLog, { serverUrl, env = {}, payload = "please BLOCKME now" }) {
  const child = spawn(process.execPath, [GUARD, "--server", "testsrv", "--", process.execPath, FAKE, recvLog], {
    cwd: ROOT,
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: serverUrl, MoorAI_TENANT: TENANT, ...env }
  });
  child.stderr.on("data", () => {});
  const byId = new Map();
  let buf = "";
  child.stdout.on("data", (c) => {
    buf += c.toString();
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
      if (!line.trim()) continue;
      try { const m = JSON.parse(line); if (m.id != null) byId.set(m.id, m); } catch { /* ignore */ }
    }
  });
  const send = (o) => child.stdin.write(JSON.stringify(o) + "\n");
  send({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { msg: "hello world" } } });
  send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { msg: payload } } });

  const deadline = Date.now() + 8000;
  while (byId.size < 2 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 25));
  try { child.stdin.end(); } catch { /* ignore */ }
  try { child.kill(); } catch { /* ignore */ }
  await new Promise((r) => setTimeout(r, 100));
  return { byId, received: existsSync(recvLog) ? readFileSync(recvLog, "utf8") : "" };
}

const isBlocked = (m) => Boolean(m && m.result && m.result.isError === true && /MoorAI blocked/i.test(String(m.result.content?.[0]?.text)));

test("PROXY: a poisoned policy cache does NOT disarm the Claude Desktop gate", async () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-proxy-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true });
  const alerts = [];

  // Phase 1 — a reachable console serving a SIGNED strict policy. The device pins the key (TOFU) and
  // records the signed body as last-known-good.
  let consoleDown = false;
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) {
      // Phase 2 takes the CONSOLE away (503) while leaving the alert sink up, so the tamper signal
      // raised by the poisoned cache can still be observed.
      if (consoleDown) { res.writeHead(503); res.end(""); return; }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(req.url === "/api/policy/pubkey" ? pubkeyBody : STRICT);
      return;
    }
    if (req.url === "/api/alerts" && req.method === "POST") {
      let b = ""; req.on("data", (c) => (b += c));
      req.on("end", () => { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}`;
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: url, tenant: TENANT, installToken: "tok" }));

  const warm = await driveProxy(home, join(home, "recv-1.log"), { serverUrl: url });
  assert.ok(isBlocked(warm.byId.get(2)), "phase 1: the signed strict policy must block BLOCKME");

  // Phase 2 — the console goes away and the attacker runs the one-liner:
  //     echo '{}' > ~/.curaiq/hook-policy.json
  consoleDown = true;
  writeFileSync(join(home, ".curaiq", "hook-policy.json"), "{}");

  const poisoned = await driveProxy(home, join(home, "recv-2.log"), { serverUrl: url });
  assert.ok(isBlocked(poisoned.byId.get(2)),
    "a `{}` cache disarmed the proxy — the tools/call was forwarded instead of blocked");
  assert.ok(!/BLOCKME/.test(poisoned.received),
    "the real MCP server RECEIVED the call that should have been blocked");
  // ...and the benign call still works, so this is enforcement, not a brick.
  assert.ok(/hello world/.test(poisoned.received), "the benign call must still reach the real server");

  // The mechanism that made the above possible, asserted last so it never preempts the headline claim:
  // phase 1's verified fetch armed the TOFU pin (which is what makes the planted body untrusted) and
  // recorded the signed body as last-known-good (which is what keeps enforcement running through it).
  assert.ok(existsSync(join(home, ".curaiq", "policy-pin.json")), "the device must have pinned the console key");
  assert.ok(existsSync(join(home, ".curaiq", "policy-lkg.json")), "the verified policy must be recorded as last-known-good");
  // Content-free tamper signal, under the same token the hook emits.
  assert.ok(alerts.some((a) => a.contentHash === "policy:cache:unsigned"),
    `no content-free tamper alert for the poisoned cache: ${JSON.stringify(alerts.map((a) => a.contentHash))}`);

  await new Promise((r) => server.close(r));
  rmSync(home, { recursive: true, force: true });
});

// A permissive cache with NO deny rule at all: if the proxy trusted it, an AWS key in a tool argument
// would sail through (threat 39 resolves to "notify" under a bare policy). Refusing it hands the
// fail-closed device OFFLINE_DEFAULT_POLICY instead, which blocks threat 39 outright.
const PLANTED = JSON.stringify({ captureTier: "content-free" });
const AWS_ARG = "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

test("PROXY: an unverifiable cache is NO policy — a fail-closed device falls to the offline default", async () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-proxy-nolkg-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true });
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:1", tenant: TENANT, installToken: "tok" }));
  // A pin for the real console key — the device has verified a real signature before, so the planted
  // (unsigned) body is refused rather than trusted.
  const pin = JSON.stringify({ v: 1, tenant: TENANT, keys: [publicKeyId(consoleKey.publicKey)], updated: new Date().toISOString() });
  writeFileSync(join(home, ".curaiq", "policy-pin.json"), pin);
  writeFileSync(join(home, ".moorai", "policy-pin.json"), pin);
  writeFileSync(join(home, ".curaiq", "hook-policy.json"), PLANTED);

  const r = await driveProxy(home, join(home, "recv.log"), {
    serverUrl: "http://127.0.0.1:1",
    env: { MOORAI_OFFLINE_MODE: "fail-closed" },
    payload: AWS_ARG
  });
  assert.ok(isBlocked(r.byId.get(2)),
    "the planted permissive cache applied — a secret in a tool argument was not blocked");
  assert.ok(!/AKIAIOSFODNN7EXAMPLE/.test(r.received), "the real MCP server received the secret-bearing call");
  assert.equal(readFileSync(join(home, ".curaiq", "hook-policy.json"), "utf8"), PLANTED,
    "a refused cache must be left exactly as planted, never promoted");

  rmSync(home, { recursive: true, force: true });
});

test("PROXY: with the SAME planted cache trusted, the call would have passed (the bypass, shown)", async () => {
  // The contrast case, so the assertion above is not just asserting the offline default's existence:
  // on a device with NO pin and NO anchor the planted body IS trusted ("unanchored" — the documented
  // no-brick behaviour), and the very same secret-bearing argument is forwarded.
  const home = mkdtempSync(join(tmpdir(), "moorai-proxy-unpinned-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true });
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:1", tenant: TENANT, installToken: "tok" }));
  writeFileSync(join(home, ".curaiq", "hook-policy.json"), PLANTED);

  const r = await driveProxy(home, join(home, "recv.log"), { serverUrl: "http://127.0.0.1:1", payload: AWS_ARG });
  assert.ok(!isBlocked(r.byId.get(2)), "an unanchored, unpinned device is expected to keep trusting its cache");
  rmSync(home, { recursive: true, force: true });
});
