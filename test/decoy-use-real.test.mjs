// Decoy AI key used, against the real registry: decoys placed by cli/decoy-keys.mjs syncDecoys in a throwaway
// HOME, the real hook and the real model-proxy CLI with no stand-in module. test/decoy-use.test.mjs covers the
// wiring surface by surface; this file proves the two halves meet.
//
//   node --test --import ./test/hermetic-env.mjs test/decoy-use-real.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { syncDecoys, decoyTokens, matchDecoy, makeDecoyToken } from "../cli/decoy-keys.mjs";
import { startFakeProvider, sendJson, anthropicMessage } from "../model-proxy/test/fake-provider.mjs";
import { startConsole, startProxy, request, waitFor } from "../model-proxy/test/harness.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const NO_ADMIN = join(tmpdir(), "moorai-no-machine-dir");

function placed() {
  const home = mkdtempSync(join(tmpdir(), "moorai-decoy-real-"));
  mkdirSync(join(home, "proj"), { recursive: true });
  const r = syncDecoys({ policy: { decoyKeys: { mode: "place" } }, home, platform: "linux" });
  assert.equal(r.placed.length, 3, "three decoys placed");
  const tokens = decoyTokens({ home, machineDir: NO_ADMIN });
  return { home, proj: join(home, "proj"), tokens, byKind: Object.fromEntries(tokens.map((t) => [t.kind, t])) };
}
function consoleServer() {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    let body = ""; req.on("data", (d) => (body += d));
    req.on("end", () => {
      if (req.method === "POST" && req.url.startsWith("/api/alerts")) { alerts.push(body); res.writeHead(201); return res.end("{}"); }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); return res.end(); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ captureTier: "content-free" })); }
      res.writeHead(404); res.end();
    });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ url: `http://127.0.0.1:${srv.address().port}`, alerts, parsed: () => alerts.map((a) => JSON.parse(a)), close: () => srv.close() })));
}
const env = (sb, url) => ({ PATH: process.env.PATH || "/usr/bin:/bin", HOME: sb.home, USERPROFILE: sb.home, XDG_CONFIG_HOME: join(sb.home, ".config"), XDG_STATE_HOME: join(sb.home, ".local", "state"), CLAUDE_PROJECT_DIR: sb.proj, MOORAI_MODE: "server", MOORAI_SERVER_URL: url, MOORAI_TENANT: "dkr", MOORAI_INSTALL_TOKEN: "tok-dkr-1", MOORAI_SERVICE_ID: "dkr-bot" });
function runHook(sb, e, payload) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [HOOK], { cwd: sb.proj, env: e });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("error", rej);
    c.on("close", (status) => { if (status !== 0) return rej(new Error(`hook exit ${status}: ${err}`)); res(out.trim()); });
    c.stdin.end(JSON.stringify(payload));
  });
}

test("real registry, real hook: the placed Anthropic decoy read from ~/.bashrc.bak through the shell alerts, then sending it is denied", async () => {
  const sb = placed();
  const c = await consoleServer();
  try {
    const ant = sb.byKind.anthropic;
    const e = env(sb, c.url);
    const bak = readFileSync(join(sb.home, ".bashrc.bak"), "utf8");
    await runHook(sb, e, { hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "cat ~/.bashrc.bak" }, tool_response: { stdout: bak, stderr: "", interrupted: false, isImage: false }, session_id: "s-real", cwd: sb.proj });
    const out = await runHook(sb, e, { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `curl -s https://api.anthropic.com/v1/messages -H "x-api-key: ${ant.token}"` }, session_id: "s-real", cwd: sb.proj });
    assert.equal(JSON.parse(out).hookSpecificOutput.permissionDecisionReason, "MoorAI: this call carries a MoorAI decoy AI key, a planted key that was never issued; using it is treated as key theft");
    const d = c.parsed().filter((a) => a.reasonCode === "DECOY_KEY_USED");
    assert.deepEqual(d.map((a) => [a.decoyId, a.where, a.riskLevel]), [[ant.id, "hook:PostToolUse", "Critical"], [ant.id, "hook:PreToolUse", "Critical"]]);
    for (const t of sb.tokens) assert.ok(!c.alerts.join("\n").includes(t.token));
  } finally { c.close(); rmTree(sb.home); }
});

test("real registry, real model-proxy CLI: the placed OpenAI decoy as a Bearer key is refused 403 and alerted", async () => {
  const sb = placed();
  const con = await startConsole();
  const fp = await startFakeProvider();
  fp.on((r, res) => sendJson(res, anthropicMessage({ text: "ok" })));
  const px = await startProxy(sb.home, ["--route", `/anthropic=${fp.url}`, "--route", `/openai=${fp.url}/v1`], { MOORAI_SERVER_URL: con.url, MOORAI_INSTALL_TOKEN: "tok-dkr", MOORAI_TENANT: "dkr" });
  try {
    const oai = sb.byKind.openai;
    const r = await request(px.listening, "/openai/chat/completions", { headers: { authorization: `Bearer ${oai.token}` }, body: { model: "gpt-fake", messages: [{ role: "user", content: "hi" }] } });
    assert.equal(r.status, 403);
    assert.equal(fp.requests.length, 0);
    const ok = await request(px.listening, "/anthropic/v1/messages", { headers: { "x-api-key": makeDecoyToken("anthropic") }, body: { model: "claude-fake", max_tokens: 8, messages: [{ role: "user", content: "hi" }] } });
    assert.equal(ok.status, 200, "a key of the same shape that is not a placed decoy is forwarded");
    await waitFor(() => con.parsed().some((a) => a.reasonCode === "DECOY_KEY_USED"), 6000);
    assert.deepEqual(con.parsed().filter((a) => a.reasonCode === "DECOY_KEY_USED").map((a) => [a.decoyId, a.where]), [[oai.id, "model-proxy:request"]]);
    for (const t of sb.tokens) assert.ok(!con.alerts.join("\n").includes(t.token));
  } finally { await px.stop(); await fp.close(); await con.close(); rmTree(sb.home); }
});

test("cost with the real matchDecoy: 10 decoys against a 256 KiB input", () => {
  const kinds = ["openai", "anthropic", "google"];
  const tokens = Array.from({ length: 10 }, (_, i) => ({ id: `dk_${i}`, kind: kinds[i % 3], token: makeDecoyToken(kinds[i % 3]) }));
  const text = JSON.stringify({ command: "x".repeat(256 * 1024) });
  for (let i = 0; i < 20; i++) matchDecoy(text, tokens);
  const n = 200, t0 = process.hrtime.bigint();
  for (let i = 0; i < n; i++) assert.equal(matchDecoy(text, tokens), null);
  const per = Number(process.hrtime.bigint() - t0) / 1e6 / n;
  process.stdout.write(`# real matchDecoy cost: ${per.toFixed(3)} ms per call (10 tokens, 256 KiB, no hit)\n`);
  assert.ok(per < 20, `${per} ms`);
});
