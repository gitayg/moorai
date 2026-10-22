// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/ot-protocol-client-hook.test.mjs
//
// The OT protocol client check (cli/ot-protocol-client.mjs) end to end through the real hook and a local
// console listener: a Modbus write blocked by the OT preset's threatPolicy, a read reported and allowed,
// and the alert fields (reasonCode OT_PROTOCOL_CLIENT, otProtocol, otOp) with no command content.
//
// SKIPPED until the hook imports cli/ot-protocol-client.mjs: cli/moorai-hook.mjs has one integrator
// (CONTRACT-F28 §0.7). This file owns the assertions; the integrator lands the one-line call in the Bash
// branch (the insertion is in the A10 package report).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { OT_THREAT } from "../cli/ot-protocol-client.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const WIRED = readFileSync(HOOK, "utf8").includes("ot-protocol-client.mjs");
const skip = WIRED ? false : "hook wiring for the OT protocol client check not landed yet (cli/moorai-hook.mjs)";

const TOKEN = "tok-othook-SECRET-71aa";
const WRITE = "mbpoll -1 -a 1 -t 4 -r 4242 10.20.0.5 1500";
const READ = "mbpoll -1 -a 1 -t 4 -r 4242 10.20.0.5";

async function consoleServer(policy) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/api/alerts") { alerts.push(JSON.parse(body)); res.writeHead(201); return res.end("{}"); }
      if (req.method === "POST" && req.url === "/api/alerts/batch") { const b = JSON.parse(body); alerts.push(...(b.alerts || [])); res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ results: (b.alerts || []).map((a) => ({ seq: a.seq, status: "stored" })) })); }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); return res.end(); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify(policy)); }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, close: () => srv.close() };
}
function run(home, command, env) {
  const payload = { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, session_id: "ot", cwd: join(home, "proj"), permission_mode: "default" };
  return new Promise((res) => {
    const c = spawn(process.execPath, [HOOK], { cwd: join(home, "proj"), env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), CLAUDE_PROJECT_DIR: join(home, "proj"), ...env } });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", (status) => { assert.equal(status, 0, err); const t = out.trim(); res({ out: t ? JSON.parse(t) : {}, raw: out + err }); });
    c.stdin.end(JSON.stringify(payload));
  });
}
const decision = (o) => (o.hookSpecificOutput && o.hookSpecificOutput.permissionDecision) || "allow";
const env = (url) => ({ MOORAI_MODE: "server", MOORAI_SERVER_URL: url, MOORAI_TENANT: "ot-test", MOORAI_INSTALL_TOKEN: TOKEN, MOORAI_SERVICE_ID: "ot-bot" });
const waitFor = async (pred, ms = 3000) => { const end = Date.now() + ms; while (Date.now() < end) { if (pred()) return true; await new Promise((r) => setTimeout(r, 50)); } return pred(); };

test("OT preset: a Modbus write from the agent shell is denied; a read is reported and allowed", { skip }, async () => {
  const c = await consoleServer({ captureTier: "content-free", threatPolicy: { [OT_THREAT.write]: "block", [OT_THREAT.read]: "notify" } });
  const home = mkdtempSync(join(tmpdir(), "moorai-othook-"));
  mkdirSync(join(home, "proj"), { recursive: true });
  try {
    const w = await run(home, WRITE, env(c.url));
    assert.equal(decision(w.out), "deny", JSON.stringify(w.out));
    assert.match(w.out.hookSpecificOutput.permissionDecisionReason, /OT protocol client \(modbus write\)/);
    assert.ok(await waitFor(() => c.alerts.some((a) => a.reasonCode === "OT_PROTOCOL_CLIENT" && a.otOp === "write")), JSON.stringify(c.alerts.map((a) => a.category)));
    const a = c.alerts.find((x) => x.reasonCode === "OT_PROTOCOL_CLIENT" && x.otOp === "write");
    assert.equal(a.otProtocol, "modbus");
    assert.equal(a.threatId, OT_THREAT.write);
    assert.equal(a.decision, "deny");
    for (const leak of ["10.20.0.5", "4242", "1500"]) assert.ok(!JSON.stringify(c.alerts).includes(leak), `alert carries ${leak}`);

    const r = await run(home, READ, env(c.url));
    assert.notEqual(decision(r.out), "deny", JSON.stringify(r.out));
    assert.ok(await waitFor(() => c.alerts.some((x) => x.reasonCode === "OT_PROTOCOL_CLIENT" && x.otOp === "read")));
  } finally { c.close(); rmTree(home); }
});

test("no OT policy: a Modbus write is reported, not blocked (built-in notify)", { skip }, async () => {
  const c = await consoleServer({ captureTier: "content-free" });
  const home = mkdtempSync(join(tmpdir(), "moorai-othook-"));
  mkdirSync(join(home, "proj"), { recursive: true });
  try {
    const w = await run(home, WRITE, env(c.url));
    assert.notEqual(decision(w.out), "deny", JSON.stringify(w.out));
    assert.ok(await waitFor(() => c.alerts.some((a) => a.reasonCode === "OT_PROTOCOL_CLIENT" && a.otOp === "write" && a.decision === "notify")));
  } finally { c.close(); rmTree(home); }
});
