// F23 at the stdio MCP proxy (mcp-proxy/moorai-mcp-guard.mjs): the egress rules judge every destination a
// tools/call's arguments name, by the same function the hook uses for mcp__<server>__<tool>, so a deny on
// 10.0.0.0/8 holds identically in the hook, the HTTP gateway (test/mcp-gateway-egress.test.mjs) and here.
// End to end over real stdio, against the real fake MCP server; "blocked" means the call never reached it.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-guard-egress.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { evaluateProfile } from "../cli/workload-profile.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const TENANT = "acme";
const key = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) });
function sign(policy) {
  const iat = new Date().toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), key.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
const POLICY = { captureTier: "content-free", egressRules: [{ id: "rfc1918", cidr: ["10.0.0.0/8"], action: "block" }] };

async function run(calls, { enrolled = true } = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-guard-egress-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true }); mkdirSync(join(home, ".moorai"), { recursive: true });
  const alerts = [];
  const body = sign(POLICY);
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(req.url === "/api/policy/pubkey" ? pubkeyBody : body); return; }
    if (req.url === "/api/alerts" && req.method === "POST") { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); }); return; }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}`;
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: url, tenant: TENANT, ...(enrolled ? { installToken: "tok" } : {}) }));
  const recv = join(home, "recv.log");
  const env = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: url, MoorAI_TENANT: TENANT };
  delete env.XDG_CONFIG_HOME; delete env.XDG_STATE_HOME;
  const child = spawn(process.execPath, [GUARD, "--server", "fetchsrv", "--", process.execPath, FAKE, recv], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env });
  child.stderr.on("data", () => {});
  const byId = new Map();
  let buf = "";
  child.stdout.on("data", (c) => {
    buf += c.toString();
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, nl); buf = buf.slice(nl + 1); try { const m = JSON.parse(line); if (m.id != null) byId.set(m.id, m); } catch { /* ignore */ } }
  });
  calls.forEach(([id, args]) => child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "echo", arguments: args } }) + "\n"));
  const deadline = Date.now() + 8000;
  while (byId.size < calls.length && Date.now() < deadline) await new Promise((r) => setTimeout(r, 25));
  await new Promise((r) => setTimeout(r, 400));
  try { child.stdin.end(); child.kill(); } catch { /* ignore */ }
  await new Promise((r) => setTimeout(r, 100));
  await new Promise((r) => server.close(r));
  const received = existsSync(recv) ? readFileSync(recv, "utf8") : "";
  rmTree(home);
  return { byId, received, alerts };
}
const isBlocked = (m) => Boolean(m && m.result && m.result.isError === true && /MoorAI blocked/i.test(String(m.result.content?.[0]?.text)));

test("stdio proxy: a tools/call naming an address inside a cidr block rule is refused and never reaches the server; others go", async () => {
  const r = await run([[1, { msg: "see https://example.com/doc" }], [2, { msg: "fetch http://10.1.2.3/admin?k=ARG-SECRET-9" }]]);
  assert.ok(!isBlocked(r.byId.get(1)), JSON.stringify(r.byId.get(1)));
  assert.ok(isBlocked(r.byId.get(2)), JSON.stringify(r.byId.get(2)));
  assert.match(r.byId.get(2).result.content[0].text, /egress to 10\.1\.2\.3:80 by mcp__fetchsrv__echo is blocked by egress rule "rfc1918"/);
  assert.ok(/example\.com/.test(r.received));
  assert.ok(!/10\.1\.2\.3/.test(r.received), "the blocked call reached the real server");
  const a = r.alerts.filter((x) => x.reasonCode === "EGRESS_RULE");
  assert.equal(a.length, 1, JSON.stringify(r.alerts.map((x) => x.category)));
  assert.deepEqual([a[0].egressHost, a[0].egressRuleId, a[0].decision, a[0].mcpServer], ["10.1.2.3", "rfc1918", "deny", "fetchsrv"]);
  assert.ok(!JSON.stringify(r.alerts).includes("ARG-SECRET-9"), "argument text reached an alert");
  // The hook's verdict on the same call.
  const hook = evaluateProfile({ policy: POLICY, tool: "mcp__fetchsrv__echo", toolInput: { msg: "fetch http://10.1.2.3/admin?k=ARG-SECRET-9" } });
  assert.equal(hook.decision, "deny");
});
