// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/mcp-file-args-proxy.test.mjs
//
// The Claude Desktop stdio proxy had the same gap as the hook's mcp__* branch: mcpGateway scans the
// serialized arguments, so `tools/call {"path":"<abs>/customers.csv"}` forwarded a file of keys and SSNs
// with no finding. End-to-end over real stdio against the real fake MCP server, with a real HTTP alert
// sink: "reported" means a content-free alert arrived; "blocked" means the real server never received
// the call. Synthetic secrets only, in temp dirs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const AWS = "AKIAQ3EGUXWN5TLMRZ7P"; // the repo's synthetic secret-aws-akia placeholder
const CSV = `name,ssn,key\nalice,123-45-6789,${AWS}\n`;

async function withSink(fn) {
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(503); res.end(""); return; } // console down: the cached policy applies
    if (req.url === "/api/alerts" && req.method === "POST") {
      let b = ""; req.on("data", (c) => (b += c));
      req.on("end", () => { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try { return await fn(`http://127.0.0.1:${server.address().port}`, alerts); } finally { await new Promise((r) => server.close(r)); }
}

function sandbox(url, policy) {
  const home = mkdtempSync(join(tmpdir(), "moorai-mcpfile-proxy-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "mcpf", installToken: "tok" }));
  if (policy) writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(policy));
  const proj = join(home, "proj");
  mkdirSync(proj);
  writeFileSync(join(proj, "customers.csv"), CSV);
  writeFileSync(join(proj, "README.md"), "# demo\n");
  return { home, proj };
}

// Send `messages` and wait for a response to every tools/call id; returns responses by id, what the real
// server received, and the wall-clock time.
async function drive(home, cwd, url, messages) {
  const recv = join(home, "recv.log");
  const env = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: url, MoorAI_TENANT: "mcpf" };
  delete env.XDG_CONFIG_HOME; delete env.XDG_STATE_HOME;
  const child = spawn(process.execPath, [GUARD, "--server", "files", "--", process.execPath, FAKE, recv], { cwd, stdio: ["pipe", "pipe", "pipe"], env });
  child.stderr.on("data", () => {});
  const byId = new Map();
  let buf = "";
  child.stdout.on("data", (c) => {
    buf += c.toString();
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
      try { const m = JSON.parse(line); if (m.id != null) byId.set(m.id, m); } catch { /* ignore */ }
    }
  });
  const t0 = Date.now();
  for (const m of messages) child.stdin.write(JSON.stringify(m) + "\n");
  const want = messages.filter((m) => m.method === "tools/call").map((m) => m.id);
  const deadline = Date.now() + 10000;
  while (!want.every((id) => byId.has(id)) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
  const ms = Date.now() - t0;
  await new Promise((r) => setTimeout(r, 300)); // let the alert posts land
  try { child.stdin.end(); } catch { /* ignore */ }
  try { child.kill(); } catch { /* ignore */ }
  return { byId, ms, received: existsSync(recv) ? readFileSync(recv, "utf8") : "" };
}

const call = (id, args, name = "upload_file") => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
const isBlocked = (m) => Boolean(m && m.result && m.result.isError === true && /MoorAI blocked/i.test(String(m.result.content?.[0]?.text)));
const fileAlerts = (alerts, id) => alerts.filter((a) => a.threatId === id && a.stage === "file");

test("PROXY: a path argument gets the named file's content scanned and reported (#39 at stage file)", async () => {
  await withSink(async (url, alerts) => {
    const { home, proj } = sandbox(url, null);
    try {
      const r = await drive(home, proj, url, [call(1, { path: join(proj, "customers.csv") })]);
      assert.ok(!isBlocked(r.byId.get(1)), "no policy: report, forward");
      assert.ok(r.received.includes("customers.csv"), "the real server received the call");
      const a = fileAlerts(alerts, 39);
      assert.ok(a.length >= 1, `expected a #39 alert at stage file, got ${JSON.stringify(alerts.map((x) => [x.threatId, x.stage, x.category]))}`);
      assert.equal(a[0].tool, "desktop:upload_file");
      assert.ok(!JSON.stringify(alerts).includes(AWS) && !JSON.stringify(alerts).includes("123-45-6789"), "content-free");
    } finally { rmTree(home); }
  });
});

test("PROXY: a policy block on #39 refuses the call before the real server sees it", async () => {
  await withSink(async (url, alerts) => {
    const { home, proj } = sandbox(url, { captureTier: "content-free", threatPolicy: { 39: "block" } });
    try {
      const r = await drive(home, proj, url, [call(1, { path: join(proj, "README.md") }), call(2, { files: [{ uri: pathToFileURL(join(proj, "customers.csv")).href }] })]);
      assert.ok(!isBlocked(r.byId.get(1)), "a clean file passes");
      assert.ok(isBlocked(r.byId.get(2)), `the secret-bearing file must be blocked: ${JSON.stringify(r.byId.get(2))}`);
      assert.match(r.byId.get(2).result.content[0].text, /file customers\.csv/);
      assert.ok(!r.received.includes("customers.csv"), "the real server received a blocked call");
      assert.ok(alerts.some((a) => a.category === "MCP: blocked file argument"), "block alert");
    } finally { rmTree(home); }
  });
});

test("PROXY: relative paths resolve against the proxy's cwd, then the client's MCP roots", async () => {
  await withSink(async (url, alerts) => {
    const { home, proj } = sandbox(url, { captureTier: "content-free", threatPolicy: { 39: "block" } });
    const other = join(home, "other");
    mkdirSync(other);
    writeFileSync(join(other, "export.csv"), CSV);
    try {
      const r = await drive(home, proj, url, [
        call(1, { path: "customers.csv" }),
        call(2, { path: "export.csv" }),
        { jsonrpc: "2.0", id: "roots-1", result: { roots: [{ uri: pathToFileURL(other).href, name: "other" }] } },
        call(3, { path: "export.csv" })
      ]);
      assert.ok(isBlocked(r.byId.get(1)), "cwd-relative");
      assert.ok(!isBlocked(r.byId.get(2)), "not under cwd and no roots yet: nothing to read");
      assert.ok(isBlocked(r.byId.get(3)), "root-relative, once the client announced its roots");
    } finally { rmTree(home); }
  });
});

test("PROXY: /dev/zero and a directory are never read; the call is forwarded promptly", async () => {
  await withSink(async (url) => {
    const { home, proj } = sandbox(url, { captureTier: "content-free", threatPolicy: { 39: "block" } });
    try {
      const r = await drive(home, proj, url, [call(1, { path: "/dev/zero", dir: proj, u: "/dev/urandom" })]);
      assert.ok(r.byId.has(1) && !isBlocked(r.byId.get(1)));
      assert.ok(r.ms < 8000, `took ${r.ms} ms`);
    } finally { rmTree(home); }
  });
});
