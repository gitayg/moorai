// Every short-lived MoorAI CLI that talks to the console must exit with its own code after doing so.
//
// v1.9.0 ended these processes with process.exit() right after fetch(). On Windows (Node 24) that aborts
// the process with 0xC0000409 (exit code 3221226505) and "Assertion failed: !(handle->flags &
// UV_HANDLE_CLOSING), file src\win\async.c, line 76" (see cli/exit-drain.mjs). MEASURED on Windows 11
// with the v1.9.0 files: the guard's enrolled abort path crashed instead of exiting 1. macOS and Linux
// never crashed, so there these tests pin the rest of the contract: the documented exit code, no signal,
// the output delivered, and the console reached before the process went away.
//
//   node --test --import ./test/hermetic-env.mjs test/cli-exit-drain.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = (p) => join(ROOT, p);
const FAKE_KEY = "sk-ant-api03-" + "Zx9".repeat(30) + "AA";
const RUNS = 3; // the crash was 5/5 on the box; three runs per case keep the file fast

// A console that serves `policy` at /api/policy and answers every other request with 200 {}.
async function fakeConsole(t, policy = {}) {
  const hits = [];
  const srv = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      hits.push(`${req.method} ${req.url.split("?")[0]}`);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(req.url.startsWith("/api/policy") ? JSON.stringify(policy) : "{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => srv.close());
  return { url: `http://127.0.0.1:${srv.address().port}`, hits };
}

function enrolledHome(t, url, files = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-cli-exit-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "acme", installToken: "tok-cli-exit" }));
  for (const [name, text] of Object.entries(files)) writeFileSync(join(home, name), text);
  t.after(() => rmTree(home));
  return home;
}
function env(home) {
  const e = { ...process.env, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), APPDATA: join(home, "AppData", "Roaming"), LOCALAPPDATA: join(home, "AppData", "Local"), MOORAI_MODE: "" };
  for (const k of ["MOORAI_OTLP_ENDPOINT", "MOORAI_SERVER_URL", "MOORAI_TENANT", "MOORAI_INSTALL_TOKEN", "MoorAI_SERVER", "MoorAI_TENANT"]) delete e[k];
  return e;
}
function run(args, home, input = "") {
  return new Promise((resolve) => {
    const ch = spawn(process.execPath, args, { cwd: ROOT, env: env(home), stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    ch.stdout.on("data", (d) => (stdout += d));
    ch.stderr.on("data", (d) => (stderr += d));
    ch.on("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
    ch.stdin.end(input);
  });
}
function exited(r, code, what) {
  assert.equal(r.signal, null, `${what}: killed by ${r.signal}\n${r.stderr}`);
  assert.equal(r.code, code, `${what}: exit ${r.code}, expected ${code}\n${r.stderr}`);
}

test("moorai-guard enrolled: a flagged prompt aborts with exit 1 after posting, and a block policy exits 3", async (t) => {
  const c = await fakeConsole(t);
  const home = enrolledHome(t, c.url);
  for (let i = 0; i < RUNS; i++) {
    const before = c.hits.length;
    const r = await run([CLI("cli/moorai-guard.mjs"), `key ${FAKE_KEY}`], home);
    exited(r, 1, "guard abort");
    assert.match(r.stderr, /aborted — nothing sent/);
    assert.ok(c.hits.slice(before).includes("POST /api/alerts"), `the alerts reached the console: ${c.hits.slice(before)}`);
  }
  const b = await fakeConsole(t, { captureTier: "content-free", threatPolicy: { 39: "block" } });
  const home2 = enrolledHome(t, b.url);
  for (let i = 0; i < RUNS; i++) exited(await run([CLI("cli/moorai-guard.mjs"), `key ${FAKE_KEY}`], home2), 3, "guard block");
});

test("moorai-agentwatch --emit: posts the window's finding and exits 0", async (t) => {
  const c = await fakeConsole(t);
  const corpus = JSON.parse(readFileSync(join(ROOT, "test", "redteam", "vector5-memory-crossagent.json"), "utf8"));
  const events = corpus.attacks.find((a) => a.id === "v5-deputy-001").events;
  const home = enrolledHome(t, c.url);
  writeFileSync(join(home, ".moorai", "agent-events.jsonl"), events.map((e) => JSON.stringify(e)).join("\n") + "\n");
  for (let i = 0; i < RUNS; i++) {
    const before = c.hits.length;
    const r = await run([CLI("cli/moorai-agentwatch.mjs"), "--emit", "--format", "json"], home);
    exited(r, 0, "agentwatch --emit");
    assert.ok(JSON.parse(r.stdout).baseline, "the report was printed");
    assert.ok(c.hits.slice(before).includes("POST /api/alerts"), "the alert reached the console");
  }
});

test("moorai-redteam: fetches the live policy and exits 0 when every class is caught", async (t) => {
  const c = await fakeConsole(t, { captureTier: "content-free", threatPolicy: {} });
  const home = enrolledHome(t, c.url);
  for (let i = 0; i < RUNS; i++) {
    const r = await run([CLI("cli/moorai-redteam.mjs"), "--format", "json"], home);
    const out = JSON.parse(r.stdout);
    assert.equal(out.policyLoaded, true, "the policy came from the console");
    exited(r, out.summary.gaps ? 1 : 0, "redteam");
  }
});

test("moorai-backtest: fetches the live policy and exits with the candidate's verdict", async (t) => {
  const c = await fakeConsole(t, { captureTier: "content-free", threatPolicy: {} });
  const home = enrolledHome(t, c.url, { "candidate.json": JSON.stringify({ threatPolicy: { 21: "deny" } }) });
  for (let i = 0; i < RUNS; i++) {
    const r = await run([CLI("cli/moorai-backtest.mjs"), "--policy", join(home, "candidate.json"), "--json"], home);
    const out = JSON.parse(r.stdout);
    assert.equal(out.currentPolicyLoaded, true, "the policy came from the console");
    exited(r, out.summary.wouldBlock || out.summary.wouldCoach ? 1 : 0, "backtest");
  }
});

test("moorai-cloud-inventory --post: posts the inventory and exits 0", async (t) => {
  const c = await fakeConsole(t);
  const home = enrolledHome(t, c.url);
  for (let i = 0; i < RUNS; i++) {
    const before = c.hits.length;
    const r = await run([CLI("cloud/moorai-cloud-inventory.mjs"), "bedrock", "--from", join(ROOT, "test", "fixtures", "cloud-bedrock"), "--post"], home);
    exited(r, 0, "cloud-inventory --post");
    assert.match(r.stderr, /posted \d+ records to the console/);
    assert.ok(c.hits.slice(before).includes("POST /api/cloud-inventory"));
  }
});

test("moorai-doctor --no-selftest: checks the console and exits with its verdict", async (t) => {
  const c = await fakeConsole(t);
  const home = enrolledHome(t, c.url);
  for (let i = 0; i < RUNS; i++) {
    const r = await run([CLI("cli/moorai-doctor.mjs"), "--no-selftest", "--json"], home);
    const out = JSON.parse(r.stdout);
    exited(r, out.exitCode, "doctor");
  }
});

test("moorai-mcp-guard enrolled: ends with its child and exits 0 after its start-up posts", async (t) => {
  const c = await fakeConsole(t);
  const home = enrolledHome(t, c.url);
  const call = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "run", arguments: { cmd: "ls" } } }) + "\n";
  for (let i = 0; i < RUNS; i++) {
    const r = await run([CLI("mcp-proxy/moorai-mcp-guard.mjs"), "--server", "exit-test", "--", process.execPath, CLI("mcp-proxy/test-fake-mcp-server.mjs"), join(home, "recv.log")], home, call);
    exited(r, 0, "mcp-guard");
    assert.match(r.stdout, /"id":1/, "the call's response was delivered before the guard exited");
  }
});
