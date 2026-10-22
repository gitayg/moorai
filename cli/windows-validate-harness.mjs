// Plumbing for the Windows runtime validation probes (cli/windows-validate-probes.mjs): a loopback console
// that serves a signed policy per tenant and collects alerts, a throwaway HOME per probe, and helpers that
// run the agent's real processes (the hook, the MCP gateway, the egress proxy) against them.
//
// The operator's own state is never touched: every child gets an environment built from scratch with HOME,
// USERPROFILE, APPDATA, LOCALAPPDATA and the XDG directories inside a temp dir, and none of the operator's
// MOORAI_* or proxy variables. The policy is signed with a key generated for this run only.
import http from "node:http";
import { spawn } from "node:child_process";
import { generateKeyPairSync, sign as edSign, randomBytes } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "./hook-core.mjs";

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The console: GET /api/policy?tenant=T answers the policy set for T, signed; GET /api/policy/pubkey the
// run's public key; POST /api/alerts stores the alert; the batch route answers 404 so the agent falls back
// to single posts; posture beats are accepted and dropped.
export async function startConsole() {
  const key = generateKeyPairSync("ed25519");
  const pubkey = JSON.stringify({ alg: "ed25519", publicKey: publicKeyId(key.publicKey) });
  const policies = new Map();
  const alerts = [];
  const tokens = [];
  const signed = (tenant, policy) => {
    const iat = new Date().toISOString();
    const digest = policyDigest(policy);
    const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant, iat, digest })), key.privateKey).toString("base64");
    return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant, iat, sig } });
  };
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { if (body.length < 1 << 20) body += c; });
    req.on("end", () => {
      const url = new URL(req.url, "http://127.0.0.1");
      if (req.method === "GET" && url.pathname === "/api/policy/pubkey") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(pubkey); }
      if (req.method === "GET" && url.pathname === "/api/policy") {
        const t = url.searchParams.get("tenant") || "";
        if (!policies.has(t)) { res.writeHead(404); return res.end(); }
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(signed(t, policies.get(t)));
      }
      if (req.method === "POST" && url.pathname === "/api/alerts") {
        try { const a = JSON.parse(body); alerts.push(a); tokens.push(String(req.headers["x-install-token"] || "")); } catch { /* not an alert */ }
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end("{}");
      }
      if (req.method === "POST" && url.pathname === "/api/agent-posture") { res.writeHead(201); return res.end("{}"); }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    alerts,
    setPolicy: (tenant, policy) => policies.set(tenant, policy),
    // By the install token the alert was posted with: each probe's sandbox enrolls with tok-<tenant>.
    alertsFor: (tenant) => alerts.filter((_, i) => tokens[i] === `tok-${tenant}`),
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); })
  };
}

// A throwaway device: HOME with an enrolled ~/.moorai/config.json naming the console and the tenant, and
// a project directory. remove() is best-effort: detached hook workers may still be writing.
export function makeSandbox(base, name, consoleUrl, tenant) {
  const home = join(base, name);
  const proj = join(home, "proj");
  mkdirSync(join(home, ".moorai"), { recursive: true });
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: consoleUrl, tenant, installToken: `tok-${tenant}` }));
  return { home, proj, tenant };
}
export function makeBase() { return mkdtempSync(join(tmpdir(), "moorai-winval-")); }
export function removeTree(dir) {
  for (let i = 0; i < 3; i++) { try { rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); return; } catch { /* a late worker write */ } }
}

// The environment every child gets, built from scratch. Only what a Windows or POSIX process needs to
// start and find its tools is copied from this process.
const PASS = ["PATH", "Path", "SystemRoot", "SYSTEMROOT", "windir", "SystemDrive", "COMSPEC", "ComSpec", "PATHEXT", "TEMP", "TMP", "TMPDIR", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "LANG"];
export function childEnv(sb, extra = {}) {
  const env = {};
  for (const k of PASS) if (process.env[k] !== undefined) env[k] = process.env[k];
  Object.assign(env, {
    HOME: sb.home, USERPROFILE: sb.home,
    APPDATA: join(sb.home, "AppData", "Roaming"), LOCALAPPDATA: join(sb.home, "AppData", "Local"),
    XDG_CONFIG_HOME: join(sb.home, ".config"), XDG_STATE_HOME: join(sb.home, ".local", "state"),
    CLAUDE_PROJECT_DIR: sb.proj
  });
  return { ...env, ...extra };
}

// Runs a child to completion with `input` on stdin. Never rejects: a spawn failure or a timeout comes back
// as { code: null, spawnError | timedOut }.
export function runChild(cmd, args, { env, cwd, input = "", timeoutMs = 30000 } = {}) {
  return new Promise((resolve) => {
    let child;
    try { child = spawn(cmd, args, { env, cwd, stdio: ["pipe", "pipe", "pipe"], windowsHide: true }); }
    catch (e) { return resolve({ code: null, stdout: "", stderr: "", spawnError: true }); }
    let stdout = "", stderr = "", done = false;
    const finish = (r) => { if (!done) { done = true; clearTimeout(timer); resolve(r); } };
    const timer = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* gone */ } finish({ code: null, stdout, stderr, timedOut: true }); }, timeoutMs);
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("error", () => finish({ code: null, stdout, stderr, spawnError: true }));
    child.on("close", (code) => finish({ code, stdout, stderr }));
    child.stdin.on("error", () => { /* the child exited before reading */ });
    child.stdin.end(input);
  });
}

// The hook's verdict from its stdout: Claude Code's hookSpecificOutput.permissionDecision, else allow on a
// clean exit, deny on exit 2 (the blocking exit code).
export function hookDecision(r) {
  if (r.spawnError) return { observed: "error", reason: "spawn-failed" };
  if (r.timedOut) return { observed: "timeout", reason: "timeout" };
  let j = null;
  const t = String(r.stdout || "").trim();
  if (t) { try { j = JSON.parse(t.split(/\r?\n/).filter(Boolean).at(-1)); } catch { return { observed: "error", reason: "bad-output" }; } }
  const d = j && j.hookSpecificOutput && j.hookSpecificOutput.permissionDecision;
  if (d === "deny" || d === "ask" || d === "allow") return { observed: d, reason: null };
  if (r.code === 2) return { observed: "deny", reason: null };
  if (r.code === 0) return { observed: "allow", reason: null };
  return { observed: "error", reason: "no-decision" };
}

export const preToolUse = (sb, tool_name, tool_input) => JSON.stringify({ session_id: `wv-${sb.tenant}`, transcript_path: "", cwd: sb.proj, permission_mode: "default", hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id: `tu-${randomBytes(4).toString("hex")}` });

// Starts a long-running agent process and resolves once its stderr says "listening on http://...".
export function startListening(cmd, args, { env, cwd, timeoutMs = 15000 } = {}) {
  return new Promise((resolve) => {
    let child;
    try { child = spawn(cmd, args, { env, cwd, stdio: ["ignore", "pipe", "pipe"], windowsHide: true }); }
    catch { return resolve({ child: null, url: null, reason: "spawn-failed" }); }
    let stderr = "", done = false;
    const finish = (r) => { if (!done) { done = true; clearTimeout(timer); resolve({ child, ...r }); } };
    const timer = setTimeout(() => finish({ url: null, reason: "not-listening" }), timeoutMs);
    child.stderr.on("data", (c) => {
      stderr += c;
      const m = /listening on (http:\/\/[^\s]+)/.exec(stderr);
      if (m) finish({ url: m[1].replace(/\/$/, ""), reason: null });
    });
    child.stdout.on("data", () => { /* drained */ });
    child.on("error", () => finish({ url: null, reason: "spawn-failed" }));
    child.on("exit", () => finish({ url: null, reason: "not-listening" }));
  });
}
export function stopChild(child, graceMs = 4000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    const t = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* gone */ } }, graceMs);
    child.once("exit", () => { clearTimeout(t); resolve(); });
    try { child.kill(); } catch { clearTimeout(t); resolve(); }
  });
}

// A minimal remote MCP server (Streamable HTTP, JSON responses) that counts the tool calls reaching it.
export async function startUpstream() {
  let calls = 0;
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.method !== "POST") { res.writeHead(405); return res.end(); }
      let m;
      try { m = JSON.parse(body); } catch { res.writeHead(400); return res.end(); }
      if (m.id == null) { res.writeHead(202); return res.end(); }
      let result;
      if (m.method === "initialize") result = { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "wv-upstream", version: "1.0.0" } };
      else if (m.method === "tools/list") result = { tools: [{ name: "send_note", description: "Saves a note.", inputSchema: { type: "object", properties: { body: { type: "string" } } } }] };
      else if (m.method === "tools/call") { calls++; result = { content: [{ type: "text", text: "saved" }], isError: false }; }
      else result = {};
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: m.id, result }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${server.address().port}`, calls: () => calls, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) };
}

// One request through a forward proxy (absolute-form request line), resolving to the HTTP status or null.
export function viaProxy(proxyUrl, target, timeoutMs = 10000) {
  return new Promise((resolve) => {
    const p = new URL(proxyUrl);
    const t = new URL(target);
    const req = http.request({ host: p.hostname, port: p.port, method: "GET", path: target, headers: { Host: t.host }, timeout: timeoutMs }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); });
    req.on("timeout", () => { req.destroy(); resolve(null); });
    req.on("error", () => resolve(null));
    req.end();
  });
}
