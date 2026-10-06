// Shared harness for the gateway tests that need more than test/mcp-gateway.test.mjs's scenario: a fake
// console that serves a signed policy and records alerts AND /api/mcp-usage posts, a throwaway HOME, and
// a real gateway process. Used by test/mcp-gateway-usage.test.mjs, -hardening, -profile and the latency
// bench (scratchpad).
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../../cli/hook-core.mjs";
import { startUpstream } from "./fake-upstream.mjs";

export const GATEWAY = join(dirname(fileURLToPath(import.meta.url)), "..", "moorai-mcp-gateway.mjs");
export const TENANT = "acme";

const consoleKey = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(consoleKey.publicKey) });
export function sign(policy) {
  const digest = policyDigest(policy);
  const iat = "2026-09-01T00:00:00.000Z";
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest })), consoleKey.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}

export async function startConsole(policyBody) {
  const alerts = [], usage = [];
  const server = http.createServer((req, res) => {
    if (req.url === "/api/policy/pubkey") { res.writeHead(200, { "Content-Type": "application/json" }); res.end(pubkeyBody); return; }
    if (req.url.startsWith("/api/policy")) {
      if (!policyBody) { res.writeHead(503); res.end(""); return; }
      res.writeHead(200, { "Content-Type": "application/json" }); res.end(policyBody); return;
    }
    if (req.method === "POST" && (req.url === "/api/alerts" || req.url === "/api/mcp-usage")) {
      let b = ""; req.on("data", (c) => (b += c));
      req.on("end", () => {
        try { (req.url === "/api/alerts" ? alerts : usage).push(req.url === "/api/alerts" ? JSON.parse(b) : { token: req.headers["x-install-token"], raw: b, body: JSON.parse(b) }); } catch { /* ignore */ }
        res.writeHead(201); res.end("{}");
      });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { alerts, usage, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}

export function makeHome(consoleUrl, enrolled = true) {
  const home = mkdtempSync(join(tmpdir(), "moorai-gw-h-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true });
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: consoleUrl, tenant: TENANT, ...(enrolled ? { installToken: "tok" } : {}) }));
  return home;
}

// Server mode the way test/workload-profile-hook.test.mjs runs the hook: MOORAI_MODE=server + the
// MOORAI_* identity from the environment.
export const serverModeEnv = (consoleUrl, serviceId = "gw-svc") => ({ MOORAI_MODE: "server", MOORAI_SERVER_URL: consoleUrl, MOORAI_TENANT: TENANT, MOORAI_INSTALL_TOKEN: "tok", MOORAI_SERVICE_ID: serviceId });

export function startGateway({ home, consoleUrl, args, env = {}, cwd }) {
  const childEnv = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: consoleUrl, MoorAI_TENANT: TENANT };
  delete childEnv.MOORAI_MODE;
  Object.assign(childEnv, env);
  const child = spawn(process.execPath, [GATEWAY, ...args], { cwd: cwd || home, stdio: ["ignore", "pipe", "pipe"], env: childEnv });
  let stderr = "";
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ child, stderr, url: null, exitCode: "timeout" }), 10000);
    child.stderr.on("data", (c) => {
      stderr += c.toString();
      const m = stderr.match(/listening on (http:\/\/[^\s]+)/);
      if (m) { clearTimeout(timer); resolve({ child, get stderr() { return stderr; }, url: m[1].replace(/\/$/, ""), exitCode: null }); }
    });
    child.on("exit", (code) => { clearTimeout(timer); resolve({ child, stderr, url: null, exitCode: code }); });
  });
}

export function stopGateway(gw) {
  return new Promise((r) => {
    if (!gw || !gw.child || gw.child.exitCode != null) return r();
    gw.child.once("exit", () => r());
    try { gw.child.kill(); } catch { r(); }
  });
}

// One gateway over one fake upstream route "/remote" (server label "remote").
export async function scenario({ policy = null, upstream = {}, gatewayArgs = [], env = {}, enrolled = true, home: givenHome, con: givenCon }, fn) {
  const con = givenCon || await startConsole(policy ? sign(policy) : null);
  const home = givenHome || makeHome(con.url, enrolled);
  const up = await startUpstream(upstream);
  const gw = await startGateway({ home, consoleUrl: con.url, args: ["--port", "0", "--route", `/remote=${up.url}`, ...gatewayArgs], env: typeof env === "function" ? env(con.url) : env });
  try {
    if (!gw.url) throw new Error(`gateway did not start: exit=${gw.exitCode} stderr=${gw.stderr}`);
    await fn({ con, up, gw, base: `${gw.url}/remote`, home });
  } finally {
    await stopGateway(gw);
    await up.close();
    if (!givenCon) await con.close();
    if (!givenHome) rmSync(home, { recursive: true, force: true });
  }
}

export const H = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
export async function rpc(url, msg, headers = {}) {
  const r = await fetch(url, { method: "POST", headers: { ...H, ...headers }, body: typeof msg === "string" ? msg : JSON.stringify(msg) });
  const text = await r.text();
  return { status: r.status, headers: r.headers, text, json: (() => { try { return JSON.parse(text); } catch { return null; } })() };
}
export const call = (id, name, args = {}) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
export const settle = (ms = 600) => new Promise((r) => setTimeout(r, ms));
