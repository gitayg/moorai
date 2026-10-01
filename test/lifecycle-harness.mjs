// Shared harness for test/provenance*.test.mjs and test/lifecycle*.test.mjs: a stub console that serves
// one policy and records every alert, a sandbox HOME, and a runner for the real hook process.
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = process.env.MOORAI_TEST_ROOT || join(dirname(fileURLToPath(import.meta.url)), "..");
export const HOOK = join(ROOT, "cli", "moorai-hook.mjs");

export function startConsole(policy) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify(policy)); }
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url.startsWith("/api/alerts")) { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } } res.writeHead(200); res.end("{}"); });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ srv, port: srv.address().port, alerts, close: () => new Promise((c) => srv.close(c)) })));
}

export function sandbox({ port, enrolled = true, tag = "lc" } = {}) {
  const home = mkdtempSync(join(tmpdir(), `moorai-${tag}-home-`));
  const proj = mkdtempSync(join(tmpdir(), `moorai-${tag}-proj-`));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({
    serverUrl: port ? `http://127.0.0.1:${port}` : "http://127.0.0.1:1",
    tenant: "acme",
    ...(enrolled ? { installToken: `tok-${tag}-test` } : {})
  }));
  return { home, proj };
}

export function runHook(sb, payload, { env = {}, args = [] } = {}) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [HOOK, ...args], { cwd: sb.proj, env: { ...process.env, HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "", ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (err += d));
    c.on("close", (code) => resolve({ code, out, err, json: out.trim().startsWith("{") ? JSON.parse(out) : null }));
    c.stdin.end(typeof payload === "string" ? payload : JSON.stringify({ session_id: "sess-lc", transcript_path: "/tmp/t.jsonl", cwd: sb.proj, ...payload }));
  });
}

function jsonl(p) { try { return readFileSync(p, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; } }
export const ledger = (sb) => jsonl(join(sb.home, ".moorai", "session-ledger.jsonl"));
export const audit = (sb) => jsonl(join(sb.home, ".moorai", "action-audit.jsonl"));
export const rawLedger = (sb) => { try { return readFileSync(join(sb.home, ".moorai", "session-ledger.jsonl"), "utf8"); } catch { return ""; } };
export const settle = (ms = 250) => new Promise((r) => setTimeout(r, ms));
