// Shared by test/ingest*.test.mjs. ROOT can point at a copy of the repo (MOORAI_TEST_ROOT) so the same
// tests run against a deliberately broken tree.
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const ROOT = process.env.MOORAI_TEST_ROOT || join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const FIX = join(ROOT, "test", "fixtures", "ingest");
export const CC = join(FIX, "claude-code");
export const CODEX = join(FIX, "codex");
export const CLI = join(ROOT, "cli", "moorai-ingest.mjs");
export const load = (rel) => import(pathToFileURL(join(ROOT, rel)).href);

// Every distinctive piece of fixture content. None may appear in default output or in a reported alert.
export const NEEDLES = [
  "PLACEHOLDER", "placeholder", "AKIA", "ghp_", "/dev/tcp", "203.0.113.7", "example.invalid", "evil.invalid",
  "cat .env", "rm -rf", "install.sh", "ignore all previous", "/placeholder/project", "config.txt",
  "11111111-1111", "22222222-2222", "33333333-3333", "a0000000000000001"
];
export const leaks = (s) => NEEDLES.filter((n) => s.includes(n));

export function tempHome({ serverUrl = "http://127.0.0.1:9", token = "" } = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-ingest-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl, tenant: "acme", ...(token ? { installToken: token } : {}) }));
  return home;
}

export function writePolicy(home, policy) {
  const p = join(home, "policy.json");
  writeFileSync(p, JSON.stringify(policy));
  return p;
}

export function runCli(args, { home, cwd = ROOT } = {}) {
  return new Promise((resolve, reject) => {
    const c = spawn(process.execPath, [CLI, ...args], { cwd, env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, NO_COLOR: "1" }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("error", reject);
    c.on("close", (code) => resolve({ code, out, err }));
  });
}

// A console that serves one policy and records every posted alert body verbatim.
export function startConsole(policy = {}) {
  const bodies = [];
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); return res.end(); }
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify(policy)); }
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url.startsWith("/api/alerts")) bodies.push(b); res.writeHead(200); res.end("{}"); });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({
    url: `http://127.0.0.1:${srv.address().port}`, bodies, alerts: () => bodies.map((b) => JSON.parse(b)),
    close: () => new Promise((c) => { srv.closeAllConnections?.(); srv.close(c); })
  })));
}
