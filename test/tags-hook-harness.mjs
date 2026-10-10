// Shared harness for the capability-tag and exception hook tests: a local console that serves the policy
// and collects alerts, a throwaway HOME, and one real hook process per call.
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");

export async function withConsole(policy, fn, { token = "tok-tags", userConfigExtra = {} } = {}) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); return res.end(); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify(policy)); }
      if (req.method === "POST") { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); return res.end("{}"); }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const home = mkdtempSync(join(tmpdir(), "moorai-tags-"));
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(proj, ".env"), "APP_MODE=dev\n");
  writeFileSync(join(proj, "README.md"), "# readme\n");
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${srv.address().port}`, tenant: "tags", ...(token ? { installToken: token } : {}), ...userConfigExtra }));
  writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(policy));
  try { return await fn({ home, proj, alerts }); } finally { srv.close(); rmTree(home); }
}
export function runHook({ home, proj }, session, tool_name, tool_input, { env = {} } = {}) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [HOOK], { cwd: proj, env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), ...env } });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("error", rej);
    c.on("close", (status) => {
      if (status !== 0) return rej(new Error(`hook exit ${status}: ${err}`));
      const t = out.trim(); const o = t ? JSON.parse(t) : {};
      res({ decision: o.hookSpecificOutput?.permissionDecision || "allow", reason: o.hookSpecificOutput?.permissionDecisionReason || "", raw: o });
    });
    c.stdin.end(JSON.stringify({ hook_event_name: "PreToolUse", session_id: session, tool_name, tool_input, cwd: proj, tool_use_id: "tu", transcript_path: "", permission_mode: "default" }));
  });
}
