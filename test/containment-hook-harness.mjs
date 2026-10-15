// Shared harness for the MXC containment tests that drive the REAL hook subprocess
// (test/containment-enforce-hook.test.mjs, test/containment-hardening-hook.test.mjs). The hook is told it runs
// on Windows 11 26100 by a test-only preload (test/fixtures/fake-win32.mjs); the hook itself has no platform
// knob. reg.exe does not exist here, so a registry read gives an unknown UBR (mxcCapable null).
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const WIN = pathToFileURL(join(ROOT, "test", "fixtures", "fake-win32.mjs")).href;
const FAULT = pathToFileURL(join(ROOT, "test", "fixtures", "hook-fault.mjs")).href;
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export async function until(fn, ms = 6000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100); } return false; }

export async function consoleStub(t, { signed = null } = {}) {
  const st = { alerts: [], posture: [], down: false };
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/api/alerts") { try { st.alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); return res.end("{}"); }
      if (req.url === "/api/agent-posture") { try { st.posture.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(201); return res.end("{}"); }
      if (signed && !st.down && req.url.startsWith("/api/policy/pubkey")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(signed.pubkey); }
      if (signed && !st.down && req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(signed.policy()); }
      res.writeHead(503); res.end("offline");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => srv.close(r)));
  st.url = `http://127.0.0.1:${srv.address().port}`;
  return st;
}

export function sandbox(t, url, policy) {
  const home = mkdtempSync(join(tmpdir(), "moorai-contain-"));
  t.after(() => rmTree(home));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "ct-test", installToken: "tok-contain" }));
  if (policy) writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(policy));
  return home;
}

// host: "claude-code" | "codex" | "copilot". win: load the Windows preload. fault: load the fault preload.
// cwd: the payload's cwd (default: the sandbox).
export function run(home, payload, { host = "codex", win = true, fault = false, env = {}, cwd = home } = {}) {
  const base = { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state") };
  const hostEnv = host === "claude-code" ? {} : { MOORAI_HOOK_HOST: "shim", MOORAI_HOOK_AGENT: host };
  const args = [...(win ? ["--import", WIN] : []), ...(fault ? ["--import", FAULT] : []), HOOK];
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, { env: { ...base, ...hostEnv, ...env }, cwd: home, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(JSON.stringify({ session_id: "s-contain", cwd, hook_event_name: "PreToolUse", ...payload }));
  });
}
export const BASH = (command, extra = {}) => ({ tool_name: "Bash", tool_input: { command, ...extra } });
export const out = (stdout) => { try { return JSON.parse(stdout.trim()); } catch { return {}; } };
export const hso = (stdout) => out(stdout).hookSpecificOutput || {};
export const lastRow = (home) => readFileSync(join(home, ".moorai", "session-ledger.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l)).at(-1);
export const containAlerts = (st) => st.alerts.filter((a) => String(a.reasonCode || "").startsWith("CONTAINMENT_"));

// The success path, end to end on macOS: every Windows path the wrap uses is a RELATIVE name with
// backslashes, which on a POSIX filesystem is one flat file name in the hook's cwd (the sandbox). So
// existsSync("C:\\Program Files\\Microsoft MXC\\wxc-exec.exe") finds a file the test created, and the
// config is written next to it. Nothing here runs wxc-exec.
export function fakeWindowsTree(home) {
  const f = (name, dir = false) => { const p = join(home, name); if (dir) mkdirSync(p, { recursive: true }); else writeFileSync(p, ""); };
  f("C:\\Program Files\\Microsoft MXC\\wxc-exec.exe");
  f("C:\\Program Files\\Git\\bin\\bash.exe");
  f("C:\\Program Files\\Git", true);
  f("C:\\src\\proj", true);
  return {
    ProgramFiles: "C:\\Program Files", PATH: `${process.env.PATH};C:\\Program Files\\Microsoft MXC`, LOCALAPPDATA: "C:\\Users\\dev\\AppData\\Local",
    APPDATA: "C:\\Users\\dev\\AppData\\Roaming", SystemRoot: "C:\\Windows", ProgramData: "C:\\ProgramData", CLAUDE_PROJECT_DIR: "C:\\src\\proj"
  };
}
export const configsIn = (home) => readdirSync(home).filter((n) => /MoorAI Host\\wrap\\wrap-[0-9a-f]{32}\.json$/.test(n));
export const WXC_FWD = "C:/Program Files/Microsoft MXC/wxc-exec.exe";
export const wrapCfgName = (c) => `C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\wrap\\wrap-${c.repeat(32)}.json`;
// The wrapped form outerCommand produces (v1.18.2), hand-built.
export const wrappedForm = (display, cfg) => `__moorai_show='${display}'; MSYS_NO_PATHCONV=1 '${WXC_FWD}' --config '${cfg}'`;
// The v1.18.0/1 form, which is no longer recognised as MoorAI's.
export const legacyWrappedForm = (display, cfg) => `: '${display}' ; MSYS_NO_PATHCONV=1 '${WXC_FWD}' --config '${cfg}'`;
