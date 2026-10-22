#!/usr/bin/env node
// Live host-conformance tier: drive each INSTALLED agent host and MCP client against MoorAI's hook and
// MCP guard, and write one signed, content-free conformance report per host version.
//
//   node scripts/host-conformance.mjs                       plan only: what would run, nothing is started
//   node scripts/host-conformance.mjs --live [options]      run it
//   node scripts/host-conformance.mjs --verify <report.json> [--pub <base64 spki>]
//
//   --host <id>         limit to these targets (repeatable; default all)
//   --cases a,b         Claude Code cases to run (default all: shell-allow, shell-deny, prompt-block,
//                       mcp-allow, mcp-deny)
//   --bin <id>=<path>   use this binary for a host instead of the one on PATH
//   --out-dir <dir>     where reports go (default ./conformance-out); one file per target: <id>-<version>.json
//   --key <path>        ed25519 signing key (PEM; created 0600 if absent). Without it an ephemeral key signs
//                       the run and the report says signature.ephemeral true.
//   --no-sandbox        do not wrap hosts in sandbox-exec (macOS)
//   --timeout-ms <n>    per host turn (default 180000)
//
// No model provider is called and no key is read. Claude Code talks to a scripted Anthropic endpoint on
// loopback (scripts/conformance/scripted-anthropic.mjs). Every host runs in a throwaway HOME, enrolled to
// a loopback stand-in console. On macOS hosts run under sandbox-exec, which denies outbound connections
// other than localhost and writes to the real ~/.claude.json, ~/.claude and ~/.cursor.
//
// Targets: claude-code (agent turns + MCP client), cursor (MCP client handshake; agent turn needs a Cursor
// account), codex, copilot, gemini, droid (recorded as installed or not; no driver without a vendor key),
// claude-desktop, vscode, cursor-desktop (GUI apps: recorded, never launched).
// Exit 1 when any case that ran failed; a target that did not run is recorded with its reason, not failed.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, existsSync, realpathSync, rmSync, accessSync, constants } from "node:fs";
import { tmpdir, platform, arch } from "node:os";
import { join, dirname, delimiter } from "node:path";
import { fileURLToPath } from "node:url";
import { HOST_REPORT_TYPE, buildReport, signReport, verifyReport, loadOrCreateKey, ephemeralKey } from "../cli/conformance-report.mjs";
import { loadManifest, parseVersion, cleanVersion } from "../cli/agent-hooks/host-version.mjs";
import { desktopTargets } from "./conformance/desktop-clients.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MOORAI = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;
export const HOST_ORDER = ["claude-code", "cursor", "codex", "copilot", "gemini", "droid"];
export const DESKTOP_IDS = ["claude-desktop", "vscode", "cursor-desktop"];

function which(bin, env = process.env) {
  for (const d of String(env.PATH || "").split(delimiter)) {
    if (!d) continue;
    const p = join(d, bin);
    try { accessSync(p, constants.X_OK); return p; } catch { /* next */ }
  }
  return null;
}
function versionOf(bin) {
  const r = spawnSync(bin, ["--version"], { encoding: "utf8", timeout: 30000, input: "" });
  return r.status === 0 ? cleanVersion(parseVersion(r.stdout)) : null;
}

export function parseArgs(argv) {
  const a = { live: false, hosts: [], cases: null, bins: {}, outDir: "conformance-out", key: null, sandbox: true, timeoutMs: 180000, verify: null, pub: null };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === "--live") a.live = true;
    else if (k === "--host") a.hosts.push(argv[++i]);
    else if (k === "--cases") a.cases = String(argv[++i]).split(",").map((s) => s.trim()).filter(Boolean);
    else if (k === "--bin") { const s = String(argv[++i]); const at = s.indexOf("="); a.bins[s.slice(0, at)] = s.slice(at + 1); }
    else if (k === "--out-dir") a.outDir = argv[++i];
    else if (k === "--key") a.key = argv[++i];
    else if (k === "--no-sandbox") a.sandbox = false;
    else if (k === "--timeout-ms") a.timeoutMs = Number(argv[++i]);
    else if (k === "--verify") a.verify = argv[++i];
    else if (k === "--pub") a.pub = argv[++i];
    else throw new Error(`unknown argument ${k}`);
  }
  return a;
}

const sandboxAvailable = () => process.platform === "darwin" && existsSync("/usr/bin/sandbox-exec");

async function hostTarget(id, m, a, scratch) {
  const bin = a.bins[id] || (m.bin && which(m.bin));
  const base = { kind: "host", id, label: m.label || id, tested: m.tested || null, model: "none", cases: [] };
  if (!bin) return { ...base, ran: false, reason: "not-installed" };
  const version = versionOf(bin);
  const sandboxed = a.sandbox && sandboxAvailable();
  if (id === "claude-code") {
    const { CLAUDE_CASES, runClaudeCase } = await import("./conformance/claude-code.mjs");
    const defs = CLAUDE_CASES.filter((c) => !a.cases || a.cases.includes(c.id));
    const cases = [];
    for (const def of defs) cases.push(await runClaudeCase(def, { bin, scratch, sandbox: sandboxed, timeoutMs: a.timeoutMs }));
    return { ...base, version, ran: true, sandboxed, model: "scripted", cases };
  }
  if (id === "cursor") {
    if (!sandboxed) process.env.MOORAI_LIVE_NO_SANDBOX = "1";
    const live = await import("../mcp-gateway/test/live/live-clients.mjs");
    const { checkCursorBundle } = await import("./host-drift.mjs");
    const { runCursor } = await import("./conformance/cursor.mjs");
    const r = await runCursor({ bin, scratch, live, checkCursorBundle });
    return { ...base, version, ran: true, sandboxed: live.SANDBOX, reason: r.reason, cases: r.cases };
  }
  return { ...base, version, ran: false, reason: "no-live-tier" };
}

function plan(a, manifest) {
  const lines = ["host-conformance: plan only (pass --live to run; nothing was started)"];
  for (const id of HOST_ORDER.filter((h) => !a.hosts.length || a.hosts.includes(h))) {
    const m = manifest.hosts[id] || {};
    const bin = a.bins[id] || (m.bin && which(m.bin));
    const what = id === "claude-code" ? "agent turns against a scripted Anthropic endpoint + MCP tool calls through the stdio guard"
      : id === "cursor" ? "MCP client handshake through the stdio guard; agent turn probe (needs a Cursor account)"
      : "recorded only (no driver without a vendor key)";
    lines.push(`  ${id.padEnd(15)} ${bin ? "installed" : "not installed"}  ${what}`);
  }
  for (const t of desktopTargets()) if (!a.hosts.length || a.hosts.includes(t.id)) lines.push(`  ${t.id.padEnd(15)} ${t.reason === "not-installed" ? "not installed" : "installed"}  recorded only (GUI app, never launched)`);
  return lines.join("\n") + "\n";
}

export async function run(argv) {
  const a = parseArgs(argv);
  if (a.verify) {
    const r = verifyReport(JSON.parse(readFileSync(a.verify, "utf8")), { pub: a.pub });
    return { code: r.ok ? 0 : 1, out: JSON.stringify(r) + "\n" };
  }
  const manifest = loadManifest();
  if (!a.live) return { code: 0, out: plan(a, manifest) };
  const key = a.key ? loadOrCreateKey(a.key) : ephemeralKey();
  const scratch = mkdtempSync(join(tmpdir(), "moorai-host-conformance-"));
  mkdirSync(a.outDir, { recursive: true });
  const targets = [];
  try {
    for (const id of HOST_ORDER.filter((h) => !a.hosts.length || a.hosts.includes(h))) targets.push(await hostTarget(id, manifest.hosts[id] || {}, a, scratch));
    for (const t of desktopTargets()) if (!a.hosts.length || a.hosts.includes(t.id)) targets.push(t);
  } finally { rmSync(scratch, { recursive: true, force: true }); }
  const lines = [];
  let failed = false;
  for (const t of targets) {
    const rep = signReport(buildReport({ type: HOST_REPORT_TYPE, targets: [t], moorai: MOORAI, platform: { os: platform(), arch: arch(), node: process.versions.node } }), key, { ephemeral: !a.key });
    const file = join(a.outDir, `${rep.targets[0].id}-${rep.targets[0].version || "unknown"}.json`);
    writeFileSync(file, JSON.stringify(rep, null, 2) + "\n");
    const c = rep.targets[0].cases;
    if (c.some((x) => x.status === "fail")) failed = true;
    lines.push(`${rep.targets[0].id.padEnd(15)} ${String(rep.targets[0].version || "-").padEnd(20)} ${rep.targets[0].ran ? "ran" : "not run"}${rep.targets[0].reason ? ` (${rep.targets[0].reason})` : ""}  ${c.map((x) => `${x.id}:${x.status}`).join(" ")}`);
  }
  return { code: failed ? 1 : 0, out: lines.join("\n") + "\n" };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === realpathSync(process.argv[1])) {
  run(process.argv.slice(2)).then(({ code, out }) => { process.stdout.write(out); process.exit(code); }, (e) => { process.stderr.write(`host-conformance: ${e && e.stack || e}\n`); process.exit(2); });
}
