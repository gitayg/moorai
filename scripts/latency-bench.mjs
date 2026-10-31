// Measures the benchmark's latency rows (rendered by scripts/latency.mjs). The in-process rows run in a
// child (scripts/latency-worker.mjs) with a sandboxed HOME; the hook rows spawn cli/moorai-hook.mjs once
// per call, interleaved with a bare `node -e ""` so both see the same machine state, and POST the same event to
// moorai-hookd (the HTTP transport, cli/moorai-hookd.mjs) in the same loop.
import { spawn } from "node:child_process";
import { rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { latencySandbox, sandboxEnv, toolCalls, envelope } from "./latency-workload.mjs";
import { latencyRow, machine } from "./latency.mjs";
import { createHookd } from "../cli/moorai-hookd.mjs";
import { envHeader } from "../cli/hook-http.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const WORKER = join(ROOT, "scripts", "latency-worker.mjs");

export const SCAN_WARMUP = 50;
export const DECIDE = { n: 2000, warmup: 200 };
export const HOOK_RUN = { n: 200, warmup: 5 };

export const LATENCY_ROWS = [
  ...["prompt", "file", "output"].map((stage) => ({ id: `scan-${stage}`, label: `In process: \`engine.scan\` at \`${stage}\``, sample: "one benign-corpus-v2 text", warmup: SCAN_WARMUP })),
  { id: "sdk-decide", label: "In process: Agent SDK tool-call decision", sample: "one `PreToolUse` from the ten-call mix", warmup: DECIDE.warmup },
  { id: "hook-e2e", label: "Process: hook end-to-end (`PreToolUse`)", sample: "spawn → stdin JSON → exit", warmup: HOOK_RUN.warmup },
  { id: "node-floor", label: "Process: Node startup floor (`node -e \"\"`)", sample: "spawn → exit, interleaved with the hook", warmup: HOOK_RUN.warmup },
  { id: "hook-http", label: "Process: hook over HTTP (`moorai-hookd`, `PreToolUse`)", sample: "POST → answer, warm worker, interleaved with the hook", warmup: HOOK_RUN.warmup }
];
const DEF = Object.fromEntries(LATENCY_ROWS.map((d) => [d.id, d]));

export function spawnTimed(args, { cwd, env, stdin = "" }) {
  return new Promise((resolve, reject) => {
    const t0 = process.hrtime.bigint();
    const c = spawn(process.execPath, args, { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (err += d));
    c.on("error", reject);
    c.on("close", (code) => resolve({ ms: Number(process.hrtime.bigint() - t0) / 1e6, code, out, err }));
    c.stdin.end(stdin);
  });
}

export function hookDecision(stdout) {
  const t = (stdout || "").trim();
  if (!t) return "allow";
  const o = JSON.parse(t);
  const h = o.hookSpecificOutput || {};
  if (h.permissionDecision) return h.permissionDecision;
  if (o.decision === "block") return "deny";
  return h.additionalContext ? "advise" : "allow";
}

// One POST to moorai-hookd as Claude Code sends it: the event as the body, CLAUDE_PROJECT_DIR in its header.
async function postTimed(hd, sb, event) {
  const t0 = process.hrtime.bigint();
  const r = await fetch(`${hd.url}/v1/hook/claude-code`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${hd.token}`, [envHeader("CLAUDE_PROJECT_DIR")]: sb.proj }, body: JSON.stringify(event) });
  const out = await r.text();
  return { ms: Number(process.hrtime.bigint() - t0) / 1e6, status: r.status, out };
}

// http: a running moorai-hookd ({ url, token }) to time alongside the hook, or null. The HTTP answer's decision
// must equal the hook's for the same event, or the run fails.
export async function measureHook(sb, { n, warmup }, { http = null } = {}) {
  const env = sandboxEnv(sb), calls = toolCalls(sb);
  const hook = [], floor = [], viaHttp = [], decisions = {};
  for (let i = -warmup; i < n; i++) {
    const k = i + warmup;
    const h = await spawnTimed([HOOK], { cwd: sb.proj, env, stdin: JSON.stringify(envelope(sb, calls[k % calls.length], k)) });
    if (h.code !== 0) throw new Error(`hook exited ${h.code}: ${h.err.slice(0, 500)}`);
    const f = await spawnTimed(["-e", ""], { cwd: sb.proj, env });
    if (f.code !== 0) throw new Error(`node -e "" exited ${f.code}`);
    const w = http ? await postTimed(http, sb, envelope(sb, calls[k % calls.length], k)) : null;
    if (w && (w.status !== 200 || hookDecision(w.out) !== hookDecision(h.out))) throw new Error(`moorai-hookd answered ${w.status} ${hookDecision(w.status === 200 ? w.out : "")} where the hook decided ${hookDecision(h.out)}`);
    if (i < 0) continue;
    hook.push(h.ms);
    floor.push(f.ms);
    if (w) viaHttp.push(w.ms);
    const d = hookDecision(h.out);
    decisions[d] = (decisions[d] || 0) + 1;
  }
  return { hook, floor, http: viaHttp, decisions };
}

export async function measureInProcess(sb, { scanWarmup, scanTexts = 0, decideN, decideWarmup }) {
  const cfg = JSON.stringify({ home: sb.home, proj: sb.proj, scanWarmup, scanTexts, decideN, decideWarmup });
  const r = await spawnTimed([WORKER, cfg], { cwd: ROOT, env: sandboxEnv(sb) });
  if (r.code !== 0) throw new Error(`latency worker exited ${r.code}: ${r.err.slice(0, 500)}`);
  return JSON.parse(r.out);
}

export async function measureLatency({ decide = DECIDE, hookRun = HOOK_RUN, scanWarmup = SCAN_WARMUP } = {}) {
  const sb = latencySandbox();
  try {
    const ip = await measureInProcess(sb, { scanWarmup, decideN: decide.n, decideWarmup: decide.warmup });
    const token = "latency-bench-hookd-token-0123456789";
    const { CLAUDE_PROJECT_DIR, ...daemonEnv } = sandboxEnv(sb);
    const hd = await createHookd({ port: 0, token, workers: 2, env: daemonEnv });
    let hk;
    try { await hd.pool.ready(); hk = await measureHook(sb, hookRun, { http: { url: hd.url, token } }); } finally { await hd.close(); }
    const rows = [
      ...["prompt", "file", "output"].map((s) => latencyRow(DEF[`scan-${s}`], ip.scan[s])),
      latencyRow(DEF["sdk-decide"], ip.decide),
      latencyRow(DEF["hook-e2e"], hk.hook),
      latencyRow(DEF["node-floor"], hk.floor),
      latencyRow(DEF["hook-http"], hk.http)
    ];
    return { measured: true, method: "nearest-rank", machine: machine(), rows, hookDecisions: hk.decisions, sdkDecisions: ip.decisions };
  } finally {
    rmSync(sb.home, { recursive: true, force: true });
  }
}
