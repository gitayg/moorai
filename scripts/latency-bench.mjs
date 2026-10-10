// Measures the benchmark's latency rows (rendered by scripts/latency.mjs). The in-process rows run in a
// child (scripts/latency-worker.mjs) with a sandboxed HOME; the hook rows spawn cli/moorai-hook.mjs once
// per call, interleaved with a bare `node -e ""` so both see the same machine state.
import { spawn } from "node:child_process";
import { rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { latencySandbox, sandboxEnv, toolCalls, envelope } from "./latency-workload.mjs";
import { latencyRow, machine } from "./latency.mjs";

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
  { id: "node-floor", label: "Process: Node startup floor (`node -e \"\"`)", sample: "spawn → exit, interleaved with the hook", warmup: HOOK_RUN.warmup }
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

export async function measureHook(sb, { n, warmup }) {
  const env = sandboxEnv(sb), calls = toolCalls(sb);
  const hook = [], floor = [], decisions = {};
  for (let i = -warmup; i < n; i++) {
    const k = i + warmup;
    const h = await spawnTimed([HOOK], { cwd: sb.proj, env, stdin: JSON.stringify(envelope(sb, calls[k % calls.length], k)) });
    if (h.code !== 0) throw new Error(`hook exited ${h.code}: ${h.err.slice(0, 500)}`);
    const f = await spawnTimed(["-e", ""], { cwd: sb.proj, env });
    if (f.code !== 0) throw new Error(`node -e "" exited ${f.code}`);
    if (i < 0) continue;
    hook.push(h.ms);
    floor.push(f.ms);
    const d = hookDecision(h.out);
    decisions[d] = (decisions[d] || 0) + 1;
  }
  return { hook, floor, decisions };
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
    const hk = await measureHook(sb, hookRun);
    const rows = [
      ...["prompt", "file", "output"].map((s) => latencyRow(DEF[`scan-${s}`], ip.scan[s])),
      latencyRow(DEF["sdk-decide"], ip.decide),
      latencyRow(DEF["hook-e2e"], hk.hook),
      latencyRow(DEF["node-floor"], hk.floor)
    ];
    return { measured: true, method: "nearest-rank", machine: machine(), rows, hookDecisions: hk.decisions, sdkDecisions: ip.decisions };
  } finally {
    rmSync(sb.home, { recursive: true, force: true });
  }
}
