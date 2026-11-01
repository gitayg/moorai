#!/usr/bin/env node
// Measures the `latency` block of docs/accuracy-measurements.json, the hook figures the moorai.dev
// accuracy page vendors.
//
//   node scripts/accuracy-latency.mjs [dir] [--runs N] [--commit <sha>] [--write]
//
// dir is the checkout to measure (default: this repository; a clean `git archive` of the release
// commit is what the published block is measured on). Each run is its own Node process: the engine,
// then the hook, on a fresh sandboxed HOME. The block is printed; --write puts it under `latency` in
// this repository's docs/accuracy-measurements.json and changes nothing else in that file.
//
// engine: decideText at stage prompt, in process, warm (one unrecorded pass), 5 passes over the 610
// benign samples. hook: one `node cli/moorai-hook.mjs` process per event, unenrolled, sandboxed HOME:
// a UserPromptSubmit per benign sample and 200 PreToolUse Bash calls with ordinary commands, after 5
// unrecorded warm-up events; a bare `node -e ""` start is timed between events as the floor.
// Percentiles are nearest-rank (scripts/latency.mjs).
import { spawn, execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS = "test/redteam/benign-corpus-v2.json";
const SELF = fileURLToPath(import.meta.url);

const args = process.argv.slice(2);
const flag = (name) => { const i = args.indexOf(name); if (i < 0) return null; const v = args[i + 1]; args.splice(i, 2); return v; };
const runOnce = args.includes("--run-once"); if (runOnce) args.splice(args.indexOf("--run-once"), 1);
const write = args.includes("--write"); if (write) args.splice(args.indexOf("--write"), 1);
const RUNS = Number(flag("--runs") ?? 2);
const commitArg = flag("--commit");
const DIR = resolve(args[0] ?? REPO);

const pct = (s, p) => s[Math.min(s.length, Math.max(1, Math.ceil(p * s.length))) - 1];
const stats = (v) => { const s = [...v].sort((a, b) => a - b); const r = (x) => +x.toFixed(2); return { n: s.length, p50: r(pct(s, .5)), p95: r(pct(s, .95)), p99: r(pct(s, .99)) }; };

function spawnTimed(argv, env, cwd, stdin = "") {
  return new Promise((res, rej) => {
    const t0 = process.hrtime.bigint();
    const c = spawn(process.execPath, argv, { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
    c.stdout.on("data", () => {}); c.stderr.on("data", () => {}); c.on("error", rej);
    c.on("close", (code) => res({ ms: Number(process.hrtime.bigint() - t0) / 1e6, code }));
    c.stdin.end(stdin);
  });
}

async function measureRun() {
  const { DETECTORS } = await import(join(DIR, "data/detectors.js"));
  const { CONTENT_RULES } = await import(join(DIR, "data/content-rules.js"));
  const { DetectionEngine } = await import(join(DIR, "src/engine.js"));
  const { decideText } = await import(join(DIR, "cli/hook-core.mjs"));
  const threats = JSON.parse(readFileSync(join(DIR, "data/threats.json"), "utf8"));
  const benign = JSON.parse(readFileSync(join(DIR, CORPUS), "utf8")).benign;
  const POLICY = Object.freeze({ captureTier: "content-free", builtinDefault: true });

  const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);
  for (const b of benign) decideText(engine, POLICY, b.text, "prompt");
  const eng = [];
  for (let pass = 0; pass < 5; pass++) for (const b of benign) {
    const t0 = process.hrtime.bigint(); decideText(engine, POLICY, b.text, "prompt");
    eng.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }

  const home = mkdtempSync(join(os.tmpdir(), "acc-lat-"));
  const proj = join(home, "proj"); mkdirSync(proj, { recursive: true }); mkdirSync(join(home, ".moorai"));
  const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local/state"), CLAUDE_PROJECT_DIR: proj };
  const HOOK = join(DIR, "cli/moorai-hook.mjs");
  const BASH = ["ls -la", "git status --short", "git log --oneline -5", "npm test", "npm run build", "node --version", "cat package.json", "pwd", "git diff --stat", "grep -rn TODO src",
    "mkdir -p dist", "cp README.md /tmp/readme.bak", "python3 -m pytest -q", "make", "wc -l src/*.js", "head -20 README.md", "npx tsc --noEmit", "git branch -a", "echo hello", "find . -name '*.md' -maxdepth 2"];
  const ev = (o, i) => JSON.stringify({ session_id: `acc-lat-${Math.floor(i / 50)}`, transcript_path: "", cwd: proj, permission_mode: "default", ...o });
  const prompt = [], bash = [], floor = []; let nonzero = 0;
  for (let i = -5; i < benign.length; i++) {
    const b = benign[(i + benign.length) % benign.length];
    const h = await spawnTimed([HOOK], env, proj, ev({ hook_event_name: "UserPromptSubmit", prompt: b.text }, i));
    const f = await spawnTimed(["-e", ""], env, proj);
    let bh = null;
    if (i < 200) bh = await spawnTimed([HOOK], env, proj, ev({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: BASH[(i + 20) % BASH.length] }, tool_use_id: `tu-${i}` }, i));
    if (i < 0) continue;
    if (h.code !== 0 && h.code !== 2) nonzero++;
    if (bh && bh.code !== 0 && bh.code !== 2) nonzero++;
    prompt.push(h.ms); floor.push(f.ms); if (bh) bash.push(bh.ms);
  }
  rmSync(home, { recursive: true, force: true });
  return { samples: benign.length, nonzero, floor, run: { engine: stats(eng), hookPrompt: stats(prompt), hookBash: stats(bash) } };
}

function childRun() {
  return new Promise((res, rej) => {
    let out = "";
    const c = spawn(process.execPath, [SELF, DIR, "--run-once"], { stdio: ["ignore", "pipe", "inherit"] });
    c.stdout.on("data", (d) => (out += d)); c.on("error", rej);
    c.on("close", (code) => (code === 0 ? res(JSON.parse(out)) : rej(new Error(`run exited ${code}`))));
  });
}

function machine() {
  const mac = process.platform === "darwin" ? `macOS ${execFileSync("sw_vers", ["-productVersion"], { encoding: "utf8" }).trim()}` : `${os.type()} ${os.release()}`;
  return `${os.cpus()[0].model}, ${os.cpus().length} cores, ${Math.round(os.totalmem() / 2 ** 30)} GB, ${mac}, Node ${process.version}`;
}

function headCommit() {
  try { return execFileSync("git", ["-C", DIR, "rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { return null; }
}

if (runOnce) {
  process.stdout.write(JSON.stringify(await measureRun()));
} else {
  const loads = [os.loadavg()[0]], runs = [], floor = []; let nonzero = 0, samples = 0;
  const sampler = setInterval(() => loads.push(os.loadavg()[0]), 30_000);
  for (let r = 0; r < RUNS; r++) {
    const one = await childRun();
    runs.push(one.run); floor.push(...one.floor); nonzero += one.nonzero; samples = one.samples;
    process.stderr.write(`run ${r + 1}/${RUNS}: ${JSON.stringify(one.run)}\n`);
  }
  clearInterval(sampler); loads.push(os.loadavg()[0]);
  if (nonzero) { console.error(`${nonzero} hook events exited with a code other than 0 or 2; nothing written`); process.exit(1); }
  const fl = stats(floor);
  const lo = Math.min(...loads).toFixed(1), hi = Math.max(...loads).toFixed(1);
  const block = {
    corpus: CORPUS,
    machine: machine(),
    load: `1-minute load average ${lo} to ${hi}, sampled every 30 s across the ${RUNS} runs`,
    method: `engine: decideText at stage prompt, in process, warm (one unrecorded pass), 5 passes over the ${samples} benign samples. hook: one \`node cli/moorai-hook.mjs\` process per event, the command transport a real agent invokes (moorai-hookd is the optional HTTP transport, not measured here), unenrolled, sandboxed HOME: a UserPromptSubmit per benign sample, and 200 PreToolUse Bash calls with ordinary commands, after 5 unrecorded warm-up events. Node start floor: a bare \`node -e ""\` timed between hook events, pooled over the runs. Each run is its own process on a fresh HOME; percentiles are nearest-rank. Harness: scripts/accuracy-latency.mjs (npm run accuracy-latency).`,
    nodeStartP50: +fl.p50.toFixed(1),
    nodeStartP95: +fl.p95.toFixed(1),
    runs,
    measuredAt: {
      version: JSON.parse(readFileSync(join(DIR, "package.json"), "utf8")).version,
      commit: commitArg ?? headCommit(),
      measured: new Date().toISOString().slice(0, 10)
    }
  };
  console.log(JSON.stringify(block, null, 2));
  if (write) {
    const file = join(REPO, "docs/accuracy-measurements.json");
    const doc = JSON.parse(readFileSync(file, "utf8"));
    doc.latency = block;
    writeFileSync(file, JSON.stringify(doc, null, 1) + "\n");
    console.error(`wrote latency to ${file}`);
  }
}
