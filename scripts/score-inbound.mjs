#!/usr/bin/env node
// INBOUND content scorer: how each surface that judges content arriving INTO the agent treats attacks
// (an instruction aimed at the agent, a live payload) and benign content (pages, tickets, documents, real
// README / package.json / source files).
//
//   node scripts/score-inbound.mjs                              # tune split, every path, text report
//   node scripts/score-inbound.mjs --path sdk,gateway --json
//   node scripts/score-inbound.mjs --real <dir> [--real <dir>]  # add node_modules files of these trees
//   node scripts/score-inbound.mjs --errors                     # tune-split ids that were missed / flagged
//   node scripts/score-inbound.mjs --split locked --i-am-scoring-the-locked-split [--rows out.json]
//
// PATHS. Each one is the surface's own code, not a re-implementation:
//   hook     the real cli/moorai-hook.mjs, spawned with a PostToolUse payload (WebFetch for web content,
//            an mcp__ tool otherwise); findings read off the alert POSTs, the decision off stdout
//   sdk      @moorai/agent-sdk's PostToolUse callback in process, the result as MCP content blocks
//            (a string for web content); findings read off the reporter
//   gateway  the MCP proxy / HTTP gateway result scan: cli/inbound.mjs inboundText + decideInbound at the
//            "file" stage, the two calls both surfaces make (resultScanText + decideText before v1.4.0)
// The policy is the no-policy baseline (builtin defaults) on every path.
//
// WHAT IS COUNTED. A finding is ALERT-level unless it is reported at riskLevel "Info" (the level the
// inbound data-class findings are reported at, docs/DETECTION_ENGINE.md §7). An attack is DETECTED when an
// alert-level injection finding (#3, #40, #50, #60) or the sample's own expected threat is reported, and FLAGGED when the decision is not
// allow. A benign sample is a false positive on the same terms. Content-free: ids, threat ids, counts.
//
// THE SPLIT is scripts/inbound-corpus.mjs's; only the tune half's errors may be printed.
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { repoSamples, realSamples, splitHash } from "./inbound-corpus.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
export const INJECTION_THREATS = new Set([3, 40, 50, 60]);
const POLICY = { captureTier: "content-free", builtinDefault: true };

export function parseArgs(argv) {
  const vals = (f) => argv.flatMap((a, i) => (a === f && argv[i + 1] ? [argv[i + 1]] : []));
  const val = (f) => vals(f)[0];
  return {
    json: argv.includes("--json"),
    errors: argv.includes("--errors"),
    split: val("--split") || "tune",
    unlock: argv.includes("--i-am-scoring-the-locked-split"),
    paths: (val("--path") || "hook,sdk,gateway").split(",").filter(Boolean),
    real: vals("--real"),
    rows: val("--rows"),
    concurrency: Number(val("--concurrency") || 8)
  };
}

// ---- the three paths -------------------------------------------------------------------------------

function startServer() {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url.startsWith("/api/policy")) { res.writeHead(404); return res.end("{}"); }
      if (req.url.startsWith("/api/alerts")) { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } }
      res.writeHead(200); res.end("{}");
    });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ srv, port: srv.address().port, alerts })));
}
function runHook(home, stdin) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const c = spawn(process.execPath, [HOOK], { cwd: home, env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", () => {});
    c.on("close", () => resolve({ ms: Number(process.hrtime.bigint() - t0) / 1e6, out }));
    c.stdin.end(stdin);
  });
}
function hookDecision(stdout) {
  const t = (stdout || "").trim();
  if (!t) return "allow";
  try { const o = JSON.parse(t); if (o.decision === "block") return "deny"; if (o.hookSpecificOutput?.additionalContext) return "ask"; } catch { /* fall through */ }
  return "allow";
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function hookPath(s) {
  const { srv, port, alerts } = await startServer();
  const home = mkdtempSync(join(tmpdir(), "moorai-inbound-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "inbound", installToken: "tok-inbound" }));
  const web = s.door === "web";
  const payload = { hook_event_name: "PostToolUse", session_id: "inbound", tool_use_id: "toolu_inbound",
    tool_name: web ? "WebFetch" : "mcp__docs__get_document",
    tool_input: web ? { url: "https://docs.example.com/p", prompt: "Summarise this page" } : { id: "doc-1" },
    tool_response: web ? s.text : [{ type: "text", text: s.text }] };
  const r = await runHook(home, JSON.stringify(payload));
  await sleep(300);
  srv.close();
  const findings = alerts.filter((a) => a.stage === "output" && a.threatId > 0).map((a) => ({ threatId: a.threatId, riskLevel: a.riskLevel }));
  return { decision: hookDecision(r.out), findings, ms: r.ms };
}

let SDK = null;
async function sdkPath(s) {
  if (!SDK) {
    const { moorAIHooks } = await import("../packages/agent-sdk/src/index.mjs");
    const sink = [];
    const reporter = { post: (a) => { sink.push(a); return null; }, flush: async () => {}, enrolled: true };
    SDK = { hooks: moorAIHooks({ policy: POLICY, reporter, serviceId: "inbound-score", toolResults: "advise" }), sink };
  }
  SDK.sink.length = 0;
  const web = s.door === "web";
  const t0 = process.hrtime.bigint();
  const out = await SDK.hooks.PostToolUse[0].hooks[0]({ hook_event_name: "PostToolUse", tool_name: web ? "WebFetch" : "mcp__docs__get_document", tool_input: {}, tool_response: web ? s.text : [{ type: "text", text: s.text }] });
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const findings = SDK.sink.filter((a) => a.threatId > 0).map((a) => ({ threatId: a.threatId, riskLevel: a.riskLevel }));
  // toolResults "advise": a result whose configured verdict is not allow comes back as additionalContext.
  return { decision: out && out.hookSpecificOutput && out.hookSpecificOutput.additionalContext ? "ask" : "allow", findings, ms };
}

let GW = null;
async function gatewayPath(s) {
  if (!GW) {
    const core = await import("../cli/hook-core.mjs");
    const ts = await import("../mcp-proxy/tool-scan.mjs");
    let inbound = null;
    try { inbound = await import("../cli/inbound.mjs"); } catch { /* before the shared module existed */ }
    GW = { engine: core.buildEngine(POLICY), core, ts, inbound };
  }
  const t0 = process.hrtime.bigint();
  const result = { content: [{ type: "text", text: s.text }] };
  const text = GW.inbound ? GW.inbound.inboundText(result) : GW.ts.resultScanText(result);
  const d = GW.inbound ? GW.inbound.decideInbound(GW.engine, POLICY, text, { surface: "mcp", stage: "file" }) : GW.core.decideText(GW.engine, POLICY, text, "file");
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  return { decision: d.decision, findings: d.findings.filter((f) => f.threatId > 0).map((f) => ({ threatId: f.threatId, riskLevel: f.riskLevel })), ms };
}

const PATHS = { hook: hookPath, sdk: sdkPath, gateway: gatewayPath };

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => { for (;;) { const i = next++; if (i >= items.length) return; out[i] = await fn(items[i]); } };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return out;
}

// ---- reducers --------------------------------------------------------------------------------------

const alertLevel = (f) => f.riskLevel !== "Info";
export function rowOf(s, r) {
  const alerts = r.findings.filter(alertLevel);
  return {
    corpus: s.corpus, id: s.id, kind: s.kind, channel: s.channel, door: s.door,
    decision: r.decision, ms: r.ms,
    injection: alerts.some((f) => INJECTION_THREATS.has(f.threatId) || (s.kind === "attack" && f.threatId === s.expect)),
    alerted: alerts.length > 0,
    alertThreats: [...new Set(alerts.map((f) => f.threatId))].sort((a, b) => a - b),
    infoThreats: [...new Set(r.findings.filter((f) => !alertLevel(f)).map((f) => f.threatId))].sort((a, b) => a - b),
    anyThreats: [...new Set(r.findings.map((f) => f.threatId))].sort((a, b) => a - b)
  };
}
const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : "-");
export function summarise(rows) {
  const by = (pred) => rows.filter(pred);
  const groups = { "injection (v2+v5+atlas+web)": (r) => ["vector2", "vector5", "atlas", "web"].includes(r.corpus), "vector3 file/index/output": (r) => r.corpus === "vector3" };
  const out = { attacks: {}, benign: {}, perThreatBenign: {}, perThreatAttack: {}, latency: {} };
  for (const [g, pred] of Object.entries(groups)) {
    const a = by((r) => pred(r) && r.kind === "attack");
    const b = by((r) => pred(r) && r.kind === "benign");
    const tp = a.filter((r) => r.injection).length, fp = b.filter((r) => r.injection).length;
    out.attacks[g] = { n: a.length, injectionDetected: tp, recall: pct(tp, a.length), anyAlert: a.filter((r) => r.alerted).length, flagged: a.filter((r) => r.decision !== "allow").length,
      benignN: b.length, benignInjectionFp: fp, precision: pct(tp, tp + fp) };
  }
  const benignSets = { web: (r) => r.corpus === "web", "vector2/3/5+atlas benign": (r) => ["vector2", "vector3", "vector5", "atlas"].includes(r.corpus), "benign-v2 as inbound": (r) => r.corpus === "benign-v2", "real node_modules files": (r) => r.corpus === "real" };
  for (const [g, pred] of Object.entries(benignSets)) {
    const b = by((r) => pred(r) && r.kind === "benign");
    if (!b.length) continue;
    out.benign[g] = { n: b.length, anyAlert: b.filter((r) => r.alerted).length, anyAlertRate: pct(b.filter((r) => r.alerted).length, b.length), injectionFp: b.filter((r) => r.injection).length, nonAllow: b.filter((r) => r.decision !== "allow").length, anyFinding: b.filter((r) => r.anyThreats.length).length };
    const t = {};
    for (const r of b) for (const id of r.alertThreats) t[id] = (t[id] || 0) + 1;
    out.perThreatBenign[g] = Object.fromEntries(Object.entries(t).sort((x, y) => y[1] - x[1]).map(([k, v]) => [`#${k}`, `${v} (${pct(v, b.length)})`]));
  }
  const atk = by((r) => r.kind === "attack");
  const t = {};
  for (const r of atk) for (const id of r.alertThreats) t[id] = (t[id] || 0) + 1;
  out.perThreatAttack = Object.fromEntries(Object.entries(t).sort((x, y) => y[1] - x[1]).map(([k, v]) => [`#${k}`, `${v}/${atk.length}`]));
  const c39 = (rs) => rs.filter((r) => r.anyThreats.includes(39)).length;
  const ben = by((r) => r.kind === "benign");
  out.cred39 = { attacks: `${c39(atk)}/${atk.length}`, benign: `${c39(ben)}/${ben.length}`, benignWeb: `${c39(by((r) => r.kind === "benign" && r.corpus === "web"))}/${by((r) => r.kind === "benign" && r.corpus === "web").length}`, benignReal: `${c39(by((r) => r.corpus === "real"))}/${by((r) => r.corpus === "real").length}` };
  const ms = rows.map((r) => r.ms).sort((x, y) => x - y);
  out.latency = { n: ms.length, medianMs: +(ms[Math.floor(ms.length / 2)] || 0).toFixed(2), p95Ms: +(ms[Math.floor(ms.length * 0.95)] || 0).toFixed(2) };
  return out;
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  if (o.split === "locked" && !o.unlock) { console.error("the locked split is scored once, with --i-am-scoring-the-locked-split"); process.exit(2); }
  const repo = repoSamples(), real = realSamples(o.real);
  const all = [...repo, ...real];
  const samples = all.filter((s) => o.split === "all" || s.split === o.split);
  const allRows = {};
  const result = { split: o.split, splitHash: { repo: splitHash(repo), ...(real.length ? { real: splitHash(real) } : {}) }, n: samples.length, paths: {} };
  for (const p of o.paths) {
    const fn = PATHS[p];
    if (!fn) throw new Error(`unknown path ${p}`);
    const rs = await mapLimit(samples, p === "hook" ? o.concurrency : 1, fn);
    const rows = samples.map((s, i) => rowOf(s, rs[i]));
    result.paths[p] = summarise(rows);
    if (o.rows) allRows[p] = rows;
    if (o.errors && o.split === "tune") {
      result.paths[p].errors = {
        missedAttacks: rows.filter((r) => r.kind === "attack" && !r.injection).map((r) => `${r.corpus}:${r.id} [${r.alertThreats.join(",")}]`),
        benignInjectionFp: rows.filter((r) => r.kind === "benign" && r.injection).map((r) => `${r.corpus}:${r.id} [${r.alertThreats.join(",")}]`),
        benignNonAllow: rows.filter((r) => r.kind === "benign" && r.decision !== "allow").map((r) => `${r.corpus}:${r.id} ${r.decision} [${r.alertThreats.join(",")}]`)
      };
    }
  }
  // --rows <file>: the per-sample rows (ids, threat ids, decisions — no text), for a reducer run on them
  // afterwards; written for any split, printed for none.
  if (o.rows) writeFileSync(o.rows, JSON.stringify(allRows));
  if (o.json) { console.log(JSON.stringify(result, null, 2)); return; }
  console.log(`inbound scorer · split=${result.split} · n=${result.n} · splitHash repo=${result.splitHash.repo.slice(0, 16)}${result.splitHash.real ? ` real=${result.splitHash.real.slice(0, 16)}` : ""}`);
  for (const [p, s] of Object.entries(result.paths)) {
    console.log(`\n== ${p}`);
    console.log(JSON.stringify(s, null, 1));
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch((e) => { console.error(e); process.exit(1); });
