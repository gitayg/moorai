#!/usr/bin/env node
// END-TO-END REACHABILITY of the inbound WebFetch surface — AMTSO vector 2.
//
// WHY THIS SCRIPT EXISTS, AND WHY scripts/score-vector24.mjs CANNOT ANSWER IT.
// score-vector24 --vector 2 calls engine.scan(text, stage) DIRECTLY. It measures whether the
// DETECTORS can read this content, and they always could: it reports the output stage at 91.7%
// (22/24) and that number is unchanged by this work. The defect was never detection — it was that the
// content never reached the detectors in production, because cli/moorai-hook.mjs registered PreToolUse
// only and PreToolUse fires BEFORE the fetch, when the page does not yet exist.
//
// So the honest measurement is REACHABILITY: spawn the REAL cli/moorai-hook.mjs as a subprocess with a
// real PostToolUse payload carrying the poisoned fetched content, and count how many output-stage
// vector-2 attacks produce a content-free alert THROUGH THE SHIPPED HOOK. It re-implements none of the
// hook's logic and reads its verdict off the wire, exactly as the vector-4 half of score-vector24 does.
//
//   --before   simulate the pre-fix product by sending the SAME content on the surface that existed
//              (PreToolUse, where tool_input is {url, prompt} and the page is absent). Expected 0.
//
//   node scripts/measure-webfetch-reachability.mjs
//   node scripts/measure-webfetch-reachability.mjs --before
//   node scripts/measure-webfetch-reachability.mjs --json
//
// Content-free: emits ids, threat ids, stages and booleans. Never a sample's text.
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const V2 = JSON.parse(readFileSync(join(ROOT, "test", "redteam", "vector2-indirect-content.json"), "utf8"));
const BEFORE = process.argv.includes("--before");
const JSON_OUT = process.argv.includes("--json");

const attacks = V2.attacks.filter((a) => a.stage === "output");
const benign = V2.benign.filter((b) => b.stage === "output");

function startServer(policy) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify(policy)); }
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url.startsWith("/api/alerts")) { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } } res.writeHead(200); res.end("{}"); });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ srv, port: srv.address().port, alerts })));
}

function sandbox(port) {
  const home = mkdtempSync(join(tmpdir(), "moorai-reach-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "reach", installToken: "tok-reach" }));
  return home;
}

function run(home, stdin) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const c = spawn(process.execPath, [HOOK], { cwd: home, env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", () => {});
    c.on("close", (code) => resolve({ ms: Number(process.hrtime.bigint() - t0) / 1e6, out, code }));
    c.stdin.end(stdin);
  });
}

// AFTER: the surface this change adds. BEFORE: the surface that existed, given the same content —
// PreToolUse, whose tool_input is {url, prompt}; the page has no field to travel in, which is the defect.
const payload = (text) => BEFORE
  ? JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "WebFetch", tool_input: { url: "https://docs.example.com/p", prompt: "Summarise this page" }, session_id: "reach" })
  : JSON.stringify({ hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: "https://docs.example.com/p", prompt: "Summarise this page" }, tool_use_id: "toolu_reach", tool_response: text, session_id: "reach" });

const POLICY = { captureTier: "content-free", threatPolicy: {} };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function one(text) {
  const { srv, port, alerts } = await startServer(POLICY);
  const home = sandbox(port);
  const r = await run(home, payload(text));
  await sleep(450);
  srv.close();
  // CAUGHT = the shipped hook emitted at least one content-free detection finding for this content.
  const found = alerts.filter((a) => a.stage === "output" && a.threatId);
  return { caught: found.length > 0, threats: [...new Set(found.map((a) => a.threatId))], ms: r.ms, code: r.code };
}

const rows = [];
for (const a of attacks) rows.push({ id: a.id, channel: a.channel, kind: "attack", ...(await one(a.text)) });
for (const b of benign) rows.push({ id: b.id, channel: b.channel, kind: "benign", ...(await one(b.text)) });

const atk = rows.filter((r) => r.kind === "attack");
const ben = rows.filter((r) => r.kind === "benign");
const caught = atk.filter((r) => r.caught).length;
const fp = ben.filter((r) => r.caught).length;
const lat = rows.map((r) => r.ms).sort((x, y) => x - y);
const pct = (n, d) => (d ? ((n / d) * 100).toFixed(1) : "0.0");

if (JSON_OUT) {
  console.log(JSON.stringify({ surface: BEFORE ? "before (PreToolUse only)" : "after (PostToolUse)", attacks: atk.length, caught, benignFires: fp, rows }, null, 2));
} else {
  console.log(`\nINBOUND WEB REACHABILITY — ${BEFORE ? "BEFORE (PreToolUse only)" : "AFTER (PostToolUse registered)"}`);
  console.log(`  entry point: spawn cli/moorai-hook.mjs, real payload on stdin, alert read off the wire`);
  console.log(`  output-stage vector-2 attacks reaching a content-free alert : ${caught}/${atk.length}  (${pct(caught, atk.length)}%)`);
  console.log(`  benign output-stage controls that also alerted              : ${fp}/${ben.length}  (${pct(fp, ben.length)}%)`);
  console.log(`  hook exit codes non-zero                                    : ${rows.filter((r) => r.code !== 0).length}`);
  console.log(`  latency per invocation  median ${lat[Math.floor(lat.length / 2)].toFixed(0)}ms  p95 ${lat[Math.floor(lat.length * 0.95)].toFixed(0)}ms  n=${lat.length}`);
  const byCh = {};
  for (const r of atk) { byCh[r.channel] = byCh[r.channel] || [0, 0]; byCh[r.channel][1]++; if (r.caught) byCh[r.channel][0]++; }
  console.log(`  by channel:`);
  for (const [c, [k, n]] of Object.entries(byCh)) console.log(`    ${c.padEnd(18)} ${k}/${n}`);
}
