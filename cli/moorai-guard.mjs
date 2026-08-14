#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline/promises";
import os from "node:os";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { loadConfig } from "./config.mjs";
import { calibrateRisk, decideEndpoints } from "./hook-core.mjs";
import { recordExposure, recordIntent } from "./signals.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CONFIG = loadConfig();
const SERVER = CONFIG.serverUrl;
const threatData = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
const engine = new DetectionEngine(threatData, DETECTORS, CONTENT_RULES);

async function getPolicy() {
  try { return await fetch(`${SERVER}/api/policy?tenant=${encodeURIComponent(CONFIG.tenant)}`, { signal: AbortSignal.timeout(2000) }).then((r) => r.json()); }
  catch { return null; }
}

const C = { red: "\x1b[31m", org: "\x1b[33m", blue: "\x1b[34m", green: "\x1b[32m", dim: "\x1b[2m", bold: "\x1b[1m", off: "\x1b[0m" };
const color = (lvl) => (lvl === "Critical" ? C.red : lvl === "High" ? C.org : C.blue);

function parseArgs(argv) {
  const out = { decide: null, prompt: "" };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--decide") out.decide = argv[++i];
    else rest.push(argv[i]);
  }
  out.prompt = rest.join(" ").trim();
  return out;
}

function djb2(s) { let h = 5381; for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0; return "h" + h.toString(16); }

// #10 — stable content-free actor fingerprint (one-way hash of user@device), stamped on every emit.
const IDENTITY = { user: os.userInfo().username, device: os.hostname(), platform: os.platform(), tenant: CONFIG.tenant, actor: djb2(`${os.userInfo().username}@${os.hostname()}`) };

function post(alert) {
  return fetch(`${SERVER}/api/alerts`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(alert) }).catch(() => {});
}

function reportAlert(finding, content, blocked = false, stage = "egress") {
  const alert = {
    threatId: finding.threat.id, category: finding.threat.category,
    riskLevel: blocked ? "Blocked" : calibrateRisk(finding.threat.riskLevel, { stage, category: finding.threat.category }), // #10
    stage, tool: "claude -p", ts: new Date().toISOString(), contentHash: djb2(content), ...IDENTITY
  };
  recordExposure(alert); // #5 — local content-free exposure ledger (secret classes only)
  return post(alert);
}

function reportContent(c, enforce) {
  return post({
    threatId: 0, category: `Content: ${c.label}`, riskLevel: enforce ? "Blocked" : "High",
    stage: "shared", tool: "claude -p", ts: new Date().toISOString(), contentHash: djb2(c.match), ...IDENTITY
  });
}

// Coach-as-literacy (EU AI Act Art. 4 angle): each time MoorAI SHOWS a developer the "why + what to do"
// for a finding, that is a just-in-time AI-literacy touchpoint delivered at the point of use. Emit a
// content-free record — topic + framework + actor, never any content — with stage "coach" so the
// console can show literacy coverage (evidence of "measures taken to your best extent"). Not a threat.
function reportTouchpoint(f) {
  return post({
    threatId: f.threat.id, category: `Literacy: ${f.threat.category}`, riskLevel: "Info",
    stage: "coach", tool: "claude -p", ts: new Date().toISOString(), contentHash: "coach:" + f.threat.id, ...IDENTITY
  });
}

function printContent(content, enforce) {
  const tag = enforce ? `${C.red}BLOCKED (policy)` : `${C.org}CONTENT`;
  for (const c of content) {
    console.error(`  ${tag}${C.off}  ${c.label}  ${C.dim}matched:${C.off} ${c.match}`);
  }
}

function printFindings(findings) {
  console.error(`\n${C.bold}MoorAI pre-flight review${C.off} ${C.dim}— ${findings.length} issue(s) before sending to claude -p${C.off}\n`);
  for (const f of findings) {
    const c = color(f.threat.riskLevel);
    const fw = [f.threat.owasp, f.threat.atlas].filter(Boolean).join(" · ");
    console.error(`  ${c}● ${f.mode === "coach" ? "COACH" : f.threat.riskLevel}${C.off}  #${f.threat.id} ${f.threat.threat}  ${C.dim}[${f.threat.category}]${f.threat.owasp ? ` ${fw}` : ""}${C.off}`);
    console.error(`     ${C.dim}matched:${C.off} ${f.match}`);
    console.error(`     ${C.dim}why:${C.off} ${f.threat.response}\n`);
  }
}

async function decide(decideFlag) {
  if (decideFlag) return decideFlag;
  if (!process.stdin.isTTY) return "abort";
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const ans = (await rl.question(`${C.bold}Proceed?${C.off} [p]roceed as-is / [r]edact then send / [a]bort: `)).trim().toLowerCase();
  rl.close();
  return ans.startsWith("p") ? "proceed" : ans.startsWith("r") ? "redact" : "abort";
}

// #3 — content-free session-kill record: the reply (or session) was terminated by policy, never the
// text. Only the terminating rule ids + a "kill:" marker leave the device.
function reportSessionKill(stage, findings) {
  return post({
    threatId: 0, category: "Session terminated (kill)", riskLevel: "Blocked", stage, tool: "claude -p",
    ts: new Date().toISOString(), contentHash: "kill:" + findings.map((f) => f.threat.id).join("."), ...IDENTITY
  });
}

function runClaude(prompt, policy, action) {
  // Output review/redaction (#4). The interactive TUI can't be masked safely (cursor/ANSI redraws),
  // but `claude -p` is a one-shot reply — so here we capture stdout, scan it for anything the model
  // surfaced (a secret echoed back, licensed code, a risky `curl | bash`, an unverifiable citation)
  // and mask flagged secret spans before printing. Buffering means the reply prints once complete
  // rather than token-by-token — an acceptable trade for the guarded print path. Opt out with
  // policy.outputReview === false.
  const review = policy?.outputReview !== false;
  return new Promise((resolve) => {
    const child = spawn("claude", ["-p", prompt], { stdio: ["ignore", review ? "pipe" : "inherit", "inherit"] });
    child.on("error", (e) => { console.error(`${C.red}failed to run claude:${C.off} ${e.message}`); resolve(1); });
    if (!review) { child.on("close", (code) => resolve(code ?? 0)); return; }
    let out = "";
    child.stdout.on("data", (d) => { out += d.toString(); });
    child.on("close", (code) => {
      const flagged = engine.scan(out, "output").filter((f) => action(f) !== "disabled");
      // #4 — report every on-device output-screening verdict, content-free (rule id + risk + one-way
      // hash of the matched span). The reply text never leaves the device; only the verdict does.
      for (const f of flagged) reportAlert(f, f.match || "", action(f) === "block" || action(f) === "kill", "output");
      const visible = flagged.filter((f) => action(f) !== "alert");
      if (visible.length) { console.error(`\n${C.org}⚠ MoorAI output review — ${visible.length} finding(s) in the reply:${C.off}`); printFindings(visible); }
      // #3 — kill/block enforcement. An output finding the policy marks "kill" (or any Critical block
      // when killOnCritical is set) suppresses the whole reply rather than masking spans — prevent,
      // not warn. The dangerous output is never printed and a content-free session-kill is emitted.
      const killed = flagged.filter((f) => action(f) === "kill" || (policy?.killOnCritical && action(f) === "block" && f.threat.riskLevel === "Critical"));
      if (killed.length) {
        console.error(`\n${C.red}✗ MoorAI killed the reply — critical output finding (#${killed.map((f) => f.threat.id).join(", #")}); nothing printed.${C.off}`);
        reportSessionKill("output", killed);
        return resolve(3);
      }
      const mask = policy?.outputRedaction === true || flagged.some((f) => action(f) === "block" || action(f) === "justify");
      if (mask) console.error(`${C.org}↻ masking flagged spans in the reply${C.off}`);
      process.stdout.write(mask ? engine.redact(out, "output") : out);
      resolve(code ?? 0);
    });
  });
}

async function main() {
  const { decide: decideFlag, prompt } = parseArgs(process.argv.slice(2));
  if (!prompt) { console.error("usage: raiseme-guard [--decide proceed|redact|abort] <prompt>"); process.exit(2); }

  const policy = await getPolicy();
  // #5 — consent-visible banner: never let an elevated capture tier run silently on the device.
  if (policy && policy.captureTier && policy.captureTier !== "content-free") {
    process.stderr.write(`\x1b[33m⚠ MoorAI capture: ${policy.captureTier} — this policy records ${policy.captureTier === "full-capture" ? "prompt / argument text" : "metadata (file paths, tool names, command shape)"}.\x1b[0m\n`);
  }
  const tp = policy?.threatPolicy || {};
  const cp = policy?.contentPolicy || {};
  const action = (f) => tp[f.threat.id] || "notify";
  const allFindings = engine.scan(prompt, "prompt").filter((f) => action(f) !== "disabled");
  const contentOn = Object.keys(cp).filter((id) => cp[id] && cp[id] !== "disabled");
  const allContent = contentOn.length ? engine.scanContent(prompt, contentOn) : [];

  // Report every active detection to the dashboard (incl. silent "alert").
  if (allFindings.length || allContent.length) {
    await Promise.allSettled([
      ...allFindings.map((f) => reportAlert(f, f.match, action(f) === "block")),
      ...allContent.map((c) => reportContent(c, cp[c.ruleId] === "block"))
    ]);
  }

  // Visible to the user = notify/block only; silent "alert" never prompts or prints.
  const findings = allFindings.filter((f) => action(f) !== "alert");
  const content = allContent.filter((c) => cp[c.ruleId] !== "alert");
  // #3 — "kill" hard-blocks the prompt like "block" (the user cannot override), and also emits a
  // content-free session-kill so the console sees the session was terminated, not merely denied.
  const killFindings = allFindings.filter((f) => action(f) === "kill");
  const blockedFindings = allFindings.filter((f) => action(f) === "block" || action(f) === "kill");
  const blockedContent = allContent.filter((c) => cp[c.ruleId] === "block");

  if (!findings.length && !content.length) {
    console.error(`${C.green}✓ MoorAI: clean — forwarding to claude -p${C.off}\n`);
    process.exit(await runClaude(prompt, policy, action));
  }

  if (findings.length) { printFindings(findings); await Promise.allSettled(findings.map((f) => reportTouchpoint(f))); }
  if (content.length) { console.error(`\n${C.bold}Parental-control review${C.off}`); for (const c of content) printContent([c], cp[c.ruleId] === "block"); console.error(""); }

  // T1-1 — model-endpoint allow-list: a base-URL override / rogue LLM host in the prompt hard-blocks.
  const epD = decideEndpoints(policy, prompt);
  if (epD.decision === "deny") { const a = { threatId: 63, category: "Unapproved model endpoint", riskLevel: "Blocked", stage: "egress", tool: "claude -p", ts: new Date().toISOString(), contentHash: djb2(epD.hosts.join(",")), ...IDENTITY }; post(a); }

  // Hard block: any threat or content category set to "block". The user cannot override.
  const hardBlock = blockedFindings.length > 0 || blockedContent.length > 0 || epD.decision === "deny";
  if (hardBlock) {
    const parts = [];
    if (blockedFindings.length) parts.push(`threat policy (#${blockedFindings.map((f) => f.threat.id).join(", #")})`);
    if (blockedContent.length) parts.push(`content policy (${blockedContent.map((c) => c.label).join(", ")})`);
    if (epD.decision === "deny") parts.push(epD.reason);
    const verb = killFindings.length ? "killed" : "blocked";
    console.error(`${C.red}✗ ${verb} by ${parts.join(" + ")} — nothing sent to claude -p${C.off}`);
    if (killFindings.length) await reportSessionKill("prompt", killFindings);
    process.exit(3);
  }

  const choice = await decide(decideFlag);
  if (choice === "abort") { console.error(`${C.red}✗ aborted — nothing sent to claude -p${C.off}`); process.exit(1); }

  let final = prompt;
  if (choice === "redact") {
    final = engine.redact(prompt, "prompt");
    console.error(`${C.org}↻ redacted before sending:${C.off} ${final}\n`);
  } else {
    console.error(`${C.org}⚠ proceeding as-is (override logged)${C.off}\n`);
  }

  // #15 — capture the human's intent to proceed past findings. Legitimate agentic use resembles an
  // attack; a human "proceed" is the signal that disambiguates them. Content-free: the overridden
  // categories and a one-way hash of the prompt, never the prompt itself. Recorded locally and, as an
  // Info-level alert, to the server (→ SIEM). "abort" already exited above, so reaching here = intent.
  if (choice !== "abort" && (allFindings.length || allContent.length)) {
    const intent = {
      ts: new Date().toISOString(), event: "override", redacted: choice === "redact",
      threatIds: allFindings.map((f) => f.threat.id),
      categories: [...allFindings.map((f) => f.threat.category), ...allContent.map((c) => `Content: ${c.label}`)],
      contentHash: djb2(prompt), ...IDENTITY
    };
    recordIntent(intent);
    post({ threatId: 0, category: "Intent: user override", riskLevel: "Info", stage: "egress", tool: "claude -p", ts: intent.ts, contentHash: intent.contentHash, ...IDENTITY });
  }
  process.exit(await runClaude(final, policy, action));
}

main();
