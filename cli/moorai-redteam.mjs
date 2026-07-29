#!/usr/bin/env node
// moorai-redteam — run MoorAI's adversarial corpus against YOUR active policy, on your own machine.
// The internal `npm run redteam` proves the engine *detects* the corpus; this proves your live policy
// actually *acts* on each attack class (prompt injection, jailbreaks, secrets/PII, license, destructive
// commands, …) rather than leaving it disabled. "Verify, don't trust" — turned into a command.
//
// Content-free: it runs a built-in adversarial corpus locally and reports pass/fail per attack class.
// No prompt of yours is read, and nothing leaves the machine. Fetches your tenant policy from the
// configured server if reachable; otherwise falls back to MoorAI's safe defaults.
//
//   node cli/moorai-redteam.mjs                 # coverage report (default)
//   node cli/moorai-redteam.mjs --format json   # machine-readable
//   node cli/moorai-redteam.mjs --help
//
// Exit code: 0 if every attack class is caught (acted on) under your policy; 1 if any is missed or
// left disabled — so it doubles as a CI gate on your own policy.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { loadConfig } from "./config.mjs";
import { threatActionFor } from "./hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HELP = `moorai-redteam — run the adversarial corpus against YOUR active policy, on this machine.

Usage:
  moorai-redteam [--format text|json]
  moorai-redteam --help

Proves your live policy ACTS on each attack class (not just that the engine can detect it).
Content-free: a built-in corpus runs locally; no prompt of yours is read, nothing leaves the machine.
Policy is fetched from the configured server if reachable, else MoorAI's safe defaults are used.
Exit 0 = every attack class caught; exit 1 = a class is missed or left disabled.
`;

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }
const fmt = argv.includes("--format") ? argv[argv.indexOf("--format") + 1] : "text";

const threatsData = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
const corpus = JSON.parse(readFileSync(join(ROOT, "test/redteam/corpus.json"), "utf8"));
const engine = new DetectionEngine(threatsData, DETECTORS, CONTENT_RULES);
const CONFIG = loadConfig();
const catOf = Object.fromEntries(threatsData.threats.map((t) => [t.id, t.category]));

async function getPolicy() {
  try {
    const headers = CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {};
    return await fetch(`${CONFIG.serverUrl}/api/policy?tenant=${encodeURIComponent(CONFIG.tenant)}`, { headers, signal: AbortSignal.timeout(2000) }).then((r) => r.json());
  } catch { return null; }
}

// verdict per attack case: caught (detected + policy acts) / disabled (detected but action=disabled) /
// missed (not detected). Benign cases: clean (no finding) / false-positive.
function evaluate(policy) {
  const attacks = [], benign = [];
  for (const c of corpus.cases) {
    const findings = c.turns ? engine.scanSession(c.turns) : engine.scan(c.text, c.stage || "prompt");
    const ids = new Set(findings.map((f) => f.threat.id));
    if (c.none) { benign.push({ id: c.id, clean: findings.length === 0 }); continue; }
    const detected = ids.has(c.expect);
    const action = threatActionFor(policy, c.expect);
    attacks.push({ id: c.id, threatId: c.expect, category: catOf[c.expect] || "—", detected, action, verdict: !detected ? "missed" : action === "disabled" ? "disabled" : "caught" });
  }
  return { attacks, benign };
}

function summarize({ attacks, benign }) {
  const caught = attacks.filter((a) => a.verdict === "caught").length;
  const disabled = attacks.filter((a) => a.verdict === "disabled").length;
  const missed = attacks.filter((a) => a.verdict === "missed").length;
  const fp = benign.filter((b) => !b.clean).length;
  return { attacks: attacks.length, caught, disabled, missed, benignClean: benign.filter((b) => b.clean).length, falsePositives: fp, gaps: missed + disabled };
}

const C = { g: "\x1b[32m", r: "\x1b[31m", y: "\x1b[33m", dim: "\x1b[2m", b: "\x1b[1m", off: "\x1b[0m" };
function byCategory(attacks) {
  const m = new Map();
  for (const a of attacks) { const k = a.category; if (!m.has(k)) m.set(k, { caught: 0, gap: 0 }); const e = m.get(k); a.verdict === "caught" ? e.caught++ : e.gap++; }
  return [...m.entries()].sort((x, y) => (y[1].caught + y[1].gap) - (x[1].caught + x[1].gap));
}

function toText(res) {
  const s = summarize(res);
  const mark = (v) => v === "caught" ? `${C.g}✓ caught${C.off}` : v === "disabled" ? `${C.y}⚠ disabled${C.off}` : `${C.r}✗ missed${C.off}`;
  let out = `\n${C.b}MoorAI red-team — your active policy vs the adversarial corpus${C.off}\n`;
  out += `${C.dim}tenant: ${CONFIG.tenant} · server: ${CONFIG.serverUrl}${C.off}\n\n`;
  out += `  ${s.caught}/${s.attacks} attack classes caught` + (s.disabled ? `  ${C.y}${s.disabled} detected-but-disabled${C.off}` : "") + (s.missed ? `  ${C.r}${s.missed} missed${C.off}` : "") + `\n`;
  out += `  benign prompts kept clean: ${s.benignClean}/${res.benign.length}` + (s.falsePositives ? `  ${C.r}${s.falsePositives} false-positive${C.off}` : "") + `\n\n`;
  out += `  ${C.dim}By attack category:${C.off}\n`;
  for (const [cat, e] of byCategory(res.attacks)) out += `    ${e.gap ? C.y : C.g}${String(e.caught).padStart(2)}/${e.caught + e.gap}${C.off}  ${cat}\n`;
  const gaps = res.attacks.filter((a) => a.verdict !== "caught");
  if (gaps.length) { out += `\n  ${C.b}Gaps to close (enable a non-disabled action for these):${C.off}\n`; for (const gp of gaps) out += `    ${mark(gp.verdict)}  #${gp.threatId} ${gp.category}  ${C.dim}(${gp.id})${C.off}\n`; }
  out += `\n${s.gaps ? `${C.r}✗ ${s.gaps} gap(s) — your policy does not act on every attack class.${C.off}` : `${C.g}✓ your policy acts on every attack class in the corpus.${C.off}`}\n`;
  return out;
}

const policy = await getPolicy();
const res = evaluate(policy);
const s = summarize(res);
if (fmt === "json") process.stdout.write(JSON.stringify({ tenant: CONFIG.tenant, policyLoaded: !!policy, summary: s, attacks: res.attacks }, null, 2) + "\n");
else process.stdout.write(toText(res));
process.exit(s.gaps ? 1 : 0);
