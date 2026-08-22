#!/usr/bin/env node
// moorai-backtest — replay YOUR OWN history against a CANDIDATE policy, on this machine, before you
// adopt it. "What would this policy change have done to me last month?" answered from evidence
// instead of imagination. The standalone twin of the console's Policy Backtest, so the AGPL agent
// has the capability without a server or an account.
//
// Content-free by construction, and that is the point: recomputing a historical event's action needs
// only (policy, threatId) — threatActionFor is a pure function of those two — and every line of the
// local action-audit log already carries threatId + category. There is no prompt, no matched span,
// no file content anywhere in this path. Nothing leaves the machine.
//
// HONEST SCOPE LIMIT: this backtests ACTION / POLICY changes only. A NEW DETECTOR (a new regex)
// cannot be backtested, because scoring a new pattern would require the original text, and the text
// is gone by construction. See LIMITATION below — it is printed on every run.
//
//   node cli/moorai-backtest.mjs --policy candidate.json         # readable table (default)
//   node cli/moorai-backtest.mjs --policy candidate.json --days 7
//   node cli/moorai-backtest.mjs --policy candidate.json --json  # machine-readable
//   node cli/moorai-backtest.mjs --help
//
// Exit code: 0 if the candidate changes nothing (or only relaxes); 1 if it would block or coach
// events that previously passed — so it doubles as a CI gate on a policy pull request.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { threatActionFor } from "./hook-core.mjs";
import { readActions, readIntent, INTENT_PATH } from "./signals.mjs";
import { loadConfig } from "./config.mjs";

// Display only — signals.mjs owns the writer and does not export this path. readActions() is the
// single reader; this constant exists so --help can name the file the user should expect.
const ACTION_AUDIT_PATH = join(homedir(), ".curaiq", "action-audit.jsonl");

// The one sentence every surface must show. Same wording as the console's server/backtest.js.
export const LIMITATION =
  "Action changes only — new detectors cannot be backtested because content is never retained.";

const HELP = `moorai-backtest — replay your own history against a candidate policy, on this machine.

Usage:
  moorai-backtest --policy <file.json> [--days N] [--json]
  moorai-backtest --help

Answers "what would this policy change have done to me?" by recomputing each past finding's action
under the candidate policy and rolling up the transitions (would block / would coach / would relax).

Reads two on-device logs; nothing leaves the machine:
  ${ACTION_AUDIT_PATH}   content-free per-action audit log
  ${INTENT_PATH}         human overrides — a weak "this was actually fine" signal

Content-free: the replay needs only (policy, threat id). No prompt, matched span, or file content is
read — there is none stored to read.

LIMITATION: ${LIMITATION}

--days N        history window (default 30)
--policy FILE   candidate policy JSON (the shape /api/policy returns: threatPolicy, tierPolicy, …)
--json          machine-readable output

Exit 0 = the candidate blocks or coaches nothing that previously passed; exit 1 = it would.
`;

// Strictness ordering, so "relax" means measurably less strict rather than merely different.
// `alert` is the legacy spelling of `notify`; `ask`/`deny` are the hook's decision vocabulary for
// `justify`/`block`. kill is block-plus-terminate.
const STRICTNESS = { disabled: 0, notify: 1, alert: 1, allow: 1, justify: 2, ask: 2, block: 3, deny: 3, kill: 4 };
const rank = (a) => STRICTNESS[a] ?? 1;

export function classifyTransition(from, to) {
  if (from === to) return "unchanged";
  if (to === "deny" || to === "block" || to === "kill") return "wouldBlock";
  if (to === "justify" || to === "ask") return "wouldCoach";
  if (rank(to) < rank(from)) return "wouldRelax"; // → notify/allow/alert/disabled from something stricter
  return "unchanged";
}

// Pure rollup over content-free (threatId, category, count) rows. Exported so it is testable without
// touching the filesystem, and so the only thing it can see is those three fields.
export function rollupTransitions(rows, currentPolicy, candidatePolicy, overridesByThreat = {}) {
  const summary = { wouldBlock: 0, wouldCoach: 0, wouldRelax: 0, unchanged: 0 };
  const changes = [];
  let total = 0;
  for (const r of rows) {
    const threatId = Number(r.threatId) || 0;
    const count = Number(r.count) || 0;
    const from = threatActionFor(currentPolicy, threatId);
    const to = threatActionFor(candidatePolicy, threatId);
    const kind = classifyTransition(from, to);
    total += count;
    summary[kind] += count;
    if (kind !== "unchanged")
      changes.push({ threatId, category: r.category || "—", from, to, count, kind, overrides: overridesByThreat[threatId] || 0 });
  }
  changes.sort((a, b) => b.count - a.count || a.threatId - b.threatId);
  return { total, changes, summary };
}

const tsMs = (e) => { const t = e && e.ts; if (typeof t === "number") return t; const p = Date.parse(t); return Number.isNaN(p) ? null : p; };
const inWindow = (e, cutoff) => { const m = tsMs(e); return m == null || m >= cutoff; };

// Group the action-audit log into content-free (threatId, category, count) rows. threatId 0 is not a
// detector finding (content-rule hits, literacy touchpoints, posture/intent signals); threatActionFor
// does not govern those, so they are counted out rather than silently resolved to the default action.
export function groupActions(actions) {
  const byKey = new Map();
  let skippedNonThreat = 0;
  for (const a of actions) {
    const id = Number(a.threatId) || 0;
    if (!id) { skippedNonThreat++; continue; }
    const key = `${id}|${a.category || ""}`;
    const e = byKey.get(key);
    if (e) e.count++;
    else byKey.set(key, { threatId: id, category: a.category || "—", count: 1 });
  }
  return { rows: [...byKey.values()], skippedNonThreat };
}

// #15 — the local intent log records every time a human overrode a finding and proceeded. A weak but
// real "this was actually fine" label: "3 would block, 2 of which a human previously overrode".
export function overrideCounts(intents) {
  const out = {};
  for (const i of intents) for (const id of (Array.isArray(i.threatIds) ? i.threatIds : [])) out[id] = (out[id] || 0) + 1;
  return out;
}

export function backtestLocal(candidatePolicy, currentPolicy, days = 30, { actions, intents } = {}) {
  const win = Math.max(1, Math.min(Number(days) || 30, 365));
  const cutoff = Date.now() - win * 86400000;
  const acts = (actions || readActions()).filter((e) => inWindow(e, cutoff));
  const ints = (intents || readIntent()).filter((e) => inWindow(e, cutoff));
  const { rows, skippedNonThreat } = groupActions(acts);
  const overridesByThreat = overrideCounts(ints);
  const { total, changes, summary } = rollupTransitions(rows, currentPolicy || {}, candidatePolicy || {}, overridesByThreat);
  return {
    days: win,
    generatedAt: new Date().toISOString(),
    total, changes, summary,
    overrides: { total: ints.length, byThreat: overridesByThreat },
    skippedNonThreat,
    limitation: LIMITATION
  };
}

// ---- CLI ----

async function fetchLivePolicy() {
  const cfg = loadConfig();
  try {
    const headers = cfg.installToken ? { "X-Install-Token": cfg.installToken } : {};
    return await fetch(`${cfg.serverUrl}/api/policy?tenant=${encodeURIComponent(cfg.tenant)}`, { headers, signal: AbortSignal.timeout(2000) }).then((r) => r.json());
  } catch { return null; }
}

const C = { g: "\x1b[32m", r: "\x1b[31m", y: "\x1b[33m", dim: "\x1b[2m", b: "\x1b[1m", off: "\x1b[0m" };
const MARK = { wouldBlock: `${C.r}block${C.off}`, wouldCoach: `${C.y}coach${C.off}`, wouldRelax: `${C.g}relax${C.off}` };

export function toText(res, { policyFile, live }) {
  const s = res.summary;
  let out = `\n${C.b}MoorAI policy backtest — your last ${res.days} day(s) vs the candidate policy${C.off}\n`;
  out += `${C.dim}candidate: ${policyFile} · current: ${live ? "live tenant policy" : "agent defaults (server unreachable)"} · ${res.total} replayed finding(s)${C.off}\n\n`;
  out += `  ${C.r}${s.wouldBlock}${C.off} would block   ${C.y}${s.wouldCoach}${C.off} would coach   ${C.g}${s.wouldRelax}${C.off} would relax   ${C.dim}${s.unchanged} unchanged${C.off}\n`;
  if (res.skippedNonThreat) out += `  ${C.dim}${res.skippedNonThreat} non-detector event(s) excluded (content rules, literacy, posture, intent)${C.off}\n`;
  if (!res.total) {
    out += `\n  ${C.dim}No history in this window — nothing to replay.${C.off}\n`;
  } else if (!res.changes.length) {
    out += `\n  ${C.g}✓ this candidate changes nothing about your recorded history.${C.off}\n`;
  } else {
    const w = Math.max(8, ...res.changes.map((c) => c.category.length));
    out += `\n  ${C.dim}${"threat".padEnd(7)}${"category".padEnd(w + 2)}${"from → to".padEnd(20)}${"events".padStart(7)}${"overridden".padStart(12)}${C.off}\n`;
    for (const c of res.changes)
      out += `  ${MARK[c.kind]} ${("#" + c.threatId).padEnd(6)}${c.category.padEnd(w + 2)}${`${c.from} → ${c.to}`.padEnd(20)}${String(c.count).padStart(7)}${String(c.overrides || "—").padStart(12)}\n`;
    if (res.overrides.total) out += `\n  ${C.dim}"overridden" = times a human previously proceeded past this finding (#15 intent log) — a weak signal that the block may be a false positive.${C.off}\n`;
  }
  out += `\n  ${C.dim}LIMITATION: ${res.limitation}${C.off}\n`;
  return out;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }
  const arg = (name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : undefined);
  const policyFile = arg("--policy");
  const days = Number(arg("--days")) || 30;
  const asJson = argv.includes("--json");

  if (!policyFile) { process.stderr.write("moorai-backtest: --policy <file.json> is required (see --help)\n"); process.exit(2); }
  let candidate;
  try { candidate = JSON.parse(readFileSync(policyFile, "utf8")); }
  catch (e) { process.stderr.write(`moorai-backtest: cannot read candidate policy ${policyFile} — ${e.message}\n`); process.exit(2); }

  const live = await fetchLivePolicy();
  const res = backtestLocal(candidate, live, days);
  if (asJson) process.stdout.write(JSON.stringify({ policyFile, currentPolicyLoaded: !!live, ...res }, null, 2) + "\n");
  else process.stdout.write(toText(res, { policyFile, live: !!live }));
  process.exit(res.summary.wouldBlock || res.summary.wouldCoach ? 1 : 0);
}
