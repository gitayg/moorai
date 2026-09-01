#!/usr/bin/env node
// MoorAI — verify the tamper-evident chain on the on-device evidence logs (record-chain.mjs).
//
// Every line the hook/guard append to the JSONL evidence logs carries a chain stamp (seq/prev/chash)
// plus a content fingerprint (rhash). This walks a log in file order and reports any discontinuity:
// a record altered in place (content_altered / chash_mismatch), a reordered or inserted record
// (prev_mismatch), or a deleted/duplicated record (seq_gap / seq_nonmonotonic). Reads only local
// files; nothing leaves the device, and every field inspected is content-free metadata.
//
//   node cli/moorai-verify-chain.mjs                 # verify all known evidence logs
//   node cli/moorai-verify-chain.mjs exposure-ledger # verify one, by name
//   node cli/moorai-verify-chain.mjs /path/to.jsonl  # verify one, by path
//   node cli/moorai-verify-chain.mjs --format json
//   node cli/moorai-verify-chain.mjs --help

import { readFileSync } from "node:fs";
import { join, isAbsolute } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { verifyChain, recordRhash } from "./record-chain.mjs";

const KNOWN = ["exposure-ledger.jsonl", "intent-log.jsonl", "action-audit.jsonl", "agent-events.jsonl", "destinations.jsonl"];

const HELP = `MoorAI verify-chain — tamper-evidence check on the on-device evidence logs.

Usage:
  moorai-verify-chain [name|path] [--format text|json]

With no argument, verifies all known logs under ${STATE_DIR}:
  ${KNOWN.join("  ")}

Reports per log: record count, ok, and any chain breaks (content_altered, chash_mismatch,
prev_mismatch, seq_gap, seq_nonmonotonic, unchained). Nothing leaves the device.
`;

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }
const fmt = argv.includes("--format") ? argv[argv.indexOf("--format") + 1] : "text";
const target = argv.find((a) => !a.startsWith("--") && a !== fmt);

function resolveTargets(t) {
  if (!t) return KNOWN.map((n) => ({ name: n, path: join(STATE_DIR, n) }));
  if (isAbsolute(t) || t.includes("/")) return [{ name: t, path: t }];
  const name = t.endsWith(".jsonl") ? t : `${t}.jsonl`;
  return [{ name, path: join(STATE_DIR, name) }];
}

function readJsonl(path) {
  try { return readFileSync(path, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; }
}

const results = resolveTargets(target).map(({ name, path }) => {
  const rows = readJsonl(path);
  const v = verifyChain(rows, { rhashOf: recordRhash });
  return { log: name, records: v.count, ok: v.ok, breaks: v.breaks };
});

if (fmt === "json") { process.stdout.write(JSON.stringify(results, null, 2) + "\n"); process.exit(0); }

let anyBreak = false;
for (const r of results) {
  const status = r.records === 0 ? "empty" : r.ok ? "OK" : `${r.breaks.length} BREAK(S)`;
  process.stdout.write(`${r.ok || r.records === 0 ? "✓" : "✗"} ${r.log} — ${r.records} record(s), ${status}\n`);
  for (const b of r.breaks) { anyBreak = true; process.stdout.write(`    seq ${b.seq}  @${b.index}  ${b.reason}\n`); }
}
process.exit(anyBreak ? 1 : 0);
