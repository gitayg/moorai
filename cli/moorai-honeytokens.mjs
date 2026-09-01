#!/usr/bin/env node
// MoorAI — content-free honeytokens (canary primitive).
//
// A honeytoken is a value nobody should ever legitimately touch — a fake API key, a decoy row, a
// tripwire string planted in a file. If it EVER shows up in an agent's I/O, that is a high-signal
// canary: not a heuristic that a secret *might* have leaked, but proof that a value which exists only
// to be a trap was read or transmitted.
//
// SACRED RULE — content-free: a honeytoken's VALUE is never stored. On register we keep only its
// one-way content hash (contentHash / HMAC-SHA-256, see content-hash.mjs), a timestamp, and an
// optional operator label (metadata, not the value). Detection is then a pure hash-set intersection:
// the hook/agent-watch already fingerprints observed I/O to the SAME keyed hashes, so a hit is exact
// hash equality — no plaintext ever changes hands.
//
// This ships the PRIMITIVE only — register/list/check + a pure match function. Wiring it into the live
// enforcement hook / engine is a deliberate follow-on, not part of this file.
//
//   node cli/moorai-honeytokens.mjs register <token> [--label <name>]
//   node cli/moorai-honeytokens.mjs list [--json]
//   node cli/moorai-honeytokens.mjs check <hash> [<hash> ...]     # observed content hashes
//   node cli/moorai-honeytokens.mjs check --value <token> [ ... ] # hash a value, then check
//   node cli/moorai-honeytokens.mjs --help

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { STATE_DIR } from "./state-dirs.mjs";
import { contentHash } from "./content-hash.mjs";

export const HONEYTOKENS_PATH = join(STATE_DIR, "honeytokens.json");

// Best-effort store. A read error (missing file, unreadable) reads as "no honeytokens registered";
// a write error never throws into a caller — registration is advisory, not an enforcement path.
export function loadHoneytokens() {
  try {
    const parsed = JSON.parse(readFileSync(HONEYTOKENS_PATH, "utf8"));
    return Array.isArray(parsed?.tokens) ? parsed.tokens : [];
  } catch { return []; }
}

function saveHoneytokens(tokens) {
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    writeFileSync(HONEYTOKENS_PATH, JSON.stringify({ version: 1, tokens }, null, 2) + "\n");
    return true;
  } catch { return false; }
}

// Register a honeytoken by its VALUE. The value is hashed and immediately discarded — only the hash
// (plus ts + optional label metadata) is persisted. Idempotent on the hash: registering the same
// value twice does not create a duplicate record.
export function registerHoneytoken(value, { label } = {}) {
  const hash = contentHash(value);
  const tokens = loadHoneytokens();
  const existing = tokens.find((t) => t.hash === hash);
  if (existing) return { record: existing, added: false };
  const record = { hash, ts: new Date().toISOString() };
  if (label) record.label = String(label);
  tokens.push(record);
  saveHoneytokens(tokens);
  return { record, added: true };
}

// PURE. Given content hashes observed in agent I/O and the registered honeytoken records, return the
// records that were hit. A hit = an observed hash equals a registered honeytoken's hash: a value that
// should never be touched was touched. `registered` defaults to the on-device store for convenience;
// pass it explicitly to keep this a pure function of its inputs.
export function checkHoneytokens(observedHashes, registered = loadHoneytokens()) {
  const seen = new Set((Array.isArray(observedHashes) ? observedHashes : [observedHashes]).map((h) => String(h)));
  return (registered || []).filter((t) => seen.has(String(t.hash)));
}

// ------------------------------------------------------------------------------------------------
// CLI
// ------------------------------------------------------------------------------------------------
const HELP = `MoorAI honeytokens — content-free canary primitive.

Usage:
  moorai-honeytokens register <token> [--label <name>]   register a canary (only its hash is stored)
  moorai-honeytokens list [--json]                        list registered honeytokens (hashes, never values)
  moorai-honeytokens check <hash> [<hash> ...]            report which registered honeytokens the hashes hit
  moorai-honeytokens check --value <token> [ ... ]        hash the given value(s), then check

A honeytoken's VALUE is never stored — only its one-way hash (${HONEYTOKENS_PATH}).
A hit means a value that should never be touched showed up in agent I/O: a high-signal canary.
`;

const flagVal = (argv, flag) => (argv.includes(flag) ? argv[argv.indexOf(flag) + 1] : null);

function cmdRegister(argv) {
  const label = flagVal(argv, "--label");
  const value = argv.find((a, i) => i > 0 && !a.startsWith("--") && argv[i - 1] !== "--label");
  if (!value) { process.stderr.write("register: a token value is required\n\n" + HELP); process.exit(2); }
  const { record, added } = registerHoneytoken(value, { label });
  process.stdout.write(`${added ? "Registered" : "Already registered"} honeytoken ${record.hash}${record.label ? ` (${record.label})` : ""}\n`);
}

function cmdList(argv) {
  const tokens = loadHoneytokens();
  if (argv.includes("--json")) { process.stdout.write(JSON.stringify({ version: 1, tokens }, null, 2) + "\n"); return; }
  if (!tokens.length) { process.stdout.write(`No honeytokens registered.\n(${HONEYTOKENS_PATH})\n`); return; }
  process.stdout.write(`MoorAI honeytokens — ${tokens.length} registered (hash-only, no values stored)\n\n`);
  for (const t of tokens) process.stdout.write(`  ${t.hash}   ${t.ts}${t.label ? `   ${t.label}` : ""}\n`);
}

function cmdCheck(argv) {
  const rest = argv.slice(1);
  const values = argv.includes("--value");
  const inputs = rest.filter((a) => a !== "--value" && !a.startsWith("--"));
  const hashes = values ? inputs.map((v) => contentHash(v)) : inputs;
  const matches = checkHoneytokens(hashes);
  if (argv.includes("--json")) { process.stdout.write(JSON.stringify({ checked: hashes.length, hits: matches }, null, 2) + "\n"); return; }
  if (!matches.length) { process.stdout.write(`No honeytoken hits (${hashes.length} hash(es) checked).\n`); return; }
  process.stdout.write(`HONEYTOKEN HIT — ${matches.length} canary value(s) observed:\n`);
  for (const m of matches) process.stdout.write(`  ${m.hash}${m.label ? `   ${m.label}` : ""}   (registered ${m.ts})\n`);
}

function main() {
  const argv = process.argv.slice(2);
  if (!argv.length || argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(argv.length ? 0 : 2); }
  const cmd = argv[0];
  if (cmd === "register") return cmdRegister(argv);
  if (cmd === "list") return cmdList(argv);
  if (cmd === "check") return cmdCheck(argv);
  process.stderr.write(`Unknown command: ${cmd}\n\n${HELP}`);
  process.exit(2);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
