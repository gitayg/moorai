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
//
// OFFLINE VERIFY (additive) — validate a portable evidence artifact with NO network and NO console:
//   node cli/moorai-verify-chain.mjs --offline <attestation.json>              # keyless in-toto chain check
//   node cli/moorai-verify-chain.mjs --offline <receipt.json> --pubkey <key>   # receipt + ed25519 signature
//
// An in-toto attestation (moorai-attest) is checked KEYLESS: its subjects/byproducts carry the SHA-256
// chain link (chash = sha256(prev|seq|rhash)), so anyone can recompute continuity with no key. A decision
// receipt (moorai-receipt) additionally carries an ed25519 signature, verified against a PROVIDED/pinned
// public key. Both fail CLOSED: a broken chain, a tampered field, or a bad signature exits non-zero.

import { readFileSync } from "node:fs";
import { join, isAbsolute } from "node:path";
import { createHash } from "node:crypto";
import { STATE_DIR } from "./state-dirs.mjs";
import { verifyChain } from "./record-chain.mjs";
import { verifyReceipt, RECEIPT_TYPE } from "./moorai-receipt.mjs";
import { STATEMENT_TYPE } from "./moorai-attest.mjs";

const KNOWN = ["exposure-ledger.jsonl", "intent-log.jsonl", "action-audit.jsonl", "agent-events.jsonl", "destinations.jsonl"];
const HEX64 = /^[0-9a-f]{64}$/;
const str = (v) => (v == null ? "" : String(v));
// Keyless SHA-256 chain link — the SAME formula as record-chain.mjs chainHash (which is not exported):
// sha256(prev|seq|rhash). Recomputing it needs no key, which is the whole point of the offline check.
const chainHash = (prev, seq, rhash) => createHash("sha256").update(`${str(prev)}|${seq}|${str(rhash)}`, "utf8").digest("hex");

const HELP = `MoorAI verify-chain — tamper-evidence check on the on-device evidence logs.

Usage:
  moorai-verify-chain [name|path] [--format text|json]
  moorai-verify-chain --offline <file> [--pubkey <key|path>] [--format text|json]

With no argument, verifies all known logs under ${STATE_DIR}:
  ${KNOWN.join("  ")}

Reports per log: record count, ok, and any chain breaks (content_altered, chash_mismatch,
prev_mismatch, seq_gap, seq_nonmonotonic, unchained). Nothing leaves the device.

--offline <file>   Validate a portable artifact with no network:
                     * an in-toto attestation (moorai-attest) — keyless SHA-256 chain recompute
                     * a decision receipt / array of receipts (moorai-receipt) — chain + ed25519 signature
--pubkey <key>     PEM or base64 SPKI DER (a value or a file path) to verify a receipt's signature
                   against a PINNED key. Without it, a receipt is checked against its own embedded key
                   (reported unpinned — internal consistency only, not proof of origin).
`;

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }
const fmt = argv.includes("--format") ? argv[argv.indexOf("--format") + 1] : "text";
const pubkeyArg = argv.includes("--pubkey") ? argv[argv.indexOf("--pubkey") + 1] : null;
const offline = argv.includes("--offline") ? argv[argv.indexOf("--offline") + 1] : null;

function readJson(path) { try { return JSON.parse(readFileSync(path, "utf8")); } catch { return undefined; } }
function readJsonl(path) {
  try { return readFileSync(path, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; }
}

// ------------------------------------------------------------------------------------------------
// OFFLINE MODE
// ------------------------------------------------------------------------------------------------

// Flatten an in-toto Statement's byproducts (falling back to subjects) into the content-free chain
// links it carries: { seq, prev, chash, rhash }. Reads only governance metadata and one-way hashes.
function linksFromStatement(st) {
  const bp = st && st.predicate && st.predicate.runDetails && st.predicate.runDetails.byproducts;
  const src = Array.isArray(bp) && bp.length ? bp : (Array.isArray(st && st.subject) ? st.subject : []);
  return src.map((s) => {
    const d = (s && s.digest) || {};
    const a = (s && s.annotations) || {};
    return {
      seq: Number.isInteger(a["moorai.chain.seq"]) ? a["moorai.chain.seq"] : null,
      prev: str(a["moorai.chain.prev"]),
      chash: str(d.sha256 || a["moorai.chain.chash"]),
      rhash: str(d["moorai-record-rhash"])
    };
  });
}

// Keyless continuity check over an attestation's chain links. Fails CLOSED: a chash that does not
// recompute from (prev|seq|rhash), a broken prev-linkage, or a seq gap/duplicate is a break.
function verifyStatementChain(st) {
  const links = linksFromStatement(st);
  const breaks = [];
  let prevChash = null, prevSeq = null;
  for (let idx = 0; idx < links.length; idx++) {
    const r = links[idx];
    if (!HEX64.test(r.chash)) { breaks.push({ index: idx, seq: r.seq, reason: "unchained" }); prevChash = null; prevSeq = null; continue; }
    // rhash present -> we can recompute the link keyless; absent -> continuity-only for this record.
    if (r.rhash && r.seq != null && chainHash(r.prev, r.seq, r.rhash) !== r.chash) breaks.push({ index: idx, seq: r.seq, reason: "chash_mismatch" });
    if (prevSeq !== null) {
      if (r.prev !== prevChash) breaks.push({ index: idx, seq: r.seq, reason: "prev_mismatch" });
      if (r.seq != null && r.seq !== prevSeq + 1) breaks.push({ index: idx, seq: r.seq, reason: r.seq <= prevSeq ? "seq_nonmonotonic" : "seq_gap" });
    }
    prevChash = r.chash; prevSeq = r.seq;
  }
  return { ok: breaks.length === 0, count: links.length, breaks };
}

// Resolve --pubkey: a literal PEM/base64 value, or a path to a file holding one. keyFrom (in
// moorai-receipt via parseTrustedKeys) parses either shape, so pass the raw text through.
function resolvePubkey(arg) {
  if (!arg) return null;
  try { return readFileSync(arg, "utf8"); } catch { return arg; } // a path, else a literal PEM/base64 value
}

function offlineResult(doc) {
  if (doc && doc._type === STATEMENT_TYPE) {
    const v = verifyStatementChain(doc);
    return { kind: "attestation", ok: v.ok, records: v.count, breaks: v.breaks };
  }
  const receipts = Array.isArray(doc) ? doc : [doc];
  const looksReceipt = receipts.length && receipts.every((r) => r && typeof r === "object" && (r.type === RECEIPT_TYPE || (r.payload && "digest" in r)));
  if (!looksReceipt) return { kind: "unknown", ok: false, records: 0, breaks: [{ index: 0, seq: null, reason: "unrecognized_artifact" }] };
  const pubkey = resolvePubkey(pubkeyArg);
  const rows = receipts.map((r, idx) => {
    const res = verifyReceipt(r, pubkey ? { pubkey } : {});
    return { index: idx, seq: r && r.payload ? r.payload.seq : null, ok: res.ok, signed: res.signed, pinned: res.pinned, reason: res.reason };
  });
  const bad = rows.filter((r) => !r.ok);
  return { kind: "receipt", ok: bad.length === 0, records: rows.length, rows, breaks: bad.map((r) => ({ index: r.index, seq: r.seq, reason: r.reason })) };
}

if (offline) {
  const doc = readJson(offline);
  if (doc === undefined) {
    if (fmt === "json") process.stdout.write(JSON.stringify({ kind: "unreadable", ok: false, file: offline }, null, 2) + "\n");
    else process.stdout.write(`✗ ${offline} — unreadable / not JSON\n`);
    process.exit(1);
  }
  const res = offlineResult(doc);
  if (fmt === "json") { process.stdout.write(JSON.stringify({ file: offline, ...res }, null, 2) + "\n"); process.exit(res.ok ? 0 : 1); }
  const status = res.ok ? "OK" : `${res.breaks.length} FAILURE(S)`;
  process.stdout.write(`${res.ok ? "✓" : "✗"} ${offline} — ${res.kind}, ${res.records} record(s), ${status}\n`);
  if (res.kind === "receipt") for (const r of res.rows) process.stdout.write(`    #${r.index} seq ${r.seq}  ${r.ok ? "valid" : "INVALID"}  signed=${r.signed} pinned=${r.pinned}${r.reason ? "  " + r.reason : ""}\n`);
  else for (const b of res.breaks) process.stdout.write(`    seq ${b.seq}  @${b.index}  ${b.reason}\n`);
  process.exit(res.ok ? 0 : 1);
}

// ------------------------------------------------------------------------------------------------
// DEFAULT MODE — on-device evidence logs (unchanged)
// ------------------------------------------------------------------------------------------------
const target = argv.find((a) => !a.startsWith("--") && a !== fmt && a !== pubkeyArg);

function resolveTargets(t) {
  if (!t) return KNOWN.map((n) => ({ name: n, path: join(STATE_DIR, n) }));
  if (isAbsolute(t) || t.includes("/")) return [{ name: t, path: t }];
  const name = t.endsWith(".jsonl") ? t : `${t}.jsonl`;
  return [{ name, path: join(STATE_DIR, name) }];
}

const results = resolveTargets(target).map(({ name, path }) => {
  const rows = readJsonl(path);
  const v = verifyChain(rows);
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
