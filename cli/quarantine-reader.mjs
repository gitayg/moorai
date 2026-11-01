// The quarantined reader: an outside-origin file (cli/file-origin.mjs) is read by a separate model with no tools,
// and the agent gets a structured summary instead of the file's text.
//
//   extract (cli/quarantine-extract.mjs) -> model (cli/quarantine-model.mjs) -> strict schema
//   (data/quarantine-summary.js validateSummary) -> every detector over the summary's fields -> framed summary
//
// Outcomes: "summarised"; "unsupported" (binary or an unreadable format: the agent is told only that, nothing is
// sent to a model); "withheld" (the summary itself raised a Prompt Injection finding); "no-reader" (no model, a
// refused URL, a timeout or output that fails the schema); "untrusted-reader" (the process that accepted the
// loopback connection runs as the agent's own OS user without the admin's same-user opt-in, fails the same-user
// pins, sits in the agent's process tree, or could not be determined: cli/quarantine-owner.mjs; nothing was sent). The caller fails closed on the last three.
//
// ON DISK (~/.moorai/quarantine, directory 0700, files 0600, swept after 24 h): <sha256(path, mtime, size)>.json
// holds the validated summary fields and sizes; <same>.md is the framed summary a rewritten Read points at. A
// cached summary is re-validated and re-scanned on every use. Never the file's text.
import { createHash, randomBytes } from "node:crypto";
import { statSync, mkdirSync, chmodSync, readdirSync, unlinkSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { join, basename } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { extractText } from "./quarantine-extract.mjs";
import { resolveReader, callReader } from "./quarantine-model.mjs";
import { verifyReaderPeer } from "./quarantine-owner.mjs";
import { validateSummary, summaryScanText, readerMessages, framedSummary, UNSUPPORTED_NOTE } from "../data/quarantine-summary.js";

export const QUARANTINE_DIR = join(STATE_DIR, "quarantine");
export const QUARANTINE_TTL_MS = 24 * 3600 * 1000;
const READER_TIMEOUT_MS = 9000;

const label = (s, n) => String(s || "").replace(/[\u0000-\u001f\u007f​-‏‪-‮⁠-⁤﻿"`<>]/g, "").slice(0, n);
const SOURCE = { quarantine: "a download", "where-froms": "a download", zone: "the Windows Internet zone", "download-dir": "the download folder" };
export function originLabel(o) { return label((o && o.app) || (o && SOURCE[o.source]) || "outside origin", 60); }

function ensureDir(now) {
  mkdirSync(QUARANTINE_DIR, { recursive: true, mode: 0o700 });
  chmodSync(QUARANTINE_DIR, 0o700);
  for (const f of readdirSync(QUARANTINE_DIR)) {
    if (!/^[0-9a-f]{64}\.(?:md|json)$|\.tmp$/.test(f)) continue;
    const p = join(QUARANTINE_DIR, f);
    try { if (now - statSync(p).mtimeMs > QUARANTINE_TTL_MS) unlinkSync(p); } catch { /* raced */ }
  }
}
function writeAtomic(p, text) {
  const tmp = `${p}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  writeFileSync(tmp, text, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, p);
}

// Any injection-class finding (threat category "Prompt Injection") on the summary's own fields, whatever the
// policy's action for it.
export function summaryInjection(engine, s) {
  try { return engine.scan(summaryScanText(s), "file", { inbound: true }).filter((f) => f.threat && f.threat.category === "Prompt Injection").map((f) => f.threat.id); } catch { return [0]; }
}

function result(outcome, fields) { return { outcome, framed: null, file: null, why: "", modelKind: null, format: null, bytes: 0, chars: 0, truncated: false, summaryChars: 0, keyFacts: 0, aiDirected: false, cached: false, ...fields }; }

// path: absolute. origin: fileOrigin's result. -> result(outcome, …). Never throws.
export async function quarantineRead(path, { cfg, engine, origin = null, deadline = Date.now() + READER_TIMEOUT_MS + 1000, now = Date.now(), verifyPeer = verifyReaderPeer, runtimes } = {}) {
  const name = label(basename(path), 120);
  const olabel = originLabel(origin);
  let st;
  try { st = statSync(path); } catch { return result("no-reader", { why: "the file could not be read" }); }
  if (!st.isFile()) return result("unsupported", { framed: framedSummary({ name, origin: olabel, note: UNSUPPORTED_NOTE }) });
  const key = createHash("sha256").update(`${path}\0${st.mtimeMs}\0${st.size}`).digest("hex");
  const jpath = join(QUARANTINE_DIR, `${key}.json`);
  const mpath = join(QUARANTINE_DIR, `${key}.md`);
  try { ensureDir(now); } catch { /* the summary still goes in the deny reason */ }
  const publish = (rec, cached) => {
    const framed = framedSummary({ name, origin: olabel, summary: rec.summary || null, note: rec.note || null, truncated: rec.truncated, chars: rec.chars });
    let file = null;
    try { if (!cached) writeAtomic(jpath, JSON.stringify(rec)); writeAtomic(mpath, framed); file = mpath; } catch { file = null; }
    const s = rec.summary;
    return result(rec.note === UNSUPPORTED_NOTE ? "unsupported" : "summarised", { framed, file, cached, modelKind: rec.modelKind || null, format: rec.format, bytes: rec.bytes, chars: rec.chars, truncated: rec.truncated, summaryChars: s ? s.summary.length : 0, keyFacts: s ? s.keyFacts.length : 0, aiDirected: !!(s && s.aiDirectedText) });
  };
  // A cached summary of this exact file version: re-validated and re-scanned before use.
  try {
    if (now - statSync(jpath).mtimeMs <= QUARANTINE_TTL_MS) {
      const rec = JSON.parse(readFileSync(jpath, "utf8"));
      if (rec && rec.note) return publish({ ...rec, note: rec.note === UNSUPPORTED_NOTE ? UNSUPPORTED_NOTE : "empty file (no text)" }, true);
      const v = rec && validateSummary(JSON.stringify(rec.summary));
      if (v && v.ok && !summaryInjection(engine, v.summary).length) return publish({ ...rec, summary: v.summary }, true);
    }
  } catch { /* no cache */ }
  const x = extractText(path);
  const base = { format: x.format, bytes: x.bytes, chars: x.text.length, truncated: x.truncated };
  if (x.kind !== "text") return publish({ ...base, note: UNSUPPORTED_NOTE }, false);
  if (!x.text.trim()) return publish({ ...base, note: "empty file (no text)" }, false);
  const reader = await resolveReader(cfg, { deadline: Math.min(deadline, Date.now() + 2000), ...(runtimes ? { runtimes } : {}) });
  if (!reader.ok) return result("no-reader", { ...base, why: reader.why, modelKind: reader.kind || null });
  // A loopback reader: the accepting process is checked before the file is sent.
  const verify = reader.kind === "local" ? (c) => verifyPeer({ ...c, sameUser: !!(cfg && cfg.sameUserReader), executables: reader.executables || [], teamIds: reader.teamIds || [] }) : null;
  const reply = await callReader(reader, readerMessages(x.text, randomBytes(8).toString("hex")), { timeoutMs: Math.max(1, Math.min(READER_TIMEOUT_MS, deadline - Date.now())), verify });
  if (!reply.ok) return result(reply.untrusted ? "untrusted-reader" : "no-reader", { ...base, why: reply.why, modelKind: reader.kind });
  const v = validateSummary(reply.content);
  if (!v.ok) return result("no-reader", { ...base, why: `invalid reader output: ${v.why}`, modelKind: reader.kind });
  const inj = summaryInjection(engine, v.summary);
  if (inj.length) return result("withheld", { ...base, why: "summary withheld: it contained instructions", modelKind: reader.kind, injIds: [...new Set(inj)], summaryChars: v.summary.summary.length, keyFacts: v.summary.keyFacts.length, aiDirected: v.summary.aiDirectedText });
  return publish({ ...base, summary: v.summary, modelKind: reader.kind }, false);
}
