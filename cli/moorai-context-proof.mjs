#!/usr/bin/env node
// MoorAI — context.tree proofs (cli/context-tree.mjs).
//
//   moorai-context-proof --session <keyed id> --index <n>
//       prints { session, index, size, leaf, leafHash, proof, root } as JSON: the leaf, its RFC 6962 inclusion
//       proof and the current root. --size <m> proves against the root of the first m leaves instead (a root
//       recorded at decision time).
//   moorai-context-proof --verify <file|-> --session <keyed id>     (or --all for every session on the device)
//       the patient-zero lookup: hashes the blob (SHA-256 at 256 bytes or more, the tenant-keyed hash below)
//       and lists every leaf whose blobHash matches, each with its proof and a verified flag.
//   --home <dir> reads ~/.moorai/context-tree under another home.
//
// Output holds hashes only. Leaves never store a source path, URL or content, so nothing here can print one,
// and the --verify argument is never echoed. Exit 0: printed / found; 1: no such leaf / no match; 2: usage.
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { loadSession, listSessions, blobHashOf, leafHash, ContextTree, SHA256_MIN_BYTES } from "./context-tree.mjs";
import { NO_KEY } from "./content-hash.mjs";

const USAGE = "usage: moorai-context-proof --session <keyed id> --index <n> [--size <m>]\n       moorai-context-proof --verify <file|-> (--session <keyed id> | --all)\n       [--home <dir>]";

function parseArgs(argv) {
  const a = { all: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const val = () => { if (i + 1 >= argv.length) throw new Error(`${k} needs a value`); return argv[++i]; };
    if (k === "--session") a.session = val();
    else if (k === "--index") a.index = val();
    else if (k === "--size") a.size = val();
    else if (k === "--verify") a.verify = val();
    else if (k === "--home") a.home = val();
    else if (k === "--all") a.all = true;
    else if (k === "-h" || k === "--help") a.help = true;
    else throw new Error(`unknown argument ${JSON.stringify(k)}`);
  }
  return a;
}
const intArg = (s, name) => { if (!/^\d+$/.test(String(s))) throw new Error(`${name} must be a non-negative integer`); return Number(s); };
const out = (o) => process.stdout.write(JSON.stringify(o, null, 2) + "\n");

function entry(session, s, index, size) {
  const leaf = s.tree.leaves[index];
  const proof = s.tree.proof(index, size);
  const root = s.tree.rootAt(size);
  return { session, index, size, leaf, leafHash: leafHash(leaf).toString("hex"), proof, root, verified: ContextTree.verify(leaf, index, size, proof, root) };
}
const report = (s) => (s.skipped.length || s.tornTail ? { skippedLines: s.skipped.length, tornTail: s.tornTail } : {});

export function main(argv, { stdin = () => readFileSync(0) } = {}) {
  let a;
  try { a = parseArgs(argv); } catch (e) { process.stderr.write(`${e.message}\n${USAGE}\n`); return 2; }
  if (a.help) { process.stdout.write(USAGE + "\n"); return 0; }
  const home = a.home || homedir();
  try {
    if (a.verify !== undefined) {
      if (!a.all && !a.session) throw new Error("--verify needs --session <keyed id> or --all");
      let bytes;
      try { bytes = a.verify === "-" ? stdin() : readFileSync(a.verify); } catch { throw new Error("cannot read the blob to verify"); }
      const want = blobHashOf(bytes);
      // A blob under 256 bytes is matched by its tenant-keyed hash. On a device with no enrollment key every
      // short blob hashes to the NO_KEY sentinel, which would "match" every short leaf: refuse instead.
      if (want.blobHash === NO_KEY) {
        process.stderr.write(`a blob under ${SHA256_MIN_BYTES} bytes is matched by the tenant-keyed hash, and this device has no enrollment key\n`);
        return 1;
      }
      const sessions = a.all ? listSessions({ home }) : [a.session];
      const matches = [], notes = [];
      for (const id of sessions) {
        const s = loadSession(id, { home });
        if (s.skipped.length || s.tornTail) notes.push({ session: id, ...report(s) });
        s.tree.leaves.forEach((l, i) => {
          if (l.blobHash === want.blobHash && l.blobHashKind === want.blobHashKind) matches.push(entry(id, s, i, s.size));
        });
      }
      out({ blobHash: want.blobHash, blobHashKind: want.blobHashKind, size: want.size, sessionsSearched: sessions.length, matches, ...(notes.length ? { sessionsWithSkippedLines: notes } : {}) });
      return matches.length ? 0 : 1;
    }
    if (!a.session || a.index === undefined) throw new Error("need --session and --index, or --verify");
    const index = intArg(a.index, "--index");
    const s = loadSession(a.session, { home });
    const size = a.size === undefined ? s.size : intArg(a.size, "--size");
    if (size > s.size || index >= size) {
      process.stderr.write(`no leaf ${index} in a tree of ${size} (session holds ${s.size})\n`);
      return 1;
    }
    out({ ...entry(a.session, s, index, size), ...report(s) });
    return 0;
  } catch (e) {
    process.stderr.write(`${e.message}\n${USAGE}\n`);
    return 2;
  }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("moorai-context-proof.mjs") || process.argv[1]?.endsWith("moorai-context-proof")) {
  process.exitCode = main(process.argv.slice(2));
}
