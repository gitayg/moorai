#!/usr/bin/env node
// moorai-allow — grant a narrow, time-boxed local exception (cli/exceptions.mjs explains the model).
//
//   sudo moorai-allow --threat 57 --pattern 'curl -sSo /tmp/u.sh *' --for 1h [--note "why"]
//   sudo moorai-allow --rule no-net-after-private --pattern 'git push origin *' --for 30m
//   moorai-allow --list
//   sudo moorai-allow --revoke <id>
//
// A person's command, not the agent's: it refuses to run without an interactive terminal on both stdin
// and stdout, and it writes /etc/moorai/exceptions.json (%ProgramData%\MoorAI\exceptions.json), which the
// hook only reads when the file is root-owned (Administrators/SYSTEM-only on Windows) — so a grant needs
// root. Every grant is narrow (one threat or rule id per entry plus a pattern with at least four literal
// characters) and expires (at most 24 hours). The hook records each grant it sees, and each use, in the
// action ledger. Exit codes: 0 done, 1 refused / invalid, 2 no interactive terminal.
import { readFileSync, writeFileSync, renameSync, mkdirSync, chmodSync } from "node:fs";
import { dirname } from "node:path";
import { randomBytes } from "node:crypto";
import os from "node:os";
import { createInterface } from "node:readline";
import { EXCEPTIONS_FILE, DEFAULT_TTL_MS, MAX_TTL_MS, parseDuration, patternProblem, addExceptions, revokeException, normaliseException } from "./exceptions.mjs";
import { readRootOwned } from "./hook-core.mjs";

function parseArgs(argv) {
  const o = { threats: [], rules: [], pattern: null, ttl: null, note: "", list: false, revoke: null, yes: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i], v = () => argv[++i];
    if (a === "--threat") o.threats.push(Number(v()));
    else if (a === "--rule") o.rules.push(String(v() ?? ""));
    else if (a === "--pattern" || a === "--path") o.pattern = v() ?? "";
    else if (a === "--for") o.ttl = v() ?? "";
    else if (a === "--note") o.note = String(v() ?? "").slice(0, 200);
    else if (a === "--list") o.list = true;
    else if (a === "--revoke") o.revoke = v() ?? "";
    else if (a === "-h" || a === "--help") o.help = true;
    else return { error: `unknown argument: ${a}` };
  }
  return o;
}
const USAGE = "usage: sudo moorai-allow (--threat <id> | --rule <id>)... --pattern '<glob>' [--for 1h] [--note <text>]\n       moorai-allow --list\n       sudo moorai-allow --revoke <id>";

function readStore() { try { return JSON.parse(readFileSync(EXCEPTIONS_FILE, "utf8")); } catch { return { version: 1, exceptions: [] }; } }
function writeStore(doc) {
  mkdirSync(dirname(EXCEPTIONS_FILE), { recursive: true, mode: 0o755 });
  const tmp = `${EXCEPTIONS_FILE}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(doc, null, 2) + "\n", { mode: 0o644 });
  chmodSync(tmp, 0o644);
  renameSync(tmp, EXCEPTIONS_FILE);
}
function ask(q) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((r) => rl.question(q, (a) => { rl.close(); r(a); }));
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  if (o.error || o.help) { process.stderr.write(`${o.error ? `moorai-allow: ${o.error}\n` : ""}${USAGE}\n`); return o.error ? 1 : 0; }
  if (o.list) {
    const now = Date.now();
    const doc = (() => { try { return JSON.parse(readRootOwned(EXCEPTIONS_FILE) || "null"); } catch { return null; } })();
    const live = (doc && Array.isArray(doc.exceptions) ? doc.exceptions : []).map((e) => normaliseException(e, { now, local: true })).filter(Boolean);
    if (!live.length) process.stdout.write(`no live local exceptions in ${EXCEPTIONS_FILE}\n`);
    for (const e of live) process.stdout.write(`${e.id}  ${e.threat ? `threat #${e.threat}` : `rule ${e.rule}`}  pattern ${JSON.stringify(e.pattern)}  expires ${new Date(e.expires).toISOString()}\n`);
    return 0;
  }
  // A person at a terminal. The agent's shell tool has none; this is the first gate, not the boundary
  // (the root-owned store is): a pseudo-terminal can be made, sudo's password cannot be guessed.
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    process.stderr.write("moorai-allow: refused — run this yourself in an interactive terminal, not through an agent.\n");
    return 2;
  }
  if (process.platform !== "win32" && typeof process.getuid === "function" && process.getuid() !== 0) {
    process.stderr.write(`moorai-allow: refused — exceptions live in ${EXCEPTIONS_FILE}, which only root can write. Run it with sudo.\n`);
    return 1;
  }
  if (o.revoke !== null) {
    writeStore(revokeException(readStore(), o.revoke));
    process.stdout.write(`revoked ${o.revoke}\n`);
    return 0;
  }
  const bad = (m) => { process.stderr.write(`moorai-allow: ${m}\n${USAGE}\n`); return 1; };
  if (!o.threats.length && !o.rules.length) return bad("name at least one --threat or --rule");
  if (o.threats.some((n) => !Number.isInteger(n) || n <= 0 || n >= 1000)) return bad("--threat takes a threat id (a positive integer)");
  const pp = patternProblem(o.pattern);
  if (pp) return bad(pp);
  const ttl = o.ttl === null ? DEFAULT_TTL_MS : parseDuration(o.ttl);
  if (!Number.isFinite(ttl) || ttl <= 0) return bad("--for takes a duration such as 30m, 1h or 8h");
  if (ttl > MAX_TTL_MS) return bad("--for is at most 24h");
  const created = new Date(), expires = new Date(created.getTime() + ttl);
  const by = process.env.SUDO_USER || os.userInfo().username;
  const entries = [...o.threats.map((threat) => ({ threat })), ...o.rules.map((rule) => ({ rule }))].map((x) => ({ id: `ex-${randomBytes(5).toString("hex")}`, ...x, pattern: o.pattern, created: created.toISOString(), expires: expires.toISOString(), by, ...(o.note ? { note: o.note } : {}) }));
  for (const e of entries) if (!normaliseException(e, { local: true })) return bad(`invalid exception: ${e.rule ? `rule ${JSON.stringify(e.rule)}` : `threat ${e.threat}`}`);
  process.stdout.write(`About to allow, until ${expires.toISOString()}:\n${entries.map((e) => `  ${e.threat ? `threat #${e.threat}` : `rule ${e.rule}`} for calls matching ${JSON.stringify(o.pattern)}`).join("\n")}\n`);
  const a = (await ask("Allow? [y/N] ")).trim().toLowerCase();
  if (a !== "y" && a !== "yes") { process.stdout.write("nothing granted\n"); return 1; }
  writeStore(addExceptions(readStore(), entries));
  if (!readRootOwned(EXCEPTIONS_FILE)) process.stderr.write(`moorai-allow: warning — ${EXCEPTIONS_FILE} is not protected (root-owned / Administrators-only), so the hook will ignore it.\n`);
  process.stdout.write(`granted ${entries.map((e) => e.id).join(", ")}. The hook honours it only where local exceptions are switched on ("localExceptions": "allow").\n`);
  return 0;
}
main().then((c) => { process.exitCode = c; });
