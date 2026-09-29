#!/usr/bin/env node
// moorai-doctor — is MoorAI actually protecting this machine? Read-only: it never changes settings,
// policy, keys or state, and never posts to a console. Secrets appear only as present/absent or a
// short sha256 fingerprint.
//
//   moorai-doctor               human-readable report
//   moorai-doctor --json        machine-readable report
//   moorai-doctor --offline     skip every network call (console check, live policy fetch)
//   moorai-doctor --no-selftest skip the live hook self-test
//
// Exit 0 when no check failed, 1 otherwise.
import { runDoctor, formatHuman } from "./doctor-report.mjs";

const HELP = `usage: moorai-doctor [--json] [--offline] [--no-selftest]

Checks whether MoorAI is registered in each agent host, enrolled, running a verified policy, and
actually deciding (a live self-test of the hook in a sandbox copy of this device's state).
Read-only. Exit 0 if no check failed, 1 otherwise.`;

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("-h") || args.includes("--help")) { console.log(HELP); return 0; }
  const unknown = args.filter((a) => !["--json", "--offline", "--no-selftest"].includes(a));
  if (unknown.length) { console.error(`moorai-doctor: unknown argument ${unknown[0]}\n${HELP}`); return 2; }
  const r = await runDoctor({ offline: args.includes("--offline"), selftest: !args.includes("--no-selftest") });
  process.stdout.write((args.includes("--json") ? JSON.stringify(r, null, 2) : formatHuman(r)) + "\n");
  return r.exitCode;
}

main().then((code) => process.exit(code), (e) => { console.error(`moorai-doctor: ${e && e.stack || e}`); process.exit(1); });
