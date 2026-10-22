#!/usr/bin/env node
// moorai-windows-validate — runs the agent's enforced surfaces on this machine (the hook, the PowerShell tool
// path, the MCP gateway, the egress rules and proxy, MXC detection and enforcement) against a loopback
// console and throwaway home directories, and writes a content-free report: probe ids, outcomes, counts,
// the Windows build. Built for a Windows box; on macOS and Linux the Windows-only probes are skipped.
//
//   node cli/moorai-windows-validate.mjs [--out report.json] [--strict] [--require-windows] [--only id,id] [--json]
//
// Needs only Node and this agent tree. It reads one registry value, starts local processes on 127.0.0.1,
// and never touches the operator's own MoorAI state, policy or console.
import { writeFileSync } from "node:fs";
import { runValidation, PROBE_IDS } from "./windows-validate-probes.mjs";
import { formatText, strictExitCode } from "./windows-validate-report.mjs";

const USAGE = `usage: moorai-windows-validate [--out <file>] [--strict] [--require-windows] [--only <id,id>] [--json]
  --out <file>        write the JSON report there (default moorai-windows-validation.json)
  --strict            exit 1 unless the verdict is pass
  --require-windows   a Windows-only probe that was skipped makes the verdict incomplete
  --only <ids>        run only these probes: ${PROBE_IDS.join(", ")}
  --json              print the JSON report instead of the text summary`;

function parseArgs(argv) {
  const o = { out: "moorai-windows-validation.json", strict: false, requireWindows: false, only: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--out") o.out = next();
    else if (a === "--strict") o.strict = true;
    else if (a === "--require-windows") o.requireWindows = true;
    else if (a === "--only") o.only = next().split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--json") o.json = true;
    else if (a === "--help" || a === "-h") o.help = true;
    else throw new Error(`unknown argument '${a}'`);
  }
  if (o.only) for (const id of o.only) if (!PROBE_IDS.includes(id)) throw new Error(`unknown probe '${id}'`);
  return o;
}

let opts;
try { opts = parseArgs(process.argv.slice(2)); }
catch (e) { process.stderr.write(`moorai-windows-validate: ${e.message}\n${USAGE}\n`); process.exit(2); }
if (opts.help) { process.stdout.write(USAGE + "\n"); process.exit(0); }

const report = await runValidation({ requireWindows: opts.requireWindows, only: opts.only });
writeFileSync(opts.out, JSON.stringify(report, null, 2) + "\n");
process.stdout.write(opts.json ? JSON.stringify(report, null, 2) + "\n" : formatText(report) + `report: ${opts.out}\n`);
process.exit(opts.strict ? strictExitCode(report) : 0);
