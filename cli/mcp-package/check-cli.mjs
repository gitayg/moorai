// The moorai-mcp-check command line (cli/moorai-mcp-check.mjs runs it). Exported so tests drive it
// in-process with a fake registry.

import { readFileSync } from "node:fs";
import { parseCheckSpec } from "./check-spec.mjs";
import { mcpCheck } from "./check.mjs";
import { renderCheck } from "./check-render.mjs";

const USAGE = "usage: moorai-mcp-check <package> [--json] [--policy file.json | --no-policy] [--tools tools-list.json]\n"
  + "  <package>: npm:name[@version] | pypi:name[==version] | name[@version] (npm) | \"npx -y name@1.2.3\" | https://host/mcp\n";

function readJsonFile(p) { return JSON.parse(readFileSync(p, "utf8")); }

async function devicePolicy() {
  try {
    const { loadConfig } = await import("../config.mjs");
    const { loadPolicyReadOnly } = await import("../doctor-policy.mjs");
    const r = loadPolicyReadOnly(loadConfig(), { offline: true });
    return r && r.policy && typeof r.policy === "object" ? r.policy : null;
  } catch { return null; }
}

async function systemDoc() {
  try {
    const { readRootOwned } = await import("../hook-core.mjs");
    const { systemConfigPath } = await import("../server-mode.mjs");
    const t = readRootOwned(systemConfigPath());
    return t ? JSON.parse(t) : null;
  } catch { return null; }
}

export async function runMcpCheck(argv = process.argv.slice(2), { out = process.stdout, err = process.stderr, fetchImpl } = {}) {
  let json = false, policyFile = null, noPolicy = false, toolsFile = null;
  const pos = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") json = true;
    else if (a === "--no-policy") noPolicy = true;
    else if (a === "--policy") policyFile = argv[++i];
    else if (a === "--tools") toolsFile = argv[++i];
    else if (a === "-h" || a === "--help") { out.write(USAGE); return 0; }
    else if (a.startsWith("--")) { err.write(`unknown option ${a}\n${USAGE}`); return 2; }
    else pos.push(a);
  }
  if (pos.length !== 1) { err.write(USAGE); return 2; }
  const spec = parseCheckSpec(pos[0]);
  if (spec.error) { err.write(`moorai-mcp-check: ${spec.error}\n${USAGE}`); return 2; }
  let policy = null, tools = null;
  try {
    if (policyFile) policy = readJsonFile(policyFile);
    if (toolsFile) tools = readJsonFile(toolsFile);
  } catch (e) { err.write(`moorai-mcp-check: cannot read ${policyFile && !policy ? "--policy" : "--tools"} file as JSON\n`); return 2; }
  if (!policyFile && !noPolicy) policy = await devicePolicy();
  const system = noPolicy || policyFile ? null : await systemDoc();
  const report = await mcpCheck(spec, { policy, system, tools, ...(fetchImpl ? { fetchImpl } : {}) });
  out.write(json ? JSON.stringify(report, null, 2) + "\n" : renderCheck(report));
  return report.summary.fail ? 1 : 0;
}

