// The moorai-model-scan command (cli/moorai-model-scan.mjs is the entry point). Kept apart so tests can
// call run() in-process.
import { readFileSync } from "node:fs";
import { scanModelPath, verdictCounts, SCAN_LIMITS } from "./model-scan.mjs";
import { modelScanPolicy } from "./model-scan-posture.mjs";

const USAGE = "usage: moorai-model-scan <path|dir> [--json] [--allow <sha256>]... [--policy file.json] [--max-files N] [--max-gib N]";

export function parseArgs(argv) {
  const o = { path: null, json: false, allow: [], policy: null, maxFiles: null, maxGiB: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") o.json = true;
    else if (a === "--allow") o.allow.push(argv[++i]);
    else if (a === "--policy") o.policy = argv[++i];
    else if (a === "--max-files") o.maxFiles = Number(argv[++i]);
    else if (a === "--max-gib") o.maxGiB = Number(argv[++i]);
    else if (a === "-h" || a === "--help") return { help: true };
    else if (a.startsWith("-")) return { error: `unknown option ${a}` };
    else if (!o.path) o.path = a;
    else return { error: "one path at a time" };
  }
  if (!o.path) return { error: "a path is required" };
  for (const h of o.allow) if (!/^[0-9a-fA-F]{64}$/.test(String(h || ""))) return { error: "--allow takes a sha256 (64 hex characters)" };
  if (o.maxFiles != null && !(Number.isInteger(o.maxFiles) && o.maxFiles > 0)) return { error: "--max-files takes a positive integer" };
  if (o.maxGiB != null && !(o.maxGiB > 0)) return { error: "--max-gib takes a positive number" };
  return o;
}

const LABEL = { unsafe: "UNSAFE", suspicious: "SUSPICIOUS", clean: "clean", allowed: "allowed", unscanned: "unscanned" };

export function run(argv = process.argv.slice(2), { out = (s) => process.stdout.write(s), err = (s) => process.stderr.write(s) } = {}) {
  const o = parseArgs(argv);
  if (o.help) { out(`${USAGE}\n`); return 0; }
  if (o.error) { err(`moorai-model-scan: ${o.error}\n${USAGE}\n`); return 2; }
  let allow = new Set(o.allow.map((h) => h.toLowerCase()));
  if (o.policy) {
    let pol;
    try { pol = JSON.parse(readFileSync(o.policy, "utf8")); } catch { err(`moorai-model-scan: cannot read policy ${o.policy}\n`); return 2; }
    allow = new Set([...allow, ...modelScanPolicy(pol).allowHashes]);
  }
  const limits = { ...SCAN_LIMITS, ...(o.maxFiles ? { maxFiles: o.maxFiles } : {}), ...(o.maxGiB ? { maxTotalBytes: o.maxGiB * 1024 ** 3 } : {}) };
  const r = scanModelPath(o.path, { allowHashes: allow, limits });
  if (r.missing) { err(`moorai-model-scan: no such file or directory: ${o.path}\n`); return 2; }
  const summary = verdictCounts(r.results);
  const capped = Object.entries(r.truncated).filter(([, v]) => v).map(([k]) => k);
  if (o.json) {
    out(`${JSON.stringify({ tool: "moorai-model-scan", results: r.results, summary, truncated: capped }, null, 2)}\n`);
  } else {
    for (const f of r.results) {
      out(`${(LABEL[f.verdict] || f.verdict).padEnd(10)} ${String(f.format || "-").padEnd(14)} ${String(f.severity || "-").padEnd(8)} ${f.path}\n`);
      if (f.sha256) out(`           sha256 ${f.sha256}\n`);
      for (const x of f.findings) {
        if (f.verdict === "clean" && x.severity === "info") continue;
        out(`           ${x.class} (${x.severity})${x.count > 1 ? ` x${x.count}` : ""}${x.details && x.details.length ? `: ${x.details.slice(0, 5).join("; ")}` : ""}\n`);
      }
    }
    out(`\n${summary.scanned} file(s): ${summary.unsafe} unsafe, ${summary.suspicious} suspicious, ${summary.clean} clean, ${summary.allowed} allowed, ${summary.unscanned} unscanned${capped.length ? ` (walk capped: ${capped.join(", ")})` : ""}\n`);
    out("Static analysis only: a backdoor that triggers on certain inputs, or trojaned weights, is not detectable this way.\n");
  }
  return summary.unsafe || summary.suspicious ? 1 : 0;
}
