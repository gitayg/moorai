#!/usr/bin/env node
// AI Servers live conformance tier: run MoorAI's model proxy and MCP gateway against real software and
// write one signed, content-free conformance report per target and version.
//
//   node scripts/server-conformance.mjs                    plan only: nothing is started
//   node scripts/server-conformance.mjs --live [options]   run it
//   node scripts/server-conformance.mjs --verify <report.json> [--pub <base64 spki>]
//
//   --upstream <url>   the local model server (default http://127.0.0.1:11434, Ollama's default address)
//   --model <name>     the model to use (default: the first of llama3.2:latest, qwen3.5:9b, mistral-nemo:latest
//                      that the server lists)
//   --only <part>      model-proxy | mcp-gateway | sdks | image (repeatable; default all)
//   --out-dir <dir>    where reports go (default ./conformance-out); one file per target: <id>-<version>.json
//   --key <path>       ed25519 signing key (PEM; created 0600 if absent); without it, an ephemeral key
//   --timeout-ms <n>   per model request (default 300000)
//
// Targets:
//   model-proxy-ollama     a real moorai-model-proxy (--mode enforce) in front of a real Ollama, through
//                          Ollama's OpenAI-compatible, Anthropic-compatible and native APIs, plus the
//                          Responses API the proxy forwards unparsed (recorded as a gap)
//   mcp-gateway-mcp-sdk    the official MCP TypeScript SDK as client and as server, through the real gateway
//   sdk-*                  the official provider SDKs: recorded as installed or not; the tier installs nothing
//   server-image-amd64     the linux/amd64 server image: recorded as present or not; the tier pulls nothing
// No paid provider is called and no API key is read. Exit 1 when any case that ran failed.
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir, platform, arch } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SERVER_REPORT_TYPE, buildReport, signReport, verifyReport, loadOrCreateKey, ephemeralKey } from "../cli/conformance-report.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MOORAI = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;
const PARTS = ["model-proxy", "mcp-gateway", "sdks", "image"];

export function parseArgs(argv) {
  const a = { live: false, upstream: "http://127.0.0.1:11434", model: null, only: [], outDir: "conformance-out", key: null, timeoutMs: 300000, verify: null, pub: null };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === "--live") a.live = true;
    else if (k === "--upstream") a.upstream = String(argv[++i]).replace(/\/$/, "");
    else if (k === "--model") a.model = argv[++i];
    else if (k === "--only") { const p = argv[++i]; if (!PARTS.includes(p)) throw new Error(`--only takes ${PARTS.join(" | ")}`); a.only.push(p); }
    else if (k === "--out-dir") a.outDir = argv[++i];
    else if (k === "--key") a.key = argv[++i];
    else if (k === "--timeout-ms") a.timeoutMs = Number(argv[++i]);
    else if (k === "--verify") a.verify = argv[++i];
    else if (k === "--pub") a.pub = argv[++i];
    else throw new Error(`unknown argument ${k}`);
  }
  return a;
}

function plan(a) {
  const want = (p) => !a.only.length || a.only.includes(p);
  const lines = ["server-conformance: plan only (pass --live to run; nothing was started)"];
  if (want("model-proxy")) lines.push(`  model-proxy-ollama   moorai-model-proxy --mode enforce in front of ${a.upstream} (OpenAI-compatible, Anthropic-compatible, native and Responses paths)`);
  if (want("mcp-gateway")) lines.push("  mcp-gateway-mcp-sdk  official MCP TypeScript SDK client and server through moorai-mcp-gateway");
  if (want("sdks")) lines.push("  sdk-*                official provider SDKs: recorded as installed or not (nothing installed)");
  if (want("image")) lines.push("  server-image-amd64   linux/amd64 server image: recorded as present or not (nothing pulled)");
  return lines.join("\n") + "\n";
}

export async function run(argv) {
  const a = parseArgs(argv);
  if (a.verify) {
    const r = verifyReport(JSON.parse(readFileSync(a.verify, "utf8")), { pub: a.pub });
    return { code: r.ok ? 0 : 1, out: JSON.stringify(r) + "\n" };
  }
  if (!a.live) return { code: 0, out: plan(a) };
  const want = (p) => !a.only.length || a.only.includes(p);
  const key = a.key ? loadOrCreateKey(a.key) : ephemeralKey();
  const scratch = mkdtempSync(join(tmpdir(), "moorai-server-conformance-"));
  mkdirSync(a.outDir, { recursive: true });
  const targets = [];
  try {
    if (want("model-proxy")) { const { runModelProxyTarget } = await import("./conformance/model-proxy-cases.mjs"); targets.push(await runModelProxyTarget({ upstream: a.upstream, model: a.model, scratch, timeoutMs: a.timeoutMs })); }
    if (want("mcp-gateway")) { const { runMcpSdkGatewayTarget } = await import("./conformance/mcp-sdk-gateway.mjs"); targets.push(await runMcpSdkGatewayTarget()); }
    const rows = await import("./conformance/server-rows.mjs");
    if (want("sdks")) targets.push(...rows.sdkTargets());
    if (want("image")) targets.push(rows.imageTarget());
  } finally { rmSync(scratch, { recursive: true, force: true }); }
  const lines = [];
  let failed = false;
  for (const t of targets) {
    const rep = signReport(buildReport({ type: SERVER_REPORT_TYPE, targets: [t], moorai: MOORAI, platform: { os: platform(), arch: arch(), node: process.versions.node } }), key, { ephemeral: !a.key });
    const tt = rep.targets[0];
    writeFileSync(join(a.outDir, `${tt.id}-${tt.version || "unknown"}.json`), JSON.stringify(rep, null, 2) + "\n");
    if (tt.cases.some((x) => x.status === "fail")) failed = true;
    lines.push(`${tt.id.padEnd(24)} ${String(tt.version || "-").padEnd(12)} ${tt.ran ? "ran" : "not run"}${tt.reason ? ` (${tt.reason})` : ""}${tt.modelName ? ` model=${tt.modelName}` : ""}  ${tt.cases.map((x) => `${x.id}:${x.status}`).join(" ")}`);
  }
  return { code: failed ? 1 : 0, out: lines.join("\n") + "\n" };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === realpathSync(process.argv[1])) {
  run(process.argv.slice(2)).then(({ code, out }) => { process.stdout.write(out); process.exit(code); }, (e) => { process.stderr.write(`server-conformance: ${e && e.stack || e}\n`); process.exit(2); });
}
