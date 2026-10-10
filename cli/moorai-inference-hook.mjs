#!/usr/bin/env node
// moorai-inference-hook — MoorAI as the AI security server for Claude Enterprise Inference hooks (beta).
// Anthropic POSTs each governed prompt from claude.ai, Claude Code and Cowork (and, with Validate tool
// calls on, each tool call frame) to this server, signed per Standard Webhooks, and holds the request for
// an allow / deny verdict. Protocol: platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint.
//
//   moorai-inference-hook serve [--host 127.0.0.1] [--port 8792] [--allow-remote]
//        [--secret-file <path>]            signing secret(s), "whsec_…", whitespace-separated (previous +
//                                          current during a rotation); else MOORAI_INFERENCE_HOOK_SECRET
//        [--fail open|closed]              a frame MoorAI authenticated but could not judge in full
//                                          (default open: Anthropic's own default failure handling is
//                                          "Allow the request")
//        [--shadow]                        always answer allow; report what would have been denied
//        [--policy-file <path>] [--service-id <name>] [--headless-ask deny|allow-with-report]
//        [--max-body 67108864] [--max-inflight 268435456] [--eval-timeout-ms 4000]
//        [--max-connections 128] [--log]
//   moorai-inference-hook test [--url http://127.0.0.1:8792/] [--secret-file <path>] [--shadow] [--json]
//        sends signed sample frames (a connection test, a clean prompt, a reverse shell as a prompt and as
//        a tool call) and the requests the server must refuse; exit 1 when any answer is not the expected one
//
// Policy and console binding as every server component reads them (cli/server-mode.mjs): the verified
// console policy, the root-owned /etc/moorai/config.json, MOORAI_SERVER_URL / MOORAI_TENANT /
// MOORAI_INSTALL_TOKEN. Alerts are content-free. Nothing is written to disk.
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { isLoopback } from "./moorai-serve.mjs";
import { parseSecrets } from "./inference-hook/signature.mjs";
import { createServer, DEFAULTS, PROTOCOL_MAX_BODY } from "./inference-hook/server.mjs";
import { runCases } from "./inference-hook/samples.mjs";

export const SECRET_ENV = "MOORAI_INFERENCE_HOOK_SECRET";

function readSecret(file, env) {
  if (file) return readFileSync(file, "utf8");
  if (env[SECRET_ENV]) return String(env[SECRET_ENV]);
  throw new Error(`a signing secret is required: --secret-file <path> or ${SECRET_ENV}`);
}

export function parseArgs(argv, env = process.env) {
  const [cmd, ...rest] = argv;
  if (cmd !== "serve" && cmd !== "test") throw new Error("usage: moorai-inference-hook serve|test [options]");
  const o = cmd === "serve" ? { cmd, ...DEFAULTS, allowRemote: false, log: false } : { cmd, url: `http://127.0.0.1:${DEFAULTS.port}/`, shadow: false, json: false };
  let secretFile;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i], v = () => { const x = rest[++i]; if (x === undefined) throw new Error(`${a} needs a value`); return x; };
    const num = () => { const n = Number(v()); if (!Number.isInteger(n)) throw new Error(`${a} needs an integer`); return n; };
    if (a === "--secret-file") secretFile = v();
    else if (cmd === "test" && a === "--url") o.url = v();
    else if (cmd === "test" && a === "--shadow") o.shadow = true;
    else if (cmd === "test" && a === "--json") o.json = true;
    else if (cmd === "serve" && a === "--host") o.host = v();
    else if (cmd === "serve" && a === "--port") o.port = num();
    else if (cmd === "serve" && a === "--allow-remote") o.allowRemote = true;
    else if (cmd === "serve" && a === "--fail") o.fail = v();
    else if (cmd === "serve" && a === "--shadow") o.mode = "shadow";
    else if (cmd === "serve" && a === "--policy-file") o.policyFile = resolve(v());
    else if (cmd === "serve" && a === "--service-id") o.serviceId = v();
    else if (cmd === "serve" && a === "--headless-ask") o.headlessAsk = v();
    else if (cmd === "serve" && a === "--max-body") o.maxBody = num();
    else if (cmd === "serve" && a === "--max-inflight") o.maxInflight = num();
    else if (cmd === "serve" && a === "--eval-timeout-ms") o.evalTimeoutMs = num();
    else if (cmd === "serve" && a === "--max-connections") o.maxConnections = num();
    else if (cmd === "serve" && a === "--log") o.log = true;
    else throw new Error(`unknown argument ${a}`);
  }
  o.secret = readSecret(secretFile, env);
  o.keys = parseSecrets(o.secret);
  if (cmd === "test") return o;
  if (o.fail !== "open" && o.fail !== "closed") throw new Error("--fail must be open or closed");
  if (o.port < 0 || o.port > 65535) throw new Error("--port must be 0-65535");
  if (o.maxBody < 1024 || o.maxBody > PROTOCOL_MAX_BODY) throw new Error(`--max-body must be 1024-${PROTOCOL_MAX_BODY} (the protocol allows bodies up to 64 MiB)`);
  if (o.maxInflight < o.maxBody) throw new Error("--max-inflight must be at least --max-body");
  if (o.evalTimeoutMs < 100 || o.evalTimeoutMs > 10000) throw new Error("--eval-timeout-ms must be 100-10000 (Anthropic's verdict timeout is 1-10000 ms, 5000 by default)");
  if (o.maxConnections < 1) throw new Error("--max-connections must be at least 1");
  if (!isLoopback(o.host) && !o.allowRemote) throw new Error(`refusing to listen on ${o.host}: not a loopback address (terminate TLS in a proxy on this host, or pass --allow-remote)`);
  return o;
}

async function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { process.stderr.write(`moorai-inference-hook: ${e.message}\n`); process.exit(2); }
  if (o.cmd === "test") {
    const results = await runCases(o.url, o.secret, { shadow: o.shadow });
    if (o.json) process.stdout.write(JSON.stringify(results, null, 2) + "\n");
    else for (const r of results) process.stdout.write(`${r.ok ? "PASS" : "FAIL"}  ${r.name}: HTTP ${r.status}${r.action ? ` ${r.action}` : ""} (expected HTTP ${r.expect.status}${r.expect.action ? ` ${r.expect.action}` : ""})\n`);
    process.exit(results.every((r) => r.ok) ? 0 : 1);
  }
  const { secret, keys, ...opts } = o;
  const s = await createServer({ ...opts, keys });
  if (!isLoopback(o.host)) process.stderr.write("moorai-inference-hook: listening on a non-loopback address in plain HTTP; transcripts cross the network in clear unless TLS is terminated in front of this port on the same host or pod\n");
  process.stdout.write(JSON.stringify({ listening: s.url, mode: o.mode, fail: o.fail, secrets: keys.length, serviceId: s.runtime.settings.serviceId }) + "\n");
  const stop = async () => { await s.close(); process.exit(0); };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
const invoked = (() => { try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (invoked) main();
