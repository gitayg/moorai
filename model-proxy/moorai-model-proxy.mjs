#!/usr/bin/env node
// moorai-model-proxy — a loopback HTTP proxy between an agent's model SDK and the model provider. See
// model-proxy/README.md. The flags, the bind rules and the token rules are moorai-serve's.
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { isLoopback } from "../cli/moorai-serve.mjs";
import { createProxy, DEFAULTS, TOKEN_HEADER } from "./server.mjs";

export const HELP = `moorai-model-proxy — MoorAI between an agent's model SDK and the provider (Anthropic Messages, OpenAI Chat Completions)

  moorai-model-proxy [--mode report|enforce] [--route /prefix=https://upstream]... [--host 127.0.0.1] [--port ${DEFAULTS.port}]
                     [--token-file <path>] [--allow-origin <origin>]... [--allow-remote] [--allow-insecure-upstream] [--max-body <bytes>]
                     [--max-response <bytes>] [--max-inflight <bytes>] [--max-scan-items <n>] [--max-scan-chars <n>] [--timeout-ms <ms>] [--upstream-timeout-ms <ms>]
                     [--policy-file <path>] [--service-id <name>] [--headless-ask deny|allow-with-report] [--cwd <dir>] [--log]

  Point the SDK at it (plain http on loopback; the proxy speaks TLS to the provider):
    ANTHROPIC_BASE_URL=http://127.0.0.1:${DEFAULTS.port}/anthropic      (upstream https://api.anthropic.com)
    OPENAI_BASE_URL=http://127.0.0.1:${DEFAULTS.port}/openai            (upstream https://api.openai.com/v1)
  The client's own API key goes upstream untouched and is never logged, stored or reported.

  --mode report     (default) check and alert; traffic is forwarded unchanged, streaming fully pass-through
  --mode enforce    refuse a request whose content is denied, and withhold a tool call that is denied
  --route P=URL     map a local path prefix to an upstream base URL (repeatable; replaces the defaults)
  --allow-origin    accept this browser Origin besides loopback ones (repeatable); any other Origin is 403
  --token-file      require ${TOKEN_HEADER}: <token> on every request (also MOORAI_MODEL_PROXY_TOKEN);
                    required with --allow-remote; stripped before the upstream
  --max-body        request body cap, default ${DEFAULTS.maxBody} (Anthropic's documented 32 MB); 413 over it
  --max-response    non-streaming response inspection cap, default ${DEFAULTS.maxResponse}
  --max-inflight    total bytes buffered across requests, default ${DEFAULTS.maxInflight}; over it, retryable 529/503
  --max-scan-items  new request items scanned per request, default ${DEFAULTS.maxScanItems}
  --max-scan-chars  characters of one item scanned, default ${DEFAULTS.maxScanChars}; content past either cap is
                    reported unevaluated (report) or refused (enforce)
  --timeout-ms      evaluation budget per request, default ${DEFAULTS.timeoutMs}
  --cwd             directory relative tool-call paths resolve against (default: the proxy's cwd)
  GET /healthz      { status, version, policyId, mode }
`;

export function parseArgs(argv, env = process.env) {
  const o = { ...DEFAULTS, routes: null, allowOrigins: [], allowRemote: false, allowInsecureUpstream: false, log: false, token: "" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i], v = () => { const x = argv[++i]; if (x === undefined) throw new Error(`${a} needs a value`); return x; };
    if (a === "--help" || a === "-h") o.help = true;
    else if (a === "--host") o.host = v();
    else if (a === "--port") o.port = Number(v());
    else if (a === "--mode") o.mode = v();
    else if (a === "--route") {
      const r = v(), eq = r.indexOf("=");
      if (eq < 1 || !r.startsWith("/")) throw new Error(`--route must be /prefix=https://upstream, got ${r.split("=")[0]}`);
      (o.routes ||= {})[r.slice(0, eq)] = r.slice(eq + 1);
    }
    else if (a === "--allow-origin") o.allowOrigins.push(v());
    else if (a === "--token-file") o.token = readFileSync(v(), "utf8").trim();
    else if (a === "--allow-remote") o.allowRemote = true;
    else if (a === "--allow-insecure-upstream") o.allowInsecureUpstream = true;
    else if (a === "--max-body") o.maxBody = Number(v());
    else if (a === "--max-response") o.maxResponse = Number(v());
    else if (a === "--max-inflight") o.maxInflight = Number(v());
    else if (a === "--max-scan-items") o.maxScanItems = Number(v());
    else if (a === "--max-scan-chars") o.maxScanChars = Number(v());
    else if (a === "--timeout-ms") o.timeoutMs = Number(v());
    else if (a === "--upstream-timeout-ms") o.upstreamTimeoutMs = Number(v());
    else if (a === "--policy-file") o.policyFile = resolve(v());
    else if (a === "--service-id") o.serviceId = v();
    else if (a === "--headless-ask") o.headlessAsk = v();
    else if (a === "--cwd") o.cwd = resolve(v());
    else if (a === "--log") o.log = true;
    else throw new Error(`unknown argument ${a}`);
  }
  if (o.help) return o;
  o.routes ||= { ...DEFAULTS.routes };
  if (!o.token && env.MOORAI_MODEL_PROXY_TOKEN) o.token = String(env.MOORAI_MODEL_PROXY_TOKEN).trim();
  if (!["report", "enforce"].includes(o.mode)) throw new Error("--mode must be report or enforce");
  if (!Number.isInteger(o.port) || o.port < 0 || o.port > 65535) throw new Error("--port must be 0-65535");
  for (const [k, min] of [["maxBody", 1024], ["maxResponse", 1024], ["maxInflight", 1048576], ["maxScanItems", 1], ["maxScanChars", 1000], ["timeoutMs", 100], ["upstreamTimeoutMs", 1000]]) {
    if (!Number.isInteger(o[k]) || o[k] < min) throw new Error(`--${k.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)} must be an integer >= ${min}`);
  }
  for (const [prefix, base] of Object.entries(o.routes)) {
    let u;
    try { u = new URL(base); } catch { throw new Error(`route ${prefix}: upstream is not a URL`); }
    if (u.username || u.password || u.search) throw new Error(`route ${prefix}: the upstream URL must not carry credentials or a query string`);
    if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error(`route ${prefix}: upstream must be http(s)`);
    // A bearer key must not cross a network in clear because a proxy was put in front of it (the gateway's rule).
    if (u.protocol === "http:" && !isLoopback(u.hostname) && !o.allowInsecureUpstream) throw new Error(`route ${prefix}: plain http to a non-loopback upstream is refused (--allow-insecure-upstream to override)`);
  }
  if (!isLoopback(o.host)) {
    if (!o.allowRemote) throw new Error(`refusing to listen on ${o.host}: not a loopback address (pass --allow-remote and a token to expose it)`);
    if (!o.token) throw new Error(`refusing to listen on ${o.host} without a token (--token-file or MOORAI_MODEL_PROXY_TOKEN)`);
  }
  if (o.token && o.token.length < 16) throw new Error("the token must be at least 16 characters");
  return o;
}

async function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { process.stderr.write(`moorai-model-proxy: ${e.message}\n`); process.exit(2); }
  if (o.help) { process.stdout.write(HELP); process.exit(0); }
  const s = await createProxy(o);
  // One machine-readable line (a supervisor or a test using --port 0 finds the port). Routes print as
  // origin + path only.
  process.stdout.write(JSON.stringify({ listening: s.url, mode: o.mode, auth: o.token ? "token" : "none", serviceId: s.runtime.settings.serviceId, routes: Object.fromEntries(Object.entries(o.routes).map(([p, b]) => { const u = new URL(b); return [p, `${u.origin}${u.pathname}`]; })) }) + "\n");
  const stop = async () => { await s.close(); process.exit(0); };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
const invoked = (() => { try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (invoked) main();
