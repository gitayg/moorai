#!/usr/bin/env node
// moorai-model-proxy — a loopback HTTP proxy between an agent's model SDK and the model provider. See
// model-proxy/README.md. The flags, the bind rules and the token rules are moorai-serve's.
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { isLoopback } from "../cli/moorai-serve.mjs";
import { createProxy, DEFAULTS, TOKEN_HEADER, HOP, defaultRoutes } from "./server.mjs";
import { loadBindings } from "./credentials.mjs";
import { PROVIDERS as FILE_SCAN_PROVIDERS } from "../cli/file-scan-policy.mjs";

export const HELP = `moorai-model-proxy — MoorAI between an agent's model SDK and the provider (Anthropic Messages, OpenAI Chat Completions, Gemini generateContent, Ollama /api/chat and /api/generate)

  moorai-model-proxy [--mode report|enforce] [--route /prefix=https://upstream]... [--host 127.0.0.1] [--port ${DEFAULTS.port}]
                     [--token-file <path>] [--allow-origin <origin>]... [--allow-remote] [--allow-insecure-upstream] [--max-body <bytes>]
                     [--max-response <bytes>] [--max-inflight <bytes>] [--max-scan-items <n>] [--max-scan-chars <n>] [--timeout-ms <ms>] [--upstream-timeout-ms <ms>]
                     [--connect-timeout <ms>]
                     [--policy-file <path>] [--service-id <name>] [--headless-ask deny|allow-with-report] [--cwd <dir>] [--log]
                     [--credentials <file>] [--require-placeholders] [--denied-tool-call refuse|replace]
                     [--unchecked-window-ms <ms>] [--unchecked-max <n>] [--intent-key-file <path>]
                     [--file-scan-key-file metadefender|virustotal=<path>]...

  Point the SDK at it (plain http on loopback; the proxy speaks TLS to the provider):
    ANTHROPIC_BASE_URL=http://127.0.0.1:${DEFAULTS.port}/anthropic      (upstream https://api.anthropic.com)
    OPENAI_BASE_URL=http://127.0.0.1:${DEFAULTS.port}/openai            (upstream https://api.openai.com/v1)
    GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:${DEFAULTS.port}/gemini     (upstream https://generativelanguage.googleapis.com; the SDK
                                                                appends /v1beta/models/<model>:generateContent)
    OLLAMA_HOST=http://127.0.0.1:${DEFAULTS.port}/ollama                (upstream http://127.0.0.1:11434, Ollama's default; ollama-python
                                                                reads OLLAMA_HOST, ollama-js takes new Ollama({ host }); a default
                                                                on a loopback bind only)
  Gemini and Ollama paths are parsed on any route (a Vertex AI endpoint, or Ollama on another port, is a --route).
  The client's own API key goes upstream untouched and is never logged, stored or reported — unless
  --credentials is given: then the agent holds a placeholder (moorai-ph:<name>) and the proxy swaps in the
  real key on the one route it is bound to (see README "Placeholder credentials").

  --mode report     (default) check and alert; traffic is forwarded unchanged, streaming fully pass-through
  --mode enforce    refuse a request whose content is denied, and withhold a tool call that is denied
  --denied-tool-call refuse   (default) with --mode enforce: a response with a denied tool call is refused
                              (403, or the provider's error event mid-stream)
  --denied-tool-call replace  with --mode enforce: the turn's tool calls are withheld and replaced by a text
                              block saying why; stop_reason end_turn / finish_reason stop
  --unchecked-window-ms  the skip alert (off by default): alert on a forwarded tool call that no framework
                    check matched within this window (moorai-serve --model-proxy-url reports the checks)
  --unchecked-max   forwarded tool call ids tracked at once, default ${DEFAULTS.uncheckedMax}
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
  --connect-timeout upstream connect budget in ms (TCP connect, and the TLS handshake for https), default
                    ${DEFAULTS.connectTimeoutMs}; past it the request is answered 504
  --cwd             directory relative tool-call paths resolve against (default: the proxy's cwd)
  --credentials     placeholder bindings file (also MOORAI_MODEL_PROXY_CREDENTIALS); refused if group- or
                    world-writable or owned by another non-root user
  --require-placeholders  with --credentials: refuse (401) a raw credential instead of reporting it
  --intent-key-file the HMAC key for intent alignment (64 hex characters, root-owned, not group- or world-
                    writable), so several proxies hash alike; default a random key per process
  --file-scan-key-file  a cloud file-scanning provider's API key, first line of a root-owned file that is not
                    group- or world-writable (repeatable, one per provider); also the admin binding's fileScanKeys
                    or MOORAI_METADEFENDER_API_KEY / MOORAI_VIRUSTOTAL_API_KEY. Never the policy, never logged.
  Policy keys read here: fileScan (scan every inline file, document or image part with MetaDefender
                    Cloud or VirusTotal before it goes upstream: mode off (default) | hash (only the SHA-256
                    leaves) | upload (unknown files are uploaded); see README "Cloud file scanning"), intentAlignment off|report|ask|block (a tool call that does not fit the person's task;
                    default report) and responseScan report|mask|block (secrets, personal data, card numbers
                    and the system prompt in the model's reply text; default report). ask / block / mask take
                    effect with --mode enforce. Name the session with X-MoorAI-Session-Id (see README).
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
    else if (a === "--connect-timeout") o.connectTimeoutMs = Number(v());
    else if (a === "--policy-file") o.policyFile = resolve(v());
    else if (a === "--service-id") o.serviceId = v();
    else if (a === "--headless-ask") o.headlessAsk = v();
    else if (a === "--cwd") o.cwd = resolve(v());
    else if (a === "--log") o.log = true;
    else if (a === "--credentials") o.credentialsFile = v();
    else if (a === "--require-placeholders") o.requirePlaceholders = true;
    else if (a === "--denied-tool-call") o.deniedToolCall = v();
    else if (a === "--unchecked-window-ms") o.uncheckedWindowMs = Number(v());
    else if (a === "--unchecked-max") o.uncheckedMax = Number(v());
    else if (a === "--intent-key-file") o.intentKeyFile = resolve(v());
    else if (a === "--file-scan-key-file") {
      const x = v(), eq = x.indexOf("=");
      const name = eq > 0 ? x.slice(0, eq) : "";
      if (!FILE_SCAN_PROVIDERS.includes(name) || eq === x.length - 1) throw new Error(`--file-scan-key-file must be <provider>=<path>, provider one of ${FILE_SCAN_PROVIDERS.join(", ")}`);
      (o.fileScanKeyFiles ||= {})[name] = resolve(x.slice(eq + 1));
    }
    else throw new Error(`unknown argument ${a}`);
  }
  if (o.help) return o;
  o.routes ||= defaultRoutes(o.host);
  if (!o.token && env.MOORAI_MODEL_PROXY_TOKEN) o.token = String(env.MOORAI_MODEL_PROXY_TOKEN).trim();
  if (!["report", "enforce"].includes(o.mode)) throw new Error("--mode must be report or enforce");
  if (!Number.isInteger(o.port) || o.port < 0 || o.port > 65535) throw new Error("--port must be 0-65535");
  // pass-through leaves an ask unsettled; the proxy has no one to put it to, so the call would be forwarded.
  if (o.headlessAsk !== undefined && !["deny", "allow-with-report"].includes(o.headlessAsk)) throw new Error(`--headless-ask must be deny or allow-with-report${o.headlessAsk === "pass-through" ? " (pass-through would forward every call that needs approval: the proxy has no approver to ask)" : ""}`);
  if (!["refuse", "replace"].includes(o.deniedToolCall)) throw new Error("--denied-tool-call must be refuse or replace");
  if (o.deniedToolCall === "replace" && o.mode !== "enforce") throw new Error("--denied-tool-call replace needs --mode enforce (report mode never changes a response)");
  if (!Number.isInteger(o.uncheckedWindowMs) || o.uncheckedWindowMs < 0 || (o.uncheckedWindowMs > 0 && o.uncheckedWindowMs < 100) || o.uncheckedWindowMs > 3600000) throw new Error("--unchecked-window-ms must be 0 (off) or an integer from 100 to 3600000");
  if (!Number.isInteger(o.uncheckedMax) || o.uncheckedMax < 16 || o.uncheckedMax > 1048576) throw new Error("--unchecked-max must be an integer from 16 to 1048576");
  for (const [k, min] of [["maxBody", 1024], ["maxResponse", 1024], ["maxInflight", 1048576], ["maxScanItems", 1], ["maxScanChars", 1000], ["timeoutMs", 100], ["upstreamTimeoutMs", 1000], ["connectTimeoutMs", 100]]) {
    const flag = k === "connectTimeoutMs" ? "connect-timeout" : k.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
    if (!Number.isInteger(o[k]) || o[k] < min) throw new Error(`--${flag} must be an integer >= ${min}`);
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
  if (!o.credentialsFile && env.MOORAI_MODEL_PROXY_CREDENTIALS) o.credentialsFile = String(env.MOORAI_MODEL_PROXY_CREDENTIALS);
  if (o.requirePlaceholders && !o.credentialsFile) throw new Error("--require-placeholders needs --credentials (or MOORAI_MODEL_PROXY_CREDENTIALS)");
  if (o.credentialsFile) {
    const routes = Object.entries(o.routes).map(([prefix, base]) => ({ prefix, base }));
    o.credentials = loadBindings(resolve(o.credentialsFile), { env, routes, reserved: HOP });
  }
  return o;
}

async function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { process.stderr.write(`moorai-model-proxy: ${e.message}\n`); process.exit(2); }
  if (o.help) { process.stdout.write(HELP); process.exit(0); }
  const s = await createProxy(o);
  // One machine-readable line (a supervisor or a test using --port 0 finds the port). Routes print as
  // origin + path only.
  // Placeholder names only: never a secret, a secret's source or its length.
  const credentials = o.credentials ? { placeholders: [...o.credentials.bindings.keys()], requirePlaceholders: o.requirePlaceholders === true } : undefined;
  process.stdout.write(JSON.stringify({ listening: s.url, mode: o.mode, ...(o.mode === "enforce" ? { deniedToolCall: o.deniedToolCall } : {}), ...(o.uncheckedWindowMs ? { uncheckedWindowMs: o.uncheckedWindowMs } : {}), auth: o.token ? "token" : "none", credentials, serviceId: s.runtime.settings.serviceId, routes: Object.fromEntries(Object.entries(o.routes).map(([p, b]) => { const u = new URL(b); return [p, `${u.origin}${u.pathname}`]; })) }) + "\n");
  const stop = async () => { await s.close(); process.exit(0); };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
const invoked = (() => { try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (invoked) main();
