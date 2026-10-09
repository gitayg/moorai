// Configuration for moorai-egress-proxy: flags → one validated object. Pure apart from reading the token
// file it is told to read, so the bind rules are unit-testable.
//
// The bind rule, as the MCP gateway's: 127.0.0.1 by default. Any non-loopback address needs BOTH
// --allow-remote and a proxy token (MOORAI_EGRESS_PROXY_TOKEN or --token-file, never argv, where `ps` would
// show it). Without both the process exits 2 before it listens.
//
// Nothing here sets policy. The egress rules come only from the verified console policy and the root-owned
// machine-wide config (judge.mjs), never from a flag, a file the proxy is pointed at, or the environment.
import { readFileSync } from "node:fs";

export const DEFAULT_PORT = 8850;
export const MIN_TOKEN_LEN = 16;
// The ports of the MoorAI services that run beside the proxy (moorai-serve 8790, the model proxy 8791,
// the MCP gateway 8848) and the proxy's own default (8850). On a loopback or local interface address the
// proxy never connects to them, whatever the rules say; its actual listening port is refused as well.
export const SIBLING_PORTS = Object.freeze([8790, 8791, 8848, 8850]);
export const DEFAULTS = Object.freeze({
  maxConnections: 256,
  headersTimeoutMs: 10000,
  requestTimeoutMs: 60000,
  idleTimeoutMs: 120000,
  connectTimeoutMs: 10000,
  dnsTimeoutMs: 5000,
  maxHeaderBytes: 16384,
  siblingPorts: SIBLING_PORTS
});
const NUM_FLAGS = {
  "--max-connections": ["maxConnections", 1, 65536],
  "--headers-timeout-ms": ["headersTimeoutMs", 100, 600000],
  "--request-timeout-ms": ["requestTimeoutMs", 100, 3600000],
  "--idle-timeout-ms": ["idleTimeoutMs", 100, 86400000],
  "--connect-timeout-ms": ["connectTimeoutMs", 100, 600000],
  "--dns-timeout-ms": ["dnsTimeoutMs", 100, 600000]
};

// The MCP gateway's loopback test (mcp-gateway/config.mjs), kept here so the proxy imports no gateway code.
export function isLoopbackHost(h) {
  const s = String(h || "").toLowerCase().replace(/^\[|\]$/g, "");
  return s === "localhost" || s === "::1" || /^127(?:\.\d{1,3}){3}$/.test(s) || s === "::ffff:127.0.0.1";
}

// argv (no node / script) + env + a file reader → { host, port, allowRemote, token, ...limits }.
// Throws an Error with a user-facing message on anything invalid.
export function parseConfig(argv, env = process.env, read = (p) => readFileSync(p, "utf8")) {
  const o = { host: "127.0.0.1", port: DEFAULT_PORT, allowRemote: false, token: "", ...DEFAULTS };
  let tokenFile = "";
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--host") o.host = next();
    else if (a === "--port" || a === "-p") o.port = Number(next());
    else if (a === "--allow-remote") o.allowRemote = true;
    else if (a === "--token-file") tokenFile = next();
    else if (a === "--sibling-ports") {
      const v = next();
      const l = v === "" ? [] : v.split(",");
      if (l.some((p) => !/^\d{1,5}$/.test(p) || Number(p) < 1 || Number(p) > 65535)) throw new Error("--sibling-ports must be a comma-separated list of ports 1-65535 (or \"\" for none)");
      o.siblingPorts = l.map(Number);
    }
    else if (NUM_FLAGS[a]) {
      const [key, min, max] = NUM_FLAGS[a];
      const v = Number(next());
      if (!Number.isInteger(v) || v < min || v > max) throw new Error(`${a} must be a whole number ${min}-${max}`);
      o[key] = v;
    } else if (a === "--help" || a === "-h") return { help: true };
    else throw new Error(`unknown argument '${a}'`);
  }
  if (!Number.isInteger(o.port) || o.port < 0 || o.port > 65535) throw new Error(`invalid port '${o.port}'`);
  if (tokenFile) o.token = String(read(tokenFile)).trim();
  else if (env.MOORAI_EGRESS_PROXY_TOKEN) o.token = String(env.MOORAI_EGRESS_PROXY_TOKEN).trim();
  if (o.token && o.token.length < MIN_TOKEN_LEN) throw new Error(`the proxy token must be at least ${MIN_TOKEN_LEN} characters`);
  if (!isLoopbackHost(o.host)) {
    if (!o.allowRemote) throw new Error(`refusing to bind ${o.host}: a non-loopback address needs --allow-remote and a proxy token`);
    if (!o.token) throw new Error(`refusing to bind ${o.host}: --allow-remote needs a proxy token (MOORAI_EGRESS_PROXY_TOKEN or --token-file)`);
  }
  return o;
}

export const USAGE = `usage: moorai-egress-proxy [--host 127.0.0.1] [--port ${DEFAULT_PORT}] [--allow-remote] [--token-file <file>]
                          [--max-connections ${DEFAULTS.maxConnections}] [--headers-timeout-ms ${DEFAULTS.headersTimeoutMs}]
                          [--request-timeout-ms ${DEFAULTS.requestTimeoutMs}] [--idle-timeout-ms ${DEFAULTS.idleTimeoutMs}]
                          [--connect-timeout-ms ${DEFAULTS.connectTimeoutMs}] [--dns-timeout-ms ${DEFAULTS.dnsTimeoutMs}]
                          [--sibling-ports ${SIBLING_PORTS.join(",")}]

  A forward proxy (HTTP_PROXY / HTTPS_PROXY) that enforces the egressRules and egressDefault of the
  verified console policy and the root-owned machine-wide config on every connection it carries:
  plain-HTTP requests by host, port, method and path; CONNECT tunnels by host and port only (TLS is not
  decrypted). DNS is resolved once and the checked address is the one connected to; loopback, private,
  link-local and IP-literal destinations need a rule that names the exact host (never a *.suffix rule),
  cloud metadata a rule that names the IP itself. The plain-HTTP path is canonicalised, judged and sent
  as one string.

  --host <addr>              bind address (default 127.0.0.1)
  --port <n>                 port (default ${DEFAULT_PORT}; 0 = any free port)
  --allow-remote             permit a non-loopback bind; requires a proxy token
  --token-file <file>        proxy token (or MOORAI_EGRESS_PROXY_TOKEN); clients send it as
                             Proxy-Authorization (Basic with the token as the password, or Bearer)
  --max-connections <n>      concurrent client connections, tunnels included
  --headers-timeout-ms <n>   time a client has to send its request headers
  --request-timeout-ms <n>   time a client has to send a whole plain-HTTP request
  --idle-timeout-ms <n>      a connection or tunnel with no traffic either way for this long is closed
  --connect-timeout-ms <n>   time to open the upstream TCP connection
  --dns-timeout-ms <n>       time to resolve the destination
  --sibling-ports <list>     ports never connected to on a loopback or local address, beside the proxy's
                             own (default ${SIBLING_PORTS.join(",")}; "" for none)`;
