// Configuration for moorai-mcp-gateway: flags and an optional JSON file → one validated object. Pure
// apart from reading the files it is told to read, so the bind rules are unit-testable.
//
// The two rules that matter for safety, enforced here and nowhere else:
//   * Bind 127.0.0.1 by default. Any non-loopback address needs BOTH --allow-remote and a gateway token
//     (MOORAI_GATEWAY_TOKEN or --token-file, never argv, where `ps` would show it). Without both the
//     process exits 2 before it listens.
//   * An upstream reached over plain http:// must be loopback, unless --allow-insecure-upstream: the
//     client's Authorization header is passed through, and a bearer token must not cross a network in
//     clear because a gateway was put in front of it.
import { readFileSync } from "node:fs";

export const DEFAULT_PORT = 8848;
export const TOKEN_HEADER = "x-moorai-gateway-token";
export const MIN_TOKEN_LEN = 16;

export function isLoopbackHost(h) {
  const s = String(h || "").toLowerCase().replace(/^\[|\]$/g, "");
  return s === "localhost" || s === "::1" || /^127(?:\.\d{1,3}){3}$/.test(s) || s === "::ffff:127.0.0.1";
}

function normPath(p) {
  let s = String(p || "").trim();
  if (!s.startsWith("/")) s = "/" + s;
  return s.length > 1 ? s.replace(/\/+$/, "") : s;
}

function labelOf(path) {
  return path.replace(/^\/+/, "").replace(/[^A-Za-z0-9._-]+/g, "-") || "mcp";
}

function parseRouteFlag(v) {
  const eq = String(v || "").indexOf("=");
  if (eq <= 0) throw new Error(`--route expects /path=https://upstream/mcp, got '${v}'`);
  return { path: v.slice(0, eq), url: v.slice(eq + 1) };
}

function routeFrom(path, spec) {
  const s = typeof spec === "string" ? { url: spec } : (spec || {});
  const p = normPath(path);
  let u;
  try { u = new URL(String(s.url || "")); } catch { throw new Error(`route ${p}: upstream URL is not a valid URL`); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error(`route ${p}: upstream must be http(s)`);
  return {
    path: p,
    url: u.href,
    server: String(s.server || labelOf(p)),
    localFiles: s.localFiles === true,
    roots: Array.isArray(s.roots) ? s.roots.filter((r) => typeof r === "string" && r).slice(0, 16) : []
  };
}

// argv (no node / script) + env + a file reader → { host, port, routes, allowRemote, token, allowOrigins, ... }
// Throws an Error with a user-facing message on anything invalid.
export function parseConfig(argv, env = process.env, read = (p) => readFileSync(p, "utf8")) {
  let file = {};
  const flags = { routes: [], allowOrigins: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--config" || a === "-c") file = JSON.parse(read(next()));
    else if (a === "--route" || a === "-r") flags.routes.push(parseRouteFlag(next()));
    else if (a === "--host") flags.host = next();
    else if (a === "--port" || a === "-p") flags.port = Number(next());
    else if (a === "--allow-remote") flags.allowRemote = true;
    else if (a === "--allow-insecure-upstream") flags.allowInsecureUpstream = true;
    else if (a === "--token-file") flags.tokenFile = next();
    else if (a === "--allow-origin") flags.allowOrigins.push(next());
    else if (a === "--local-files") flags.localFiles = true;
    else if (a === "--server" || a === "-s") flags.server = next();
    else if (a === "--help" || a === "-h") return { help: true };
    else throw new Error(`unknown argument '${a}'`);
  }

  const routes = [];
  const fileRoutes = file.routes && typeof file.routes === "object" ? file.routes : {};
  for (const [p, spec] of Object.entries(fileRoutes)) routes.push(routeFrom(p, spec));
  for (const r of flags.routes) {
    routes.push(routeFrom(r.path, { url: r.url, server: flags.routes.length === 1 && flags.server ? flags.server : undefined, localFiles: flags.localFiles === true }));
  }
  if (!routes.length) throw new Error("no routes: pass --route /name=https://remote.example/mcp or --config <file>");
  const seen = new Set();
  for (const r of routes) { if (seen.has(r.path)) throw new Error(`route ${r.path} is defined twice`); seen.add(r.path); }

  const host = String(flags.host || file.host || "127.0.0.1");
  const port = flags.port != null ? flags.port : file.port != null ? Number(file.port) : DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`invalid port '${port}'`);
  const allowRemote = flags.allowRemote === true || file.allowRemote === true;
  const allowInsecureUpstream = flags.allowInsecureUpstream === true || file.allowInsecureUpstream === true;

  let token = "";
  const tokenFile = flags.tokenFile || file.tokenFile;
  if (tokenFile) token = String(read(tokenFile)).trim();
  else if (env.MOORAI_GATEWAY_TOKEN) token = String(env.MOORAI_GATEWAY_TOKEN).trim();
  if (token && token.length < MIN_TOKEN_LEN) throw new Error(`the gateway token must be at least ${MIN_TOKEN_LEN} characters`);

  if (!isLoopbackHost(host)) {
    if (!allowRemote) throw new Error(`refusing to bind ${host}: a non-loopback address needs --allow-remote and a gateway token`);
    if (!token) throw new Error(`refusing to bind ${host}: --allow-remote needs a gateway token (MOORAI_GATEWAY_TOKEN or --token-file)`);
  }
  for (const r of routes) {
    const u = new URL(r.url);
    if (u.protocol === "http:" && !isLoopbackHost(u.hostname) && !allowInsecureUpstream) {
      throw new Error(`route ${r.path}: plain http to a non-loopback upstream would send the client's Authorization header in clear; use https or --allow-insecure-upstream`);
    }
  }

  const allowOrigins = [...(Array.isArray(file.allowOrigins) ? file.allowOrigins : []), ...flags.allowOrigins].map(String);
  return { host, port, routes, allowRemote, allowInsecureUpstream, token, allowOrigins };
}

// What an upstream URL is safe to print: origin + path. Never the query string (some servers take an API
// key there) and never userinfo.
export function displayUrl(url) {
  try { const u = new URL(url); return `${u.protocol}//${u.host}${u.pathname}`; } catch { return "(invalid)"; }
}

export const USAGE = `usage: moorai-mcp-gateway --route /name=https://remote.example/mcp [--route ...] [options]
       moorai-mcp-gateway --config gateway.json [options]

  --route /path=URL          map a local path to a remote MCP endpoint (repeatable); the MCP server
                             label (allow-list, alerts) is the path's name unless --server is given
  --server <label>           label for a single --route
  --config <file>            JSON: { "host", "port", "routes": { "/path": { "url", "server",
                             "localFiles", "roots" } }, "allowOrigins": [] }
  --host <addr>              bind address (default 127.0.0.1)
  --port <n>                 port (default ${DEFAULT_PORT}; 0 = any free port)
  --allow-remote             permit a non-loopback bind; requires a gateway token
  --token-file <file>        gateway token (or MOORAI_GATEWAY_TOKEN); clients send it in
                             X-MoorAI-Gateway-Token, and it is stripped before the upstream
  --local-files              scan local files named in tool arguments (only when the gateway runs on
                             the same machine as those files)
  --allow-origin <origin>    accept a browser Origin besides loopback ones (repeatable)
  --allow-insecure-upstream  permit plain http:// to a non-loopback upstream`;
