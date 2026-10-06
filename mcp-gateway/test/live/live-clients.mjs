// Real MCP client applications driven against MoorAI's two MCP pieces, with NO model call.
//
//   stdio : client --stdio--> mcp-proxy/moorai-mcp-guard.mjs --> tee-server.mjs --> test-fake-mcp-server.mjs
//   http  : client --HTTP---> moorai-mcp-gateway (a real process) --> fake-upstream.mjs (in-process)
//
// The clients are the installed CLIs, driven only through their MCP management subcommands, which
// connect to a configured server and health-check it without starting a model turn. Measured on
// Claude Code 2.1.284 and cursor-agent 2026.05.27:
//   claude mcp list            initialize + notifications/initialized + tools/list, then disconnects.
//                              "✔ Connected" needs tools/list to succeed: a tools/list error prints
//                              "! Connected · tools fetch failed — <message>". No tool names printed.
//                              Project .mcp.json servers are "⏸ Pending approval" and NOT connected
//                              unless settings.json says enableAllProjectMcpServers.
//   cursor-agent mcp enable    approves a .cursor/mcp.json server (written under $HOME/.cursor).
//   cursor-agent mcp list-tools  the same handshake, and prints the tool names it received.
//
// Isolation, so a run cannot touch the developer's own client config:
//   * every client runs with a throwaway HOME (and CLAUDE_CONFIG_DIR for Claude Code), its config
//     written only there and in a throwaway project dir;
//   * CLAUDE*/ANTHROPIC*/MCP_*/CURSOR* variables are removed from its environment, so no account,
//     token or host-session socket from a parent session reaches it (a client with no credentials
//     cannot start a paid turn even if invoked wrongly);
//   * on macOS it runs under sandbox-exec with a profile that DENIES writes to the real
//     ~/.claude.json, ~/.claude and ~/.cursor, and denies every outbound IP connection except
//     localhost. Set MOORAI_LIVE_NO_SANDBOX=1 to run without it (other platforms always do).
//
// MOORAI_LIVE_BREAK, for falsification only — each mode must turn the suite red:
//   bypass        the client is pointed straight at the fake server, MoorAI not in the path
//   dead          the client is pointed at a MoorAI path that does not exist (bad guard path / route)
//   toolscan      the stdio guard's own MOORAI_TEST_TOOLSCAN_THROW hook (its tools/list observer throws)
//   no-refusal    the "refused" gateway target is started without its method allow-list
//   no-policy     the stand-in console serves no policy, so the echo deny rule never arms
//   list-error    the fake server answers tools/list with a JSON-RPC error (MoorAI still in the path), so
//                 a client that reports "tools fetched" without a working tools/list would be caught
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync, accessSync, readdirSync, constants } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join, dirname, delimiter } from "node:path";
import { fileURLToPath } from "node:url";
import { startUpstream } from "../fake-upstream.mjs";
import { startConsole, makeHome, startGateway, stopGateway, sign, TENANT } from "../harness.mjs";
import { toolIdentity } from "../../../mcp-proxy/tool-scan.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO = join(HERE, "..", "..", "..");
export const GUARD = join(REPO, "mcp-proxy", "moorai-mcp-guard.mjs");
export const FAKE_SERVER = join(REPO, "mcp-proxy", "test-fake-mcp-server.mjs");
export const TEE = join(REPO, "mcp-proxy", "test", "live", "tee-server.mjs");
export const NODE = process.execPath;
// The password-database home, NOT $HOME: under test/hermetic-env.mjs $HOME is already a temp dir, and
// the sandbox has to protect the developer's real files.
export const REAL_HOME = userInfo().homedir;
export const BREAK = process.env.MOORAI_LIVE_BREAK || "";

export const STDIO_LABEL = "fake-stdio";
export const HTTP_LABEL = "fake-http";
export const REFUSED_LABEL = "fake-refused";
// The policy every MoorAI process in the matrix runs under (served signed by the stand-in console). The
// handshake tier never calls a tool; the live tool-call tier relies on the echo deny rule.
export const POLICY = { captureTier: "content-free", mcpToolRules: { echo: { deny: ["BLOCKME"] } } };

const LIST_ERROR = (id) => `{"jsonrpc":"2.0","id":${id},"error":{"code":-32603,"message":"injected tools/list failure"}}`;

export function which(bin) {
  for (const d of String(process.env.PATH || "").split(delimiter)) {
    if (!d) continue;
    const p = join(d, bin);
    try { accessSync(p, constants.X_OK); return p; } catch { /* next */ }
  }
  return null;
}

export const SANDBOX = process.platform === "darwin" && !process.env.MOORAI_LIVE_NO_SANDBOX && existsSync("/usr/bin/sandbox-exec");
export function sandboxProfile(home = REAL_HOME) {
  const q = (s) => JSON.stringify(s);
  return [
    "(version 1)",
    "(allow default)",
    '(deny network-outbound (remote ip "*:*"))',
    '(allow network-outbound (remote ip "localhost:*"))',
    `(deny file-write* (literal ${q(join(home, ".claude.json"))}) (subpath ${q(join(home, ".claude"))}) (subpath ${q(join(home, ".cursor"))}))`
  ].join("");
}

export function clientEnv(home, extra = {}) {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (/^(CLAUDE|ANTHROPIC|MCP_|CURSOR)/.test(k)) continue;
    if (["XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "APPDATA", "LOCALAPPDATA"].includes(k)) continue;
    env[k] = v;
  }
  return { ...env, HOME: home, USERPROFILE: home, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1", ...extra };
}

// One client process, sandboxed when available. → { code, stdout, stderr, argv }
export function runClient(bin, args, { cwd, env, timeoutMs = 60000 }) {
  const argv = SANDBOX ? ["/usr/bin/sandbox-exec", "-p", sandboxProfile(), bin, ...args] : [bin, ...args];
  return new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => { stdout += c; });
    child.stderr.on("data", (c) => { stderr += c; });
    const t = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* gone */ } }, timeoutMs);
    child.on("close", (code, signal) => { clearTimeout(t); resolve({ code: code ?? signal, stdout, stderr, argv: [bin, ...args] }); });
  });
}

// ---------------------------------------------------------------------------------------------
// Clients. Each knows how to write its isolated config, approve the server, and run the handshake.
// ---------------------------------------------------------------------------------------------
function lineFor(name, out) {
  return String(out).split("\n").find((l) => l.startsWith(name + ":")) || "";
}

export const CLIENTS = {
  "claude-code": {
    bin: "claude",
    async version(bin, sandboxHome) {
      const r = await runClient(bin, ["--version"], { cwd: sandboxHome, env: clientEnv(sandboxHome, { CLAUDE_CONFIG_DIR: join(sandboxHome, ".cfg") }) });
      return r.stdout.trim().split("\n")[0] || `exit ${r.code}`;
    },
    // servers: { name: <.mcp.json entry> }
    async handshake(bin, cell, name, entry) {
      const cfg = join(cell.home, ".claude-config");
      mkdirSync(cfg, { recursive: true });
      writeFileSync(join(cfg, "settings.json"), JSON.stringify({ enableAllProjectMcpServers: true }));
      writeFileSync(join(cell.proj, ".mcp.json"), JSON.stringify({ mcpServers: { [name]: entry } }, null, 2));
      const r = await runClient(bin, ["mcp", "list"], { cwd: cell.proj, env: clientEnv(cell.home, { CLAUDE_CONFIG_DIR: cfg }) });
      const line = lineFor(name, r.stdout);
      const status = line.slice(line.lastIndexOf(" - ") + 3).trim();
      const connected = /Connected/.test(status) && !/Failed|Pending|needs auth/i.test(status);
      const toolsFetchFailed = /tools fetch failed/.test(status);
      return {
        status: status || "(no status line)",
        connected,
        toolsFetched: connected && !toolsFetchFailed && /✔/.test(status),
        tools: null, // claude mcp list does not print tool names
        raw: r
      };
    }
  },
  "cursor-agent": {
    bin: "cursor-agent",
    async version(bin, sandboxHome) {
      const r = await runClient(bin, ["--version"], { cwd: sandboxHome, env: clientEnv(sandboxHome) });
      return r.stdout.trim().split("\n")[0] || `exit ${r.code}`;
    },
    async handshake(bin, cell, name, entry) {
      mkdirSync(join(cell.proj, ".cursor"), { recursive: true });
      writeFileSync(join(cell.proj, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { [name]: entry } }, null, 2));
      const env = clientEnv(cell.home);
      const en = await runClient(bin, ["mcp", "enable", name], { cwd: cell.proj, env });
      const r = await runClient(bin, ["mcp", "list-tools", name], { cwd: cell.proj, env });
      const m = /Tools for .*?\((\d+)\):\n([\s\S]*)/.exec(r.stdout);
      const tools = m ? m[2].split("\n").map((l) => (/^- ([^\s(]+)/.exec(l.trim()) || [])[1]).filter(Boolean) : null;
      const status = (r.stdout + r.stderr).trim().split("\n")[0] || `exit ${r.code}`;
      return {
        status,
        connected: r.code === 0 && !!m,
        toolsFetched: !!(tools && tools.length),
        tools,
        raw: { ...r, enable: en }
      };
    }
  },
  // The official TypeScript SDK's Client (StdioClientTransport / StreamableHTTPClientTransport), run as
  // a child process from mcp-gateway/test/live/sdk-client.mjs. Skipped when the SDK is not installed.
  "mcp-sdk": {
    locate() {
      try { import.meta.resolve("@modelcontextprotocol/sdk/client/index.js"); return SDK_CLIENT; } catch { return null; }
    },
    async version() {
      const p = new URL("../../../package.json", import.meta.resolve("@modelcontextprotocol/sdk/client/index.js"));
      return `@modelcontextprotocol/sdk ${JSON.parse(readFileSync(p, "utf8")).version}`;
    },
    async run(bin, cell, entry, calls = []) {
      const r = await runClient(NODE, [bin, JSON.stringify({ entry: sdkEntry(entry), calls })], { cwd: cell.proj, env: clientEnv(cell.home) });
      let j = null;
      try { j = JSON.parse(r.stdout.trim().split("\n").pop()); } catch { /* reported below */ }
      return { j, r };
    },
    async handshake(bin, cell, name, entry) {
      const { j, r } = await this.run(bin, cell, entry);
      return {
        status: j ? (j.ok ? `connected to ${j.serverVersion && j.serverVersion.name}; tools: ${j.tools.join(",")}` : `error: ${j.error}`) : `exit ${r.code}: ${r.stderr.slice(0, 200)}`,
        connected: !!(j && j.ok),
        toolsFetched: !!(j && j.tools && j.tools.length),
        tools: j ? j.tools : null,
        raw: r
      };
    },
    async toolCalls(bin, cell, name, entry, calls) {
      const { j, r } = await this.run(bin, cell, entry, calls);
      return { results: j && j.ok ? j.calls : null, error: j ? j.error || null : `exit ${r.code}`, raw: r };
    }
  },
  // The official MCP Inspector CLI (`npx @modelcontextprotocol/inspector --cli`), driven through a
  // session config file. Its target syntax splits at the first "--", which the guard's own command line
  // contains, so a config file is the only way to hand it the wrapped command intact.
  "mcp-inspector": {
    locate: locateInspector,
    async version(bin) {
      const p = join(dirname(bin), "..", "..", "..", "package.json");
      return `@modelcontextprotocol/inspector ${JSON.parse(readFileSync(p, "utf8")).version}`;
    },
    async run(bin, cell, name, entry, methodArgs) {
      const cfg = join(cell.proj, "inspector-config.json");
      writeFileSync(cfg, JSON.stringify({ mcpServers: { [name]: inspectorEntry(entry) } }, null, 2));
      const r = await runClient(NODE, [bin, "--cli", "--config", cfg, "--server", name, ...methodArgs], { cwd: cell.proj, env: clientEnv(cell.home) });
      let j = null;
      try { j = JSON.parse(r.stdout); } catch { /* reported below */ }
      return { j, r };
    },
    async handshake(bin, cell, name, entry) {
      const { j, r } = await this.run(bin, cell, name, entry, ["--method", "tools/list"]);
      const tools = j && Array.isArray(j.tools) ? j.tools.map((t) => t.name) : null;
      return {
        status: tools ? `tools/list ok: ${tools.join(",")}` : (j && j.error ? `error: ${j.error.message}` : `exit ${r.code}: ${(r.stdout + r.stderr).slice(0, 200)}`),
        connected: r.code === 0 && !!tools,
        toolsFetched: !!(tools && tools.length),
        tools,
        raw: r
      };
    },
    async toolCalls(bin, cell, name, entry, calls) {
      const results = [];
      const raws = [];
      for (const c of calls) {
        const args = Object.entries(c.arguments || {}).map(([k, v]) => `${k}=${v}`);
        const { j, r } = await this.run(bin, cell, name, entry, ["--method", "tools/call", "--tool-name", c.name, ...(args.length ? ["--tool-arg", ...args] : [])]);
        raws.push(r);
        if (!j || !Array.isArray(j.content)) return { results: null, error: `exit ${r.code}: ${(r.stdout + r.stderr).slice(0, 300)}`, raw: raws };
        results.push({ name: c.name, isError: !!j.isError, text: j.content.map((x) => x.text || "").join("") });
      }
      return { results, error: null, raw: raws };
    }
  }
};

const SDK_CLIENT = join(HERE, "sdk-client.mjs");
const sdkEntry = (e) => (e.type === "http" ? { type: "http", url: e.url } : { command: e.command, args: e.args, env: e.env });
const inspectorEntry = (e) => (e.type === "http" ? { type: "streamable-http", url: e.url } : { command: e.command, args: e.args, env: e.env });

// MOORAI_LIVE_INSPECTOR=<path to clients/launcher/build/index.js>, else the newest copy npx cached under
// the real ~/.npm/_npx (read-only lookup; nothing is downloaded here — run
// `npx -y @modelcontextprotocol/inspector --cli --help` once to populate it).
function locateInspector() {
  if (process.env.MOORAI_LIVE_INSPECTOR) return existsSync(process.env.MOORAI_LIVE_INSPECTOR) ? process.env.MOORAI_LIVE_INSPECTOR : null;
  const root = join(REAL_HOME, ".npm", "_npx");
  let best = null;
  try {
    for (const d of readdirSync(root)) {
      const base = join(root, d, "node_modules", "@modelcontextprotocol", "inspector");
      const bin = join(base, "clients", "launcher", "build", "index.js");
      if (!existsSync(bin)) continue;
      let v = "0";
      try { v = JSON.parse(readFileSync(join(base, "package.json"), "utf8")).version; } catch { /* unknown */ }
      if (!best || cmpVer(v, best.v) > 0) best = { bin, v };
    }
  } catch { /* no npx cache */ }
  return best ? best.bin : null;
}
function cmpVer(a, b) {
  const x = String(a).split(".").map(Number), y = String(b).split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0);
  return 0;
}

// Which clients are installed. MOORAI_LIVE_CLIENTS=claude-code,cursor-agent narrows it.
export async function detectClients(scratch) {
  const want = process.env.MOORAI_LIVE_CLIENTS ? process.env.MOORAI_LIVE_CLIENTS.split(",").map((s) => s.trim()) : Object.keys(CLIENTS);
  const out = [];
  for (const id of want) {
    const c = CLIENTS[id];
    if (!c) continue;
    const bin = c.locate ? c.locate() : which(c.bin);
    if (!bin) { out.push({ id, bin: null, version: null }); continue; }
    const vh = mkdtempSync(join(scratch, `ver-${id}-`));
    out.push({ id, bin, version: await c.version(bin, vh) });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Targets: what the client is pointed at. Each has its own MoorAI HOME so its side-effects are its own.
// ---------------------------------------------------------------------------------------------
export async function startWorld(scratch) {
  const con = await startConsole(BREAK === "no-policy" ? null : sign(POLICY));
  return { scratch, con, close: () => con.close() };
}

function moorHome(world) { return makeHome(world.con.url, true); }

// The stdio guard wrapping (tee → fake server). `host` is the guard's --host usage stamp.
export function stdioTarget(world, { host, label = STDIO_LABEL, fakeEnv = {} } = {}) {
  const home = moorHome(world);
  const dir = mkdtempSync(join(world.scratch, "stdio-"));
  const wire = join(dir, "wire.jsonl");
  const calls = join(dir, "calls.jsonl");
  const server = [TEE, wire, "--", NODE, FAKE_SERVER, calls];
  const guardPath = BREAK === "dead" ? GUARD + ".missing" : GUARD;
  if (BREAK === "list-error") {
    const f = join(dir, "list-error.json");
    writeFileSync(f, LIST_ERROR("__ID__"));
    fakeEnv = { FAKE_RAW_LIST: f, ...fakeEnv };
  }
  const env = {
    HOME: home, USERPROFILE: home, MoorAI_SERVER: world.con.url, MoorAI_TENANT: TENANT,
    XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"),
    ...(BREAK === "toolscan" ? { MOORAI_TEST_TOOLSCAN_THROW: "1" } : {}),
    ...fakeEnv
  };
  const entry = BREAK === "bypass"
    ? { command: NODE, args: server, env }
    : { command: NODE, args: [guardPath, "--server", label, "--host", host || "unknown", "--", NODE, ...server], env };
  return {
    transport: "stdio", label, home, wire, calls, entry,
    clientMessages: () => readJsonl(wire),
    toolCalls: () => readJsonl(calls),
    stop: async () => {}
  };
}

// A real gateway process in front of the in-process fake upstream. `gatewayArgs` add flags.
export async function httpTarget(world, { label = HTTP_LABEL, route = "/fake", gatewayArgs = [], upstream = {} } = {}) {
  const home = moorHome(world);
  const up = await startUpstream(BREAK === "list-error" ? { listReply: (m) => LIST_ERROR(m.id), ...upstream } : upstream);
  const gw = await startGateway({
    home, consoleUrl: world.con.url,
    args: ["--port", "0", "--route", `${route}=${up.url}`, "--server", label, ...gatewayArgs],
    env: { XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state") }
  });
  if (!gw.url) { await up.close(); throw new Error(`gateway did not start: exit=${gw.exitCode} stderr=${gw.stderr}`); }
  const url = BREAK === "bypass" ? up.url : BREAK === "dead" ? `${gw.url}${route}-missing` : `${gw.url}${route}`;
  return {
    transport: "http", label, home, url, gw, up,
    entry: { type: "http", url },
    cursorEntry: { url },
    clientMessages: () => up.received.filter((r) => r.json).map((r) => r.json),
    toolCalls: () => up.calls().map((r) => r.json.params),
    stop: async () => { await stopGateway(gw); await up.close(); }
  };
}

export function entryFor(clientId, target) {
  if (target.transport === "http" && clientId === "cursor-agent") return target.cursorEntry;
  return target.entry;
}

export function readJsonl(p) {
  try { return readFileSync(p, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l)); } catch { return []; }
}

// What MoorAI recorded about this target: the tool-stage baseline entry for `echo` under this target's
// server label (written by observeTools on every tools/list response it relays — content-free:
// fingerprints of the name and the label, never the name itself).
export function baselineFor(target, toolName = "echo") {
  try {
    const j = JSON.parse(readFileSync(join(target.home, ".moorai", "mcp-tool-baseline.json"), "utf8"));
    const id = toolIdentity({ name: toolName }, target.label);
    const e = j.tools && j.tools[id.key];
    return e ? { present: true, labelMatches: e.srv === id.srv, entry: e } : { present: false, labelMatches: false };
  } catch { return { present: false, labelMatches: false }; }
}

export async function waitFor(fn, ms = 4000, step = 100) {
  const end = Date.now() + ms;
  for (;;) {
    const v = fn();
    if (v || Date.now() > end) return v;
    await new Promise((r) => setTimeout(r, step));
  }
}

export function newCell(world, clientId, transport) {
  const dir = mkdtempSync(join(world.scratch, `cell-${clientId}-${transport}-`));
  const home = join(dir, "home"), proj = join(dir, "proj");
  mkdirSync(home, { recursive: true }); mkdirSync(proj, { recursive: true });
  return { dir, home, proj };
}

// One client × one target. → everything the matrix and the test assert on.
export async function runCell(world, client, target, name) {
  const cell = newCell(world, client.id, target.transport);
  const hs = await CLIENTS[client.id].handshake(client.bin, cell, name, entryFor(client.id, target));
  const baseline = await waitFor(() => { const b = baselineFor(target); return b.present ? b : null; }, hs.connected ? 4000 : 500) || baselineFor(target);
  const msgs = target.clientMessages();
  const init = msgs.find((m) => m.method === "initialize");
  return {
    client: client.id, version: client.version, transport: target.transport, label: target.label,
    status: hs.status, connected: hs.connected, toolsFetched: hs.toolsFetched, tools: hs.tools,
    serverSawInitialize: !!init,
    clientInfo: init && init.params && init.params.clientInfo ? init.params.clientInfo : null,
    serverSawToolsList: msgs.some((m) => m.method === "tools/list"),
    baseline,
    raw: hs.raw, cell
  };
}

export function cleanup(p) { try { rmSync(p, { recursive: true, force: true }); } catch { /* temp */ } }
export { TENANT, spawnSync };

// ---------------------------------------------------------------------------------------------
// The no-model tool-call tier, for clients that can call a tool themselves (SDK, Inspector): one benign
// echo, then one the policy denies (args contain BLOCKME). What MoorAI must show for it:
//   * the benign call reached the server and its echo came back;
//   * the denied call came back as MoorAI's isError refusal and NEVER reached the server;
//   * MoorAI's usage tally (~/.moorai/mcp-usage.json) counted both calls under this label;
//   * its content-free ledger (~/.moorai/action-audit.jsonl) has an allow and a deny "MCP tool call";
//   * the stand-in console received a Blocked alert for this server.
// ---------------------------------------------------------------------------------------------
export const BENIGN = { name: "echo", arguments: { m: "hello-moorai" } };
export const DENIED = { name: "echo", arguments: { m: "BLOCKME" } };

export function usageCount(target) {
  try {
    const j = JSON.parse(readFileSync(join(target.home, ".moorai", "mcp-usage.json"), "utf8"));
    let n = 0;
    for (const day of Object.values(j.days || {})) for (const m of Object.values(day)) n += m[target.label] || 0;
    return n;
  } catch { return 0; }
}
export function ledgerCalls(target) {
  return readJsonl(join(target.home, ".moorai", "action-audit.jsonl")).filter((e) => e.category === "MCP tool call" && e.mcpServer === target.label);
}

export async function runToolCallCell(world, client, target, name) {
  const cell = newCell(world, client.id, target.transport + "-call");
  const n0 = world.con.alerts.length;
  const tc = await CLIENTS[client.id].toolCalls(client.bin, cell, name, entryFor(client.id, target), [BENIGN, DENIED]);
  await waitFor(() => usageCount(target) >= 2 && ledgerCalls(target).length >= 2, 3000);
  await waitFor(() => world.con.alerts.slice(n0).some((a) => a.mcpServer === target.label && a.riskLevel === "Blocked"), 2000);
  const serverArgs = target.toolCalls().map((p) => JSON.stringify(p && p.arguments));
  return {
    client: client.id, version: client.version, transport: target.transport, label: target.label,
    results: tc.results, error: tc.error,
    serverGotBenign: serverArgs.some((a) => a.includes("hello-moorai")),
    serverGotDenied: serverArgs.some((a) => a.includes("BLOCKME")),
    usage: usageCount(target),
    ledger: ledgerCalls(target).map((e) => e.decision),
    alerts: world.con.alerts.slice(n0).filter((a) => a.mcpServer === target.label),
    raw: tc.raw, cell
  };
}

export function judgeToolCall(r) {
  const why = [];
  const [b, d] = r.results || [];
  if (!r.results) why.push(`client could not call tools (${r.error})`);
  else {
    if (!b || b.isError || !b.text.includes("hello-moorai")) why.push("benign echo did not come back");
    if (!d || !d.isError || !/^MoorAI blocked this MCP tool call/.test(d.text)) why.push("denied call was not refused by MoorAI");
  }
  if (!r.serverGotBenign) why.push("benign call never reached the server");
  if (r.serverGotDenied) why.push("DENIED CALL REACHED THE SERVER");
  if (r.usage < 2) why.push(`usage tally counted ${r.usage} calls, want 2`);
  if (!r.ledger.includes("allow") || !r.ledger.includes("deny")) why.push(`ledger decisions ${JSON.stringify(r.ledger)}, want allow + deny`);
  if (!r.alerts.some((a) => a.riskLevel === "Blocked" && a.decision === "deny")) why.push("console got no Blocked alert");
  return why;
}
