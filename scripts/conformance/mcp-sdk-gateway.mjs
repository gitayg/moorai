// AI Servers live conformance: the official MCP TypeScript SDK on BOTH ends of MoorAI's MCP HTTP gateway.
//
//   SDK Client (StreamableHTTPClientTransport, mcp-gateway/test/live/sdk-client.mjs, its own process)
//     → moorai-mcp-gateway (a real process, enrolled to a stand-in console serving a signed policy)
//     → an SDK Server (StreamableHTTPServerTransport, stateless) on loopback with one `echo` tool
//
// Cases: echo {"m":"hello-moorai"} is forwarded and answered; echo {"m":"BLOCKME"} (the policy's
// mcpToolRules deny) comes back as MoorAI's refusal, the SDK server never receives it, and the console
// gets a Blocked alert. The server records counts and one boolean, never the arguments.
import http from "node:http";
import { spawn } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SDK_CLIENT = join(ROOT, "mcp-gateway", "test", "live", "sdk-client.mjs");
export const GATEWAY_POLICY = { captureTier: "content-free", mcpToolRules: { echo: { deny: ["BLOCKME"] } } };

export function sdkVersion() {
  try { return JSON.parse(readFileSync(new URL("../../../package.json", import.meta.resolve("@modelcontextprotocol/sdk/server/index.js")), "utf8")).version; } catch { return null; }
}

export async function startSdkServer() {
  const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
  const { StreamableHTTPServerTransport } = await import("@modelcontextprotocol/sdk/server/streamableHttp.js");
  const { ListToolsRequestSchema, CallToolRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");
  const st = { calls: 0, gotDenied: false, gotBenign: false };
  const make = () => {
    const s = new Server({ name: "moorai-conformance-sdk-server", version: "1.0.0" }, { capabilities: { tools: {} } });
    s.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: "echo", description: "Echo the m argument", inputSchema: { type: "object", properties: { m: { type: "string" } } } }] }));
    s.setRequestHandler(CallToolRequestSchema, async (req) => {
      st.calls++;
      const m = String((req.params.arguments || {}).m || "");
      if (m.includes("BLOCKME")) st.gotDenied = true;
      if (m === "hello-moorai") st.gotBenign = true;
      return { content: [{ type: "text", text: m }] };
    });
    return s;
  };
  const server = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => { b += c; });
    req.on("end", async () => {
      if (req.method !== "POST") { res.writeHead(405); return res.end(); }
      const s = make();
      const t = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on("close", () => { t.close(); s.close(); });
      try { await s.connect(t); await t.handleRequest(req, res, JSON.parse(b)); } catch { if (!res.headersSent) { res.writeHead(400); res.end(); } }
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${server.address().port}/mcp`, stats: () => ({ ...st }), close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) };
}

function runSdkClient(spec, env) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [SDK_CLIENT, JSON.stringify(spec)], { env, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    c.stdout.on("data", (d) => { out += d; });
    const t = setTimeout(() => c.kill("SIGKILL"), 60000);
    c.on("close", () => { clearTimeout(t); try { resolve(JSON.parse(out.trim().split("\n").pop())); } catch { resolve(null); } });
  });
}

const isBlocked = (a) => a && (a.riskLevel === "Blocked" || a.decision === "deny");
export function judgeSdkGateway(j, srv, alerts) {
  const calls = (j && j.calls) || [];
  const [b, d] = calls;
  const blocked = (alerts || []).find(isBlocked) || null;
  const allowPass = !!(b && !b.isError && b.text === "hello-moorai" && srv.gotBenign);
  const denyRefused = !!(d && d.isError && /^MoorAI blocked this MCP tool call/.test(d.text));
  const denyPass = denyRefused && !srv.gotDenied && !!blocked;
  return [
    { id: "sdk-echo-allow", surface: "mcp-gateway", expect: "forward", observed: b && !b.isError ? "forward" : "none", status: allowPass ? "pass" : "fail", checks: { clientConnected: !!(j && j.ok), toolListed: !!(j && j.tools && j.tools.includes("echo")), serverGotCall: !!srv.gotBenign, resultReturned: !!(b && !b.isError) }, alert: null },
    { id: "sdk-echo-deny", surface: "mcp-gateway", expect: "refuse", observed: denyRefused ? "refuse" : d && !d.isError ? "forward" : "none", status: denyPass ? "pass" : "fail", checks: { refusedByMoorAI: denyRefused, serverGotCall: !!srv.gotDenied, alertSeen: !!blocked }, alert: blocked ? { category: blocked.category ?? null, riskLevel: blocked.riskLevel ?? null, decision: blocked.decision ?? null, reasonCode: blocked.reasonCode ?? null } : null }
  ];
}

export const MCP_SDK_TARGET = { kind: "sdk", id: "mcp-gateway-mcp-sdk", label: "MoorAI MCP gateway with the official MCP TypeScript SDK client and server" };

export async function runMcpSdkGatewayTarget() {
  const version = sdkVersion();
  if (!version) return { ...MCP_SDK_TARGET, ran: false, model: "none", reason: "sdk-not-installed", cases: [] };
  const { startConsole, makeHome, startGateway, stopGateway, sign } = await import("../../mcp-gateway/test/harness.mjs");
  const con = await startConsole(sign(GATEWAY_POLICY));
  const home = makeHome(con.url, true);
  const srv = await startSdkServer();
  let gw;
  try {
    gw = await startGateway({ home, consoleUrl: con.url, args: ["--port", "0", "--route", `/sdk=${srv.url}`, "--server", "sdk-server"], env: { XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state") } });
    if (!gw.url) throw new Error(`gateway did not start: exit=${gw.exitCode}`);
    const started = Date.now();
    const env = { PATH: process.env.PATH, HOME: home };
    const j = await runSdkClient({ entry: { type: "http", url: `${gw.url}/sdk` }, calls: [{ name: "echo", arguments: { m: "hello-moorai" } }, { name: "echo", arguments: { m: "BLOCKME" } }] }, env);
    const end = Date.now() + 4000;
    while (Date.now() < end && !con.alerts.some(isBlocked)) await new Promise((r) => setTimeout(r, 100));
    const cases = judgeSdkGateway(j, srv.stats(), con.alerts).map((c) => ({ ...c, latencyMs: Date.now() - started }));
    return { ...MCP_SDK_TARGET, version, ran: true, model: "none", cases };
  } finally {
    await stopGateway(gw);
    await srv.close();
    await con.close();
    rmSync(home, { recursive: true, force: true });
  }
}
