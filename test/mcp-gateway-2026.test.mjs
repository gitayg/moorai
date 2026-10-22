// F25: what the HTTP MCP gateway needs from the MCP 2026-07-28 revision, each against the spec text:
//   * Streamable HTTP "Custom Headers from Tool Parameters": "Any server that processes the message body
//     MUST validate that encoded header values, after decoding if Base64-encoded, match the corresponding
//     values in the request body", with 400 and -32020 HeaderMismatch; "Intermediate servers that do not
//     recognize an Mcp-Param-{Name} header MUST forward it and otherwise ignore it".
//   * "Server Validation": a failure includes "A required standard header (MCP-Protocol-Version,
//     Mcp-Method, Mcp-Name) is missing".
//   * Authorization: "MCP servers MUST implement OAuth 2.0 Protected Resource Metadata (RFC9728)"; the
//     metadata URL comes from WWW-Authenticate resource_metadata or the well-known URI "At the path of the
//     server's MCP endpoint"; and "Access tokens MUST NOT be included in the URI query string".
// A real gateway process, fake remote servers, a fake console with a signed policy.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-gateway-2026.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readdirSync, readFileSync, statSync, rmSync } from "node:fs";
import { join } from "node:path";
import { scenario, startConsole, makeHome, sign, startGateway, stopGateway, H } from "../mcp-gateway/test/harness.mjs";

const PV = "2026-07-28";
const meta = { "io.modelcontextprotocol/protocolVersion": PV, "io.modelcontextprotocol/clientInfo": { name: "t", version: "1" }, "io.modelcontextprotocol/clientCapabilities": {} };
const TOOLS = [{
  name: "execute_sql", description: "Run SQL.",
  inputSchema: { type: "object", properties: {
    region: { type: "string", "x-mcp-header": "Region" },
    shard: { type: "integer", "x-mcp-header": "Shard" },
    opts: { type: "object", properties: { tenant: { type: "string", "x-mcp-header": "Tenant" } } },
    query: { type: "string" }
  } }
}, { name: "echo", description: "Echo.", inputSchema: { type: "object" } }];
const modernHeaders = (method, name, extra = {}) => ({ "MCP-Protocol-Version": PV, "Mcp-Method": method, ...(name ? { "Mcp-Name": name } : {}), ...extra });
const tcall = (id, name, args) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args, _meta: meta } });
async function post(url, body, headers = {}) {
  const r = await fetch(url, { method: "POST", headers: { ...H, ...headers }, body: JSON.stringify(body) });
  const text = await r.text();
  return { status: r.status, headers: r.headers, text, json: (() => { try { return JSON.parse(text); } catch { return null; } })() };
}
const b64 = (s) => `=?base64?${Buffer.from(s, "utf8").toString("base64")}?=`;

test("Mcp-Param-*: values mirrored from x-mcp-header parameters must match the body (decoded, integers numerically); unrecognized ones are forwarded", async () => {
  await scenario({ policy: { captureTier: "content-free" }, upstream: { tools: TOOLS } }, async ({ up, base }) => {
    const list = await post(base, { jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: meta } }, modernHeaders("tools/list"));
    assert.equal(list.status, 200);
    const args = { region: "us-west1", shard: 42, opts: { tenant: "Hello, 世界" }, query: "SELECT 1" };
    const good = modernHeaders("tools/call", "execute_sql", { "Mcp-Param-Region": "us-west1", "Mcp-Param-Shard": "42", "Mcp-Param-Tenant": b64("Hello, 世界") });
    const ok = await post(base, tcall(2, "execute_sql", args), good);
    assert.equal(ok.status, 200, ok.text);
    assert.equal(ok.json.result.isError, false);
    const ok2 = await post(base, tcall(3, "execute_sql", args), { ...good, "Mcp-Param-Shard": "42.0" });
    assert.equal(ok2.status, 200, "an integer compares numerically");
    const before = up.calls().length;
    for (const [hdrs, why] of [
      [{ ...good, "Mcp-Param-Region": "eu-west1" }, /Mcp-Param-Region/],
      [{ ...good, "Mcp-Param-Shard": "43" }, /Mcp-Param-Shard/],
      [Object.fromEntries(Object.entries(good).filter(([k]) => k !== "Mcp-Param-Tenant")), /Mcp-Param-Tenant/],
      [{ ...good, "Mcp-Param-Tenant": "=?base64?***?=" }, /Mcp-Param-Tenant/]
    ]) {
      const r = await post(base, tcall(9, "execute_sql", args), hdrs);
      assert.equal(r.status, 400, r.text);
      assert.equal(r.json.error.code, -32020);
      assert.match(r.json.error.message, why);
    }
    // A header for a parameter the body does not carry is refused too (it would carry a value the body does not).
    const noVal = await post(base, tcall(10, "execute_sql", { query: "x" }), modernHeaders("tools/call", "execute_sql", { "Mcp-Param-Region": "us-west1" }));
    assert.equal(noVal.status, 400);
    assert.equal(up.calls().length, before, "a mismatched call reached the upstream");
    // Not annotated: forwarded and ignored.
    const other = await post(base, tcall(11, "echo", { a: 1 }), modernHeaders("tools/call", "echo", { "Mcp-Param-Anything": "x" }));
    assert.equal(other.status, 200);
    assert.equal(up.calls().at(-1).headers["mcp-param-anything"], "x");
  });
});

test("2026-07-28 requests: a missing MCP-Protocol-Version, Mcp-Method or Mcp-Name header is a HeaderMismatch; older-era requests need none", async () => {
  await scenario({ policy: { captureTier: "content-free" } }, async ({ up, base }) => {
    const call = tcall(1, "echo", { a: 1 });
    for (const [hdrs, missing] of [
      [{ "Mcp-Method": "tools/call", "Mcp-Name": "echo" }, "MCP-Protocol-Version"],
      [{ "MCP-Protocol-Version": PV, "Mcp-Name": "echo" }, "Mcp-Method"],
      [{ "MCP-Protocol-Version": PV, "Mcp-Method": "tools/call" }, "Mcp-Name"]
    ]) {
      const r = await post(base, call, hdrs);
      assert.equal(r.status, 400, `${missing}: ${r.text}`);
      assert.equal(r.json.error.code, -32020);
      assert.match(r.json.error.message, new RegExp(`required ${missing} header is missing`));
    }
    assert.equal(up.calls().length, 0);
    const legacy = await post(base, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { a: 1 } } });
    assert.equal(legacy.status, 200, "a 2025-era request without the headers is forwarded");
  });
});

// A protected remote MCP server (an OAuth resource server): 401 without a token, with resource_metadata.
async function startResourceServer({ prmResource, challengeMetadata = true, foreignPrm = null } = {}) {
  const seen = [];
  const srv = http.createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers });
      const base = `http://127.0.0.1:${srv.address().port}`;
      if (req.method === "GET" && req.url === "/.well-known/oauth-protected-resource/mcp") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ resource: prmResource || `${base}/mcp`, authorization_servers: ["https://auth.example.com"], scopes_supported: ["files:read"], bearer_methods_supported: ["header"] }));
      }
      if (req.method === "POST" && req.url === "/mcp") {
        if (req.headers.authorization !== "Bearer tok-good-123") {
          const md = foreignPrm || `${base}/.well-known/oauth-protected-resource/mcp`;
          res.writeHead(401, { "WWW-Authenticate": `Bearer ${challengeMetadata ? `resource_metadata="${md}", ` : ""}scope="files:read"`, "Content-Type": "application/json" });
          return res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "unauthorized" } }));
        }
        const m = JSON.parse(b);
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { tools: [], resultType: "complete" } }));
      }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}/mcp`, seen, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}
async function withGateway(upUrl, fn) {
  const con = await startConsole(sign({ captureTier: "content-free" }));
  const home = makeHome(con.url, true);
  const gw = await startGateway({ home, consoleUrl: con.url, args: ["--port", "0", "--route", `/rs=${upUrl}`] });
  try { assert.ok(gw.url, gw.stderr); await fn(gw.url, home); } finally { await stopGateway(gw); await con.close(); rmSync(home, { recursive: true, force: true }); }
}
const listMsg = { jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: meta } };
function filesUnder(dir) { const out = []; for (const f of readdirSync(dir)) { const p = join(dir, f); if (statSync(p).isDirectory()) out.push(...filesUnder(p)); else out.push(p); } return out; }

test("OAuth discovery: the upstream's 401 points at the gateway's protected-resource metadata, which names the gateway route as the resource and keeps the authorization servers", async () => {
  const rs = await startResourceServer();
  await withGateway(rs.url, async (gw, home) => {
    const r = await post(`${gw}/rs`, listMsg, modernHeaders("tools/list"));
    assert.equal(r.status, 401);
    const wa = r.headers.get("www-authenticate");
    assert.equal(wa, `Bearer resource_metadata="${gw}/.well-known/oauth-protected-resource/rs", scope="files:read"`);
    const prm = await fetch(`${gw}/.well-known/oauth-protected-resource/rs`);
    assert.equal(prm.status, 200);
    const doc = await prm.json();
    assert.equal(doc.resource, `${gw}/rs`);
    assert.deepEqual(doc.authorization_servers, ["https://auth.example.com"]);
    assert.deepEqual(doc.scopes_supported, ["files:read"]);
    // With the token the client obtained, the call goes through; the gateway passes the header and keeps no copy.
    const ok = await post(`${gw}/rs`, listMsg, { ...modernHeaders("tools/list"), Authorization: "Bearer tok-good-123" });
    assert.equal(ok.status, 200);
    assert.equal(rs.seen.at(-1).headers.authorization, "Bearer tok-good-123");
    for (const f of filesUnder(home)) assert.ok(!readFileSync(f, "utf8").includes("tok-good-123"), `the token was written to ${f}`);
  });
  await rs.close();
});

test("OAuth discovery: no resource_metadata in the challenge → the gateway adds its own and reads the upstream's well-known metadata; a foreign metadata URL is never fetched", async () => {
  const foreign = await startResourceServer();
  for (const opts of [{ challengeMetadata: false }, { foreignPrm: `${foreign.url.replace(/\/mcp$/, "")}/.well-known/oauth-protected-resource/mcp` }]) {
    const rs = await startResourceServer(opts);
    await withGateway(rs.url, async (gw) => {
      const r = await post(`${gw}/rs`, listMsg, modernHeaders("tools/list"));
      assert.match(r.headers.get("www-authenticate"), new RegExp(`resource_metadata="${gw}/\\.well-known/oauth-protected-resource/rs"`));
      const doc = await (await fetch(`${gw}/.well-known/oauth-protected-resource/rs`)).json();
      assert.equal(doc.resource, `${gw}/rs`);
      assert.ok(rs.seen.some((s) => s.method === "GET" && s.url === "/.well-known/oauth-protected-resource/mcp"));
    });
    await rs.close();
  }
  assert.equal(foreign.seen.length, 0, "the gateway fetched metadata from another origin");
  await foreign.close();
});

test("OAuth discovery: upstream metadata naming another resource is not served (RFC 9728 3.3: the data MUST NOT be used)", async () => {
  const rs = await startResourceServer({ prmResource: "https://other.example/mcp" });
  await withGateway(rs.url, async (gw) => {
    const prm = await fetch(`${gw}/.well-known/oauth-protected-resource/rs`);
    assert.equal(prm.status, 502);
  });
  await rs.close();
});

test("an access token in the query string is refused before anything goes upstream", async () => {
  const rs = await startResourceServer();
  await withGateway(rs.url, async (gw) => {
    const r = await post(`${gw}/rs?access_token=tok-good-123`, listMsg, modernHeaders("tools/list"));
    assert.equal(r.status, 400);
    assert.match(r.json.error.message, /access token in the query string/);
    assert.ok(!rs.seen.some((s) => s.method === "POST"));
  });
  await rs.close();
});
