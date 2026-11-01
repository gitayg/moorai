// The gateway's OAuth checks (mcp-gateway/oauth-gate.mjs, oauth-token.mjs, oauth-as-check.mjs), each against
// the MCP 2026-07-28 authorization text it enforces:
//   * "MCP servers MUST NOT accept or transit any other tokens" / "The MCP server MUST NOT pass through the
//     token it received from the MCP client": a JWT whose audience is another resource is reported by default
//     and not forwarded under audience block.
//   * RFC 8414 3.3 as the revision applies it ("the `issuer` value in the document MUST be identical to the
//     issuer identifier used to construct the well-known URL"), "All authorization server endpoints MUST be
//     served over HTTPS", and PKCE ("If `code_challenge_methods_supported` is absent ... MCP clients MUST
//     refuse to proceed"; S256 required): checked on the authorization servers the gateway's metadata names.
//   * scopes against an admin allow-list per server, on the token and on a step-up challenge.
// A real gateway process, a fake resource server, a fake authorization server, a fake console with a signed
// policy that records alerts.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-gateway-oauth.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { randomBytes } from "node:crypto";
import { readdirSync, readFileSync, statSync, rmSync } from "node:fs";
import { join } from "node:path";
import { startConsole, makeHome, sign, startGateway, stopGateway, H, settle } from "../mcp-gateway/test/harness.mjs";
import { audienceVerdict, issuerVerdict, tokenScopes, excessScopes, jwtClaims, bearerOf, oauthPolicy, createReuseTracker } from "../mcp-gateway/oauth-token.mjs";
import { asMetadataCandidates, asDocFailures, asUrlOk, asAddressOk, asLookup, upstreamIsLoopback } from "../mcp-gateway/oauth-as-check.mjs";
import { networkInterfaces } from "node:os";

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (claims) => `${b64u({ alg: "RS256", typ: "at+jwt" })}.${b64u(claims)}.${randomBytes(32).toString("base64url")}`;
const LIST = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };
async function post(url, headers = {}) {
  const r = await fetch(url, { method: "POST", headers: { ...H, ...headers }, body: JSON.stringify(LIST) });
  const text = await r.text();
  return { status: r.status, headers: r.headers, text, json: (() => { try { return JSON.parse(text); } catch { return null; } })() };
}
function filesUnder(dir) { const out = []; for (const f of readdirSync(dir)) { const p = join(dir, f); if (statSync(p).isDirectory()) out.push(...filesUnder(p)); else out.push(p); } return out; }

// A resource server: PRM at its path, 401 + challenge without a token, any token accepted.
async function startResourceServer({ authorizationServers = ["https://auth.example.com"], challengeScope = "files:read", host = "127.0.0.1" } = {}) {
  const seen = [];
  const srv = http.createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, auth: req.headers.authorization });
      const base = `http://${host}:${srv.address().port}`;
      if (req.method === "GET" && req.url === "/.well-known/oauth-protected-resource/mcp") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ resource: `${base}/mcp`, authorization_servers: authorizationServers, scopes_supported: ["files:read"] }));
      }
      if (req.method === "POST" && req.url === "/mcp") {
        if (!req.headers.authorization) {
          res.writeHead(401, { "WWW-Authenticate": `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp", scope="${challengeScope}"`, "Content-Type": "application/json" });
          return res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "unauthorized" } }));
        }
        const m = JSON.parse(b);
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { tools: [] } }));
      }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, host, r));
  srv.unref();
  const port = srv.address().port;
  return { url: `http://${host}:${port}/mcp`, origin: `http://${host}:${port}`, seen, posts: () => seen.filter((s) => s.method === "POST").length, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}

// An authorization server serving RFC 8414 metadata built by doc(issuer).
async function startAuthServer(doc) {
  const seen = [];
  const srv = http.createServer((req, res) => {
    seen.push(req.url);
    const issuer = `http://127.0.0.1:${srv.address().port}`;
    if (req.url === "/.well-known/oauth-authorization-server") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify(doc(issuer))); }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  srv.unref();
  return { issuer: `http://127.0.0.1:${srv.address().port}`, seen, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}
const goodAs = (issuer) => ({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, code_challenge_methods_supported: ["S256"] });

// One gateway with routes { "/rs": url, ... } under the signed policy.
async function withGateway({ routes, policy = {}, enrolled = true, extraArgs = [] }, fn) {
  const con = await startConsole(sign({ captureTier: "content-free", ...policy }));
  const home = makeHome(con.url, enrolled);
  const args = ["--port", "0", ...extraArgs];
  for (const [p, u] of Object.entries(routes)) args.push("--route", `${p}=${u}`);
  const gw = await startGateway({ home, consoleUrl: con.url, args });
  try { assert.ok(gw.url, gw.stderr); await fn({ gw: gw.url, con, home, port: new URL(gw.url).port }); }
  finally { await stopGateway(gw); await con.close(); rmSync(home, { recursive: true, force: true }); }
}
const oauthAlerts = (con, check) => con.alerts.filter((a) => a.reasonCode === "MCP_OAUTH" && (!check || a.oauthCheck === check));
async function waitAlerts(con, check, n = 1) {
  for (let i = 0; i < 40 && oauthAlerts(con, check).length < n; i++) await settle(50);
  return oauthAlerts(con, check);
}
function assertNoLeak(con, home, secrets) {
  const alertsText = JSON.stringify(con.alerts);
  for (const s of secrets) {
    assert.ok(!alertsText.includes(s), "an alert carried a token or claim value");
    for (const f of filesUnder(home)) assert.ok(!readFileSync(f, "utf8").includes(s), `a token or claim value was written to ${f}`);
  }
}

test("token inspection: audience, issuer, scope, bearer parsing", () => {
  const ctx = { upstream: "https://mcp.example.com/mcp", gatewayHost: "127.0.0.1:8848", routePath: "/rs", extra: ["https://api.example.com"] };
  assert.equal(audienceVerdict({ aud: "https://mcp.example.com/mcp" }, ctx), "match");
  assert.equal(audienceVerdict({ aud: "HTTPS://MCP.example.com" }, ctx), "match", "an origin-wide audience covers the upstream");
  assert.equal(audienceVerdict({ aud: ["https://other.example/mcp", "http://localhost:8848/rs"] }, ctx), "match", "the gateway route, by a loopback alias");
  assert.equal(audienceVerdict({ aud: "https://api.example.com/v1" }, ctx), "match", "an admin-listed audience");
  assert.equal(audienceVerdict({ aud: "https://mcp.example.com/mc" }, ctx), "mismatch", "a path prefix must end at a segment");
  assert.equal(audienceVerdict({ aud: "https://other.example/mcp" }, ctx), "mismatch");
  assert.equal(audienceVerdict({ aud: "http://127.0.0.1:8848/other" }, ctx), "mismatch", "another route of the gateway");
  assert.equal(audienceVerdict({ aud: "http://127.0.0.1:9999/rs" }, ctx), "mismatch", "another port");
  assert.equal(audienceVerdict({ aud: ["https://other.example", "0b5e8a2c-guid"] }, ctx), "mismatch", "a non-URI audience cannot vouch for the route");
  assert.equal(audienceVerdict({ aud: ["https://other.example", 42] }, ctx), "mismatch", "nor can a non-string one");
  assert.equal(audienceVerdict({ aud: ["https://mcp.example.com/mcp", "0b5e8a2c-guid"] }, ctx), "match");
  assert.equal(audienceVerdict({ aud: ["0b5e8a2c-guid", "client-id"] }, ctx), "unknown", "no URI: cannot be judged");
  assert.equal(audienceVerdict({ aud: [] }, ctx), "unknown");
  assert.equal(audienceVerdict({}, ctx), "unknown");
  assert.equal(issuerVerdict({ iss: "https://auth.example.com/" }, ["https://auth.example.com"]), "match");
  assert.equal(issuerVerdict({ iss: "https://evil.example" }, ["https://auth.example.com"]), "mismatch");
  assert.equal(issuerVerdict({ iss: "https://evil.example" }, null), "unknown");
  assert.deepEqual(tokenScopes({ scope: "a b  c" }), ["a", "b", "c"]);
  assert.deepEqual(tokenScopes({ scp: ["a", "b"] }), ["a", "b"]);
  assert.equal(tokenScopes({}), null);
  assert.deepEqual(excessScopes(["a", "b", "b", "c"], ["a"]), ["b", "c"]);
  assert.equal(bearerOf("bearer abc"), "abc");
  assert.equal(bearerOf("Basic abc"), null);
  assert.equal(jwtClaims("ghp_opaqueTokenValue"), null);
  assert.equal(jwtClaims("a.b.c.d.e"), null, "a JWE is opaque");
  assert.deepEqual(jwtClaims(jwt({ aud: "x" })), { aud: "x" });
  const p = oauthPolicy({ mcpOAuth: { audience: "nonsense", scopes: { rs: ["a", 3] } } });
  assert.equal(p.audience, "report", "an unknown mode falls back to the default, never to off");
  assert.equal(p.authServer, "off");
  assert.deepEqual(p.scopes, { rs: ["a"] });
  const t = createReuseTracker(2);
  t.note("tok", "https://a.example");
  assert.equal(t.elsewhere("tok", "https://a.example"), false);
  assert.equal(t.elsewhere("tok", "https://b.example"), true);
  t.note("x", "o"); t.note("y", "o");
  assert.equal(t.size(), 2, "bounded");
  assert.equal(t.elsewhere("tok", "https://b.example"), false, "the oldest entry is dropped");
});

test("authorization-server metadata: candidate URLs in the revision's order, and the issuer / https / PKCE checks", () => {
  assert.deepEqual(asMetadataCandidates("https://auth.example.com"), ["https://auth.example.com/.well-known/oauth-authorization-server", "https://auth.example.com/.well-known/openid-configuration"]);
  assert.deepEqual(asMetadataCandidates("https://auth.example.com/tenant1"), ["https://auth.example.com/.well-known/oauth-authorization-server/tenant1", "https://auth.example.com/.well-known/openid-configuration/tenant1", "https://auth.example.com/tenant1/.well-known/openid-configuration"]);
  const iss = "https://auth.example.com";
  assert.deepEqual(asDocFailures(iss, goodAs(iss)), []);
  assert.deepEqual(asDocFailures(iss, { ...goodAs(iss), issuer: "https://honest.example" }), ["issuer"]);
  assert.deepEqual(asDocFailures(iss, { ...goodAs(iss), token_endpoint: "http://auth.example.com/token" }), ["https"]);
  assert.deepEqual(asDocFailures(iss, { ...goodAs(iss), code_challenge_methods_supported: ["plain"] }), ["pkce"]);
  const { code_challenge_methods_supported: _, ...noPkce } = goodAs(iss);
  assert.deepEqual(asDocFailures(iss, noPkce), ["pkce"]);
});

test("audience: under audience block, a JWT for another resource is refused before it reaches the upstream, with a challenge pointing at the route's metadata; nothing of the token leaves", async () => {
  const rs = await startResourceServer();
  await withGateway({ routes: { "/rs": rs.url }, policy: { mcpOAuth: { audience: "block" } } }, async ({ gw, con, home }) => {
    const foreign = jwt({ aud: "https://victim-api.example/mcp", iss: "https://auth.example.com", scope: "files:read" });
    const r = await post(`${gw}/rs`, { Authorization: `Bearer ${foreign}` });
    assert.equal(r.status, 401, r.text);
    assert.equal(rs.posts(), 0, "the token was forwarded");
    assert.match(r.headers.get("www-authenticate"), new RegExp(`^Bearer resource_metadata="${gw}/\\.well-known/oauth-protected-resource/rs", error="invalid_token"`));
    assert.match(r.json.error.message, /not issued for this MCP server/);
    const [a] = await waitAlerts(con, "audience");
    assert.equal(a.category, "MCP gateway: OAuth token for another resource");
    assert.equal(a.decision, "deny");
    assert.equal(a.riskLevel, "Blocked");
    assert.equal(a.mcpServer, "rs");
    // the same token for this resource goes through
    for (const aud of [rs.url, `${gw}/rs`]) {
      const ok = await post(`${gw}/rs`, { Authorization: `Bearer ${jwt({ aud })}` });
      assert.equal(ok.status, 200, ok.text);
    }
    assert.equal(rs.posts(), 2);
    await settle(200);
    assertNoLeak(con, home, [foreign, "victim-api.example"]);
  });
  await rs.close();
});

test("audience: under audience block, a token issued for another gateway route is not passed to this route's upstream", async () => {
  const a = await startResourceServer(), b = await startResourceServer();
  await withGateway({ routes: { "/a": a.url, "/b": b.url }, policy: { mcpOAuth: { audience: "block" } } }, async ({ gw, port }) => {
    const forA = jwt({ aud: `http://localhost:${port}/a` });
    assert.equal((await post(`${gw}/a`, { Authorization: `Bearer ${forA}` })).status, 200);
    const r = await post(`${gw}/b`, { Authorization: `Bearer ${forA}` });
    assert.equal(r.status, 401, r.text);
    assert.equal(b.posts(), 0);
  });
  await a.close(); await b.close();
});

test("audience: the default (report) forwards and alerts; an admin-listed audience is accepted; coach (unenrolled) forwards under block", async () => {
  const rs = await startResourceServer();
  const foreign = jwt({ aud: "https://api.example.com/v1" });
  await withGateway({ routes: { "/rs": rs.url } }, async ({ gw, con }) => {
    assert.equal((await post(`${gw}/rs`, { Authorization: `Bearer ${foreign}` })).status, 200);
    const [al] = await waitAlerts(con, "audience");
    assert.equal(al.decision, "allow");
    assert.equal(al.riskLevel, "High");
  });
  await withGateway({ routes: { "/rs": rs.url }, policy: { mcpOAuth: { audiences: { rs: ["https://api.example.com"] } } } }, async ({ gw, con }) => {
    assert.equal((await post(`${gw}/rs`, { Authorization: `Bearer ${foreign}` })).status, 200);
    await settle(300);
    assert.equal(oauthAlerts(con).length, 0);
  });
  await withGateway({ routes: { "/rs": rs.url }, policy: { mcpOAuth: { audience: "block" } }, enrolled: false }, async ({ gw }) => {
    assert.equal((await post(`${gw}/rs`, { Authorization: `Bearer ${foreign}` })).status, 200, "coach forwards");
  });
  await rs.close();
});

test("scope: a token's scopes beyond the admin allow-list are reported, refused under scopeAction block; a step-up challenge asking for more is reported", async () => {
  const rs = await startResourceServer({ challengeScope: "files:read admin:all" });
  const broad = jwt({ aud: rs.url, scope: "files:read files:write" });
  const narrow = jwt({ aud: rs.url, scope: "files:read" });
  await withGateway({ routes: { "/rs": rs.url }, policy: { mcpOAuth: { scopes: { rs: ["files:read"] } } } }, async ({ gw, con }) => {
    assert.equal((await post(`${gw}/rs`, { Authorization: `Bearer ${broad}` })).status, 200);
    const [s] = await waitAlerts(con, "scope");
    assert.equal(s.decision, "allow");
    assert.equal(s.excessScopes, 1);
    assert.equal((await post(`${gw}/rs`)).status, 401, "the upstream's own challenge");
    const [c] = await waitAlerts(con, "challenge-scope");
    assert.equal(c.excessScopes, 1);
    assert.ok(!JSON.stringify(con.alerts).includes("files:write") && !JSON.stringify(con.alerts).includes("admin:all"), "a scope name left");
  });
  await withGateway({ routes: { "/rs": rs.url }, policy: { mcpOAuth: { scopes: { rs: ["files:read"] }, scopeAction: "block" } } }, async ({ gw, con }) => {
    const before = rs.posts();
    const r = await post(`${gw}/rs`, { Authorization: `Bearer ${broad}` });
    assert.equal(r.status, 403, r.text);
    assert.equal(rs.posts(), before);
    assert.equal((await waitAlerts(con, "scope"))[0].decision, "deny");
    assert.equal((await post(`${gw}/rs`, { Authorization: `Bearer ${narrow}` })).status, 200);
  });
  await rs.close();
});

test("issuer: once the upstream's metadata is known, a JWT from another issuer is reported, refused under issuer block", async () => {
  const rs = await startResourceServer({ authorizationServers: ["https://auth.example.com"] });
  const evil = jwt({ aud: rs.url, iss: "https://evil-as.example" });
  const good = jwt({ aud: rs.url, iss: "https://auth.example.com" });
  await withGateway({ routes: { "/rs": rs.url }, policy: { mcpOAuth: { issuer: "block" } } }, async ({ gw, con }) => {
    assert.equal((await post(`${gw}/rs`, { Authorization: `Bearer ${evil}` })).status, 200, "unknown metadata: no verdict");
    assert.equal((await fetch(`${gw}/.well-known/oauth-protected-resource/rs`)).status, 200);
    const r = await post(`${gw}/rs`, { Authorization: `Bearer ${evil}` });
    assert.equal(r.status, 401, r.text);
    assert.equal((await waitAlerts(con, "issuer"))[0].decision, "deny");
    assert.equal((await post(`${gw}/rs`, { Authorization: `Bearer ${good}` })).status, 200);
  });
  await rs.close();
});

test("reuse: an opaque bearer token sent to a second upstream origin is reported, refused under tokenReuse block", async () => {
  const a = await startResourceServer(), b = await startResourceServer();
  const tok = `ghp_${randomBytes(18).toString("hex")}`;
  await withGateway({ routes: { "/a": a.url, "/b": b.url } }, async ({ gw, con, home }) => {
    assert.equal((await post(`${gw}/a`, { Authorization: `Bearer ${tok}` })).status, 200);
    assert.equal((await post(`${gw}/a`, { Authorization: `Bearer ${tok}` })).status, 200);
    await settle(200);
    assert.equal(oauthAlerts(con, "reuse").length, 0, "the same upstream twice is not reuse");
    assert.equal((await post(`${gw}/b`, { Authorization: `Bearer ${tok}` })).status, 200);
    const [al] = await waitAlerts(con, "reuse");
    assert.equal(al.mcpServer, "b");
    assert.equal(al.decision, "allow");
    assertNoLeak(con, home, [tok]);
  });
  await withGateway({ routes: { "/a": a.url, "/b": b.url }, policy: { mcpOAuth: { tokenReuse: "block" } } }, async ({ gw }) => {
    const before = b.posts();
    assert.equal((await post(`${gw}/a`, { Authorization: `Bearer ${tok}` })).status, 200);
    assert.equal((await post(`${gw}/b`, { Authorization: `Bearer ${tok}` })).status, 401);
    assert.equal(b.posts(), before);
  });
  await a.close(); await b.close();
});

// One POST with the given header lines written as is (fetch joins repeated headers into one).
function rawPost(url, headerLines) {
  const u = new URL(url);
  const body = JSON.stringify(LIST);
  return new Promise((resolve, reject) => {
    const s = net.connect(Number(u.port), u.hostname, () => s.write([`POST ${u.pathname} HTTP/1.1`, `Host: ${u.host}`, "Content-Type: application/json", "Accept: application/json, text/event-stream", `Content-Length: ${Buffer.byteLength(body)}`, "Connection: close", ...headerLines, "", body].join("\r\n")));
    let out = "";
    s.on("data", (c) => (out += c));
    s.on("end", () => resolve({ status: Number(/^HTTP\/1\.1 (\d+)/.exec(out)?.[1]), text: out }));
    s.on("error", reject);
  });
}

test("malformed: an Authorization value that names Bearer but is not exactly one token is reported, refused 400 under audience block, a second Authorization header too; its parts still get the token checks", async () => {
  const a = await startResourceServer(), b = await startResourceServer();
  const foreign = jwt({ aud: "https://victim-api.example/mcp" });
  const tok = `ghp_${randomBytes(18).toString("hex")}`;
  await withGateway({ routes: { "/a": a.url, "/b": b.url } }, async ({ gw, con, home }) => {
    assert.equal((await post(`${gw}/a`, { Authorization: `Bearer ${foreign} trailing` })).status, 200, "report forwards");
    const [m] = await waitAlerts(con, "malformed");
    assert.ok(m, "no malformed alert");
    assert.equal(m.decision, "allow");
    assert.equal(m.category, "MCP gateway: Authorization header without exactly one Bearer token");
    assert.equal((await waitAlerts(con, "audience"))[0].decision, "allow", "the JWT inside the malformed value is still judged");
    assert.equal((await post(`${gw}/a`, { Authorization: "Basic dXNlcjpwYXNz" })).status, 200);
    await settle(200);
    assert.equal(oauthAlerts(con, "malformed").length, 1, "another scheme is not judged");
    assertNoLeak(con, home, [foreign, tok, "victim-api.example", "trailing"]);
  });
  await withGateway({ routes: { "/a": a.url, "/b": b.url }, policy: { mcpOAuth: { audience: "block" } } }, async ({ gw, con }) => {
    const good = jwt({ aud: a.url });
    const before = a.posts();
    for (const v of [`Bearer ${good} junk`, `Bearer ${good},x`, `Bearer ${good}, Bearer ${tok}`, "Bearer"]) {
      const r = await post(`${gw}/a`, { Authorization: v });
      assert.equal(r.status, 400, `${v.replace(good, "<jwt>")}: ${r.text}`);
      assert.match(r.headers.get("www-authenticate"), /error="invalid_request"/);
    }
    const dup = await rawPost(`${gw}/a`, [`Authorization: Bearer ${good}`, `Authorization: Bearer ${tok}`]);
    assert.equal(dup.status, 400, dup.text);
    assert.equal(a.posts(), before, "a malformed value reached the upstream");
    assert.equal((await waitAlerts(con, "malformed"))[0].decision, "deny");
    assert.equal((await post(`${gw}/a`, { Authorization: `Bearer ${good}` })).status, 200, "one token passes");
  });
  await withGateway({ routes: { "/a": a.url, "/b": b.url }, policy: { mcpOAuth: { tokenReuse: "block" } } }, async ({ gw }) => {
    assert.equal((await post(`${gw}/a`, { Authorization: `Bearer ${tok}` })).status, 200);
    const before = b.posts();
    assert.equal((await post(`${gw}/b`, { Authorization: `Bearer ${tok} extra` })).status, 401, "a token reused inside a malformed value");
    assert.equal(b.posts(), before);
  });
  await a.close(); await b.close();
});

test("audience: a non-URI aud value (a client id, a GUID) beside URIs that all name another resource does not turn the verdict into no verdict, alone, padded past 64 values, or inside a malformed value; a token whose aud values are all non-URI still has no verdict and keeps the reuse check", async () => {
  const a = await startResourceServer(), b = await startResourceServer();
  const mixed = jwt({ aud: ["https://victim-api.example/mcp", "0b5e8a2c-guid"] });
  const padded = jwt({ aud: [...Array.from({ length: 64 }, (_, i) => `client-${i}`), "https://victim-api.example/mcp"] });
  const opaqueAud = jwt({ aud: ["0b5e8a2c-guid", "client-id"] });
  await withGateway({ routes: { "/a": a.url, "/b": b.url }, policy: { mcpOAuth: { audience: "block" } } }, async ({ gw, con, home }) => {
    for (const t of [mixed, padded]) {
      const r = await post(`${gw}/a`, { Authorization: `Bearer ${t}` });
      assert.equal(r.status, 401, r.text);
      assert.match(r.headers.get("www-authenticate"), /error="invalid_token"/);
    }
    assert.equal(a.posts(), 0, "a token for another resource was forwarded");
    assert.equal((await waitAlerts(con, "audience"))[0].decision, "deny");
    assert.equal((await post(`${gw}/a`, { Authorization: `Bearer ${opaqueAud}` })).status, 200, "all non-URI: no verdict");
    assert.equal((await post(`${gw}/a`, { Authorization: `Bearer ${jwt({ aud: [a.url, "0b5e8a2c-guid"] })}` })).status, 200, "a URI that matches still matches");
    await settle(200);
    assertNoLeak(con, home, [mixed, padded, "victim-api.example", "0b5e8a2c-guid"]);
  });
  await withGateway({ routes: { "/a": a.url, "/b": b.url } }, async ({ gw, con }) => {
    assert.equal((await post(`${gw}/a`, { Authorization: `Bearer ${mixed} trailing` })).status, 200, "report forwards");
    assert.equal((await waitAlerts(con, "audience"))[0]?.decision, "allow", "the mixed JWT inside a malformed value is judged");
  });
  await withGateway({ routes: { "/a": a.url, "/b": b.url }, policy: { mcpOAuth: { tokenReuse: "block" } } }, async ({ gw }) => {
    for (const t of [mixed, opaqueAud]) {
      assert.equal((await post(`${gw}/a`, { Authorization: `Bearer ${t}` })).status, 200);
      const before = b.posts();
      assert.equal((await post(`${gw}/b`, { Authorization: `Bearer ${t}` })).status, 401, "reuse still applies");
      assert.equal(b.posts(), before);
    }
  });
  await a.close(); await b.close();
});

test("authorization servers: under authServer block, metadata that fails the issuer, https or PKCE check is not served; report serves and alerts; off fetches nothing", async () => {
  const cases = [
    [(iss) => goodAs(iss), null],
    [(iss) => ({ ...goodAs(iss), issuer: "https://honest.example" }), "issuer"],
    [(iss) => ({ ...goodAs(iss), token_endpoint: "http://auth.example.com/token" }), "https"],
    [(iss) => ({ ...goodAs(iss), code_challenge_methods_supported: ["plain"] }), "pkce"]
  ];
  for (const [doc, fails] of cases) {
    const as = await startAuthServer(doc);
    const rs = await startResourceServer({ authorizationServers: [as.issuer] });
    await withGateway({ routes: { "/rs": rs.url }, policy: { mcpOAuth: { authServer: "block" } } }, async ({ gw, con }) => {
      const prm = await fetch(`${gw}/.well-known/oauth-protected-resource/rs`);
      assert.equal(prm.status, fails ? 502 : 200, `${fails}: ${await prm.text()}`);
      if (fails) {
        const [al] = await waitAlerts(con, "auth-server");
        assert.deepEqual(al.authServerChecks, [fails]);
        assert.equal(al.decision, "deny");
      }
    });
    await rs.close(); await as.close();
  }
  const as = await startAuthServer((iss) => ({ ...goodAs(iss), code_challenge_methods_supported: undefined }));
  const rs = await startResourceServer({ authorizationServers: [as.issuer] });
  await withGateway({ routes: { "/rs": rs.url }, policy: { mcpOAuth: { authServer: "report" } } }, async ({ gw, con }) => {
    assert.equal((await fetch(`${gw}/.well-known/oauth-protected-resource/rs`)).status, 200);
    const [al] = await waitAlerts(con, "auth-server");
    assert.deepEqual(al.authServerChecks, ["pkce"]);
    assert.equal(al.decision, "allow");
  });
  const fetched = as.seen.length;
  assert.ok(fetched > 0);
  await withGateway({ routes: { "/rs": rs.url } }, async ({ gw }) => {
    assert.equal((await fetch(`${gw}/.well-known/oauth-protected-resource/rs`)).status, 200);
  });
  assert.equal(as.seen.length, fetched, "with authServer off the gateway fetched authorization-server metadata");
  await rs.close(); await as.close();
});

test("authorization servers: a document naming more servers than the check reads (4) is refused under authServer block and reported under report; 4 are checked as before", async () => {
  const good = await startAuthServer((iss) => goodAs(iss));
  const bad = await startAuthServer((iss) => ({ ...goodAs(iss), code_challenge_methods_supported: ["plain"] }));
  const five = await startResourceServer({ authorizationServers: [good.issuer, good.issuer, good.issuer, good.issuer, bad.issuer] });
  await withGateway({ routes: { "/rs": five.url }, policy: { mcpOAuth: { authServer: "block" } } }, async ({ gw, con }) => {
    const prm = await fetch(`${gw}/.well-known/oauth-protected-resource/rs`);
    assert.equal(prm.status, 502, await prm.text());
    const [al] = await waitAlerts(con, "auth-server");
    assert.deepEqual([al.authServerChecks, al.decision], [["too-many-servers"], "deny"]);
  });
  await withGateway({ routes: { "/rs": five.url }, policy: { mcpOAuth: { authServer: "report" } } }, async ({ gw, con }) => {
    assert.equal((await fetch(`${gw}/.well-known/oauth-protected-resource/rs`)).status, 200);
    const [al] = await waitAlerts(con, "auth-server");
    assert.deepEqual([al.authServerChecks, al.decision], [["too-many-servers"], "allow"]);
  });
  const four = await startResourceServer({ authorizationServers: [good.issuer, good.issuer, good.issuer, bad.issuer] });
  await withGateway({ routes: { "/rs": four.url }, policy: { mcpOAuth: { authServer: "block" } } }, async ({ gw, con }) => {
    assert.equal((await fetch(`${gw}/.well-known/oauth-protected-resource/rs`)).status, 502);
    const [al] = await waitAlerts(con, "auth-server");
    assert.deepEqual(al.authServerChecks, ["pkce"]);
  });
  await five.close(); await four.close(); await good.close(); await bad.close();
});

// A TCP listener that counts connections and answers each request with an authorization server document that
// fails PKCE (so a fetch that got through would be visible as a 502 under authServer block).
async function startCountingAs() {
  let conns = 0;
  const srv = http.createServer((req, res) => {
    const issuer = `http://127.0.0.1:${srv.address().port}`;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ...goodAs(issuer), code_challenge_methods_supported: ["plain"] }));
  });
  srv.on("connection", () => { conns++; });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  srv.unref();
  return { port: srv.address().port, conns: () => conns, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}
const lanIp = Object.values(networkInterfaces()).flat().find((a) => a && a.family === "IPv4" && !a.internal)?.address;

test("authorization servers: fetch targets are https and public; loopback only for a loopback upstream; private, link-local and metadata addresses never", () => {
  assert.equal(upstreamIsLoopback("http://127.0.0.1:3000/mcp"), true);
  assert.equal(upstreamIsLoopback("http://localhost:3000/mcp"), true);
  assert.equal(upstreamIsLoopback("http://[::ffff:127.0.0.1]:3000/mcp"), true);
  assert.equal(upstreamIsLoopback("https://mcp.example.com/mcp"), false);
  assert.equal(upstreamIsLoopback("http://192.168.1.5/mcp"), false);
  for (const lo of [false, true]) {
    for (const ip of ["169.254.169.254", "fd00:ec2::254", "::ffff:169.254.169.254", "169.254.170.2", "100.100.100.200", "10.0.0.5", "192.168.1.1", "172.16.0.1", "fe80::1", "fc00::1", "0.0.0.0"]) assert.equal(asAddressOk(ip, lo), false, `${ip} lo=${lo}`);
    assert.equal(asAddressOk("93.184.216.34", lo), true);
    assert.equal(asAddressOk("127.0.0.1", lo), lo);
    assert.equal(asAddressOk("::1", lo), lo);
    assert.equal(asUrlOk("https://auth.example.com", lo), true);
    assert.equal(asUrlOk("http://auth.example.com/.well-known/oauth-authorization-server", lo), false, "http to a non-loopback host");
    assert.equal(asUrlOk("https://169.254.169.254/latest", lo), false);
    assert.equal(asUrlOk("https://[fd00:ec2::254]/", lo), false);
    assert.equal(asUrlOk("https://10.1.2.3/", lo), false);
    assert.equal(asUrlOk("http://127.0.0.1:9000/", lo), lo);
    assert.equal(asUrlOk("http://localhost:9000/", lo), lo);
    assert.equal(asUrlOk("ftp://auth.example.com/", lo), false);
  }
  const fake = (addrs) => (h, o, cb) => cb(null, addrs.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })));
  const run = (addrs, lo) => new Promise((r) => asLookup(fake(addrs), lo)("as.example", { all: true }, (err, list) => r(err ? err.code : list.length)));
  return (async () => {
    assert.equal(await run(["93.184.216.34"], false), 1);
    assert.equal(await run(["169.254.169.254"], true), "MOORAI_AS_ADDRESS", "a name that resolves to cloud metadata");
    assert.equal(await run(["fd00:ec2::254"], false), "MOORAI_AS_ADDRESS");
    assert.equal(await run(["93.184.216.34", "10.0.0.5"], false), "MOORAI_AS_ADDRESS", "any private answer refuses");
    assert.equal(await run(["127.0.0.1"], false), "MOORAI_AS_ADDRESS");
    assert.equal(await run(["127.0.0.1"], true), 1);
  })();
});

test("authorization servers: with a non-loopback upstream, a loopback, private or metadata authorization server named by the upstream is never fetched (by literal or by a name that resolves to loopback), fails the check as `address`: 502 under authServer block, reported under report", { skip: !lanIp && "no non-loopback IPv4 interface" }, async () => {
  const as = await startCountingAs();
  for (const named of [`http://127.0.0.1:${as.port}`, `https://localhost:${as.port}`, "https://10.1.2.3", "https://169.254.169.254"]) {
    const rs = await startResourceServer({ host: lanIp, authorizationServers: [named] });
    await withGateway({ routes: { "/rs": rs.url }, policy: { mcpOAuth: { authServer: "block" } }, extraArgs: ["--allow-insecure-upstream"] }, async ({ gw, con }) => {
      const prm = await fetch(`${gw}/.well-known/oauth-protected-resource/rs`);
      assert.equal(prm.status, 502, `${named}: ${await prm.text()}`);
      const [al] = await waitAlerts(con, "auth-server");
      assert.deepEqual([al?.authServerChecks, al?.decision], [["address"], "deny"], named);
    });
    await withGateway({ routes: { "/rs": rs.url }, policy: { mcpOAuth: { authServer: "report" } }, extraArgs: ["--allow-insecure-upstream"] }, async ({ gw, con }) => {
      assert.equal((await fetch(`${gw}/.well-known/oauth-protected-resource/rs`)).status, 200);
      const [al] = await waitAlerts(con, "auth-server");
      assert.deepEqual([al?.authServerChecks, al?.decision], [["address"], "allow"], named);
    });
    assert.equal(as.conns(), 0, `the gateway connected to ${named}`);
    await rs.close();
  }
  // an egress cidr rule that also blocks the address does not turn the refusal into unreadable metadata
  const rs = await startResourceServer({ host: lanIp, authorizationServers: [`https://localhost:${as.port}`] });
  await withGateway({ routes: { "/rs": rs.url }, policy: { mcpOAuth: { authServer: "block" }, egressRules: [{ id: "no-loopback", cidr: "127.0.0.0/8", action: "block" }] }, extraArgs: ["--allow-insecure-upstream"] }, async ({ gw, con }) => {
    assert.equal((await fetch(`${gw}/.well-known/oauth-protected-resource/rs`)).status, 502);
    const [al] = await waitAlerts(con, "auth-server");
    assert.deepEqual(al?.authServerChecks, ["address"]);
  });
  assert.equal(as.conns(), 0);
  await rs.close();
  await as.close();
});

test("authorization servers: an authorization server at an allowed address whose metadata cannot be read gets no verdict, also under authServer block", async () => {
  const closed = http.createServer();
  await new Promise((r) => closed.listen(0, "127.0.0.1", r));
  const deadPort = closed.address().port;
  await new Promise((r) => closed.close(r));
  const rs = await startResourceServer({ authorizationServers: [`http://127.0.0.1:${deadPort}`] });
  await withGateway({ routes: { "/rs": rs.url }, policy: { mcpOAuth: { authServer: "block" } } }, async ({ gw, con }) => {
    assert.equal((await fetch(`${gw}/.well-known/oauth-protected-resource/rs`)).status, 200);
    await settle(300);
    assert.equal(oauthAlerts(con, "auth-server").length, 0);
  });
  await rs.close();
});

test("authorization servers: concurrent unauthenticated metadata requests share one read of the upstream and one authorization-server check", async () => {
  const as = await startAuthServer((iss) => goodAs(iss));
  const rs = await startResourceServer({ authorizationServers: [as.issuer] });
  await withGateway({ routes: { "/rs": rs.url }, policy: { mcpOAuth: { authServer: "report" } } }, async ({ gw }) => {
    const all = await Promise.all(Array.from({ length: 12 }, () => fetch(`${gw}/.well-known/oauth-protected-resource/rs`).then((r) => r.status)));
    assert.deepEqual([...new Set(all)], [200]);
    for (let i = 0; i < 3; i++) assert.equal((await fetch(`${gw}/.well-known/oauth-protected-resource/rs`)).status, 200);
  });
  assert.equal(as.seen.length, 1, `authorization-server fetches: ${as.seen.length}`);
  assert.equal(rs.seen.filter((x) => x.method === "GET").length, 1, "upstream metadata reads");
  await rs.close(); await as.close();
});
