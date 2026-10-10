// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/model-proxy-credentials.test.mjs
//
// Placeholder credentials in moorai-model-proxy (model-proxy/credentials.mjs, credential-mask.mjs): the agent
// sends `moorai-ph:<name>`, the real CLI swaps in the bound secret on the bound route only, refuses every
// other placeholder use, masks a secret the upstream echoes, and refuses an unsafe bindings file. Fake
// provider and fake console; the "secrets" are test strings that exist only in this file.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import net from "node:net";
import { startFakeProvider, sendJson, sendSse, anthropicMessage, anthropicStream, openaiCompletion, openaiStream } from "../model-proxy/test/fake-provider.mjs";
import { CLI, sandbox, startConsole, startProxy, request, waitFor, sseEvents } from "../model-proxy/test/harness.mjs";
import { checkFileSafe, loadBindings } from "../model-proxy/credentials.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const SECRET_A = "FAKE-anthropic-secret-0123456789abcdefXYZ";
const SECRET_O = "FAKE-openai-secret-9876543210zyxwvuQRS";
const PH_A = "moorai-ph:anthropic-test";
const PH_O = "moorai-ph:openai-test";
const RAW_KEY = "sk-ant-FAKE-raw-key-not-a-placeholder-000111";
const MSG = { model: "claude-fake", max_tokens: 64, messages: [{ role: "user", content: "What is the capital of France?" }] };
const OMSG = { model: "gpt-fake", messages: [{ role: "user", content: "Capital of France?" }] };
const A_PH = { "x-api-key": PH_A, "anthropic-version": "2023-06-01" };
const O_PH = { authorization: `Bearer ${PH_O}` };
const POSIX = process.platform !== "win32";

let fp, con, home, credFile, secretFile, px, enf, req;
const env = () => ({ MOORAI_SERVER_URL: con.url, MOORAI_INSTALL_TOKEN: "tok-model-proxy-cred", MOORAI_TENANT: "t-mp", FAKE_ANTHROPIC_SECRET: SECRET_A });
const routes = () => ["--route", `/anthropic=${fp.url}`, "--route", `/openai=${fp.url}/v1`, "--route", `/other=${fp.url}`];
function writeBindings(path, bindings, mode = 0o600) { writeFileSync(path, JSON.stringify({ bindings }), { mode }); chmodSync(path, mode); }
const goodBindings = () => ({
  [PH_A]: { secret: { env: "FAKE_ANTHROPIC_SECRET" }, route: "/anthropic", upstream: fp.url, header: "x-api-key" },
  [PH_O]: { secret: { file: secretFile }, route: "/openai", upstream: `${fp.url}/v1`, header: "authorization", scheme: "Bearer" }
});

before(async () => {
  fp = await startFakeProvider();
  con = await startConsole();
  home = sandbox();
  credFile = join(home, "credentials.json");
  secretFile = join(home, "openai.secret");
  writeFileSync(secretFile, `${SECRET_O}\n`, { mode: 0o600 }); chmodSync(secretFile, 0o600);
  writeBindings(credFile, goodBindings());
  px = await startProxy(home, [...routes(), "--credentials", credFile, "--log"], env());
  enf = await startProxy(home, [...routes(), "--mode", "enforce", "--log"], { ...env(), MOORAI_MODEL_PROXY_CREDENTIALS: credFile });
  req = await startProxy(home, [...routes(), "--credentials", credFile, "--require-placeholders", "--log"], env());
});
// Defensive: a before() that failed half-way must not leave servers open and hang the run.
after(async () => { for (const p of [px, enf, req]) await p?.stop(); await fp?.close(); await con?.close(); if (home) rmTree(home); });

// Every byte a client could see: status line fields, headers, body; and every place the proxy writes to.
const visible = (r) => `${r.status} ${JSON.stringify(r.headers)} ${r.raw.toString("latin1")}`;
function assertNoSecret(text, where) {
  for (const s of [SECRET_A, SECRET_O]) assert.ok(!String(text).includes(s), `${where} carries a bound secret`);
}

test("startup line names the placeholders only; the env-var path (MOORAI_MODEL_PROXY_CREDENTIALS) loads the same file", () => {
  assert.deepEqual(px.credentials, { placeholders: [PH_A, PH_O], requirePlaceholders: false });
  assert.deepEqual(enf.credentials, { placeholders: [PH_A, PH_O], requirePlaceholders: false });
  assert.equal(req.credentials.requirePlaceholders, true);
  assertNoSecret(JSON.stringify([px.credentials, enf.credentials, req.credentials]), "the startup line");
});

test("swap: the bound secret reaches the upstream in the bound header (both APIs, with its scheme); nothing else changes", async () => {
  let sent;
  fp.on((r, res) => { sent = sendJson(res, anthropicMessage({ text: "Paris." })); });
  const n = fp.requests.length;
  const a = await request(px.listening, "/anthropic/v1/messages", { body: MSG, headers: A_PH });
  assert.equal(a.status, 200);
  assert.ok(a.raw.equals(sent), "the response is forwarded unchanged");
  assert.equal(fp.requests[n].headers["x-api-key"], SECRET_A);
  assert.equal(fp.requests[n].headers["anthropic-version"], "2023-06-01");
  assert.ok(fp.requests[n].body.equals(Buffer.from(JSON.stringify(MSG))));

  fp.on((r, res) => sendJson(res, openaiCompletion({ text: "Paris." })));
  const o = await request(px.listening, "/openai/chat/completions", { body: OMSG, headers: O_PH });
  assert.equal(o.status, 200);
  assert.equal(fp.requests.at(-1).headers.authorization, `Bearer ${SECRET_O}`, "scheme kept, the file secret trimmed");

  // An unparsed path on the bound route is swapped too.
  fp.on((r, res) => sendJson(res, { data: [] }));
  const g = await request(px.listening, "/anthropic/v1/models", { method: "GET", headers: A_PH });
  assert.equal(g.status, 200);
  assert.equal(fp.requests.at(-1).headers["x-api-key"], SECRET_A);
});

// The Gemini API's documented query-string auth: `?key=<API key>`. MEASURED BEFORE THIS CHANGE: forwarded
// with no alert, and forwarded even with --require-placeholders, because only headers were checked.
test("a raw key in the ?key= query string is a raw credential: reported once per route and forwarded; --require-placeholders refuses it (401)", async () => {
  const GKEY = "AIzaFAKE-gemini-raw-key-0000000000000000";
  const GPATH = `/other/v1beta/models?alt=json&key=${GKEY}`;
  fp.on((r, res) => sendJson(res, { models: [] }));
  const n0 = con.alerts.length, n = fp.requests.length;
  const a = await request(px.listening, GPATH, { method: "GET" });
  assert.equal(a.status, 200);
  assert.ok(fp.requests[n].url.includes(`key=${GKEY}`), "report mode forwards the client's own key untouched");
  assert.ok(await waitFor(() => con.parsed().slice(n0).some((x) => /raw credential sent/.test(x.category) && x.tool === "model-proxy:credential:other")));
  const quiet = await request(px.listening, "/other/v1beta/models?alt=json&key=", { method: "GET" });
  assert.equal(quiet.status, 200, "an empty key is no credential");

  const m = fp.requests.length;
  const refused = await request(req.listening, GPATH, { method: "GET" });
  assert.equal(refused.status, 401); assert.match(refused.json.error.message, /accepts only credential placeholders/);
  assert.equal(fp.requests.length, m, "nothing forwarded");
  assert.ok(await waitFor(() => con.parsed().some((x) => /raw credential refused/.test(x.category) && x.tool === "model-proxy:credential:other")));
  const none = await request(req.listening, "/other/v1beta/models?alt=json", { method: "GET" });
  assert.equal(none.status, 200, "a query with no key is not a raw credential");
  for (const s of [JSON.stringify(con.parsed()), visible(refused), px.stderr(), req.stderr()]) assert.ok(!s.includes(GKEY) && !s.includes("gemini-raw-key"), "content-free: the key is never echoed, logged or reported");
});

test("a placeholder on the wrong route (same host), in the wrong header, or in the URL is refused and never forwarded", async () => {
  fp.on((r, res) => sendJson(res, anthropicMessage()));
  const n = fp.requests.length;
  // /other points at the very same upstream host as /anthropic: route AND host must both match.
  const other = await request(px.listening, "/other/v1/messages", { body: MSG, headers: A_PH });
  assert.equal(other.status, 403); assert.equal(other.json.error.type, "permission_error");
  assert.match(other.json.error.message, /not bound to this route/);
  const cross = await request(px.listening, "/anthropic/v1/messages", { body: MSG, headers: { authorization: `Bearer ${PH_O}` } });
  assert.equal(cross.status, 403); assert.match(cross.json.error.message, /not bound to this route/);
  const wrongHeader = await request(px.listening, "/anthropic/v1/messages", { body: MSG, headers: { "x-custom-key": PH_A } });
  assert.equal(wrongHeader.status, 403); assert.match(wrongHeader.json.error.message, /not bound to this header/);
  const inUrl = await request(px.listening, `/anthropic/v1/messages?key=${encodeURIComponent(PH_A)}`, { body: MSG, headers: A_PH });
  assert.equal(inUrl.status, 400); assert.match(inUrl.json.error.message, /in the URL is never swapped/);
  const openaiShape = await request(px.listening, "/openai/chat/completions", { body: OMSG, headers: { "x-api-key": PH_A } });
  assert.equal(openaiShape.status, 403); assert.ok(openaiShape.json.error.message, "OpenAI error shape");
  assert.equal(fp.requests.length, n, "nothing reached the upstream");
  for (const r of [other, cross, wrongHeader, inUrl, openaiShape]) { assertNoSecret(visible(r), "a refusal"); assert.ok(!visible(r).includes("anthropic-test"), "content-free: no placeholder name echoed"); }
});

test("an unknown or malformed placeholder is refused (401), never forwarded", async () => {
  const n = fp.requests.length;
  const unknown = await request(px.listening, "/anthropic/v1/messages", { body: MSG, headers: { "x-api-key": "moorai-ph:nope" } });
  assert.equal(unknown.status, 401); assert.equal(unknown.json.error.type, "authentication_error");
  assert.match(unknown.json.error.message, /unknown or malformed credential placeholder/);
  const wrongScheme = await request(px.listening, "/openai/chat/completions", { body: OMSG, headers: { authorization: `Basic ${PH_O}` } });
  assert.equal(wrongScheme.status, 401);
  const noScheme = await request(px.listening, "/openai/chat/completions", { body: OMSG, headers: { authorization: PH_O } });
  assert.equal(noScheme.status, 401);
  const glued = await request(px.listening, "/anthropic/v1/messages", { body: MSG, headers: { "x-api-key": `${PH_A}x y` } });
  assert.equal(glued.status, 401);
  assert.equal(fp.requests.length, n);
});

// Raw HTTP: the only way to send two spellings of one header name.
function rawRequest(base, lines, body) {
  const u = new URL(base);
  return new Promise((res, rej) => {
    const s = net.connect(Number(u.port), u.hostname, () => s.write(`POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n${lines.join("\r\n")}\r\n\r\n${body}`));
    let out = ""; s.on("data", (d) => (out += d)); s.on("end", () => res(out)); s.on("error", rej);
  });
}
test("case-variant duplicates of a credential header are refused (400): Node would keep the first Authorization, or join two x-api-key values", async () => {
  fp.on((r, res) => sendJson(res, anthropicMessage()));
  const n = fp.requests.length;
  const body = JSON.stringify(MSG);
  const a = await rawRequest(px.listening, [`X-Api-Key: ${PH_A}`, `x-api-key: ${RAW_KEY}`], body);
  assert.match(a, /^HTTP\/1\.1 400 /); assert.match(a, /appears more than once/);
  const b = await rawRequest(px.listening, [`Authorization: Bearer ${PH_O}`, `authorization: Bearer ${RAW_KEY}`], body);
  assert.match(b, /^HTTP\/1\.1 400 /);
  const c = await rawRequest(px.listening, [`x-api-key: ${PH_A}`, `X-API-KEY: ${PH_A}`], body);
  assert.match(c, /^HTTP\/1\.1 400 /);
  assert.equal(fp.requests.length, n);
  // one spelling, any case: swapped
  const ok = await rawRequest(px.listening, [`X-API-Key: ${PH_A}`], body);
  assert.match(ok, /^HTTP\/1\.1 200 /);
  assert.equal(fp.requests.at(-1).headers["x-api-key"], SECRET_A);
});

// The upstream echoes whatever key it received, everywhere it can.
const echoKey = (r) => r.headers["x-api-key"] || String(r.headers.authorization || "").replace(/^Bearer /, "");
test("an upstream that echoes the secret: masked in every client-visible byte — JSON, SSE split in 5-byte slices, error body, headers, redirect, gzip — in report and enforce", async () => {
  const cases = [
    ["json", "/anthropic/v1/messages", A_PH, MSG, (r, res) => sendJson(res, anthropicMessage({ text: `your key is ${echoKey(r)}.` }), { headers: { "x-echo": echoKey(r), "set-cookie": [`k=${echoKey(r)}`, "b=1"] } })],
    ["sse", "/anthropic/v1/messages", A_PH, { ...MSG, stream: true }, (r, res) => sendSse(res, anthropicStream({ text: `stream key ${echoKey(r)} and again ${echoKey(r)}` }), { slice: 5 })],
    ["openai-sse", "/openai/chat/completions", O_PH, { ...OMSG, stream: true }, (r, res) => sendSse(res, openaiStream({ text: `${echoKey(r)}${echoKey(r)}` }), { slice: 3 })],
    ["openai-json", "/openai/chat/completions", O_PH, OMSG, (r, res) => sendJson(res, openaiCompletion({ text: `Bearer ${echoKey(r)}` }))],
    ["error", "/anthropic/v1/messages", A_PH, MSG, (r, res) => sendJson(res, { type: "error", error: { type: "authentication_error", message: `invalid x-api-key ${echoKey(r)}` } }, { status: 401, headers: { "www-authenticate": `Bearer realm="${echoKey(r)}"` } })],
    ["redirect", "/anthropic/v1/models", A_PH, undefined, (r, res) => { res.writeHead(302, { location: `https://elsewhere.example/?key=${echoKey(r)}`, "content-length": 0 }); res.end(); }],
    ["gzip", "/anthropic/v1/messages", A_PH, MSG, (r, res) => { const b = gzipSync(JSON.stringify(anthropicMessage({ text: `gz ${echoKey(r)}` }))); res.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip", "content-length": b.length }); res.end(b); }]
  ];
  for (const proxy of [px, enf]) {
    for (const [name, path, headers, body, handler] of cases) {
      fp.on(handler);
      const r = await request(proxy.listening, path, { method: body ? "POST" : "GET", body, headers });
      assertNoSecret(visible(r), `${name} (${proxy === px ? "report" : "enforce"})`);
      assert.ok(/\*{20,}/.test(visible(r)), `${name}: the echo is masked in place, not dropped`);
      if (name === "json") { assert.equal(r.status, 200); assert.equal(Number(r.headers["content-length"]), r.raw.length, "same-length mask keeps Content-Length right"); assert.equal(r.json.content[0].type, "text"); }
      if (name === "gzip") { assert.equal(r.status, 200); assert.equal(r.headers["content-encoding"], undefined, "decoded to be checked"); assert.match(r.json.content[0].text, /^gz \*+$/); }
      if (/sse/.test(name)) {
        // what an SDK assembles from the deltas, not just the wire bytes
        const text = sseEvents(r.raw).map((e) => { try { const d = JSON.parse(e.data); return d.delta?.text ?? d.choices?.[0]?.delta?.content ?? ""; } catch { return ""; } }).join("");
        assert.match(text, /\*{20,}/); assertNoSecret(text, `${name}: the assembled text`);
      }
      if (name === "redirect") { assert.equal(r.status, 302); assert.match(r.headers.location, /^https:\/\/elsewhere\.example\/\?key=\*+$/); }
    }
  }
  // An unknown content coding cannot be checked for an echo: refused.
  fp.on((r, res) => { res.writeHead(200, { "content-type": "application/json", "content-encoding": "zstd" }); res.end(Buffer.from(echoKey(r))); });
  const z = await request(px.listening, "/anthropic/v1/messages", { body: MSG, headers: A_PH });
  assert.equal(z.status, 502); assertNoSecret(visible(z), "zstd refusal");
  assertNoSecret(px.stderr() + enf.stderr(), "the proxy's log");
  await new Promise((r) => setTimeout(r, 300));
  assertNoSecret(con.alerts.join("\n"), "the console alerts");
});

test("a raw credential where placeholders are configured: reported once per route (content-free) and forwarded; --require-placeholders refuses it (401)", async () => {
  fp.on((r, res) => sendJson(res, anthropicMessage()));
  const n0 = con.alerts.length, n = fp.requests.length;
  const a = await request(px.listening, "/anthropic/v1/messages", { body: MSG, headers: { "x-api-key": RAW_KEY } });
  assert.equal(a.status, 200);
  assert.equal(fp.requests[n].headers["x-api-key"], RAW_KEY, "report mode forwards the client's own key untouched");
  await request(px.listening, "/anthropic/v1/messages", { body: MSG, headers: { "x-api-key": RAW_KEY } });
  assert.ok(await waitFor(() => con.parsed().slice(n0).some((x) => /raw credential sent/.test(x.category))));
  await new Promise((r) => setTimeout(r, 200));
  const sent = con.parsed().slice(n0).filter((x) => /raw credential/.test(x.category));
  assert.equal(sent.length, 1, "once per route");
  assert.equal(sent[0].tool, "model-proxy:credential:anthropic"); assert.equal(sent[0].decision, "notify");
  assert.ok(!JSON.stringify(sent).includes(RAW_KEY) && !JSON.stringify(sent).includes("FAKE-raw-key"), "content-free");

  const m = fp.requests.length;
  const refused = await request(req.listening, "/anthropic/v1/messages", { body: MSG, headers: { "x-api-key": RAW_KEY } });
  assert.equal(refused.status, 401); assert.match(refused.json.error.message, /accepts only credential placeholders/);
  const refusedO = await request(req.listening, "/openai/chat/completions", { body: OMSG, headers: { authorization: `Bearer ${RAW_KEY}` } });
  assert.equal(refusedO.status, 401);
  assert.equal(fp.requests.length, m, "nothing forwarded");
  assert.ok(!visible(refused).includes(RAW_KEY));
  assert.ok(await waitFor(() => con.parsed().some((x) => /raw credential refused/.test(x.category) && x.decision === "deny")));
  const ok = await request(req.listening, "/anthropic/v1/messages", { body: MSG, headers: A_PH });
  assert.equal(ok.status, 200); assert.equal(fp.requests.at(-1).headers["x-api-key"], SECRET_A, "a placeholder still works");
  const none = await request(req.listening, "/anthropic/v1/models", { method: "GET" });
  assert.equal(none.status, 200, "no credential at all is not a raw credential");
});

test("no bindings: behaviour unchanged — a placeholder-looking value goes upstream as sent, a raw key too, an echo is not touched", async () => {
  const plain = await startProxy(home, routes(), env());
  try {
    assert.equal(plain.credentials, undefined);
    let sent;
    fp.on((r, res) => { sent = sendJson(res, anthropicMessage({ text: `echo ${echoKey(r)}` }), { headers: { "x-echo": echoKey(r) } }); });
    const r = await request(plain.listening, "/anthropic/v1/messages?k=moorai-ph:x", { body: MSG, headers: { "x-api-key": PH_A } });
    assert.equal(r.status, 200); assert.ok(r.raw.equals(sent));
    assert.equal(fp.requests.at(-1).headers["x-api-key"], PH_A); assert.equal(fp.requests.at(-1).url, "/v1/messages?k=moorai-ph:x");
    assert.equal(r.headers["x-echo"], PH_A);
    const gz = gzipSync("{}");
    fp.on((q, res) => { res.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip", "content-length": gz.length }); res.end(gz); });
    const g = await request(plain.listening, "/anthropic/v1/messages", { body: MSG, headers: { "x-api-key": RAW_KEY } });
    assert.equal(g.headers["content-encoding"], "gzip"); assert.ok(g.raw.equals(gz), "a compressed body passes as before");
  } finally { await plain.stop(); }
});

test("the bindings file and a secret file: refused when group/world-writable or owned by another non-root user; bad bindings stop the proxy (exit 2) without echoing a secret", { skip: !POSIX && "POSIX modes" }, () => {
  const run = (file, extraEnv = {}) => spawnSync(process.execPath, [CLI, "--port", "0", ...routes(), "--credentials", file], { encoding: "utf8", timeout: 15000, env: { PATH: process.env.PATH, HOME: home, MOORAI_SERVER_URL: "http://127.0.0.1:1", FAKE_ANTHROPIC_SECRET: SECRET_A, ...extraEnv } });
  const bad = join(home, "bad.json");
  for (const mode of [0o666, 0o620, 0o602]) {
    writeBindings(bad, goodBindings(), mode);
    const r = run(bad);
    assert.equal(r.status, 2, `mode ${mode.toString(8)}`); assert.match(r.stderr, /group- or world-writable/);
  }
  writeBindings(bad, goodBindings(), 0o644);
  chmodSync(secretFile, 0o660);
  try { const r = run(bad); assert.equal(r.status, 2); assert.match(r.stderr, /secret file .* is group- or world-writable/); } finally { chmodSync(secretFile, 0o600); }
  // Another owner: injected stat (a test cannot chown without root).
  const st = (uid, mode = 0o100600) => () => ({ isFile: () => true, mode, uid });
  assert.throws(() => checkFileSafe("/x", "credentials file", { platform: "linux", uid: 501, stat: st(777) }), /owned by another user \(uid 777\)/);
  assert.doesNotThrow(() => checkFileSafe("/x", "credentials file", { platform: "linux", uid: 501, stat: st(0) }), "root-owned is fine");
  assert.doesNotThrow(() => checkFileSafe("/x", "credentials file", { platform: "linux", uid: 501, stat: st(501) }));
  assert.doesNotThrow(() => checkFileSafe("/x", "credentials file", { platform: "win32", uid: undefined, stat: st(9, 0o100666) }), "Windows: modes are not ACLs, not checked");

  const cases = [
    [{ [PH_A]: { ...goodBindings()[PH_A], secret: SECRET_A } }, /a literal secret is refused/],
    [{ [PH_A]: { ...goodBindings()[PH_A], secret: { value: SECRET_A } } }, /a literal secret is refused/],
    [{ [PH_A]: { ...goodBindings()[PH_A], secret: { env: "NOT_SET_ANYWHERE" } } }, /NOT_SET_ANYWHERE is not set/],
    [{ [PH_A]: { ...goodBindings()[PH_A], upstream: "https://api.anthropic.com" } }, /does not match route \/anthropic's upstream exactly/],
    [{ [PH_A]: { ...goodBindings()[PH_A], route: "/nope" } }, /not one of this component's routes/],
    [{ [PH_A]: { ...goodBindings()[PH_A], header: "x-moorai-proxy-token" } }, /stripped or owned by this component/],
    [{ [PH_A]: { ...goodBindings()[PH_A], header: "proxy-authorization" } }, /stripped or owned/],
    [{ "anthropic-test": goodBindings()[PH_A] }, /binding name must be moorai-ph:/],
    [{ [PH_A]: { ...goodBindings()[PH_A], extra: 1 } }, /unknown key "extra"/],
    [{}, /has no bindings/]
  ];
  for (const [b, re] of cases) {
    writeBindings(bad, b);
    const r = run(bad);
    assert.equal(r.status, 2, String(re)); assert.match(r.stderr, re);
    assertNoSecret(r.stderr + r.stdout, `error ${re}`);
  }
  // A short secret, a secret with a newline inside: refused by name, the value never printed.
  for (const v of ["q7Zx", "abcdefgh\r\nX-Evil: 1"]) {
    writeBindings(bad, goodBindings());
    const r = run(bad, { FAKE_ANTHROPIC_SECRET: v });
    assert.equal(r.status, 2); assert.ok(!r.stderr.includes(v.trim()), "the value is not echoed");
  }
  writeFileSync(bad, `{"bindings": {"${PH_A}": ${SECRET_A}}`, { mode: 0o600 });
  const j = run(bad);
  assert.equal(j.status, 2); assert.match(j.stderr, /is not valid JSON/); assertNoSecret(j.stderr, "a JSON parse error");
  const rp = spawnSync(process.execPath, [CLI, "--require-placeholders"], { encoding: "utf8", timeout: 15000, env: { PATH: process.env.PATH, HOME: home } });
  assert.equal(rp.status, 2); assert.match(rp.stderr, /needs --credentials/);
  // The loader itself, for the route set the CLI builds.
  writeBindings(bad, goodBindings());
  const loaded = loadBindings(bad, { env: { FAKE_ANTHROPIC_SECRET: SECRET_A }, routes: [{ prefix: "/anthropic", base: fp.url }, { prefix: "/openai", base: `${fp.url}/v1/` }] });
  assert.deepEqual([...loaded.bindings.keys()], [PH_A, PH_O]);
});
