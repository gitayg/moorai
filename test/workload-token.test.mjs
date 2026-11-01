// The OIDC exchange for a cloud workload (cli/workload-token.mjs, CONTRACT-F28 §5.2): request a GitHub
// Actions ID token, exchange it at POST /api/workload/token for a scoped mwt_ token. Fake fetch only; the
// tokens never appear in an error.
// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/workload-token.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { requestGithubIdToken, exchangeWorkloadToken, mintWorkloadToken, audienceFor, validWorkloadToken, WorkloadTokenError, REFUSAL_CODES } from "../cli/workload-token.mjs";

const WID = "wkl-5c1e0a9b2d3f";
const MWT = "mwt_" + "b".repeat(43);
const REQ_TOKEN = "ghs_REQUEST_TOKEN_SECRET";
const JWT = "eyJhbGciOiJSUzI1NiJ9.eyJyZXBvc2l0b3J5IjoiYWNtZS93ZWIifQ.SIGNATURE_SECRET";
const ghEnv = { ACTIONS_ID_TOKEN_REQUEST_URL: "https://pipelines.example/idtoken?api-version=2.0", ACTIONS_ID_TOKEN_REQUEST_TOKEN: REQ_TOKEN };

function fakeFetch(routes) {
  const calls = [];
  const f = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    for (const [match, reply] of routes) if (String(url).startsWith(match)) return reply(String(url), init);
    return new Response("{}", { status: 404 });
  };
  f.calls = calls;
  return f;
}
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const noSecrets = (e) => { const s = `${e && e.message} ${JSON.stringify(e)}`; for (const x of [REQ_TOKEN, JWT, MWT, "SIGNATURE_SECRET"]) assert.ok(!s.includes(x), `error carries ${x}`); };

test("token shape and audience", () => {
  assert.ok(validWorkloadToken(MWT));
  assert.ok(!validWorkloadToken("mwt_short"));
  assert.ok(!validWorkloadToken("tok_" + "b".repeat(43)));
  assert.ok(!validWorkloadToken("mwt_" + "b".repeat(42) + "!"));
  assert.equal(audienceFor("acme"), "moorai:acme");
  assert.deepEqual([...REFUSAL_CODES].sort(), ["bad-signature", "claim-not-allowed", "expired", "unknown-workload"]);
});

test("GitHub ID token: bearer request token, audience appended to the request URL, `value` returned", async () => {
  const f = fakeFetch([["https://pipelines.example/idtoken", () => json(200, { value: JWT })]]);
  const t = await requestGithubIdToken({ env: ghEnv, audience: "moorai:acme", fetchImpl: f });
  assert.equal(t, JWT);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].url, "https://pipelines.example/idtoken?api-version=2.0&audience=moorai%3Aacme");
  assert.equal(f.calls[0].init.headers.Authorization, `bearer ${REQ_TOKEN}`);
  // A request URL with no query string gets `?audience=`.
  const g = fakeFetch([["https://p.example/t", () => json(200, { value: JWT })]]);
  await requestGithubIdToken({ env: { ACTIONS_ID_TOKEN_REQUEST_URL: "https://p.example/t", ACTIONS_ID_TOKEN_REQUEST_TOKEN: REQ_TOKEN }, audience: "moorai:x", fetchImpl: g });
  assert.equal(g.calls[0].url, "https://p.example/t?audience=moorai%3Ax");
});

test("GitHub ID token: missing permission, HTTP error or a malformed answer fail with a code, never a secret", async () => {
  await assert.rejects(requestGithubIdToken({ env: {}, audience: "a", fetchImpl: fakeFetch([]) }), (e) => e instanceof WorkloadTokenError && e.code === "oidc-unavailable" && /id-token: write/.test(e.message));
  for (const reply of [() => json(403, { message: REQ_TOKEN }), () => json(200, { value: 42 }), () => new Response("not json", { status: 200 })]) {
    await assert.rejects(requestGithubIdToken({ env: ghEnv, audience: "a", fetchImpl: fakeFetch([["https://pipelines.example", reply]]) }), (e) => { noSecrets(e); return e.code === "oidc-request-failed"; });
  }
  await assert.rejects(requestGithubIdToken({ env: ghEnv, audience: "a", fetchImpl: async () => { throw new Error(`connect failed ${REQ_TOKEN}`); } }), (e) => { noSecrets(e); return e.code === "oidc-request-failed"; });
});

test("exchange: POST /api/workload/token with the workload id and the ID token, no install token header", async () => {
  const f = fakeFetch([["https://console.example/api/workload/token", () => json(200, { token: MWT, expiresAt: "2026-10-21T18:00:00.000Z" })]]);
  const r = await exchangeWorkloadToken({ serverUrl: "https://console.example/", workloadId: WID, idToken: JWT, fetchImpl: f });
  assert.deepEqual(r, { token: MWT, expiresAt: "2026-10-21T18:00:00.000Z" });
  const c = f.calls[0];
  assert.equal(c.init.method, "POST");
  assert.deepEqual(JSON.parse(c.init.body), { workloadId: WID, idToken: JWT });
  assert.equal(c.init.headers["X-Install-Token"], undefined);
  assert.equal(c.init.headers["Content-Type"], "application/json");
});

test("exchange refusals: a 401 reason code from the closed list, anything else is a generic code", async () => {
  for (const code of REFUSAL_CODES) {
    await assert.rejects(exchangeWorkloadToken({ serverUrl: "https://c.example", workloadId: WID, idToken: JWT, fetchImpl: fakeFetch([["https://c.example", () => json(401, { error: code })]]) }), (e) => e.code === code);
  }
  await assert.rejects(exchangeWorkloadToken({ serverUrl: "https://c.example", workloadId: WID, idToken: JWT, fetchImpl: fakeFetch([["https://c.example", () => json(401, { error: `claim ${JWT}` })]]) }), (e) => { noSecrets(e); return e.code === "exchange-refused"; });
  await assert.rejects(exchangeWorkloadToken({ serverUrl: "https://c.example", workloadId: WID, idToken: JWT, fetchImpl: fakeFetch([["https://c.example", () => json(404, {})]]) }), (e) => e.code === "exchange-unsupported");
  await assert.rejects(exchangeWorkloadToken({ serverUrl: "https://c.example", workloadId: WID, idToken: JWT, fetchImpl: fakeFetch([["https://c.example", () => json(200, { token: "mwt_bad", expiresAt: "2026-10-21T18:00:00.000Z" })]]) }), (e) => { noSecrets(e); return e.code === "bad-response"; });
  await assert.rejects(exchangeWorkloadToken({ serverUrl: "https://c.example", workloadId: WID, idToken: JWT, fetchImpl: fakeFetch([["https://c.example", () => json(200, { token: MWT, expiresAt: "soon" })]]) }), (e) => { noSecrets(e); return e.code === "bad-response"; });
  await assert.rejects(exchangeWorkloadToken({ serverUrl: "https://c.example", workloadId: "wkl-nothex", idToken: JWT, fetchImpl: fakeFetch([]) }), (e) => e.code === "bad-workload-id");
  await assert.rejects(exchangeWorkloadToken({ serverUrl: "ftp://c.example", workloadId: WID, idToken: JWT, fetchImpl: fakeFetch([]) }), (e) => e.code === "bad-server-url");
});

test("mint: request then exchange, audience moorai:<tenant>", async () => {
  const f = fakeFetch([
    ["https://pipelines.example/idtoken", () => json(200, { value: JWT })],
    ["https://console.example/api/workload/token", () => json(200, { token: MWT, expiresAt: "2026-10-21T18:00:00.000Z" })]
  ]);
  const r = await mintWorkloadToken({ env: ghEnv, serverUrl: "https://console.example", tenant: "acme", workloadId: WID, fetchImpl: f });
  assert.equal(r.token, MWT);
  assert.equal(r.attestation, "github-oidc");
  assert.match(f.calls[0].url, /audience=moorai%3Aacme$/);
});
