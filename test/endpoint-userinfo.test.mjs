// #63 "Unapproved model endpoint" — URL userinfo (`https://user:pass@host`) in host extraction.
//
// Two defects, one root cause, both measured on the pre-fix code:
//
//   1. ENFORCEMENT BYPASS. HOST_RE's capture group starts immediately after `://` and its character
//      class excludes `@` and `:`, so a userinfo-bearing URL matched NOTHING. Appending a userinfo
//      prefix to a rogue LLM endpoint defeated policy.endpointAllow entirely:
//        curl https://api.openai.com/v1                 -> deny  hosts=["api.openai.com"]
//        curl https://alice:hunter2@api.openai.com/v1   -> allow hosts=[]
//
//   2. CONTENT LEAK. hostOf stopped at the first colon, so it captured the URL USERNAME:
//        OPENAI_BASE_URL=https://bob:pw@api.groq.com/v1 -> deny  hosts=["bob"]
//      That value is hashed into telemetry as djb2(epD.hosts.join(",")) at five call sites; djb2 is a
//      32-bit non-cryptographic hash, so a short username is brute-forceable — on the very path whose
//      comment reads "Content-free: operates on hosts, never content".
//
// The proxy path (extractTransitOverrides/proxyHostOf) already documented and worked around this same
// flaw locally. Its behaviour is pinned here too, because the fix must not disturb it.
//
//   node --test test/endpoint-userinfo.test.mjs
//   (never bare `node --test` — its default glob sweeps in mcp-proxy/test-fake-mcp-server.mjs, a stdio
//    server that reads stdin forever and hangs.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { decideEndpoints } from "../cli/hook-core.mjs";
import { extractEndpointHosts, extractHosts, extractTransitOverrides } from "../data/model-endpoints.js";

const POLICY = { endpointAllow: ["api.anthropic.com"] };

// ---------------------------------------------------------------------------------------------
// 1. The bypass: userinfo must not buy an unapproved endpoint a pass.
// ---------------------------------------------------------------------------------------------

test("BYPASS: a userinfo-bearing rogue endpoint is DENIED, exactly like the bare one", () => {
  const bare = decideEndpoints(POLICY, "curl https://api.openai.com/v1");
  assert.equal(bare.decision, "deny");
  assert.deepEqual(bare.hosts, ["api.openai.com"]);

  const withUserinfo = decideEndpoints(POLICY, "curl https://alice:hunter2@api.openai.com/v1");
  assert.equal(withUserinfo.decision, "deny", "userinfo defeated the allow-list");
  assert.deepEqual(withUserinfo.hosts, ["api.openai.com"]);
});

test("BYPASS: a bare `@` with no password is still userinfo", () => {
  const d = decideEndpoints(POLICY, "curl https://alice@api.openai.com/v1");
  assert.equal(d.decision, "deny");
  assert.deepEqual(d.hosts, ["api.openai.com"]);
});

test("BYPASS: userinfo does not hide an endpoint from the base-URL-override sweep either", () => {
  const d = decideEndpoints(POLICY, "OPENAI_BASE_URL=https://bob:pw@api.groq.com/v1 node app.js");
  assert.equal(d.decision, "deny");
  assert.deepEqual(d.hosts, ["api.groq.com"]);
});

// ---------------------------------------------------------------------------------------------
// 2. The leak: the recorded value is the HOSTNAME, never the username or the password.
// ---------------------------------------------------------------------------------------------

test("LEAK: the recorded host is the hostname, not the username", () => {
  const hosts = decideEndpoints(POLICY, "OPENAI_BASE_URL=https://bob:pw@api.groq.com/v1 node app.js").hosts;
  // This join IS the djb2 input at the five contentHash call sites — assert on the wire form.
  const wire = hosts.join(",");
  assert.equal(wire, "api.groq.com");
  assert.ok(!wire.includes("bob"), wire);
  assert.ok(!wire.includes("pw"), wire);
  assert.ok(!wire.includes("@"), wire);
});

test("LEAK: no credential fragment survives extraction, direct-URL branch included", () => {
  const CRED = "s3cr3t-user-name";
  const text = `curl https://${CRED}:hunter2@api.openai.com/v1/chat && ` +
    `ANTHROPIC_BASE_URL=https://${CRED}:hunter2@rogue.example/v1 claude`;
  for (const fn of [extractEndpointHosts, extractHosts]) {
    const wire = JSON.stringify(fn(text));
    assert.ok(!wire.includes(CRED), `${fn.name}: ${wire}`);
    assert.ok(!wire.includes("hunter2"), `${fn.name}: ${wire}`);
  }
  assert.ok(extractHosts(text).includes("rogue.example"));
});

// ---------------------------------------------------------------------------------------------
// 3. Non-userinfo behaviour is unchanged.
// ---------------------------------------------------------------------------------------------

test("UNCHANGED: approved host allowed, unapproved denied, loopback always allowed, ports dropped", () => {
  assert.equal(decideEndpoints(POLICY, "curl https://api.anthropic.com/v1/messages").decision, "allow");
  assert.equal(decideEndpoints(POLICY, "curl https://api.openai.com/v1").decision, "deny");
  assert.equal(decideEndpoints(POLICY, "OLLAMA_BASE_URL=http://localhost:11434 ollama run llama3").decision, "allow");
  assert.deepEqual(decideEndpoints(POLICY, "curl https://api.openai.com:8443/v1").hosts, ["api.openai.com"]);
  assert.equal(decideEndpoints({}, "curl https://api.openai.com/v1").decision, "allow"); // unset list = report-only
});

test("UNCHANGED: an `@` after the authority is not userinfo", () => {
  // The path/query is not part of the authority, so an `@` there must not eat the host.
  assert.deepEqual(extractHosts("curl https://api.openai.com/v1/users/me@example.com"), ["api.openai.com"]);
  assert.deepEqual(extractHosts("curl https://api.openai.com/?to=me@example.com"), ["api.openai.com"]);
});

test("UNCHANGED: extractHosts stays content-free and still sees every host", () => {
  const hosts = extractHosts('curl -H "Authorization: Bearer SEKRIT" "https://a.example/v1/x?token=SEKRIT" && curl http://127.0.0.1:8080/z');
  assert.deepEqual(hosts.sort(), ["127.0.0.1", "a.example"]);
});

test("UNCHANGED: loopback with userinfo is still loopback (IPv6 brackets survive)", () => {
  assert.deepEqual(extractHosts("curl http://user:pw@[::1]:11434/api/generate"), ["[::1]"]);
  assert.equal(decideEndpoints(POLICY, "OLLAMA_BASE_URL=http://user:pw@[::1]:11434 ollama run llama3").decision, "allow");
});

// ---------------------------------------------------------------------------------------------
// 4. The proxy path (#67) is deliberately separate — pin it so the #63 fix cannot disturb it.
// ---------------------------------------------------------------------------------------------

test("PROXY: extractTransitOverrides still drops userinfo, and still takes a schemeless/socks value", () => {
  assert.deepEqual(extractTransitOverrides("HTTPS_PROXY=http://user:pw@evil.example:8080").proxies, ["evil.example"]);
  assert.deepEqual(extractTransitOverrides("ALL_PROXY=socks5://user:pw@evil.example:1080").proxies, ["evil.example"]);
  assert.deepEqual(extractTransitOverrides("HTTP_PROXY=evil.example:3128").proxies, ["evil.example"]);
  assert.deepEqual(extractTransitOverrides("HTTPS_PROXY=http://user@[::1]:8080").proxies, ["[::1]"]);
});

// ---------------------------------------------------------------------------------------------
// 5. The residual, pinned as a limit rather than left silent (the convention destinations.test.mjs
//    uses for the dotless-hostname gap).
// ---------------------------------------------------------------------------------------------

test("LIMIT: a userinfo longer than HOST_RE's 256-char bound still evades the direct-URL sweep", () => {
  // The bound exists so the optional group cannot scan an unbounded run before failing (the text is
  // free-form agent input, and every `https://` in it is a match start). Past it, the direct-URL sweep
  // behaves as it did before the fix. Not a regression — pre-fix, ANY userinfo evaded it — but it is a
  // real remaining bypass for a `curl https://<257+ chars>@rogue/…`, so it is stated, not implied.
  const long = "a".repeat(280) + ".com";
  assert.deepEqual(extractEndpointHosts(`curl https://${long}@api.openai.com/v1`), []);
  // The base-URL-override branch goes through hostOf, which has no such bound and is unaffected.
  assert.deepEqual(extractEndpointHosts(`OPENAI_BASE_URL=https://${long}@api.openai.com/v1`), ["api.openai.com"]);
});
