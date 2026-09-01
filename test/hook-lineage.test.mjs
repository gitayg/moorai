import { test } from "node:test";
import assert from "node:assert/strict";
import { detectCrossAgentMessaging, detectTraceGaps } from "../data/agent-detections.js";
import { checkHoneytokens } from "../cli/moorai-honeytokens.mjs";
import { hashWithKey, deriveKey, NO_KEY } from "../cli/content-hash.mjs";

// These pin the CONTRACT between what cli/moorai-hook.mjs now emits and what the detectors / honeytoken
// canary consume — the integration the hook wiring depends on, exercised without spawning the hook.

test("a Task handoff event (role:handoff, to:<child>) triggers cross-agent messaging", () => {
  // Shape the hook emits on a Task delegation: agent/session = this session, to = hashed subagent_type.
  const events = [{ sig: "Task|abc", agent: "S", session: "S", role: "handoff", parent: "S", to: "child1", server: "local" }];
  const found = detectCrossAgentMessaging(events);
  assert.equal(found.length, 1);
  assert.equal(found[0].type, "cross-agent-messaging");
  assert.equal(found[0].agent, "S");
  assert.deepEqual(found[0].evidence.peers, ["child1"]);
});

test("an ordinary same-agent event produces no cross-agent finding (no false handoff)", () => {
  const events = [{ sig: "Read|abc", agent: "S", session: "S", server: "local" }];
  assert.deepEqual(detectCrossAgentMessaging(events), []);
});

test("the chain seq lives under `chain` and is NOT read as a per-agent step (no false trace gap)", () => {
  // Global per-log chain seq 1 then 5 for one agent (other agents' events took 2..4). Because the hook
  // stores it under chain.seq, detectTraceGaps sees no top-level seq/step and must NOT report a gap.
  const events = [
    { sig: "Read|a", agent: "S", session: "S", ts: 1000, chain: { seq: 1 } },
    { sig: "Read|a", agent: "S", session: "S", ts: 2000, chain: { seq: 5 } }
  ];
  const gaps = detectTraceGaps(events).filter((g) => g.evidence.kind === "missing-steps");
  assert.deepEqual(gaps, [], "chain.seq must not be interpreted as a per-agent step");
});

test("a real per-agent step counter still triggers missing-steps (detector works when a step exists)", () => {
  const events = [
    { sig: "Read|a", agent: "S", session: "S", step: 1 },
    { sig: "Read|a", agent: "S", session: "S", step: 3 }
  ];
  const gaps = detectTraceGaps(events).filter((g) => g.evidence.kind === "missing-steps");
  assert.equal(gaps.length, 1);
  assert.equal(gaps[0].evidence.missing, 1);
});

test("honeytoken wiring: on an enrolled (keyed) device, the same value hits and a different value misses", () => {
  // The hook passes contentHash(f.match) to the canary; a honeytoken is registered as contentHash(value).
  // On an enrolled device those are keyed HMACs, so an equal value is an exact hit and a different one
  // misses. (Modelled with an explicit key so the test does not depend on this box being enrolled.)
  const key = deriveKey("test-tenant-token");
  const decoy = "moorai-decoy-key-DO-NOT-USE";
  const registered = [{ hash: hashWithKey(key, decoy), label: "aws-canary" }];
  const hits = checkHoneytokens([hashWithKey(key, decoy)], registered);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].label, "aws-canary");
  assert.deepEqual(checkHoneytokens([hashWithKey(key, "something-else")], registered), []);
});

test("honeytoken wiring: the NO_KEY sentinel never matches (an unenrolled device is inert, not noisy)", () => {
  assert.deepEqual(checkHoneytokens([NO_KEY], [{ hash: NO_KEY, label: "x" }]), []);
});
