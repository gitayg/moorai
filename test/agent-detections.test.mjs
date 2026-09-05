// Content-free forensic detections over the on-device agent-event stream — pure unit tests. No HOME,
// no fs, no hook: content-free event arrays are fed straight in. Rows use the shape readAgentEvents()
// returns, optionally carrying the content-free lineage metadata the detections read
// (agent, parent, session, role, to/target, seq, total).
//
//   node --test test/agent-detections.test.mjs
//   (per-file runner only — never `node --test` across the whole suite)
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  detectOrphanAgents, detectCrossAgentMessaging, detectTraceGaps,
  detectVelocityBurst, detectConfusedDeputy, detectFanOutAnomaly
} from "../data/agent-detections.js";

const agentsOf = (findings) => new Set(findings.map((f) => f.agent));
const shapeOk = (f) =>
  typeof f.type === "string" &&
  typeof f.agent === "string" &&
  ["low", "medium", "high"].includes(f.severity) &&
  typeof f.count === "number" &&
  f.evidence && typeof f.evidence === "object";

// ---------------------------------------------------------------- orphan agents ----

test("orphan: a subagent whose parent never appears (or that has no lineage) is flagged; legit children are not", () => {
  const events = [
    { ts: 1000, sig: "Read|root", agent: "root", role: "root" },
    { ts: 1001, sig: "Read|root", agent: "root" },
    { ts: 2000, sig: "Task|sub-1", agent: "sub-1", parent: "root", role: "subagent" },   // parent present → ok
    { ts: 3000, sig: "Task|sub-2", agent: "sub-2", parent: "ghost", role: "subagent" },  // parent absent → orphan
    { ts: 3001, sig: "Bash|sub-2", agent: "sub-2", parent: "ghost" },                     // second orphan event
    { ts: 4000, sig: "Task|sub-3", agent: "sub-3", role: "subagent" }                     // child role, no lineage → orphan
  ];
  const findings = detectOrphanAgents(events);
  assert.ok(findings.every(shapeOk), "every finding must match the content-free schema");
  assert.deepEqual(agentsOf(findings), new Set(["sub-2", "sub-3"]));

  const s2 = findings.find((f) => f.agent === "sub-2");
  assert.equal(s2.count, 2);
  assert.ok(s2.evidence.reasons.includes("missing-parent"));
  assert.ok(s2.evidence.parents.includes("ghost"));

  const s3 = findings.find((f) => f.agent === "sub-3");
  assert.ok(s3.evidence.reasons.includes("no-lineage"));
});

test("orphan: none flagged when every parent id resolves to a known agent or session", () => {
  const events = [
    { ts: 1000, sig: "Read|root", agent: "root" },
    { ts: 2000, sig: "Task|sub-1", agent: "sub-1", parent: "root", role: "subagent" },
    { ts: 2500, sig: "Task|sub-2", agent: "sub-2", parent: "sess-9", role: "subagent" },
    { ts: 2600, sig: "Read|root", agent: "root", session: "sess-9" } // sess-9 is a known session id
  ];
  assert.deepEqual(detectOrphanAgents(events), []);
});

// ---------------------------------------------------------- cross-agent messaging ----

test("cross-agent: explicit handoff targets and a shared messaging channel are flagged", () => {
  const events = [
    { ts: 1000, sig: "Task|A", agent: "A", to: "B" },      // explicit A → B
    { ts: 1001, sig: "Task|A", agent: "A", target: "C" },  // explicit A → C
    { ts: 2000, sig: "MCP|X", agent: "X", server: "bus", flags: { handoff: true } }, // messaging marker on shared channel
    { ts: 2001, sig: "MCP|Y", agent: "Y", server: "bus" }  // Y shares the bus → peer of X
  ];
  const findings = detectCrossAgentMessaging(events);
  assert.ok(findings.every(shapeOk));

  const a = findings.find((f) => f.agent === "A");
  assert.ok(a, "A should be flagged");
  assert.ok(a.evidence.peers.includes("B") && a.evidence.peers.includes("C"));

  const x = findings.find((f) => f.agent === "X");
  assert.ok(x, "X should be flagged via the shared messaging channel");
  assert.ok(x.evidence.peers.includes("Y"));
});

test("cross-agent: sharing a plain server with no target and no messaging marker is NOT flagged", () => {
  const events = [
    { ts: 1000, sig: "Read|A", agent: "A", server: "files" },
    { ts: 1001, sig: "Read|B", agent: "B", server: "files" },
    { ts: 1002, sig: "Read|A", agent: "A", server: "files" }
  ];
  assert.deepEqual(detectCrossAgentMessaging(events), []);
});

// ------------------------------------------------------------------- trace gaps ----

test("trace-gap: a missing monotonic step is flagged with from/to/missing", () => {
  const events = [
    { ts: 1000, sig: "T|A", agent: "A", session: "s1", seq: 1 },
    { ts: 1001, sig: "T|A", agent: "A", session: "s1", seq: 2 },
    { ts: 1002, sig: "T|A", agent: "A", session: "s1", seq: 5 } // steps 3,4 missing
  ];
  const findings = detectTraceGaps(events);
  assert.ok(findings.every(shapeOk));
  const step = findings.find((f) => f.evidence.kind === "missing-steps");
  assert.ok(step, "a missing-steps finding is expected");
  assert.equal(step.evidence.from, 2);
  assert.equal(step.evidence.to, 5);
  assert.equal(step.evidence.missing, 2);
  assert.equal(step.count, 2);
});

test("trace-gap: a large time discontinuity vs the agent's own cadence is flagged", () => {
  const events = [];
  for (let i = 0; i < 6; i++) events.push({ ts: 1000 + i * 1000, sig: "T|A", agent: "A" }); // steady 1s cadence
  events.push({ ts: 1000 + 5 * 1000 + 600_000, sig: "T|A", agent: "A" });                   // 10-minute gap
  const findings = detectTraceGaps(events);
  const time = findings.find((f) => f.evidence.kind === "time-gap");
  assert.ok(time, "a time-gap finding is expected");
  assert.equal(time.evidence.gapMs, 600_000);
  assert.ok(time.evidence.ratio >= 20);
});

test("trace-gap: a session whose declared total exceeds observed events is flagged as truncated", () => {
  const events = [
    { ts: 1000, sig: "T|A", agent: "A", session: "s1", total: 10 },
    { ts: 1001, sig: "T|A", agent: "A", session: "s1" },
    { ts: 1002, sig: "T|A", agent: "A", session: "s1" }
  ];
  const findings = detectTraceGaps(events);
  const trunc = findings.find((f) => f.evidence.kind === "truncated-session");
  assert.ok(trunc, "a truncated-session finding is expected");
  assert.equal(trunc.evidence.declared, 10);
  assert.equal(trunc.evidence.observed, 3);
  assert.equal(trunc.evidence.missing, 7);
});

test("trace-gap: a contiguous, steady-cadence, fully-observed trace is NOT flagged", () => {
  const events = [];
  for (let i = 0; i < 8; i++) events.push({ ts: 1000 + i * 1000, sig: "T|A", agent: "A", session: "s1", seq: i + 1 });
  assert.deepEqual(detectTraceGaps(events), []);
});

// -------------------------------------------------------------- velocity / burst ----

test("velocity: a machine-speed burst far below the agent's own cadence is flagged", () => {
  const events = [];
  for (let i = 0; i < 20; i++) events.push({ ts: 1000 + i * 1000, sig: "T|A", agent: "A" }); // steady 1s cadence (19 gaps)
  let t = 1000 + 19 * 1000;
  for (let i = 0; i < 4; i++) { t += 10; events.push({ ts: t, sig: "T|A", agent: "A" }); }    // 4 calls 10ms apart → burst (minority)
  const findings = detectVelocityBurst(events);
  assert.ok(findings.every(shapeOk));
  const a = findings.find((f) => f.agent === "A");
  assert.ok(a, "the bursting agent should be flagged");
  assert.equal(a.evidence.kind, "cadence-burst");
  assert.ok(a.evidence.burstGaps >= 2, "at least two fast gaps counted");
  assert.equal(a.evidence.medianMs, 1000);
  assert.ok(a.evidence.peakRatio >= 8);
});

test("velocity: a steady cadence with a single long idle gap is NOT a burst", () => {
  const events = [];
  for (let i = 0; i < 7; i++) events.push({ ts: 1000 + i * 1000, sig: "T|A", agent: "A" }); // steady
  events.push({ ts: 1000 + 6 * 1000 + 600_000, sig: "T|A", agent: "A" });                   // long idle gap (trace-gap, not burst)
  assert.deepEqual(detectVelocityBurst(events), []);
});

// ---------------------------------------------------------- confused deputy / boundary ----

test("confused-deputy: ingest of untrusted content then egress to a NEW destination is flagged", () => {
  const events = [
    { ts: 1000, sig: "Read|A", agent: "A", server: "files", legs: { read: true, ingest: true } }, // untrusted content in
    { ts: 2000, sig: "Fetch|A", agent: "A", server: "evil.example", legs: { callout: true } }       // egress to a fresh sink
  ];
  const findings = detectConfusedDeputy(events);
  assert.ok(findings.every(shapeOk));
  const a = findings.find((f) => f.agent === "A");
  assert.ok(a, "the pivoting agent should be flagged");
  assert.equal(a.evidence.kind, "inject-then-egress");
  assert.ok(a.evidence.destinations.includes("evil.example"));
  assert.equal(a.count, 1);
});

test("confused-deputy: egress to an already-seen destination, or egress before any ingest, is NOT flagged", () => {
  const seenDest = [
    { ts: 1000, sig: "Fetch|A", agent: "A", server: "api", legs: { callout: true } },   // api reached first
    { ts: 2000, sig: "Read|A", agent: "A", server: "files", legs: { ingest: true } },   // then ingest
    { ts: 3000, sig: "Fetch|A", agent: "A", server: "api", legs: { callout: true } }    // egress to KNOWN api → no pivot
  ];
  assert.deepEqual(detectConfusedDeputy(seenDest), []);
  const egressFirst = [
    { ts: 1000, sig: "Fetch|B", agent: "B", server: "new", legs: { callout: true } },   // egress before any ingest
    { ts: 2000, sig: "Read|B", agent: "B", server: "files", legs: { ingest: true } }
  ];
  assert.deepEqual(detectConfusedDeputy(egressFirst), []);
});

// ---------------------------------------------------------------- subagent fan-out ----

test("fan-out: a parent spawning far more distinct children than the norm is flagged", () => {
  const events = [];
  for (let i = 0; i < 6; i++) events.push({ ts: 1000 + i, sig: "Task|c" + i, agent: "c" + i, parent: "P1", role: "subagent" });
  events.push({ ts: 2000, sig: "Task|d0", agent: "d0", parent: "P2", role: "subagent" }); // P2 spawns 1
  events.push({ ts: 2001, sig: "Task|e0", agent: "e0", parent: "P3", role: "subagent" }); // P3 spawns 1
  const findings = detectFanOutAnomaly(events);
  assert.ok(findings.every(shapeOk));
  assert.deepEqual(agentsOf(findings), new Set(["P1"]));
  const p1 = findings.find((f) => f.agent === "P1");
  assert.equal(p1.evidence.kind, "subagent-fan-out");
  assert.equal(p1.count, 6);
  assert.equal(p1.evidence.distinctChildren, 6);
  assert.equal(p1.evidence.baseline, "population");
});

test("fan-out: parents with comparable, modest child counts are NOT flagged", () => {
  const events = [
    { ts: 1, sig: "Task|a", agent: "a", parent: "P1", role: "subagent" },
    { ts: 2, sig: "Task|b", agent: "b", parent: "P1", role: "subagent" },
    { ts: 3, sig: "Task|c", agent: "c", parent: "P2", role: "subagent" },
    { ts: 4, sig: "Task|d", agent: "d", parent: "P2", role: "subagent" },
    { ts: 5, sig: "Task|e", agent: "e", parent: "P3", role: "subagent" },
    { ts: 6, sig: "Task|f", agent: "f", parent: "P3", role: "subagent" },
    { ts: 7, sig: "Task|g", agent: "g", parent: "P3", role: "subagent" } // P3 has 3, still not an outlier vs 2,2
  ];
  assert.deepEqual(detectFanOutAnomaly(events), []);
});

// ------------------------------------------------------------------- fail-open ----

test("fail-open: bad or empty input never throws, always returns an array", () => {
  for (const fn of [
    detectOrphanAgents, detectCrossAgentMessaging, detectTraceGaps,
    detectVelocityBurst, detectConfusedDeputy, detectFanOutAnomaly
  ]) {
    assert.deepEqual(fn([]), []);
    assert.deepEqual(fn(null), []);
    assert.deepEqual(fn(undefined), []);
    assert.ok(Array.isArray(fn([{ nonsense: true }, null, 7])));
  }
});
