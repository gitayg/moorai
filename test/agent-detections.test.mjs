// Content-free forensic detections over the on-device agent-event stream — pure unit tests. No HOME,
// no fs, no hook: content-free event arrays are fed straight in. Rows use the shape readAgentEvents()
// returns, optionally carrying the content-free lineage metadata the detections read
// (agent, parent, session, role, to/target, seq, total).
//
//   node --test test/agent-detections.test.mjs
//   (per-file runner only — never `node --test` across the whole suite)
import { test } from "node:test";
import assert from "node:assert/strict";
import { detectOrphanAgents, detectCrossAgentMessaging, detectTraceGaps } from "../data/agent-detections.js";

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

// ------------------------------------------------------------------- fail-open ----

test("fail-open: bad or empty input never throws, always returns an array", () => {
  for (const fn of [detectOrphanAgents, detectCrossAgentMessaging, detectTraceGaps]) {
    assert.deepEqual(fn([]), []);
    assert.deepEqual(fn(null), []);
    assert.deepEqual(fn(undefined), []);
    assert.ok(Array.isArray(fn([{ nonsense: true }, null, 7])));
  }
});
