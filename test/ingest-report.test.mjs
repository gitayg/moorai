// moorai-ingest --report: content-free historical alerts to a recording console. Each must be marked
// replayed, carry the ORIGINAL call time, carry the same keyed `session` the live hook would have sent
// for that session id, never claim a block, and contain no transcript content. Off by default.
//
//   node --test --import ./test/hermetic-env.mjs test/ingest-report.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { CC, CODEX, load, leaks, runCli, tempHome, writePolicy, startConsole } from "./fixtures/ingest/helpers.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const { hashWithKey, deriveKey } = await load("cli/content-hash.mjs");
const TOKEN = "tok-ingest-report";
const keyed = (raw) => hashWithKey(deriveKey(TOKEN), raw);
const TOOLS = new Set(["hook:Bash", "hook:Write", "hook:MultiEdit", "hook:WebFetch", "hook:Read", "hook:mcp__placeholder__send", "hook:UserPromptSubmit"]);

const CASES = [
  { agent: "claude-code", path: CC, findings: 9, sessions: ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"], tsPrefix: "2026-09-0" },
  { agent: "codex", path: CODEX, findings: 4, sessions: ["33333333-3333-4333-8333-333333333333"], tsPrefix: "2026-09-03T08:00:0" }
];

for (const c of CASES) {
  test(`${c.agent}: --report posts one historical, content-free alert per finding`, async () => {
    const con = await startConsole();
    const home = tempHome({ serverUrl: con.url, token: TOKEN });
    try {
      const policy = writePolicy(home, {});
      const r = await runCli([c.path, "--agent", c.agent, "--days", "0", "--policy", policy, "--report"], { home });
      assert.equal(r.code, 0, r.err);
      const alerts = con.alerts();
      assert.equal(alerts.length, c.findings);
      assert.match(r.out, new RegExp(`${c.findings} historical alert\\(s\\) sent, 0 failed`));
      const sessions = new Set(c.sessions.map(keyed));
      for (const a of alerts) {
        assert.equal(a.replayed, true);
        assert.equal(a.source, "ingest");
        assert.equal(a.agent, c.agent);
        assert.ok(a.ts.startsWith(c.tsPrefix), `original timestamp, got ${a.ts}`);
        assert.notEqual(a.ts, a.ingestedAt);
        assert.ok(sessions.has(a.session), "session is the hook's keyed hash of the raw session id");
        assert.equal(a.enforcement, "UNEVALUATED");
        assert.notEqual(a.riskLevel, "Blocked");
        assert.ok(["deny", "ask", "mask", "allow"].includes(a.wouldDecision));
        assert.ok(a.threatId > 0 && typeof a.category === "string" && typeof a.stage === "string" && a.tool.startsWith("hook:"));
        assert.ok(a.contentHash.startsWith("h2:") && a.replayId.startsWith("h2:"));
      }
      assert.equal(new Set(alerts.map((a) => a.replayId)).size, alerts.length, "replayIds are distinct");
      // The tool name is identity, not content, and the live hook sends it the same way — including an
      // MCP tool's server and tool name (the codex fixture's server is literally named "placeholder").
      // It is checked against the fixture's tool names, then left out of the content check.
      for (const a of alerts) assert.ok(TOOLS.has(a.tool), `unexpected tool ${a.tool}`);
      assert.deepEqual(leaks(alerts.map(({ tool, ...rest }) => JSON.stringify(rest)).join("\n")), []);
      assert.ok(alerts.some((a) => a.threatId === 54 && a.wouldDecision === "deny"), "the reverse shell would have been blocked");
    } finally { rmTree(home); await con.close(); }
  });
}

test("without --report nothing is posted, and an unenrolled device posts nothing even with it", async () => {
  const con = await startConsole();
  const enrolled = tempHome({ serverUrl: con.url, token: TOKEN });
  const unenrolled = tempHome({ serverUrl: con.url });
  try {
    const r1 = await runCli([CC, "--agent", "claude-code", "--days", "0", "--policy", writePolicy(enrolled, {})], { home: enrolled });
    assert.equal(r1.code, 0, r1.err);
    const r2 = await runCli([CC, "--agent", "claude-code", "--days", "0", "--policy", writePolicy(unenrolled, {}), "--report"], { home: unenrolled });
    assert.equal(r2.code, 0, r2.err);
    assert.match(r2.out, /not enrolled/);
    assert.equal(con.bodies.length, 0);
  } finally { rmTree(enrolled); rmTree(unenrolled); await con.close(); }
});
