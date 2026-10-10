// moorai-ingest bounds: total bytes, bytes per file, line length, file count and wall time each stop
// the run where they say, and the result says it was cut short.
//
//   node --test --import ./test/hermetic-env.mjs test/ingest-bounds.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { load } from "./fixtures/ingest/helpers.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const { runIngest } = await load("cli/ingest/run.mjs");
const { NO_POLICY_BASELINE } = await load("cli/ingest/replay.mjs");

const N = 2000;
function transcripts(files = 1, { bigLine = 0 } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "moorai-ingest-bounds-"));
  mkdirSync(join(dir, "p"));
  for (let f = 0; f < files; f++) {
    const sid = `55555555-5555-4555-8555-55555555555${f}`;
    const lines = [];
    for (let i = 0; i < N; i++) {
      if (bigLine && i === 1) lines.push(JSON.stringify({ type: "user", sessionId: sid, message: { role: "user", content: "x".repeat(bigLine) } }));
      lines.push(JSON.stringify({ type: "assistant", sessionId: sid, timestamp: "2026-09-05T00:00:00.000Z", message: { role: "assistant", content: [{ type: "tool_use", id: `t${i}`, name: "Bash", input: { command: "ls -la" } }] } }));
    }
    const p = join(dir, "p", `${sid}.jsonl`);
    writeFileSync(p, lines.join("\n") + "\n");
    utimesSync(p, new Date(Date.now() - f * 1000), new Date(Date.now() - f * 1000));
  }
  return dir;
}
const run = (dir, bounds, extra = {}) => runIngest({ policy: NO_POLICY_BASELINE, policyId: "t", policySource: "t", days: 0, explicit: [{ path: dir, agent: "claude-code" }], bounds, ...extra }).then((r) => r.result);

test("unbounded control: every line of the synthetic transcript is replayed", async () => {
  const dir = transcripts();
  try {
    const r = await run(dir, {});
    assert.equal(r.events.call, N);
    assert.deepEqual(r.truncated, { files: false, bytes: false, time: false, walk: false, filesCut: 0 });
  } finally { rmTree(dir); }
});

test("the total byte budget holds", async () => {
  const dir = transcripts(2);
  try {
    const r = await run(dir, { maxBytes: 50000 });
    assert.ok(r.bytesRead <= 50000, `read ${r.bytesRead}`);
    assert.ok(r.bytesRead > 40000);
    assert.equal(r.truncated.bytes, true);
    assert.ok(r.events.call > 0 && r.events.call < N);
    assert.equal(r.skipped.partialLines, 1, "the line the budget cut is counted, not parsed");
  } finally { rmTree(dir); }
});

test("the per-file byte bound holds and every file is still visited", async () => {
  const dir = transcripts(3);
  try {
    const r = await run(dir, { maxFileBytes: 10000 });
    assert.equal(r.files["claude-code"], 3);
    assert.equal(r.truncated.filesCut, 3);
    assert.ok(r.bytesRead <= 30000);
    assert.ok(r.events.call > 0 && r.events.call < 3 * N / 10);
  } finally { rmTree(dir); }
});

test("an over-long line is skipped and counted, and the next line still parses", async () => {
  const dir = transcripts(1, { bigLine: 200000 });
  try {
    const r = await run(dir, { maxLineBytes: 10000 });
    assert.equal(r.skipped.oversizeLines, 1);
    assert.equal(r.events.call, N);
    assert.equal(r.events.prompt, 0);
  } finally { rmTree(dir); }
});

test("the file-count bound keeps the newest files", async () => {
  const dir = transcripts(3);
  try {
    const full = await runIngest({ policy: NO_POLICY_BASELINE, policyId: "t", policySource: "t", days: 0, explicit: [{ path: dir, agent: "claude-code" }], bounds: { maxFiles: 1 } });
    const r = full.result;
    assert.equal(r.files["claude-code"], 1);
    assert.equal(r.truncated.files, true);
    assert.equal(r.events.call, N);
    assert.deepEqual(full.sessions.map((s) => s.sessionId), ["55555555-5555-4555-8555-555555555550"], "the most recently modified file");
  } finally { rmTree(dir); }
});

test("the time bound holds", async () => {
  const dir = transcripts(2);
  try {
    let t = 0;
    const clock = () => (t += 1000); // every clock read is one second later
    const r = await run(dir, { maxSeconds: 5 }, { clock });
    assert.equal(r.truncated.time, true);
    assert.ok(r.events.call < 10, `replayed ${r.events.call} calls in a 5-second budget`);
    assert.ok(r.elapsedMs <= 7000);
  } finally { rmTree(dir); }
});
