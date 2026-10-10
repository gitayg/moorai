// moorai-ingest: counts from synthetic Claude Code and Codex transcripts, a candidate policy changing
// the would-block counts, and malformed lines skipped and counted. Placeholder content only (see
// test/fixtures/ingest/build-fixtures.mjs for what each fixture line is and why it should fire).
//
//   node --test --import ./test/hermetic-env.mjs test/ingest.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CC, CODEX, load } from "./fixtures/ingest/helpers.mjs";

const { runIngest } = await load("cli/ingest/run.mjs");
const { NO_POLICY_BASELINE } = await load("cli/ingest/replay.mjs");

const run = (agent, path, policy = NO_POLICY_BASELINE, extra = {}) =>
  runIngest({ policy, policyId: "test", policySource: "test", days: 0, explicit: [{ path, agent }], ...extra }).then((r) => r.result);
const threatCounts = (r) => Object.fromEntries(r.byThreat.map((t) => [t.threatId, t.findings]));

test("Claude Code: every call, result and prompt is counted, by decision and by threat", async () => {
  const r = await run("claude-code", CC);
  assert.deepEqual(r.files, { "claude-code": 3, codex: 0 });
  assert.equal(r.sessions.total, 2, "the sub-agent transcript joins its parent session");
  // 8 judged calls; Glob is not a hook tool; 3 results ingested (the denied reverse shell never ran,
  // the failed rm has no result, the trailing ls has no result at all).
  assert.deepEqual(r.events, { call: 8, post: 3, prompt: 1, promptScanned: 0, unsupported: 1 });
  assert.deepEqual(r.decisions, { deny: 1, ask: 5, mask: 0, allow: 6 });
  assert.equal(r.flaggedAllow, 1, "the Write of a secret-shaped placeholder is reported, not blocked, by default");
  assert.equal(r.findings, 9);
  assert.deepEqual(threatCounts(r), { 39: 2, 55: 2, 17: 1, 40: 1, 43: 1, 54: 1, 57: 1 });
  assert.deepEqual(r.byAgent["claude-code"], { sessions: 2, events: 12, findings: 9, deny: 1, ask: 5, mask: 0, allow: 6 });
  assert.deepEqual(r.sessions, { total: 2, withFindings: 2, wouldBlock: 1, wouldAsk: 1 });
  assert.deepEqual(r.coverage, { covered: 1, uncovered: 1, unknown: 0 }, "one session ran the MoorAI hook, one ran only another hook");
});

test("Codex: rollout calls go through the Codex hook adapter and are counted", async () => {
  const r = await run("codex", CODEX);
  assert.deepEqual(r.files, { "claude-code": 0, codex: 1 });
  // exec_command, shell, apply_patch, an MCP call; update_plan and code-mode exec are not hook tools.
  assert.deepEqual(r.events, { call: 4, post: 0, prompt: 2, promptScanned: 0, unsupported: 2 });
  assert.deepEqual(r.decisions, { deny: 1, ask: 1, mask: 0, allow: 4 });
  assert.equal(r.findings, 4);
  assert.deepEqual(threatCounts(r), { 39: 2, 54: 1, 55: 1 });
  assert.deepEqual(r.coverage, { covered: 0, uncovered: 0, unknown: 1 }, "Codex does not record hook runs in its rollout");
});

test("a candidate policy changes the would-block counts", async () => {
  const strict = { threatPolicy: { 39: "block" } };
  const cc = await run("claude-code", CC, strict);
  assert.deepEqual(cc.decisions, { deny: 3, ask: 4, mask: 0, allow: 5 }, "the Write and the Read of secret placeholders now block");
  assert.equal(cc.sessions.wouldBlock, 1);
  const cx = await run("codex", CODEX, strict);
  assert.deepEqual(cx.decisions, { deny: 3, ask: 1, mask: 0, allow: 2 });
  const relaxed = await run("claude-code", CC, { threatPolicy: { 54: "notify", 55: "notify" } });
  // With the reverse shell no longer denied it runs, so its injected output is now ingested and scanned.
  assert.deepEqual(relaxed.decisions, { deny: 0, ask: 4, mask: 0, allow: 9 });
  assert.equal(relaxed.events.post, 4);
  const prompts = await run("claude-code", CC, { promptScan: "all" });
  assert.equal(prompts.events.promptScanned, 1, "promptScan: all scans the typed prompt the default skips");
  assert.ok(prompts.findings > 9);
});

test("malformed lines are skipped and counted, and the valid lines around them still count", async () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-ingest-bad-"));
  const sid = "44444444-4444-4444-8444-444444444444";
  const call = (i) => JSON.stringify({ type: "assistant", sessionId: sid, timestamp: "2026-09-04T00:00:00.000Z", message: { role: "assistant", content: [{ type: "tool_use", id: `t${i}`, name: "Bash", input: { command: "ls -la" } }] } });
  const lines = [call(1), "{", "[1,2", "null", "\"a string\"", call(2), "{\"type\":", "[]", call(3)];
  mkdirSync(join(dir, "p"));
  writeFileSync(join(dir, "p", `${sid}.jsonl`), lines.join("\n") + "\n");
  const r = await run("claude-code", dir);
  assert.equal(r.skipped.malformedLines, 6);
  assert.equal(r.events.call, 3);
  const cx = await run("codex", CODEX);
  assert.equal(cx.skipped.malformedLines, 1, "a truncated rollout line");
  assert.equal(cx.skipped.malformedArgs, 1, "a function_call whose arguments are not JSON");
  const cc = await run("claude-code", CC);
  assert.equal(cc.skipped.malformedLines, 1);
});

test("--discover finds Claude Code and Codex transcripts in their default homes, .zst rollouts included", async () => {
  const { cpSync, readFileSync, readdirSync } = await import("node:fs");
  const { zstdCompressSync } = await import("node:zlib");
  const { tempHome, writePolicy, runCli } = await import("./fixtures/ingest/helpers.mjs");
  const { rmTree } = await import("./fs-cleanup.mjs");
  const home = tempHome();
  try {
    cpSync(join(CC, "projects"), join(home, ".claude", "projects"), { recursive: true });
    const day = join(CODEX, "sessions", "2026", "09", "03");
    const name = readdirSync(day)[0];
    mkdirSync(join(home, ".codex", "sessions", "2026", "09", "03"), { recursive: true });
    mkdirSync(join(home, ".codex", "archived_sessions"), { recursive: true });
    cpSync(join(day, name), join(home, ".codex", "sessions", "2026", "09", "03", name));
    if (zstdCompressSync) writeFileSync(join(home, ".codex", "archived_sessions", name.replace("33333333-3333", "66666666-6666") + ".zst"), zstdCompressSync(readFileSync(join(day, name))));
    writeFileSync(join(home, ".codex", "sessions", "notes.jsonl"), "{}\n"); // not a rollout name: ignored
    const r = await runCli(["--discover", "--json", "--policy", writePolicy(home, {})], { home });
    assert.equal(r.code, 0, r.err);
    const j = JSON.parse(r.out);
    assert.deepEqual(j.files, { "claude-code": 3, codex: zstdCompressSync ? 2 : 1 });
    assert.equal(j.byAgent.codex.findings, zstdCompressSync ? 8 : 4, "the compressed rollout replays like the plain one");
    assert.equal(j.byAgent["claude-code"].findings, 9);
  } finally { rmTree(home); }
});
