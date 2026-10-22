// moorai-ingest for Gemini CLI sessions: a JSONL session (metadata, message, `$set` and `$patch` lines) and
// a legacy whole-file .json session, both in the shapes Gemini CLI's chat recorder writes
// (packages/core/src/services/chatRecordingTypes.ts, chatRecordingService.ts). Tool calls go through the
// same adapter the live Gemini hook uses (cli/agent-hooks/gemini.mjs). Placeholder content only
// (test/fixtures/ingest/build-fixtures.mjs). No Gemini CLI is installed here: these are fixtures, not a
// live session.
//
//   node --test --import ./test/hermetic-env.mjs test/ingest-gemini.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { FIX, load, tempHome, writePolicy, runCli, leaks } from "./fixtures/ingest/helpers.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const GEM = join(FIX, "gemini");
const CHATS = join(GEM, "tmp", "placeholderhash", "chats");
const JSONL = join(CHATS, "session-2026-09-05T09-00-55555555.jsonl");
const LEGACY = join(CHATS, "session-2026-09-04T09-00-66666666.json");

const { runIngest } = await load("cli/ingest/run.mjs");
const { NO_POLICY_BASELINE } = await load("cli/ingest/replay.mjs");
const { isTranscriptName, AGENTS } = await load("cli/ingest/discover.mjs");
const run = (path, policy = NO_POLICY_BASELINE) => runIngest({ policy, policyId: "test", policySource: "test", days: 0, explicit: [{ path, agent: "gemini" }] }).then((r) => r.result);
const threatCounts = (r) => Object.fromEntries(r.byThreat.map((t) => [t.threatId, t.findings]));

test("gemini is an ingest agent, and only session files under a chats folder are transcripts", () => {
  assert.ok(AGENTS.includes("gemini"));
  assert.equal(isTranscriptName("gemini", "session-2026-09-05T09-00-55555555.jsonl", "/h/.gemini/tmp/x/chats/session-2026-09-05T09-00-55555555.jsonl"), true);
  assert.equal(isTranscriptName("gemini", "session-2026-09-04T09-00-66666666.json", "/h/.gemini/tmp/x/chats/session-2026-09-04T09-00-66666666.json"), true);
  assert.equal(isTranscriptName("gemini", "abcd1234.jsonl", "/h/.gemini/tmp/x/chats/parent-session/abcd1234.jsonl"), true, "a sub-agent session sits in a folder named after its parent");
  assert.equal(isTranscriptName("gemini", "logs.json", "/h/.gemini/tmp/x/logs.json"), false);
  assert.equal(isTranscriptName("gemini", "checkpoint-a.json", "/h/.gemini/tmp/x/checkpoint-a.json"), false);
});

test("JSONL session: every tool call goes through the Gemini hook adapter; a patched call counts once; web_fetch's result is scanned", async () => {
  const r = await run(JSONL);
  assert.deepEqual(r.files, { "claude-code": 0, codex: 0, gemini: 1 });
  // run_shell_command, read_file, web_fetch, write_file (sent twice: as written, then patched) — glob is not a
  // tool the Gemini hook is registered for. The web_fetch result is ingested (AfterTool); a prompt is captured.
  assert.deepEqual(r.events, { call: 4, post: 1, prompt: 1, promptScanned: 0, unsupported: 1 });
  assert.equal(r.decisions.deny, 1, "the reverse shell would have been denied");
  assert.equal(r.skipped.malformedLines, 1);
  const t = threatCounts(r);
  assert.ok(t[54] >= 1, "reverse shell");
  assert.ok(t[39] >= 1, "the secret-shaped placeholder in write_file");
  assert.ok(r.byAgent.gemini.findings >= 3);
  assert.deepEqual(r.coverage, { covered: 0, uncovered: 0, unknown: 1 }, "Gemini CLI does not record hook runs in its session file");
});

test("legacy whole-file .json session is read too", async () => {
  const r = await run(LEGACY);
  assert.deepEqual(r.files, { "claude-code": 0, codex: 0, gemini: 1 });
  assert.equal(r.events.call, 1);
  assert.equal(r.events.prompt, 1);
  assert.equal(r.decisions.ask, 1, "cat .env is held for sign-off (#55)");
  assert.equal(threatCounts(r)[55], 1);
});

test("a candidate policy changes the Gemini would-block counts", async () => {
  const strict = await run(JSONL, { threatPolicy: { 39: "block" } });
  assert.equal(strict.decisions.deny, 2, "the write_file of a secret placeholder now blocks too");
});

test("--discover finds Gemini CLI sessions under ~/.gemini/tmp; output stays content-free", async () => {
  const home = tempHome();
  try {
    cpSync(join(GEM, "tmp"), join(home, ".gemini", "tmp"), { recursive: true });
    writeFileSync(join(home, ".gemini", "tmp", "placeholderhash", "logs.json"), "[]");
    mkdirSync(join(home, ".gemini", "tmp", "other"), { recursive: true });
    writeFileSync(join(home, ".gemini", "tmp", "other", "session-x.jsonl"), "{}\n"); // not under chats/: ignored
    const r = await runCli(["--discover", "--json", "--policy", writePolicy(home, {})], { home });
    assert.equal(r.code, 0, r.err);
    const j = JSON.parse(r.out);
    assert.deepEqual(j.files, { "claude-code": 0, codex: 0, gemini: 2 });
    assert.ok(j.byAgent.gemini.findings >= 4);
    assert.deepEqual(leaks(r.out), []);
    assert.ok(!r.out.includes("55555555") && !r.out.includes("66666666"), "no session id in the output");
    const text = await runCli(["--discover", "--policy", writePolicy(home, {})], { home });
    assert.match(text.out, /2 Gemini CLI/);
    assert.deepEqual(leaks(text.out), []);
  } finally { rmTree(home); }
});

test("--agent gemini is accepted for an explicit path", async () => {
  const home = tempHome();
  try {
    const r = await runCli([CHATS, "--agent", "gemini", "--json", "--days", "0", "--policy", writePolicy(home, {})], { home });
    assert.equal(r.code, 0, r.err);
    assert.equal(JSON.parse(r.out).files.gemini, 2);
  } finally { rmTree(home); }
});
