// Ask-outcome tracking (cli/ask-outcome.mjs): an ask MoorAI answered on a tracked tool is remembered, keyed,
// until the call's PostToolUse / PostToolUseFailure, or Stop.
//
//   node --test --import ./test/hermetic-env.mjs test/ask-outcome.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ASKS_FILE, MAX_ASKS, ASK_TTL_MS, MAX_UNRESOLVED_PER_STOP, ASK_TRACKED, askTrackable, recordAsk, takeAsk, takeUnresolvedAsks } from "../cli/ask-outcome.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const fresh = () => mkdtempSync(join(tmpdir(), "moorai-asks-"));

test("askTrackable: the PostToolUse matcher set, nothing else", () => {
  for (const t of ["WebFetch", "WebSearch", "Bash", "PowerShell", "Agent", "Task", "mcp__github__create_issue", "mcp__x__y"]) assert.equal(askTrackable(t), true, t);
  for (const t of ["Write", "Edit", "MultiEdit", "Read", "NotebookEdit", "Monitor", "", undefined, "mcp_", "bash"]) assert.equal(askTrackable(t), false, String(t));
  assert.deepEqual(ASK_TRACKED.PostToolUseFailure, ["Bash", "PowerShell", "mcp__*"]);
  assert.equal(MAX_UNRESOLVED_PER_STOP, 16);
});

test("record then take: one-shot, keyed only, and a different id resolves nothing", () => {
  const dir = fresh();
  try {
    assert.equal(recordAsk({ sessionId: "sess-RAW-1", toolUseId: "toolu_RAW_abc", agentId: "agent-RAW-9", seqFrom: 10, seqTo: 12 }, { dir }), true);
    const raw = readFileSync(join(dir, ASKS_FILE), "utf8");
    for (const s of ["sess-RAW-1", "toolu_RAW_abc", "agent-RAW-9"]) assert.ok(!raw.includes(s), `raw id ${s} on disk`);
    assert.equal(takeAsk({ sessionId: "sess-RAW-1", toolUseId: "toolu_other" }, { dir }), null);
    assert.equal(takeAsk({ sessionId: "sess-other", toolUseId: "toolu_RAW_abc" }, { dir }), null);
    const hit = takeAsk({ sessionId: "sess-RAW-1", toolUseId: "toolu_RAW_abc" }, { dir });
    assert.equal(hit.seqFrom, 10);
    assert.equal(hit.seqTo, 12);
    assert.equal(takeAsk({ sessionId: "sess-RAW-1", toolUseId: "toolu_RAW_abc" }, { dir }), null, "take is one-shot");
  } finally { rmTree(dir); }
});

test("bounded at MAX_ASKS (oldest go) and a 24 h TTL", () => {
  const dir = fresh();
  try {
    const t0 = 1_000_000_000_000;
    for (let i = 0; i < MAX_ASKS + 5; i++) recordAsk({ sessionId: "s", toolUseId: `u${i}`, seqFrom: i + 1, seqTo: i + 1 }, { dir, now: t0 + i });
    const st = JSON.parse(readFileSync(join(dir, ASKS_FILE), "utf8"));
    assert.equal(st.asks.length, MAX_ASKS);
    assert.equal(takeAsk({ sessionId: "s", toolUseId: "u0" }, { dir, now: t0 + 400 }), null, "the oldest was dropped");
    assert.equal(takeAsk({ sessionId: "s", toolUseId: `u${MAX_ASKS + 4}` }, { dir, now: t0 + 400 }).seqFrom, MAX_ASKS + 5);
    assert.equal(takeAsk({ sessionId: "s", toolUseId: "u100" }, { dir, now: t0 + ASK_TTL_MS + 1000 }), null, "expired");
  } finally { rmTree(dir); }
});

test("takeUnresolvedAsks: per session and thread, at most 16, the rest counted, all removed", () => {
  const dir = fresh();
  try {
    for (let i = 0; i < 20; i++) recordAsk({ sessionId: "s", toolUseId: `m${i}`, seqFrom: i + 1, seqTo: i + 1 }, { dir });
    recordAsk({ sessionId: "s", agentId: "sub", toolUseId: "x", seqFrom: 99, seqTo: 99 }, { dir });
    recordAsk({ sessionId: "other", toolUseId: "y", seqFrom: 100, seqTo: 100 }, { dir });
    const r = takeUnresolvedAsks({ sessionId: "s" }, { dir });
    assert.equal(r.asks.length, 16);
    assert.equal(r.more, 4);
    assert.deepEqual(r.asks[0], { seqFrom: 1, seqTo: 1 });
    assert.deepEqual(takeUnresolvedAsks({ sessionId: "s" }, { dir }), { asks: [], more: 0 });
    assert.deepEqual(takeUnresolvedAsks({ sessionId: "s", agentId: "sub" }, { dir }).asks, [{ seqFrom: 99, seqTo: 99 }]);
    assert.equal(takeAsk({ sessionId: "other", toolUseId: "y" }, { dir }).seqFrom, 100);
  } finally { rmTree(dir); }
});

test("lock held elsewhere: record and take give up within the wait, never hang, never throw", () => {
  const dir = fresh();
  try {
    recordAsk({ sessionId: "s", toolUseId: "u", seqFrom: 1, seqTo: 1 }, { dir });
    mkdirSync(join(dir, ".ask-pending.lock")); // a lock path nobody can remove as a file
    const t = Date.now();
    assert.equal(recordAsk({ sessionId: "s", toolUseId: "v", seqFrom: 2, seqTo: 2 }, { dir }), false);
    assert.equal(takeAsk({ sessionId: "s", toolUseId: "u" }, { dir }), null);
    assert.deepEqual(takeUnresolvedAsks({ sessionId: "s" }, { dir }), { asks: [], more: 0 });
    assert.ok(Date.now() - t < 3000);
  } finally { rmTree(dir); }
});

test("a torn or planted file reads as empty, nothing thrown; a missing range is kept as null", () => {
  const dir = fresh();
  try {
    writeFileSync(join(dir, ASKS_FILE), "{not json");
    assert.equal(takeAsk({ sessionId: "s", toolUseId: "u" }, { dir }), null);
    assert.equal(recordAsk({ sessionId: "s", toolUseId: "u" }, { dir }), true);
    assert.deepEqual(takeAsk({ sessionId: "s", toolUseId: "u" }, { dir }), { seqFrom: null, seqTo: null, agentId: "" });
    assert.equal(recordAsk({ sessionId: "", toolUseId: "u" }, { dir }), false);
    assert.equal(recordAsk({ sessionId: "s", toolUseId: "" }, { dir }), false);
    assert.ok(existsSync(join(dir, ASKS_FILE)));
  } finally { rmTree(dir); }
});
