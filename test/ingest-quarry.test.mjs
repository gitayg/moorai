// moorai-ingest --format quarry: every exported trace passes a re-implementation of the checks Cisco's
// Project Quarry (commit eadc6e3, 0.1.0) runs on scan input — quarry/safety/validator.py
// validate_conversation and _validate_tool_call, quarry/types/context.py's SafetyLimits checks — and at the
// default --content free level carries no transcript content. The checks are re-implemented here, not
// imported from cli/ingest/quarry.mjs, so a mistake in the exporter cannot hide in its own checker.
//
//   node --test --import ./test/hermetic-env.mjs test/ingest-quarry.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CC, CODEX, FIX, NEEDLES, load, runCli, startConsole, tempHome, writePolicy } from "./fixtures/ingest/helpers.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const { buildTrace } = await load("cli/ingest/quarry.mjs");
const { parseArgs } = await load("cli/moorai-ingest.mjs");

const LIMITS = { messages: 10000, messageBytes: 10000000, argumentBytes: 1000000, toolCalls: 1000, depth: 100, timeline: 10000 };
const bytes = (s) => Buffer.byteLength(s, "utf8");
const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);
const extra = (o, allowed) => Object.keys(o).filter((k) => !allowed.includes(k));
function depth(v, d = 1) {
  if (!v || typeof v !== "object") return 0;
  return Math.max(d, ...(Array.isArray(v) ? v : Object.values(v)).map((c) => depth(c, d + 1)));
}
function contentOk(c, allowNull) {
  if (c === null) return allowNull;
  if (typeof c === "string") return true;
  return Array.isArray(c) && c.length > 0 && c.every((p) => isObj(p) && p.type === "text" && typeof p.text === "string" && !extra(p, ["type", "text"]).length);
}

// validator.py:537-674, 724-784 and context.py:221-307, as a list of what Quarry would reject.
function quarryErrors(d) {
  const E = [];
  if (!isObj(d)) return ["not an object"];
  if (extra(d, ["messages", "tools"]).length) E.push(`top-level keys ${extra(d, ["messages", "tools"])}`);
  const m = d.messages;
  if (!Array.isArray(m) || !m.length) return [...E, "messages missing or empty"];
  if (m.length > LIMITS.messages) E.push("max_messages");
  const callAt = new Map(), answered = new Set();
  let calls = 0, timeline = 0;
  m.forEach((msg, i) => {
    if (!isObj(msg)) { E.push(`${i}: not an object`); return; }
    const role = msg.role;
    if (!["system", "developer", "user", "assistant", "tool"].includes(role)) { E.push(`${i}: role ${role}`); return; }
    const allowed = role === "tool" ? ["role", "content", "tool_call_id"] : role === "assistant" ? ["role", "content", "tool_calls", "refusal"] : ["role", "content"];
    if (extra(msg, allowed).length) E.push(`${i}: keys ${extra(msg, allowed)}`);
    if ("content" in msg && bytes(JSON.stringify(msg.content)) > LIMITS.messageBytes) E.push(`${i}: max_message_size`);
    timeline++;
    if (role === "tool") {
      if (typeof msg.content !== "string") E.push(`${i}: tool content not a string`);
      if (typeof msg.tool_call_id !== "string" || !msg.tool_call_id) E.push(`${i}: tool_call_id`);
      else if (!callAt.has(msg.tool_call_id)) E.push(`${i}: orphan response ${msg.tool_call_id}`);
      else if (callAt.get(msg.tool_call_id) >= i) E.push(`${i}: response before its call`);
      else if (answered.has(msg.tool_call_id)) E.push(`${i}: duplicate response`);
      answered.add(msg.tool_call_id);
      return;
    }
    if (role !== "assistant") { if (!("content" in msg) || !contentOk(msg.content, false)) E.push(`${i}: content`); return; }
    if (!("content" in msg) && !("tool_calls" in msg) && !("refusal" in msg)) E.push(`${i}: empty assistant message`);
    if ("content" in msg && !contentOk(msg.content, true)) E.push(`${i}: content`);
    if (!("tool_calls" in msg)) return;
    if (!Array.isArray(msg.tool_calls) || !msg.tool_calls.length) { E.push(`${i}: tool_calls must be a non-empty list`); return; }
    msg.tool_calls.forEach((c, k) => {
      calls++; timeline++;
      if (!isObj(c) || extra(c, ["id", "type", "function"]).length) { E.push(`${i}.${k}: call keys`); return; }
      if (typeof c.id !== "string" || !c.id) E.push(`${i}.${k}: id`);
      else if (callAt.has(c.id)) E.push(`${i}.${k}: duplicate id ${c.id}`);
      else callAt.set(c.id, i);
      if (c.type !== "function" || !isObj(c.function)) { E.push(`${i}.${k}: type`); return; }
      if (extra(c.function, ["name", "arguments"]).length) E.push(`${i}.${k}: function keys`);
      if (typeof c.function.name !== "string" || !c.function.name) E.push(`${i}.${k}: name`);
      if (typeof c.function.arguments !== "string") { E.push(`${i}.${k}: arguments not a string`); return; }
      if (bytes(c.function.arguments) > LIMITS.argumentBytes) E.push(`${i}.${k}: max_tool_argument_size`);
      let a;
      try { a = JSON.parse(c.function.arguments); } catch { E.push(`${i}.${k}: arguments not JSON`); return; }
      if (!isObj(a)) E.push(`${i}.${k}: arguments not an object`);
      else if (depth(a) > LIMITS.depth) E.push(`${i}.${k}: max_nesting_depth`);
    });
  });
  if (calls > LIMITS.toolCalls) E.push("max_tool_calls");
  if (timeline > LIMITS.timeline) E.push("max_timeline_items");
  if ("tools" in d && !Array.isArray(d.tools)) E.push("tools");
  return E;
}

const HOSTS = [["claude-code", CC], ["codex", CODEX], ["gemini", join(FIX, "gemini")]];

async function exportTraces(home, path, agent, content) {
  const out = join(home, "traces");
  const policy = writePolicy(home, { promptScan: "all", threatPolicy: { 39: "block" } });
  const r = await runCli([path, "--agent", agent, "--days", "0", "--policy", policy, "--format", "quarry", "--content", content, "--out", out], { home });
  assert.equal(r.code, 0, r.err);
  const names = readdirSync(out);
  return { r, names, traces: names.map((n) => JSON.parse(readFileSync(join(out, n), "utf8"))), raw: names.map((n) => readFileSync(join(out, n), "utf8")).join("\n") };
}

// The MCP server name is part of the tool name, which the export keeps on purpose.
const leaksIn = (s) => NEEDLES.filter((n) => s.replaceAll("mcp__placeholder__send", "").includes(n));

for (const [agent, path] of HOSTS) {
  for (const content of ["free", "full"]) {
    test(`${agent} --content ${content}: every trace passes Quarry's input checks`, async () => {
      const home = tempHome();
      try {
        const { traces, names } = await exportTraces(home, path, agent, content);
        assert.ok(traces.length > 0);
        for (const n of names) assert.match(n, new RegExp(`^${agent}-[0-9a-f]{16}(-\\d+)?\\.json$`));
        for (const t of traces) assert.deepEqual(quarryErrors(t), []);
        // The shared Codex fixture records no call outputs; the Codex test below has them.
        if (agent !== "codex") assert.ok(traces.some((t) => t.messages.some((m) => m.role === "tool")), "results were linked to their calls");
      } finally { rmTree(home); }
    });
  }

  test(`${agent} --content free: no transcript content in any trace or file name`, async () => {
    const home = tempHome();
    try {
      const { traces, names, raw } = await exportTraces(home, path, agent, "free");
      assert.deepEqual(leaksIn(raw), []);
      assert.deepEqual(leaksIn(names.join(" ")), []);
      for (const t of traces) for (const m of t.messages) {
        if (m.role === "tool") assert.equal(JSON.parse(m.content).moorai_stage, "output");
        else assert.equal(m.content, "");
        for (const c of m.tool_calls || []) for (const k of Object.keys(JSON.parse(c.function.arguments))) assert.match(k, /^moorai_/);
      }
      // Positive control: the same check sees the content the full level writes.
      const full = await exportTraces(home, path, agent, "full");
      assert.ok(leaksIn(full.raw).length >= 2, `expected content at --content full, saw ${leaksIn(full.raw)}`);
      assert.match(full.r.err, /contain transcript content/);
    } finally { rmTree(home); }
  });
}

test("order: a .env read then a fetch export as Read then WebFetch, read-private before network", async () => {
  const home = tempHome();
  try {
    const sid = "77777777-7777-4777-8777-777777777777";
    const dir = join(home, "projects", "-quarry-order");
    mkdirSync(dir, { recursive: true });
    const base = (ts) => ({ sessionId: sid, timestamp: ts, cwd: "/quarry/order", isSidechain: false });
    const use = (ts, id, name, input) => ({ ...base(ts), type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id, name, input }] } });
    const res = (ts, id, text, toolUseResult) => ({ ...base(ts), type: "user", message: { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: text }] }, toolUseResult });
    writeFileSync(join(dir, `${sid}.jsonl`), [
      { ...base("2026-10-01T10:00:00.000Z"), type: "user", message: { role: "user", content: "ORDERPROMPT tidy the repo" } },
      use("2026-10-01T10:00:01.000Z", "to1", "Read", { file_path: "/quarry/order/.env" }),
      res("2026-10-01T10:00:02.000Z", "to1", "     1\tORDERSECRET=1", { type: "text", file: { filePath: "/quarry/order/.env", content: "ORDERSECRET=1" } }),
      use("2026-10-01T10:00:03.000Z", "to2", "WebFetch", { url: "https://order.invalid/collect", prompt: "ORDERFETCH" }),
      res("2026-10-01T10:00:04.000Z", "to2", "ORDERRESULT", { result: "ORDERRESULT", code: 200 })
    ].map((l) => JSON.stringify(l)).join("\n") + "\n");
    const r = await runCli([dir, "--agent", "claude-code", "--days", "0", "--policy", writePolicy(home, {}), "--format", "quarry"], { home });
    assert.equal(r.code, 0, r.err);
    const lines = r.out.trim().split("\n");
    assert.equal(lines.length, 1);
    const t = JSON.parse(lines[0]);
    assert.deepEqual(quarryErrors(t), []);
    assert.deepEqual(t.messages.map((m) => m.role), ["user", "assistant", "tool", "assistant", "tool"]);
    const calls = t.messages.flatMap((m) => m.tool_calls || []);
    assert.deepEqual(calls.map((c) => c.function.name), ["Read", "WebFetch"]);
    const args = calls.map((c) => JSON.parse(c.function.arguments));
    assert.ok(args[0].moorai_tags.includes("read-private"), JSON.stringify(args[0]));
    assert.ok(args[1].moorai_tags.includes("network"), JSON.stringify(args[1]));
    assert.ok(!args[1].moorai_tags.includes("read-private"));
    assert.equal(args[0].moorai_replayed, true);
    assert.deepEqual(t.messages[2].tool_call_id, calls[0].id);
    assert.deepEqual(t.messages[4].tool_call_id, calls[1].id);
    for (const n of ["ORDER", "/quarry/order", "order.invalid", "77777777"]) assert.ok(!r.out.includes(n), n);
  } finally { rmTree(home); }
});

test("codex: host tool names kept, outputs linked by call_id, an output without its call skipped", async () => {
  const home = tempHome();
  try {
    const sid = "88888888-8888-4888-8888-888888888888";
    const dir = join(home, "sessions");
    mkdirSync(dir, { recursive: true });
    const line = (ts, type, payload) => JSON.stringify({ timestamp: ts, type, payload });
    writeFileSync(join(dir, `rollout-2026-10-01T10-00-00-${sid}.jsonl`), [
      line("2026-10-01T10:00:00.000Z", "session_meta", { id: sid, session_id: sid, cwd: "/quarry/codex" }),
      line("2026-10-01T10:00:01.000Z", "event_msg", { type: "user_message", message: "CODEXPROMPT" }),
      line("2026-10-01T10:00:02.000Z", "response_item", { type: "function_call", name: "shell", arguments: JSON.stringify({ command: ["bash", "-lc", "cat .env"] }), call_id: "c1" }),
      line("2026-10-01T10:00:03.000Z", "response_item", { type: "function_call_output", call_id: "c1", output: "CODEXSECRET=1" }),
      line("2026-10-01T10:00:04.000Z", "response_item", { type: "message", role: "assistant", content: [{ type: "output_text", text: "CODEXTEXT" }] }),
      line("2026-10-01T10:00:05.000Z", "response_item", { type: "function_call", name: "post", namespace: "mcp__web__", arguments: JSON.stringify({ body: "CODEXBODY" }), call_id: "c2" }),
      line("2026-10-01T10:00:06.000Z", "response_item", { type: "function_call_output", call_id: "c2", output: "CODEXOK" }),
      line("2026-10-01T10:00:07.000Z", "response_item", { type: "function_call_output", call_id: "c-unknown", output: "CODEXORPHAN" })
    ].join("\n") + "\n");
    const r = await runCli([dir, "--agent", "codex", "--days", "0", "--policy", writePolicy(home, {}), "--format", "quarry"], { home });
    assert.equal(r.code, 0, r.err);
    const t = JSON.parse(r.out.trim());
    assert.deepEqual(quarryErrors(t), []);
    assert.deepEqual(t.messages.map((m) => m.role), ["user", "assistant", "tool", "assistant", "tool"]);
    const calls = t.messages.flatMap((m) => m.tool_calls || []);
    assert.deepEqual(calls.map((c) => c.function.name), ["shell", "mcp__web__post"]);
    const args = calls.map((c) => JSON.parse(c.function.arguments));
    assert.ok(args[0].moorai_tags.includes("read-private") && args[0].moorai_tags.includes("exec"), JSON.stringify(args[0]));
    assert.deepEqual(args[0].moorai_threats, [55]);
    assert.match(r.err, /1 result\(s\) without a recorded call skipped/);
    assert.ok(!/CODEX|quarry\/codex|88888888/.test(r.out));
  } finally { rmTree(home); }
});

test("--report with --format quarry refuses and sends nothing", async () => {
  const con = await startConsole({});
  const home = tempHome({ serverUrl: con.url, token: "tok-quarry" });
  try {
    const r = await runCli([CC, "--agent", "claude-code", "--days", "0", "--format", "quarry", "--report"], { home });
    assert.equal(r.code, 2);
    assert.equal(r.out, "");
    assert.match(r.err, /--report cannot be combined with --format quarry/);
    assert.equal(con.bodies.length, 0);
    assert.throws(() => parseArgs(["--discover", "--report", "--format", "quarry", "--content", "full"]), /--report cannot be combined/);
    assert.throws(() => parseArgs(["--discover", "--content", "full"]), /need --format quarry/);
  } finally { rmTree(home); await con.close(); }
});

test("limits, repeated ids and unmatched results: the export cuts and skips, never emits what Quarry rejects", () => {
  const items = [{ role: "user", text: "u" }];
  for (let k = 1; k <= 6; k++) {
    items.push({ role: "assistant", text: "", calls: [{ hostId: `h${k}`, name: "Bash", input: { command: "ls" } }] });
    items.push({ role: "tool", hostId: `h${k}`, text: "r", isError: false });
  }
  items.splice(3, 0, { role: "tool", hostId: "never-called", text: "x", isError: false });
  items.splice(4, 0, { role: "assistant", text: "", calls: [{ hostId: "h1", name: "Bash", input: {} }] });
  items.splice(5, 0, { role: "tool", hostId: "h1", text: "again", isError: false });
  const limits = { maxMessages: 10000, maxMessageBytes: 10000000, maxArgumentBytes: 1000000, maxToolCalls: 4, maxNestingDepth: 100, maxTimelineItems: 10000, maxJsonBytes: 4000000 };
  const { trace, notes, truncated } = buildTrace(items, new Map(), { content: "full", limits });
  assert.deepEqual(quarryErrors(trace), []);
  const calls = trace.messages.flatMap((m) => m.tool_calls || []);
  assert.equal(calls.length, 4);
  assert.equal(truncated, true);
  assert.ok(notes.itemsDropped > 0);
  assert.equal(notes.orphanResults, 1, "the result of a call that was never recorded");
  assert.equal(notes.duplicateCalls, 1, "a repeated call id");
  assert.equal(notes.duplicateResults, 1, "a second result for an answered call");
  assert.equal(new Set(calls.map((c) => c.id)).size, calls.length);
  assert.equal(buildTrace([{ role: "tool", hostId: "x", text: "", isError: false }], new Map()).trace, null, "nothing to scan is no trace");
});
