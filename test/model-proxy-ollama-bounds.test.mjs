// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/model-proxy-ollama-bounds.test.mjs
//
// The Ollama NDJSON path's memory and CPU bounds (model-proxy/ndjson.mjs, ollama.mjs, ollama-replace.mjs):
// what one response can make the proxy hold is capped at maxHold, whatever the line kinds, the mode or the
// number of turns, and over the cap fails closed. Unit tests drive the stream machines directly and read
// what they retain (`retained`: held line bytes, kept calls, kept text); the end-to-end tests run the real
// CLI against a fake Ollama upstream (model-proxy/test/fake-ollama.mjs).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createStream } from "../model-proxy/ollama.mjs";
import { createReplaceStream } from "../model-proxy/ollama-replace.mjs";
import { createLineSplitter } from "../model-proxy/ndjson.mjs";
import { startFakeProvider } from "../model-proxy/test/fake-provider.mjs";
import { sandbox, startConsole, startProxy, request } from "../model-proxy/test/harness.mjs";
import { chatLines, sendNdjson, clientRead, MODEL } from "../model-proxy/test/fake-ollama.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const MAX = 65536;
const ev = (s) => { const raw = Buffer.from(s); return { raw, data: s.replace(/\r?\n$/, "") }; };
const callLine = (cmd = "ls -la", pad = 0) => `${JSON.stringify({ model: MODEL, message: { role: "assistant", content: "", tool_calls: [{ function: { name: "run_shell", arguments: { command: cmd, ...(pad ? { pad: "x".repeat(pad) } : {}) } } }] }, done: false })}\n`;
const DONE = `${JSON.stringify({ model: MODEL, message: { role: "assistant", content: "" }, done_reason: "stop", done: true })}\n`;
const BLANK = `${" ".repeat(1023)}\n`;
// The checker's rule for a call marked over the cap (check.mjs checkArgs): denied in enforce mode.
function decider() {
  const lists = [];
  const decide = async (list) => { lists.push(list); return list.some((c) => c.over) ? { decision: "deny", denied: [{ name: list[0].name, reasons: ["tool call arguments exceed the scan cap"] }] } : { decision: "allow", denied: [] }; };
  return { decide, lists };
}
const total = (r) => r.rawBytes + r.textChars;

test("refuse mode: blank lines inside a held turn count against maxHold; past it the turn is refused and nothing stays held", async () => {
  const { decide } = decider();
  const m = createStream({ enforce: true, decide, maxHold: MAX });
  let r = await m.onEvent(ev(callLine()));
  let fed = 0, peak = 0;
  for (let i = 0; i < 1024 && !r.refuse; i++) {
    r = await m.onEvent(ev(BLANK));
    fed += BLANK.length;
    peak = Math.max(peak, total(m.retained));
    assert.deepEqual(r.out || [], [], "nothing of the held turn is released");
  }
  assert.ok(r.refuse, `still holding after ${fed} bytes of blank lines`);
  assert.ok(fed <= MAX + BLANK.length, `refused only after ${fed} bytes`);
  assert.ok(peak <= MAX, `held ${peak} bytes`);
  assert.equal(m.holding, false);
  assert.equal(m.retained.rawBytes, 0);
});

test("replace mode: blank lines inside a held turn count against maxHold; the held bytes stay under it and the turn is replaced as over the cap", async () => {
  const { decide } = decider();
  const m = createReplaceStream({ decide, maxHold: MAX });
  await m.onEvent(ev(callLine()));
  let peak = 0;
  for (let i = 0; i < 1024; i++) { const r = await m.onEvent(ev(BLANK)); assert.deepEqual(r.out, []); peak = Math.max(peak, total(m.retained)); }
  assert.ok(peak <= MAX, `held ${peak} bytes of a 1 MiB blank-line stream (cap ${MAX})`);
  const r = await m.onEvent(ev(DONE));
  assert.ok(r.replaced, "the over-cap turn is replaced");
  const out = Buffer.concat(r.out).toString();
  assert.ok(!out.includes("ls -la") && !out.includes("tool_calls"), "the call is withheld");
  assert.match(clientRead(Buffer.concat(r.out)).text, /withheld this turn's tool call; nothing was run — tool call run_shell: tool call arguments exceed the scan cap/);
});

test("report mode: a turn's tool calls are kept only up to maxHold of call lines, then decided as over the cap", async () => {
  const { decide, lists } = decider();
  const m = createStream({ enforce: false, decide, maxHold: MAX });
  const line = callLine("ls", 16000);
  let peakCalls = 0;
  for (let i = 0; i < 64; i++) { await m.onEvent(ev(line)); peakCalls = Math.max(peakCalls, m.retained.calls); }
  assert.ok(peakCalls * line.length <= MAX, `kept ${peakCalls} calls of ${line.length} bytes each (cap ${MAX})`);
  assert.ok(lists.length >= 1 && lists[0].every((c) => c.over), "the over-cap turn is decided (for the report) as over the cap");
});

test("replace mode: past the cap no further tool calls are kept", async () => {
  const { decide } = decider();
  const m = createReplaceStream({ decide, maxHold: MAX });
  const line = callLine("ls", 16000);
  let peakCalls = 0;
  for (let i = 0; i < 128; i++) { await m.onEvent(ev(line)); peakCalls = Math.max(peakCalls, m.retained.calls); }
  assert.ok(peakCalls * line.length <= MAX, `kept ${peakCalls} calls of ${line.length} bytes each (cap ${MAX})`);
  const r = await m.onEvent(ev(DONE));
  assert.ok(r.replaced);
});

test("every mode: each turn of a response is decided on its own calls; a stream of many turns never accumulates them", async () => {
  for (const mk of [(decide) => createStream({ enforce: true, decide, maxHold: MAX }), (decide) => createStream({ enforce: false, decide, maxHold: MAX }), (decide) => createReplaceStream({ decide, maxHold: MAX })]) {
    const { decide, lists } = decider();
    const m = mk(decide);
    for (let i = 0; i < 5; i++) { await m.onEvent(ev(callLine(`echo ${i}`))); await m.onEvent(ev(DONE)); await new Promise((r) => setImmediate(r)); }
    assert.deepEqual(lists.map((l) => l.length), [1, 1, 1, 1, 1]);
    assert.equal(m.retained.calls, 0);
  }
});

test("a turn that is over the cap on its first line is decided as over the cap, never as an empty (allowed) list", async () => {
  for (const mk of [(decide) => createStream({ enforce: true, decide, maxHold: 200 }), (decide) => createReplaceStream({ decide, maxHold: 200 })]) {
    const { decide, lists } = decider();
    const m = mk(decide);
    let r = await m.onEvent(ev(callLine("ls", 400)));
    if (!r.refuse) r = await m.onEvent(ev(DONE));
    assert.ok(r.refuse || r.replaced, JSON.stringify(r));
    assert.ok(lists[0].length >= 1 && lists[0].every((c) => c.over), JSON.stringify(lists));
  }
});

test("/api/generate text and a held turn share one maxHold: text kept up to the cap leaves no room to hold a turn past it", async () => {
  for (const mk of [(decide) => createStream({ enforce: true, decide, maxHold: MAX }), (decide) => createReplaceStream({ decide, maxHold: MAX })]) {
    const { decide } = decider();
    const m = mk(decide);
    const word = `${JSON.stringify({ model: MODEL, response: "y".repeat(4000), done: false })}\n`;
    for (let i = 0; i < 16; i++) await m.onEvent(ev(word));
    let r = await m.onEvent(ev(callLine()));
    let peak = total(m.retained);
    for (let i = 0; i < 16 && !r.refuse; i++) { r = await m.onEvent(ev(callLine())); peak = Math.max(peak, total(m.retained)); }
    assert.ok(peak <= MAX, `text + held = ${peak} (cap ${MAX})`);
    if (!r.refuse) r = await m.onEvent(ev(DONE));
    assert.ok(r.refuse || r.replaced, JSON.stringify(r).slice(0, 200));
  }
});

test("NDJSON splitter: a line that arrives whole in one chunk is held to the cap too", () => {
  const s = createLineSplitter(64);
  assert.deepEqual(s.push(Buffer.from(`${JSON.stringify({ a: "x".repeat(100) })}\n`)), []);
  assert.equal(s.overflow, true);
  const t = createLineSplitter(64);
  assert.equal(t.push(Buffer.from('{"a":1}\n{"b":2}\n{"c"')).length, 2);
  assert.deepEqual(t.push(Buffer.from(":3}")), []);
  assert.deepEqual(t.end().map((e) => e.data), ['{"c":3}']);
});

test("NDJSON splitter: a 1 MiB line delivered a byte at a time is linear (seconds of CPU with the old concat-and-rescan)", () => {
  const s = createLineSplitter(1048576);
  const one = Buffer.from("a");
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < 1048576 && !s.overflow; i++) s.push(one);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.ok(ms < 5000, `${ms} ms`);
  const out = s.push(Buffer.from("\n"));
  assert.equal(s.overflow, true, "1 MiB plus its newline is over the 1 MiB cap");
  assert.deepEqual(out, []);
});

// ---- through the CLI ----
let fp, con, home, pxF, pxE;
before(async () => {
  fp = await startFakeProvider();
  con = await startConsole();
  home = sandbox();
  const env = { MOORAI_SERVER_URL: con.url, MOORAI_INSTALL_TOKEN: "tok-model-proxy-ollama-bounds-1", MOORAI_TENANT: "t-mp-ob" };
  const routes = ["--route", `/ollama=${fp.url}`];
  pxF = await startProxy(home, ["--mode", "enforce", ...routes], env);
  pxE = await startProxy(home, ["--mode", "enforce", "--denied-tool-call", "replace", ...routes], env);
});
after(async () => { await pxF?.stop(); await pxE?.stop(); await fp?.close(); await con?.close(); if (home) rmTree(home); });
const chat = (px) => request(px.listening, "/ollama/api/chat", { body: { model: MODEL, messages: [{ role: "user", content: "list files" }] } });
// An allowed call (`ls -la`), then 1.1 MiB of blank lines inside its turn (past the 1 MiB default hold cap),
// then the done line.
const padded = () => { const l = chatLines({ text: "", tools: [{ name: "run_shell", input: { command: "ls -la" } }] }); const done = l.pop(); return [...l, ...Array(1100).fill(BLANK), done]; };

test("through the proxy, refuse mode: an allowed call followed by 1.1 MiB of blank lines is refused as over the hold cap, not released", async () => {
  fp.on((r, res) => sendNdjson(res, padded(), { slice: 65536 }));
  const r = await chat(pxF);
  assert.ok(!r.raw.includes("ls -la"), "the held call was released");
  assert.match(clientRead(r.raw).error || "", /exceed the scan cap|over the hold cap/);
});

test("through the proxy, replace mode: the same turn is replaced as over the hold cap", async () => {
  fp.on((r, res) => sendNdjson(res, padded(), { slice: 65536 }));
  const r = await chat(pxE);
  assert.ok(!r.raw.includes("ls -la"), "the held call was released");
  const c = clientRead(r.raw);
  assert.equal(c.calls.length, 0);
  assert.match(c.text, /withheld this turn's tool call; nothing was run — tool call run_shell: (tool call arguments exceed the scan cap|over the hold cap)/);
  assert.ok(r.raw.length < 64 * 1024, `${r.raw.length} bytes delivered: the blank lines were freed, not replayed`);
});
