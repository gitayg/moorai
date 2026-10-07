// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/model-proxy-enforce.test.mjs
//
// moorai-model-proxy --mode enforce, RESPONSE side (model → agent), through the real CLI process, against
// the fake provider (model-proxy/test/fake-provider.mjs) and a fake console, for both the Anthropic Messages
// and the OpenAI Chat Completions shapes. Every tool call and every text here is benign: the deny verdicts
// come from a declared WORKLOAD PROFILE (cli/workload-profile.mjs) loaded with --policy-file, matched on
// --service-id, that allows only `Read` and says `action: "block"` — so a `Bash` call (`ls -la`) is a
// PROFILE_DRIFT deny and a `Read` of README.md is allowed.
// No real provider and no real key is involved anywhere.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { startFakeProvider, sendJson, sendSse, anthropicMessage, anthropicStream, openaiCompletion, openaiStream } from "../model-proxy/test/fake-provider.mjs";
import { sandbox, startConsole, startProxy, request, waitFor, sseEvents } from "../model-proxy/test/harness.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const SERVICE = "model-bot";
const PROFILE_ID = "model-bot-readonly";
const POLICY = { workloadProfiles: [{ id: PROFILE_ID, match: { serviceId: SERVICE }, tools: ["Read"], action: "block" }] };
const READ = { name: "Read", input: { file_path: "README.md" } };
const BASH = { name: "Bash", input: { command: "ls -la" } };
const TEXT = "Let me look at the project files.";
const PROMPT = "please list the project files";

const sse = (type, data) => `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
const ochunk = (choices) => `data: ${JSON.stringify({ id: "chatcmpl-fake03", object: "chat.completion.chunk", created: 1759700000, model: "gpt-fake", choices })}\n\n`;
const FILLER = "lorem ipsum dolor sit amet ";

const APIS = {
  anthropic: {
    path: "/anthropic/v1/messages",
    headers: { "anthropic-version": "2023-06-01" },
    body: (stream) => ({ model: "claude-fake", max_tokens: 64, ...(stream ? { stream: true } : {}), messages: [{ role: "user", content: PROMPT }] }),
    json: (tools) => anthropicMessage({ text: TEXT, tools }),
    stream: (tools) => anthropicStream({ text: TEXT, tools }),
    toolStart: (evs, from = 0) => evs.findIndex((e, i) => i >= from && e.includes('"type":"content_block_start"') && e.includes('"type":"tool_use"')),
    terminal: "message_stop",
    callEnd: (evs) => evs.findIndex((e, i) => i > evs.findIndex((x) => x.includes('"type":"tool_use"')) && e.includes('"type":"content_block_stop"')),
    // The same stream with the tool call's last argument fragment missing its closing brace.
    unclosed: (evs) => editLast(evs, "input_json_delta", (d) => { d.delta.partial_json = d.delta.partial_json.replace(/\}$/, ""); }),
    jsonUnclosed: () => { const m = anthropicMessage({ text: TEXT, tools: [BASH] }); m.content[1].input = JSON.stringify(BASH.input).replace(/\}$/, ""); return m; },
    toolMarkers: ['"type":"tool_use"', "input_json_delta", "toolu_fake"],
    // The refusal as the SDK reads it: { status, type, message }.
    refusalJson: (j) => { assert.equal(j.type, "error"); return { type: j.error.type, message: j.error.message, code: "permission_error" }; },
    streamRefusal(evs) {
      const last = evs.at(-1);
      assert.equal(last.event, "error", `last event: ${JSON.stringify(last)}`);
      const d = JSON.parse(last.data);
      assert.equal(d.type, "error");
      return { type: d.error.type, message: d.error.message, code: "permission_error" };
    },
    // A Read whose arguments are past the 1 MiB hold cap, in events each under the 1 MiB SSE event cap.
    overCap() {
      const json = JSON.stringify({ file_path: "README.md", note: FILLER.repeat(Math.ceil(1300000 / FILLER.length)) });
      const out = [sse("message_start", { type: "message_start", message: { id: "msg_fake04", type: "message", role: "assistant", model: "claude-fake", content: [], stop_reason: null, usage: { input_tokens: 10, output_tokens: 1 } } }),
        sse("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_fakebig", name: "Read", input: {} } })];
      for (let j = 0; j < json.length; j += 200000) out.push(sse("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: json.slice(j, j + 200000) } }));
      out.push(sse("content_block_stop", { type: "content_block_stop", index: 0 }), sse("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use", stop_sequence: null }, usage: { output_tokens: 9 } }), sse("message_stop", { type: "message_stop" }));
      return out;
    }
  },
  openai: {
    path: "/openai/chat/completions",
    headers: {},
    body: (stream) => ({ model: "gpt-fake", ...(stream ? { stream: true } : {}), messages: [{ role: "user", content: PROMPT }] }),
    json: (tools) => openaiCompletion({ text: TEXT, tools }),
    stream: (tools) => openaiStream({ text: TEXT, tools }),
    toolStart: (evs, from = 0) => evs.findIndex((e, i) => i >= from && e.includes('"tool_calls"')),
    terminal: "[DONE]",
    callEnd: (evs) => evs.findIndex((e) => e.includes('"finish_reason":"tool_calls"')),
    unclosed: (evs) => editLast(evs, '"arguments"', (d) => { const f = d.choices[0].delta.tool_calls[0].function; f.arguments = f.arguments.replace(/\}$/, ""); }),
    jsonUnclosed: () => { const m = openaiCompletion({ text: TEXT, tools: [BASH] }); const f = m.choices[0].message.tool_calls[0].function; f.arguments = f.arguments.replace(/\}$/, ""); return m; },
    toolMarkers: ['"tool_calls"', "call_fake"],
    refusalJson: (j) => ({ type: j.error.type, message: j.error.message, code: j.error.code }),
    streamRefusal(evs) {
      const last = evs.at(-1);
      assert.equal(last.event, null);
      const d = JSON.parse(last.data);
      assert.ok(d.error, `last chunk carries no error: ${last.data}`);
      return { type: d.error.type, message: d.error.message, code: d.error.code };
    },
    overCap() {
      const json = JSON.stringify({ file_path: "README.md", note: FILLER.repeat(Math.ceil(1300000 / FILLER.length)) });
      const out = [ochunk([{ index: 0, delta: { role: "assistant", content: "" }, logprobs: null, finish_reason: null }]),
        ochunk([{ index: 0, delta: { tool_calls: [{ index: 0, id: "call_fakebig", type: "function", function: { name: "Read", arguments: "" } }] }, logprobs: null, finish_reason: null }])];
      for (let j = 0; j < json.length; j += 200000) out.push(ochunk([{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: json.slice(j, j + 200000) } }] }, logprobs: null, finish_reason: null }]));
      out.push(ochunk([{ index: 0, delta: {}, logprobs: null, finish_reason: "tool_calls" }]), "data: [DONE]\n\n");
      return out;
    }
  }
};
// The SSE event list with the last event containing `marker` rewritten by `fn` (on its parsed data).
function editLast(evs, marker, fn) {
  const i = evs.findLastIndex((e) => e.includes(marker));
  const m = evs[i].match(/^((?:event: [^\n]*\n)?data: )(.*)\n\n$/s);
  const d = JSON.parse(m[2]); fn(d);
  const out = [...evs]; out[i] = `${m[1]}${JSON.stringify(d)}\n\n`;
  assert.notEqual(out[i], evs[i], "the edit removed the closing brace");
  return out;
}
// The error object of a stream's last event (Anthropic `event: error` body.error, OpenAI chunk.error).
const lastError = (raw) => { const d = JSON.parse(sseEvents(raw).at(-1).data); return d.error; };
// A 502 in each provider's shape: Anthropic api_error, OpenAI server_error (model-proxy errorBody).
const UPSTREAM_ERROR_TYPE = { anthropic: "api_error", openai: "server_error" };
// What every refusal shares: the provider's permission error, a content-free reason.
const PROVIDER_CODE = { anthropic: "permission_error", openai: "moorai_policy_denied" };
function assertContentFree(s, extra = []) {
  for (const n of ["ls -la", "README.md", PROMPT, TEXT, "Let me look", "lorem", ...extra]) assert.ok(!s.includes(n), `carries ${JSON.stringify(n)}: ${s.slice(0, 400)}`);
}

let fp, con, home, px;
before(async () => {
  fp = await startFakeProvider();
  con = await startConsole();
  home = sandbox();
  const pf = join(home, "policy.json");
  writeFileSync(pf, JSON.stringify(POLICY));
  px = await startProxy(home, ["--mode", "enforce", "--route", `/anthropic=${fp.url}`, "--route", `/openai=${fp.url}/v1`, "--policy-file", pf, "--service-id", SERVICE],
    { MOORAI_SERVER_URL: con.url, MOORAI_INSTALL_TOKEN: "tok-model-proxy-enforce-1", MOORAI_TENANT: "t-mp-enf" });
});
after(async () => { await px.stop(); await fp.close(); await con.close(); rmTree(home); });

test("profile trigger: the proxy runs enforce, as the declared service, and the profile is what decides", async () => {
  assert.equal(px.mode, "enforce"); assert.equal(px.serviceId, SERVICE);
  const hz = await request(px.listening, "/healthz", { method: "GET" });
  assert.equal(hz.json.mode, "enforce");
});

for (const [name, api] of Object.entries(APIS)) {
  const call = (stream, opts = {}) => request(px.listening, api.path, { body: api.body(stream), headers: api.headers, ...opts });

  test(`${name}, non-streaming: an allowed tool call (Read) is forwarded byte-identical`, async () => {
    let sent;
    fp.on((r, res) => { sent = sendJson(res, api.json([READ])); });
    const r = await call(false);
    assert.equal(r.status, 200);
    assert.ok(r.raw.equals(sent), "response bytes differ from what the provider sent");
    assert.equal(r.headers["request-id"], "req_fake_0001");
  });

  test(`${name}, non-streaming: a denied tool call (Bash) is a 403 in the provider's error shape, content-free; the upstream body is not delivered`, async () => {
    fp.on((r, res) => sendJson(res, api.json([BASH])));
    const n = fp.requests.length;
    const r = await call(false);
    assert.equal(fp.requests.length, n + 1, "the request itself is allowed and reaches the provider");
    assert.equal(r.status, 403);
    assert.equal(r.headers["x-moorai-model-proxy"], "refused");
    const e = api.refusalJson(r.json);
    assert.equal(e.type, "permission_error"); assert.equal(e.code, PROVIDER_CODE[name]);
    assert.match(e.message, new RegExp(`tool call Bash: outside the declared workload profile "${PROFILE_ID}" \\(tool not in the profile\\)`));
    for (const m of [...api.toolMarkers, "msg_fake01", "chatcmpl-fake01", "Sure."]) assert.ok(!r.raw.includes(m), `upstream content delivered: ${m}`);
    assertContentFree(r.raw.toString());
  });

  test(`${name}, streaming: an allowed tool call is released and the whole stream is byte-identical`, async () => {
    const events = api.stream([READ]);
    fp.on((r, res) => sendSse(res, events));
    const r = await call(true);
    assert.equal(r.status, 200); assert.match(r.headers["content-type"], /text\/event-stream/);
    assert.ok(r.raw.equals(Buffer.from(events.join(""))), `stream bytes differ:\n${r.raw.toString().slice(0, 600)}`);
  });

  test(`${name}, streaming: text before a tool call reaches the client while the provider is paused mid-tool-call`, async () => {
    const events = api.stream([READ]);
    const ts = api.toolStart(events);
    assert.ok(ts > 0);
    let release;
    const gate = new Promise((r) => { release = r; });
    let providerDone = false;
    // The provider pauses after the tool call's first argument fragment: the call is not complete.
    fp.on((r, res) => sendSse(res, events, { gate, gateAfter: ts + 2 }).then(() => { providerDone = true; }));
    const got = [];
    const p = call(true, { onChunk: (d) => got.push(d) });
    const prefix = Buffer.from(events.slice(0, ts).join(""));
    // A failed assertion must still un-pause the provider, or the request (and the run) hangs.
    try {
      const arrived = await waitFor(() => Buffer.concat(got).length >= prefix.length, 4000);
      assert.ok(arrived, `before the tool call completed the client had ${Buffer.concat(got).length} of ${prefix.length} text bytes`);
      await new Promise((r) => setTimeout(r, 150));
      assert.equal(providerDone, false, "the provider is still paused inside the tool call");
      assert.ok(Buffer.concat(got).equals(prefix), `only the events before the tool call, exactly: ${Buffer.concat(got).toString().slice(-300)}`);
      for (const m of api.toolMarkers) assert.ok(!Buffer.concat(got).includes(m), `held tool-call bytes reached the client early: ${m}`);
    } finally { release(); }
    const r = await p;
    assert.ok(r.raw.equals(Buffer.from(events.join(""))), "after the release the full stream, byte-identical");
  });

  test(`${name}, streaming: a denied tool call ends the stream with the provider-shaped error event; the held tool-call bytes are never sent`, async () => {
    const events = api.stream([BASH]);
    const ts = api.toolStart(events);
    fp.on((r, res) => sendSse(res, events));
    const r = await call(true);
    assert.equal(r.status, 200);
    const prefix = Buffer.from(events.slice(0, ts).join(""));
    assert.ok(r.raw.subarray(0, prefix.length).equals(prefix), "the text before the tool call was released unchanged");
    const tail = r.raw.subarray(prefix.length).toString();
    for (const m of [...api.toolMarkers, "ls -la", api.terminal, "message_delta"]) assert.ok(!tail.includes(m), `after the text: ${m} was sent: ${tail.slice(0, 300)}`);
    const evs = sseEvents(r.raw);
    assert.equal(evs.length, sseEvents(prefix).length + 1, "exactly one event after the text: the error");
    const e = api.streamRefusal(evs);
    assert.equal(e.type, "permission_error"); assert.equal(e.code, PROVIDER_CODE[name]);
    assert.match(e.message, /tool call Bash: outside the declared workload profile/);
    assertContentFree(tail);
  });

  test(`${name}, streaming: the upstream ending inside a held tool call ends in an error, and no partial tool call is released`, async () => {
    const events = api.stream([READ]);
    const ts = api.toolStart(events);
    const prefix = Buffer.from(events.slice(0, ts).join(""));
    // (a) the tool call's start and two argument fragments; (b) every argument fragment (the arguments are
    // complete, valid JSON) but not the end of the call. Then the response ends cleanly.
    for (const cut of [events.slice(0, ts + 3), events.slice(0, api.callEnd(events))]) {
      fp.on((r, res) => sendSse(res, cut));
      const r = await call(true);
      assert.ok(r.raw.subarray(0, prefix.length).equals(prefix));
      const tail = r.raw.subarray(prefix.length).toString();
      for (const m of api.toolMarkers) assert.ok(!tail.includes(m), `a partial tool call was released (${m}): ${tail.slice(0, 300)}`);
      const e = api.streamRefusal(sseEvents(r.raw));
      assert.equal(e.code, PROVIDER_CODE[name]);
      assert.match(e.message, /tool call Read: the stream ended inside the tool call/);
      assertContentFree(tail);
    }
  });

  test(`${name}: the provider dropping the connection mid-response is an accurate, non-retryable 502-class error, never "overloaded"; nothing partial is released`, async () => {
    const events = api.stream([READ]);
    const ts = api.toolStart(events);
    const prefix = Buffer.from(events.slice(0, ts).join(""));
    const drop = (text) => (q, res) => { res.writeHead(200, { "content-type": "text/event-stream" }); res.write(text); setTimeout(() => res.destroy(), 50); };
    // (a) streaming, inside a held tool call
    fp.on(drop(events.slice(0, ts + 3).join("")));
    const a = await call(true);
    assert.ok(a.raw.subarray(0, prefix.length).equals(prefix));
    for (const m of api.toolMarkers) assert.ok(!a.raw.subarray(prefix.length).includes(m), `a partial tool call was released on an abrupt close (${m})`);
    const ea = lastError(a.raw);
    assert.equal(ea.type, UPSTREAM_ERROR_TYPE[name], JSON.stringify(ea));
    assert.match(ea.message, /the upstream closed inside a tool call; it was not released/);
    assertContentFree(a.raw.subarray(prefix.length).toString());
    // (b) streaming, in the text before any tool call
    fp.on(drop(events.slice(0, ts - 1).join("")));
    const b = await call(true);
    assert.ok(b.raw.subarray(0, Buffer.byteLength(events.slice(0, ts - 1).join(""))).equals(Buffer.from(events.slice(0, ts - 1).join(""))));
    const eb = lastError(b.raw);
    assert.equal(eb.type, UPSTREAM_ERROR_TYPE[name]);
    assert.match(eb.message, /the upstream closed the response before it ended/);
    // (c) non-streaming: half a body, then the connection drops. A status can still be sent: 502, and
    // x-should-retry: false, which both SDKs obey before their ">= 500 is retried" rule.
    const body = Buffer.from(JSON.stringify(api.json([READ])));
    fp.on((q, res) => { res.writeHead(200, { "content-type": "application/json", "content-length": body.length }); res.write(body.subarray(0, body.length >> 1)); setTimeout(() => res.destroy(), 50); });
    const c = await call(false);
    assert.equal(c.status, 502);
    assert.equal(c.headers["x-should-retry"], "false");
    const ec = name === "anthropic" ? (assert.equal(c.json.type, "error"), c.json.error) : c.json.error;
    assert.equal(ec.type, UPSTREAM_ERROR_TYPE[name]);
    assert.match(ec.message, /the upstream closed the response before it ended/);
    for (const m of [...api.toolMarkers, "msg_fake01", "chatcmpl-fake01"]) assert.ok(!c.raw.includes(m), `partial upstream body delivered: ${m}`);
  });

  test(`${name}: a tool call whose arguments are not valid JSON (a Bash call missing its closing brace) is refused in enforce mode, streaming and not`, async () => {
    // streaming
    const events = api.unclosed(api.stream([BASH]));
    const ts = api.toolStart(events);
    fp.on((r, res) => sendSse(res, events));
    const s1 = await call(true);
    const tail = s1.raw.subarray(Buffer.byteLength(events.slice(0, ts).join(""))).toString();
    for (const m of [...api.toolMarkers, "ls -la", api.terminal]) assert.ok(!tail.includes(m), `${m} was sent: ${tail.slice(0, 300)}`);
    const e = api.streamRefusal(sseEvents(s1.raw));
    assert.equal(e.code, PROVIDER_CODE[name]);
    assert.match(e.message, /tool call Bash: tool call arguments are not a valid JSON object/);
    assertContentFree(tail);
    // non-streaming
    fp.on((r, res) => sendJson(res, api.jsonUnclosed()));
    const n1 = await call(false);
    assert.equal(n1.status, 403);
    assert.match(api.refusalJson(n1.json).message, /tool call Bash: tool call arguments are not a valid JSON object/);
    for (const m of [...api.toolMarkers, "ls -la"]) assert.ok(!n1.raw.includes(m), `${m} delivered`);
  });

  test(`${name}, streaming: tool-call arguments over the 1 MiB hold cap are refused, content-free`, async () => {
    const events = api.overCap();
    for (const e of events) assert.ok(e.length < 1048576, "each event is under the SSE event cap, so it is the hold cap that trips");
    fp.on((r, res) => sendSse(res, events, { slice: 65536 }));
    const r = await call(true);
    assert.equal(r.status, 200);
    for (const m of [...api.toolMarkers, "lorem", api.terminal]) assert.ok(!r.raw.includes(m), `${m} was sent`);
    const e = api.streamRefusal(sseEvents(r.raw));
    assert.equal(e.type, "permission_error"); assert.equal(e.code, PROVIDER_CODE[name]);
    assert.match(e.message, /tool call Read: tool call arguments exceed the scan cap/);
    assertContentFree(r.raw.toString());
    // Reported unevaluated, once per label per process (model-proxy/report.mjs unevaluatedReporter), so the
    // second API finds the first one's alert.
    const unev = () => con.parsed().filter((x) => x.reasonCode === "UNEVALUATED_SIZE_CAP" && x.tool === "model-proxy:Read");
    assert.ok(await waitFor(() => unev().length === 1), JSON.stringify(con.parsed().map((x) => [x.tool, x.reasonCode])));
    assert.equal(unev()[0].enforcement, "UNEVALUATED"); assert.equal(unev()[0].surface, "model-proxy");
  });

  test(`${name}: two tool calls in one turn, one allowed (Read) and one denied (Bash) — the turn is refused`, async () => {
    // Non-streaming: the whole response is refused, the allowed sibling included.
    fp.on((r, res) => sendJson(res, api.json([READ, BASH])));
    const r = await call(false);
    assert.equal(r.status, 403);
    assert.match(api.refusalJson(r.json).message, /tool call Bash: outside the declared workload profile/);
    for (const m of api.toolMarkers) assert.ok(!r.raw.includes(m), `a tool call of the refused turn was delivered: ${m}`);
    // Streaming: the stream ends in the error; the denied call's bytes and the turn's end are never sent.
    const events = api.stream([READ, BASH]);
    fp.on((q, res) => sendSse(res, events));
    const s = await call(true);
    const raw = s.raw.toString();
    for (const m of ["ls -la", api.terminal, "message_delta", "toolu_fake1", "call_fake1"]) assert.ok(!raw.includes(m), `${m} was sent`);
    const e = api.streamRefusal(sseEvents(s.raw));
    assert.equal(e.code, PROVIDER_CODE[name]);
    assert.match(e.message, /tool call Bash: outside the declared workload profile/);
    if (name === "openai") {
      // Every choice's calls are held together until its finish_reason: neither call is released.
      for (const m of api.toolMarkers) assert.ok(!raw.includes(m), `openai: a tool call of the refused turn was released: ${m}`);
    } else {
      // Anthropic holds per content block (README: content_block_start … content_block_stop), so the
      // allowed Read block before the denied one was released; the turn still never completes.
      const second = api.toolStart(events, api.toolStart(events) + 1);
      const pre = Buffer.from(events.slice(0, second).join(""));
      assert.ok(s.raw.subarray(0, pre.length).equals(pre), "everything up to the denied block, unchanged");
      assert.equal(sseEvents(s.raw).length, sseEvents(pre).length + 1, "then only the error event");
    }
  });
}

test("report mode: a tool call whose arguments are not valid JSON is forwarded unchanged (content-scanned, never refused)", async () => {
  const hr = sandbox();
  const pf = join(hr, "policy.json");
  writeFileSync(pf, JSON.stringify(POLICY));
  const rep = await startProxy(hr, ["--route", `/anthropic=${fp.url}`, "--route", `/openai=${fp.url}/v1`, "--policy-file", pf, "--service-id", SERVICE]);
  try {
    for (const [name, api] of Object.entries(APIS)) {
      const events = api.unclosed(api.stream([BASH]));
      fp.on((r, res) => sendSse(res, events));
      const s1 = await request(rep.listening, api.path, { body: api.body(true), headers: api.headers });
      assert.ok(s1.raw.equals(Buffer.from(events.join(""))), `${name}: report mode changed the stream`);
      let sent;
      fp.on((r, res) => { sent = sendJson(res, api.jsonUnclosed()); });
      const n1 = await request(rep.listening, api.path, { body: api.body(false), headers: api.headers });
      assert.equal(n1.status, 200); assert.ok(n1.raw.equals(sent), `${name}: report mode changed the response`);
    }
  } finally { await rep.stop(); rmTree(hr); }
});

test("alerts in enforce mode: posted to the console, content-free, enforcement as configured (not LIMITED), surface model-proxy", async () => {
  const n0 = con.alerts.length;
  for (const api of Object.values(APIS)) {
    fp.on((r, res) => sendJson(res, api.json([BASH])));
    assert.equal((await request(px.listening, api.path, { body: api.body(false), headers: api.headers })).status, 403);
    const events = api.stream([BASH]);
    fp.on((r, res) => sendSse(res, events));
    await request(px.listening, api.path, { body: api.body(true), headers: api.headers });
  }
  const drift = () => con.parsed().slice(n0).filter((x) => x.reasonCode === "PROFILE_DRIFT");
  assert.ok(await waitFor(() => drift().length >= 4), `alerts: ${JSON.stringify(con.parsed().slice(n0).map((x) => [x.tool, x.reasonCode, x.enforcement]))}`);
  for (const x of drift()) {
    assert.equal(x.surface, "model-proxy");
    assert.equal(x.tool, "model-proxy:Bash");
    assert.equal(x.enforcement, "AS_CONFIGURED", `enforce mode refused it: ${JSON.stringify(x)}`);
    assert.equal(x.riskLevel, "Blocked"); assert.equal(x.decision, "deny");
    assert.equal(x.profileId, PROFILE_ID); assert.equal(x.driftKind, "tool");
    assert.equal(x.user, "service"); assert.equal(x.device, `svc:${SERVICE}`); assert.equal(x.tenant, "t-mp-enf");
    assert.ok(x.policyId, "provenance stamped");
  }
  // Every alert this file caused, not only the drift ones: nothing of a prompt, a text, an argument.
  for (const b of con.alerts) {
    assertContentFree(b);
    assert.notEqual(JSON.parse(b).enforcement, "LIMITED", `an enforce-mode alert stamped LIMITED: ${b}`);
  }
});

test("a tool call with no hook branch whose arguments are past --max-scan-chars: enforce refuses it, report forwards it and reports it unevaluated", async () => {
  // get_weather has no hook branch (model-proxy/check.mjs mapTool → null), so its argument JSON is
  // content-scanned; past the cap that scan would read only a prefix.
  const LONG = { name: "get_weather", input: { city: "Paris", notes: FILLER.repeat(120) } };
  const SHORT = { name: "get_weather", input: { city: "Paris" } };
  assert.ok(JSON.stringify(LONG.input).length > 2000 && JSON.stringify(SHORT.input).length < 2000);
  const caps = ["--max-scan-chars", "2000"];
  const c2 = await startConsole();
  const he = sandbox(), hr = sandbox();
  const envOf = (t) => ({ MOORAI_SERVER_URL: c2.url, MOORAI_INSTALL_TOKEN: t });
  let enf, rep;
  try {
    enf = await startProxy(he, ["--mode", "enforce", "--route", `/anthropic=${fp.url}`, "--route", `/openai=${fp.url}/v1`, ...caps], envOf("tok-model-proxy-enforce-2"));
    rep = await startProxy(hr, ["--route", `/anthropic=${fp.url}`, "--route", `/openai=${fp.url}/v1`, ...caps], envOf("tok-model-proxy-enforce-3"));
    for (const [name, api] of Object.entries(APIS)) {
      const go = (p, stream) => request(p.listening, api.path, { body: api.body(stream), headers: api.headers });
      // enforce, non-streaming: refused, content-free
      fp.on((r, res) => sendJson(res, api.json([LONG])));
      const e = await go(enf, false);
      assert.equal(e.status, 403, `${name}: enforce forwarded arguments it read only part of`);
      const ej = api.refusalJson(e.json);
      assert.equal(ej.code, PROVIDER_CODE[name]);
      assert.match(ej.message, /tool call get_weather: not evaluated: over the 2000-character scan cap/);
      assertContentFree(e.raw.toString(), ["Paris"]);
      // enforce, streaming: the stream ends in the error, the call never released
      const events = api.stream([LONG]);
      fp.on((r, res) => sendSse(res, events, { slice: 512 }));
      const es = await go(enf, true);
      for (const m of [...api.toolMarkers, "lorem"]) assert.ok(!es.raw.includes(m), `${name}: ${m} was sent`);
      assert.match(api.streamRefusal(sseEvents(es.raw)).message, /tool call get_weather: not evaluated: over the 2000-character scan cap/);
      // enforce, under the cap: allowed
      let sent;
      fp.on((r, res) => { sent = sendJson(res, api.json([SHORT])); });
      const ok = await go(enf, false);
      assert.equal(ok.status, 200); assert.ok(ok.raw.equals(sent));
      // report: forwarded byte-identical
      fp.on((r, res) => { sent = sendJson(res, api.json([LONG])); });
      const r = await go(rep, false);
      assert.equal(r.status, 200); assert.ok(r.raw.equals(sent), `${name}: report mode changed the response`);
    }
    // Reported unevaluated (response direction), once per label per process, by both proxies.
    const unev = () => c2.parsed().filter((x) => x.reasonCode === "UNEVALUATED_SIZE_CAP" && x.tool === "model-proxy:get_weather");
    assert.ok(await waitFor(() => unev().length >= 2), JSON.stringify(c2.parsed().map((x) => [x.tool, x.reasonCode])));
    for (const x of unev()) { assert.equal(x.enforcement, "UNEVALUATED"); assert.equal(x.stage, "tool"); assert.equal(x.surface, "model-proxy"); }
    for (const b of c2.alerts) assertContentFree(b, ["Paris"]);
  } finally { await enf?.stop(); await rep?.stop(); await c2.close(); rmTree(he); rmTree(hr); }
});
