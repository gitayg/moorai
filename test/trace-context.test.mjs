// W3C trace context (cli/trace-context.mjs) and the surfaces that use it without the hook: the allow-trail
// record (cli/action-trail.mjs), the OTLP export (cli/otel.mjs) and the egress proxy (egress-proxy/server.mjs).
//
//   node --test --import ./test/hermetic-env.mjs test/trace-context.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { traceIdFor, newTraceId, newSpanId, parseTraceparent, formatTraceparent, tracestateMoorai, mergeTracestate, continueOrStart, TRACE_LABEL } from "../cli/trace-context.mjs";
import { deriveKey, contentHash } from "../cli/content-hash.mjs";
import { buildActionRecord, RECORD_FIELDS } from "../cli/action-trail.mjs";
import { buildTracePayload } from "../cli/otel.mjs";
import { startUpstream, startEcho, fakeResolver, fakeConnect, startProxy, stateOf, viaProxy, connectVia } from "../egress-proxy/test/harness.mjs";

const TOKEN = "tok-trace-context";
const SID = "6257fe77-32be-41b0-a205-9712de862398";
const HEX32 = /^[0-9a-f]{32}$/, HEX16 = /^[0-9a-f]{16}$/;

test("traceIdFor: 32 hex, the same for the install token and its derived key, per session and per tenant", () => {
  const a = traceIdFor({ tenantKey: TOKEN, sessionKey: SID });
  assert.match(a, HEX32);
  assert.equal(traceIdFor({ tenantKey: TOKEN, sessionKey: SID }), a, "deterministic");
  assert.equal(traceIdFor({ tenantKey: deriveKey(TOKEN), sessionKey: SID }), a, "the derived key gives the same id");
  assert.notEqual(traceIdFor({ tenantKey: TOKEN, sessionKey: `${SID}x` }), a, "another session, another trace");
  assert.notEqual(traceIdFor({ tenantKey: "tok-other-tenant", sessionKey: SID }), a, "another tenant, another trace");
  assert.ok(!a.includes(SID.replace(/-/g, "").slice(0, 12)), "not the raw session id");
  // Not the content hash of the session id either: a trace id is its own derivation (TRACE_LABEL).
  assert.ok(!a.startsWith(contentHash(SID).slice(3)), "domain-separated from contentHash");
  assert.equal(TRACE_LABEL, "moorai/trace-id/v1");
});

test("traceIdFor: no tenant key or no session id gives null (the caller starts a random trace)", () => {
  for (const tenantKey of [undefined, null, "", Buffer.alloc(0)]) assert.equal(traceIdFor({ tenantKey, sessionKey: SID }), null);
  for (const sessionKey of [undefined, null, "", 42]) assert.equal(traceIdFor({ tenantKey: TOKEN, sessionKey }), null);
});

test("traceIdFor: deterministic across processes", async () => {
  const { execFileSync } = await import("node:child_process");
  const src = `import { traceIdFor } from ${JSON.stringify(new URL("../cli/trace-context.mjs", import.meta.url).href)}; process.stdout.write(traceIdFor({ tenantKey: ${JSON.stringify(TOKEN)}, sessionKey: ${JSON.stringify(SID)} }));`;
  const out = execFileSync(process.execPath, ["--input-type=module", "-e", src], { encoding: "utf8" });
  assert.equal(out, traceIdFor({ tenantKey: TOKEN, sessionKey: SID }));
});

test("newTraceId / newSpanId: random lowercase hex of the W3C lengths", () => {
  const t = new Set(), s = new Set();
  for (let i = 0; i < 64; i++) { const a = newTraceId(), b = newSpanId(); assert.match(a, HEX32); assert.match(b, HEX16); t.add(a); s.add(b); }
  assert.equal(t.size, 64); assert.equal(s.size, 64);
});

test("parseTraceparent: version 00 is exact", () => {
  const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
  assert.deepEqual(parseTraceparent(tp), { traceId: "4bf92f3577b34da6a3ce929d0e0e4736", parentSpanId: "00f067aa0ba902b7", flags: 1, sampled: true });
  assert.deepEqual(parseTraceparent(` ${tp.slice(0, -2)}00 `), { traceId: "4bf92f3577b34da6a3ce929d0e0e4736", parentSpanId: "00f067aa0ba902b7", flags: 0, sampled: false });
  for (const bad of [
    "00-00000000000000000000000000000000-00f067aa0ba902b7-01", // all-zero trace id
    "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", // all-zero span id
    "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", // uppercase
    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
    "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
    `${tp}, ${tp}`, "", null, undefined, 7, [tp]
  ]) assert.equal(parseTraceparent(bad), null, String(bad));
});

// W3C Trace Context §3.2.4: "If a higher version is detected, the implementation SHOULD try to parse it"
// by the 00 layout: at least 55 characters, the 2 flag characters followed by the end or a dash.
test("parseTraceparent: a version above 00 is read by the 00 layout (W3C 3.2.4); ff and malformed versions are not", () => {
  const T = "4bf92f3577b34da6a3ce929d0e0e4736", S = "00f067aa0ba902b7";
  for (const v of ["01", "cc", "fe"]) {
    assert.deepEqual(parseTraceparent(`${v}-${T}-${S}-01`), { traceId: T, parentSpanId: S, flags: 1, sampled: true }, v);
    assert.deepEqual(parseTraceparent(`${v}-${T}-${S}-00-what-the-future-will-be-like`), { traceId: T, parentSpanId: S, flags: 0, sampled: false }, v);
  }
  for (const bad of [
    `cc-${T}-${S}-01.what-the-future-will-be-like`, // the flags not followed by the end or a dash
    `cc-${T}-${S}-0`,                                // shorter than 55 characters
    `cc-${T}-${S}-0g`,                               // flags not hex
    `cc-${T}x${S}-01`, `cc-${T}-${S}x01`,            // a field not followed by a dash
    `cc-${"0".repeat(32)}-${S}-01`, `cc-${T}-${"0".repeat(16)}-01`,
    `cc-${T.toUpperCase()}-${S}-01`,
    `ff-${T}-${S}-01-future`, `CC-${T}-${S}-01`, `0g-${T}-${S}-01`, `c-${T}-${S}-01`, `ccc-${T}-${S}-01`,
    `cc-${T}-${S}-01, cc-${T}-${S}-01`              // two headers joined
  ]) assert.equal(parseTraceparent(bad), null, bad);
  // Optional whitespace around the value is spaces and tabs only.
  assert.equal(parseTraceparent(`\t00-${T}-${S}-01 `).traceId, T);
  assert.equal(parseTraceparent(`00-${T}-${S}-01\n`), null);
  // A continued higher-version trace goes on as version 00 with the incoming tracestate merged.
  const c = continueOrStart({ traceparent: `cc-${T}-${S}-01-future`, tracestate: "rojo=1", agentName: "gateway" });
  assert.deepEqual([c.traceId, c.parentSpanId, c.traceparent, c.tracestate], [T, S, `00-${T}-${c.spanId}-01`, "moorai=a:gateway,rojo=1"]);
});

test("formatTraceparent: the W3C form, or null for an id that is not one", () => {
  assert.equal(formatTraceparent({ traceId: "4bf92f3577b34da6a3ce929d0e0e4736", spanId: "00f067aa0ba902b7", sampled: true }), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
  assert.equal(formatTraceparent({ traceId: "4bf92f3577b34da6a3ce929d0e0e4736", spanId: "00f067aa0ba902b7", sampled: false }), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00");
  assert.equal(formatTraceparent({ traceId: "0".repeat(32), spanId: "00f067aa0ba902b7" }), null);
  assert.equal(formatTraceparent({ traceId: "4bf92f3577b34da6a3ce929d0e0e4736", spanId: "XYZ" }), null);
});

test("tracestateMoorai: only an agent name from the console's vocabulary", () => {
  assert.equal(tracestateMoorai({ agentName: "claude-code" }), "moorai=a:claude-code");
  assert.equal(tracestateMoorai({ agentName: "model-proxy" }), "moorai=a:model-proxy");
  for (const bad of ["", "egress-proxy", "claude code", "a=b", "x,y", undefined]) assert.equal(tracestateMoorai({ agentName: bad }), null, String(bad));
});

test("mergeTracestate: ours to the front, the others kept in order, a stale moorai entry replaced, a header that is not a valid list discarded, at most 32", () => {
  assert.equal(mergeTracestate("rojo=00f067aa0ba902b7,congo=t61rcWkgMzE", "moorai=a:claude-code"), "moorai=a:claude-code,rojo=00f067aa0ba902b7,congo=t61rcWkgMzE");
  assert.equal(mergeTracestate("rojo=1, moorai=a:codex ,congo=2", "moorai=a:claude-code"), "moorai=a:claude-code,rojo=1,congo=2");
  assert.equal(mergeTracestate(["rojo=1", "congo=2"], "moorai=a:gateway"), "moorai=a:gateway,rojo=1,congo=2", "repeated headers are one list");
  assert.equal(mergeTracestate("Bad=1,ok=2,=3,x=,dup=1,dup=2,t@sys=v", "moorai=a:serve"), "moorai=a:serve", "a header with an invalid member is discarded whole");
  const many = Array.from({ length: 40 }, (_, i) => `k${i}=v${i}`).join(",");
  assert.equal(mergeTracestate(many, "moorai=a:serve"), "moorai=a:serve", "more than 32 list-members is not a valid list");
  assert.equal(mergeTracestate("rojo=1", null), "rojo=1");
  assert.equal(mergeTracestate("", null), null);
});

// W3C Trace Context §3.3.1: list-member grammar, at most 32 list-members, empty and whitespace-only members
// allowed; §4.3: "If the tracestate header cannot be parsed the vendor MAY discard the entire header";
// §3.3.1.5: truncation removes whole entries, those over 128 characters first, then from the end.
test("mergeTracestate: W3C list-member grammar, empty members, duplicates, the 32-member limit and where to drop", () => {
  const O = "moorai=a:gateway";
  // Empty and whitespace-only members, and spaces / tabs around a member, are ignored.
  assert.equal(mergeTracestate(" a=1 ,\t, ,b=2\t,", O), `${O},a=1,b=2`);
  assert.equal(mergeTracestate(" ,\t", O), O);
  assert.equal(mergeTracestate("a=b c", O), `${O},a=b c`, "a space inside a value is allowed");
  // Every one of these is not a valid list-member, and its header is discarded whole.
  const k256 = "z".repeat(256), t241 = "t".repeat(241), v256 = "v".repeat(256);
  for (const bad of [
    "foo=,bar=3", "foo=bar=baz,bar=3", "FOO=1,bar=3", "foo.bar=1,bar=3", "foo =1,bar=3", "@foo=1,bar=3", "foo@=1,bar=3",
    "foo@@bar=1,bar=3", "foo@bar@baz=1,bar=3", `${"z".repeat(257)}=1,bar=3`, `${"t".repeat(242)}@v=1,bar=3`, `t@${"v".repeat(15)}=1,bar=3`,
    `t@1v=1,bar=3`, `foo=${v256}x,bar=3`, "foo=a\tb,bar=3", "foo=a\nb,bar=3", "foo=\u00e9,bar=3", "foo,bar=3", "bar=3,=1",
    "foo=1\n,bar=3", "\rfoo=1,bar=3", "\u00a0foo=1,bar=3" // only spaces and tabs around a member are ignored
  ]) assert.equal(mergeTracestate(bad, O), O, JSON.stringify(bad));
  // The longest valid keys and values are kept.
  for (const ok of [`${k256}=1`, `${t241}@${"s".repeat(14)}=1`, `${"t".repeat(242)}@v`.slice(1) + "=1", `0tenant@sys=1`, `a_-*/9=1`, `foo=${v256}`, "foo=!~"]) {
    assert.equal(mergeTracestate(`${ok},bar=3`, O), `${O},${ok},bar=3`, ok.slice(0, 40));
  }
  // One entry per key: a repeated key keeps its first (left-most, most recent) entry.
  assert.equal(mergeTracestate("foo=1,bar=2,foo=3", O), `${O},foo=1,bar=2`);
  assert.equal(mergeTracestate(["foo=1", "foo=2"], O), `${O},foo=1`);
  // 32 members are a valid list; ours added makes 33, so one goes: the right-most.
  const m32 = Array.from({ length: 32 }, (_, i) => `k${i}=v${i}`);
  assert.deepEqual(mergeTracestate(m32.join(","), O).split(","), [O, ...m32.slice(0, 31)]);
  // ... unless an entry is over 128 characters: that one goes first.
  const long = `big=${"x".repeat(125)}`;
  const withLong = [...m32.slice(0, 5), long, ...m32.slice(6)];
  assert.deepEqual(mergeTracestate(withLong.join(","), O).split(","), [O, ...m32.slice(0, 5), ...m32.slice(6)]);
  assert.equal(`big=${"x".repeat(124)}`.length, 128);
  const at128 = [...m32.slice(0, 5), `big=${"x".repeat(124)}`, ...m32.slice(6)];
  assert.deepEqual(mergeTracestate(at128.join(","), O).split(","), [O, ...at128.slice(0, 31)], "128 characters is not over 128");
  // A 32-member list that already holds our key: replaced in place at the front, nothing dropped.
  const own32 = [...m32.slice(0, 10), "moorai=a:old", ...m32.slice(11)];
  assert.deepEqual(mergeTracestate(own32.join(","), O).split(","), [O, ...m32.slice(0, 10), ...m32.slice(11)]);
  // 33 members, empty ones not counted, is discarded; 32 plus empty ones is not.
  assert.equal(mergeTracestate([...m32, "k32=v32"].join(","), O), O);
  assert.deepEqual(mergeTracestate([...m32, "", " "].join(","), null).split(","), m32);
  // No entry of ours: the valid list goes on unchanged.
  assert.equal(mergeTracestate(m32.join(","), null), m32.join(","));
});

test("continueOrStart: a valid incoming traceparent is continued; else the session's trace; else a random one", () => {
  const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
  const c = continueOrStart({ traceparent: tp, tracestate: "rojo=1", traceId: "a".repeat(32), agentName: "model-proxy" });
  assert.equal(c.traceId, "4bf92f3577b34da6a3ce929d0e0e4736");
  assert.equal(c.parentSpanId, "00f067aa0ba902b7");
  assert.match(c.spanId, HEX16);
  assert.equal(c.traceparent, `00-4bf92f3577b34da6a3ce929d0e0e4736-${c.spanId}-00`, "the incoming sampled flag is kept");
  assert.equal(c.tracestate, "moorai=a:model-proxy,rojo=1");
  const s = continueOrStart({ traceparent: "garbage", tracestate: "rojo=1", traceId: "a".repeat(32), agentName: "model-proxy" });
  assert.equal(s.traceId, "a".repeat(32));
  assert.equal(s.parentSpanId, undefined);
  assert.equal(s.tracestate, "moorai=a:model-proxy", "an invalid traceparent's tracestate is not carried");
  const r = continueOrStart({});
  assert.match(r.traceId, HEX32);
  assert.equal(r.tracestate, undefined);
});

test("allow-trail record: trace ids are contract fields, hex only", () => {
  for (const k of ["traceId", "spanId", "parentSpanId"]) assert.ok(RECORD_FIELDS.includes(k), k);
  const r = buildActionRecord({ tool: "Bash", traceId: "4bf92f3577b34da6a3ce929d0e0e4736", spanId: "00f067aa0ba902b7", parentSpanId: "b7ad6b7169203331" });
  assert.equal(r.traceId, "4bf92f3577b34da6a3ce929d0e0e4736");
  assert.equal(r.spanId, "00f067aa0ba902b7");
  assert.equal(r.parentSpanId, "b7ad6b7169203331");
  const bad = buildActionRecord({ tool: "Bash", traceId: "/Users/alice/secret.txt", spanId: "0".repeat(16), parentSpanId: "ABCDEF0123456789" });
  for (const k of ["traceId", "spanId", "parentSpanId"]) assert.equal(bad[k], undefined, k);
});

test("OTLP export: a record's span takes the record's traceId, spanId and parentSpanId", () => {
  const traceId = "4bf92f3577b34da6a3ce929d0e0e4736", spanId = "00f067aa0ba902b7", parentSpanId = "b7ad6b7169203331";
  const span = buildTracePayload({ tool: "hook:Bash", category: "x", traceId, spanId, parentSpanId }).resourceSpans[0].scopeSpans[0].spans[0];
  assert.equal(span.traceId, traceId);
  assert.equal(span.spanId, spanId);
  assert.equal(span.parentSpanId, parentSpanId);
  const root = buildTracePayload({ tool: "hook:Bash", traceId, spanId }).resourceSpans[0].scopeSpans[0].spans[0];
  assert.equal(root.parentSpanId, undefined);
  const none = buildTracePayload({ tool: "inventory:local-model" }).resourceSpans[0].scopeSpans[0].spans[0];
  assert.match(none.traceId, HEX32);
  assert.match(none.spanId, HEX16);
  assert.equal(none.parentSpanId, undefined);
  const junk = buildTracePayload({ tool: "x", traceId: "nope", spanId: "nope", parentSpanId: parentSpanId }).resourceSpans[0].scopeSpans[0].spans[0];
  assert.match(junk.traceId, HEX32);
  assert.equal(junk.parentSpanId, undefined, "no parent under a trace id that is not the record's");
});

// ---- the egress proxy ----
const PUBLIC = "93.184.216.34";
let up, echo;
before(async () => { up = await startUpstream(); echo = await startEcho(); });
after(async () => { await up.close(); await echo.close(); });
async function proxyWith(policy) {
  const p = await startProxy({}, { getState: stateOf(policy), resolve: fakeResolver({ "api.example.com": [PUBLIC], "evil.example": [PUBLIC] }), connect: fakeConnect({ httpPort: up.port, echoPort: echo.port }) });
  return p;
}
const ALLOW = { egressRules: [{ id: "all", host: "api.example.com", port: 80, action: "allow" }], egressDefault: "block" };
const ALERT = { egressRules: [{ id: "watch", host: "api.example.com", port: 80, action: "alert" }], egressDefault: "block" };

test("egress proxy: a request with no traceparent goes upstream with a new sampled trace and no stale tracestate", async () => {
  const p = await proxyWith(ALLOW);
  try {
    const n = up.seen.length;
    const r = await viaProxy(p.port, "http://api.example.com/a", { headers: { tracestate: "rojo=1" } });
    assert.equal(r.status, 200);
    const h = up.seen[n].headers;
    const tp = parseTraceparent(h.traceparent);
    assert.ok(tp, `traceparent upstream: ${h.traceparent}`);
    assert.equal(tp.sampled, true);
    assert.equal(h.tracestate, undefined, "a tracestate without a valid traceparent is not forwarded");
  } finally { await p.close(); }
});

test("egress proxy: a valid incoming traceparent and its tracestate go upstream unchanged", async () => {
  const p = await proxyWith(ALLOW);
  try {
    const n = up.seen.length;
    const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
    const r = await viaProxy(p.port, "http://api.example.com/b", { headers: { traceparent: tp, tracestate: "moorai=a:claude-code,rojo=1" } });
    assert.equal(r.status, 200);
    assert.equal(up.seen[n].headers.traceparent, tp);
    assert.equal(up.seen[n].headers.tracestate, "moorai=a:claude-code,rojo=1");
  } finally { await p.close(); }
});

test("egress proxy: a higher-version traceparent (W3C 3.2.4) continues the trace and goes upstream unchanged with its tracestate", async () => {
  const p = await proxyWith(ALERT);
  try {
    const n = up.seen.length;
    const tp = "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-future";
    await viaProxy(p.port, "http://api.example.com/v", { headers: { traceparent: tp, tracestate: "rojo=1" } });
    assert.equal(up.seen[n].headers.traceparent, tp);
    assert.equal(up.seen[n].headers.tracestate, "rojo=1");
    const a = p.reports.at(-1);
    assert.equal(a.traceId, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert.equal(a.parentSpanId, "00f067aa0ba902b7");
  } finally { await p.close(); }
});

test("egress proxy: an invalid incoming traceparent is replaced with a new trace", async () => {
  const p = await proxyWith(ALLOW);
  try {
    const n = up.seen.length;
    await viaProxy(p.port, "http://api.example.com/c", { headers: { traceparent: "00-00000000000000000000000000000000-00f067aa0ba902b7-01", tracestate: "rojo=1" } });
    const tp = parseTraceparent(up.seen[n].headers.traceparent);
    assert.ok(tp && tp.traceId !== "0".repeat(32));
    assert.equal(up.seen[n].headers.tracestate, undefined);
  } finally { await p.close(); }
});

test("egress proxy: an alert about a request carries that request's trace; a block refuses with the trace too", async () => {
  const p = await proxyWith(ALERT);
  try {
    const n = up.seen.length;
    const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    await viaProxy(p.port, "http://api.example.com/d", { headers: { traceparent: tp } });
    const a = p.reports.at(-1);
    assert.ok(a, "the alert rule raised an alert");
    assert.equal(a.traceId, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert.equal(a.parentSpanId, "00f067aa0ba902b7");
    assert.match(a.spanId, HEX16);
    assert.equal(up.seen[n].headers.traceparent, tp);
    const b = await viaProxy(p.port, "http://evil.example/x");
    assert.equal(b.status, 403);
    const blk = p.reports.at(-1);
    assert.match(blk.traceId, HEX32);
    assert.match(blk.spanId, HEX16);
    assert.equal(blk.parentSpanId, undefined);
  } finally { await p.close(); }
});

test("egress proxy: a refused CONNECT's alert carries the CONNECT request's trace", async () => {
  const p = await proxyWith(ALLOW);
  try {
    const r = await connectVia(p.port, "evil.example:443", { traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" });
    assert.equal(r.status, 403);
    const a = p.reports.at(-1);
    assert.equal(a.traceId, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert.equal(a.parentSpanId, "00f067aa0ba902b7");
  } finally { await p.close(); }
});
