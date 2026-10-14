// The W3C trace context of a tools/call the stdio guard forwards, put where MCP carries it: the request's
// `params._meta.traceparent` and `params._meta.tracestate`. MCP 2026-07-28 (basic, "General fields: _meta")
// reserves exactly these keys "for OpenTelemetry trace context propagation", values in W3C Trace Context
// format; 2025-11-25 and earlier define no trace keys, and an unprefixed `_meta` key name is valid there.
//
// The line is EDITED IN PLACE, never re-serialized: every byte the client sent stays as it was except the
// two values set (or added) and, when no tracestate is sent, the client's tracestate member removed. So a
// number past 2^53, an escape, key order and whitespace reach the server exactly as the client wrote them,
// and the arguments the gate judged are the arguments the server reads.
//
// No edit (null: the caller forwards the line unchanged) when the line is not one JSON object with a
// single `params` object, when `params` has more than one `_meta`, when `_meta` is not an object, or when
// `_meta` repeats a trace key: a repeated key reads differently in different parsers, so no value set here
// could be the one the server takes.

const WS = new Set([" ", "\t", "\n", "\r"]);
function ws(s, i) { while (i < s.length && WS.has(s[i])) i++; return i; }
function endOfString(s, i) {
  for (let j = i + 1; j < s.length; j++) {
    if (s[j] === "\\") j++;
    else if (s[j] === "\"") return j + 1;
  }
  return -1;
}
// The end (exclusive) of the JSON value starting at i, or -1.
function endOfValue(s, i) {
  const c = s[i];
  if (c === "\"") return endOfString(s, i);
  if (c === "{" || c === "[") {
    let depth = 0;
    for (let j = i; j < s.length; j++) {
      const d = s[j];
      if (d === "\"") { j = endOfString(s, j) - 1; if (j < 0) return -1; }
      else if (d === "{" || d === "[") depth++;
      else if (d === "}" || d === "]") { depth--; if (depth === 0) return j + 1; }
    }
    return -1;
  }
  let j = i;
  while (j < s.length && !WS.has(s[j]) && s[j] !== "," && s[j] !== "}" && s[j] !== "]") j++;
  return j > i ? j : -1;
}
// The members of the object starting at `open` ("{"): [{ key, start, valStart, valEnd }], start being the
// key's opening quote; null when it does not read as an object.
function membersOf(s, open) {
  const out = [];
  let i = ws(s, open + 1);
  if (s[i] === "}") return out;
  for (;;) {
    if (s[i] !== "\"") return null;
    const ke = endOfString(s, i);
    if (ke < 0) return null;
    let key;
    try { key = JSON.parse(s.slice(i, ke)); } catch { return null; }
    let j = ws(s, ke);
    if (s[j] !== ":") return null;
    j = ws(s, j + 1);
    const ve = endOfValue(s, j);
    if (ve < 0) return null;
    out.push({ key, start: i, valStart: j, valEnd: ve });
    i = ws(s, ve);
    if (s[i] === "}") return out;
    if (s[i] !== ",") return null;
    i = ws(s, i + 1);
  }
}
const only = (members, key) => { const m = members.filter((x) => x.key === key); return m.length > 1 ? undefined : m[0] || null; };

// line: one JSON-RPC message (a tools/call). trace: { traceparent, tracestate } (tracestate "" = none).
// → the edited line, or null.
export function setMetaTrace(line, trace) {
  if (!trace || typeof trace.traceparent !== "string") return null;
  const top = ws(line, 0);
  if (line[top] !== "{") return null;
  const tm = membersOf(line, top);
  const params = tm && only(tm, "params");
  if (!params || line[params.valStart] !== "{") return null;
  const pm = membersOf(line, params.valStart);
  const meta = pm && only(pm, "_meta");
  if (!pm || meta === undefined) return null;
  const want = [["traceparent", trace.traceparent], ...(trace.tracestate ? [["tracestate", trace.tracestate]] : [])];
  const pair = ([k, v]) => `${JSON.stringify(k)}:${JSON.stringify(v)}`;
  const edits = [];
  if (!meta) {
    edits.push({ at: params.valStart + 1, end: params.valStart + 1, text: `"_meta":{${want.map(pair).join(",")}}${pm.length ? "," : ""}` });
  } else {
    if (line[meta.valStart] !== "{") return null;
    const mm = membersOf(line, meta.valStart);
    if (!mm) return null;
    const tp = only(mm, "traceparent"), ts = only(mm, "tracestate");
    if (tp === undefined || ts === undefined) return null;
    const add = [];
    for (const [k, v] of want) {
      const cur = k === "traceparent" ? tp : ts;
      if (cur) edits.push({ at: cur.valStart, end: cur.valEnd, text: JSON.stringify(v) });
      else add.push([k, v]);
    }
    // No tracestate to send (no moorai entry, and no valid traceparent to carry the client's on): the
    // client's member is removed with one of its separating commas.
    if (ts && !trace.tracestate) {
      const i = mm.indexOf(ts);
      if (i + 1 < mm.length) edits.push({ at: ts.start, end: mm[i + 1].start, text: "" });
      else if (i > 0) edits.push({ at: mm[i - 1].valEnd, end: ts.valEnd, text: "" });
      else edits.push({ at: ts.start, end: ts.valEnd, text: "" });
    }
    const remaining = mm.length - (ts && !trace.tracestate ? 1 : 0);
    if (add.length) edits.push({ at: meta.valStart + 1, end: meta.valStart + 1, text: `${add.map(pair).join(",")}${remaining ? "," : ""}` });
  }
  let out = line;
  // Right to left. At one offset the removal was pushed before the insertion, and the sort is stable.
  for (const e of edits.sort((a, b) => b.at - a.at)) out = out.slice(0, e.at) + e.text + out.slice(e.end);
  return out;
}
