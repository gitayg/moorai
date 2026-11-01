// moorai-ingest --format quarry: each transcript file as one scan input for Cisco's Project Quarry
// (Apache-2.0, alpha; format pinned to commit eadc6e3, quarry/_version.py __version__ "0.1.0"): the
// OpenAI-shaped { "messages": [...] } object its scanner validates in quarry/safety/validator.py
// validate_conversation (:504) and bounds in quarry/types/context.py (:170-310, limits in
// quarry/safety/limits.py SafetyLimits).
//
// Two content levels:
//   free (default)  no prompt, file, code, argument or result text. Every message's content is "", except
//                   a tool response's, which is the JSON text of its output facts. Each call keeps its real
//                   tool name and position; its arguments are MoorAI facts only (FACT KEYS below).
//   full            the transcript text and the call's real input, plus the same facts. Written only to a
//                   local file or stdout; moorai-ingest refuses --report with --format quarry.
//
// FACT KEYS (in function.arguments; content-free at both levels):
//   moorai_stage            "pre"
//   moorai_tags             capability tags of the call (cli/tool-tags.mjs callTags: read-private, read, write,
//                           network, exec), as the live hook computes them
//   moorai_inferred_tags    the subset resting only on an MCP tool's name
//   moorai_replayed         false for a call MoorAI's replay does not judge (cli/ingest/replay.mjs unsupported)
//   moorai_decision         the replay's verdict for the call: allow | ask | deny | mask  (replayed calls only)
//   moorai_threats          threat ids the replay reported for the call, ascending        (replayed calls only)
//   moorai_findings         [{ threat, category, risk, stage }]                          (replayed calls only)
//   moorai_output_decision / moorai_output_threats   the replay's verdict on the call's result, where the
//                           hook scans results (PostToolUse surfaces)
//   moorai_input_omitted    full level only: "malformed" | "oversize" | "depth" when the real input is left out
// A free-level tool response's content: { moorai_stage: "output", moorai_replayed, moorai_error,
// moorai_decision?, moorai_threats? }.
//
// Never emitted, because Quarry rejects it: a duplicate tool-call id (validator.py:753), a tool response
// without an earlier call (:661, :665) or a second response to one call (:670), a key outside the OpenAI
// shape (:537, :589, :741, :763), an empty messages list (:558), arguments that are not a JSON object
// (:326) or nest deeper than max_nesting_depth (:375, limits.py:55), or input over a SafetyLimits bound.
// Over-limit input is rejected, never reshaped, by Quarry (limits.py:66-69, context.py:171-176), so the
// export cuts the session's tail and counts it instead.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { callTags } from "../tool-tags.mjs";
import { sessionKeyedHash } from "../session-state.mjs";
import { fileFingerprint, FP_PREFIX } from "../content-hash.mjs";
import { TRACES } from "./quarry-trace.mjs";

export const QUARRY_PIN = Object.freeze({ commit: "eadc6e3", version: "0.1.0" });

export const QUARRY_LIMITS = Object.freeze({
  maxMessages: 10000,          // limits.py:42 max_messages, context.py:221
  maxMessageBytes: 10000000,   // limits.py:49 max_message_size (serialized content), context.py:249-254
  maxArgumentBytes: 1000000,   // limits.py:50 max_tool_argument_size (UTF-8 bytes), context.py:283-288
  maxToolCalls: 1000,          // limits.py:51 max_tool_calls (assistant calls), context.py:271
  maxNestingDepth: 100,        // limits.py:55 max_nesting_depth, validator.py:341-385
  maxTimelineItems: 10000,     // limits.py:57 max_timeline_items: messages + calls, context.py:60-69, 299-307
  // limits.py:56 max_total_size is 50 MB of PYTHON OBJECT footprint, which context.py:209-213 puts at
  // "roughly 5-12x its JSON size" for many small messages: 4 MB of JSON stays under it at 12x.
  maxJsonBytes: 4000000
});

// Per-text cap at the full level (each message, each string in a call's input), the hook's own file scan
// cap (cli/ingest/replay.mjs FILE_CAP), so one large read cannot use the session's whole budget.
export const TEXT_CAP = 262144;

const bytes = (s) => Buffer.byteLength(s, "utf8");
const wellFormed = (s) => (typeof s.toWellFormed === "function" ? s.toWellFormed() : s);

export function capText(s, n = TEXT_CAP) {
  const t = wellFormed(String(s));
  if (bytes(t) <= n) return { text: t, cut: false };
  return { text: Buffer.from(t, "utf8").subarray(0, n).toString("utf8").replace(/�$/, ""), cut: true };
}

// Container depth with the root object at 1, as validator.py:341 counts it.
function depthOf(v) {
  let max = 0;
  const stack = [[v, 1]];
  while (stack.length) {
    const [x, d] = stack.pop();
    if (!x || typeof x !== "object") continue;
    if (d > max) max = d;
    for (const c of Array.isArray(x) ? x : Object.values(x)) if (c && typeof c === "object") stack.push([c, d + 1]);
  }
  return max;
}

function capValue(v, notes) {
  if (typeof v === "string") { const c = capText(v); if (c.cut) notes.textsTruncated++; return c.text; }
  if (Array.isArray(v)) return v.map((x) => capValue(x, notes));
  if (v && typeof v === "object") { const o = {}; for (const [k, x] of Object.entries(v)) o[wellFormed(k)] = capValue(x, notes); return o; }
  return v;
}

const threatIds = (findings) => [...new Set((findings || []).map((f) => f.threatId).filter((n) => Number.isInteger(n)))].sort((a, b) => a - b);
const findingFacts = (findings) => (findings || []).map((f) => ({ threat: Number.isInteger(f.threatId) ? f.threatId : 0, category: String(f.category || ""), risk: String(f.riskLevel || ""), stage: String(f.stage || "") }));

function tagsFor(call, j) {
  const inputs = j && j.ev ? (Array.isArray(j.ev.input) ? j.ev.input : [j.ev.input]) : [{ tool_name: call.name, tool_input: call.input || {} }];
  const fileIds = j && j.pre ? j.pre.findings.filter((f) => f.stage === "file").map((f) => f.threatId) : [];
  const tags = new Set(), inferred = new Set();
  for (const i of inputs) {
    if (!i || typeof i !== "object") continue;
    const t = callTags({ tool: i.tool_name || "", toolInput: i.tool_input, cwd: i.cwd || "", findingIds: fileIds });
    for (const x of t.tags) tags.add(x);
    for (const x of t.inferred) inferred.add(x);
  }
  const order = ["read-private", "read", "write", "network", "exec"];
  return { tags: order.filter((x) => tags.has(x)), inferred: order.filter((x) => inferred.has(x)) };
}

export function callFacts(call, j) {
  const { tags, inferred } = tagsFor(call, j);
  const f = { moorai_stage: "pre", moorai_tags: tags, moorai_inferred_tags: inferred, moorai_replayed: false };
  if (j && j.pre && !j.pre.unsupported) {
    f.moorai_replayed = true;
    f.moorai_decision = j.pre.decision;
    f.moorai_threats = threatIds(j.pre.findings);
    f.moorai_findings = findingFacts(j.pre.findings);
  }
  if (j && j.post) { f.moorai_output_decision = j.post.decision; f.moorai_output_threats = threatIds(j.post.findings); }
  return f;
}

export function outputFacts(j, isError) {
  const f = { moorai_stage: "output", moorai_replayed: !!(j && j.post), moorai_error: !!isError };
  if (j && j.post) { f.moorai_decision = j.post.decision; f.moorai_threats = threatIds(j.post.findings); }
  return f;
}

function argumentsFor(call, j, full, notes) {
  const facts = callFacts(call, j);
  if (!full) return JSON.stringify(facts);
  if (!call.input) { notes.inputsOmitted++; return JSON.stringify({ ...facts, moorai_input_omitted: "malformed" }); }
  const args = { ...capValue(call.input, notes), ...facts };
  if (depthOf(args) > QUARRY_LIMITS.maxNestingDepth) { notes.inputsOmitted++; return JSON.stringify({ ...facts, moorai_input_omitted: "depth" }); }
  const s = JSON.stringify(args);
  if (bytes(s) > QUARRY_LIMITS.maxArgumentBytes) { notes.inputsOmitted++; return JSON.stringify({ ...facts, moorai_input_omitted: "oversize" }); }
  return s;
}

export const emptyNotes = () => ({ itemsDropped: 0, orphanResults: 0, duplicateCalls: 0, duplicateResults: 0, textsTruncated: 0, inputsOmitted: 0 });

// items (cli/ingest/quarry-trace.mjs) + joins (hostId → { ev, pre, post }) → { trace, notes, truncated }.
// trace is null when nothing is left to scan (Quarry rejects an empty messages list).
export function buildTrace(items, joins, { content = "free", limits = QUARRY_LIMITS } = {}) {
  const full = content === "full";
  const notes = emptyNotes();
  const messages = [];
  const idOfHost = new Map(), idOfCall = new Map(), joinOf = new Map(), answered = new Set();
  let total = bytes('{"messages":[]}'), calls = 0, timeline = 0, n = 0, truncated = false;
  const text = (s) => {
    if (!full) return "";
    const c = capText(s);
    if (c.cut) notes.textsTruncated++;
    return c.text;
  };
  const fits = (msg, addCalls) => {
    const len = bytes(JSON.stringify(msg)) + 1;
    if (messages.length + 1 > limits.maxMessages || total + len > limits.maxJsonBytes || timeline + 1 + addCalls > limits.maxTimelineItems || calls + addCalls > limits.maxToolCalls) return false;
    total += len; timeline += 1 + addCalls; calls += addCalls;
    return true;
  };
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    if (it.role === "user") {
      const msg = { role: "user", content: text(it.text) };
      if (!fits(msg, 0)) { truncated = true; notes.itemsDropped += items.length - i; break; }
      messages.push(msg);
      continue;
    }
    if (it.role === "assistant") {
      const tool_calls = [], pending = [];
      for (const c of it.calls) {
        if (c.hostId && idOfHost.has(c.hostId)) { notes.duplicateCalls++; continue; }
        const id = `call_${++n}`;
        const j = c.hostId ? joins.get(c.hostId) : undefined;
        tool_calls.push({ id, type: "function", function: { name: wellFormed(c.name), arguments: argumentsFor(c, j, full, notes) } });
        pending.push([c, id, j]);
      }
      let msg = { role: "assistant", content: text(it.text), ...(tool_calls.length ? { tool_calls } : {}) };
      let kept = tool_calls.length, ok = fits(msg, kept);
      while (!ok && kept > 0) {
        kept--;
        msg = { role: "assistant", content: msg.content, ...(kept ? { tool_calls: tool_calls.slice(0, kept) } : {}) };
        ok = fits(msg, kept);
      }
      if (ok) { messages.push(msg); register(pending.slice(0, kept)); }
      if (!ok || kept < tool_calls.length) { truncated = true; notes.itemsDropped += items.length - i - (ok ? 1 : 0); break; }
      continue;
    }
    const id = it.call ? idOfCall.get(it.call) : it.hostId ? idOfHost.get(it.hostId) : undefined;
    if (!id) { notes.orphanResults++; continue; }
    if (answered.has(id)) { notes.duplicateResults++; continue; }
    const j = joinOf.get(id);
    const msg = { role: "tool", tool_call_id: id, content: full ? text(it.text) : JSON.stringify(outputFacts(j, it.isError)) };
    if (!fits(msg, 0)) { truncated = true; notes.itemsDropped += items.length - i; break; }
    answered.add(id);
    messages.push(msg);
  }
  function register(list) {
    for (const [c, id, j] of list) { if (c.hostId) idOfHost.set(c.hostId, id); idOfCall.set(c, id); joinOf.set(id, j); }
  }
  return { trace: messages.length ? { messages } : null, notes, truncated };
}

function traceName(agent, unitId) {
  const h = sessionKeyedHash(`quarry:${agent}:${unitId}`) || fileFingerprint(`quarry:${agent}:${unitId}`).slice(FP_PREFIX.length);
  return `${agent}-${h}`;
}

// The runIngest observer. out: a directory (one <agent>-<hash>.json per transcript file, mode 0600) or
// null for one JSON object per line on `stdout`.
export function createQuarryExport({ content = "free", out = null, stdout = process.stdout } = {}) {
  const stats = { traces: 0, empty: 0, truncated: 0, ...emptyNotes() };
  const files = new Map(), used = new Set();
  let cur = null;
  if (out) mkdirSync(out, { recursive: true, mode: 0o700 });
  const state = (f) => {
    let s = files.get(f);
    if (!s) { s = { trace: new (TRACES[f.agent] || TRACES["claude-code"])(), joins: new Map() }; files.set(f, s); }
    return s;
  };
  const observer = {
    // Files are read one at a time, and every verdict of a file arrives before its fileEnd.
    record(f, rec) { cur = state(f); cur.trace.push(rec); },
    verdict(ev, stage, v) {
      if (!cur || !ev.toolUseId) return;
      const j = cur.joins.get(ev.toolUseId) || {};
      j.ev = ev;
      j[stage] = v;
      cur.joins.set(ev.toolUseId, j);
    },
    fileEnd(f) {
      const s = files.get(f);
      files.delete(f);
      cur = null;
      if (!s) return;
      const items = s.trace.end();
      const { trace, notes, truncated } = buildTrace(items, s.joins, { content });
      for (const k of Object.keys(notes)) stats[k] += notes[k];
      if (!trace) { stats.empty++; return; }
      if (truncated) stats.truncated++;
      stats.traces++;
      const json = JSON.stringify(trace);
      if (!out) { stdout.write(json + "\n"); return; }
      const unit = s.trace.sessionId ? `${s.trace.sessionId}:${s.trace.agentId || ""}` : `path:${f.path}`;
      let name = traceName(f.agent, unit);
      for (let k = 2; used.has(name); k++) name = `${traceName(f.agent, unit)}-${k}`;
      used.add(name);
      writeFileSync(join(out, `${name}.json`), json + "\n", { mode: 0o600 });
    }
  };
  return { observer, stats };
}

export function statsText(stats, { content, out }) {
  const extra = [
    stats.empty && `${stats.empty} with nothing to scan`,
    stats.truncated && `${stats.truncated} cut at Quarry's input limits (${stats.itemsDropped} trailing message(s) dropped)`,
    stats.orphanResults && `${stats.orphanResults} result(s) without a recorded call skipped`,
    stats.duplicateCalls && `${stats.duplicateCalls} repeated call id(s) skipped`,
    stats.duplicateResults && `${stats.duplicateResults} repeated result(s) skipped`,
    stats.textsTruncated && `${stats.textsTruncated} text(s) cut to ${TEXT_CAP} bytes`,
    stats.inputsOmitted && `${stats.inputsOmitted} call input(s) left out`
  ].filter(Boolean);
  return `moorai-ingest: ${stats.traces} Quarry trace(s), content ${content}, written to ${out || "stdout"}${extra.length ? `; ${extra.join("; ")}` : ""}\n`;
}
