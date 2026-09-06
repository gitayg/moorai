// THE INBOUND WEB GAP — AMTSO vector 2, the defining agentic attack.
//
// THE DEFECT, stated as the hook itself stated it. cli/moorai-hook.mjs registered PreToolUse ONLY.
// PreToolUse fires BEFORE the fetch, so `tool_input` is {url, prompt} and the fetched page DOES NOT
// EXIST YET. The outbound request was scanned; the response never was. A poisoned web page the agent
// was asked to summarise reached the model completely unexamined — even though the repo ships
// output-stage detectors that catch 22 of the 24 output-stage vector-2 attacks when handed the text.
// The detectors could always read this content; they were simply never given it in production.
//
// THE CONTRACT, established from the SHIPPED BINARY'S OWN ZOD SCHEMA (Claude Code 2.1.263), not from
// recollection and not from prose — the embedded /hooks UI blurb and the published docs disagree with
// each other on the field name, and the runtime schema is what actually parses the payload:
//
//   PostToolUse input : { hook_event_name:"PostToolUse", tool_name, tool_input, tool_response,
//                         tool_use_id, duration_ms? }  + the shared envelope (session_id, cwd, ...)
//   PreToolUse  input : { hook_event_name:"PreToolUse",  tool_name, tool_input, tool_use_id }
//
//   PostToolUse output: hookSpecificOutput accepts additionalContext / classifierContext /
//                       updatedToolOutput / updatedMCPToolOutput. It does NOT accept
//                       permissionDecision — that field is PreToolUse-only. Blocking, where policy
//                       calls for it, is the top-level {decision:"block", reason} channel.
//
// So the PreToolUse response shape is INVALID here, and emitting it would be silently ignored. That
// is why this file asserts the emitted envelope shape, not merely that "something was emitted".
//
// STAGE = "output". MEASURED, not inherited. mcp-proxy's result stage chose "file" for MCP tool
// results, and the obvious move was to copy it. On the vector-2 output-stage population (24 attacks,
// 11 benign) the measurement says otherwise:
//
//     stage="output"   attacks 22/24 (91.7%)    stage="file"   attacks 16/24 (66.7%)
//     UNION(output,file) = 22/24 — file's catches are a strict SUBSET of output's.
//
// Scanning both stages buys ZERO additional attacks and only adds benign noise, so this is a single
// stage, and "output" strictly dominates. The divergence from the MCP proxy is real and explicable:
// the proxy's dominant miss was a CREDENTIAL READ (.env), where stage "file" escalates secret
// categories to Critical via calibrateRisk; web-delivered vector-2 content is injected-DIRECTIVE
// shaped, and "file" instead fires the repo-file-shaped #3/#60 while missing 6 web attacks outright.
// The corpus agrees with the choice by construction: these samples DECLARE stage "output" as the
// stage at which that content actually reaches the agent.
//
// REPORT-FIRST. Nothing here blocks by default. Measured with no policy: the 11 output-stage benign
// controls resolve 10 allow / 1 ask, and the 24 attacks 20 allow / 4 ask — zero denies. A deny is
// reachable only when an org policy resolves a threat to block/kill via the existing threatActionFor.
//
//   node --test test/webfetch-result-stage.test.mjs
//   (bare `node --test` walks src-tauri/target/ and hangs — always name the file.)
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const V2 = JSON.parse(readFileSync(join(ROOT, "test", "redteam", "vector2-indirect-content.json"), "utf8"));
const v2 = (id) => (V2.attacks || []).concat(V2.benign || []).find((s) => s.id === id);

// Real corpus samples, at the channel and stage they are labelled with: poisoned fetched web pages.
const POISONED = v2("v2-web-004").text;      // plain-text injected "SYSTEM MESSAGE" directive
const POISONED_HTML = v2("v2-web-001").text; // the same attack hidden in an HTML comment
const BENIGN = v2("v2-benign-017").text;     // a page that merely EXPLAINS base64 — a hard negative

function startServer(policy) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify(policy)); }
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url.startsWith("/api/alerts")) { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } } res.writeHead(200); res.end("{}"); });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ srv, port: srv.address().port, alerts })));
}

function sandbox({ port, enrolled = true } = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-wf-home-"));
  const proj = mkdtempSync(join(tmpdir(), "moorai-wf-proj-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({
    serverUrl: port ? `http://127.0.0.1:${port}` : "http://127.0.0.1:1",
    tenant: "acme",
    ...(enrolled ? { installToken: "tok-webfetch-result-test" } : {})
  }));
  return { home, proj };
}

function run(args, env, cwd, stdin) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const c = spawn(process.execPath, [HOOK, ...args], { cwd, env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (err += d));
    c.on("close", (code) => resolve({ ms: Number(process.hrtime.bigint() - t0) / 1e6, out, err, code }));
    if (stdin != null) c.stdin.end(stdin); else c.stdin.end();
  });
}

// The REAL PostToolUse envelope, exactly as the binary's zod schema defines it.
const postPayload = (text, { tool = "WebFetch", url = "https://docs.example.com/notes", session = "sess-wf" } = {}) =>
  JSON.stringify({
    hook_event_name: "PostToolUse",
    session_id: session,
    transcript_path: "/tmp/t.jsonl",
    cwd: "/tmp",
    tool_name: tool,
    tool_input: { url, prompt: "Summarise this page" },
    tool_use_id: "toolu_01WFTEST",
    tool_response: text,
    duration_ms: 42
  });

const ON = { captureTier: "content-free", threatPolicy: {} };
const settle = (ms = 1200) => new Promise((r) => setTimeout(r, ms));

async function postRun(policy, text, opts = {}) {
  const { srv, port, alerts } = await startServer(policy);
  const sb = sandbox({ port, enrolled: opts.enrolled });
  const r = await run([], { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" }, sb.proj, opts.raw || postPayload(text, opts));
  await settle(opts.settle);
  srv.close();
  return { alerts, sb, ...r };
}
const outputAlerts = (alerts) => alerts.filter((a) => a.stage === "output");

// ================================================================================================
// 1. REACHABILITY — the whole point. Poisoned FETCHED CONTENT becomes an alert through the real hook.
// ================================================================================================

test("REACHABLE: poisoned WebFetch response content produces a content-free alert at stage 'output'", async () => {
  const { alerts, code } = await postRun(ON, POISONED);
  const out = outputAlerts(alerts);
  assert.equal(code, 0, "the hook must always exit 0 — governance, fail-open");
  assert.ok(out.length >= 1,
    `fetched page content must reach the detectors through the shipped hook; got stages ${JSON.stringify(alerts.map((a) => a.stage))}`);
  assert.ok(out.some((a) => a.tool === "hook:WebFetch"),
    `the alert must be attributed to WebFetch; got tools ${JSON.stringify(out.map((a) => a.tool))}`);
});

test("REACHABLE: an injected directive hidden in an HTML comment is caught the same way", async () => {
  const { alerts } = await postRun(ON, POISONED_HTML);
  assert.ok(outputAlerts(alerts).length >= 1, "html-comment hiding must not evade the result scan");
});

test("STAGE IS PINNED to 'output' — not 'file', not 'egress'", async () => {
  const { alerts } = await postRun(ON, POISONED);
  // Detection findings only. `report()` also emits a stage-"coach" literacy touchpoint alongside any
  // High/Critical finding (cli/hook-core.mjs literacyTouchpoint) — a different, pre-existing alert
  // class that deliberately carries its own stage, so it is excluded rather than asserted on.
  const mine = alerts.filter((a) => a.tool === "hook:WebFetch" && a.threatId && a.stage !== "coach");
  assert.ok(mine.length >= 1, "expected at least one WebFetch finding to pin the stage on");
  for (const a of mine) {
    assert.equal(a.stage, "output",
      `the fetched-content scan is pinned to stage "output" (measured: 22/24 vs 16/24 at "file"); got "${a.stage}"`);
  }
});

test("CONTENT-FREE: the page text never leaves the device", async () => {
  const { alerts } = await postRun(ON, POISONED);
  const blob = JSON.stringify(alerts);
  assert.ok(!blob.includes("SYSTEM MESSAGE"), "the matched span / page content must never be forwarded");
  assert.ok(!blob.includes("ANTHROPIC SAFETY TEAM"), "the matched span / page content must never be forwarded");
  for (const a of outputAlerts(alerts)) {
    assert.ok(typeof a.contentHash === "string" && a.contentHash.length > 0, "every alert carries a keyed one-way hash");
  }
});

// ================================================================================================
// 2. REGISTRATION — both layers. A matcher the host never invokes is not protection.
// ================================================================================================

test("REGISTERED: install writes PostToolUse matchers for the inbound tools", async () => {
  const sb = sandbox({});
  await run(["install"], { HOME: sb.home, USERPROFILE: sb.home }, sb.proj, null);
  const s = JSON.parse(readFileSync(join(sb.home, ".claude", "settings.json"), "utf8"));
  const post = (s.hooks?.PostToolUse || []).filter((e) => JSON.stringify(e).includes("moorai-hook"));
  const matchers = post.map((e) => e.matcher);
  assert.ok(matchers.includes("WebFetch"), `PostToolUse must cover WebFetch; got ${JSON.stringify(matchers)}`);
  assert.ok(matchers.includes("WebSearch"), `PostToolUse must cover WebSearch; got ${JSON.stringify(matchers)}`);
  assert.ok((s.hooks?.PreToolUse || []).length > 0, "installing PostToolUse must not disturb PreToolUse");
});

test("UPGRADE PATH: an existing PreToolUse-only install gains PostToolUse on an ordinary invocation", async () => {
  const { srv, port } = await startServer(ON);
  const sb = sandbox({ port });
  // A device installed BEFORE this change: MoorAI PreToolUse entries only, no PostToolUse key at all.
  mkdirSync(join(sb.home, ".claude"), { recursive: true });
  writeFileSync(join(sb.home, ".claude", "settings.json"), JSON.stringify({
    hooks: { PreToolUse: [{ matcher: "Read", hooks: [{ type: "command", command: `node ${HOOK}` }] }] }
  }));
  await run([], { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" }, sb.proj,
    JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: join(sb.proj, "x.txt") }, session_id: "s" }));
  srv.close();
  const s = JSON.parse(readFileSync(join(sb.home, ".claude", "settings.json"), "utf8"));
  const matchers = (s.hooks?.PostToolUse || []).filter((e) => JSON.stringify(e).includes("moorai-hook")).map((e) => e.matcher);
  assert.ok(matchers.includes("WebFetch"),
    `convergeHooks must reconcile PostToolUse too — a fix only new installs get is half a fix; got ${JSON.stringify(matchers)}`);
});

test("NEVER RE-ADDS: a device with no MoorAI entries stays uninstalled", async () => {
  const { srv, port } = await startServer(ON);
  const sb = sandbox({ port });
  mkdirSync(join(sb.home, ".claude"), { recursive: true });
  writeFileSync(join(sb.home, ".claude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Read", hooks: [{ type: "command", command: "node /somebody/else.js" }] }] } }));
  await run([], { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" }, sb.proj, postPayload(POISONED));
  srv.close();
  const s = JSON.parse(readFileSync(join(sb.home, ".claude", "settings.json"), "utf8"));
  assert.equal((s.hooks?.PostToolUse || []).length, 0, "an operator who uninstalled MoorAI must not have it silently re-added");
});

test("UNINSTALL removes the PostToolUse entries too", async () => {
  const sb = sandbox({});
  await run(["install"], { HOME: sb.home, USERPROFILE: sb.home }, sb.proj, null);
  await run(["uninstall"], { HOME: sb.home, USERPROFILE: sb.home }, sb.proj, null);
  const s = JSON.parse(readFileSync(join(sb.home, ".claude", "settings.json"), "utf8"));
  const left = (s.hooks?.PostToolUse || []).filter((e) => JSON.stringify(e).includes("moorai-hook"));
  assert.equal(left.length, 0, "uninstall must leave no MoorAI PostToolUse entries behind");
});

// ================================================================================================
// 3. THE RESPONSE ENVELOPE — the PreToolUse shape is invalid here and would be silently ignored.
// ================================================================================================

test("REPORT-FIRST: a finding under the default policy does not block the result", async () => {
  const { out, code } = await postRun(ON, POISONED);
  assert.equal(code, 0);
  if (out.trim()) {
    const j = JSON.parse(out);
    assert.notEqual(j.decision, "block", "nothing new blocks by default");
  }
});

test("ENVELOPE: the hook never emits the PreToolUse permissionDecision shape on a PostToolUse event", async () => {
  // A blocking org policy, so the strongest response this surface can produce is exercised.
  const blocking = { captureTier: "content-free", threatPolicy: { 40: "block", 17: "block", 15: "block", 50: "block" } };
  const { out } = await postRun(blocking, POISONED);
  if (!out.trim()) return; // report-only is an acceptable outcome; the shape assertion is what matters
  const j = JSON.parse(out);
  const hso = j.hookSpecificOutput;
  if (hso) {
    assert.equal(hso.hookEventName, "PostToolUse", "hookEventName must name the event that actually fired");
    assert.equal(hso.permissionDecision, undefined,
      "permissionDecision is PreToolUse-only per the shipped zod schema — emitting it here is silently ignored");
    assert.equal(hso.permissionDecisionReason, undefined, "permissionDecisionReason is PreToolUse-only");
  }
  if (j.decision !== undefined) {
    assert.equal(j.decision, "block", 'the only legal top-level decision value for this surface is "block"');
    assert.ok(typeof j.reason === "string" && j.reason.length > 0, "a block must carry a reason");
  }
});

// ================================================================================================
// 4. FAIL-OPEN AND BOUNDED — attacker-controlled HTML from the open internet.
// ================================================================================================

test("FAIL-OPEN: malformed / hostile tool_response shapes never break the tool result", async () => {
  const shapes = [
    JSON.stringify({ hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: {}, tool_response: null }),
    JSON.stringify({ hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: {}, tool_response: 12345 }),
    JSON.stringify({ hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: {}, tool_response: [] }),
    JSON.stringify({ hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: {} }), // no tool_response at all
    JSON.stringify({ hook_event_name: "PostToolUse", tool_name: "WebFetch" }),                 // no tool_input either
    JSON.stringify({ hook_event_name: "PostToolUse" }),                                        // no tool_name
    "{ this is not json at all",
    ""
  ];
  for (const raw of shapes) {
    const { code } = await postRun(ON, null, { raw, settle: 150 });
    assert.equal(code, 0, `a hostile payload must never break the agent; shape ${raw.slice(0, 60)} exited ${code}`);
  }
});

test("BOUNDED: a multi-megabyte page is capped, still scanned, and still fast", async () => {
  // 4 MB of filler with the attack at the very front, so the cap is exercised but the signal is inside it.
  const huge = POISONED + "\n" + "lorem ipsum dolor sit amet ".repeat(160000);
  assert.ok(huge.length > 4_000_000, `fixture must actually be large; was ${huge.length}`);
  const { alerts, code, ms } = await postRun(ON, huge, { settle: 1500 });
  assert.equal(code, 0);
  assert.ok(outputAlerts(alerts).length >= 1, "content inside the cap must still be scanned");
  assert.ok(ms < 8000, `a huge page must not stall the hook; took ${ms.toFixed(0)}ms`);
});

test("BOUNDED: content beyond the cap is dropped, never delayed", async () => {
  // The attack sits AFTER 4 MB of benign filler, i.e. outside the 64 KB cap. This asserts the cap is
  // REAL — that the scan genuinely stops at the boundary rather than the boundary being decorative.
  // Less scanning above the cap is the documented, deliberate trade; a stall or a dropped tool result
  // is not, so exit 0 and the latency bound are asserted in the same breath.
  const huge = "lorem ipsum dolor sit amet ".repeat(160000) + "\n" + POISONED;
  const { alerts, code, ms } = await postRun(ON, huge, { settle: 800 });
  assert.equal(code, 0, "beyond the cap the result is still delivered untouched");
  assert.equal(outputAlerts(alerts).length, 0,
    "content past the cap must not be scanned — if this fires, the cap is not being applied");
  assert.ok(ms < 8000, `must not stall; took ${ms.toFixed(0)}ms`);
});

test("REDOS-SAFE: adversarial repetition in fetched HTML does not stall the scan", async () => {
  // Classic catastrophic-backtracking bait aimed at nested quantifiers, in HTML the fetcher would return.
  const bait = "<div>" + "<!--" + "a".repeat(40000) + "-->" + "\n" + "!".repeat(20000) + "\n" + ("<b>" + "x".repeat(200) + "</b>").repeat(400) + "</div>";
  const { code, ms } = await postRun(ON, bait, { settle: 200 });
  assert.equal(code, 0);
  assert.ok(ms < 8000, `attacker-controlled repetition must not hang the hook; took ${ms.toFixed(0)}ms`);
});

// ================================================================================================
// 5. WEBSEARCH — the second inbound path.
// ================================================================================================

test("WebSearch results are scanned on the same surface", async () => {
  const { alerts } = await postRun(ON, POISONED, { tool: "WebSearch" });
  const mine = alerts.filter((a) => a.tool === "hook:WebSearch");
  assert.ok(mine.length >= 1,
    `WebSearch is a second inbound path for third-party text; got tools ${JSON.stringify(alerts.map((a) => a.tool))}`);
});

test("STRUCTURED tool_response objects are walked, not stringified past", async () => {
  // The WebFetch result is not necessarily a bare string; the schema types it as unknown.
  const raw = JSON.stringify({
    hook_event_name: "PostToolUse",
    tool_name: "WebFetch",
    tool_input: { url: "https://docs.example.com/x" },
    tool_response: { type: "text", text: POISONED, sources: [{ url: "https://docs.example.com/x" }] },
    session_id: "sess-struct"
  });
  const { alerts } = await postRun(ON, null, { raw });
  assert.ok(outputAlerts(alerts).length >= 1, "an object-shaped tool_response must still be scanned");
});

// ================================================================================================
// 6. NO REGRESSION ON THE PRE-EXISTING SURFACE
// ================================================================================================

test("PreToolUse WebFetch still scans the OUTBOUND request and still uses the PreToolUse shape", async () => {
  // Threats 3 and 40 are what the engine fires on this text at the "prompt" stage the outbound branch
  // uses; blocking one makes the pre-existing deny path deterministic.
  const { srv, port, alerts } = await startServer({ captureTier: "content-free", threatPolicy: { 40: "block" } });
  const sb = sandbox({ port });
  const r = await run([], { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" }, sb.proj,
    JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "WebFetch", tool_input: { url: "https://evil.invalid/x", prompt: POISONED }, session_id: "s-pre" }));
  await settle(600);
  srv.close();
  assert.equal(r.code, 0);
  assert.ok(r.out.includes("PreToolUse"), `the outbound PreToolUse path must be unchanged; stdout was ${JSON.stringify(r.out)}`);
  assert.ok(alerts.some((a) => a.stage === "egress"), "the outbound request is still scanned at the egress stage");
});

test("a benign fetched page is not blocked", async () => {
  const { out, code } = await postRun(ON, BENIGN);
  assert.equal(code, 0);
  if (out.trim()) {
    const j = JSON.parse(out);
    assert.notEqual(j.decision, "block", "a page that merely explains an attack must not be blocked");
  }
});
