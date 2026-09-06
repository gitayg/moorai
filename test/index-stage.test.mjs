// The THIRD dead detector stage: "index".
//
// THE FINDING. src/engine.js shipped `scanForIndex(text) { return this.scan(text, "index"); }` and
// NOTHING in the product called it. scripts/score-vectors.mjs recorded it verbatim —
// `{ reachable: false, via: "DetectionEngine.scanForIndex exists but no shipped caller" }` — and the
// vector-3 corpus carries 5 attacks + 2 benign samples at that stage which therefore measured a stage
// no deployment could ever reach. Three detectors declare it (inj-untrusted-directive,
// mcp-tool-poisoning, mcp-hidden-canary), so it was partially dead surface, not merely a dead method.
//
// WHAT THE STAGE IS FOR. The engine's own comment says "content headed for a local vector store / RAG
// index before it's embedded ... a future embedding writer". MoorAI has no embedding writer and no
// vector store (the only embeddings in the tree are src/semantic.js's escalation second opinion, which
// indexes nothing). But the stage's real meaning survives the missing feature: it is UNTRUSTED CONTENT
// THE AGENT INGESTS INTO ITS CONTEXT WITHOUT THE USER TYPING IT. In a coding agent that is the SKILL
// SURFACE — data/skill-surface.js's own section header calls it "instruction / memory files loaded into
// context at session start": CLAUDE.md, AGENTS.md, .mcp.json, .claude/settings.json, .cursorrules.
// The vector-3 index samples agree: their families are poisoned-autoload-config,
// malicious-tool-description and hidden-canary-in-metadata.
//
// THE GAP THAT MADE WIRING (NOT DELETION) THE RIGHT CALL. Those files are auto-loaded at session start
// with NO tool call, so the PreToolUse hook never sees them. Today they are scanned only if the agent
// happens to `Read` one. A poisoned CLAUDE.md steers every future prompt and was never screened.
//
// WHAT THIS PINS:
//   1. The index stage has a shipped caller: a poisoned auto-loaded context file becomes a
//      content-free alert at stage "index" on the normal PreToolUse path.
//   2. It goes through DetectionEngine.scanForIndex — the choke-point contract, not a `scan(t,"file")`
//      look-alike.
//   3. It is REPORT-ONLY and OUT-OF-BAND: the tool call's own verdict is unchanged and the hot path
//      does not wait for it (prior art: maybeAgentScan / maybeEscalate).
//   4. It is content-free (no matched span, no file content) at the default capture tier.
//   5. It is opt-out-able and fail-open (no policy → nothing happens, exit 0).
//   6. It does not re-alert on an unchanged file, and DOES re-alert when one is poisoned mid-session.
//
//   node --test test/index-stage.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DETECTORS } from "../data/detectors.js";
import { buildEngine } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const V3 = JSON.parse(readFileSync(join(ROOT, "test", "redteam", "vector3-supply-chain.json"), "utf8"));
const v3 = (id) => (V3.attacks || []).concat(V3.benign || []).find((s) => s.id === id);

// A real corpus sample, at the stage it is labelled with: a poisoned auto-load config.
const POISONED = v3("v3-cfg-013").text;
const BENIGN = v3("v3-benign-019").text;

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

// A throwaway HOME (state + config) and a separate throwaway PROJECT dir (the agent's cwd), so the
// scan looks at the sandbox's auto-loaded context files and never at the real repo's.
function sandbox({ port, claudeMd = null, mcpJson = null } = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-idx-home-"));
  const proj = mkdtempSync(join(tmpdir(), "moorai-idx-proj-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({
    serverUrl: port ? `http://127.0.0.1:${port}` : "http://127.0.0.1:1",
    tenant: "acme",
    installToken: "tok-index-stage-test"
  }));
  if (claudeMd != null) writeFileSync(join(proj, "CLAUDE.md"), claudeMd);
  if (mcpJson != null) writeFileSync(join(proj, ".mcp.json"), mcpJson);
  const file = join(proj, "sample.txt");
  writeFileSync(file, "hello world\n");
  return { home, proj, file };
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

const readPayload = (file, session = "sess-idx") => JSON.stringify({ tool_name: "Read", tool_input: { file_path: file }, session_id: session });
const ON = { captureTier: "content-free", threatPolicy: {} };
const settle = (ms = 2500) => new Promise((r) => setTimeout(r, ms));

// One PreToolUse run in a sandbox, waiting long enough for the detached ingest scan to POST.
async function hookRun(policy, opts = {}) {
  const { srv, port, alerts } = await startServer(policy);
  const sb = opts.sb || sandbox({ port, ...opts });
  const r = await run([], { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" }, sb.proj, readPayload(sb.file, opts.session));
  await settle(opts.settle);
  srv.close();
  return { alerts, sb, port, ...r };
}
const indexAlerts = (alerts) => alerts.filter((a) => a.stage === "index");

// ================================================================================================
// 1. THE STAGE HAS A SHIPPED CALLER
// ================================================================================================

test("WIRED: a poisoned auto-loaded CLAUDE.md becomes a content-free alert at stage 'index'", async () => {
  const { alerts } = await hookRun(ON, { claudeMd: POISONED });
  const idx = indexAlerts(alerts);
  assert.ok(idx.length >= 1,
    `the index stage must fire from the shipped PreToolUse path; got stages ${JSON.stringify(alerts.map((a) => a.stage))}`);
  assert.ok(idx.some((a) => [40, 50, 60].includes(a.threatId)),
    `the finding must come from an index-scoped detector; got threatIds ${JSON.stringify(idx.map((a) => a.threatId))}`);
});

test("WIRED: a poisoned .mcp.json is ingested content too", async () => {
  const { alerts } = await hookRun(ON, { mcpJson: POISONED });
  assert.ok(indexAlerts(alerts).length >= 1, "the .mcp.json auto-load path must be screened at the index stage");
});

test("a clean project produces NO index alert (the wiring is not fixed by always alerting)", async () => {
  const { alerts } = await hookRun(ON, { claudeMd: BENIGN });
  assert.equal(indexAlerts(alerts).length, 0,
    `a benign auto-load config must be silent; got ${JSON.stringify(indexAlerts(alerts).map((a) => a.threatId))}`);
});

// ================================================================================================
// 2. IT GOES THROUGH scanForIndex, AND scanForIndex COVERS THE CORPUS
// ================================================================================================

test("DetectionEngine.scanForIndex is the choke-point and covers the corpus index attacks", () => {
  const engine = buildEngine(null);
  const idxAttacks = (V3.attacks || []).filter((s) => s.stage === "index");
  assert.equal(idxAttacks.length, 5, "the corpus must still carry 5 index-stage attacks");
  const caught = idxAttacks.filter((s) => engine.scanForIndex(s.text).length > 0);
  assert.ok(caught.length >= 4, `scanForIndex must catch >= 4/5 index attacks; caught ${caught.length}`);
  // the three detectors that declare the stage are the ones that can fire there
  const scoped = DETECTORS.filter((d) => (d.stages || [d.stage]).includes("index")).map((d) => d.detectorId);
  assert.deepEqual(scoped.sort(), ["inj-untrusted-directive", "mcp-hidden-canary", "mcp-tool-poisoning"]);
});

// The headline number, pinned so it cannot rot: how many of the corpus's index-stage attacks are
// reachable THROUGH THE SHIPPED HOOK, not just through the library API. 4/5 — identical to the
// library ceiling above, i.e. ZERO wiring loss. (v3-delay-007 is a rules-level miss at both the index
// and the file stage and was one before this wiring; v3-benign-020 is a rules-level FP at both stages
// for the same reason. Neither is introduced here.)
test("E2E: 4 of the 5 corpus index-stage attacks are reachable through the shipped hook", async () => {
  const attacks = (V3.attacks || []).filter((s) => s.stage === "index");
  let reachable = 0;
  for (const s of attacks) {
    // Both genuine auto-load paths: a rules/memory file and an MCP server config.
    let hit = (await hookRun(ON, { claudeMd: s.text })).alerts.filter((a) => a.stage === "index").length;
    if (!hit) hit = (await hookRun(ON, { mcpJson: s.text })).alerts.filter((a) => a.stage === "index").length;
    if (hit) reachable++;
  }
  assert.equal(reachable, 4, `index-stage attacks reachable end-to-end: ${reachable}/${attacks.length}`);
});

// ================================================================================================
// 3. REPORT-ONLY AND OUT-OF-BAND
// ================================================================================================

test("the ingest scan never changes the tool call's verdict and never fails the hook", async () => {
  const { out, code, alerts } = await hookRun(ON, { claudeMd: POISONED });
  assert.equal(code, 0, "the hook must still exit 0");
  assert.equal(out, "", "a finding in an auto-loaded context file is advisory — it must not deny the Read");
  assert.ok(indexAlerts(alerts).length >= 1, "precondition: the scan did fire for this run");
});

test("the ingest scan is out-of-band — the hot path does not wait for it", async () => {
  // The parent process must return before the detached worker's POSTs land. Measured as: the hook's
  // own wall time is far below the settle window the alert needs.
  const { srv, port, alerts } = await startServer(ON);
  const sb = sandbox({ port, claudeMd: POISONED });
  const r = await run([], { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" }, sb.proj, readPayload(sb.file));
  const duringHook = indexAlerts(alerts).length;
  await settle();
  srv.close();
  assert.equal(duringHook, 0, "the index alert must NOT have been posted by the parent hook process");
  assert.ok(indexAlerts(alerts).length >= 1, "the detached worker must post it afterwards");
  assert.ok(r.ms < 8000, `hook wall time ${r.ms.toFixed(0)}ms`);
});

// ================================================================================================
// 4. CONTENT-FREE
// ================================================================================================

test("the index alert carries no matched span and no file content", async () => {
  const { alerts } = await hookRun(ON, { claudeMd: POISONED });
  const a = indexAlerts(alerts)[0];
  assert.ok(a, "precondition: an index alert was posted");
  const blob = JSON.stringify(a);
  assert.equal(a.matchText, undefined, "content-free tier must not carry the matched span");
  for (const word of ["exfiltrate", "credentials", ".env", "ignore"]) {
    assert.ok(!blob.toLowerCase().includes(word.toLowerCase()) || a.category.toLowerCase().includes(word.toLowerCase()),
      `the alert leaked payload text (${word}): ${blob}`);
  }
  assert.ok(typeof a.contentHash === "string" && a.contentHash.length > 0, "the alert must still carry a one-way hash");
});

// ================================================================================================
// 5. GATED / FAIL-OPEN
// ================================================================================================

test("policy.indexScan=false opts out", async () => {
  const { alerts } = await hookRun({ ...ON, indexScan: false }, { claudeMd: POISONED });
  assert.equal(indexAlerts(alerts).length, 0, "an operator must be able to turn the ingest scan off");
});

test("no policy at all -> nothing scanned, exit 0 (fail-open)", async () => {
  const sb = sandbox({ port: 0, claudeMd: POISONED }); // serverUrl points at a dead port
  const r = await run([], { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" }, sb.proj, readPayload(sb.file));
  assert.equal(r.code, 0);
  assert.equal(r.out, "");
});

// ================================================================================================
// 6. NO RE-ALERT STORM, BUT A MID-SESSION POISONING IS STILL SEEN
// ================================================================================================

test("an unchanged context file is not re-alerted, a changed one is", async () => {
  const { srv, port, alerts } = await startServer(ON);
  try {
    const sb = sandbox({ port, claudeMd: POISONED });
    const env = { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" };
    await run([], env, sb.proj, readPayload(sb.file));
    await settle();
    const first = indexAlerts(alerts).length;
    assert.ok(first >= 1, "precondition: the first run alerted");

    // Same file, second scan: the worker is invoked directly so the hot-path interval stamp is not
    // what is under test here — the fingerprint memory is.
    await run(["indexscan"], env, sb.proj, null);
    await settle();
    assert.equal(indexAlerts(alerts).length, first, "an unchanged auto-load file must not re-alert");

    // Rug-pull: the file is poisoned differently mid-session.
    writeFileSync(join(sb.proj, "CLAUDE.md"), v3("v3-desc-011").text);
    await run(["indexscan"], env, sb.proj, null);
    await settle();
    assert.ok(indexAlerts(alerts).length > first, "a CHANGED auto-load file must be re-scanned and re-alerted");
  } finally { srv.close(); }
});
