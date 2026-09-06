// Contract tests for the AMTSO vector 2 / vector 4 corpora and their scorer.
//
// These do NOT assert a recall number — recall is a measurement, and pinning it here would turn a
// detector regression into a corpus test failure. What they DO pin is everything the measurement
// depends on being true:
//   * both corpora parse and every sample carries the fields the scorer reads (a sample missing
//     `stage` or `action` is silently scored as something else, which is how a corpus quietly stops
//     measuring what it claims to);
//   * the enum values are the ones the scorer groups by (a typo'd channel becomes its own row and the
//     breakdown looks fine while being wrong);
//   * no forbidden secret shape ever entered the tree (a Stripe sk_live_-shaped fixture blocks the push);
//   * `hookRegistered()` agrees with the matcher list cli/moorai-hook.mjs actually installs — this is
//     the load-bearing claim behind the whole "unregistered tools" finding;
//   * the vector-4 corpus really does exercise tools outside that matcher list, so the finding is
//     measured rather than asserted.
//
//   node --test test/vector24-corpus.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { hookRegistered, INSTALLED_MATCHERS, VECTOR_FILES } from "../scripts/score-vector24.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const load = (p) => JSON.parse(readFileSync(join(ROOT, p), "utf8"));

const V2 = load(VECTOR_FILES[2]);
const V4 = load(VECTOR_FILES[4]);
const all = (d) => [...(d.attacks || []), ...(d.benign || [])];

const STAGES = new Set(["file", "output", "index", "prompt"]);
const CHANNELS = new Set(["web-page", "repo-file", "issue-ticket", "calendar-invite", "email", "api-response", "document-excerpt", "kb-retrieval"]);
const HIDING = new Set(["html-comment", "invisible-text", "markdown-trick", "metadata", "encoded", "plain"]);
const TOKENS = new Set(["{{HOME}}", "{{CRED_FILE}}", "{{BENIGN_FILE}}", "{{STAGE_FILE}}", "{{AWS_KEY}}", "{{AWS_SECRET}}", "{{GH_TOKEN}}"]);

// ---- shared hygiene -------------------------------------------------------------------------

// A Stripe live-key-shaped fixture trips GitHub push protection and has already cost this repo a
// blocked push. Asserted over the raw file text so it catches one hiding in any field.
for (const [name, path] of Object.entries(VECTOR_FILES)) {
  test(`vector ${name}: no forbidden secret shapes in the corpus`, () => {
    const raw = readFileSync(join(ROOT, path), "utf8");
    assert.equal(/sk_live_/.test(raw), false, "Stripe live-key shape present");
    assert.equal(/-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----[\s\S]{200,}/.test(raw), false, "a full private key body is present");
  });
}

for (const [name, data] of [["2", V2], ["4", V4]]) {
  test(`vector ${name}: unique ids and both arrays populated`, () => {
    assert.ok((data.attacks || []).length > 0, "no attacks");
    assert.ok((data.benign || []).length > 0, "no benign controls");
    const ids = all(data).map((s) => s.id);
    assert.equal(new Set(ids).size, ids.length, "duplicate sample id");
    for (const s of all(data)) {
      assert.ok(typeof s.validity === "string" && s.validity.trim().length > 20, `${s.id}: missing/short validity`);
      assert.equal(s.amtso?.attackVector, Number(name), `${s.id}: wrong amtso.attackVector`);
      assert.ok(s.subTechnique, `${s.id}: missing subTechnique`);
    }
    // benign samples must be flagged, or the FP denominator silently becomes zero
    for (const s of data.benign) assert.equal(s.shouldDetect, false, `${s.id}: benign sample not marked shouldDetect:false`);
  });
}

// ---- vector 2 -------------------------------------------------------------------------------

test("vector 2: every sample is scorable at a declared stage with real text", () => {
  for (const s of all(V2)) {
    assert.equal(s.harness, "text", `${s.id}: harness must be "text"`);
    assert.ok(STAGES.has(s.stage), `${s.id}: bad stage ${s.stage}`);
    assert.ok(CHANNELS.has(s.channel), `${s.id}: bad channel ${s.channel}`);
    assert.ok(HIDING.has(s.hiding), `${s.id}: bad hiding ${s.hiding}`);
    assert.ok(typeof s.text === "string" && s.text.trim().length > 0, `${s.id}: empty text`);
  }
});

test("vector 2: the channel x hiding grid is actually covered, not concentrated", () => {
  const atk = V2.attacks;
  const byChannel = {}, byHiding = {};
  for (const s of atk) { byChannel[s.channel] = (byChannel[s.channel] || 0) + 1; byHiding[s.hiding] = (byHiding[s.hiding] || 0) + 1; }
  // Every declared channel and hiding technique carries attacks; a declared-but-empty bucket makes the
  // per-technique breakdown read as coverage it does not have.
  assert.ok(Object.keys(byChannel).length >= 7, `only ${Object.keys(byChannel).length} channels exercised`);
  assert.ok(Object.keys(byHiding).length >= 5, `only ${Object.keys(byHiding).length} hiding techniques exercised`);
  for (const [c, n] of Object.entries(byChannel)) assert.ok(n >= 3, `channel ${c} has only ${n} attacks`);
});

test("vector 2: benign controls are adversarial, not trivially clean", () => {
  // A precision number is only worth reading if the benign controls LOOK like attacks — an FP rate
  // measured over harmless lorem ipsum is free. This pins the two properties that make it real:
  //   (1) an absolute floor of controls that sit inside the detectors' own vocabulary, and
  //   (2) at least one benign control for EVERY hiding technique the attacks use, so no technique
  //       gets a recall number with no corresponding false-positive number beside it.
  // The floor is absolute rather than a share of the corpus: adding easy controls must not be able to
  // satisfy it, and it stays meaningful as the corpus grows.
  const loaded = /ignore|instruction|prompt inject|curl|\.ssh|base64|token|credential|api[_ -]?key|system prompt|previous/i;
  const hard = V2.benign.filter((s) => loaded.test(s.text));
  assert.ok(hard.length >= 10, `only ${hard.length} benign controls sit near detector vocabulary`);

  const attackHiding = new Set(V2.attacks.map((s) => s.hiding));
  const benignHiding = new Set(V2.benign.map((s) => s.hiding));
  for (const h of attackHiding) {
    assert.ok(benignHiding.has(h), `hiding technique "${h}" has attacks but no benign control — its FP rate is unmeasured`);
  }
});

// ---- vector 4 -------------------------------------------------------------------------------

test("vector 4: every sample resolves to a real PreToolUse payload", () => {
  for (const s of all(V4)) {
    assert.equal(s.harness, "action", `${s.id}: harness must be "action"`);
    const acts = Array.isArray(s.actions) && s.actions.length ? s.actions : [s.action];
    assert.ok(acts.length > 0 && acts.every(Boolean), `${s.id}: no action/actions`);
    for (const a of acts) {
      assert.ok(typeof a.tool_name === "string" && a.tool_name.length > 0, `${s.id}: missing tool_name`);
      assert.ok(a.tool_input && typeof a.tool_input === "object", `${s.id}: missing tool_input`);
      assert.ok(Object.keys(a.tool_input).length > 0, `${s.id}: empty tool_input`);
    }
    if (Array.isArray(s.actions) && s.actions.length > 1) {
      assert.ok(Number.isInteger(s.consumeAction) && s.consumeAction >= 1 && s.consumeAction <= s.actions.length,
        `${s.id}: multi-step sample needs a valid 1-based consumeAction`);
    }
  }
});

test("vector 4: only the seven placeholder tokens the scorer substitutes are used", () => {
  const raw = readFileSync(join(ROOT, VECTOR_FILES[4]), "utf8");
  for (const m of new Set([...raw.matchAll(/\{\{[A-Za-z_]+\}\}/g)].map((x) => x[0]))) {
    assert.ok(TOKENS.has(m), `unknown placeholder token ${m} — the scorer would leave it literal`);
  }
});

// ---- the reachability claim -------------------------------------------------------------------

test("hookRegistered agrees with the matchers cli/moorai-hook.mjs installs", () => {
  const hookSrc = readFileSync(join(ROOT, "cli", "moorai-hook.mjs"), "utf8");
  // If PRETOOL_MATCHERS stops holding exactly these, the scorer's reachability split is stale. Read as
  // an array literal rather than imported: cli/moorai-hook.mjs calls main() at module scope and main()
  // awaits stdin, so importing it never resolves.
  const m = /const PRETOOL_MATCHERS = (\[[^\]]*\])/.exec(hookSrc);
  assert.ok(m, "cli/moorai-hook.mjs no longer declares PRETOOL_MATCHERS as an array literal");
  assert.deepEqual(JSON.parse(m[1].replace(/'/g, '"')), INSTALLED_MATCHERS, "the scorer's matcher list has drifted from the hook's");
  for (const t of ["Read", "Bash", "Task", "mcp__github__create_pull_request", "mcp__exfil__upload", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch"]) {
    assert.equal(hookRegistered(t), true, `${t} should be covered by an installed matcher`);
  }
  // What REMAINS of the coverage hole: no installed matcher names these, so the hook never runs for
  // them. Write/Edit/MultiEdit/NotebookEdit/WebFetch used to be on this list and are now registered
  // AND dispatched (see test/hook-tool-coverage.test.mjs).
  for (const t of ["Glob", "Grep", "WebSearch"]) {
    assert.equal(hookRegistered(t), false, `${t} is unexpectedly covered by an installed matcher`);
  }
});

test("vector 4's reachability hole is closed — every tool the corpus exercises is now registered", () => {
  // This test used to assert the OPPOSITE (">= 2 unregistered tools"), because the corpus was written
  // against a hook that registered only Read/Bash/mcp__.*/Task and the write family was measurably
  // unreachable. That hole is closed, so the assertion is inverted rather than deleted: the corpus still
  // contains the write-family actions it always did, and this now proves the hook can actually see them.
  const tools = new Set(V4.attacks.flatMap((s) => (Array.isArray(s.actions) && s.actions.length ? s.actions : [s.action]).map((a) => a.tool_name)));
  const unreg = [...tools].filter((t) => !hookRegistered(t));
  assert.deepEqual(unreg, [], `the corpus exercises tools no installed matcher covers: ${unreg.join(", ")}`);
  for (const t of ["Write", "Edit"]) assert.ok(tools.has(t), `corpus no longer exercises ${t} — the write surface goes unmeasured`);
});

test("vector 4 also exercises multi-step staging chains", () => {
  const chains = V4.attacks.filter((s) => Array.isArray(s.actions) && s.actions.length > 1);
  assert.ok(chains.length >= 3, `only ${chains.length} multi-step chains — stage-then-exfiltrate is unmeasured`);
});
