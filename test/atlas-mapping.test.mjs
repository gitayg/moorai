// Per-file runner:  node --test test/atlas-mapping.test.mjs
//
// THE DEFECT THIS PINS. Every one of the 72 threats carried exactly ONE `atlas` id — zero arrays.
// A rule that genuinely implements three ATLAS techniques credited one, and the other two read as
// uncovered in every consumer of the mapping: the public comparison page, the console's compliance
// crosswalk (`server/compliance.js` groups threats by `t.atlas`), and the SIEM CEF export. The fix
// is a schema change — `atlas` is now `string | string[]` — which is the part that can silently
// break a reader: `threat.atlas === "AML.T0051"` is false for `["AML.T0051"]`, and
// `[owasp, atlas].join(" · ")` renders `AML.T0051,AML.T0054` instead of two tags. So this file
// scores three things and not only the ids:
//
//   1. SHAPE     — every tag is a string or a non-empty array of unique, well-formed ids.
//   2. TRUTH     — every credited id is a real technique in ATLAS 2026.09, checked against the
//                  checked-in fixture (test/atlas-techniques-2026-09.json), not against memory.
//   3. THE MAP   — the multi-technique credits are named one by one, so a future edit that drops
//                  one back to a single id fails here instead of quietly shrinking a public number.
//
// Plus the consumer contract: atlasIds() normalises both shapes, and cli/moorai-guard.mjs reads the
// tag through it rather than interpolating the raw field.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { atlasIds, atlasPartialNote, atlasLabel } from "../data/atlas.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const { meta, threats } = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
const ATLAS = JSON.parse(readFileSync(join(ROOT, "test/atlas-techniques-2026-09.json"), "utf8")).techniques;

const byId = new Map(threats.map((t) => [t.id, t]));
const idsOf = (n) => atlasIds(byId.get(n));

// ---------------------------------------------------------------------------------------------
// 1. Shape
// ---------------------------------------------------------------------------------------------
test("ATLAS-MAP: every tag is a string or a non-empty array of unique, well-formed ids", () => {
  for (const t of threats) {
    const a = t.atlas;
    assert.ok(typeof a === "string" || Array.isArray(a), `#${t.id} atlas must be string | string[], got ${typeof a}`);
    const ids = atlasIds(t);
    assert.ok(ids.length > 0, `#${t.id} has no ATLAS id`);
    assert.equal(new Set(ids).size, ids.length, `#${t.id} repeats an ATLAS id: ${ids.join(", ")}`);
    for (const id of ids) assert.match(id, /^AML\.T\d{4}(\.\d{3})?$/, `#${t.id} malformed ATLAS id ${id}`);
    if (Array.isArray(a)) assert.ok(a.length > 1, `#${t.id} is a one-element array — use the bare string`);
  }
});

test("ATLAS-MAP: a bounded credit is marked, and only for a technique the rule actually credits", () => {
  for (const t of threats) {
    if (!t.atlasPartial) continue;
    const ids = new Set(atlasIds(t));
    for (const [id, limit] of Object.entries(t.atlasPartial)) {
      assert.ok(ids.has(id), `#${t.id} marks ${id} partial but does not credit it`);
      assert.equal(typeof limit, "string", `#${t.id} ${id} partial limit must be a string`);
      assert.ok(limit.length > 3, `#${t.id} ${id} partial limit is empty`);
    }
  }
});

// ---------------------------------------------------------------------------------------------
// 2. Truth — every id exists in ATLAS 2026.09
// ---------------------------------------------------------------------------------------------
test("ATLAS-MAP: every credited id is a real ATLAS 2026.09 technique", () => {
  for (const t of threats) {
    for (const id of atlasIds(t)) assert.ok(ATLAS[id], `#${t.id} credits ${id}, which is not a technique in ATLAS 2026.09`);
  }
});

test("ATLAS-MAP: the four verbatim public limits stay attached to their technique", () => {
  const expected = [
    [50, "AML.T0068", "text/markup only"],
    [71, "AML.T0077", "no egress OCR"],
    [72, "AML.T0129", "file-metadata channel only"],
    [70, "AML.T0134", "endpoint artefact only"]
  ];
  for (const [threatId, id, limit] of expected) {
    assert.equal(atlasPartialNote(byId.get(threatId), id), limit, `#${threatId} ${id} must state its public limit verbatim`);
  }
});

// ---------------------------------------------------------------------------------------------
// 3. The map — each multi-technique credit, named
// ---------------------------------------------------------------------------------------------
// [threat id, technique, the distinct mechanism that earns it]
const CREDITS = [
  [2,  "AML.T0054", "six detectors match the published guardrail-override families (DAN/AutoDAN templates, affirmative-prefix forcing, persona+policy-negation, PAP/PAIR/TAP persuasion frames)"],
  [3,  "AML.T0054", "inj-multiturn-persona scores persona scaffolding across a SESSION window, not a single prompt"],
  [3,  "AML.T0068", "inj-perturbed's collapse + bounded-fuzzy pass recovers an override phrase that was spaced, punctuation-split or misspelled to evade matching"],
  [22, "AML.T0080", "the rule's subject is a write into an assistant's persistent memory — AML.T0020 is training data, which agent memory is not"],
  [25, "AML.T0110", "the approved-connector allow-list (policy.mcpAllow) gates which tool definitions the agent may load"],
  [40, "AML.T0099", "inj-untrusted-directive fires only at the file / index / tool-output stages — an imperative sitting inside a connected data source, which no prompt-stage detector sees"],
  [43, "AML.T0101", "destructive-command matches the irreversible mutative commands the agent runs through its shell tool"],
  [47, "AML.T0086", "action-external-comms matches the send-message tool families and gates them on human approval — the exfiltration-by-legitimate-tool channel"],
  [51, "AML.T0056", "sysprompt-extract matches the extraction probe itself"],
  [52, "AML.T0056", "sysprompt-echo matches the reply reciting its own instruction block"],
  [54, "AML.T0112", "exec-reverse-shell matches the payload shapes that hand a remote host interactive control of the machine through the agent"],
  [55, "AML.T0098", "cred-file-access matches the agent using a tool to read credential files and the keychain"],
  [56, "AML.T0101", "mcp-destructive-call matches the irreversible operation invoked through a TOOL rather than a shell"],
  [60, "AML.T0081", "the index stage scans data/skill-surface.js's auto-loaded agent-configuration paths and re-alerts on mid-session poisoning or baseline drift"],
  [60, "AML.T0110", "the tool stage scans an MCP tool's model-visible description and schema for directives its stated function does not justify"],
  [62, "AML.T0060", "inspectInstall classifies the package NAME offline as a known-bad or typosquat near-miss — the adversary-registered entity behind a hallucination"],
  [65, "AML.T0086", "the secret-value fingerprint is matched against MCP TOOL ARGUMENTS, an egress channel that never touches the inference API"],
  [66, "AML.T0118", "data/agent-detections.js reconstructs the spawn/handoff graph and flags orphan subagents and agent-to-agent messages, independent of any tool call"],
  [67, "AML.T0081", "the proxy and CA-trust environment overrides are reported by variable NAME at agent launch — the configuration change that weakens the agent's TLS verification, before any request"],
  [68, "AML.T0080", "craftedAssistantLink requires the decoded payload to ask for PERSISTENCE — a durable write into cross-session memory — as a condition separate from the link shape"],
];

test("ATLAS-MAP: every re-mapped credit is present", () => {
  const missing = CREDITS.filter(([threatId, id]) => !idsOf(threatId).includes(id))
    .map(([threatId, id, why]) => `#${threatId} is missing ${id} — ${why}`);
  assert.deepEqual(missing, [], `re-mapped ATLAS credits dropped:\n  ${missing.join("\n  ")}`);
});

test("ATLAS-MAP: the techniques the re-map rejected stay uncredited", () => {
  // Each was considered against the rule's own text and failed the standard; a future edit that
  // quietly adds one back has to argue with this list first.
  const REJECTED = [
    [69, "AML.T0084", "a restatement of AML.T0133 on the same detector"],
    [70, "AML.T0130", "aiTargetedCloakingHit gates on AUDIENCE then ORs DIVERGENCE with steeringDirectiveHit — one finding, one mechanism; response biasing is what the cloaking achieves, not a separate detection"],
    [51, "AML.T0069", "the Discovery-tactic superset of AML.T0056"],
    [21, "AML.T0070", "MoorAI has no RAG index and scans no retrieval store — the index stage is the skill surface"],
    [40, "AML.T0093", "a restatement of AML.T0099 — the mechanism never sees the public-facing application"],
    [53, "AML.T0029", "the same size threshold as the AML.T0034 credit, with a different impact label"],
    [17, "AML.T0067", "out-links fires on every URL in an output; flagging everything is not detection"],
    [29, "AML.T0067", "out-citation is coach-mode and fires on every citation marker"],
    [59, "AML.T0086", "the trifecta detects capability CO-OCCURRENCE, not an exfiltrating tool call"],
    [66, "AML.T0103", "the same orphan-subagent detector already credited for AML.T0118"],
    [57, "AML.T0011", "a downstream consequence of the AML.T0010 credit on the same evidence"],
    [46, "AML.T0081", "host security posture is not the AI agent's configuration"],
    [63, "AML.T0081", "the detector decides the DESTINATION host, not a configuration change"]
  ];
  const wrong = REJECTED.filter(([threatId, id]) => idsOf(threatId).includes(id))
    .map(([threatId, id, why]) => `#${threatId} credits ${id} — rejected because ${why}`);
  assert.deepEqual(wrong, [], `a rejected ATLAS credit was added:\n  ${wrong.join("\n  ")}`);
});

// ---------------------------------------------------------------------------------------------
// 4. Coverage — the published numbers
// ---------------------------------------------------------------------------------------------
test("ATLAS-MAP: distinct technique coverage, in and out of the Agentic AI set", () => {
  const distinct = new Set(threats.flatMap((t) => atlasIds(t)));
  const agentic = [...distinct].filter((id) => ATLAS[id]?.agentic);
  const agenticTop = agentic.filter((id) => !id.includes(".", 7));
  const scored = Object.entries(ATLAS).filter(([id, v]) => v.agentic && !id.includes(".", 7)).length;

  assert.equal(scored, 76, "the scored Agentic AI set is 76 top-level techniques");
  assert.equal(distinct.size, 28, "distinct ATLAS techniques credited across the rule base");
  assert.equal(agenticTop.length, 27, "credited techniques inside the 76-technique Agentic AI set");
});

// ---------------------------------------------------------------------------------------------
// 5. The consumer contract — both shapes, one reader
// ---------------------------------------------------------------------------------------------
test("ATLAS-MAP: atlasIds normalises a string, an array, and a missing tag", () => {
  assert.deepEqual(atlasIds({ atlas: "AML.T0051" }), ["AML.T0051"]);
  assert.deepEqual(atlasIds({ atlas: ["AML.T0051", "AML.T0054"] }), ["AML.T0051", "AML.T0054"]);
  assert.deepEqual(atlasIds({}), []);
  assert.deepEqual(atlasIds(undefined), []);
});

test("ATLAS-MAP: atlasLabel renders every id, and states a bounded credit's limit", () => {
  assert.equal(atlasLabel({ atlas: ["AML.T0051", "AML.T0054"] }), "AML.T0051 · AML.T0054");
  assert.equal(
    atlasLabel({ atlas: "AML.T0068", atlasPartial: { "AML.T0068": "text/markup only" } }),
    "AML.T0068 (text/markup only)"
  );
  // The defect the helper exists to prevent: a raw array reaching a join renders one comma-joined blob.
  assert.notEqual(atlasLabel(byId.get(2)), String(byId.get(2).atlas));
});

test("ATLAS-MAP: the guard's framework line reads the tag through atlasIds, not the raw field", () => {
  const src = readFileSync(join(ROOT, "cli/moorai-guard.mjs"), "utf8");
  assert.match(src, /import \{[^}]*atlasIds[^}]*\} from "\.\.\/data\/atlas\.js"/, "moorai-guard must import atlasIds");
  assert.doesNotMatch(src, /\bf\.threat\.atlas\b/, "moorai-guard must not interpolate the raw atlas field");
});

test("ATLAS-MAP: meta.version records the shape change", () => {
  assert.equal(meta.version, "0.7.0");
  assert.match(meta.schema?.atlas || "", /string \| string\[\]/);
});
