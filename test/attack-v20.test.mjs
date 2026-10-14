// Per-file runner:  node --test test/attack-v20.test.mjs
//
// The rule base is mapped to MITRE ATT&CK Enterprise v20 (released 2026-10-13) beside OWASP and ATLAS. Each
// threat carries `attack`: an array of { id, coverage, reason }, empty when no ATT&CK technique corresponds,
// with `attackNote` saying why. This file scores:
//
//   1. THE SOURCE  — data/attack-v20-techniques.json is MITRE's v20 data, not memory: its version, the
//                    matrix totals the v20 release notes publish, and the names of the v20 AI techniques.
//   2. SHAPE       — every rule carries the tag, every credit is well formed, and a rule with no credit
//                    says why.
//   3. TRUTH       — every credited id is an active v20 technique; a revoked v19 id fails with its
//                    replacement named.
//   4. THE MAP     — the counts per coverage level and the credits for the techniques v20 added are pinned,
//                    so an edit that widens or drops one fails here instead of reaching a buyer's report.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ATTACK_V20, ATTACK_SCOPE, COVERAGE_LEVELS, attackCredits, attackIds, attackCoverage, attackLabel } from "../data/attack.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const { meta, threats } = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
const FIXTURE = JSON.parse(readFileSync(join(ROOT, "data/attack-v20-techniques.json"), "utf8"));
const TECH = FIXTURE.techniques;
const byId = new Map(threats.map((t) => [t.id, t]));
const ID_RE = /^T\d{4}(\.\d{3})?$/;

// ---------------------------------------------------------------------------------------------
// 1. The source
// ---------------------------------------------------------------------------------------------
test("ATTACK-V20: the fixture is MITRE's v20 enterprise data", () => {
  assert.equal(FIXTURE.version, "20.0");
  assert.equal(ATTACK_V20.version, FIXTURE.version);
  assert.match(FIXTURE._source, /attack-stix-data\/releases\/tag\/v20\.0/);
  assert.match(FIXTURE._source, /sha256 [0-9a-f]{64}/);
  // The Enterprise totals in the v20 release notes (attack.mitre.org/resources/updates/): 227 techniques, 479 sub-techniques.
  assert.equal(FIXTURE.counts.activeTechniques, 227);
  assert.equal(FIXTURE.counts.activeSubTechniques, 479);
  assert.equal(FIXTURE.counts.inSlice, Object.keys(TECH).length);
});

test("ATTACK-V20: the techniques v20 added carry MITRE's names", () => {
  const added = {
    "T1698": "Indirect Prompt Injection",
    "T1699": "Direct Prompt Injection",
    "T1700": "AI-Enabled Exfiltration",
    "T1685.007": "Impair Autonomous Defenses",
    "T1608.007": "AI Result Poisoning",
    "T1696": "Anti-Automation Evasion",
    "T1697": "Steal Application Specific Passwords"
  };
  for (const [id, name] of Object.entries(added)) {
    assert.equal(TECH[id]?.name, name, `${id} name`);
    assert.match(TECH[id].created, /^2026-09-/, `${id} is a v20 addition`);
  }
});

test("ATTACK-V20: every fixture id is well formed, and every sub-technique's parent is in the slice", () => {
  for (const [id, t] of Object.entries(TECH)) {
    assert.match(id, ID_RE);
    assert.ok(t.name && Array.isArray(t.tactics) && t.tactics.length > 0, `${id} needs a name and tactics`);
    if (id.includes(".")) assert.ok(TECH[id.split(".")[0]], `${id}'s parent is missing`);
  }
});

// ---------------------------------------------------------------------------------------------
// 2. Shape
// ---------------------------------------------------------------------------------------------
test("ATTACK-V20: every rule carries the tag, and the schema documents it", () => {
  assert.ok(meta.schema.attack, "meta.schema.attack is missing");
  assert.ok(meta.schema.attackNote, "meta.schema.attackNote is missing");
  assert.equal(threats.length, 80);
  for (const t of threats) assert.ok(Array.isArray(t.attack), `#${t.id} attack must be an array`);
});

test("ATTACK-V20: every credit is { id, coverage, reason } with a one-line reason and no repeat", () => {
  for (const t of threats) {
    const ids = [];
    for (const c of t.attack) {
      assert.deepEqual(Object.keys(c).sort(), ["coverage", "id", "reason"], `#${t.id} credit keys`);
      assert.match(c.id, ID_RE, `#${t.id} malformed id ${c.id}`);
      assert.ok(COVERAGE_LEVELS.includes(c.coverage), `#${t.id} ${c.id} coverage ${c.coverage}`);
      assert.equal(typeof c.reason, "string");
      assert.ok(c.reason.length > 10 && c.reason.length <= 200, `#${t.id} ${c.id} reason must be one short line`);
      assert.ok(!/\n/.test(c.reason), `#${t.id} ${c.id} reason must be one line`);
      ids.push(c.id);
    }
    assert.equal(new Set(ids).size, ids.length, `#${t.id} repeats a technique`);
  }
});

test("ATTACK-V20: a rule with no credit says why, and only such a rule carries a note", () => {
  for (const t of threats) {
    if (t.attack.length === 0) {
      assert.equal(typeof t.attackNote, "string", `#${t.id} has no credit and no attackNote`);
      assert.ok(t.attackNote.length > 10 && !/\n/.test(t.attackNote), `#${t.id} attackNote must be one line`);
    } else {
      assert.equal(t.attackNote, undefined, `#${t.id} has credits and a note`);
    }
  }
});

// ---------------------------------------------------------------------------------------------
// 3. Truth
// ---------------------------------------------------------------------------------------------
test("ATTACK-V20: every credited id is an active v20 technique", () => {
  for (const t of threats) {
    for (const id of attackIds(t)) {
      const rev = FIXTURE.revoked[id];
      assert.ok(!rev, `#${t.id} credits ${id} (${rev?.name}), revoked in v19; use ${rev?.revokedBy.join(", ")}`);
      assert.ok(TECH[id], `#${t.id} credits ${id}, which is not in the v20 slice (data/attack-v20-techniques.json)`);
    }
  }
});

test("ATTACK-V20: every scope technique is an active v20 technique with a known lane", () => {
  for (const [id, lane] of Object.entries(ATTACK_SCOPE)) {
    assert.ok(TECH[id], `scope id ${id} is not in the v20 slice`);
    assert.ok(["agent", "edr", "identity", "email", "pre"].includes(lane), `${id} lane ${lane}`);
  }
});

test("ATTACK-V20: every credited technique is in the AI-agent scope the benchmark reports over", () => {
  for (const t of threats) for (const id of attackIds(t)) assert.ok(ATTACK_SCOPE[id], `#${t.id} credits ${id}, missing from ATTACK_SCOPE`);
});

// ---------------------------------------------------------------------------------------------
// 4. The map
// ---------------------------------------------------------------------------------------------
test("ATTACK-V20: the counts per coverage level", () => {
  const credits = threats.flatMap(attackCredits);
  const count = (l) => credits.filter((c) => c.coverage === l).length;
  assert.deepEqual(
    { credits: credits.length, full: count("full"), partial: count("partial"), none: count("none") },
    { credits: 74, full: 3, partial: 56, none: 15 }
  );
  const rules = (l) => threats.filter((t) => t.attack.length > 0 && attackCoverage(t) === l).length;
  assert.deepEqual(
    { full: rules("full"), partial: rules("partial"), none: rules("none"), unmapped: threats.filter((t) => t.attack.length === 0).length },
    { full: 2, partial: 35, none: 10, unmapped: 33 }
  );
});

test("ATTACK-V20: the credits for the techniques v20 added", () => {
  const who = (id) => threats.filter((t) => attackIds(t).includes(id)).map((t) => `${t.id}:${t.attack.find((c) => c.id === id).coverage}`);
  assert.deepEqual(who("T1698"), ["3:full", "21:partial", "40:full", "60:partial", "69:partial", "70:partial", "72:partial", "74:partial"]);
  assert.deepEqual(who("T1699"), ["2:full", "51:partial"]);
  assert.deepEqual(who("T1700"), ["47:partial", "59:partial", "65:partial", "71:partial"]);
  assert.deepEqual(who("T1685.007"), ["40:partial"]);
  assert.deepEqual(who("T1608.007"), ["70:partial"]);
  assert.deepEqual(who("T1696"), []);
  assert.deepEqual(who("T1697"), []);
  // T1195.001 is the one major-version change in v20 Enterprise: it now names agent skill files and IDE task files.
  assert.deepEqual(who("T1195.001"), ["4:none", "25:partial", "60:partial", "62:partial", "80:partial"]);
});

test("ATTACK-V20: transit interception stays uncredited until a shipped hook calls decideTransit", () => {
  assert.deepEqual(byId.get(67).attack.map((c) => [c.id, c.coverage]), [["T1557", "none"], ["T1553.004", "none"]]);
});

test("ATTACK-V20: helpers read the tag the same way everywhere", () => {
  assert.deepEqual(attackIds({}), []);
  assert.equal(attackCoverage({ attack: [] }), "none");
  assert.equal(attackCoverage(byId.get(3)), "full");
  assert.equal(attackCoverage(byId.get(40)), "partial");
  assert.equal(attackCoverage(byId.get(67)), "none");
  assert.equal(attackLabel(byId.get(40)), "T1698 · T1685.007 (partial)");
});
