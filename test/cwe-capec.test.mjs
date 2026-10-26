// Per-file runner:  node --test test/cwe-capec.test.mjs
//
// Every rule in data/threats.json carries `cwe` (the weakness the threat exploits) and `capec` (the attack
// pattern the threat is), each an array of { id, title }. This file scores:
//
//   1. SHAPE  — both tags on every rule, always arrays of { id: integer, title: string }, no repeated id;
//               an empty array carries its one-line note, a non-empty one carries none.
//   2. TRUTH  — every id is in data/cwe-capec.js and its title equals the canonical name exactly, and the
//               tables themselves equal the names read from MITRE (CWE 4.20) and the OWASP Threat Model
//               Library's capec-names.json (CAPEC 3.9) on 2026-10-26.
//   3. THE MAP — every rule's ids, named, so an edit that adds or drops a credit fails here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { CWE_TITLES, CAPEC_TITLES } from "../data/cwe-capec.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const { meta, threats } = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));

const TAGS = [
  ["cwe", "cweNote", CWE_TITLES, "CWE"],
  ["capec", "capecNote", CAPEC_TITLES, "CAPEC"]
];

// ---------------------------------------------------------------------------------------------
// 1. Shape
// ---------------------------------------------------------------------------------------------
test("CWE-CAPEC: every threat carries cwe and capec as arrays of { id: integer, title: string }", () => {
  for (const t of threats) {
    for (const [tag, , , name] of TAGS) {
      assert.ok(Array.isArray(t[tag]), `#${t.id} ${tag} must be an array, got ${typeof t[tag]}`);
      for (const e of t[tag]) {
        assert.equal(typeof e, "object", `#${t.id} ${tag} entry must be an object`);
        assert.deepEqual(Object.keys(e).sort(), ["id", "title"], `#${t.id} ${tag} entry keys`);
        assert.ok(Number.isInteger(e.id) && e.id > 0, `#${t.id} ${name} id must be a positive integer, got ${JSON.stringify(e.id)}`);
        assert.equal(typeof e.title, "string", `#${t.id} ${name}-${e.id} title must be a string`);
      }
      const ids = t[tag].map((e) => e.id);
      assert.equal(new Set(ids).size, ids.length, `#${t.id} repeats a ${name} id: ${ids.join(", ")}`);
    }
  }
});

test("CWE-CAPEC: an empty tag carries a note, and a non-empty one does not", () => {
  for (const t of threats) {
    for (const [tag, note] of TAGS) {
      if (t[tag].length === 0) {
        assert.equal(typeof t[note], "string", `#${t.id} has ${tag}: [] without ${note}`);
        assert.ok(t[note].trim().length > 10, `#${t.id} ${note} is empty`);
      } else {
        assert.ok(!(note in t), `#${t.id} credits ${tag} and also carries ${note}`);
      }
    }
  }
});

test("CWE-CAPEC: meta.schema documents cwe, capec, cweNote and capecNote", () => {
  for (const k of ["cwe", "capec", "cweNote", "capecNote"]) {
    assert.equal(typeof meta.schema?.[k], "string", `meta.schema.${k} missing`);
    assert.ok(meta.schema[k].length > 40, `meta.schema.${k} is too short to document the field`);
  }
  assert.match(meta.schema.cwe, /data\/cwe-capec\.js/);
  assert.match(meta.schema.capec, /data\/cwe-capec\.js/);
});

// ---------------------------------------------------------------------------------------------
// 2. Truth
// ---------------------------------------------------------------------------------------------
test("CWE-CAPEC: every credited id is in the canonical table, with its exact title", () => {
  for (const t of threats) {
    for (const [tag, , table, name] of TAGS) {
      for (const { id, title } of t[tag]) {
        assert.ok(table[id], `#${t.id} credits ${name}-${id}, which is not in data/cwe-capec.js`);
        assert.equal(title, table[id], `#${t.id} ${name}-${id} title must be the canonical name`);
      }
    }
  }
});

test("CWE-CAPEC: the tables hold only ids a rule credits", () => {
  for (const [tag, , table, name] of TAGS) {
    const used = new Set(threats.flatMap((t) => t[tag].map((e) => e.id)));
    const unused = Object.keys(table).map(Number).filter((id) => !used.has(id));
    assert.deepEqual(unused, [], `${name} ids in the table that no rule credits`);
  }
});

// Read from https://cwe.mitre.org/data/definitions/<id>.html (CWE 4.20) on 2026-10-26. Every one is
// a Base, Class or Compound entry with vulnerability-mapping usage ALLOWED or ALLOWED-WITH-REVIEW.
const CWE_VERIFIED = {
  15: "External Control of System or Configuration Setting",
  94: "Improper Control of Generation of Code ('Code Injection')",
  201: "Insertion of Sensitive Information Into Sent Data",
  250: "Execution with Unnecessary Privileges",
  308: "Use of Single-factor Authentication",
  312: "Cleartext Storage of Sensitive Information",
  352: "Cross-Site Request Forgery (CSRF)",
  441: "Unintended Proxy or Intermediary ('Confused Deputy')",
  451: "User Interface (UI) Misrepresentation of Critical Information",
  494: "Download of Code Without Integrity Check",
  497: "Exposure of Sensitive System Information to an Unauthorized Control Sphere",
  502: "Deserialization of Untrusted Data",
  732: "Incorrect Permission Assignment for Critical Resource",
  770: "Allocation of Resources Without Limits or Throttling",
  829: "Inclusion of Functionality from Untrusted Control Sphere",
  1427: "Improper Neutralization of Input Used for LLM Prompting"
};

// From the OWASP Threat Model Library's scripts/capec-names.json (CAPEC 3.9), 2026-10-26.
const CAPEC_VERIFIED = {
  13: "Subverting Environment Variable Values",
  62: "Cross Site Request Forgery",
  75: "Manipulating Writeable Configuration Files",
  98: "Phishing",
  130: "Excessive Allocation",
  154: "Resource Location Spoofing",
  164: "Mobile Phishing",
  169: "Footprinting",
  185: "Malicious Software Download",
  195: "Principal Spoof",
  268: "Audit Log Manipulation",
  479: "Malicious Root Certificate",
  578: "Disable Security Software",
  586: "Object Injection",
  600: "Credential Stuffing",
  636: "Hiding Malicious Data or Code within Files",
  639: "Probe System Files",
  656: "Voice Phishing",
  698: "Install Malicious Extension"
};

test("CWE-CAPEC: the tables equal the names read from the sources", () => {
  assert.deepEqual({ ...CWE_TITLES }, CWE_VERIFIED);
  assert.deepEqual({ ...CAPEC_TITLES }, CAPEC_VERIFIED);
  assert.ok(Object.isFrozen(CWE_TITLES) && Object.isFrozen(CAPEC_TITLES), "the tables are frozen");
});

test("CWE-CAPEC: CWE-1426 is not credited — MITRE marks it DISCOURAGED for mapping", () => {
  assert.ok(!threats.some((t) => t.cwe.some((e) => e.id === 1426)), "CWE-1426 is credited");
});

// ---------------------------------------------------------------------------------------------
// 3. The map — every rule's ids
// ---------------------------------------------------------------------------------------------
// threat id: [cwe ids, capec ids]
const MAP = {
  1: [[], []], 2: [[1427], []], 3: [[1427], []], 4: [[829], [698]], 5: [[250], []], 6: [[732], []],
  7: [[], []], 8: [[], []], 9: [[], []], 10: [[], [98]], 11: [[], [195]], 12: [[], [195, 656]],
  13: [[], [656, 164]], 14: [[], []], 15: [[], []], 16: [[], []], 17: [[], []], 18: [[], []],
  19: [[], []], 20: [[], []], 21: [[1427], []], 22: [[1427], [75]], 23: [[250], []], 24: [[], []],
  25: [[1427, 829], []], 26: [[308], [600]], 27: [[], []], 28: [[250], []], 29: [[], []], 30: [[], [195]],
  31: [[], []], 32: [[], []], 33: [[], []], 34: [[], []], 35: [[], []], 36: [[], []],
  37: [[], []], 38: [[770], []], 39: [[201], []], 40: [[1427], []], 41: [[], []], 42: [[], []],
  43: [[], []], 44: [[], []], 45: [[], []], 46: [[], [578]], 47: [[], []], 48: [[], []],
  49: [[], []], 50: [[1427], []], 51: [[1427, 497], []], 52: [[497], []], 53: [[770], [130]], 54: [[94], []],
  55: [[312], [639]], 56: [[], []], 57: [[494], [185]], 58: [[], []], 59: [[1427], []], 60: [[1427, 829], [75]],
  61: [[], []], 62: [[829], [185]], 63: [[15], [13]], 64: [[250], []], 65: [[201], []], 66: [[441], []],
  67: [[15], [13, 479]], 68: [[1427, 352], [62]], 69: [[1427, 497], [169]], 70: [[1427], []], 71: [[], []], 72: [[1427], [636]],
  73: [[], [268]], 74: [[1427], []], 75: [[451], [154]], 76: [[502], [586]], 77: [[], []], 78: [[], []],
  79: [[], []], 80: [[494], [185]], 84: [[], [578]], 85: [[], []]
};

test("CWE-CAPEC: every rule's credits match the reviewed map", () => {
  assert.deepEqual(threats.map((t) => t.id).sort((a, b) => a - b), Object.keys(MAP).map(Number), "the map covers every rule");
  const drift = threats.filter((t) => {
    const [cwe, capec] = MAP[t.id];
    return JSON.stringify(t.cwe.map((e) => e.id)) !== JSON.stringify(cwe) || JSON.stringify(t.capec.map((e) => e.id)) !== JSON.stringify(capec);
  }).map((t) => `#${t.id}: cwe ${t.cwe.map((e) => e.id)} capec ${t.capec.map((e) => e.id)}`);
  assert.deepEqual(drift, [], `credits differ from the reviewed map:\n  ${drift.join("\n  ")}`);
});
