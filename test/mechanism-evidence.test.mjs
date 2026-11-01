// The mechanism-evidence path the benchmark uses to back an OWASP credit that has no detector
// (scripts/mechanism-evidence.mjs, data/mechanism-evidence.json): a declaration counts only while its
// source holds its symbol and every test it names exists in the unit suite with exactly that title.
//
//   node --test --import ./test/hermetic-env.mjs test/mechanism-evidence.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { testTitles, verifyMechanisms, loadMechanismEvidence } from "../scripts/mechanism-evidence.mjs";
import { OWASP_AGENTIC, OWASP_MCP } from "../data/owasp-frameworks.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FW = { owaspAgentic: OWASP_AGENTIC, owaspMcp: OWASP_MCP };
const THREATS = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));

const RULE = { threats: [{ id: 7, owaspAgentic: ["ASI10"], owaspAgenticPartial: { ASI10: "bounded" }, owaspMcp: [] }] };
const decl = (over = {}) => ({ mechanisms: [{ id: "gate", name: "a gate", threatId: 7, owaspAgentic: ["ASI10"], path: "src/gate.mjs", symbol: "export function gate", tests: [{ file: "test/gate.test.mjs", title: "gate: an out-of-scope call is denied" }], ...over }] });

function fakeRoot(testSrc) {
  const root = mkdtempSync(join(tmpdir(), "moorai-mech-ev-"));
  mkdirSync(join(root, "src"));
  mkdirSync(join(root, "test"));
  writeFileSync(join(root, "src/gate.mjs"), "export function gate() { return \"deny\"; }\n");
  writeFileSync(join(root, "test/gate.test.mjs"), testSrc);
  return root;
}

test("titles: quoted, escaped and template titles are read exactly; skip, todo and substituted titles are not", () => {
  const src = [
    'test("a \\"quoted\\" title", () => {});',
    "test('single \\'one\\'', () => {});",
    "it(`template → arrow`, async () => {});",
    'test.skip("skipped", () => {});',
    'test.todo("later");',
    'test("opted out", { skip: true }, () => {});',
    "test(`vector ${name}: dynamic`, () => {});",
    'mytest("not a test call", () => {});',
    'test.only("only one", () => {});'
  ].join("\n");
  assert.deepEqual([...testTitles(src)].sort(), ['a "quoted" title', "only one", "single 'one'", "template → arrow"]);
});

test("a declaration whose test exists with its exact title is proven and backs the rule's credit", () => {
  const root = fakeRoot('test("gate: an out-of-scope call is denied", () => {});\n');
  const r = verifyMechanisms(decl(), RULE, FW, root);
  assert.deepEqual(r.proven.map((m) => m.id), ["gate"]);
  assert.equal(r.backing(7, "owaspAgentic", "ASI10"), 1);
  assert.equal(r.backing(7, "owaspMcp", "ASI10"), 0);
});

test("drop the test title, skip the test or lose the symbol, and the credit is no longer backed", () => {
  for (const [why, src, over] of [
    ["title renamed", 'test("gate: something else", () => {});\n', {}],
    ["test skipped", 'test.skip("gate: an out-of-scope call is denied", () => {});\n', {}],
    ["title only in a string", 'const t = "gate: an out-of-scope call is denied";\n', {}],
    ["symbol gone", 'test("gate: an out-of-scope call is denied", () => {});\n', { symbol: "export function removedGate" }],
    ["file outside the suite", 'test("gate: an out-of-scope call is denied", () => {});\n', { tests: [{ file: "test/gate.mjs", title: "gate: an out-of-scope call is denied" }] }]
  ]) {
    const r = verifyMechanisms(decl(over), RULE, FW, fakeRoot(src));
    assert.equal(r.proven.length, 0, why);
    assert.equal(r.backing(7, "owaspAgentic", "ASI10"), 0, why);
    assert.equal(r.unproven[0].id, "gate", why);
    assert.ok(r.unproven[0].missing.length > 0, why);
  }
});

test("a declaration cannot add a credit: an item the rule does not carry, an unknown item or rule, or no test is an error", () => {
  const root = fakeRoot('test("gate: an out-of-scope call is denied", () => {});\n');
  assert.throws(() => verifyMechanisms(decl({ owaspAgentic: ["ASI07"] }), RULE, FW, root), /does not credit ASI07/);
  assert.throws(() => verifyMechanisms(decl({ owaspMcp: ["MCP09"] }), RULE, FW, root), /does not credit MCP09/);
  assert.throws(() => verifyMechanisms(decl({ owaspAgentic: ["ASI11"] }), RULE, FW, root), /not a owaspAgentic item/);
  assert.throws(() => verifyMechanisms(decl({ threatId: 999 }), RULE, FW, root), /no rule #999/);
  assert.throws(() => verifyMechanisms(decl({ tests: [] }), RULE, FW, root), /at least one/);
  assert.throws(() => verifyMechanisms(decl({ owaspAgentic: undefined }), RULE, FW, root), /names no owaspAgentic or owaspMcp item/);
});

test("the shipped declarations are all proven, and each backs only credits its rule carries", () => {
  const r = verifyMechanisms(loadMechanismEvidence(ROOT), THREATS, FW, ROOT);
  assert.deepEqual(r.unproven, []);
  assert.ok(r.proven.length >= 10);
});

test("ASI07, ASI10 and MCP09 are backed by a proven mechanism, at the bounded level their rules carry", () => {
  const r = verifyMechanisms(loadMechanismEvidence(ROOT), THREATS, FW, ROOT);
  for (const [key, item] of [["owaspAgentic", "ASI07"], ["owaspAgentic", "ASI10"], ["owaspMcp", "MCP09"]]) {
    const backed = THREATS.threats.filter((t) => (t[key] || []).includes(item) && r.backing(t.id, key, item) > 0);
    assert.ok(backed.length > 0, `${item} has no proven mechanism`);
    for (const t of backed) assert.ok(t[`${key}Partial`]?.[item], `#${t.id} ${item} is a bounded credit`);
  }
});
