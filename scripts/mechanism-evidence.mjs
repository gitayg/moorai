// Mechanism evidence for the OWASP Agentic and MCP tables in docs/BENCHMARK.md.
//
// A rule's OWASP credit counts there when the rule has an on-device detector (data/detectors.js) or when
// data/mechanism-evidence.json names the enforcing mechanism behind it AND the test that proves it
// enforces. A declaration is proven only when its source file exists and contains its symbol, and every
// test it names is a file in the unit suite (test/*.test.mjs) holding a test() or it() with exactly that
// title (not .skip or .todo). An unproven declaration adds nothing; the benchmark lists it.
//
// A declaration can only back a credit the rule already carries in data/threats.json, at the level it
// carries it there (owaspAgenticPartial / owaspMcpPartial). It never adds a credit or raises a level; a
// declaration that names a credit the rule does not carry is an error.
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

export const EVIDENCE_FILE = "data/mechanism-evidence.json";
export const FRAMEWORK_KEYS = ["owaspAgentic", "owaspMcp"];
const SUITE = /^test\/[^/]+\.test\.mjs$/;

export function loadMechanismEvidence(root) {
  return JSON.parse(readFileSync(join(root, EVIDENCE_FILE), "utf8"));
}

const ESC = { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", v: "\v", 0: "\0" };
function unquote(lit) {
  return lit.slice(1, -1).replace(/\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[\s\S])/g, (_, e) => {
    if (e[0] === "u") return String.fromCodePoint(parseInt(e[1] === "{" ? e.slice(2, -1) : e.slice(1), 16));
    if (e[0] === "x" && e.length === 3) return String.fromCharCode(parseInt(e.slice(1), 16));
    return ESC[e] ?? e;
  });
}

// The titles of the runnable test() / it() calls in a test file's source. A template literal with a
// ${} substitution is not a fixed title and is skipped; so is a call whose options say skip or todo.
export function testTitles(src) {
  const titles = new Set();
  const re = /(?<![\w.$])(test|it)(\.only)?\s*\(\s*("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\$]|\\.|\$(?!\{))*`)\s*(,\s*\{[^}]*\b(?:skip|todo)\s*:)?/g;
  for (const m of src.matchAll(re)) if (!m[4]) titles.add(unquote(m[3]));
  return titles;
}

function check(root, m) {
  const missing = [];
  const src = existsSync(join(root, m.path)) ? readFileSync(join(root, m.path), "utf8") : null;
  if (src === null) missing.push(`source ${m.path} not found`);
  else if (!src.includes(m.symbol)) missing.push(`symbol not in ${m.path}: ${m.symbol}`);
  for (const t of m.tests) {
    if (!SUITE.test(t.file)) { missing.push(`not a unit-suite test file: ${t.file}`); continue; }
    if (!existsSync(join(root, t.file))) { missing.push(`test file not found: ${t.file}`); continue; }
    if (!testTitles(readFileSync(join(root, t.file), "utf8")).has(t.title)) missing.push(`no test titled "${t.title}" in ${t.file}`);
  }
  return missing;
}

// Validates the declarations against the threat matrix and the frameworks' item lists, then checks each
// one's evidence on disk. Returns { proven, unproven, backing } where backing(threatId, key, item) is the
// number of proven mechanisms backing that rule's credit for that item.
export function verifyMechanisms(decl, threats, frameworks, root) {
  const byId = new Map(threats.threats.map((t) => [t.id, t]));
  const seen = new Set();
  const proven = [];
  const unproven = [];
  for (const m of decl.mechanisms || []) {
    const where = `mechanism ${JSON.stringify(m.id)}`;
    if (typeof m.id !== "string" || !m.id || seen.has(m.id)) throw new Error(`${where}: id missing or repeated`);
    seen.add(m.id);
    if (typeof m.name !== "string" || !m.name || typeof m.path !== "string" || typeof m.symbol !== "string" || !m.symbol) throw new Error(`${where}: name, path and symbol are required`);
    const t = byId.get(m.threatId);
    if (!t) throw new Error(`${where}: no rule #${m.threatId} in data/threats.json`);
    if (!Array.isArray(m.tests) || !m.tests.length || m.tests.some((x) => typeof x?.file !== "string" || typeof x?.title !== "string" || !x.title)) throw new Error(`${where}: needs at least one { file, title } test`);
    const keys = FRAMEWORK_KEYS.filter((k) => m[k] !== undefined);
    if (!keys.length) throw new Error(`${where}: names no owaspAgentic or owaspMcp item`);
    for (const k of keys) {
      if (!Array.isArray(m[k]) || !m[k].length) throw new Error(`${where}: ${k} must be a non-empty array`);
      for (const id of m[k]) {
        if (!(id in frameworks[k].items)) throw new Error(`${where}: ${id} is not a ${k} item`);
        if (!(t[k] || []).includes(id)) throw new Error(`${where}: rule #${t.id} does not credit ${id} in data/threats.json; a mechanism cannot add a credit`);
      }
    }
    const missing = check(root, m);
    (missing.length ? unproven : proven).push(missing.length ? { id: m.id, threatId: m.threatId, missing } : m);
  }
  const count = new Map();
  for (const m of proven) for (const k of FRAMEWORK_KEYS) for (const id of m[k] || []) {
    const key = `${m.threatId}|${k}|${id}`;
    count.set(key, (count.get(key) || 0) + 1);
  }
  return { proven, unproven, backing: (threatId, k, id) => count.get(`${threatId}|${k}|${id}`) || 0 };
}
