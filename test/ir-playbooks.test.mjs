// docs/IR_PLAYBOOKS.md names threat ids, reason codes, commands, console routes and views that an incident team
// will act on. Each one must exist in the code: a playbook that sends a responder to a filter, a flag or a button
// that is not there fails in the incident, not in review. This test parses the doc and checks every citation
// against this tree, and console citations against test/fixtures/console-surface.json (test/ir-console-surface.mjs
// run on the console the playbooks were written against). With MOORAI_CONSOLE_DIR set to a console checkout it
// checks them against that checkout too, and checks that the fixture holds nothing the checkout lacks.
//
//   node --test --import ./test/hermetic-env.mjs test/ir-playbooks.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { consoleSurface } from "./ir-console-surface.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DOC_PATH = join(ROOT, "docs/IR_PLAYBOOKS.md");
const DOC = readFileSync(DOC_PATH, "utf8");
const PKG = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const THREATS = new Set(JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8")).threats.map((t) => t.id));
const FIXTURE = JSON.parse(readFileSync(join(ROOT, "test/fixtures/console-surface.json"), "utf8"));
const CONSOLE_DIR = process.env.MOORAI_CONSOLE_DIR && existsSync(join(process.env.MOORAI_CONSOLE_DIR, "server")) ? process.env.MOORAI_CONSOLE_DIR : null;
const LIVE = CONSOLE_DIR ? consoleSurface(CONSOLE_DIR) : null;

// #90 (cardholder data) is added in v1.43.0 by a separate change that is not in this tree yet. ORCHESTRATOR: drop
// 90 from this list once data/threats.json has it, so the stub playbook is checked like the others.
const PENDING_THREATS = new Set([]);
// Upper-case tokens in the doc that are not reason codes: the environment variable this test reads.
const NOT_REASON_CODES = new Set(["MOORAI_CONSOLE_DIR"]);

const COMMENTS = [...DOC.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1]);
const PROSE = DOC.replace(/<!--[\s\S]*?-->/g, "");

// ---- the agent's own vocabulary ----
function walk(dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) { if (e.name !== "node_modules" && e.name !== "test" && e.name !== "tests") walk(p, out); }
    else if (/\.(m?js|rs)$/.test(e.name)) out.push(p);
  }
  return out;
}
const SOURCE_DIRS = ["cli", "mcp-gateway", "mcp-proxy", "model-proxy", "egress-proxy", "data", "src", "cloud", "packages/agent-sdk/src", "guardd/src", "src-tauri/src"];
const AGENT_LITERALS = new Set();
for (const d of SOURCE_DIRS) if (existsSync(join(ROOT, d))) for (const f of walk(join(ROOT, d))) for (const m of readFileSync(f, "utf8").matchAll(/["'`]([A-Z][A-Z0-9_]{2,})["'`]/g)) AGENT_LITERALS.add(m[1]);
const BINS = new Map(Object.entries(PKG.bin));
for (const m of readFileSync(join(ROOT, "guardd/Cargo.toml"), "utf8").matchAll(/\[\[bin\]\]\s*\nname = "([^"]+)"\s*\npath = "([^"]+)"/g)) BINS.set(m[1], join("guardd", m[2]));

// ---- doc extraction ----
function threatIds(text) { return [...text.matchAll(/(?<![\w&/])#(\d{1,3})(?!\d)/g)].map((m) => Number(m[1])); }
function reasonCodes(text) {
  const out = new Set();
  for (const m of text.matchAll(/\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b/g)) out.add(m[0]);
  for (const m of text.matchAll(/`([A-Z]{5,})`/g)) out.add(m[1]);
  for (const t of NOT_REASON_CODES) out.delete(t);
  return [...out];
}
const FENCES = [...PROSE.matchAll(/```[a-z]*\n([\s\S]*?)```/g)].map((m) => m[1]);
const INLINE = [...PROSE.replace(/```[a-z]*\n[\s\S]*?```/g, "").matchAll(/`([^`\n]+)`/g)].map((m) => m[1]);
function commandLines() {
  const lines = [];
  for (const f of FENCES) {
    const joined = f.replace(/\\\n\s*/g, " ").replace(/<<'EOF'\n[\s\S]*?\nEOF\n/g, "<<'EOF'\n");
    for (const l of joined.split("\n")) { const c = l.replace(/\s{2,}#\s.*$/, "").trim(); if (c) lines.push(c); }
  }
  return lines.concat(INLINE);
}
function tokens(seg) {
  const out = [];
  for (const m of seg.matchAll(/'[^']*'|"[^"]*"|\S+/g)) out.push(m[0]);
  return out;
}
const segments = (line) => line.split(/\s*(?:&&|\|\||;|\|)\s*/).map((s) => s.trim()).filter(Boolean);

// The file a command runs, and the files it imports directly: where its flags and subcommands are read.
function sourceSet(rel) {
  const p = join(ROOT, rel);
  const files = [p];
  if (p.endsWith(".mjs") || p.endsWith(".js")) for (const m of readFileSync(p, "utf8").matchAll(/from\s+["'](\.{1,2}\/[^"']+)["']/g)) { const q = resolve(dirname(p), m[1]); if (existsSync(q)) files.push(q); }
  return files.map((f) => readFileSync(f, "utf8")).join("\n");
}

// → list of problems for one command segment ([] when it is fine or not a command this repo ships).
function checkSegment(seg) {
  const t = tokens(seg);
  if (!t.length) return [];
  let target = null, args = [], label = seg;
  if (t[0] === "npx") { const b = (t[1] || "").replace(/@[^@]*$/, ""); if (!BINS.has(b)) return [`npx ${b}: not a package bin`]; target = BINS.get(b); args = t.slice(2); }
  else if (/^moorai-/.test(t[0])) { if (!BINS.has(t[0])) return [`${t[0]}: not a package bin or helper binary`]; target = BINS.get(t[0]); args = t.slice(1); }
  else if (t[0] === "npm") { if (t[1] === "run" && !(PKG.scripts && PKG.scripts[t[2]])) return [`npm run ${t[2]}: no such script`]; return []; }
  else if (t[0] === "node") {
    if (t[1] === "--test") return t.slice(2).filter((x) => /\.m?js$/.test(x)).filter((x) => !existsSync(join(ROOT, x))).map((x) => `${label}: ${x} does not exist`);
    if (!t[1] || !existsSync(join(ROOT, t[1]))) return [`node ${t[1]}: no such file`];
    target = t[1]; args = t.slice(2);
  } else return [];
  if (!/\.m?js$/.test(target)) return [];
  const src = sourceSet(target);
  const problems = [];
  for (const a of args) {
    if (!a.startsWith("--")) continue;
    const flag = a.split("=")[0];
    if (!new RegExp(flag.replace(/[-]/g, "\\-") + "(?![\\w-])").test(src)) problems.push(`${label}: ${flag} is not read by ${target}`);
  }
  const sub = args[0];
  if (sub && /^[a-z][a-z-]+$/.test(sub) && !new RegExp(`["'\`]${sub}["'\`]`).test(src)) problems.push(`${label}: subcommand ${sub} is not in ${target}`);
  return problems;
}

function routes() {
  const out = new Set();
  for (const s of INLINE.concat(FENCES)) for (const m of s.matchAll(/(?:^|\s)((?:GET|POST)\s+)?(\/(?:api|compliance)\/[A-Za-z0-9/_.:<>-]*)/g)) out.add(m[2].replace(/[.:]+$/, ""));
  return [...out];
}
function routeKnown(r, surface) {
  if (!r.includes("<")) return surface.paths.includes(r);
  const prefix = r.slice(0, r.indexOf("<"));
  return surface.paths.some((p) => p === prefix || (p.startsWith(prefix) && p.length > prefix.length) || p === prefix.replace(/\/$/, "") + "/");
}
function viewCitations() {
  const out = [];
  for (const m of PROSE.matchAll(/\*\*([^*\n]+?)\*\* view/g)) out.push({ view: m[1].trim() });
  for (const m of PROSE.matchAll(/\*\*([^*\n→]+?) → ([^*\n]+?)\*\*/g)) out.push({ view: m[1].trim(), panel: m[2].trim() });
  return out;
}
function viewProblems(surface, name) {
  const problems = [];
  for (const c of viewCitations()) {
    const v = surface.views.find((x) => x.label === c.view);
    if (!v) { problems.push(`${name}: no console view "${c.view}"`); continue; }
    if (c.panel && !v.panels.includes(c.panel)) problems.push(`${name}: view "${c.view}" has no panel "${c.panel}"`);
  }
  return problems;
}
function refs() {
  const out = [];
  for (const c of COMMENTS) {
    const m = c.match(/^\s*refs:\s*\n([\s\S]*)$/);
    if (!m) continue;
    for (const line of m[1].split("\n").map((l) => l.trim()).filter(Boolean)) {
      const i = line.indexOf("#");
      out.push({ path: line.slice(0, i), symbol: line.slice(i + 1) });
    }
  }
  return out;
}

// ---- tests ----
test("every threat id the playbooks cite is in data/threats.json", () => {
  const cited = [...new Set(threatIds(DOC))];
  assert.ok(cited.length >= 20, `expected the playbooks to cite threat ids, found ${cited.length}`);
  const missing = cited.filter((id) => !THREATS.has(id) && !PENDING_THREATS.has(id));
  assert.deepEqual(missing, [], `threat ids cited in docs/IR_PLAYBOOKS.md that data/threats.json does not have: ${missing.map((i) => "#" + i).join(", ")}`);
});

test("every reason code the playbooks cite is in the agent's code or the console's vocabulary", () => {
  const cited = reasonCodes(PROSE);
  assert.ok(cited.length >= 20, `expected the playbooks to cite reason codes, found ${cited.length}`);
  const known = new Set([...AGENT_LITERALS, ...FIXTURE.reasonCodes, ...(LIVE ? LIVE.reasonCodes : [])]);
  const missing = cited.filter((c) => !known.has(c));
  assert.deepEqual(missing, [], `reason codes cited in docs/IR_PLAYBOOKS.md that no code defines: ${missing.join(", ")}`);
});

test("the reason codes the doc says the console drops are agent codes the console does not store", () => {
  const para = PROSE.match(/these agent reason codes are not stored:([^\n]*(?:\n(?!\n)[^\n]*)*)/);
  assert.ok(para, "the paragraph listing the reason codes the console does not store is missing");
  const listed = [...para[1].matchAll(/`([A-Z][A-Z0-9_]+)`/g)].map((m) => m[1]);
  assert.ok(listed.length >= 5, `expected that paragraph to list codes, found ${listed.length}`);
  for (const surface of [FIXTURE, LIVE].filter(Boolean)) {
    const stored = listed.filter((c) => surface.reasonCodes.includes(c));
    assert.deepEqual(stored, [], `console ${surface.console} stores these, so the doc is wrong to say it drops them: ${stored.join(", ")}`);
  }
  const notAgent = listed.filter((c) => !AGENT_LITERALS.has(c));
  assert.deepEqual(notAgent, [], `not agent reason codes: ${notAgent.join(", ")}`);
});

test("every command the playbooks give is a bin, script or file of this repository, with flags its source reads", () => {
  const lines = commandLines();
  let checked = 0;
  const problems = [];
  for (const l of lines) for (const s of segments(l)) { const t = tokens(s); if (["npx", "node", "npm"].includes(t[0]) || /^moorai-/.test(t[0] || "")) checked++; problems.push(...checkSegment(s)); }
  assert.ok(checked >= 20, `expected the playbooks to give commands, found ${checked}`);
  assert.deepEqual(problems, [], problems.join("\n"));
});

test("every console route the playbooks cite is in the console's code", () => {
  const cited = routes();
  assert.ok(cited.length >= 15, `expected the playbooks to cite console routes, found ${cited.length}`);
  for (const surface of [FIXTURE, LIVE].filter(Boolean)) {
    const missing = cited.filter((r) => !routeKnown(r, surface));
    assert.deepEqual(missing, [], `console ${surface.console} has no route: ${missing.join(", ")}`);
  }
});

test("every console view and panel the playbooks name is on the dashboard", () => {
  assert.ok(viewCitations().length >= 10, "expected the playbooks to name console views");
  for (const [surface, name] of [[FIXTURE, "fixture"], [LIVE, "live console"]].filter((x) => x[0])) assert.deepEqual(viewProblems(surface, `${name} ${surface.console}`), []);
});

test("every hidden reference names a file that holds the cited text", (t) => {
  const all = refs();
  assert.ok(all.length >= 40, `expected references in hidden comments, found ${all.length}`);
  const problems = [];
  let skipped = 0;
  for (const r of all) {
    let base = ROOT, p = r.path;
    if (p.startsWith("console:")) { if (!CONSOLE_DIR) { skipped++; continue; } base = CONSOLE_DIR; p = p.slice("console:".length); }
    const f = join(base, p);
    if (!existsSync(f) || !statSync(f).isFile()) { problems.push(`${r.path}: no such file`); continue; }
    if (!readFileSync(f, "utf8").includes(r.symbol)) problems.push(`${r.path}: does not contain ${JSON.stringify(r.symbol)}`);
  }
  if (skipped) t.diagnostic(`${skipped} console references not checked: MOORAI_CONSOLE_DIR is not set`);
  assert.deepEqual(problems, [], problems.join("\n"));
});

test("the console fixture holds nothing the live console lacks", { skip: LIVE ? false : "MOORAI_CONSOLE_DIR is not set" }, () => {
  const paths = FIXTURE.paths.filter((p) => !LIVE.paths.includes(p));
  const codes = FIXTURE.reasonCodes.filter((c) => !LIVE.reasonCodes.includes(c));
  const panels = [];
  for (const v of FIXTURE.views) { const lv = LIVE.views.find((x) => x.label === v.label); if (!lv) panels.push(v.label); else for (const p of v.panels) if (!lv.panels.includes(p)) panels.push(`${v.label} → ${p}`); }
  assert.deepEqual({ paths, codes, panels }, { paths: [], codes: [], panels: [] });
});

test("the README links the playbooks", () => {
  assert.match(readFileSync(join(ROOT, "README.md"), "utf8"), /\]\(docs\/IR_PLAYBOOKS\.md\)/);
});
