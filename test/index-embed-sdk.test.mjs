// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/index-embed-sdk.test.mjs
//
// @moorai/agent-sdk scanBeforeEmbed / guardEmbed (packages/agent-sdk/src/embed.mjs): content an app is
// about to embed is scanned at the engine's "index" stage first. Fixtures are real vector-3 corpus samples
// labelled stage "index": a poisoned auto-load config that only the index-stage detectors catch (nothing
// fires on it at the prompt stage) and the HTML-comment directive sample; the benign one is the corpus's
// own clean README.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanBeforeEmbed, guardEmbed, createMoorAI } from "../packages/agent-sdk/src/index.mjs";
import { buildEngine } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const V3 = JSON.parse(readFileSync(join(ROOT, "test", "redteam", "vector3-supply-chain.json"), "utf8"));
const v3 = (id) => [...V3.attacks, ...V3.benign].find((s) => s.id === id).text;
const POISONED = v3("v3-cfg-013");
const CANARY = v3("v3-canary-008"); // an HTML comment carrying an assistant directive
const BENIGN = v3("v3-benign-019");
const REPORT = { captureTier: "content-free" };
const BLOCK = { captureTier: "content-free", indexScanAction: "block" };

function sink() {
  const alerts = [];
  return { alerts, reporter: { post: (a) => { alerts.push(a); return null; }, flush: async () => {}, enrolled: true } };
}

test("scanBeforeEmbed: a poisoned chunk is flagged, a benign one allowed; report mode drops nothing", async () => {
  // Precondition: the fixture is index-only, so a flag below is the index stage's doing.
  assert.equal(buildEngine(REPORT).scan(POISONED, "prompt").length, 0, "the fixture would not prove the index stage if the prompt stage already caught it");
  const { alerts, reporter } = sink();
  const r = await scanBeforeEmbed([BENIGN, POISONED, CANARY], { source: "kb/handbook.md", policy: REPORT, reporter, console: { installToken: "tok-index-embed" } });
  assert.equal(r.action, "report");
  assert.deepEqual(r.allowed, [0]);
  assert.deepEqual(r.flagged, [1, 2]);
  assert.deepEqual(r.denied, []);
  assert.equal(r.results[0].verdict, "allow");
  assert.equal(r.results[1].verdict, "flag");
  assert.ok(r.results[1].threatIds.includes(40), JSON.stringify(r.results[1]));
  assert.ok(r.results[2].findings.some((f) => f.detectorId === "mcp-hidden-canary"), `the index-only canary detector must fire on the HTML comment: ${JSON.stringify(r.results[2])}`);
  assert.ok(r.results[1].findings.every((f) => f.stage === "index"));
  // Content-free: no chunk text in the verdicts or the alerts, and the source name only as a hash.
  const wire = JSON.stringify(r) + JSON.stringify(alerts);
  for (const s of ["pkg-analytics", "attacker-cdn", "Storybook", "kb/handbook.md", ".env"]) assert.ok(!wire.includes(s), `leaked ${s}`);
  assert.ok(alerts.length >= 2 && alerts.every((a) => a.stage === "index" && a.decision === "notify" && /^h2:/.test(a.indexSource) && a.indexSource !== "h2:nokey"), JSON.stringify(alerts));
});

test("policy block: the poisoned chunk is denied with a reason; the benign chunk still passes", async () => {
  const r = await scanBeforeEmbed([BENIGN, POISONED], { policy: BLOCK, reporter: sink().reporter });
  assert.equal(r.action, "block");
  assert.deepEqual(r.denied, [1]);
  assert.deepEqual(r.allowed, [0]);
  assert.match(r.results[1].reasons.join(","), /#40/);
});

test("objects are chunks too: a LangChain-style Document's pageContent and metadata are scanned", async () => {
  const r = await scanBeforeEmbed([{ pageContent: BENIGN, metadata: { source: "a" } }, { pageContent: "ok", metadata: { note: POISONED } }], { policy: BLOCK, reporter: sink().reporter });
  assert.deepEqual(r.denied, [1]);
});

test("guardEmbed: under block the denied chunk never reaches embedFn and is reported; report mode passes everything", async () => {
  const seen = [];
  const reports = [];
  const embed = async (chunks) => { seen.push(chunks); return chunks.map((c) => c.length); };
  const guarded = guardEmbed(embed, { policy: BLOCK, reporter: sink().reporter, onReport: (r) => reports.push(r) });
  const out = await guarded([BENIGN, POISONED, BENIGN]);
  assert.deepEqual(seen, [[BENIGN, BENIGN]]);
  assert.equal(out.length, 2);
  assert.deepEqual(reports[0].denied, [1]);

  const none = [];
  const all = await guardEmbed(async (c) => { none.push(c); return c; }, { policy: BLOCK, reporter: sink().reporter })([POISONED]);
  assert.deepEqual(all, []);
  assert.equal(none.length, 0, "embedFn must not be called when every chunk is denied");

  const passed = [];
  await guardEmbed(async (c) => { passed.push(c); }, { policy: REPORT, reporter: sink().reporter })([BENIGN, POISONED]);
  assert.deepEqual(passed, [[BENIGN, POISONED]], "report mode (the default) drops nothing");
});

test("a shared runtime: scanBeforeEmbed and guardEmbed accept a createMoorAI() instance", async () => {
  const { alerts, reporter } = sink();
  const rt = await createMoorAI({ policy: BLOCK, reporter });
  const r = await scanBeforeEmbed([POISONED], { runtime: rt, source: "s" });
  assert.deepEqual(r.denied, [0]);
  assert.ok(alerts.some((a) => a.stage === "index" && a.riskLevel === "Blocked" && a.decision === "deny"));
});

test("fail-open: an internal error keeps every chunk unless failClosed", async () => {
  const broken = { scanForIndex: async () => { throw new Error("engine down"); } };
  const errors = [];
  const r = await scanBeforeEmbed([POISONED, BENIGN], { runtime: broken, onError: (e) => errors.push(e) });
  assert.equal(r.failOpen, true);
  assert.deepEqual(r.allowed, [0, 1]);
  assert.equal(errors.length, 1);
  const passed = [];
  await guardEmbed(async (c) => { passed.push(c); }, { runtime: broken })([POISONED]);
  assert.deepEqual(passed, [[POISONED]]);
  await assert.rejects(scanBeforeEmbed([POISONED], { runtime: broken, failClosed: true }), /engine down/);
});
