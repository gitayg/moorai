// Human-reviewed per-language phrases (test/i18n-fixtures/<language>.json) run through the real engine,
// with the same stage expectations as test/hebrew-injection.test.mjs:
//   override  -> inj-multilingual#3 at prompt/file/index, inj-multilingual-untrusted#40 at output,
//                mcp-tool-poisoning-i18n#60 at tool
//   reveal    -> inj-multilingual#3 at prompt/file/index; no i18n finding at output/tool
//   negatives -> no i18n finding at any stage
// Schema and review rules: test/i18n-fixtures/README.md.
//
//   node --test test/i18n-fixtures.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { INJECTION_I18N_BY_LANG } from "../data/injection-i18n.js";
import { DetectionEngine } from "../src/engine.js";

const threats = JSON.parse(readFileSync(new URL("../data/threats.json", import.meta.url)));
const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);
const scan = (text, stage) => engine.scan(text, stage).map((f) => `${f.detectorId}#${f.threat.id}`);

const asToolMetadata = (s) => JSON.stringify({ name: "search_docs", description: `Searches the docs index. ${s}` });
const input = (text, stage) => (stage === "tool" ? asToolMetadata(text) : text);
const I18N_ID = /^inj-multilingual|^mcp-tool-poisoning-i18n/;

const OVERRIDE_EXPECT = {
  prompt: "inj-multilingual#3",
  file: "inj-multilingual#3",
  index: "inj-multilingual#3",
  output: "inj-multilingual-untrusted#40",
  tool: "mcp-tool-poisoning-i18n#60"
};
const STAGES = Object.keys(OVERRIDE_EXPECT);

const DIR = new URL("./i18n-fixtures/", import.meta.url);
const files = readdirSync(DIR).filter((f) => f.endsWith(".json")).sort();

test("at least one fixture file is present", () => assert.ok(files.length > 0));

for (const file of files) {
  const fx = JSON.parse(readFileSync(new URL(file, DIR), "utf8"));
  const lang = file.replace(/\.json$/, "");

  test(`${file}: schema`, () => {
    assert.equal(fx.language, lang, "language must equal the file name");
    assert.ok(INJECTION_I18N_BY_LANG[lang], `no INJECTION_I18N_BY_LANG entry named "${lang}"`);
    assert.equal(typeof fx.reviewedBy, "string");
    assert.ok(fx.reviewedBy.trim().length > 0, "reviewedBy is required");
    for (const k of ["override", "reveal", "negatives"]) {
      assert.ok(Array.isArray(fx[k]), `${k} must be an array`);
      for (const s of fx[k]) assert.equal(typeof s, "string", `${k} entries must be strings`);
    }
  });

  (fx.override || []).forEach((text, i) => {
    for (const [st, want] of Object.entries(OVERRIDE_EXPECT)) {
      test(`${lang} override[${i}] @${st}: raises ${want}`, () => {
        const got = scan(input(text, st), st);
        assert.ok(got.includes(want), `${st} stage: [${got.join(",")}]`);
      });
    }
  });

  (fx.reveal || []).forEach((text, i) => {
    for (const st of ["prompt", "file", "index"]) {
      test(`${lang} reveal[${i}] @${st}: raises inj-multilingual#3`, () => {
        const got = scan(text, st);
        assert.ok(got.includes("inj-multilingual#3"), `${st} stage: [${got.join(",")}]`);
      });
    }
    for (const st of ["output", "tool"]) {
      test(`${lang} reveal[${i}] @${st}: stays prompt-stage only (no i18n finding)`, () => {
        const got = scan(input(text, st), st);
        assert.ok(!got.some((g) => I18N_ID.test(g)), `${st} stage: [${got.join(",")}]`);
      });
    }
  });

  (fx.negatives || []).forEach((text, i) => {
    for (const st of STAGES) {
      test(`${lang} negative[${i}] @${st}: no multilingual injection finding`, () => {
        const got = scan(input(text, st), st);
        assert.ok(!got.some((g) => I18N_ID.test(g)), `false positive: [${got.join(",")}]`);
      });
    }
  });
}
