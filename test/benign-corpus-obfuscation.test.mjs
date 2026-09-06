// Guards the OBFUSCATION-SHAPED slice of the benign corpus — the slice that exists because both standing
// precision gates were measurably blind to a whole detector family.
//
// WHAT WENT WRONG (measured, not hypothetical). data/obfuscation-signal.js was built in two variants: one
// that fires on statistical obscurity alone, and the shipped one that additionally requires a decode-and-act
// directive. On heldout-v3 the obscurity-only variant costs 48 false positives out of 97 benign samples.
// Both standing gates — scripts/score-benign-v2.mjs and scripts/redteam-eval.mjs — stayed GREEN for it.
// The reason was structural, not a threshold: of the 509 benign samples this corpus held before this file
// existed, exactly ONE tripped any obs-* tell. A corpus with no obscurity-shaped text cannot price an
// obscurity detector, so a 48-FP regression was invisible by construction.
//
// This file asserts the three properties that make the gate able to see that class again:
//   1. IMMUTABILITY — every sample present in HEAD is still present, unchanged, byte for byte. The slice is
//      additive; nothing was reworded to make a number move.
//   2. COVERAGE — every one of the seven obs-* tells in data/obfuscation-signal.js is exercised by at least
//      one genuinely benign sample. This is the assertion that would have caught the blind spot.
//   3. SEPARATION — an INJECTED engine whose obf-deliberate-obscurity drops the directive requirement now
//      scores materially worse on this corpus than the shipped one. Before the slice, the two scored
//      identically (14/501 both), which is exactly what "blind" means.
//
// Nothing here modifies a detector. The variant in test 3 is built by mapping the exported DETECTORS array
// to a copy — data/detectors.js and data/obfuscation-signal.js are read-only to this file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { obfuscationTells, obscured, OBFUSCATION_TELLS } from "../data/obfuscation-signal.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS_PATH = "test/redteam/benign-corpus-v2.json";
const raw = readFileSync(join(ROOT, CORPUS_PATH), "utf8");
const corpus = JSON.parse(raw);
const samples = corpus.benign;
const slice = samples.filter((s) => String(s.category).startsWith("obf-"));

// The fixed, content-free obscurity vocabulary this slice is authored against.
const OBS_TELLS = OBFUSCATION_TELLS.filter((t) => t.g === "obs").map((t) => t.id);

// ---------------------------------------------------------------------------------------------------
// 1. IMMUTABILITY of everything that was already here
// ---------------------------------------------------------------------------------------------------

function headCorpus() {
  const out = execFileSync("git", ["show", `HEAD:${CORPUS_PATH}`], { cwd: ROOT, maxBuffer: 32 * 1024 * 1024 });
  return JSON.parse(out.toString("utf8"));
}

test("every sample committed at HEAD is still present, in order, byte-identical", () => {
  const head = headCorpus();
  assert.ok(head.benign.length > 0, "HEAD corpus is empty — the git lookup returned nothing usable");
  assert.ok(
    samples.length >= head.benign.length,
    `samples were REMOVED: HEAD has ${head.benign.length}, working tree has ${samples.length}`
  );
  for (let i = 0; i < head.benign.length; i++) {
    const a = head.benign[i];
    const b = samples[i];
    assert.equal(b?.id, a.id, `sample #${i} changed identity: HEAD ${a.id} vs ${b?.id}`);
    assert.equal(
      JSON.stringify(b),
      JSON.stringify(a),
      `sample ${a.id} was modified — this corpus is append-only`
    );
  }
});

test("no id present at HEAD has disappeared, and no id is duplicated", () => {
  const head = headCorpus();
  const now = new Set(samples.map((s) => s.id));
  assert.equal(now.size, samples.length, "duplicate ids in the working-tree corpus");
  for (const s of head.benign) assert.ok(now.has(s.id), `sample ${s.id} was removed from the corpus`);
});

test("the raw byte prefix of the benign array is unchanged", () => {
  // Stronger than the parsed comparison above: proves the additions are a pure APPEND at the end of the
  // array, not a reserialisation that happened to round-trip to the same objects.
  const headRaw = execFileSync("git", ["show", `HEAD:${CORPUS_PATH}`], { cwd: ROOT, maxBuffer: 32 * 1024 * 1024 }).toString("utf8");
  const marker = '"benign": [';
  const h = headRaw.slice(headRaw.indexOf(marker));
  const n = raw.slice(raw.indexOf(marker));
  const TAIL = "\n    }\n  ]\n}\n";
  assert.ok(h.endsWith(TAIL), "HEAD corpus does not end in the expected array tail");
  const headBody = h.slice(0, h.length - TAIL.length);
  assert.ok(
    n.startsWith(headBody),
    "the benign array no longer starts with HEAD's bytes — an existing sample was edited or reformatted"
  );
});

// ---------------------------------------------------------------------------------------------------
// 2. The slice itself, and the COVERAGE that makes it worth having
// ---------------------------------------------------------------------------------------------------

test("the obfuscation-shaped slice is large enough to price the family", () => {
  assert.ok(slice.length >= 80, `expected >= 80 obfuscation-shaped benign samples, got ${slice.length}`);
});

test("every obfuscation-shaped sample is labelled with a bucket, a twin and a mimicked signal", () => {
  const vocab = new Set(OBS_TELLS);
  const buckets = new Set();
  for (const s of slice) {
    assert.equal(s.hard_negative, true, `${s.id} is obfuscation-shaped but not marked hard_negative`);
    assert.ok(typeof s.twin_of === "string" && s.twin_of.length, `${s.id} has no twin_of`);
    assert.ok("mimics" in s, `${s.id} has no mimics field`);
    if (s.mimics !== null) {
      assert.ok(vocab.has(s.mimics), `${s.id} mimics "${s.mimics}", which is not an obs-* tell id`);
    }
    buckets.add(s.category);
  }
  assert.ok(buckets.size >= 8, `expected >= 8 obfuscation buckets, got ${buckets.size}: ${[...buckets].join(",")}`);
});

test("the corpus now contains a real population of obscurity-shaped benign text", () => {
  // The blind spot in one number. Before this slice, exactly 1 of 509 samples tripped any obs-* tell, so
  // the corpus could not distinguish an obscurity detector from a coin flip.
  const n = samples.filter((s) => obscured(s.text)).length;
  assert.ok(n >= 40, `only ${n} benign samples trip an obs-* tell — the corpus is still blind to this family`);
});

test("EVERY obs-* tell is exercised by at least one genuinely benign sample", () => {
  // This is the assertion whose absence let a 48-FP variant through a green dashboard. A detector signal
  // with no benign coverage has an unmeasured false-positive rate, whatever the dashboard says.
  const covered = new Set();
  for (const s of samples) for (const t of obfuscationTells(s.text)) covered.add(t);
  const missing = OBS_TELLS.filter((t) => !covered.has(t));
  assert.deepEqual(missing, [], `obs tells with ZERO benign coverage: ${missing.join(", ")}`);
});

test("no live-shaped provider secret entered with the new slice", () => {
  const forbidden = [
    /sk_live_[0-9a-zA-Z]{10,}/,
    /sk_test_51[0-9a-zA-Z]{10,}/,
    /xox[baprs]-[0-9]{8,}-[0-9]{8,}/,
    /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    /AIza[0-9A-Za-z_-]{35}/,
    /glpat-[0-9A-Za-z_-]{20}/
  ];
  for (const s of slice) {
    for (const re of forbidden) {
      assert.equal(re.test(s.text), false, `${s.id} contains a live-shaped secret matching ${re}`);
    }
  }
});

// ---------------------------------------------------------------------------------------------------
// 3. SEPARATION — the corpus can now tell the two obfuscation variants apart
// ---------------------------------------------------------------------------------------------------

// Build an engine from a COPY of DETECTORS whose obf-deliberate-obscurity fires on obscurity alone. The
// obscurity-only variant in the report used a catch-all prefilter (the shipped prefilter words —
// decode / apply / encoded — do most of the gating on their own), so that is what is modelled here.
// data/detectors.js and data/obfuscation-signal.js are NOT modified; only the local array copy is.
function obscurityOnlyDetectors() {
  return DETECTORS.map((d) =>
    d.detectorId === "obf-deliberate-obscurity"
      ? { ...d, patterns: [/[\s\S]/], refine: (_m, text) => obscured(text) }
      : d
  );
}

async function fpCount(detectors) {
  const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const engine = new DetectionEngine(threats, detectors, CONTENT_RULES);
  const counted = samples.filter((s) => !s.ambiguous);
  let fp = 0;
  for (const s of counted) {
    const findings = await engine.scan(s.text, s.stage || "prompt");
    if (findings.length) fp++;
  }
  return { fp, counted: counted.length };
}

test("the obscurity-only variant is now visibly worse than the shipped one", async () => {
  const shipped = await fpCount(DETECTORS);
  const relaxed = await fpCount(obscurityOnlyDetectors());
  const delta = relaxed.fp - shipped.fp;
  // Measured when this slice landed: shipped 20/602, obscurity-only 66/602 (delta 46). On the 509-sample
  // corpus that preceded it, both scored 14/501 — delta ZERO. A floor of 25 keeps a large margin over that
  // while not pinning a number that other people's detector work would trip.
  assert.ok(
    delta >= 25,
    `obscurity-only variant costs only ${delta} extra FPs (shipped ${shipped.fp}/${shipped.counted}, ` +
      `relaxed ${relaxed.fp}/${relaxed.counted}) — the corpus has stopped pricing this detector family`
  );
});

test("the obscurity-only variant fires on a broad spread of the slice, not one outlier", async () => {
  const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const engine = new DetectionEngine(threats, obscurityOnlyDetectors(), CONTENT_RULES);
  const buckets = new Set();
  for (const s of samples) {
    const findings = await engine.scan(s.text, s.stage || "prompt");
    if (findings.some((f) => f.detectorId === "obf-deliberate-obscurity")) buckets.add(s.category);
  }
  assert.ok(buckets.size >= 6, `obscurity-only fires in only ${buckets.size} buckets: ${[...buckets].join(",")}`);
});
