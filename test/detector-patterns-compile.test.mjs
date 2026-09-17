// A detector with a `refine` gate compiles its patterns through the ReDoS guard (src/engine.js
// _matchDetector) and silently skips any pattern the guard rejects. That left two secret detectors
// dead from v0.63.2 until this test existed. A rejected pattern here is a detector that never fires.
import { test } from "node:test";
import assert from "node:assert/strict";
import { safeRegex } from "../src/safe-regex.js";
import { DETECTORS } from "../data/detectors.js";
import { SECRET_DETECTORS } from "../data/secrets-patterns.js";

function patternsOf(list) {
  const out = [];
  for (const d of list) if (d.refine) for (const [i, p] of (d.patterns || (d.pattern ? [d.pattern] : [])).entries()) {
    if (p instanceof RegExp) out.push({ id: d.detectorId || d.id || d.name, i, p });
  }
  return out;
}

const KNOWN_DEAD = new Set([]);

test("every bundled pattern compiles under the ReDoS guard", () => {
  const all = [...patternsOf(DETECTORS), ...patternsOf(SECRET_DETECTORS)];
  assert.ok(all.length > 0, "expected refine-gated detectors to exist");
  const dead = all
    .filter(({ p }) => !safeRegex(p.source, p.flags.includes("g") ? p.flags : p.flags + "g"))
    .map(({ id, i }) => `${id}#${i}`)
    .filter((k) => !KNOWN_DEAD.has(k));
  assert.deepEqual(dead, [], `patterns the engine would silently skip: ${dead.join(", ")}`);
});
