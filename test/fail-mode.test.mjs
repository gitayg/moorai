// cli/fail-mode.mjs resolveFailMode: the administrator decides what a surface does when it cannot reach
// a decision. Precedence: the root-owned admin binding (surface key, then default), then the signed
// policy (surface key, then default), then the caller's fallback. Invalid values are ignored with a
// warning and never throw.
//
//   node --test --import ./test/hermetic-env.mjs test/fail-mode.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveFailMode, effectiveFailModes, FAIL_SURFACES, FAIL_MODES } from "../cli/fail-mode.mjs";

const quiet = { warn: () => {} };

test("contract constants are the frozen ones", () => {
  assert.deepEqual([...FAIL_SURFACES], ["hook", "modelProxy", "mcpGateway", "inferenceHook"]);
  assert.deepEqual([...FAIL_MODES], ["open", "closed"]);
});

test("no admin, no policy: the fallback decides (default open)", () => {
  assert.deepEqual(resolveFailMode(null, "hook", quiet), { mode: "open", source: "default" });
  assert.deepEqual(resolveFailMode(null, "hook", { ...quiet, fallback: "closed" }), { mode: "closed", source: "default" });
});

test("the signed policy's surface key decides, then its default", () => {
  assert.deepEqual(resolveFailMode({ failMode: { hook: "closed" } }, "hook", quiet), { mode: "closed", source: "policy" });
  assert.deepEqual(resolveFailMode({ failMode: { default: "closed" } }, "mcpGateway", quiet), { mode: "closed", source: "policy" });
  assert.deepEqual(resolveFailMode({ failMode: { default: "closed", modelProxy: "open" } }, "modelProxy", quiet), { mode: "open", source: "policy" });
  // a key for another surface does not leak
  assert.deepEqual(resolveFailMode({ failMode: { hook: "closed" } }, "mcpGateway", quiet), { mode: "open", source: "default" });
});

test("the policy beats the caller's fallback in both directions", () => {
  assert.deepEqual(resolveFailMode({ failMode: { inferenceHook: "open" } }, "inferenceHook", { ...quiet, fallback: "closed" }), { mode: "open", source: "policy" });
  assert.deepEqual(resolveFailMode({ failMode: { inferenceHook: "closed" } }, "inferenceHook", { ...quiet, fallback: "open" }), { mode: "closed", source: "policy" });
});

test("the admin binding wins over the policy, surface key then default, in both directions", () => {
  const policy = { failMode: { hook: "closed", default: "closed" } };
  assert.deepEqual(resolveFailMode(policy, "hook", { ...quiet, admin: { failMode: { hook: "open" } } }), { mode: "open", source: "admin" });
  assert.deepEqual(resolveFailMode(policy, "hook", { ...quiet, admin: { failMode: { default: "open" } } }), { mode: "open", source: "admin" });
  assert.deepEqual(resolveFailMode({ failMode: { hook: "open" } }, "hook", { ...quiet, admin: { failMode: { default: "closed" } } }), { mode: "closed", source: "admin" });
  // admin surface key beats admin default
  assert.deepEqual(resolveFailMode(null, "hook", { ...quiet, admin: { failMode: { default: "closed", hook: "open" } } }), { mode: "open", source: "admin" });
  // an admin binding that says nothing about fail mode leaves the policy in charge
  assert.deepEqual(resolveFailMode(policy, "hook", { ...quiet, admin: { serverUrl: "https://c.example", tenant: "acme" } }), { mode: "closed", source: "policy" });
});

test("invalid values are ignored with a warning, never thrown, and the next source decides", () => {
  const warnings = [];
  const warn = (m) => warnings.push(m);
  assert.deepEqual(resolveFailMode({ failMode: { hook: "CLOSED", default: "closed" } }, "hook", { warn }), { mode: "closed", source: "policy" });
  assert.deepEqual(resolveFailMode({ failMode: { hook: 1 } }, "hook", { warn }), { mode: "open", source: "default" });
  assert.deepEqual(resolveFailMode({ failMode: "closed" }, "hook", { warn }), { mode: "open", source: "default" });
  assert.deepEqual(resolveFailMode({ failMode: ["closed"] }, "hook", { warn }), { mode: "open", source: "default" });
  assert.deepEqual(resolveFailMode(null, "hook", { warn, admin: { failMode: { hook: "deny" } } }), { mode: "open", source: "default" });
  assert.deepEqual(resolveFailMode(null, "hook", { warn, fallback: "maybe" }), { mode: "open", source: "default" });
  assert.ok(warnings.length >= 6, `each invalid value warns (${warnings.length})`);
  for (const w of warnings) assert.ok(!/CLOSED|deny|maybe/.test(w), `a warning names the key, not the value: ${w}`);
});

test("garbage inputs never throw", () => {
  for (const p of [undefined, null, 0, "x", [], { failMode: null }, { failMode: { __proto__: { hook: "closed" } } }]) {
    assert.doesNotThrow(() => resolveFailMode(p, "hook", quiet));
  }
  assert.deepEqual(resolveFailMode({ failMode: Object.create({ hook: "closed" }) }, "hook", quiet), { mode: "open", source: "default" }, "an inherited key is not a policy value");
  assert.doesNotThrow(() => resolveFailMode(null, "hook", { ...quiet, admin: "closed" }));
  assert.doesNotThrow(() => resolveFailMode(null, "hook"));
});

test("an unknown surface still honours failMode.default, and warns", () => {
  const warnings = [];
  assert.deepEqual(resolveFailMode({ failMode: { default: "closed", hook: "open" } }, "nope", { warn: (m) => warnings.push(m) }), { mode: "closed", source: "policy" });
  assert.equal(warnings.length, 1);
});

test("effectiveFailModes reports every surface as {mode, source}", () => {
  const r = effectiveFailModes({ failMode: { mcpGateway: "closed" } }, { admin: { failMode: { hook: "closed" } }, ...quiet });
  assert.deepEqual(r, {
    hook: { mode: "closed", source: "admin" },
    modelProxy: { mode: "open", source: "default" },
    mcpGateway: { mode: "closed", source: "policy" },
    inferenceHook: { mode: "open", source: "default" }
  });
});
