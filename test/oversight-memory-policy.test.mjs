// Weakening oversight (#84): oversight.memoryFiles and oversight.protectMemoryFiles set together. When they
// conflict the stricter one wins: protectMemoryFiles: false never turns off a memoryFiles the admin set, and
// protectMemoryFiles: true raises "off" and "notify" to #84's action.
//
//   node --test --import ./test/hermetic-env.mjs test/oversight-memory-policy.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { oversightPolicy } from "../cli/oversight-surfaces.mjs";
import { decideOversight } from "../cli/hook-core.mjs";

const pol = (o, extra = {}) => ({ oversight: { v: 1, ...o }, ...extra });
const memory = (o) => oversightPolicy(pol(o), () => {}).memory;
const decide = (o, extra) => decideOversight(pol(o, extra), ["memory-file"]).decision;

test("protectMemoryFiles: false does not override a memoryFiles the admin set", () => {
  assert.equal(memory({ memoryFiles: "block", protectMemoryFiles: false }), "block");
  assert.equal(decide({ memoryFiles: "block", protectMemoryFiles: false }), "deny");
  assert.equal(memory({ memoryFiles: "ask", protectMemoryFiles: false }), "ask");
  assert.equal(decide({ memoryFiles: "ask", protectMemoryFiles: false }), "ask");
  assert.equal(memory({ memoryFiles: "notify", protectMemoryFiles: false }), "notify", "notify still alerts: stricter than off");
  assert.equal(memory({ memoryFiles: "explode", protectMemoryFiles: false }), "inherit", "an invalid memoryFiles takes #84's action, stricter than off");
});

test("protectMemoryFiles: true raises off and notify to #84's action", () => {
  assert.equal(memory({ memoryFiles: "off", protectMemoryFiles: true }), "inherit");
  assert.equal(decide({ memoryFiles: "off", protectMemoryFiles: true }), "ask");
  assert.equal(memory({ memoryFiles: "notify", protectMemoryFiles: true }), "inherit");
  assert.equal(decide({ memoryFiles: "notify", protectMemoryFiles: true }), "ask");
  assert.equal(memory({ memoryFiles: "block", protectMemoryFiles: true }), "block");
});

test("one key alone keeps its meaning", () => {
  assert.equal(memory({ protectMemoryFiles: false }), false);
  assert.equal(memory({ memoryFiles: "off" }), false);
  assert.equal(memory({ protectMemoryFiles: true }), "inherit");
  assert.equal(memory({}), "default");
});
