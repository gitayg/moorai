// The console's approval gate (mcpGate) narrows mcpAllow to the approved set, which is empty until an admin
// approves a server. With the gate on, an empty list denies every server; with it off, empty is no allow-list.
import { test } from "node:test";
import assert from "node:assert/strict";
import { decideMcpServer } from "../cli/hook-core.mjs";

test("gate off: an empty or missing allow-list blocks nothing", () => {
  assert.equal(decideMcpServer({ mcpAllow: [] }, "files").decision, "allow");
  assert.equal(decideMcpServer({}, "files").decision, "allow");
  assert.equal(decideMcpServer(undefined, "files").decision, "allow");
});

test("gate on, nothing approved yet: every server is denied", () => {
  const d = decideMcpServer({ mcpGate: true, mcpAllow: [] }, "files");
  assert.equal(d.decision, "deny");
  assert.match(d.reason, /not approved/);
  assert.equal(decideMcpServer({ mcpGate: true }, "files").decision, "deny");
});

test("gate on: an approved server is allowed, any other is denied", () => {
  const p = { mcpGate: true, mcpAllow: ["files"] };
  assert.equal(decideMcpServer(p, "files").decision, "allow");
  assert.equal(decideMcpServer(p, "other").decision, "deny");
});
