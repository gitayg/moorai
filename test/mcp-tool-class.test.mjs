// Default MCP tool policy by class (policy mcpToolClassDefaults / mcpToolClasses, cli/mcp-tool-class.mjs):
// classification precedence (override → annotation, only when stricter → name heuristic → unknown), the
// verdict per class, the field's validation, and the explicit argument allow-list that skips it.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-tool-class.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyMcpTool, decideMcpToolClass, heuristicClass, annotationClass, toolClassDefaults, createAnnotationClasses, toolClassAlert } from "../cli/mcp-tool-class.mjs";

const DEFAULTS = { read: "allow", write: "ask", destructive: "block", unknown: "ask" };
const P = (extra = {}) => ({ mcpToolClassDefaults: DEFAULTS, ...extra });

test("name heuristic: destructive verbs beat write verbs beat read verbs; anything else is unknown", () => {
  assert.equal(heuristicClass("list_issues"), "read");
  assert.equal(heuristicClass("getFileContents"), "read");
  assert.equal(heuristicClass("search-code"), "read");
  assert.equal(heuristicClass("create_issue"), "write");
  assert.equal(heuristicClass("sendEmail"), "write");
  assert.equal(heuristicClass("delete_repository"), "destructive");
  assert.equal(heuristicClass("get_and_delete"), "destructive", "any destructive token wins");
  assert.equal(heuristicClass("force_push"), "destructive");
  assert.equal(heuristicClass("salesforce_query"), "unknown", "tokens match whole words only");
  assert.equal(heuristicClass("frobnicate"), "unknown");
});

test("annotations: only explicit hints count; destructiveHint wins over readOnlyHint", () => {
  assert.equal(annotationClass({ destructiveHint: true }), "destructive");
  assert.equal(annotationClass({ readOnlyHint: false }), "write");
  assert.equal(annotationClass({ readOnlyHint: true }), "read");
  assert.equal(annotationClass({ readOnlyHint: true, destructiveHint: true }), "destructive");
  assert.equal(annotationClass({ idempotentHint: true, openWorldHint: false }), null, "no read/write hint: no class (spec defaults are not applied)");
  assert.equal(annotationClass(null), null);
});

test("precedence: an admin override wins outright, in either direction", () => {
  const p = P({ mcpToolClasses: { github: { delete_branch: "read", list_secrets: "destructive" } } });
  assert.deepEqual(classifyMcpTool(p, { server: "github", tool: "delete_branch", annotation: "destructive" }), { toolClass: "read", source: "override" });
  assert.deepEqual(classifyMcpTool(p, { server: "github", tool: "list_secrets" }), { toolClass: "destructive", source: "override" });
  assert.deepEqual(classifyMcpTool(p, { server: "github", tool: "mcp__github__list_secrets" }), { toolClass: "destructive", source: "override" }, "the hook's mcp__<server>__<tool> name finds the same override");
  assert.deepEqual(classifyMcpTool(p, { server: "other", tool: "list_secrets" }), { toolClass: "read", source: "heuristic" }, "an override is per server");
  const bad = P({ mcpToolClasses: { github: { create_issue: "harmless" } } });
  assert.deepEqual(classifyMcpTool(bad, { server: "github", tool: "create_issue" }), { toolClass: "write", source: "heuristic" }, "an override naming no class is ignored");
});

test("precedence: an annotation can make a tool more restricted than its name says", () => {
  assert.deepEqual(classifyMcpTool(P(), { server: "s", tool: "get_report", annotation: "destructive" }), { toolClass: "destructive", source: "annotation" });
  assert.deepEqual(classifyMcpTool(P(), { server: "s", tool: "list_rows", annotation: "write" }), { toolClass: "write", source: "annotation" });
  assert.deepEqual(classifyMcpTool(P(), { server: "s", tool: "frobnicate", annotation: "destructive" }), { toolClass: "destructive", source: "annotation" });
});

test("precedence: an annotation can NEVER loosen what the name heuristic says", () => {
  assert.deepEqual(classifyMcpTool(P(), { server: "s", tool: "delete_repo", annotation: "read" }), { toolClass: "destructive", source: "heuristic" });
  assert.deepEqual(classifyMcpTool(P(), { server: "s", tool: "create_issue", annotation: "read" }), { toolClass: "write", source: "heuristic" });
  assert.deepEqual(classifyMcpTool(P(), { server: "s", tool: "delete_repo", annotation: "write" }), { toolClass: "destructive", source: "heuristic" });
  // unknown → read would loosen an "ask" to an "allow": refused.
  assert.deepEqual(classifyMcpTool(P(), { server: "s", tool: "frobnicate", annotation: "read" }), { toolClass: "unknown", source: "heuristic" });
  // Measured on the verdicts the policy gives: with unknown "block", a write annotation (ask) is looser.
  const strictUnknown = { mcpToolClassDefaults: { ...DEFAULTS, unknown: "block" } };
  assert.deepEqual(classifyMcpTool(strictUnknown, { server: "s", tool: "frobnicate", annotation: "write" }), { toolClass: "unknown", source: "heuristic" });
  assert.equal(decideMcpToolClass(P(), { server: "s", tool: "delete_repo", annotation: "read" }).decision, "deny");
});

test("verdict per class: allow / ask / block → allow / ask / deny, with a content-free reason", () => {
  const p = P();
  assert.equal(decideMcpToolClass(p, { server: "s", tool: "list_issues" }).decision, "allow");
  assert.equal(decideMcpToolClass(p, { server: "s", tool: "create_issue" }).decision, "ask");
  const d = decideMcpToolClass(p, { server: "s", tool: "delete_repo" });
  assert.equal(d.decision, "deny");
  assert.equal(d.configured, "block");
  assert.match(d.reason, /delete_repo is a destructive MCP tool \(heuristic\)/);
  assert.equal(decideMcpToolClass(p, { server: "s", tool: "frobnicate" }).decision, "ask");
});

test("absent or invalid field: off — no verdict for any tool", () => {
  assert.equal(toolClassDefaults({}), null);
  assert.equal(toolClassDefaults(null), null);
  assert.equal(toolClassDefaults({ mcpToolClassDefaults: "block" }), null);
  assert.equal(toolClassDefaults({ mcpToolClassDefaults: ["block"] }), null);
  assert.equal(toolClassDefaults({ mcpToolClassDefaults: { destructive: "deny", write: true } }), null, "values outside allow/ask/block are ignored");
  for (const tool of ["delete_repo", "create_issue", "frobnicate"]) assert.equal(decideMcpToolClass({}, { server: "s", tool }), null);
  // A class the policy does not name gets no verdict.
  const partial = { mcpToolClassDefaults: { destructive: "block" } };
  assert.equal(decideMcpToolClass(partial, { server: "s", tool: "create_issue" }), null);
  assert.equal(decideMcpToolClass(partial, { server: "s", tool: "drop_table" }).decision, "deny");
});

test("an explicit mcpToolRules allow-list for the tool skips the class verdict; a deny-only rule does not", () => {
  assert.equal(decideMcpToolClass(P({ mcpToolRules: { delete_repo: { allow: ["^\\{\"name\":\"scratch-"] } } }), { server: "s", tool: "delete_repo" }), null);
  assert.equal(decideMcpToolClass(P({ mcpToolRules: { delete_repo: { deny: ["prod"] } } }), { server: "s", tool: "delete_repo" }).decision, "deny");
});

test("annotation tracker keeps the strictest class each tool name has shown: a re-listing cannot loosen it", () => {
  const a = createAnnotationClasses();
  a.observe([{ name: "get_report", annotations: { destructiveHint: true } }, { name: "plain" }]);
  assert.equal(a.get("get_report"), "destructive");
  assert.equal(a.get("plain"), null);
  a.observe([{ name: "get_report", annotations: { readOnlyHint: true } }]);
  assert.equal(a.get("get_report"), "destructive");
  a.observe([{ name: "plain", annotations: { readOnlyHint: false } }]);
  assert.equal(a.get("plain"), "write");
});

test("the alert is content-free: class, verdict, source, server, tool, reasonCode", () => {
  const tc = decideMcpToolClass(P(), { server: "github", tool: "delete_repo" });
  const a = toolClassAlert(tc, { tool: "delete_repo", server: "github", toolPrefix: "desktop", decision: "deny" });
  assert.deepEqual(a, { threatId: 0, category: "MCP: tool blocked by class default", riskLevel: "Blocked", stage: "mcp", tool: "desktop:delete_repo", decision: "deny", reasonCode: "MCP_TOOL_CLASS", toolClass: "destructive", toolClassSource: "heuristic", mcpServer: "github", contentHash: "mcp:tool-class:destructive:block" });
});

test("SDK decideToolCall mirrors the hook: class verdict by name, merged by rank; absent field unchanged", async () => {
  const { decideToolCall } = await import("../packages/agent-sdk/src/index.mjs");
  const { buildEngine } = await import("../cli/hook-core.mjs");
  const policy = { captureTier: "content-free", ...P() };
  const engine = buildEngine(policy);
  const d = (p, tool) => decideToolCall(engine, p, { tool, toolInput: { name: "x" }, cwd: "/w/proj", systemConfig: null });
  assert.equal(d(policy, "mcp__github__list_issues").decision, "allow");
  assert.equal(d(policy, "mcp__github__create_issue").decision, "ask");
  const del = d(policy, "mcp__github__delete_repository");
  assert.equal(del.decision, "deny");
  assert.ok(del.signals.some((s) => s.category === "MCP: tool blocked by class default"));
  assert.equal(d({ captureTier: "content-free" }, "mcp__github__delete_repository").decision, "allow");
});
