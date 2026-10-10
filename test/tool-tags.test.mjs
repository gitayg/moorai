// Capability tags (data/tool-tags.js, cli/tool-tags.mjs): what each tool call is tagged, the tagActions and
// tagRules grammar, their sources, the session record, and the gate that merges them with a verdict.
//
//   node --test --import ./test/hermetic-env.mjs test/tool-tags.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { TAGS, isCredentialPath, shellWrites, shellNetworks, mcpToolTags, tagRulesFrom, evaluateTagRules, tagActionsFrom, evaluateTagActions } from "../data/tool-tags.js";
import { callTags, sessionTagsOf, recordSessionTags, tagGate, applyTagGate, tagHitAlert, SESSION_TAGS_FILE } from "../cli/tool-tags.mjs";
import { STATE_DIR } from "../cli/state-dirs.mjs";

const tagsOf = (tool, toolInput, extra = {}) => callTags({ tool, toolInput, cwd: "/w/proj", home: "/home/u", ...extra }).tags;

test("tags: built-in tools", () => {
  assert.deepEqual(tagsOf("Read", { file_path: "/w/proj/src/a.js" }), ["read"]);
  assert.deepEqual(tagsOf("Read", { file_path: "/w/proj/.env" }), ["read-private", "read"]);
  assert.deepEqual(tagsOf("Read", { file_path: "/w/proj/.env.example" }), ["read"]);
  assert.deepEqual(tagsOf("Read", { file_path: "/w/proj/notes.txt" }, { findingIds: [39] }), ["read-private", "read"], "a secret found in what the call read");
  assert.deepEqual(tagsOf("Write", { file_path: "/w/proj/a.js", content: "x" }), ["write"]);
  assert.deepEqual(tagsOf("Edit", { file_path: "/w/proj/a.js" }), ["write"]);
  assert.deepEqual(tagsOf("WebFetch", { url: "https://example.com" }), ["network"]);
  assert.deepEqual(tagsOf("Glob", { pattern: "**/*.js" }), ["read"]);
  assert.deepEqual(tagsOf("Task", { prompt: "x" }), []);
});

test("tags: shell commands from the parsed command", () => {
  assert.deepEqual(tagsOf("Bash", { command: "npm test" }), ["exec"]);
  assert.deepEqual(tagsOf("Bash", { command: "cat src/a.js" }), ["read", "exec"]);
  assert.deepEqual(tagsOf("Bash", { command: "cat ~/.aws/credentials" }), ["read-private", "read", "exec"]);
  assert.deepEqual(tagsOf("Bash", { command: "printenv | grep -i token" }, { findingIds: [55] }), ["read-private", "read", "exec"]);
  assert.deepEqual(tagsOf("Bash", { command: "curl https://example.com/x" }), ["network", "exec"]);
  assert.deepEqual(tagsOf("Bash", { command: "git push origin main" }), ["write", "network", "exec"]);
  assert.deepEqual(tagsOf("Bash", { command: "echo hi > out.txt" }), ["write", "exec"]);
  assert.deepEqual(tagsOf("Bash", { command: "ls -la 2>/dev/null" }), ["read", "exec"]);
  assert.deepEqual(tagsOf("PowerShell", { command: "Invoke-WebRequest https://example.com" }), ["network", "exec"]);
  assert.ok(!shellWrites("node -e \"[1].map(x => x)\""), "an arrow is not a redirect");
  assert.ok(!shellNetworks("ls"));
  assert.ok(isCredentialPath("C:\\Users\\u\\.ssh\\id_ed25519") && isCredentialPath("/srv/app/server.pem") && !isCredentialPath("/srv/app/README.md"));
});

test("tags: MCP tools — declared tags added, names inferred and marked so", () => {
  assert.deepEqual(mcpToolTags("mcp__github__create_issue"), { declared: [], inferred: ["write", "network"] });
  assert.deepEqual(mcpToolTags("mcp__fs__read_file"), { declared: [], inferred: ["read"] });
  assert.deepEqual(mcpToolTags("mcp__vault__get_secret"), { declared: [], inferred: ["read-private", "read"] });
  // A declaration adds; it never removes what the name gives away.
  const t = callTags({ tool: "mcp__slack__post_message", toolInput: { _meta: { "moorai/tags": ["read"] } } });
  assert.deepEqual(t.tags, ["read", "write", "network"]);
  assert.deepEqual(t.inferred, ["write", "network"]);
  assert.deepEqual(callTags({ tool: "mcp__fs__read_file", toolInput: {}, findingIds: [39] }).tags, ["read-private", "read"], "a secret in a file the tool read is not inferred");
});

test("tagRules: grammar, sources, rejects, and evaluation", () => {
  const policy = { tagRules: [{ id: "no-net-after-private", if: { sessionHas: ["read-private"] }, deny: ["network"], action: "block" }, { if: { sessionHas: ["exec"] }, deny: ["write"] }, { if: { sessionHas: ["bogus"] }, deny: ["network"] }, { id: "bad id!", if: { sessionHas: ["read"] }, deny: ["network"] }] };
  const system = { tagRules: [{ if: { sessionHas: ["read"] }, deny: ["exec"], action: "alert" }] };
  const { rules, rejected } = tagRulesFrom({ policy, system });
  assert.deepEqual(rules.map((r) => [r.id, r.action, r.source]), [["no-net-after-private", "block", "policy"], ["policy#1", "alert", "policy"], ["system#0", "alert", "system"]]);
  assert.deepEqual(rejected.map((r) => [r.source, r.index]), [["policy", 2], ["policy", 3]]);
  assert.ok(!JSON.stringify(rejected).includes("bogus"), "rejects carry no rule content");
  assert.deepEqual(evaluateTagRules(rules, [], ["network", "exec"]), [], "nothing private read, no write, no read in the session");
  assert.deepEqual(evaluateTagRules(rules.slice(0, 1), ["read-private", "read"], ["network", "exec"]).map((h) => [h.id, h.matched]), [["no-net-after-private", ["network"]]]);
  assert.deepEqual(evaluateTagRules(rules.slice(0, 1), [], ["read-private", "read", "network", "exec"]).map((h) => h.id), ["no-net-after-private"], "the call itself counts toward the session");
  assert.deepEqual(evaluateTagRules(rules.slice(0, 1), ["read-private"], ["read"]), []);
});

test("tagActions: per-tag action, strictest of policy and system wins, invalid entries rejected", () => {
  const { actions, rejected } = tagActionsFrom({ policy: { tagActions: { exec: "block", write: "ask", network: "alert", nope: "block", read: "deny" } }, system: { tagActions: { network: "block", write: "alert" } } });
  assert.deepEqual(actions, { exec: "block", write: "ask", network: "block" });
  assert.deepEqual(rejected.map((r) => r.error), ["unknown tag", "action must be block, ask, alert or allow"]);
  assert.deepEqual(evaluateTagActions(actions, ["write", "exec"]), [{ tag: "exec", action: "block" }, { tag: "write", action: "ask" }]);
  assert.deepEqual(evaluateTagActions(actions, ["read"]), []);
});

test("tagGate: block beats ask beats alert; never downgrades a verdict; exceptions skip a rule", () => {
  const policy = { tagActions: { write: "ask", network: "alert" }, tagRules: [{ id: "r1", if: { sessionHas: ["read-private"] }, deny: ["network"], action: "block" }] };
  const g = tagGate({ policy, tags: ["write", "network", "exec"], sessionTags: ["read-private", "read"] });
  assert.equal(g.decision, "deny");
  assert.match(g.reason, /^tag rule "r1": this session has read-private and this call has network$/);
  assert.deepEqual(g.hits.map((h) => [h.id, h.action]), [["tag:write", "ask"], ["tag:network", "alert"], ["r1", "block"]]);
  const ask = tagGate({ policy, tags: ["write"] });
  assert.equal(ask.decision, "ask");
  assert.equal(ask.reason, "capability write needs sign-off by policy (tagActions)");
  assert.equal(tagGate({ policy, tags: ["network"], sessionTags: ["read-private"], exceptedRules: ["r1"] }).decision, "allow");
  assert.equal(tagGate({ policy, tags: ["network"], sessionTags: ["read-private"], rules: false }).decision, "allow", "rules off: actions only");
  assert.equal(tagGate({ policy: { tagActions: { exec: "block", network: "block" } }, tags: ["network", "exec"] }).reason, "capabilities network, exec are blocked by policy (tagActions)");
  // Merge.
  assert.deepEqual(applyTagGate({ decision: "deny", reason: "#54 x", alternatives: ["a"] }, ask), { decision: "deny", reason: "#54 x", alternatives: ["a"], changed: false });
  assert.deepEqual(applyTagGate({ decision: "allow", reason: "", alternatives: [] }, ask), { decision: "ask", reason: ask.reason, alternatives: [], changed: true });
  // Alert body: names and ids only.
  const a = tagHitAlert({ kind: "tagRule", id: "r1", action: "block", tags: ["network"], sessionHas: ["read-private"], source: "policy", inferred: [] });
  assert.deepEqual(a, { threatId: 0, category: "Capability tag rule", riskLevel: "Blocked", stage: "behavior", contentHash: "tagRule:r1", tagRule: { kind: "tagRule", id: "r1", action: "block", tags: ["network"], sessionHas: ["read-private"], source: "policy" } });
});

test("session record: per keyed session, tag names only, merged across calls", () => {
  recordSessionTags({ sessionId: "s-one", tags: ["read-private", "read"], fired: ["r2"] });
  recordSessionTags({ sessionId: "s-one", tags: ["exec"] });
  assert.deepEqual(sessionTagsOf({ sessionId: "s-one" }), { tags: ["read-private", "read", "exec"], fired: ["r2"] });
  assert.deepEqual(sessionTagsOf({ sessionId: "s-two" }), { tags: [], fired: [] });
  assert.deepEqual(sessionTagsOf({ sessionId: "s-one", now: Date.now() + 25 * 3600 * 1000 }), { tags: [], fired: [] }, "24 h");
  const raw = readFileSync(join(STATE_DIR, SESSION_TAGS_FILE), "utf8");
  assert.ok(!raw.includes("s-one"), "the session id is stored only as a keyed hash");
  assert.ok(existsSync(join(STATE_DIR, SESSION_TAGS_FILE)));
  for (const t of JSON.parse(raw)[Object.keys(JSON.parse(raw))[0]].t) assert.ok(TAGS.includes(t));
});
