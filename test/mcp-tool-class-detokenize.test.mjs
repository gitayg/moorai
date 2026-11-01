// The detokenize tool class (cli/mcp-tool-class.mjs): a tool that turns protected data readable. Its names,
// its built-in "ask" with mcpToolClassDefaults unset, the admin's verdict and override, annotations that never
// demote it, the approval-routing match key toolClass (cli/approval-routing.mjs), and the same class for the
// model proxy's function tools (model-proxy/business-tools.mjs).
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-tool-class-detokenize.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { detokenizeName, classifyMcpTool, decideMcpToolClass, toolClassDefaults, effectiveClassDefaults, toolClassAlert, TOOL_CLASSES } from "../cli/mcp-tool-class.mjs";
import { validateRule, ruleMatches, toolClassOf, approvalAlert, MATCH_KEYS, APPROVAL_REQUESTED } from "../cli/approval-routing.mjs";
import { classifyBusinessTool, businessToolActionsFrom, businessActionFor } from "../model-proxy/business-tools.mjs";

const POSITIVE = [
  "detokenize", "detokenize_card", "detokenise_value", "deTokenize", "de_tokenize", "decrypt", "decrypt_field", "decryptBlob", "kms_decrypt",
  "unseal", "unseal_vault", "unmask_pii", "un_mask", "unredact_document", "deanonymize_record", "de-anonymize", "reIdentify", "re_identify", "decipher_text", "unprotect_data",
  "get_secret", "get_secret_value", "read_secret", "fetch_secret", "reveal_password", "getPassword", "retrieve_credentials", "access_secret_version", "lookup_secret",
  "vault_read", "read_vault_secret", "get_vault_secret", "get_card_number", "getCardNumber", "get_pan", "read_cvv", "show_full_pan", "get_credit_card", "reveal_card_number"
];
const NEGATIVE = [
  "list_secrets", "get_secret_metadata", "get_secret_info", "describe_secret", "create_secret", "update_secret", "delete_secret", "rotate_secret", "list_vaults", "get_vault",
  "get_card", "get_cards", "list_cards", "create_card", "update_card", "move_card", "tokenize_card", "encrypt_file", "mask_pii", "redact_document", "anonymize_record", "hash_value",
  "reset_password", "set_password", "get_password_policy", "pan_camera", "panorama", "reveal_in_finder", "get_issue", "create_issue", "list_issues", "delete_repository",
  "secret_scan", "token_count", "get_token_usage", "decryption_status", "frobnicate", "Bash", ""
];

test("names: detokenize, decrypt, unseal, unmask, de-anonymize, a secret or vault value read, a card number read", () => {
  for (const n of POSITIVE) assert.equal(detokenizeName(n), true, n);
});

test("names: whole tokens only; listings, metadata, writes, protecting verbs and a board card are not detokenize", () => {
  for (const n of NEGATIVE) assert.equal(detokenizeName(n), false, n);
});

test("names: a server label naming a secret store makes a value-read tool of it detokenize, not its listing", () => {
  assert.equal(detokenizeName("get", "vault"), true);
  assert.equal(detokenizeName("mcp__vault__dump", "vault"), true);
  assert.equal(detokenizeName("read_item", "1password"), true);
  assert.equal(detokenizeName("list_items", "1password"), false);
  assert.equal(detokenizeName("get_status", "vault"), false);
  assert.equal(detokenizeName("get", "github"), false);
});

test("built-in default: detokenize asks with mcpToolClassDefaults unset (and with no policy); no other class gets a verdict", () => {
  assert.ok(TOOL_CLASSES.includes("detokenize"));
  assert.equal(toolClassDefaults({}), null, "the policy sets nothing");
  assert.deepEqual(effectiveClassDefaults({}), { detokenize: "ask" });
  for (const p of [{}, null, { mcpToolClassDefaults: "block" }, { mcpToolClassDefaults: { detokenize: "deny" } }]) {
    const d = decideMcpToolClass(p, { server: "pay", tool: "detokenize_card" });
    assert.equal(d.decision, "ask", JSON.stringify(p));
    assert.equal(d.toolClass, "detokenize");
    assert.match(d.reason, /detokenize_card is a detokenize MCP tool \(heuristic\); the built-in default for detokenize tools is ask/);
  }
  for (const tool of ["delete_repo", "create_issue", "list_issues", "frobnicate"]) assert.equal(decideMcpToolClass({}, { server: "s", tool }), null, tool);
  assert.equal(decideMcpToolClass({}, { server: "pay", tool: "mcp__pay__detokenize_card" }).decision, "ask", "the hook's mcp__ name");
});

test("admin verdict: mcpToolClassDefaults.detokenize allow / ask / block replaces the built-in", () => {
  const allow = decideMcpToolClass({ mcpToolClassDefaults: { detokenize: "allow" } }, { server: "pay", tool: "decrypt_field" });
  assert.equal(allow.decision, "allow");
  assert.match(allow.reason, /your organization's default for detokenize tools is allow/);
  assert.equal(decideMcpToolClass({ mcpToolClassDefaults: { detokenize: "block" } }, { server: "pay", tool: "decrypt_field" }).decision, "deny");
  assert.equal(decideMcpToolClass({ mcpToolClassDefaults: { write: "block" } }, { server: "pay", tool: "decrypt_field" }).decision, "ask", "setting another class keeps the built-in");
  assert.equal(decideMcpToolClass({ mcpToolClassDefaults: { detokenize: "block" }, mcpToolRules: { decrypt_field: { allow: ["^\\{\"id\":\"test-"] } } }, { server: "pay", tool: "decrypt_field" }), null, "an explicit argument allow-list for the tool skips it");
});

test("override: mcpToolClasses puts a tool into the class or takes it out", () => {
  const p = { mcpToolClasses: { crm: { fetch_record: "detokenize", decrypt_preview: "read" } } };
  assert.deepEqual(classifyMcpTool(p, { server: "crm", tool: "fetch_record" }), { toolClass: "detokenize", source: "override" });
  assert.equal(decideMcpToolClass(p, { server: "crm", tool: "fetch_record" }).decision, "ask");
  assert.deepEqual(classifyMcpTool(p, { server: "crm", tool: "decrypt_preview" }), { toolClass: "read", source: "override" });
  assert.equal(decideMcpToolClass(p, { server: "crm", tool: "decrypt_preview" }), null, "taken out: read has no verdict");
  assert.equal(decideMcpToolClass(p, { server: "other", tool: "decrypt_preview" }).decision, "ask", "an override is per server");
});

test("annotations never demote a detokenize name; a strictly stricter class verdict (annotation or verb) still wins", () => {
  assert.deepEqual(classifyMcpTool({}, { server: "s", tool: "decrypt_field", annotation: "read" }), { toolClass: "detokenize", source: "heuristic" });
  assert.deepEqual(classifyMcpTool({}, { server: "s", tool: "decrypt_field", annotation: "destructive" }), { toolClass: "detokenize", source: "heuristic" }, "destructive has no verdict: looser than ask");
  const tie = { mcpToolClassDefaults: { read: "ask", destructive: "ask", detokenize: "ask" } };
  assert.equal(classifyMcpTool(tie, { server: "s", tool: "decrypt_field", annotation: "read" }).toolClass, "detokenize", "a tie keeps detokenize");
  assert.equal(classifyMcpTool(tie, { server: "s", tool: "decrypt_field", annotation: "destructive" }).toolClass, "detokenize");
  const strict = { mcpToolClassDefaults: { destructive: "block" } };
  assert.deepEqual(classifyMcpTool(strict, { server: "s", tool: "decrypt_field", annotation: "destructive" }), { toolClass: "destructive", source: "annotation" });
  assert.equal(classifyMcpTool(strict, { server: "s", tool: "decrypt_and_delete" }).toolClass, "destructive", "verb class block beats detokenize ask");
  assert.equal(classifyMcpTool({}, { server: "s", tool: "decrypt_and_delete" }).toolClass, "detokenize", "destructive without a verdict does not");
  assert.equal(classifyMcpTool({}, { server: "s", tool: "decrypt_and_upload" }).toolClass, "detokenize");
});

test("alert: content-free, carries the class", () => {
  const tc = decideMcpToolClass({}, { server: "pay", tool: "detokenize_card" });
  assert.deepEqual(toolClassAlert(tc, { tool: "detokenize_card", server: "pay", toolPrefix: "gateway", decision: "ask" }), { threatId: 0, category: "MCP: tool held by class default", riskLevel: "Medium", stage: "mcp", tool: "gateway:detokenize_card", decision: "ask", reasonCode: "MCP_TOOL_CLASS", toolClass: "detokenize", toolClassSource: "heuristic", mcpServer: "pay", contentHash: "mcp:tool-class:detokenize:ask" });
});

test("approval routing: match key toolClass takes the class names, matches the call's class, and the alert carries it", () => {
  assert.ok(MATCH_KEYS.includes("toolClass"));
  const rule = validateRule({ id: "detok", label: "Detokenize needs a reviewer", match: { toolClass: ["detokenize"] }, holds: ["ask", "block"], group: "secops" });
  assert.deepEqual(rule.value.match, { toolClass: ["detokenize"] });
  assert.match(validateRule({ id: "x", label: "x", match: { toolClass: ["secret"] }, holds: ["ask"], group: "g" }).error, /match\.toolClass/);
  assert.match(validateRule({ id: "x", label: "x", match: { toolClass: [] }, holds: ["ask"], group: "g" }).error, /match\.toolClass/);
  assert.equal(ruleMatches(rule.value, "ask", { toolClass: "detokenize" }), true);
  assert.equal(ruleMatches(rule.value, "ask", { toolClass: "write" }), false);
  assert.equal(ruleMatches(rule.value, "ask", {}), false);
  assert.equal(toolClassOf({}, "mcp__pay__detokenize_card"), "detokenize");
  assert.equal(toolClassOf({ mcpToolClasses: { pay: { detokenize_card: "read" } } }, "mcp__pay__detokenize_card"), "read");
  assert.equal(toolClassOf({}, "mcp__github__create_issue"), "write");
  assert.equal(toolClassOf({}, "Bash"), "");
  const ev = { kind: APPROVAL_REQUESTED, requestId: "apr_0123456789ABCDEFGHJKMNPQRS", ruleId: "detok", actionHash: "h2:0123456789abcdef", threatId: 0, verdict: "ask", requestedAt: "t0", expiresAt: "t1" };
  assert.equal(approvalAlert(ev, { tool: "mcp__pay__detokenize_card", toolClass: "detokenize" }).toolClass, "detokenize");
  assert.equal("toolClass" in approvalAlert(ev, { tool: "Bash" }), false);
});

test("model proxy: detokenize is a business class with a built-in ask; businessToolActions, then mcpToolClassDefaults, set it", () => {
  for (const n of ["detokenize_card", "functions.decryptField", "default_api.get_card_number", "get_secret", "unmask-pii"]) assert.ok(classifyBusinessTool(n).includes("detokenize"), n);
  for (const n of ["list_secrets", "get_card", "tokenize_card", "issue_refund", "get_weather"]) assert.ok(!classifyBusinessTool(n).includes("detokenize"), n);
  assert.equal(businessToolActionsFrom(null).detokenize, "ask");
  assert.equal(businessToolActionsFrom({ mcpToolClassDefaults: { detokenize: "block" } }).detokenize, "block");
  assert.equal(businessToolActionsFrom({ mcpToolClassDefaults: { detokenize: "deny" } }).detokenize, "ask");
  assert.equal(businessToolActionsFrom({ mcpToolClassDefaults: { detokenize: "block" }, businessToolActions: { detokenize: "allow" } }).detokenize, "allow");
  assert.equal(businessToolActionsFrom({ businessToolActions: { money: "block" } }).money, "block");
  assert.deepEqual(businessActionFor({}, "detokenize_card"), { classes: ["detokenize"], cls: "detokenize", act: "ask" });
});

test("SDK decideToolCall: a detokenize MCP tool asks with mcpToolClassDefaults unset", async () => {
  const { decideToolCall } = await import("../packages/agent-sdk/src/index.mjs");
  const { buildEngine } = await import("../cli/hook-core.mjs");
  const policy = { captureTier: "content-free" };
  const d = (tool) => decideToolCall(buildEngine(policy), policy, { tool, toolInput: { id: "x" }, cwd: "/w/proj", systemConfig: null });
  assert.equal(d("mcp__pay__detokenize_card").decision, "ask");
  assert.equal(d("mcp__github__delete_repository").decision, "allow");
});
