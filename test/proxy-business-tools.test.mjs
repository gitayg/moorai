// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/proxy-business-tools.test.mjs
//
// The model proxy's built-in business-impact catalogue (model-proxy/business-tools.mjs): a function the model
// calls is classed by its NAME as money, bulk-data, identity, destructive or delegation. The built-in action
// for a class is alert (reported, never blocked); a policy's businessToolActions raises or silences a class,
// and a functionToolActions key naming the function itself wins over its class. Content-free: the alert
// carries the class and the function name, never an argument.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { classifyBusinessTool, businessToolActionsFrom, BUSINESS_CLASSES } from "../model-proxy/business-tools.mjs";
import { startFakeProvider, sendJson, openaiCompletion } from "../model-proxy/test/fake-provider.mjs";
import { chatResponse, MODEL } from "../model-proxy/test/fake-ollama.mjs";
import { sandbox, startConsole, startProxy, request, waitFor } from "../model-proxy/test/harness.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const POSITIVE = {
  money: ["issue_refund", "IssueRefund", "process_refund", "refund_order", "apply_coupon", "applyCouponCode", "apply_discount", "add_promo_code", "redeem_voucher", "transfer_funds", "transferFunds", "wire_transfer", "send_money", "create_payout", "charge_card", "charge_customer", "pay_invoice", "process_payment", "create_payment_intent", "issue_store_credit", "set_price", "update_price", "change_product_pricing", "adjust_balance", "functions.issue_refund", "default_api.apply_coupon", "issue-refund"],
  "bulk-data": ["export_customer_data_any", "export_users", "exportAllOrders", "dump_database", "dump_table", "get_all_users", "list_all_customers", "fetch_all_customer_records", "download_all", "download_all_files", "bulk_export", "read_any_user_data", "export_customer"],
  identity: ["grant_admin", "grant_role", "assign_role", "add_permission", "elevate_privileges", "make_admin", "promote_to_admin", "reset_password", "resetUserPassword", "disable_mfa", "reset_2fa", "delete_account", "deleteUserAccount", "disable_user", "deactivate_account", "suspend_member", "close_account", "impersonate_user", "login_as_user"],
  destructive: ["delete_file", "delete_order", "bulk_delete_records", "purge_cache", "wipe_disk", "drop_table", "drop_database", "truncate_table", "destroy_instance", "erase_logs", "delete_account"],
  delegation: ["accept_handoff", "request_handoff", "hand_off_to_billing", "fan_out", "fanOut", "fanout_tasks", "spawn_agent", "spawn_subagent", "delegate_task", "delegate", "transfer_to_refund_agent", "invoke_agent", "call_worker", "dispatch_subagent"]
};
const NEGATIVE = [
  "get_coupon_list", "list_coupons", "validate_coupon", "check_coupon", "coupon_details", "get_refund_status", "refund_status", "refund_policy", "list_refunds", "get_price", "price_lookup", "lookup_product", "search_products",
  "get_order", "list_open_tickets", "read_ticket", "summarize_reviews", "get_weather", "send_email", "create_ticket", "add_to_cart", "apply_filter", "update_profile_photo", "reset_search_filters",
  "get_user_roles", "list_permissions", "check_permission", "is_admin", "get_account", "get_deleted_items", "is_deleted", "undelete_item", "dropdown_options", "drop_shipping_quote", "drop_pin",
  "get_handoff_status", "get_export_status", "list_agents", "get_agent", "transfer_call", "remove_item_from_cart", "payment_history", "get_payment_methods", "credit_score_lookup", "Bash", "Read", "WebFetch", "Task", "Agent", "run_shell", "read_file", "write_file", "fetch_url", ""
];

test("classifyBusinessTool: every catalogue example is classed, by folded name, camelCase and namespace prefixes included", () => {
  assert.deepEqual([...BUSINESS_CLASSES], ["money", "bulk-data", "identity", "destructive", "delegation"]);
  for (const [cls, names] of Object.entries(POSITIVE)) for (const n of names) assert.ok(classifyBusinessTool(n).includes(cls), `${n} → ${cls}, got ${JSON.stringify(classifyBusinessTool(n))}`);
});

test("classifyBusinessTool: read-only and unrelated names are not classed (get_coupon_list is not apply_coupon)", () => {
  for (const n of NEGATIVE) assert.deepEqual(classifyBusinessTool(n), [], `${n} classed as ${JSON.stringify(classifyBusinessTool(n))}`);
});

test("businessToolActionsFrom: alert by default for every class; a valid policy entry replaces it; anything else is ignored", () => {
  const all = (a) => Object.fromEntries(BUSINESS_CLASSES.map((c) => [c, a]));
  assert.deepEqual(businessToolActionsFrom(null), all("alert"));
  assert.deepEqual(businessToolActionsFrom({ businessToolActions: ["block"] }), all("alert"));
  assert.deepEqual(businessToolActionsFrom({ businessToolActions: { money: "block", identity: "ask", destructive: "allow", "bulk-data": "deny", delegation: 5, other: "block" } }), { ...all("alert"), money: "block", identity: "ask", destructive: "allow" });
});

// ---- through the CLI ----
const BIZ = { businessToolActions: { money: "block", identity: "ask", delegation: "allow" }, functionToolActions: { issue_partial_refund: "alert", apply_coupon: "allow", "tools.*": "alert" } };
const call = (name, input = { order_id: "A-1009" }) => ({ name, input });
let fp, con, home, pxE, pxR, pxD;
before(async () => {
  fp = await startFakeProvider();
  con = await startConsole();
  home = sandbox();
  const pol = join(home, "biz.json");
  writeFileSync(pol, JSON.stringify(BIZ));
  const plain = join(home, "plain.json");
  writeFileSync(plain, JSON.stringify({ captureTier: "content-free" }));
  const env = { MOORAI_SERVER_URL: con.url, MOORAI_INSTALL_TOKEN: "tok-proxy-biz-1", MOORAI_TENANT: "t-mp-biz" };
  const routes = ["--route", `/ollama=${fp.url}`, "--route", `/openai=${fp.url}/v1`];
  pxE = await startProxy(home, ["--mode", "enforce", "--policy-file", pol, ...routes], env);
  pxR = await startProxy(home, ["--policy-file", pol, ...routes], env);
  pxD = await startProxy(home, ["--mode", "enforce", "--policy-file", plain, ...routes], env);
});
after(async () => { for (const p of [pxE, pxR, pxD]) await p?.stop(); await fp?.close(); await con?.close(); if (home) rmTree(home); });
const ollama = (px, tools) => { fp.on((r, res) => sendJson(res, chatResponse({ tools }))); return request(px.listening, "/ollama/api/chat", { body: { model: MODEL, stream: false, messages: [{ role: "user", content: "handle the queue" }] } }); };
const mine = (n0) => con.parsed().slice(n0);

test("built-in default: a business tool is reported by class (alert), never refused, even in enforce mode; arguments never leave", async () => {
  for (const [name, cls] of [["issue_refund", "money"], ["export_customer_data_any", "bulk-data"], ["transfer_funds", "money"], ["delete_account", "identity"], ["accept_handoff", "delegation"], ["fan_out", "delegation"], ["apply_coupon", "money"]]) {
    const n0 = con.alerts.length;
    const r = await ollama(pxD, [call(name)]);
    assert.equal(r.status, 200, `${name}: ${r.raw}`);
    assert.ok(await waitFor(() => mine(n0).some((x) => x.tool === `model-proxy:${name}` && x.businessClass)), `${name}: ${JSON.stringify(mine(n0))}`);
    const al = mine(n0).filter((x) => x.tool === `model-proxy:${name}` && x.businessClass);
    assert.ok(al.some((x) => x.businessClass === cls), `${name}: ${JSON.stringify(al)}`);
    for (const x of al) {
      assert.equal(x.decision, "notify", name);
      assert.equal(x.riskLevel, "Medium", name);
      assert.equal(x.functionName, name, name);
      assert.match(x.category, /^Model proxy: business-impact function reported \(/, name);
    }
    assert.ok(!con.alerts.slice(n0).join("\n").includes("A-1009"), `${name}: an argument left`);
  }
  const n0 = con.alerts.length;
  assert.equal((await ollama(pxD, [call("get_coupon_list", {})])).status, 200);
  await new Promise((r) => setTimeout(r, 200));
  assert.ok(!mine(n0).some((x) => x.businessClass), JSON.stringify(mine(n0)));
});

test("businessToolActions block: enforce refuses a money function (Ollama and OpenAI) and names the class; ask is settled headless (deny); allow silences a class", async () => {
  const n0 = con.alerts.length;
  const a = await ollama(pxE, [call("issue_refund")]);
  assert.equal(a.status, 403);
  assert.match(a.json.error, /tool call issue_refund: function issue_refund blocked by policy \(businessToolActions: money\)/);
  fp.on((r, res) => sendJson(res, openaiCompletion({ tools: [call("transfer_funds")] })));
  const o = await request(pxE.listening, "/openai/chat/completions", { body: { model: "gpt-fake", messages: [{ role: "user", content: "pay" }] } });
  assert.equal(o.status, 403);
  assert.match(o.json.error.message, /function transfer_funds blocked by policy \(businessToolActions: money\)/);
  assert.ok(await waitFor(() => mine(n0).some((x) => x.tool === "model-proxy:issue_refund" && x.decision === "deny")), JSON.stringify(mine(n0)));
  const d = mine(n0).find((x) => x.tool === "model-proxy:issue_refund" && x.decision === "deny");
  assert.equal(d.riskLevel, "Blocked");
  assert.equal(d.businessClass, "money");
  assert.match(d.category, /business-impact function denied \(money\)/);
  const r = await ollama(pxE, [call("reset_password", { user: "bob" })]);
  assert.equal(r.status, 403);
  assert.match(r.json.error, /function reset_password requires approval \(businessToolActions: identity\)/);
  const n1 = con.alerts.length;
  assert.equal((await ollama(pxE, [call("spawn_agent", { task: "x" })])).status, 200, "delegation: allow");
  await new Promise((res) => setTimeout(res, 200));
  assert.ok(!mine(n1).some((x) => x.tool === "model-proxy:spawn_agent" && x.businessClass), `the class is silenced (the namespace-wide tools.* alert still reports): ${JSON.stringify(mine(n1))}`);
});

test("most specific wins: a functionToolActions key for the function itself beats its class (alert, or allow); a namespace-wide key does not loosen a class", async () => {
  const n0 = con.alerts.length;
  assert.equal((await ollama(pxE, [call("issue_partial_refund")])).status, 200, "named alert beats money: block");
  assert.equal((await ollama(pxE, [call("apply_coupon", { code: "SAVE50" })])).status, 200, "named allow beats money: block");
  assert.ok(await waitFor(() => mine(n0).some((x) => x.tool === "model-proxy:issue_partial_refund")), JSON.stringify(mine(n0)));
  assert.ok(mine(n0).filter((x) => x.tool === "model-proxy:issue_partial_refund").every((x) => /functionToolActions/.test(x.category) && !x.businessClass), JSON.stringify(mine(n0)));
  const t = await ollama(pxE, [call("tools.issue_refund")]);
  assert.equal(t.status, 403, "a `tools.*` alert key matches everything but is not specific: the money block still applies");
});

test("report mode: a blocked class is forwarded unchanged and filed deny with enforcement LIMITED", async () => {
  const n0 = con.alerts.length;
  let sent;
  fp.on((r, res) => { sent = sendJson(res, chatResponse({ tools: [call("issue_refund")] })); });
  const r = await request(pxR.listening, "/ollama/api/chat", { body: { model: MODEL, stream: false, messages: [{ role: "user", content: "x" }] } });
  assert.ok(r.raw.equals(sent));
  assert.ok(await waitFor(() => mine(n0).some((x) => x.tool === "model-proxy:issue_refund" && x.enforcement === "LIMITED" && x.decision === "deny" && x.businessClass === "money")), JSON.stringify(mine(n0)));
});
