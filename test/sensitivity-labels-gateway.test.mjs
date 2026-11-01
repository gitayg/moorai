// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/sensitivity-labels-gateway.test.mjs
//
// labelPolicy through the HTTP MCP gateway (a route with --local-files), a real gateway process, the fake
// remote server and a fake console serving a SIGNED policy (mcp-gateway/test/harness.mjs). Generated
// fixture files only (test/fixtures/label-files.mjs).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scenario, rpc, call, settle } from "../mcp-gateway/test/harness.mjs";
import { rmTree } from "./fs-cleanup.mjs";
import { docx, LABEL_ID } from "./fixtures/label-files.mjs";

const RULES = { rules: [{ match: { id: LABEL_ID }, onRead: "notify", onSend: "block" }] };
const LOCAL = ["--local-files"];
async function until(fn, ms = 5000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await settle(100); } return false; }

function files(t) {
  const d = mkdtempSync(join(tmpdir(), "moorai-label-gw-"));
  t.after(() => rmTree(d));
  const deck = join(d, "board-deck.docx"), broken = join(d, "broken.docx");
  writeFileSync(deck, docx({ custom: [{ id: LABEL_ID, name: "Highly Confidential" }] }));
  writeFileSync(broken, docx({ custom: [{ id: LABEL_ID, name: "Highly Confidential" }] }).subarray(0, 150));
  return { deck, broken };
}

test("GATEWAY: an upload of a labelled file is refused before the upstream; the alert carries the label, not the path", async (t) => {
  const { deck } = files(t);
  await scenario({ policy: { captureTier: "content-free", labelPolicy: RULES }, gatewayArgs: LOCAL }, async ({ con, up, base }) => {
    const r = await rpc(base, call(1, "upload_file", { path: deck }));
    assert.equal(r.json.result.isError, true, r.text.slice(0, 300));
    assert.deepEqual(up.calls(), [], "the upstream received the upload");
    assert.ok(await until(() => con.alerts.some((a) => a.sensitivityLabel)), JSON.stringify(con.alerts.map((a) => a.category)));
    const a = con.alerts.find((x) => x.sensitivityLabel);
    assert.deepEqual([a.threatId, a.riskLevel, a.tool, a.sensitivityLabel.labelId, a.sensitivityLabel.action, a.sensitivityLabel.verdict], [1, "Blocked", "gateway:upload_file", LABEL_ID, "send", "block"]);
    assert.ok(!JSON.stringify(con.alerts).includes("board-deck"), "content-free");
  });
});

test("GATEWAY: an unreadable label under failMode.mcpGateway closed is refused (failWhy label); open forwards", async (t) => {
  const { broken } = files(t);
  await scenario({ policy: { captureTier: "content-free", labelPolicy: RULES, failMode: { mcpGateway: "closed" } }, gatewayArgs: LOCAL }, async ({ con, up, base }) => {
    const r = await rpc(base, call(2, "upload_file", { path: broken }));
    assert.equal(r.json.result.isError, true, r.text.slice(0, 300));
    assert.match(r.json.result.content[0].text, /could not read the sensitivity label of a file it names/);
    assert.deepEqual(up.calls(), []);
    assert.ok(await until(() => con.alerts.some((a) => a.reasonCode === "FAIL_CLOSED" && a.failWhy === "label")), JSON.stringify(con.alerts.map((a) => [a.category, a.failWhy])));
  });
  await scenario({ policy: { captureTier: "content-free", labelPolicy: RULES }, gatewayArgs: LOCAL }, async ({ up, base }) => {
    const r = await rpc(base, call(3, "upload_file", { path: broken }));
    assert.equal(r.json.result.isError, false, r.text.slice(0, 300));
    assert.equal(up.calls().length, 1);
  });
});
