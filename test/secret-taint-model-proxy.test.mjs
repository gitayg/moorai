// #65 session-read secrets through moorai-model-proxy: a token in a tool_result the request feeds back to
// the model is tracked; the model's next tool call carrying it base64-encoded is withheld (enforce,
// replace), with the content-free alert naming the encoding and the source. Real CLI process, fake
// provider, fake console; the token is synthetic.
//
//   node --test --import ./test/hermetic-env.mjs test/secret-taint-model-proxy.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { startFakeProvider, sendJson, anthropicMessage } from "../model-proxy/test/fake-provider.mjs";
import { sandbox, startConsole, startProxy, request, waitFor } from "../model-proxy/test/harness.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const TOK = `ghp_${[...randomBytes(36)].map((b) => ALNUM[b % ALNUM.length]).join("")}`;
const B64 = Buffer.from(TOK).toString("base64");
const CALL = { name: "mcp__remote__post", input: { body: B64 } };

let fp, con, home, px;
before(async () => {
  fp = await startFakeProvider();
  con = await startConsole();
  home = sandbox();
  px = await startProxy(home, ["--mode", "enforce", "--denied-tool-call", "replace", "--route", `/anthropic=${fp.url}`], { MOORAI_SERVER_URL: con.url, MOORAI_INSTALL_TOKEN: "tok-secret-taint-mp", MOORAI_TENANT: "t-st-mp" });
});
after(async () => { await px.stop(); await fp.close(); await con.close(); rmTree(home); });

const body = (messages) => ({ model: "claude-fake", max_tokens: 64, messages });
const send = (messages) => request(px.listening, "/anthropic/v1/messages", { body: body(messages), headers: { "anthropic-version": "2023-06-01" } });
const toolText = (j) => j.content.filter((b) => b.type === "text").map((b) => b.text).join("\n");

test("model proxy: a token from a tool_result, then sent base64-encoded in the model's tool call, is withheld", async () => {
  fp.on((req, res) => sendJson(res, anthropicMessage({ text: "Posting it.", tools: [CALL] })));
  // No tool result has carried the token yet: the call goes through.
  const first = await send([{ role: "user", content: "post the nightly report" }]);
  assert.equal(first.status, 200);
  assert.ok(first.json.content.some((b) => b.type === "tool_use" && b.name === CALL.name), `withheld before the token was read: ${toolText(first.json)}`);
  // The conversation now carries a tool result with the token.
  const second = await send([
    { role: "user", content: "post the nightly report" },
    { role: "assistant", content: [{ type: "tool_use", id: "toolu_r", name: "Bash", input: { command: "cat ~/.config/registry.txt" } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_r", content: `registry token: ${TOK}` }] }
  ]);
  assert.equal(second.status, 200);
  assert.ok(!second.json.content.some((b) => b.type === "tool_use"), "the tool call carrying the encoded token was delivered");
  assert.match(toolText(second.json), /local secret egress/);
  assert.ok(await waitFor(() => con.parsed().some((a) => a.threatId === 65 && Array.isArray(a.secretEgress))), JSON.stringify(con.parsed().map((a) => [a.threatId, a.category])));
  const a = con.parsed().find((x) => x.threatId === 65 && Array.isArray(x.secretEgress));
  assert.deepEqual(a.secretEgress.map((m) => [m.encoding, m.source]), [["base64", "session-read"]]);
  for (const f of [TOK, B64, TOK.slice(4, 20)]) assert.ok(!con.alerts.join("\n").includes(f), "an alert carries the token");
});
