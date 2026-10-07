// Regressions from the v1.4.1 commit review of the HTTP MCP gateway:
//   (1) "parser-differential in mcp-gateway/validate.mjs": repeatedKey() refused two keys that differ only in
//       case, but not ONE key that differs only in case from a field the gate reads. A lone `Arguments`
//       left `params.arguments` undefined to JSON.parse (the gate scanned `{}`), while a case-insensitive
//       decoder (Go's encoding/json, measured with go1.26) reads it as the arguments and runs them.
//   (2) "denial-of-service in mcp-gateway/server.mjs": a batch of N tools/call is gated one message after
//       another with no yield to I/O, ~3.7 ms each (71% of it the per-call ledger write), so one client's
//       batch starved every other client; and a client already in a cool-down could keep feeding refusals
//       into the cool-down's 4096-entry tables until its own entry was evicted.
//   (3) found while checking (2): arguments nested ~100000 deep made the gate's JSON.stringify throw, and
//       a failing check forwards, so the call reached the upstream unscanned. A client message is now
//       refused past MAX_DEPTH levels at the json stage, in every --schema mode.
// Benign stand-ins only (the AWS documentation example key), local fake upstreams only.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-gateway-review2.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { scenario, rpc, call, settle, H } from "../mcp-gateway/test/harness.mjs";
import { repeatedKey, MAX_DEPTH } from "../mcp-gateway/validate.mjs";
import { MAX_KEYS } from "../mcp-gateway/cooldown.mjs";
import { MAX_BATCH_MESSAGES } from "../mcp-gateway/server.mjs";

const POLICY = { captureTier: "content-free", threatPolicy: { 39: "block" } };
const AWS_J = JSON.stringify("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1\n");
const COOL = ["--cooldown-refusals", "2", "--cooldown-window", "60", "--cooldown-seconds", "120"];

// ------------------------------------------------------------------------------- (1) parser differential
test("REVIEW2 parse: a lone case variant of a field the gate reads (Arguments, \\u0041rguments, argument\\u017f) is refused", async () => {
  await scenario({ policy: POLICY }, async ({ up, base }) => {
    let id = 0;
    for (const key of ["Arguments", "\\u0041rguments", "argument\\u017f", "ARGUMENTS"]) {
      const r = await rpc(base, `{"jsonrpc":"2.0","id":${++id},"method":"tools/call","params":{"name":"send","${key}":{"body":${AWS_J}}}}`);
      assert.equal(r.json && r.json.result && r.json.result.isError, true, `${key}: ${r.text}`);
    }
    const env = await rpc(base, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"send","arguments":{}},"PARAMS":{"name":"send","arguments":{"body":${AWS_J}}}}`);
    assert.equal(env.json && env.json.result && env.json.result.isError, true, `envelope PARAMS: ${env.text}`);
    assert.equal(up.received.length, 0, "a case-variant MCP field reached the upstream");
    const ok = await rpc(base, call(10, "echo", { Arguments: 1, NAME: 2 }));
    assert.equal(ok.json.result.isError, false, "keys INSIDE arguments may take any case");
    assert.equal(up.received.length, 1);
  });
});

// Guards for the leads that turned out NOT to be differentials (these pass on v1.4.1 as shipped too):
// repeatedKey reads a key the way JSON.parse does (escapes decoded, string state kept across \" and \\).
test("REVIEW2 parse: repeatedKey compares decoded keys and is not confused by escapes, nesting or whitespace", () => {
  const yes = {
    escapedDup: '{"method":"a","m\\u0065thod":"b"}',
    escapedCaseFold: '{"\\u004dethod":"a","method":"b"}',
    nestedArrayDup: '{"a":[[{"x":1,"x":2}]]}',
    wsBeforeColon: '{"x" \n\t: 1, "x"\r: 2}',
    proto: '{"a":{"__proto__":1,"__proto__":2}}',
    batchElement: '[{"jsonrpc":"2.0"},{"id":1,"ID":2}]',
    paramsFold: '{"params":{"name":"a","n\\u0041me":"b"}}'
  };
  const no = {
    quoteInValue: '{"x":"\\",\\"x\\":","y":1}',
    backslashEnd: '{"x":"\\\\","y":"\\\\\\"x\\":"}',
    sameKeyDifferentObjects: '[{"x":1},{"x":2}]',
    caseInsideArguments: '{"params":{"arguments":{"a":1,"A":2}}}',
    caseOutsideEnvelope: '{"result":{"tools":[{"name":"a","Name":"b"}]}}'
  };
  for (const [k, s] of Object.entries(yes)) { JSON.parse(s); assert.equal(repeatedKey(s), true, k); }
  for (const [k, s] of Object.entries(no)) { JSON.parse(s); assert.equal(repeatedKey(s), false, k); }
});

// ------------------------------------------------------------------------------- (2) denial of service
test("REVIEW2 dos: a batch longer than MAX_BATCH_MESSAGES is refused before it is gated; one at the cap still goes", async () => {
  await scenario({ policy: POLICY }, async ({ up, base }) => {
    const batch = (n) => Array.from({ length: n }, (_, i) => call(i + 1, "echo", { a: i }));
    const big = await rpc(base, batch(MAX_BATCH_MESSAGES + 1));
    assert.equal(big.status, 413, `over-cap batch: ${big.status} ${big.text.slice(0, 200)}`);
    assert.equal(big.json && big.json.error && big.json.error.code, -32600);
    assert.equal(up.received.length, 0, "an over-cap batch reached the upstream");
    const at = await rpc(base, batch(MAX_BATCH_MESSAGES));
    assert.notEqual(at.status, 413, at.text.slice(0, 200));
    assert.equal(up.received.length, 1, "a batch at the cap is forwarded");
  });
});

test("REVIEW2 dos: a client in a cool-down cannot evict its own cool-down by feeding the tables refusals", { timeout: 240000 }, async () => {
  await scenario({ policy: POLICY, gatewayArgs: COOL }, async ({ up, base }) => {
    for (let i = 0; i < 2; i++) await rpc(base, "{}", { Authorization: `Bearer junk-${i}` });
    const before = await rpc(base, call(1, "echo", { a: 1 }));
    assert.match(before.json.result.content[0].text, /cool-down/);
    // Two invalid bodies per fresh credential would start MAX_KEYS credential cool-downs.
    const creds = Array.from({ length: MAX_KEYS }, (_, i) => `Bearer flush-${i}`);
    for (let i = 0; i < creds.length; i += 32) {
      await Promise.all(creds.slice(i, i + 32).map(async (c) => { await rpc(base, "{}", { Authorization: c }); await rpc(base, "{}", { Authorization: c }); }));
    }
    const after = await rpc(base, call(2, "echo", { a: 1 }));
    assert.equal(after.json && after.json.result && after.json.result.isError, true, `the cool-down was flushed: ${after.text}`);
    assert.equal(up.received.length, 0, "a cooled-down peer reached the upstream");
  });
});

// ------------------------------------------------------------------------------- (3) nesting depth
test("REVIEW2 depth: a client message nested deeper than MAX_DEPTH is refused unscanned in every --schema mode; one at the limit passes", async () => {
  // envelope { + params { + arguments { = 3 levels, then `pad` arrays.
  const nested = (id, name, args, pad) => `{"jsonrpc":"2.0","id":${id},"method":"tools/call","params":{"name":"${name}","arguments":{${args}"pad":${"[".repeat(pad)}${"]".repeat(pad)}}}}`;
  for (const mode of ["enforce", "report", "off"]) {
    await scenario({ policy: POLICY, upstream: { resultText: "ok" }, gatewayArgs: ["--schema", mode] }, async ({ con, up, base }) => {
      const deep = await rpc(base, nested(1, "send", `"body":${AWS_J},`, 100000));
      assert.equal(deep.json && deep.json.result && deep.json.result.isError, true, `${mode} depth 100003: ${deep.text.slice(0, 200)}`);
      const over = await rpc(base, nested(2, "echo", "", MAX_DEPTH - 2));
      assert.equal(over.json && over.json.result && over.json.result.isError, true, `${mode} depth ${MAX_DEPTH + 1}: ${over.text.slice(0, 200)}`);
      if (mode !== "enforce") {
        // the lenient path: a BOM fails the strict stage, report|off still read the body
        const r = await fetch(base, { method: "POST", headers: H, body: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(nested(3, "echo", "", 100000))]) });
        const t = await r.text();
        let j = null; try { j = JSON.parse(t); } catch { /* not the gateway's answer */ }
        assert.equal(j && j.result && j.result.isError, true, `${mode} BOM + deep: ${r.status} ${t.slice(0, 200)}`);
      }
      assert.equal(up.calls().length, 0, `${mode}: a too-deep message reached the upstream`);
      const at = await rpc(base, nested(4, "echo", "", MAX_DEPTH - 3));
      assert.equal(at.json && at.json.result && at.json.result.isError, false, `${mode} depth ${MAX_DEPTH}: ${at.text.slice(0, 200)}`);
      assert.equal(up.calls().length, 1, `${mode}: a message at the limit is forwarded`);
      await settle();
      assert.ok(con.alerts.some((a) => a.reasonCode === "SCHEMA_INVALID" && a.schemaStage === "json" && a.decision === "deny"), `${mode}: no SCHEMA_INVALID json deny alert`);
    });
  }
});
