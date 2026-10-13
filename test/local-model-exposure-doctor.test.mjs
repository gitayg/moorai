// moorai doctor's inventory rows (cli/doctor-inventory.mjs) for the three v1.15.0 detectors. The scan is
// injected; the rows must be read-only (write: false) and must skip the DNS-dependent row with --offline.
//
//   node --test test/local-model-exposure-doctor.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkInventory } from "../cli/doctor-inventory.mjs";

const scan = (fields, notes = { socketSource: "lsof", ambiguousConnections: 0 }, seen = []) => async (o) => { seen.push(o); return { fields, alerts: [], notes }; };
const byId = (rows) => Object.fromEntries(rows.map((r) => [r.id, r]));

test("an exposed server and an unknown caller warn; the scan runs read-only", async () => {
  const seen = [];
  const rows = byId(await checkInventory(null, { run: scan({
    localModelServers: [{ runtime: "ollama", port: 11434, bind: "loopback", viaProxy: false }],
    aiApiCallers: [{ processImage: "python.exe", provider: "anthropic", known: false }, { processImage: "claude", provider: "anthropic", known: true }],
    decoyKeys: { placed: 0, source: "none" }
  }, { socketSource: "lsof", ambiguousConnections: 2 }, seen) }));
  assert.equal(seen[0].write, false);
  assert.equal(seen[0].resolve, true);
  assert.equal(rows["local-model-exposure"].status, "warn");
  assert.match(rows["local-model-exposure"].summary, /ollama :11434 \(loopback\)/);
  assert.equal(rows["ai-api-callers"].status, "warn");
  assert.match(rows["ai-api-callers"].summary, /python\.exe→anthropic/);
  assert.match(rows["ai-api-callers"].summary, /2 connection\(s\) to shared front-end addresses not attributed/);
  assert.equal(rows["decoy-keys"].status, "ok");
});

test("policy off turns the warnings into ok rows; place without decoys warns", async () => {
  const fields = { localModelServers: [{ runtime: "vllm", port: 8000, bind: "lan", viaProxy: false }], aiApiCallers: [{ processImage: "x", provider: "openai", known: false }], decoyKeys: { placed: 0, source: "none" } };
  const rows = byId(await checkInventory({ localModelExposure: "off", aiApiCallers: "off", decoyKeys: { mode: "place" } }, { run: scan(fields) }));
  assert.equal(rows["local-model-exposure"].status, "ok");
  assert.equal(rows["ai-api-callers"].status, "ok");
  assert.equal(rows["decoy-keys"].status, "warn");
});

test("--offline skips the callers row and does not resolve", async () => {
  const seen = [];
  const rows = byId(await checkInventory(null, { offline: true, run: scan({ localModelServers: [{ runtime: "ollama", port: 11435, bind: "loopback", viaProxy: true }], aiApiCallers: [], decoyKeys: { placed: 3, source: "agent" } }, undefined, seen) }));
  assert.equal(seen[0].resolve, false);
  assert.equal(rows["ai-api-callers"].status, "skip");
  assert.equal(rows["local-model-exposure"].status, "ok");
  assert.match(rows["local-model-exposure"].summary, /reachable only through MoorAI/);
  assert.match(rows["decoy-keys"].summary, /3 placed \(agent\)/);
});

test("an unreadable TCP table skips the socket rows instead of reporting a clean device", async () => {
  const rows = byId(await checkInventory(null, { run: scan({ localModelServers: [], aiApiCallers: [], decoyKeys: { placed: 0, source: "none" } }, { socketSource: "none" }) }));
  assert.equal(rows["local-model-exposure"].status, "skip");
  assert.equal(rows["ai-api-callers"].status, "skip");
});
