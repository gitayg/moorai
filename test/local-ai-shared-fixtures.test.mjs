// The JS half of the local-AI inventory's JS↔Rust behavioural parity. Every case in
// test/fixtures/local-ai/*.json is replayed here against cli/listen-sockets.mjs, cli/local-ai-inventory.mjs
// and cli/local-ai-windows.mjs, and in src-tauri/src/{listen_sockets,local_ai,local_ai_windows}.rs against
// the Rust mirrors (`cargo test --lib`). A change to one side that the other does not make fails one of
// the two. The tables themselves are pinned by source in test/aibom-rust-parity.test.mjs.
//
//   node --test test/local-ai-shared-fixtures.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { bindOf, parseLsof, parseSs, parseProcNetTcp, parseNetstat } from "../cli/listen-sockets.mjs";
import { runningRuntimes, installedRuntimes, localAiInventory } from "../cli/local-ai-inventory.mjs";
import { parseWindowsAi, gpuTier, parseOdrList, odrAgentConnectors, ODR_ARGV } from "../cli/local-ai-windows.mjs";

const fx = (n) => JSON.parse(readFileSync(new URL(`./fixtures/local-ai/${n}.json`, import.meta.url), "utf8"));
const lines = (a) => a.join("\n");

test("sockets: bind classes and every parser give the fixture's records", () => {
  const f = fx("sockets");
  for (const h of f.bind.loopback) assert.equal(bindOf(h), "loopback", h);
  for (const h of f.bind.network) assert.equal(bindOf(h), "network", h);
  assert.deepEqual(parseLsof(lines(f.lsof)), f.expect.lsof);
  assert.deepEqual(parseSs(lines(f.ss)), f.expect.ss);
  assert.deepEqual(parseProcNetTcp(lines(f.procTcp)), f.expect.procTcp);
  assert.deepEqual(parseProcNetTcp(lines(f.procTcp6)), f.expect.procTcp6);
  assert.deepEqual(parseNetstat(f.netstat.join("\r\n")), f.expect.netstat);
});

test("runtimes: running cases (listening class included) and installed cases match the fixture", () => {
  const f = fx("runtimes");
  assert.ok(f.running.length >= 15 && f.installed.length >= 4);
  for (const c of f.running) assert.deepEqual(runningRuntimes({ listeners: c.listeners, processes: c.processes }), c.expect, c.name);
  for (const c of f.installed) {
    const set = new Set(c.exists);
    const got = installedRuntimes({ platform: c.platform, env: c.env, home: c.home, exists: (p) => set.has(p.replace(/\\/g, "/")), readFile: (p) => { if (p in c.plists) return c.plists[p]; throw new Error("ENOENT"); } });
    assert.deepEqual(got, c.expect, c.name);
    assert.doesNotMatch(JSON.stringify(got), /\/(Users|Applications|opt|custom)|C:\//, `${c.name}: no path is output`);
  }
});

test("Windows AI platform: every PowerShell case and GPU tier matches the fixture; nothing identifying leaks", () => {
  const f = fx("windows-ai");
  for (const c of f.cases) {
    const got = parseWindowsAi(c.stdout);
    assert.deepEqual(got, c.expect, c.name);
    for (const l of f.leaks) assert.ok(!JSON.stringify(got).includes(l), `${c.name}: ${l} leaked`);
  }
  for (const [n, m, tier] of f.tiers) assert.equal(gpuTier(n, m), tier, n);
});

test("ODR agent connectors: both documented shapes parse to names + packaged/contained; nothing else leaks", () => {
  const f = fx("odr-list");
  assert.ok(f.cases.length >= 7);
  for (const c of f.cases) {
    const got = parseOdrList(c.stdout);
    assert.deepEqual(got, c.expect, c.name);
    for (const l of f.leaks) assert.ok(!JSON.stringify(got).includes(l), `${c.name}: ${l} leaked`);
  }
  const many = parseOdrList(JSON.stringify(Array.from({ length: 105 }, (_, i) => ({ server: { name: `s${i}` } }))));
  assert.equal(many.count, 105);
  assert.equal(many.items.length, 100, "items are capped, the count is not");
});

test("ODR probe: one `odr.exe list` with a 5 s budget, fail-open, Windows only", () => {
  const calls = [];
  const sample = fx("odr-list").cases[0];
  assert.deepEqual(odrAgentConnectors((cmd, args, timeout) => { calls.push([cmd, args, timeout]); return sample.stdout; }), sample.expect);
  assert.deepEqual(calls, [["odr.exe", ["list"], 5000]]);
  assert.deepEqual(ODR_ARGV, ["odr.exe", ["list"]]);
  assert.equal(odrAgentConnectors(() => null), null, "no odr.exe (build < 26220.7262) → null");
  const base = { env: {}, home: "C:/none", exists: () => false, readFile: () => { throw new Error("x"); } };
  const win = localAiInventory({ ...base, platform: "win32", runner: (cmd) => (cmd === "odr.exe" ? sample.stdout : null) });
  assert.deepEqual(win.agentConnectors, sample.expect);
  const cmds = [];
  const mac = localAiInventory({ ...base, platform: "darwin", runner: (cmd) => { cmds.push(cmd); return null; } });
  assert.equal(mac.agentConnectors, null);
  assert.ok(!cmds.includes("odr.exe"), "never probed off Windows");
  const thrown = localAiInventory({ ...base, platform: "win32", runner: (cmd) => { if (cmd === "odr.exe") throw new Error("boom"); return null; } });
  assert.equal(thrown.agentConnectors, null, "a throwing probe is fail-open");
});
