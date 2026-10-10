// Self-hosted and air-gapped consoles in the desktop renderer (src/api.js). A device provisioned to a
// console — enrolled (identity.console) or only MDM-provisioned (identity.serverUrl) — talks to that
// console and never to the MoorAI cloud, before or after enrolment. Only an unprovisioned consumer
// install keeps the cloud default. The host half (update endpoint selection, console_fetch's origin,
// https, route and timeout rules) is proven in src-tauri/src/update_source.rs and console_http.rs.
//
//   node --test test/desktop-airgap.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const CLOUD = /moorai\.dev|glick\.run/;
const SELF = "https://moorai.acme.internal";
let n = 0;

async function desktop({ identity, store = {} }) {
  const kv = new Map(Object.entries(store));
  const calls = [];
  const saved = {};
  const shim = (k, v) => { saved[k] = Object.getOwnPropertyDescriptor(globalThis, k); Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true }); };
  shim("localStorage", { getItem: (k) => (kv.has(k) ? kv.get(k) : null), setItem: (k, v) => kv.set(k, String(v)), removeItem: (k) => kv.delete(k) });
  shim("navigator", { platform: "MacIntel", userAgent: "test" });
  shim("screen", { width: 1 });
  const invoke = async (cmd, args) => {
    calls.push({ cmd, args });
    if (cmd === "identity") return identity;
    if (cmd === "device_ai_tools") return { tools: [] };
    if (cmd === "device_agent_activity") return { activity: [{ host: "codex", lastActiveEpoch: 1700000000 }] };
    if (cmd === "console_fetch") {
      const p = args.req.path;
      if (p.startsWith("/d/")) return { status: 200, body: { tenant: "acme" } };
      if (p === "/api/signup") return { status: 200, body: { tenant: "acme", claimToken: "cl_1" } };
      return { status: 200, body: {} };
    }
    return {};
  };
  shim("window", { __TAURI__: { core: { invoke } } });
  shim("fetch", async (url) => { calls.push({ cmd: "fetch", args: { url: String(url) } }); return { ok: true, status: 200, json: async () => ({}) }; });
  const restore = () => { for (const [k, d] of Object.entries(saved)) { if (d) Object.defineProperty(globalThis, k, d); else delete globalThis[k]; } };
  const api = await import(`../src/api.js?airgap=${++n}`);
  await api.loadIdentity();
  return { api, calls, restore };
}
const everything = async (api) => {
  api.postAlert({ threatId: 39, category: "Information & Privacy", riskLevel: "High", stage: "prompt" });
  api.reportPrompt("sent", 1);
  api.reportIdentity();
  await api.getPolicy();
  await api.reportDevice();
  await api.reportActivity();
  await api.reportPatches({});
  await api.signUp("Acme", "admin@acme.test");
  await api.checkAndInstallUpdate();
};
const net = (calls) => calls.filter((c) => c.cmd === "console_fetch" || c.cmd === "fetch");
const where = (c) => (c.cmd === "fetch" ? c.args.url : c.args.req.credentialed ? `<recorded console>${c.args.req.path}` : `${c.args.req.base}${c.args.req.path}`);

test("MDM-provisioned, not yet enrolled: the provisioned console is the base and the cloud is never named", async () => {
  const { api, calls, restore } = await desktop({ identity: { user: "u", device: "d", platform: "darwin", tenant: "acme", installToken: "", console: null, consoleWarning: null, serverUrl: SELF }, store: { "raiseme.server": "https://app.moorai.dev" } });
  try {
    assert.equal(api.serverBase(), SELF);
    await everything(api);
    const reqs = net(calls);
    assert.ok(reqs.length >= 2, JSON.stringify(reqs));
    assert.ok(reqs.every((c) => c.cmd === "console_fetch"), "the renderer fetched directly: " + JSON.stringify(reqs));
    assert.deepEqual(reqs.map(where).filter((u) => CLOUD.test(u)), [], "a provisioned device named the MoorAI cloud");
    assert.ok(reqs.some((c) => where(c) === `${SELF}/api/signup`), JSON.stringify(reqs.map(where)));
  } finally { restore(); }
});

test("enrolled to a self-hosted console: every call is host-routed and credentialed calls name no origin", async () => {
  const { api, calls, restore } = await desktop({ identity: { user: "u", device: "d", platform: "darwin", tenant: "acme", installToken: "tok-SECRET", console: SELF, consoleWarning: null, serverUrl: SELF } });
  try {
    assert.equal(api.serverBase(), SELF);
    await everything(api);
    const reqs = net(calls);
    assert.deepEqual(reqs.map(where).filter((u) => CLOUD.test(u)), []);
    assert.ok(reqs.filter((c) => c.args.req?.credentialed).length >= 7);
    for (const c of reqs.filter((c) => c.args.req?.credentialed)) assert.equal(c.args.req.base, null);
    assert.ok(calls.some((c) => c.cmd === "check_and_install_update"), "the update check is the host's to route (update_source.rs)");
  } finally { restore(); }
});

test("unprovisioned consumer install keeps today's cloud default (and a localStorage override)", async () => {
  const id = { user: "u", device: "d", platform: "darwin", tenant: "unprovisioned", installToken: "", console: null, consoleWarning: null, serverUrl: null };
  let d = await desktop({ identity: id });
  try { assert.equal(d.api.serverBase(), "https://app.moorai.dev"); } finally { d.restore(); }
  d = await desktop({ identity: id, store: { "raiseme.server": "https://lab.example/" } });
  try { assert.equal(d.api.serverBase(), "https://lab.example"); } finally { d.restore(); }
  d = await desktop({ identity: id, store: { "raiseme.server": "http://lab.example" } });
  try { assert.equal(d.api.serverBase(), "https://app.moorai.dev", "a plain-http override is not a console"); } finally { d.restore(); }
});

test("an enrolment link names a self-hosted console; a bare token enrolls against the current base", async () => {
  const { api, calls, restore } = await desktop({ identity: { user: "u", device: "d", platform: "darwin", tenant: "unprovisioned", installToken: "", console: null, consoleWarning: null, serverUrl: null } });
  try {
    assert.deepEqual(api.parseEnrollInput(`  ${SELF}/d/it_abc  `), { token: "it_abc", base: SELF });
    assert.deepEqual(api.parseEnrollInput("http://127.0.0.1:8788/d/it_abc"), { token: "it_abc", base: "http://127.0.0.1:8788" });
    assert.deepEqual(api.parseEnrollInput("it_abc"), { token: "it_abc", base: "https://app.moorai.dev" });
    assert.throws(() => api.parseEnrollInput("http://collector.evil.test/d/it_abc"), /https/);
    assert.throws(() => api.parseEnrollInput(`${SELF}/admin`), /d\/<token>/);
    await api.enroll(`${SELF}/d/it_abc`);
    const asked = net(calls).at(-1);
    assert.equal(where(asked), `${SELF}/d/it_abc`);
    const save = calls.find((c) => c.cmd === "save_provision");
    assert.deepEqual(save.args.config, { tenant: "acme", serverUrl: SELF, installToken: "it_abc" });
  } finally { restore(); }
});

test("the webview cannot drive the updater plugin directly (it could bypass updates-off or allow downgrades)", () => {
  const cap = JSON.parse(readFileSync(new URL("../src-tauri/capabilities/default.json", import.meta.url), "utf8"));
  assert.ok(!cap.permissions.some((p) => String(p).startsWith("updater:")), JSON.stringify(cap.permissions));
});
