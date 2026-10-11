// Self-hosted and air-gapped consoles in the desktop renderer (src/api.js). A device provisioned to a
// console — enrolled (identity.console) or provisioned by an administrator (identity.provisionedConsole:
// a managed preference or the root/admin-owned machine file, src-tauri/src/admin_config.rs) — talks to
// that console and never to the MoorAI cloud, before or after enrolment. Only an unprovisioned consumer
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

test("QUIET: MDM-provisioned by an administrator, not yet enrolled: the provisioned console is the base and the cloud is never named", async () => {
  const { api, calls, restore } = await desktop({ identity: { user: "u", device: "d", platform: "darwin", tenant: "acme", installToken: "", console: null, consoleWarning: null, provisionedConsole: SELF }, store: { "raiseme.server": "https://app.moorai.dev" } });
  try {
    assert.equal(api.serverBase(), SELF);
    assert.equal(api.enrolBase(), SELF);
    assert.deepEqual(api.parseEnrollInput("it_abc"), { token: "it_abc", base: SELF }, "a bare token enrols against the provisioned console");
    await everything(api);
    const reqs = net(calls);
    assert.ok(reqs.length >= 2, JSON.stringify(reqs));
    assert.ok(reqs.every((c) => c.cmd === "console_fetch"), "the renderer fetched directly: " + JSON.stringify(reqs));
    assert.deepEqual(reqs.map(where).filter((u) => CLOUD.test(u)), [], "a provisioned device named the MoorAI cloud");
    assert.ok(reqs.some((c) => where(c) === `${SELF}/api/signup`), JSON.stringify(reqs.map(where)));
  } finally { restore(); }
});

test("QUIET: enrolled in the app to a self-hosted console: every call is host-routed and credentialed calls name no origin", async () => {
  // save_provision recorded the console host-side as an enrolment (identity.enrolledConsole), which is where a
  // later signup or bare token starts (enrolBase()); localStorage plays no part.
  const { api, calls, restore } = await desktop({ identity: { user: "u", device: "d", platform: "darwin", tenant: "acme", installToken: "tok-SECRET", console: SELF, enrolledConsole: SELF, consoleWarning: null } });
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

test("QUIET: unprovisioned consumer install keeps the cloud default; the desktop app ignores a localStorage override", async () => {
  const id = { user: "u", device: "d", platform: "darwin", tenant: "unprovisioned", installToken: "", console: null, consoleWarning: null };
  let d = await desktop({ identity: id });
  try {
    assert.equal(d.api.serverBase(), "https://app.moorai.dev");
    assert.deepEqual(d.api.parseEnrollInput("it_abc"), { token: "it_abc", base: "https://app.moorai.dev" }, "a bare token enrols against the cloud");
  } finally { d.restore(); }
  d = await desktop({ identity: id, store: { "raiseme.server": "https://lab.example/" } });
  try { assert.equal(d.api.enrolBase(), "https://app.moorai.dev", "WebKit storage is the agent's to write"); assert.equal(d.api.serverBase(), "https://app.moorai.dev"); } finally { d.restore(); }
});

// The plain-browser build has no host to record a console, so it keeps the localStorage override.
async function browser(store = {}) {
  const kv = new Map(Object.entries(store));
  const saved = {};
  const shim = (k, v) => { saved[k] = Object.getOwnPropertyDescriptor(globalThis, k); Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true }); };
  shim("localStorage", { getItem: (k) => (kv.has(k) ? kv.get(k) : null), setItem: (k, v) => kv.set(k, String(v)), removeItem: (k) => kv.delete(k) });
  shim("navigator", { platform: "MacIntel", userAgent: "test" });
  shim("screen", { width: 1 });
  shim("window", {});
  const restore = () => { for (const [k, dsc] of Object.entries(saved)) { if (dsc) Object.defineProperty(globalThis, k, dsc); else delete globalThis[k]; } };
  const api = await import(`../src/api.js?browser=${++n}`);
  await api.loadIdentity();
  return { api, restore };
}
test("QUIET: the plain-browser build keeps the localStorage override (https only)", async () => {
  let b = await browser({ "raiseme.server": "https://lab.example/" });
  try { assert.equal(b.api.enrolBase(), "https://lab.example"); assert.equal(b.api.serverBase(), "https://lab.example"); } finally { b.restore(); }
  b = await browser({ "raiseme.server": "http://lab.example" });
  try { assert.equal(b.api.enrolBase(), "https://app.moorai.dev", "a plain-http override is not a console"); } finally { b.restore(); }
  b = await browser();
  try { assert.equal(b.api.enrolBase(), "https://app.moorai.dev"); } finally { b.restore(); }
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

// ~/.moorai/config.json is writable by the agent MoorAI guards. v1.12.0's host reported its serverUrl
// to the renderer (identity.serverUrl), and serverBase() put it ahead of everything but the recorded
// console, so a planted value received the install token a user pasted, the signup's name and email,
// and the default-policy query, and the provision it answered became the device's recorded console.
const EVIL = "https://collector.evil.test";
test("TRUST: a serverUrl the agent wrote to config.json receives no pasted install token, no signup and no policy query", async () => {
  const { api, calls, restore } = await desktop({ identity: { user: "u", device: "d", platform: "darwin", tenant: "unprovisioned", installToken: "", console: null, consoleWarning: null, serverUrl: EVIL } });
  try {
    await api.enroll("it_REAL_TOKEN");
    await api.signUp("Acme", "admin@acme.test");
    await api.getPolicy();
    const reqs = net(calls).map(where);
    assert.deepEqual(reqs.filter((u) => u.includes("evil")), [], JSON.stringify(reqs));
    assert.ok(reqs.includes("https://app.moorai.dev/d/it_REAL_TOKEN"), JSON.stringify(reqs));
    const save = calls.find((c) => c.cmd === "save_provision");
    assert.ok(!JSON.stringify(save.args).includes("evil"), "the planted origin became the enrolment's console: " + JSON.stringify(save.args));
  } finally { restore(); }
});

test("TRUST: a console recorded by migration from a planted config.json does not receive a pasted install token", async () => {
  // No enrolment yet; the agent wrote {serverUrl, installToken} and the host's first-use migration recorded it.
  const { api, calls, restore } = await desktop({ identity: { user: "u", device: "d", platform: "darwin", tenant: "planted", installToken: "tok-planted", console: EVIL, consoleWarning: null, serverUrl: EVIL } });
  try {
    await api.enroll("it_REAL_TOKEN");
    await api.signUp("Acme", "admin@acme.test");
    const uncredentialed = net(calls).filter((c) => !c.args.req?.credentialed).map(where);
    assert.deepEqual(uncredentialed.filter((u) => u.includes("evil")), [], JSON.stringify(uncredentialed));
  } finally { restore(); }
});

// The webview's localStorage lives in WebKit storage under the user's home (~/Library/WebKit/<bundle id>/
// on macOS), which the agent MoorAI guards can write. Through v1.12.1 enrolBase() honoured its
// "raiseme.server" in the desktop app, so a planted value received the install token a user pasted, the
// signup's name and email and the claim, and the provision it answered became the recorded console.
test("TRUST: a console the agent wrote to the webview's localStorage receives no pasted install token, no signup and no claim", async () => {
  const { api, calls, restore } = await desktop({ identity: { user: "u", device: "d", platform: "darwin", tenant: "unprovisioned", installToken: "", console: null, consoleWarning: null }, store: { "raiseme.server": EVIL } });
  try {
    await api.enroll("it_REAL_TOKEN");
    await api.signUp("Acme", "admin@acme.test");
    await api.awaitClaim("cl_1");
    await api.getPolicy();
    const reqs = net(calls).map(where);
    assert.deepEqual(reqs.filter((u) => u.includes("evil")), [], JSON.stringify(reqs));
    assert.ok(reqs.includes("https://app.moorai.dev/d/it_REAL_TOKEN"), JSON.stringify(reqs));
    for (const save of calls.filter((c) => c.cmd === "save_provision")) assert.ok(!JSON.stringify(save.args).includes("evil"), "the planted origin became the enrolment's console: " + JSON.stringify(save.args));
  } finally { restore(); }
});

test("TRUST: on a device enrolled in the app to a self-hosted console, a planted localStorage console does not take a re-enrolment", async () => {
  const { api, calls, restore } = await desktop({ identity: { user: "u", device: "d", platform: "darwin", tenant: "acme", installToken: "tok-SECRET", console: SELF, enrolledConsole: SELF, consoleWarning: null }, store: { "raiseme.server": EVIL } });
  try {
    assert.equal(api.enrolBase(), SELF);
    await api.enroll("it_NEW_TOKEN");
    await api.signUp("Acme", "admin@acme.test");
    const reqs = net(calls).map(where);
    assert.deepEqual(reqs.filter((u) => u.includes("evil")), [], JSON.stringify(reqs));
    assert.ok(reqs.includes(`${SELF}/d/it_NEW_TOKEN`), JSON.stringify(reqs));
    assert.ok(reqs.includes(`${SELF}/api/signup`), JSON.stringify(reqs));
  } finally { restore(); }
});

test("the webview cannot drive the updater plugin directly (it could bypass updates-off or allow downgrades)", () => {
  const cap = JSON.parse(readFileSync(new URL("../src-tauri/capabilities/default.json", import.meta.url), "utf8"));
  assert.ok(!cap.permissions.some((p) => String(p).startsWith("updater:")), JSON.stringify(cap.permissions));
});
