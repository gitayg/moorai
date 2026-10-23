// An unenrolled desktop app sends nothing to any console: no policy poll, no report, and so no login
// name or hostname anywhere. Enrolled, the user and device never ride a URL query string: the policy
// request names the tenant and the keyed actor (h2:, as the hooks send it), and the user and device go
// as request headers (X-MoorAI-User / X-MoorAI-Device), attached host-side inside the desktop app
// (src-tauri/src/console_http.rs) and by the plain-browser build itself. The update check carries no
// user or device identifier.
//
//   node --test --import ./test/hermetic-env.mjs test/desktop-unenrolled-silent.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

const USER = "jdoe.private";
const HOST = "JDOE-LAPTOP.local";
let n = 0;

async function desktop({ identity, tauri = true }) {
  const kv = new Map();
  const net = [];
  const saved = {};
  const shim = (k, v) => { saved[k] = Object.getOwnPropertyDescriptor(globalThis, k); Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true }); };
  shim("localStorage", { getItem: (k) => (kv.has(k) ? kv.get(k) : null), setItem: (k, v) => kv.set(k, String(v)), removeItem: (k) => kv.delete(k) });
  shim("navigator", { platform: "MacIntel", userAgent: "test" });
  shim("screen", { width: 1 });
  const invoke = async (cmd, args) => {
    if (cmd === "identity") return identity;
    if (cmd === "console_fetch") { net.push({ via: "host", url: `${args.req.credentialed ? "<recorded console>" : args.req.base}${args.req.path}`, ipc: JSON.stringify(args) }); return { status: 200, body: {} }; }
    if (cmd === "check_and_install_update") { net.push({ via: "updater", url: "<update endpoint>", ipc: JSON.stringify(args ?? null) }); return false; }
    if (cmd === "device_ai_tools") return { tools: [] };
    if (cmd === "device_agent_activity") return { activity: [{ host: "codex", lastActiveEpoch: 1700000000 }] };
    if (cmd === "device_accounts") return { accounts: [] };
    if (cmd === "app_version") return "1.0.0";
    return {};
  };
  shim("window", tauri ? { __TAURI__: { core: { invoke } } } : {});
  shim("fetch", async (url, opts = {}) => { net.push({ via: "fetch", url: String(url), headers: opts.headers || {} }); return { ok: true, status: 200, json: async () => ({ version: "1.0.0" }) }; });
  const restore = () => { for (const [k, d] of Object.entries(saved)) { if (d) Object.defineProperty(globalThis, k, d); else delete globalThis[k]; } };
  const api = await import(`../src/api.js?silent=${++n}`);
  await api.loadIdentity();
  return { api, net, restore };
}

// What app.js runs at boot and on every poll tick, minus the updater (tested on its own below).
const bootAndPoll = async (api) => {
  api.reportIdentity();
  for (let i = 0; i < 3; i++) await api.getPolicy();
  api.postAlert({ threatId: 39, category: "Information & Privacy", riskLevel: "High", stage: "prompt" });
  api.reportPrompt("sent", 1);
  await api.reportDevice();
  await api.reportActivity();
  await api.reportPatches({});
};

const UNENROLLED = { user: USER, device: HOST, platform: "darwin", tenant: "unprovisioned", installToken: "", console: null, consoleWarning: null };

const ENROLLED = { user: USER, device: HOST, platform: "darwin", tenant: "acme", installToken: "tok-SECRET", console: "https://console.acme.test", enrolledConsole: "https://console.acme.test", consoleWarning: null };

test("QUERY: enrolled, the policy request names the tenant and the keyed actor, never the user or the device", async () => {
  const { api, net, restore } = await desktop({ identity: ENROLLED });
  try {
    await api.getPolicy();
    const pol = net.filter((r) => r.url.includes("/api/policy"));
    assert.equal(pol.length, 1, JSON.stringify(net));
    const u = new URL(pol[0].url.replace("<recorded console>", "https://x.test"));
    assert.deepEqual([...u.searchParams.keys()].sort(), ["actor", "tenant"], u.search);
    assert.equal(u.searchParams.get("tenant"), "acme");
    assert.match(u.searchParams.get("actor"), /^h2:[0-9a-f]{16}$/);
    for (const v of [USER, HOST, encodeURIComponent(USER), encodeURIComponent(HOST)]) assert.ok(!pol[0].url.includes(v), `${v} in ${pol[0].url}`);
    assert.ok(JSON.parse(pol[0].ipc).req.credentialed, "only a credentialed call; the host attaches the identity headers");
  } finally { restore(); }
});

test("QUERY: no request the enrolled app makes carries the user or the device in its URL", async () => {
  const { api, net, restore } = await desktop({ identity: ENROLLED });
  try {
    await bootAndPoll(api);
    assert.ok(net.length >= 7, JSON.stringify(net));
    for (const r of net) for (const v of [USER, HOST, encodeURIComponent(USER), encodeURIComponent(HOST)]) assert.ok(!r.url.includes(v), `${v} in the URL ${r.url}`);
  } finally { restore(); }
});

test("QUERY: the plain-browser build sends the user and device as percent-encoded headers, not in the URL", async () => {
  const { api, net, restore } = await desktop({ identity: { ...ENROLLED, user: "José Ü", device: "büro-pc" } });
  try {
    globalThis.window.__TAURI__ = undefined;
    await api.getPolicy();
    assert.equal(net.length, 1, JSON.stringify(net));
    const r = net[0];
    assert.ok(r.url.startsWith("https://console.acme.test/api/policy?"), r.url);
    assert.ok(!/[?&](user|device)=/.test(r.url), r.url);
    assert.equal(r.headers["X-MoorAI-User"], encodeURIComponent("José Ü"));
    assert.equal(r.headers["X-MoorAI-Device"], encodeURIComponent("büro-pc"));
    assert.equal(r.headers["X-Install-Token"], "tok-SECRET");
  } finally { restore(); }
});

test("UPDATE: the update check carries no user or device identifier, enrolled or not", async () => {
  for (const identity of [UNENROLLED, ENROLLED]) {
    const { api, net, restore } = await desktop({ identity });
    try {
      await api.checkAndInstallUpdate();
      assert.equal(net.length, 1, JSON.stringify(net));
      assert.equal(net[0].via, "updater");
      assert.equal(net[0].ipc, "null", "the renderer passes the host updater nothing: " + net[0].ipc);
    } finally { restore(); }
    // the version banner's check (checkUpdate): a plain GET of /api/health
    const b = await desktop({ identity });
    try {
      await b.api.checkUpdate();
      assert.equal(b.net.length, 1, JSON.stringify(b.net));
      assert.match(b.net[0].url, /\/api\/health$/);
      for (const r of b.net) {
        for (const v of [USER, HOST, encodeURIComponent(USER), encodeURIComponent(HOST)]) assert.ok(!r.url.includes(v), r.url);
        assert.deepEqual(Object.keys(r.headers || {}), [], `the browser update check sent headers: ${JSON.stringify(r.headers)}`);
      }
    } finally { b.restore(); }
  }
});

// src/content-hash.js resolves its key once per process, so the enrolled cases above run first.
test("SILENT: an unenrolled consumer install makes no console request at all, so no user or host leaves the device", async () => {
  const { api, net, restore } = await desktop({ identity: UNENROLLED });
  try {
    assert.equal(api.enrolled(), false);
    await bootAndPoll(api);
    assert.deepEqual(net, [], "an unenrolled app reached a console: " + JSON.stringify(net));
  } finally { restore(); }
});

test("SILENT: an administrator-provisioned device that has not enrolled polls nothing either", async () => {
  const { api, net, restore } = await desktop({ identity: { ...UNENROLLED, tenant: "acme", provisionedConsole: "https://moorai.acme.internal" } });
  try {
    await bootAndPoll(api);
    assert.deepEqual(net, [], JSON.stringify(net));
  } finally { restore(); }
});

test("SILENT: the plain-browser build, unenrolled, fetches no policy", async () => {
  const { api, net, restore } = await desktop({ identity: UNENROLLED });
  try {
    globalThis.window.__TAURI__ = undefined;
    for (let i = 0; i < 3; i++) await api.getPolicy();
    assert.deepEqual(net, [], JSON.stringify(net));
  } finally { restore(); }
});

test("SILENT: unenrolled with no console recorded at all (a host too old to report one, or the browser build), still nothing", async () => {
  const { console: _c, consoleWarning: _w, ...old } = UNENROLLED;
  for (const browser of [false, true]) {
    const { api, net, restore } = await desktop({ identity: old });
    try {
      if (browser) globalThis.window.__TAURI__ = undefined;
      for (let i = 0; i < 3; i++) await api.getPolicy();
      assert.deepEqual(net, [], `${browser ? "browser" : "host"}: ` + JSON.stringify(net));
    } finally { restore(); }
  }
});
