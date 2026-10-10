// The desktop renderer (src/api.js) never sends the install token itself: inside the host every console
// call goes through the `console_fetch` command (src-tauri/src/console_http.rs), which picks the
// console recorded at enrolment (console_binding.rs) for credentialed calls and attaches the token
// host-side. The renderer can neither name the origin of a credentialed call nor see the token cross
// IPC. The host half — origin, https, routes, redirects, timeout — is proven in console_http.rs's tests;
// the plain-browser fallback (fetch, redirects off) is pinned here.
//
//   node --test test/desktop-console-binding.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

const TOKEN = "tok-SECRET-INSTALL";
let n = 0;

// Fresh module per case (api.js keeps identity at module scope), with the smallest honest browser shim.
async function desktop({ identity, store = {} }) {
  const kv = new Map(Object.entries(store));
  const sent = [];
  const saved = {};
  const shim = (k, v) => { saved[k] = Object.getOwnPropertyDescriptor(globalThis, k); Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true }); };
  shim("localStorage", { getItem: (k) => (kv.has(k) ? kv.get(k) : null), setItem: (k, v) => kv.set(k, String(v)), removeItem: (k) => kv.delete(k) });
  shim("navigator", { platform: "MacIntel", userAgent: "test" });
  shim("screen", { width: 1 });
  const invoke = async (cmd, args) => {
    if (cmd === "identity") return identity;
    if (cmd === "save_provision") { sent.push({ via: "save_provision", url: "", config: args.config }); return {}; }
    if (cmd === "console_fetch") { const q = args.req; sent.push({ via: "host", url: `${q.credentialed ? "<recorded console>" : q.base}${q.path}`, credentialed: q.credentialed, base: q.base, ipc: JSON.stringify(args) }); return { status: 200, body: q.path.startsWith("/d/") ? { tenant: "acme" } : {} }; }
    if (cmd === "device_ai_tools") return { tools: [] };
    if (cmd === "device_agent_activity") return { activity: [{ host: "codex", lastActiveEpoch: 1700000000 }] };
    return {};
  };
  shim("window", { __TAURI__: { core: { invoke } } });
  shim("fetch", async (url, opts = {}) => { sent.push({ url: String(url), token: opts.headers?.["X-Install-Token"] ?? null, redirect: opts.redirect }); return { ok: true, json: async () => ({}) }; });
  const restore = () => { for (const [k, d] of Object.entries(saved)) { if (d) Object.defineProperty(globalThis, k, d); else delete globalThis[k]; } };
  const api = await import(`../src/api.js?case=${++n}`);
  await api.loadIdentity();
  return { api, sent, restore };
}
const fire = async (api) => {
  api.postAlert({ threatId: 39, category: "Information & Privacy", riskLevel: "High", stage: "prompt" });
  api.reportPrompt("sent", 1);
  api.reportIdentity();
  await api.getPolicy();
  await api.reportDevice();
  await api.reportActivity();
  await api.reportPatches({});
};
const ID = { user: "dev", device: "mac", platform: "darwin", tenant: "acme", installToken: TOKEN };

test("inside the host, every report is a credentialed console_fetch: no origin named by the renderer, no token over IPC", async () => {
  const { api, sent, restore } = await desktop({ identity: { ...ID, console: "https://console.good.test", consoleWarning: null }, store: { "raiseme.server": "https://collector.evil.test" } });
  try {
    await fire(api);
    const cred = sent.filter((s) => s.credentialed);
    assert.ok(cred.length >= 7, JSON.stringify(sent));
    assert.ok(sent.filter((s) => s.via !== "save_provision").every((s) => s.via === "host"), "the renderer fetched a console directly: " + JSON.stringify(sent));
    for (const s of cred) {
      assert.equal(s.base, null, `${s.url}: a credentialed call must not name an origin`);
      assert.ok(!s.ipc.includes(TOKEN), `${s.url}: the install token crossed IPC`);
      assert.ok(!s.ipc.includes("evil"), `${s.url}: the poisoned base reached the host`);
    }
  } finally { restore(); }
});

test("plain-browser build: a poisoned base in localStorage never receives the token; the host-recorded console does, redirects off", async () => {
  const { api, sent, restore } = await desktop({ identity: { ...ID, console: "https://console.good.test", consoleWarning: null }, store: { "raiseme.server": "https://collector.evil.test" } });
  try {
    // the identity was read from the host; from here on there is no host to route through
    const tauri = globalThis.window.__TAURI__;
    globalThis.window.__TAURI__ = undefined;
    api.postAlert({ threatId: 39, category: "Information & Privacy", riskLevel: "High", stage: "prompt" });
    api.reportPrompt("sent", 1);
    api.reportIdentity();
    await api.getPolicy();
    globalThis.window.__TAURI__ = tauri;
    const withToken = sent.filter((s) => s.token);
    assert.ok(withToken.length >= 4, JSON.stringify(sent));
    assert.deepEqual(sent.filter((s) => s.url.includes("evil")), [], "nothing at all went to the poisoned base");
    for (const s of withToken) {
      assert.ok(s.url.startsWith("https://console.good.test/"), s.url);
      assert.equal(s.redirect, "error", `${s.url} must not follow a redirect with the token`);
    }
  } finally { restore(); }
});

test("the host refused the console (rewritten config.json, plain http): no credentialed request at all, and the reason is exposed", async () => {
  const why = "MoorAI is not sending its install token to the console in ~/.moorai/config.json: http://collector.evil.test is not https.";
  const { api, sent, restore } = await desktop({ identity: { ...ID, console: null, consoleWarning: why }, store: { "raiseme.server": "https://collector.evil.test" } });
  try {
    await fire(api);
    assert.deepEqual(sent.filter((s) => s.token), [], "no request carried the token");
    assert.equal(api.consoleWarning(), why);
    assert.equal(api.enrolled(), true, "enforcement does not drop to coach because the console was refused");
  } finally { restore(); }
});

test("enrolment fetches the provision through the host (which never follows a redirect), and refuses a non-https console", async () => {
  const { api, sent, restore } = await desktop({ identity: { ...ID, installToken: "", console: null, consoleWarning: null } });
  try {
    await api.enroll("tok-new", "https://console.good.test/");
    const asked = sent.filter((s) => s.via === "host").at(-1);
    assert.equal(asked.url, "https://console.good.test/d/tok-new");
    assert.equal(asked.credentialed, false);
    assert.deepEqual(sent.at(-1), { via: "save_provision", url: "", config: { tenant: "acme", serverUrl: "https://console.good.test", installToken: "tok-new" } }, "a provision without serverUrl records the console it came from");
    const n = sent.length;
    await assert.rejects(api.enroll("tok-new", "http://collector.evil.test"), /https/);
    assert.equal(sent.length, n, "nothing was asked of a plain-http console");
    // plain-browser build: fetch, redirects off
    globalThis.window.__TAURI__ = undefined;
    globalThis.fetch = async (url, opts = {}) => { sent.push({ url: String(url), redirect: opts.redirect }); return { ok: true, status: 200, json: async () => ({ tenant: "acme", serverUrl: "https://console.good.test" }) }; };
    await api.enroll("tok-new", "https://console.good.test/");
    assert.deepEqual(sent.at(-1), { url: "https://console.good.test/d/tok-new", redirect: "error" });
    assert.ok(!sent.some((s) => s.url.includes("evil")), "the token never left for a plain-http console");
  } finally { restore(); }
});
