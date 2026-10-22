// F16 — Browser Guard made store-listable and force-installable: icons, managed-storage schema, the
// background relay that posts alerts (a content script's fetch runs under the page's origin, so it cannot
// reach a console), store listing and privacy text, the packaging script, and the Chrome / Edge
// force-install policy templates. The store submission itself is the owner's step.
//
//   node --test --import ./test/hermetic-env.mjs test/browser-ext-store.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { BufferSource } from "../cli/model-scan-bytes.mjs";
import { zipEntries, readEntry } from "../cli/model-scan-zip.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const EXT = join(ROOT, "browser-ext");
const read = (p) => readFileSync(join(EXT, p), "utf8");
const manifest = () => JSON.parse(read("manifest.json"));
const tmp = (p) => mkdtempSync(join(tmpdir(), `moorai-bx-${p}-`));

function pngSize(buf) {
  assert.equal(buf.subarray(0, 8).toString("hex"), "89504e470d0a1a0a", "PNG signature");
  assert.equal(buf.subarray(12, 16).toString("ascii"), "IHDR");
  return [buf.readUInt32BE(16), buf.readUInt32BE(20)];
}

// ---- manifest ---------------------------------------------------------------------------------------

test("manifest: MV3 with 16/32/48/128 icons that exist at their stated size", () => {
  const m = manifest();
  assert.equal(m.manifest_version, 3);
  for (const s of ["16", "32", "48", "128"]) {
    assert.ok(m.icons && m.icons[s], `icons.${s}`);
    assert.deepEqual(pngSize(readFileSync(join(EXT, m.icons[s]))), [Number(s), Number(s)], `icon ${s}`);
    assert.equal(m.action.default_icon[s], m.icons[s]);
  }
});

test("manifest: managed-storage schema, a background service worker, and every referenced file exists", () => {
  const m = manifest();
  assert.equal(m.storage && m.storage.managed_schema, "managed-schema.json");
  assert.equal(m.background && m.background.service_worker, "background.js");
  for (const f of [m.storage.managed_schema, m.background.service_worker, m.options_page, ...m.content_scripts.flatMap((c) => [...c.js, ...(c.css || [])])]) assert.ok(existsSync(join(EXT, f)), f);
  const js = m.content_scripts[0].js;
  assert.ok(js.indexOf("config.js") >= 0 && js.indexOf("config.js") < js.indexOf("report.js") && js.indexOf("report.js") < js.indexOf("content.js"), "config.js loads before report.js and content.js");
  assert.equal(m.key, undefined, "no key field: the store assigns the id");
  assert.deepEqual(m.permissions, ["activeTab", "storage"], "no new permissions (store review)");
  assert.equal(m.version, "0.1.0", "the extension version is bumped by release, not by this change");
  assert.ok(m.description.length <= 132, "store description limit is 132 characters");
});

test("managed schema: the admin-settable keys, typed, in the Chrome schema subset", () => {
  const s = JSON.parse(read("managed-schema.json"));
  assert.equal(s.type, "object");
  assert.deepEqual(Object.keys(s.properties).sort(), ["installToken", "lockSettings", "mode", "reportEnabled", "serverUrl"]);
  assert.deepEqual(s.properties.mode.enum, ["coach", "block"]);
  for (const [k, v] of Object.entries(s.properties)) {
    assert.ok(["string", "boolean"].includes(v.type), k);
    assert.ok(typeof v.title === "string" && typeof v.description === "string", k);
  }
});

// ---- config, report and background, run as the browser would (vm, fake chrome) ------------------------

function fakeChrome({ managed = {}, sync = {}, managedError = false, id = "ext-self", granted = true } = {}) {
  const sent = [];
  const listeners = [];
  const lastErr = { v: undefined };
  const area = (vals, err) => ({
    get(defaults, cb) {
      if (err) { lastErr.v = { message: "managed storage unavailable" }; cb({}); lastErr.v = undefined; return; }
      const out = defaults && typeof defaults === "object" ? { ...defaults, ...vals } : { ...vals };
      cb(out);
    }
  });
  return {
    sent, listeners,
    chrome: {
      runtime: {
        id,
        get lastError() { return lastErr.v; },
        sendMessage(msg, cb) { sent.push(msg); if (cb) cb({ ok: true }); },
        onMessage: { addListener(fn) { listeners.push(fn); } }
      },
      storage: { managed: area(managed, managedError), sync: area(sync), onChanged: { addListener() {} } },
      permissions: { contains(q, cb) { cb(granted); } }
    }
  };
}

function load(files, ctx) {
  const sandbox = { console, setTimeout, URL, ...ctx };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  for (const f of files) vm.runInContext(read(f), sandbox, { filename: f });
  return sandbox;
}
const flush = () => new Promise((r) => setTimeout(r, 20));

test("config: managed (admin) values override the user's sync values; lockSettings is reported; a bad managed mode is ignored", async () => {
  const { chrome } = fakeChrome({ managed: { serverUrl: "https://console.example.com", mode: "block", lockSettings: true }, sync: { serverUrl: "https://user.example", mode: "coach", installToken: "tok-u" } });
  const s = load(["config.js"], { chrome });
  const cfg = await new Promise((r) => s.MoorAIConfig.load(r));
  assert.equal(cfg.serverUrl, "https://console.example.com");
  assert.equal(cfg.mode, "block");
  assert.equal(cfg.installToken, "tok-u");
  assert.equal(cfg.locked, true);
  assert.deepEqual([...cfg.managedKeys].sort(), ["lockSettings", "mode", "serverUrl"]);
  const merged = s.MoorAIConfig.merge({ mode: "yolo", reportEnabled: "yes" }, { mode: "coach" });
  assert.equal(merged.mode, "coach");
  assert.equal(merged.reportEnabled, true);
  const { chrome: c2 } = fakeChrome({ managedError: true, sync: { serverUrl: "https://u.example" } });
  const s2 = load(["config.js"], { chrome: c2 });
  const cfg2 = await new Promise((r) => s2.MoorAIConfig.load(r));
  assert.equal(cfg2.serverUrl, "https://u.example", "no managed storage (unmanaged browser) falls back to sync");
  assert.equal(cfg2.locked, false);
});

test("report (content script): hands content-free alerts to the background worker; never fetches from the page's origin", async () => {
  const { chrome, sent } = fakeChrome({ sync: { serverUrl: "https://console.example.com", installToken: "tok" } });
  let fetched = 0;
  const s = load(["config.js", "report.js"], { chrome, fetch: () => { fetched++; return Promise.resolve({ ok: true }); }, location: { host: "chatgpt.com", href: "https://chatgpt.com/c/abc?q=secret" } });
  await s.MoorAIReport.send([{ threatId: "dlp-email", category: "PII: email", riskLevel: "High", contentHash: "h2:0123456789abcdef", match: "alice@example.com" }], "chatgpt", false);
  await flush();
  assert.equal(fetched, 0, "a content-script fetch is subject to the page's same-origin policy");
  assert.equal(sent.length, 1);
  assert.equal(sent[0].type, "moorai-alerts");
  const keys = new Set(sent[0].alerts.flatMap((a) => Object.keys(a)));
  for (const k of keys) assert.ok(["threatId", "category", "riskLevel", "stage", "tool", "ts", "contentHash", "host", "source"].includes(k), k);
  const s0 = JSON.stringify(sent[0]);
  assert.ok(!s0.includes("alice@example.com") && !s0.includes("/c/abc") && !s0.includes("secret"));
  assert.equal(sent[0].alerts[0].host, "chatgpt.com");
  assert.equal(sent[0].alerts.length, 2, "the High finding also carries its literacy touchpoint");
});

function bg(opts) {
  const f = fakeChrome(opts);
  const calls = [];
  const s = load(["config.js", "background.js"], { chrome: f.chrome, fetch: (url, init) => { calls.push({ url, init }); return Promise.resolve({ ok: true }); } });
  return { ...f, calls, s };
}
const ALERT = { threatId: "dlp-email", category: "PII: email", riskLevel: "High", stage: "browser", tool: "browser:chatgpt", ts: "2026-10-21T00:00:00.000Z", contentHash: "h2:0123456789abcdef", host: "chatgpt.com", source: "browser-ext" };

test("background: posts each alert to <serverUrl>/api/alerts with X-Install-Token (managed config wins)", async () => {
  const b = bg({ managed: { serverUrl: "https://console.example.com/", installToken: "tok-m" }, sync: { serverUrl: "https://user.example" } });
  assert.equal(b.listeners.length, 1);
  b.listeners[0]({ type: "moorai-alerts", alerts: [ALERT, { ...ALERT, riskLevel: "Info" }] }, { id: "ext-self", tab: { id: 1 } }, () => {});
  await flush();
  assert.equal(b.calls.length, 2);
  assert.equal(b.calls[0].url, "https://console.example.com/api/alerts");
  assert.equal(b.calls[0].init.method, "POST");
  assert.equal(b.calls[0].init.headers["X-Install-Token"], "tok-m");
  assert.deepEqual(JSON.parse(b.calls[0].init.body), ALERT);
});

test("background: drops a message from another extension, unknown fields, overlong strings and a bad type", async () => {
  const b = bg({ sync: { serverUrl: "https://console.example.com", installToken: "t" } });
  const h = b.listeners[0];
  h({ type: "moorai-alerts", alerts: [ALERT] }, { id: "someone-else" }, () => {});
  h({ type: "other", alerts: [ALERT] }, { id: "ext-self" }, () => {});
  h({ type: "moorai-alerts", alerts: [{ ...ALERT, category: "x".repeat(500) }] }, { id: "ext-self" }, () => {});
  h({ type: "moorai-alerts", alerts: [{ ...ALERT, prompt: "the user's text" }] }, { id: "ext-self" }, () => {});
  await flush();
  assert.equal(b.calls.length, 1, "only the last one is sent, with the unknown field stripped");
  assert.ok(!b.calls[0].init.body.includes("the user's text"));
  assert.deepEqual(JSON.parse(b.calls[0].init.body), ALERT);
});

test("background: nothing is sent with no server URL, with reporting off, or without host permission for the console", async () => {
  for (const o of [{ sync: {} }, { sync: { serverUrl: "https://c.example", reportEnabled: false } }, { sync: { serverUrl: "https://c.example" }, granted: false }, { sync: { serverUrl: "javascript:alert(1)" } }]) {
    const b = bg(o);
    b.listeners[0]({ type: "moorai-alerts", alerts: [ALERT] }, { id: "ext-self" }, () => {});
    await flush();
    assert.equal(b.calls.length, 0, JSON.stringify(o));
  }
});

// ---- store text -------------------------------------------------------------------------------------

// Names public copy must never carry are kept OUT of this public repository (a list here would itself
// name them): point MOORAI_COPY_DENYLIST at a local file of words, one per line, to run the check.
function namesIn(text) {
  let deny = [];
  try { deny = readFileSync(process.env.MOORAI_COPY_DENYLIST, "utf8").split(/\s+/).filter(Boolean).map((w) => w.toLowerCase()); } catch { return []; }
  const words = new Set(String(text).toLowerCase().match(/[a-z0-9]+/g) || []);
  return deny.filter((w) => words.has(w));
}

test("store listing: single purpose, a justification for every permission and host, and the data disclosure", () => {
  const l = read("store/listing.md");
  const m = manifest();
  assert.match(l, /## Single purpose/);
  for (const p of [...m.permissions, ...m.host_permissions, ...m.optional_host_permissions]) assert.ok(l.includes(`\`${p}\``), `justification for ${p}`);
  assert.match(l, /## Data usage/);
  assert.match(l, /owner/i, "the listing says the store submission is the owner's step");
  assert.deepEqual(namesIn(l), []);
});

test("privacy policy: states what leaves the browser (and that prompt text never does)", () => {
  const p = read("store/PRIVACY.md");
  assert.match(p, /never leaves your browser/i);
  assert.match(p, /keyed one-way hash/i);
  assert.match(p, /host/i);
  assert.deepEqual(namesIn(p), []);
});

// ---- packaging ---------------------------------------------------------------------------------------

function pack(args) { return spawnSync(process.execPath, [join(ROOT, "scripts", "browser-ext-package.mjs"), ...args], { encoding: "utf8" }); }
function zipFiles(buf) {
  const src = new BufferSource(buf);
  return Object.fromEntries(zipEntries(src).map((e) => [e.name, readEntry(src, e, 8 * 1024 * 1024)]));
}
const RUNTIME = ["background.js", "config.js", "content-hash.js", "content.css", "content.js", "detectors.js", "icons/icon128.png", "icons/icon16.png", "icons/icon32.png", "icons/icon48.png", "managed-schema.json", "manifest.json", "options.html", "options.js", "report.js"];

test("package: a store zip with exactly the runtime files, deterministic, readable", () => {
  const out = tmp("pkg");
  const r = pack(["--out", out]);
  assert.equal(r.status, 0, r.stderr);
  const zips = readdirSync(out).filter((f) => f.endsWith(".zip"));
  assert.deepEqual(zips, ["moorai-browser-guard-0.1.0.zip"]);
  const buf = readFileSync(join(out, zips[0]));
  const files = zipFiles(buf);
  assert.deepEqual(Object.keys(files).sort(), RUNTIME);
  assert.equal(JSON.parse(files["manifest.json"]).manifest_version, 3);
  assert.equal(files["detectors.js"].toString("utf8"), read("detectors.js"));
  const out2 = tmp("pkg2");
  pack(["--out", out2]);
  assert.ok(buf.equals(readFileSync(join(out2, zips[0]))), "same inputs, same bytes");
});

test("package --console-origin: a self-hosted build that carries the console origin as a host permission; https only", () => {
  const out = tmp("self");
  const before = read("manifest.json");
  const r = pack(["--out", out, "--console-origin", "https://console.example.com"]);
  assert.equal(r.status, 0, r.stderr);
  const files = zipFiles(readFileSync(join(out, "moorai-browser-guard-0.1.0-selfhosted.zip")));
  assert.ok(JSON.parse(files["manifest.json"]).host_permissions.includes("https://console.example.com/*"));
  assert.equal(read("manifest.json"), before, "the source manifest is untouched");
  assert.notEqual(pack(["--out", tmp("bad"), "--console-origin", "http://console.example.com"]).status, 0);
});

// ---- force-install policy templates -------------------------------------------------------------------

const ID = "abcdefghijklmnopabcdefghijklmnop";
function policy(args) { return spawnSync(process.execPath, [join(ROOT, "scripts", "browser-ext-policy.mjs"), ...args], { encoding: "utf8" }); }

function balancedXml(s) {
  const body = s.replace(/<\?xml[^>]*\?>/, "").replace(/<!DOCTYPE[^>]*>/, "").replace(/<!--[\s\S]*?-->/g, "");
  const stack = [];
  for (const m of body.matchAll(/<(\/?)([A-Za-z][\w:.-]*)[^>]*?(\/?)>/g)) {
    if (m[3] === "/") continue;
    if (m[1]) { if (stack.pop() !== m[2]) return false; } else stack.push(m[2]);
  }
  return stack.length === 0;
}

test("policy: rejects an id that is not 32 letters a-p", () => {
  assert.notEqual(policy(["--id", "not-an-id", "--out", tmp("x")]).status, 0);
});

test("policy: renders Chrome and Edge force-install for macOS, Windows, Linux and the ADMX, with the managed settings", () => {
  const out = tmp("pol");
  const r = policy(["--id", ID, "--server-url", "https://console.example.com/?a=1&b=2", "--install-token", "tok-123", "--mode", "block", "--lock", "--out", out]);
  assert.equal(r.status, 0, r.stderr);
  const f = (n) => readFileSync(join(out, n), "utf8");
  const names = readdirSync(out, { recursive: true }).map(String).sort();
  for (const n of ["chrome-macos.mobileconfig", "edge-macos.mobileconfig", "chrome-windows.reg", "edge-windows.reg", "chrome-linux-policy.json", "moorai-browser-guard.admx", join("en-US", "moorai-browser-guard.adml")]) assert.ok(names.includes(n), n);
  for (const n of names.filter((x) => /\.(mobileconfig|reg|json|admx|adml)$/.test(x))) assert.ok(!f(n).includes("__"), `placeholder left in ${n}`);

  const cm = f("chrome-macos.mobileconfig");
  assert.ok(balancedXml(cm));
  assert.ok(cm.includes(`<string>${ID};https://clients2.google.com/service/update2/crx</string>`));
  assert.ok(cm.includes(`com.google.Chrome.extensions.${ID}`));
  assert.ok(cm.includes("https://console.example.com/?a=1&amp;b=2"), "XML-escaped");
  assert.ok(f("edge-macos.mobileconfig").includes(`<string>${ID};https://edge.microsoft.com/extensionwebstorebase/v1/crx</string>`));

  const cr = f("chrome-windows.reg");
  assert.ok(cr.startsWith("Windows Registry Editor Version 5.00"));
  assert.ok(cr.includes("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist]"));
  assert.ok(cr.includes(`"1"="${ID};https://clients2.google.com/service/update2/crx"`));
  assert.ok(cr.includes(`[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${ID}\\policy]`));
  assert.ok(cr.includes('"mode"="block"') && cr.includes('"lockSettings"=dword:00000001') && cr.includes('"installToken"="tok-123"'));
  const er = f("edge-windows.reg");
  assert.ok(er.includes("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist]"));
  assert.ok(er.includes(`"1"="${ID};https://edge.microsoft.com/extensionwebstorebase/v1/crx"`));

  const lj = JSON.parse(f("chrome-linux-policy.json"));
  assert.deepEqual(lj.ExtensionInstallForcelist, [`${ID};https://clients2.google.com/service/update2/crx`]);
  assert.deepEqual(lj["3rdparty"].extensions[ID], { serverUrl: "https://console.example.com/?a=1&b=2", installToken: "tok-123", mode: "block", reportEnabled: true, lockSettings: true });

  const admx = f("moorai-browser-guard.admx"), adml = f(join("en-US", "moorai-browser-guard.adml"));
  assert.ok(balancedXml(admx) && balancedXml(adml));
  assert.ok(admx.includes(`Software\\Policies\\Google\\Chrome\\3rdparty\\extensions\\${ID}\\policy`));
  assert.ok(admx.includes(`Software\\Policies\\Microsoft\\Edge\\3rdparty\\extensions\\${ID}\\policy`));
  for (const m of admx.matchAll(/\$\(string\.([A-Za-z0-9_]+)\)/g)) assert.ok(adml.includes(`<string id="${m[1]}">`), `ADML string ${m[1]}`);
  for (const m of admx.matchAll(/\$\(presentation\.([A-Za-z0-9_]+)\)/g)) assert.ok(adml.includes(`<presentation id="${m[1]}">`), `ADML presentation ${m[1]}`);

  if (process.platform === "darwin" && existsSync("/usr/bin/plutil")) {
    for (const n of ["chrome-macos.mobileconfig", "edge-macos.mobileconfig"]) {
      const lint = spawnSync("/usr/bin/plutil", ["-lint", join(out, n)], { encoding: "utf8" });
      assert.equal(lint.status, 0, `${n}: ${lint.stdout}${lint.stderr}`);
    }
  }
});

test("policy: no install token given → no token key anywhere; a self-hosted update URL replaces the store URL", () => {
  const out = tmp("pol2");
  const r = policy(["--id", ID, "--server-url", "https://console.example.com", "--update-url", "https://intranet.example/moorai/updates.xml", "--out", out]);
  assert.equal(r.status, 0, r.stderr);
  for (const n of ["chrome-macos.mobileconfig", "chrome-windows.reg", "chrome-linux-policy.json", "edge-windows.reg"]) {
    const s = readFileSync(join(out, n), "utf8");
    assert.ok(!s.includes("installToken"), n);
    assert.ok(s.includes(`${ID};https://intranet.example/moorai/updates.xml`), n);
  }
});
