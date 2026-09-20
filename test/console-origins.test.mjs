// Which origins may script the local policy-compiler endpoint, and which console hostnames the
// desktop app is allowed to reach. Both are hostname allowlists that no other test covers, and both
// break silently: a missing origin shows up as a CORS rejection or a blocked fetch at runtime, never
// as a failing build. The console answers on two names — app.moorai.dev is where it serves from, and
// moorai.glick.run is the name older installs were built against, which now redirects. A WebSocket
// handshake does NOT follow a redirect, so the app's own base must name the serving host directly.
//
//   node --test test/console-origins.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { originAllowed } from "../cli/moorai-localsvc.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const tauriConf = JSON.parse(readFileSync(join(ROOT, "src-tauri/tauri.conf.json"), "utf8"));
const apiSrc = readFileSync(join(ROOT, "src/api.js"), "utf8");

const CONSOLE_HOSTS = ["https://app.moorai.dev", "https://moorai.glick.run"];

test("the local endpoint accepts both console origins and localhost, and nothing else", () => {
  for (const o of CONSOLE_HOSTS) assert.equal(originAllowed(o), true, `${o} must be allowed`);
  assert.equal(originAllowed("http://localhost:5173"), true, "dev origin allowed");
  assert.equal(originAllowed("http://127.0.0.1:8787"), true, "loopback allowed");

  assert.equal(originAllowed("https://app.moorai.dev.evil.test"), false, "suffix-extended host refused");
  assert.equal(originAllowed("https://evil.test"), false, "unrelated origin refused");
  assert.equal(originAllowed(""), false, "empty origin refused");
  assert.equal(originAllowed(undefined), false, "missing origin refused");
});

test("the app CSP permits both console hostnames over https and wss", () => {
  const csp = tauriConf.app.security.csp;
  for (const host of CONSOLE_HOSTS) {
    assert.ok(csp.includes(host), `CSP must allow ${host}`);
    assert.ok(csp.includes(host.replace("https://", "wss://")), `CSP must allow the wss form of ${host}`);
  }
});

test("the updater tries both hostnames, so an install built against either keeps updating", () => {
  const eps = tauriConf.plugins.updater.endpoints;
  for (const host of CONSOLE_HOSTS) {
    assert.ok(eps.some((e) => e.startsWith(host)), `updater must list ${host}`);
  }
});

test("the app's default base names the serving host — a WebSocket cannot follow a redirect", () => {
  const m = apiSrc.match(/const BASE = \(localStorage\.getItem\("raiseme\.server"\) \|\| "([^"]+)"\)/);
  assert.ok(m, "BASE default is declared in the expected shape");
  assert.equal(m[1], "https://app.moorai.dev",
    "BASE must be the host the console serves from, not one that redirects to it");
});
