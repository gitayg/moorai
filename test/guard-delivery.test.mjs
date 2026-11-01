// moorai-guard (the `claude -p` wrapper) delivers its alerts: every post carries X-Install-Token (the
// console's POST /api/alerts answers 401 without one), a post the console does not take goes to the alert
// outbox (unnumbered: the guard takes no seq), and the intent-override alert carries its origin.
//
//   node --test --import ./test/hermetic-env.mjs test/guard-delivery.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import net from "node:net";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "cli", "moorai-guard.mjs");
const TOKEN = "tok-guard-delivery";
const AWS = "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// Answers 401 to an alert without the right token, as the console does.
async function tokenConsole() {
  const alerts = [], refused = [];
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); return res.end(); }
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ captureTier: "content-free" })); }
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/api/alerts") {
        if (req.headers["x-install-token"] !== TOKEN) { refused.push(body); res.writeHead(401, { "content-type": "application/json" }); return res.end(JSON.stringify({ error: "enrollment required" })); }
        alerts.push(JSON.parse(body)); res.writeHead(201); return res.end(JSON.stringify({ ok: true }));
      }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, refused, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}
function home(url) {
  const h = mkdtempSync(join(tmpdir(), "moorai-guard-delivery-"));
  mkdirSync(join(h, ".moorai"), { recursive: true });
  writeFileSync(join(h, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "acme", installToken: TOKEN }));
  return h;
}
// PATH is an empty directory: `claude` is never found, so nothing is sent to a model; the guard's own posts
// all happen before it tries.
function guard(h, args) {
  const bin = mkdtempSync(join(tmpdir(), "moorai-guard-nopath-"));
  return new Promise((res) => {
    const c = spawn(process.execPath, [GUARD, ...args], { cwd: h, env: { HOME: h, USERPROFILE: h, PATH: bin }, stdio: ["ignore", "pipe", "pipe"] });
    let err = "";
    c.stderr.on("data", (d) => (err += d));
    c.stdout.on("data", () => {});
    c.on("close", (status) => { rmTree(bin); res({ status, err }); });
  });
}

test("guard alerts carry X-Install-Token and reach a console that requires it", async () => {
  const c = await tokenConsole();
  const h = home(c.url);
  try {
    await guard(h, ["--decide", "abort", `deploy with ${AWS}`]);
    assert.ok(c.alerts.length > 0, `nothing stored; refused ${c.refused.length}`);
    assert.equal(c.refused.length, 0, "a post without the token was refused");
  } finally { await c.close(); rmTree(h); }
});

test("guard --decide proceed: the intent-override alert carries origin guard-flag (inferred)", async () => {
  const c = await tokenConsole();
  const h = home(c.url);
  try {
    await guard(h, ["--decide", "proceed", `deploy with ${AWS}`]);
    const o = c.alerts.find((a) => a.category === "Intent: user override");
    assert.ok(o, "no intent-override alert");
    assert.deepEqual([o.origin.kind, o.origin.status, o.origin.basis], ["override", "inferred", "guard-flag"]);
  } finally { await c.close(); rmTree(h); }
});

test("console unreachable: guard alerts go to the outbox, unnumbered", async () => {
  const s = net.createServer();
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  const port = s.address().port;
  await new Promise((r) => s.close(r));
  const h = home(`http://127.0.0.1:${port}`);
  try {
    await guard(h, ["--decide", "abort", `deploy with ${AWS}`]);
    const lines = readFileSync(join(h, ".moorai", "alert-outbox.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    assert.ok(lines.length > 0);
    assert.ok(lines.every((e) => e.seq === null && e.via === "direct-failed"));
    assert.ok(lines.every((e) => !("matchText" in e.alert)));
  } finally { rmTree(h); }
});

test("an alert the console stored is not queued again: the guard waits for its posts before it exits", async () => {
  const c = await tokenConsole();
  const h = home(c.url);
  try {
    await guard(h, ["--decide", "proceed", `deploy with ${AWS}`]);
    const overrides = c.alerts.filter((a) => a.category === "Intent: user override");
    assert.equal(overrides.length, 1, `the console stored ${overrides.length} override alerts`);
    let queued = [];
    try { queued = readFileSync(join(h, ".moorai", "alert-outbox.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { queued = []; }
    assert.deepEqual(queued.map((e) => e.alert.category), [], "an alert the console answered 201 for went to the outbox, so the worker sends it a second time");
  } finally { await c.close(); rmTree(h); }
});
