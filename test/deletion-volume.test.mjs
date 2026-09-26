// Cumulative destructive volume: deletions summed across the calls of one session. Crossing the
// threshold posts one content-free alert and (mode "ask", the default) raises the NEXT deletion call to
// ask. Counts and timestamps only.
//
//   node --test --import ./test/hermetic-env.mjs test/deletion-volume.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { deletionTally, assessDeletionVolume, deletionConfig } from "../data/deletion-volume.js";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");

// ---- per-command tally ----

const TALLY = [
  ["rm a.txt b.txt c.txt", { ops: 3, rec: 0, cmds: 1 }],
  ["rm -f -- -weird.txt", { ops: 1, rec: 0, cmds: 1 }],
  ["rm -rf build dist", { ops: 2, rec: 1, cmds: 1 }],
  ["sudo rm -r -f /var/tmp/x", { ops: 1, rec: 1, cmds: 1 }],
  ["rm -r build", { ops: 1, rec: 0, cmds: 1 }],
  ["rmdir empty1 empty2", { ops: 2, rec: 0, cmds: 1 }],
  ["unlink one", { ops: 1, rec: 0, cmds: 1 }],
  ["find . -name '*.log' -delete", { ops: 1, rec: 1, cmds: 1 }],
  ["find . -type f -exec rm {} \\;", { ops: 1, rec: 1, cmds: 1 }],
  ["ls *.tmp | xargs rm -f", { ops: 1, rec: 0, cmds: 1 }],
  ["Remove-Item -Recurse -Force .\\out", { ops: 1, rec: 1, cmds: 1 }],
  ["Remove-Item x.txt -Filter *.log", { ops: 1, rec: 0, cmds: 1 }],
  ["rd /s /q build", { ops: 1, rec: 1, cmds: 1 }],
  ["del /q a.txt b.txt", { ops: 2, rec: 0, cmds: 1 }],
  ["git clean -fdx", { ops: 1, rec: 0, cmds: 1 }],
  ["git clean -f -e keep.me src/ docs/", { ops: 2, rec: 0, cmds: 1 }],
  ["git reset --hard HEAD~3", { ops: 1, rec: 0, cmds: 1 }],
  ["psql -c 'DROP TABLE users'", { ops: 1, rec: 0, cmds: 1 }],
  ["rm a && rm -rf b; git clean -f", { ops: 3, rec: 1, cmds: 3 }],
  ["cd /tmp && FOO=1 rm x y", { ops: 2, rec: 0, cmds: 1 }]
];
const NONE = ["ls -la", "git clean -n", "git clean -fn", "git clean", "echo rm -rf /", "git rm --cached x", "npm run clean", "rm", "cat notes-for-release.md", "Get-ChildItem -Recurse -Force", ""];

for (const [c, want] of TALLY) test(`tally: ${JSON.stringify(c)}`, () => assert.deepEqual(deletionTally(c), want));
for (const c of NONE) test(`tally: nothing on ${JSON.stringify(c)}`, () => assert.deepEqual(deletionTally(c), { ops: 0, rec: 0, cmds: 0 }));

// ---- the session window ----

const C = (o = {}) => ({ ...deletionConfig(null), ...o });
const T = (ops, rec = 0) => ({ ops, rec, cmds: 1 });

test("session: crossing the operand threshold alerts once and arms an ask for the next deletion", () => {
  const c = C({ operands: 10 });
  let r = assessDeletionVolume(null, "S", T(6), 1000, c);
  assert.equal(r.alert, null);
  assert.equal(r.escalate, false);
  r = assessDeletionVolume(r.state, "S", T(4), 2000, c);
  assert.deepEqual(r.alert, { operands: 10, recursive: 0, calls: 2 });
  assert.equal(r.escalate, false, "the crossing call itself is not escalated");
  r = assessDeletionVolume(r.state, "S", T(1), 3000, c);
  assert.equal(r.escalate, true, "the next deletion asks");
  assert.equal(r.alert, null, "no second alert");
  r = assessDeletionVolume(r.state, "S", T(1), 4000, c);
  assert.equal(r.escalate, false, "the ask was consumed and the window cleared");
  // another full threshold re-arms the ask but never re-alerts
  r = assessDeletionVolume(r.state, "S", T(9), 5000, c);
  assert.equal(r.alert, null);
  r = assessDeletionVolume(r.state, "S", T(1), 6000, c);
  assert.equal(r.escalate, true);
});

test("session: recursive threshold, window expiry, per-session isolation, no-deletion calls change nothing", () => {
  const c = C({ recursive: 3, windowMin: 10 });
  let r = assessDeletionVolume(null, "S", T(1, 1), 0, c);
  r = assessDeletionVolume(r.state, "S", T(1, 1), 3 * 60000, c);
  r = assessDeletionVolume(r.state, "S", T(1, 1), 11 * 60000 + 1, c);
  assert.equal(r.alert, null, "the first recursive delete fell out of the 10-minute window");
  r = assessDeletionVolume(r.state, "S", T(1, 1), 12 * 60000, c);
  assert.deepEqual(r.alert, { operands: 3, recursive: 3, calls: 3 });
  const other = assessDeletionVolume(r.state, "S2", T(1, 1), 12 * 60000, c);
  assert.equal(other.alert, null);
  assert.equal(other.escalate, false, "a new session starts from zero");
  const noop = assessDeletionVolume(r.state, "S", { ops: 0, rec: 0, cmds: 0 }, 12 * 60000, c);
  assert.equal(noop.dirty, false);
  assert.equal(noop.escalate, false, "a non-deletion call does not consume the ask");
});

test("session: mode alert never escalates; mode off is honoured by the caller's config", () => {
  const c = C({ operands: 2, mode: "alert" });
  let r = assessDeletionVolume(null, "S", T(2), 1, c);
  assert.ok(r.alert);
  r = assessDeletionVolume(r.state, "S", T(1), 2, c);
  assert.equal(r.escalate, false);
  assert.equal(deletionConfig({ deletionVolume: { mode: "off" } }).mode, "off");
  assert.deepEqual(deletionConfig(null), { mode: "ask", operands: 25, recursive: 5, windowMin: 15, maxSessions: 32 });
});

test("session: malformed state is an empty window; sessions are LRU-capped", () => {
  for (const bad of [null, 1, [], { sessions: [] }, { sessions: { S: { win: "x" } } }]) {
    assert.equal(assessDeletionVolume(bad, "S", T(1), 1, C()).alert, null);
  }
  let st = null;
  for (let i = 0; i < 40; i++) st = assessDeletionVolume(st, `S${i}`, T(1), i, C({ maxSessions: 5 })).state;
  assert.equal(Object.keys(st.sessions).length, 5);
  assert.ok(st.sessions.S39);
});

// ---- end to end through the real hook ----

async function withServer(policy, fn) {
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(policy)); return; }
    if (req.url === "/api/alerts" && req.method === "POST") {
      let b = ""; req.on("data", (c) => { b += c; }); req.on("end", () => { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try { return await fn(server.address().port, alerts); } finally { server.close(); }
}

function makeHome(port) {
  const home = mkdtempSync(join(tmpdir(), "moorai-delvol-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", installToken: "tok-delvol" }));
  return home;
}

async function runHook(home, session, command) {
  const child = spawn(process.execPath, [HOOK], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" } });
  let out = "";
  child.stdout.on("data", (c) => { out += c; });
  child.stderr.on("data", () => {});
  child.stdin.end(JSON.stringify({ tool_name: "Bash", session_id: session, cwd: home, tool_input: { command } }));
  await new Promise((r) => child.on("exit", r));
  const t = out.trim();
  if (!t) return { decision: "allow", reason: "" };
  const o = JSON.parse(t).hookSpecificOutput || {};
  return { decision: o.permissionDecision || "allow", reason: o.permissionDecisionReason || "" };
}

const CATEGORY = "Unusual deletion volume in session";
const volAlerts = (alerts) => alerts.filter((a) => a.category === CATEGORY);

test("hook e2e: threshold alerts once, escalates the next deletion to ask, resets per session", async () => {
  await withServer({ captureTier: "content-free", deletionVolume: { operands: 6 } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      assert.equal((await runHook(home, "s1", "rm payroll-q3.xlsx board-minutes.docx merger-plan.pdf")).decision, "allow");
      assert.equal(volAlerts(alerts).length, 0);
      assert.equal((await runHook(home, "s1", "rm salaries.csv offer-letters.zip layoffs-draft.md")).decision, "allow", "report-only on the crossing call");
      const hits = volAlerts(alerts);
      assert.equal(hits.length, 1);
      assert.equal(hits[0].threatId, 43);
      assert.equal(hits[0].stage, "behavior");
      assert.deepEqual({ operands: hits[0].signature.operands, recursive: hits[0].signature.recursive, calls: hits[0].signature.calls }, { operands: 6, recursive: 0, calls: 2 });
      assert.equal((await runHook(home, "s1", "ls -la")).decision, "allow", "a non-deletion call is not escalated");
      const esc = await runHook(home, "s1", "rm notes-final.txt");
      assert.equal(esc.decision, "ask", "the next deletion is escalated");
      assert.match(esc.reason, /unusual deletion volume in session/);
      assert.equal((await runHook(home, "s1", "rm notes-final-2.txt")).decision, "allow", "the ask is consumed");
      assert.equal(volAlerts(alerts).length, 1, "one alert per session");
      // a new session starts from zero
      assert.equal((await runHook(home, "s2", "rm one-more.txt")).decision, "allow");
      assert.equal(volAlerts(alerts).length, 1);
      // counts and timestamps only
      const p = join(home, ".moorai", "deletion-volume.json");
      assert.ok(existsSync(p));
      const blob = readFileSync(p, "utf8") + JSON.stringify(volAlerts(alerts));
      for (const raw of ["payroll", "salaries", "merger", "notes-final", "one-more", "rm "]) assert.ok(!blob.includes(raw), `raw ${raw} leaked`);
    } finally { rmSync(home, { recursive: true, force: true }); }
  });
});

test("hook e2e: with #43 set to notify, a recursive delete after the threshold is raised to ask", async () => {
  await withServer({ captureTier: "content-free", threatPolicy: { 43: "notify" }, deletionVolume: { recursive: 2 } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      assert.equal((await runHook(home, "r1", "rm -rf build")).decision, "allow", "#43 notify: per-call allow");
      assert.equal((await runHook(home, "r1", "rm -rf dist")).decision, "allow");
      assert.equal(volAlerts(alerts).length, 1);
      assert.equal((await runHook(home, "r1", "rm -rf coverage")).decision, "ask");
    } finally { rmSync(home, { recursive: true, force: true }); }
  });
});

test("hook e2e: mode alert reports without ever asking", async () => {
  await withServer({ captureTier: "content-free", deletionVolume: { operands: 2, mode: "alert" } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      await runHook(home, "m1", "rm a b");
      assert.equal(volAlerts(alerts).length, 1);
      assert.equal((await runHook(home, "m1", "rm c")).decision, "allow");
    } finally { rmSync(home, { recursive: true, force: true }); }
  });
});
