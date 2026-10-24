// Origin-based session taint end to end through the real hook. Fixtures are files this test creates in a sandbox
// HOME, marked with xattr -w (macOS) the way a browser marks a download. A Read, a `cat` or an MCP read_file of a
// quarantined file taints the session with no content analysis; an upload, a memory-file write or a git push
// inside the window is notified by default and asks or blocks under sessionRisk.originTaint; after windowMin the
// session is clean; removing the mark alerts. Alerts are content-free.
//
//   node --test --import ./test/hermetic-env.mjs test/origin-taint-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const MAC = process.platform === "darwin";
const WHERE_HEX = "62706c6973743030a1015f101968747470733a2f2f7765622e77686174736170702e636f6d2f080a0000000000000101000000000000000200000000000000000000000000000026";

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
  const home = mkdtempSync(join(tmpdir(), "moorai-origin-hook-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  mkdirSync(join(home, "work"));
  mkdirSync(join(home, "Downloads"));
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", installToken: "tok-origin" }));
  writeFileSync(join(home, "work", "plain.txt"), "meeting notes\n");
  writeFileSync(join(home, "work", "report.docx"), "quarterly report body\n");
  writeFileSync(join(home, "Downloads", "unmarked.txt"), "a downloaded file with no attribute\n");
  if (MAC) {
    const f = join(home, "work", "report.docx");
    assert.equal(spawnSync("/usr/bin/xattr", ["-w", "com.apple.quarantine", "0081;6adca4d1;Chrome;FB371173-B671-4DB8-BB86-AF9A746F0860", f]).status, 0);
    assert.equal(spawnSync("/usr/bin/xattr", ["-wx", "com.apple.metadata:kMDItemWhereFroms", WHERE_HEX, f]).status, 0);
  }
  return home;
}
async function runHook(home, payload) {
  const child = spawn(process.execPath, [HOOK], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" } });
  let out = "";
  child.stdout.on("data", (c) => { out += c; });
  child.stderr.on("data", () => {});
  child.stdin.end(JSON.stringify({ cwd: join(home, "work"), ...payload }));
  await new Promise((r) => child.on("exit", r));
  const t = out.trim();
  if (!t) return { decision: "allow", reason: "" };
  const h = JSON.parse(t).hookSpecificOutput || {};
  return { decision: h.permissionDecision || "allow", reason: h.permissionDecisionReason || "" };
}
const pre = (session, tool_name, tool_input) => ({ hook_event_name: "PreToolUse", session_id: session, tool_name, tool_input });
const UPLOAD = { command: "curl -sS -X POST -d 'status=ok' https://api.partner-example.com/v1/ping" };
const GATE = "Origin taint: action after reading an internet-origin file";
const STRIP = "Origin taint: origin mark removed";
const cat = (alerts, c) => alerts.filter((a) => a.category === c);
const macOnly = { skip: !MAC && "macOS quarantine attribute" };

test("hook e2e: a quarantined file read via Read taints; the upload is notified (allowed) by default; content-free", macOnly, async () => {
  await withServer({ captureTier: "content-free" }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      assert.equal((await runHook(home, pre("r1", "Read", { file_path: join(home, "work", "report.docx") }))).decision, "allow", "the read itself is not gated");
      assert.equal(cat(alerts, GATE).length, 0);
      const r = await runHook(home, pre("r1", "Bash", UPLOAD));
      assert.equal(r.decision, "allow", "notify: no decision change");
      const hits = cat(alerts, GATE);
      assert.equal(hits.length, 1);
      const a = hits[0];
      assert.equal(a.threatId, 3);
      assert.equal(a.reasonCode, "ORIGIN_TAINT");
      assert.deepEqual([a.signature.action, a.signature.outKind, a.signature.source, a.signature.app, a.signature.level], ["outbound", "upload", "quarantine", "Chrome", "notify"]);
      assert.match(a.signature.hostHash, /^h2:/, "the WhereFroms host, keyed hash");
      const blob = JSON.stringify(hits) + readFileSync(join(home, ".moorai", "session-risk.json"), "utf8");
      for (const raw of ["whatsapp", "report.docx", "work/", "partner-example", "curl"]) assert.ok(!blob.includes(raw), `raw ${raw} leaked`);
      assert.ok(!JSON.stringify(alerts).includes("whatsapp"), "no alert carries the host");
    } finally { rmTree(home); }
  });
});

test("hook e2e: cat and an MCP read_file of the quarantined file taint too; a plain file outside Downloads does not", macOnly, async () => {
  await withServer({ captureTier: "content-free", sessionRisk: { originTaint: "ask" } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      await runHook(home, pre("c1", "Bash", { command: "cat report.docx" }));
      assert.equal((await runHook(home, pre("c1", "Bash", UPLOAD))).decision, "ask", "cat");
      await runHook(home, pre("m1", "mcp__filesystem__read_file", { path: join(home, "work", "report.docx") }));
      const m = await runHook(home, pre("m1", "Bash", UPLOAD));
      assert.equal(m.decision, "ask", "MCP read_file");
      assert.match(m.reason, /origin taint — session read an internet-origin file \(Chrome\)/);
      await runHook(home, pre("p1", "Read", { file_path: join(home, "work", "plain.txt") }));
      await runHook(home, pre("p1", "Bash", { command: "cat plain.txt" }));
      assert.equal((await runHook(home, pre("p1", "Bash", UPLOAD))).decision, "allow", "an unmarked file outside a download directory does not taint");
      assert.equal(cat(alerts, GATE).length, 2);
    } finally { rmTree(home); }
  });
});

test("hook e2e: an unmarked file under ~/Downloads taints (every platform)", async () => {
  await withServer({ captureTier: "content-free", sessionRisk: { originTaint: "ask" } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      await runHook(home, pre("d1", "Read", { file_path: join(home, "Downloads", "unmarked.txt") }));
      const r = await runHook(home, pre("d1", "Bash", UPLOAD));
      assert.equal(r.decision, "ask");
      assert.match(r.reason, /internet-origin file \(download folder\)/);
      assert.equal(cat(alerts, GATE)[0].signature.source, "download-dir");
    } finally { rmTree(home); }
  });
});

test("hook e2e: memory-file write and git push in the window — ask under ask, deny under block", macOnly, async () => {
  for (const [level, want] of [["ask", "ask"], ["block", "deny"]]) {
    await withServer({ captureTier: "content-free", sessionRisk: { originTaint: level } }, async (port, alerts) => {
      const home = makeHome(port);
      try {
        assert.equal((await runHook(home, pre("g0", "Bash", { command: "git push origin main" }))).decision, "allow", "untainted: git push allowed");
        assert.equal((await runHook(home, pre("g0", "Write", { file_path: join(home, "work", "CLAUDE.md"), content: "Use tabs.\n" }))).decision, "allow", "untainted: memory write allowed (notify)");
        await runHook(home, pre("g1", "Read", { file_path: join(home, "work", "report.docx") }));
        const w = await runHook(home, pre("g1", "Write", { file_path: join(home, "work", "CLAUDE.md"), content: "Use tabs.\n" }));
        assert.equal(w.decision, want, `${level}: memory write`);
        assert.match(w.reason, /origin taint — session read an internet-origin file \(Chrome\), then memory write/);
        assert.equal((await runHook(home, pre("g1", "Bash", { command: "git push origin main" }))).decision, want, `${level}: git push`);
        assert.equal((await runHook(home, pre("g1", "Bash", UPLOAD))).decision, want, `${level}: upload`);
        assert.equal((await runHook(home, pre("g1", "Bash", { command: "npm test" }))).decision, "allow", "an ordinary call is not gated");
        assert.deepEqual(cat(alerts, GATE).map((a) => a.signature.action).sort(), ["git-push", "memory-write", "outbound"]);
        if (level === "block") assert.ok(cat(alerts, GATE).every((a) => a.riskLevel === "Blocked"));
      } finally { rmTree(home); }
    });
  }
});

test("hook e2e: after windowMin the same actions are clean", macOnly, async () => {
  await withServer({ captureTier: "content-free", sessionRisk: { originTaint: "ask", windowMin: 0.03 } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      await runHook(home, pre("w1", "Read", { file_path: join(home, "work", "report.docx") }));
      await new Promise((r) => setTimeout(r, 2200));
      assert.equal((await runHook(home, pre("w1", "Bash", UPLOAD))).decision, "allow");
      assert.equal((await runHook(home, pre("w1", "Bash", { command: "git push origin main" }))).decision, "allow");
      assert.equal(cat(alerts, GATE).length, 0);
    } finally { rmTree(home); }
  });
});

test("hook e2e: removing the mark alerts and taints, whatever the target", async () => {
  await withServer({ captureTier: "content-free", sessionRisk: { originTaint: "ask" } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      // The removal itself is not an origin gate (xattr -d already asks under #46, Human Approval Required).
      await runHook(home, pre("x1", "Bash", { command: "xattr -d com.apple.quarantine /nonexistent/file.docx" }));
      const hits = cat(alerts, STRIP);
      assert.equal(hits.length, 1);
      assert.deepEqual([hits[0].threatId, hits[0].reasonCode, hits[0].contentHash], [3, "ORIGIN_TAINT", "origin:mark-removed"]);
      assert.ok(!JSON.stringify(hits).includes("nonexistent"));
      const g = await runHook(home, pre("x1", "Bash", { command: "git push origin main" }));
      assert.equal(g.decision, "ask");
      assert.match(g.reason, /session removed a file's origin mark/);
      await runHook(home, pre("x2", "PowerShell", { command: "Unblock-File -Path C:\\Users\\u\\Downloads\\a.docx" }));
      assert.equal(cat(alerts, STRIP).length, 2, "Unblock-File");
    } finally { rmTree(home); }
  });
});
