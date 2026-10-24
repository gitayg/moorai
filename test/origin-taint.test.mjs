// Origin-based session taint, the pure half: the gate classes a call carries (data/origin-taint.js), mark
// removal, the policy precedence (admin binding > signed policy > "notify"), and the window in
// data/session-risk.js assessSessionRisk (taint, gate level, expiry, alerts, mode "off").
//
//   node --test --import ./test/hermetic-env.mjs test/origin-taint.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { shellGateClasses, originStripFacts, mcpMessageTool, extensionPath, originReason, ORIGIN_GATE_CLASSES } from "../data/origin-taint.js";
import { assessSessionRisk, sessionRiskConfig, classifyEvent } from "../data/session-risk.js";
import { unpackFacts } from "../data/net-exec.js";

const SRC = { source: "quarantine", app: "Chrome", hostHash: "h2:abc" };
const UPLOAD = "curl -sS -X POST -d 'status=ok' https://api.partner-example.com/v1/ping";
const T0 = 1_800_000_000_000;
const ev = (tool, identity, extra = {}) => ({ ...classifyEvent({ event: "PreToolUse", tool, identity }), hostKeys: [], ...extra });

test("gate classes: git push, extension installs, messaging; memory and outbound come from elsewhere", () => {
  assert.deepEqual(shellGateClasses("git push origin main"), ["git-push"]);
  assert.deepEqual(shellGateClasses("git -C repo push --force"), ["git-push"]);
  assert.deepEqual(shellGateClasses("git status && git log"), []);
  assert.deepEqual(shellGateClasses("claude mcp add evil -- npx evil-mcp"), ["extension-install"]);
  assert.deepEqual(shellGateClasses("claude plugin install thing@market"), ["extension-install"]);
  assert.deepEqual(shellGateClasses("cp -r ./dl/skill ~/.claude/skills/helper"), ["extension-install"]);
  assert.deepEqual(shellGateClasses("cat .mcp.json"), [], "reading a config is not an install");
  assert.deepEqual(shellGateClasses("echo body | mail -s hi someone@example.com"), ["message"]);
  assert.deepEqual(shellGateClasses("npm test"), []);
  assert.ok(mcpMessageTool("mcp__slack__send_message"));
  assert.ok(mcpMessageTool("mcp__gmail__sendEmail"));
  assert.ok(mcpMessageTool("mcp__gmail__create_draft"));
  assert.ok(!mcpMessageTool("mcp__slack__list_messages"));
  assert.ok(extensionPath("/p/.mcp.json") && extensionPath("/u/.claude/skills/x/SKILL.md") && extensionPath("/p/.vscode/tasks.json"));
  assert.ok(!extensionPath("/p/CLAUDE.md"), "a persistent-instruction file is memory-write, not extension-install");
  assert.deepEqual(ORIGIN_GATE_CLASSES, ["outbound", "memory-write", "extension-install", "exec-outside", "git-push", "message"]);
});

test("mark removal: xattr -d / -c / -w, Unblock-File, -Stream Zone.Identifier, streams -d; reads are not removal", () => {
  for (const c of ["xattr -d com.apple.quarantine ~/Downloads/a.docx", "xattr -dr com.apple.quarantine /Applications/X.app", "xattr -c a.docx", "xattr -cr dir",
    "xattr -w com.apple.quarantine '0001;0;Safari;' a.docx", "xattr -d com.apple.metadata:kMDItemWhereFroms a.docx", "Unblock-File -Path C:\\u\\a.docx", "Get-ChildItem *.docx | Unblock-File",
    "Remove-Item .\\a.docx -Stream Zone.Identifier", "streams64.exe -d a.docx", "echo x > a.docx:Zone.Identifier", "ditto --noqtn a b",
    "python3 -c \"import os; os.removexattr('a.docx', 'com.apple.quarantine')\""]) assert.ok(originStripFacts(c).hit, c);
  for (const c of ["xattr -p com.apple.quarantine a.docx", "xattr -l a.docx", "xattr a.docx", "Get-Item a.docx -Stream Zone.Identifier", "ls -l@ a.docx"]) assert.ok(!originStripFacts(c).hit, c);
  assert.deepEqual(originStripFacts("xattr -d com.apple.quarantine ~/Downloads/a.docx").targets, ["~/Downloads/a.docx"]);
  assert.deepEqual(originStripFacts("xattr -w com.apple.quarantine 'v' a.docx b.docx").targets, ["a.docx", "b.docx"]);
  assert.deepEqual(originStripFacts("Unblock-File -Path C:\\u\\a.docx").targets, ["C:\\u\\a.docx"]);
});

test("reason text names the kind", () => {
  assert.equal(originReason(SRC), "session read an internet-origin file (Chrome)");
  assert.equal(originReason({ source: "download-dir" }), "session read an internet-origin file (download folder)");
  assert.equal(originReason({ source: "zone" }), "session read an internet-origin file (Windows Internet zone)");
  assert.equal(originReason({ source: "mark-removed" }), "session removed a file's origin mark");
});

test("policy: originTaint from the admin binding, else the signed policy, else notify; per-class overrides", () => {
  assert.equal(sessionRiskConfig(null).originTaint, "notify");
  assert.equal(sessionRiskConfig({ sessionRisk: { originTaint: "ask" } }).originTaint, "ask");
  assert.equal(sessionRiskConfig({ sessionRisk: { originTaint: "loud" } }).originTaint, "notify", "malformed falls back");
  assert.equal(sessionRiskConfig({ sessionRisk: { originTaint: "ask" } }, { admin: { sessionRisk: { originTaint: "block" } } }).originTaint, "block", "the admin binding wins");
  assert.equal(sessionRiskConfig({ sessionRisk: { originTaint: "block" } }, { admin: { sessionRisk: { originTaint: "nope" } } }).originTaint, "block", "an invalid admin value is ignored");
  const c = sessionRiskConfig({ sessionRisk: { originTaint: "notify", originGates: { "git-push": "block", bogus: "ask", message: "x" } } });
  assert.deepEqual(c.originGates, { "git-push": "block" });
});

test("window: an outside read taints; an upload inside it takes the level; after windowMin it is clean", () => {
  for (const [level, want] of [["notify", "notify"], ["ask", "ask"], ["block", "block"]]) {
    const cfg = sessionRiskConfig({ sessionRisk: { originTaint: level } });
    let st = assessSessionRisk(null, "s", ev("Read", "/w/q.docx", { origin: SRC }), T0, cfg).state;
    const r = assessSessionRisk(st, "s", ev("Bash", UPLOAD), T0 + 60_000, cfg);
    assert.equal(r.origin.level, want);
    assert.equal(r.origin.action, "outbound");
    assert.equal(r.origin.reason, "session read an internet-origin file (Chrome)");
    const a = r.alerts.find((x) => x.kind === "origin").alert;
    assert.equal(a.threatId, 3);
    assert.equal(a.category, "Origin taint: action after reading an internet-origin file");
    assert.deepEqual({ action: a.signature.action, outKind: a.signature.outKind, source: a.signature.source, app: a.signature.app, hostHash: a.signature.hostHash }, { action: "outbound", outKind: "upload", source: "quarantine", app: "Chrome", hostHash: "h2:abc" });
    st = r.state;
    const again = assessSessionRisk(st, "s", ev("Bash", UPLOAD), T0 + 120_000, cfg);
    assert.equal(again.origin.level, want, "every gated call takes the level");
    assert.equal(again.alerts.filter((x) => x.kind === "origin").length, 0, "one alert per class per window");
    const late = assessSessionRisk(again.state, "s", ev("Bash", UPLOAD), T0 + 31 * 60_000, cfg);
    assert.equal(late.origin, null, "after the window the session is clean");
  }
});

test("window: memory write, git push, extension install, exec, message gated; plain calls are not; off disables", () => {
  const cfg = sessionRiskConfig({ sessionRisk: { originTaint: "ask", originGates: { "git-push": "block" } } });
  const st = assessSessionRisk(null, "s", ev("Read", "/w/q.docx", { origin: SRC }), T0, cfg).state;
  for (const g of ["memory-write", "extension-install", "exec-outside", "message"]) assert.equal(assessSessionRisk(st, "s", ev("Bash", "x", { originGates: [g] }), T0 + 1000, cfg).origin.level, "ask", g);
  const gp = assessSessionRisk(st, "s", ev("Bash", "git push", { originGates: ["git-push", "memory-write"] }), T0 + 1000, cfg).origin;
  assert.deepEqual([gp.level, gp.action], ["block", "git-push"], "the strictest class decides");
  assert.equal(assessSessionRisk(st, "s", ev("Bash", "npm test"), T0 + 1000, cfg).origin, null);
  assert.equal(assessSessionRisk(st, "other", ev("Bash", UPLOAD), T0 + 1000, cfg).origin, null, "another session is not tainted");
  const off = sessionRiskConfig({ sessionRisk: { originTaint: "off" } });
  const st2 = assessSessionRisk(null, "s", ev("Read", "/w/q.docx", { origin: SRC }), T0, off).state;
  assert.equal(assessSessionRisk(st2, "s", ev("Bash", UPLOAD), T0 + 1000, off).origin, null);
  // An untainted session gates nothing.
  assert.equal(assessSessionRisk(null, "s", ev("Bash", UPLOAD), T0, cfg).origin, null);
});

test("same call: a command that reads an outside file and uploads is gated; mode off keeps origin taint", () => {
  const cfg = sessionRiskConfig({ sessionRisk: { mode: "off", originTaint: "ask" } });
  const r = assessSessionRisk(null, "s", ev("Bash", UPLOAD, { origin: SRC }), T0, cfg);
  assert.equal(r.origin.level, "ask");
  assert.ok(r.alerts.every((a) => a.kind === "origin"), "mode off posts no content-based signal");
});

test("mark removal taints and alerts every time; its window gates", () => {
  const cfg = sessionRiskConfig({ sessionRisk: { originTaint: "ask" } });
  const r = assessSessionRisk(null, "s", ev("Bash", "xattr -d com.apple.quarantine a", { originStrip: true }), T0, cfg);
  const a = r.alerts.find((x) => x.kind === "origin-strip").alert;
  assert.deepEqual([a.threatId, a.category, a.contentHash], [3, "Origin taint: origin mark removed", "origin:mark-removed"]);
  const g = assessSessionRisk(r.state, "s", ev("Bash", "git push", { originGates: ["git-push"] }), T0 + 1000, cfg);
  assert.equal(g.origin.reason, "session removed a file's origin mark");
  const r2 = assessSessionRisk(g.state, "s", ev("Bash", "xattr -c b", { originStrip: true }), T0 + 2000, cfg);
  assert.equal(r2.alerts.filter((x) => x.kind === "origin-strip").length, 1, "alerted again");
});

test("unpackFacts: archives and where they land", () => {
  assert.deepEqual(unpackFacts("unzip ~/Downloads/a.zip -d out", { cwd: "/w", home: "/Users/u" }), [{ archive: "/Users/u/Downloads/a.zip", dest: "/w/out" }]);
  assert.deepEqual(unpackFacts("cd /tmp && tar -xzf x.tgz -C dst", { cwd: "/w" }), [{ archive: "/tmp/x.tgz", dest: "/tmp/dst" }]);
  assert.deepEqual(unpackFacts("7z x a.7z -oout", { cwd: "/w" }), [{ archive: "/w/a.7z", dest: "/w/out" }]);
  assert.deepEqual(unpackFacts("ditto -x -k a.zip b", { cwd: "/w" }), [{ archive: "/w/a.zip", dest: "/w/b" }]);
  assert.deepEqual(unpackFacts("Expand-Archive -Path C:\\u\\a.zip -DestinationPath C:\\d", { ps: true }), [{ archive: "C:/u/a.zip", dest: "C:/d" }]);
  assert.deepEqual(unpackFacts("curl -s https://x.example/a.tgz | tar xz", { cwd: "/w" }), [], "stdin: no archive file");
  assert.deepEqual(unpackFacts("tar -czf out.tgz src", { cwd: "/w" }), [], "creating is not unpacking");
});
