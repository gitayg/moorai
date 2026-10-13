// AI CLI started by an unexpected parent (cli/ai-cli-parents.mjs): classification, the ancestry walk, the
// per-session step and the process-table readers, with injected process tables.
//
//   node --test --import ./test/hermetic-env.mjs test/ai-cli-parents.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classifyImage, assessChain, aiCliParentStep, parentPolicy, lastParentClass, parseWinChain, winChainScript, readChainProc, readChainPs, readChainWindows, imageBase, isTempPath, AI_CLI_PARENT, AI_CLI_PARENT_CATEGORY, CACHE_FILE } from "../cli/ai-cli-parents.mjs";
import { rmTree } from "./fs-cleanup.mjs";

let pid = 1000;
const P = (image, path = "") => ({ pid: ++pid, ppid: 0, image, path });
// A chain from the hook's parent upward, with each ppid linked to the next entry.
const chain = (...xs) => { xs.forEach((x, i) => { x.ppid = xs[i + 1] ? xs[i + 1].pid : 0; }); return xs; };
const W = (dir, name) => P(name, `C:\\${dir}\\${name}`);

test("C2Agent shapes: a system host, an Office app, a script host, a temp or C:\\Windows image above the agent are flagged", () => {
  const cases = [
    [chain(P("bash.exe"), W("Users\\a\\AppData\\Roaming\\npm", "claude.exe"), W("Windows\\System32", "sihost.exe"), W("Windows\\System32", "svchost.exe")), {}, ["sihost.exe", "system-host", 1]],
    [chain(P("cmd.exe"), P("claude.exe"), P("cmd.exe"), W("Windows\\System32", "RuntimeBroker.exe")), {}, ["RuntimeBroker.exe", "system-host", 2]],
    [chain(P("node.exe"), P("codex.exe"), W("Windows", "xkqzv.exe")), { shim: true }, ["xkqzv.exe", "temp-or-system-path", 1]],
    [chain(P("node.exe"), P("cmd.exe"), P("node.exe"), P("pwsh.exe"), W("Windows\\Help", "updater32.exe")), { shim: true }, ["updater32.exe", "temp-or-system-path", 2]],
    [chain(P("bash.exe"), P("claude.exe"), P("powershell.exe"), W("Program Files\\Microsoft Office\\root\\Office16", "WINWORD.EXE")), {}, ["WINWORD.EXE", "office", 2]],
    [chain(P("bash.exe"), P("claude.exe"), P("python.exe"), W("Windows\\System32", "mshta.exe")), {}, ["mshta.exe", "script-host", 2]],
    [chain(P("sh"), P("claude", "/home/u/.local/bin/claude"), P("bash", "/usr/bin/bash"), P("agentd", "/tmp/.cache/agentd")), {}, ["agentd", "temp-or-system-path", 2]],
    [chain(P("bash.exe"), P("claude.exe"), W("Users\\u\\AppData\\Local\\Temp", "cmd.exe")), {}, ["cmd.exe", "temp-or-system-path", 1]],
    [chain(P("bash.exe"), P("claude.exe"), W("Users\\u\\AppData\\Roaming", "explorer.exe")), {}, ["explorer.exe", "system-host", 1]],
    [chain(P("bash.exe"), P("claude.exe"), W("Windows", "explorer.exe"), W("Windows\\System32", "sihost.exe")), {}, ["explorer.exe", "system-host", 1]],
    [chain(P("zsh"), P("claude"), P("osascript", "/usr/bin/osascript")), {}, ["osascript", "script-host", 1]]
  ];
  for (const [c, o, [image, cls, depth]] of cases) {
    const a = assessChain(c, o);
    assert.deepEqual([a.parentImage, a.parentClass, a.chainDepth], [image, cls, depth], c.map((x) => x.image).join(" <- "));
  }
});

test("ordinary launches read as normal: terminals, IDEs, the Claude desktop app, tmux, sshd, an AI CLI driving another, the init process", () => {
  const cases = [
    // measured on this Mac: Claude Code started by the Claude desktop app
    chain(P("zsh", "/bin/zsh"), P("claude", "/Users/u/Library/Application Support/Claude/claude-code/2.1.295/x/claude.app/Contents/MacOS/claude"), P("disclaimer", "/Applications/Claude.app/Contents/Helpers/disclaimer"), P("Claude", "/Applications/Claude.app/Contents/MacOS/Claude"), P("launchd", "/sbin/launchd")),
    chain(P("zsh"), P("claude"), P("zsh", "-zsh"), P("login", "/usr/bin/login"), P("iTerm2", "/Applications/iTerm.app/Contents/MacOS/iTerm2")),
    chain(P("bash.exe"), P("claude.exe"), P("pwsh.exe"), W("Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.21", "WindowsTerminal.exe")),
    chain(P("bash.exe"), P("claude.exe"), P("cmd.exe"), W("Windows", "explorer.exe")),
    chain(P("zsh"), P("node"), P("zsh"), P("Code Helper (Plugin)", "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)")),
    chain(P("bash.exe"), P("claude.exe"), W("Users\\u\\AppData\\Local\\Programs\\cursor", "Cursor.exe")),
    chain(P("sh"), P("codex"), P("bash"), P("tmux: server")),
    chain(P("sh"), P("claude"), P("bash"), P("sshd-session")),
    chain(P("sh"), P("claude"), P("bash"), P("claude")),
    chain(P("node"), P("node"), P("python3.12"), P("zsh"), P("Terminal", "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal")),
    chain(P("sh"), P("claude"), P("systemd", "/usr/lib/systemd/systemd"))
  ];
  for (const c of cases.slice(0, 4)) assert.equal(assessChain(c).parentClass, "normal", c.map((x) => x.image).join(" <- "));
  for (const c of cases.slice(4)) assert.equal(assessChain(c, { shim: c[0].image === "node" && c[1].image === "node" }).parentClass, "normal", c.map((x) => x.image).join(" <- "));
  // a container: the agent's chain ends at pid 1 through shells only
  const box = [{ pid: 40, ppid: 30, image: "sh" }, { pid: 30, ppid: 1, image: "claude" }, { pid: 1, ppid: 0, image: "bash" }];
  assert.equal(assessChain(box).parentClass, "normal");
});

test("the allow-list, CI runners in server mode, unknown parents and unreadable chains", () => {
  const rb = chain(P("bash.exe"), P("claude.exe"), W("Windows\\System32", "RuntimeBroker.exe"));
  assert.equal(assessChain(rb, { allow: parentPolicy({ aiCliParents: { allow: ["runtimebroker.EXE"] } }).allow }).parentClass, "normal");
  assert.equal(assessChain(rb, { allow: parentPolicy({ aiCliParents: { allow: ["RuntimeBroker"] } }).allow }).parentClass, "normal");
  const ci = chain(P("sh"), P("claude"), P("bash"), P("Runner.Worker", "/home/runner/actions-runner/bin/Runner.Worker"));
  assert.equal(assessChain(ci, { serverMode: true }).parentClass, "normal");
  assert.equal(assessChain(ci).parentClass, "unknown");
  assert.equal(assessChain(chain(P("zsh"), P("claude"), P("Raycast"))).parentClass, "unknown");
  assert.equal(assessChain([]).parentClass, "unreadable");
  assert.equal(assessChain([{ pid: 5, ppid: 4, image: "zsh" }]).parentClass, "unreadable");
  // the parent is gone (a Windows orphan, or the walk could not read further): unknown, not normal
  assert.equal(assessChain([{ pid: 9, ppid: 8, image: "bash.exe" }, { pid: 8, ppid: 7, image: "claude.exe" }]).parentClass, "unknown");
  // six shells and interpreters above the agent: the walk stops, unknown
  assert.equal(assessChain(chain(P("sh"), P("claude"), ...Array.from({ length: 8 }, () => P("bash")))).parentClass, "unknown");
});

test("classifyImage and helpers: basename only, case-insensitive, .exe optional, temp directories on every platform", () => {
  assert.equal(imageBase("C:\\Windows\\System32\\RuntimeBroker.exe"), "RuntimeBroker.exe");
  assert.equal(imageBase("-zsh"), "zsh");
  assert.equal(imageBase("/usr/bin/x (deleted)"), "x");
  assert.equal(classifyImage("SIHOST.EXE"), "system-host");
  assert.equal(classifyImage("WmiPrvSE.exe"), "system-host");
  assert.equal(classifyImage("Microsoft Excel"), "office");
  assert.equal(classifyImage("regsvr32.exe"), "script-host");
  assert.equal(classifyImage("cmd.exe", "C:\\Windows\\System32\\cmd.exe"), "transparent");
  assert.equal(classifyImage("conhost.exe", "C:\\Windows\\System32\\conhost.exe"), "normal");
  assert.equal(classifyImage("notepad.exe", "C:\\Windows\\System32\\notepad.exe"), "temp-or-system-path");
  assert.equal(classifyImage("tool.exe", "D:\\apps\\tool.exe"), "unknown");
  for (const p of ["/tmp/x", "/private/tmp/x", "/var/tmp/x", "/dev/shm/x", "/private/var/folders/ab/cdef/T/x", "C:\\Users\\u\\AppData\\Local\\Temp\\x.exe", "C:\\Windows\\Temp\\x.exe", "c:/temp/x.exe"]) assert.equal(isTempPath(p), true, p);
  for (const p of ["/usr/bin/x", "/Users/u/tmpfile", "C:\\Program Files\\x.exe", ""]) assert.equal(isTempPath(p), false, p);
  assert.deepEqual(parentPolicy({ aiCliParents: { mode: "bogus" } }).mode, "alert");
  assert.deepEqual(parentPolicy(null).mode, "alert");
  assert.deepEqual(parentPolicy({ aiCliParents: { mode: "block" } }).mode, "block");
});

function home() { return mkdtempSync(join(tmpdir(), "moorai-acp-")); }
const SIHOST = chain(P("bash.exe"), P("claude.exe"), P("sihost.exe", "C:\\Windows\\System32\\sihost.exe"));
const counting = (c) => { const r = (startPid, n) => { r.calls++; r.args = [startPid, n]; return c; }; r.calls = 0; return r; };

test("the step: classified once per session, one alert, content-free fields, block denies PreToolUse only", () => {
  const dir = home();
  try {
    const readChain = counting(SIHOST);
    const policy = { aiCliParents: { mode: "block" } };
    const a = aiCliParentStep({ policy, sessionId: "s1", agent: "claude-code", event: "UserPromptSubmit", readChain, stateDir: dir, startPid: 4242 });
    assert.equal(readChain.calls, 1);
    assert.equal(readChain.args[0], 4242);
    assert.equal(a.deny, null, "UserPromptSubmit is never denied");
    assert.equal(a.alerts.length, 1);
    assert.deepEqual(a.alerts[0], { threatId: 0, category: AI_CLI_PARENT_CATEGORY, riskLevel: "Blocked", reasonCode: AI_CLI_PARENT, stage: "policy", decision: "deny", contentHash: "ai-cli-parent:system-host:sihost.exe", agentName: "claude-code", parentImage: "sihost.exe", parentClass: "system-host", chainDepth: 1 });
    assert.ok(!JSON.stringify(a.alerts).includes("System32"), "no path leaves the device");
    const b = aiCliParentStep({ policy, sessionId: "s1", agent: "claude-code", event: "PreToolUse", readChain, stateDir: dir });
    assert.equal(readChain.calls, 1, "cached for the session");
    assert.equal(b.alerts.length, 0, "alerted once per session");
    assert.match(b.deny, /unexpected parent process \(system-host\)/);
    assert.ok(!b.deny.includes("sihost"));
    // a second session walks again
    aiCliParentStep({ policy, sessionId: "s2", event: "PreToolUse", readChain, stateDir: dir });
    assert.equal(readChain.calls, 2);
    // the allow-list, added later, releases the cached session
    assert.equal(aiCliParentStep({ policy: { aiCliParents: { mode: "block", allow: ["sihost.exe"] } }, sessionId: "s1", event: "PreToolUse", readChain, stateDir: dir }).deny, null);
    assert.equal(lastParentClass(dir), "system-host");
    assert.ok(readFileSync(join(dir, CACHE_FILE), "utf8").length > 0);
  } finally { rmTree(dir); }
});

test("the step: alert mode alerts High and never denies; coach never denies; off never walks; normal never alerts", () => {
  const dir = home();
  try {
    const alert = aiCliParentStep({ policy: {}, sessionId: "a", event: "PreToolUse", readChain: counting(SIHOST), stateDir: dir });
    assert.deepEqual([alert.alerts.length, alert.alerts[0].riskLevel, alert.alerts[0].decision, alert.deny], [1, "High", "notify", null]);
    assert.equal(alert.alerts[0].agentName, "unknown");
    const coach = aiCliParentStep({ policy: { aiCliParents: { mode: "block" } }, sessionId: "c", event: "PreToolUse", coach: true, readChain: counting(SIHOST), stateDir: dir });
    assert.deepEqual([coach.alerts.length, coach.alerts[0].riskLevel, coach.deny], [1, "High", null]);
    const off = counting(SIHOST);
    assert.deepEqual(aiCliParentStep({ policy: { aiCliParents: { mode: "off" } }, sessionId: "o", readChain: off, stateDir: dir }), { alerts: [], deny: null, result: null });
    assert.equal(off.calls, 0);
    const ok = aiCliParentStep({ policy: { aiCliParents: { mode: "block" } }, sessionId: "n", event: "PreToolUse", readChain: counting(chain(P("zsh"), P("claude"), P("Terminal"))), stateDir: dir });
    assert.deepEqual([ok.alerts.length, ok.deny, ok.result.parentClass], [0, null, "normal"]);
    assert.equal(lastParentClass(dir), "normal");
    const none = aiCliParentStep({ policy: {}, sessionId: "u", readChain: counting([]), stateDir: dir });
    assert.deepEqual([none.alerts.length, none.result.parentClass, lastParentClass(dir)], [0, "unreadable", "unknown"]);
    // a reader that throws is a step that does nothing
    assert.deepEqual(aiCliParentStep({ policy: {}, sessionId: "t", readChain: () => { throw new Error("x"); }, stateDir: dir }).alerts, []);
  } finally { rmTree(dir); }
});

test("readers: the Windows CIM walk output, /proc, and ps, from canned outputs", () => {
  const win = [
    "4242|900|bash.exe|C:\\Program Files\\Git\\usr\\bin\\bash.exe|133700000000000300",
    "900|812|claude.exe|C:\\Users\\u\\.local\\bin\\claude.exe|133700000000000200",
    "812|700|sihost.exe|C:\\Windows\\System32\\sihost.exe|133700000000000100",
    // pid 700 was reused by a process created after its child: not the parent, the chain ends here
    "700|4|late.exe|C:\\x\\late.exe|133700000000000999"
  ].join("\r\n");
  const c = parseWinChain(win);
  assert.deepEqual(c.map((x) => x.image), ["bash.exe", "claude.exe", "sihost.exe"]);
  assert.equal(assessChain(c).parentClass, "system-host");
  assert.deepEqual(parseWinChain("12|0|System||0\r\n"), [{ pid: 12, ppid: 0, image: "System", path: "", created: 0 }]);
  assert.match(winChainScript(4242, 12), /\$p=4242/);
  assert.match(winChainScript("1;Remove-Item x", 12), /\$p=0\n/, "the pid is a number in the script, never text");
  assert.deepEqual(readChainWindows(5, 3, () => win).length, 3);
  assert.deepEqual(readChainWindows(5, 3, () => { throw new Error("no powershell"); }), []);
  const procs = { 50: "50 (sh) S 40 1 1", 40: "40 (claude) S 30 1 1", 30: "30 (a (b) c) S 1 1 1", 1: "1 (systemd) S 0 1 1" };
  const exe = { 40: "/home/u/.local/bin/claude", 30: "/tmp/x/a (b) c (deleted)" };
  const fs = { readFileSync: (p) => { const n = p.split("/")[2]; if (!procs[n]) throw new Error("ENOENT"); return procs[n]; }, readlinkSync: (p) => { const n = p.split("/")[2]; if (!exe[n]) throw new Error("EACCES"); return exe[n]; } };
  const pc = readChainProc(50, 12, fs);
  assert.deepEqual(pc.map((x) => [x.pid, x.ppid, x.image, x.path]), [[50, 40, "sh", ""], [40, 30, "claude", "/home/u/.local/bin/claude"], [30, 1, "a (b) c", "/tmp/x/a (b) c"], [1, 0, "systemd", ""]]);
  assert.equal(assessChain(pc).parentClass, "temp-or-system-path");
  const ps = { 50: "   40 /bin/zsh", 40: "   30 /opt/claude/claude", 30: "    1 /Applications/Utilities/Some App.app/Contents/MacOS/Some App" };
  const pr = readChainPs(50, 12, (args) => ps[args[3]] || "");
  assert.deepEqual(pr.map((x) => x.image), ["zsh", "claude", "Some App"]);
});

test("the real process table on this platform: the walk reads this test's own ancestry", { skip: process.platform === "win32" && "Windows runs on a real box" }, () => {
  const read = process.platform === "linux" ? readChainProc : readChainPs;
  const c = read(process.pid, 12);
  assert.ok(c.length >= 2, "at least this process and its parent");
  assert.equal(c[0].pid, process.pid);
  assert.equal(c[0].ppid, process.ppid);
  assert.match(c[0].image, /^node/);
});
