// AI CLI started by an unexpected parent (cli/ai-cli-parents.mjs): classification, the ancestry walk, the
// per-session step and the process-table readers, with injected process tables.
//
//   node --test --import ./test/hermetic-env.mjs test/ai-cli-parents.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classifyImage, inLocation, assessChain, aiCliParentStep, aiCliParentAsk, parentPolicy, lastParentClass, parseWinChain, winChainScript, readChainProc, readChainPs, readChainWindows, imageBase, isTempPath, AI_CLI_PARENT, AI_CLI_PARENT_CATEGORY, CACHE_FILE } from "../cli/ai-cli-parents.mjs";
import { windowsWalker, winWalkScript, walkPaths, WALK_LIFE_MS } from "../cli/ai-cli-parents-win-walk.mjs";
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

test("a terminal or IDE is normal only by name AND expected install location, per platform", () => {
  const normal = [
    // Windows: VS Code / Cursor under Program Files or %LOCALAPPDATA%\Programs, Windows Terminal under WindowsApps, conhost / explorer under C:\Windows
    ["Code.exe", "C:\\Program Files\\Microsoft VS Code\\Code.exe"],
    ["Code.exe", "C:\\Users\\u\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"],
    ["Cursor.exe", "C:\\Users\\u\\AppData\\Local\\Programs\\cursor\\Cursor.exe"],
    ["idea64.exe", "C:\\Program Files (x86)\\JetBrains\\IntelliJ IDEA\\bin\\idea64.exe"],
    ["WindowsTerminal.exe", "C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.21.2361.0_x64__8wekyb3d8bbwe\\WindowsTerminal.exe"],
    ["OpenConsole.exe", "C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.21\\OpenConsole.exe"],
    ["conhost.exe", "C:\\Windows\\System32\\conhost.exe"],
    ["explorer.exe", "C:\\Windows\\explorer.exe"],
    ["explorer.exe", "C:\\Windows\\System32\\explorer.exe"],
    // macOS: /Applications/<App>.app/Contents/MacOS/…, ~/Applications/…
    ["iTerm2", "/Applications/iTerm.app/Contents/MacOS/iTerm2"],
    ["Terminal", "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"],
    ["Cursor", "/Applications/Cursor.app/Contents/MacOS/Cursor"],
    ["idea", "/Users/u/Applications/IntelliJ IDEA Ultimate.app/Contents/MacOS/idea"],
    ["Code Helper (Plugin)", "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)"],
    // Linux: /usr/bin, /usr/local/bin, /usr/share, /opt, /snap, ~/.local/bin, ~/.local/share and similar
    ["gnome-terminal-server", "/usr/libexec/gnome-terminal-server"],
    ["konsole", "/usr/bin/konsole"],
    ["alacritty", "/usr/local/bin/alacritty"],
    ["code", "/usr/share/code/code"],
    ["cursor", "/opt/cursor/cursor"],
    ["code", "/snap/code/171/usr/share/code/code"],
    ["kitty", "/home/u/.local/bin/kitty"],
    ["idea", "/home/u/.local/share/JetBrains/Toolbox/apps/intellij-idea-ultimate/bin/idea"],
    ["nvim", "/opt/homebrew/bin/nvim"]
  ];
  for (const [image, path] of normal) {
    assert.equal(inLocation(image, path), true, path);
    assert.equal(classifyImage(image, path), "normal", path);
  }
  const notNormal = [
    // the right name, no path: a name alone is not enough
    ["Code.exe", "", "unknown"], ["iTerm2", "", "unknown"], ["Terminal", "", "unknown"], ["konsole", "", "unknown"], ["explorer.exe", "", "unknown"],
    // the right name, the wrong place
    ["Code.exe", "C:\\Users\\u\\AppData\\Roaming\\Code.exe", "unknown"],
    ["Code.exe", "D:\\tools\\Code.exe", "unknown"],
    ["Cursor.exe", "C:\\ProgramData\\cursor\\Cursor.exe", "unknown"],
    ["WindowsTerminal.exe", "C:\\Program Files\\Terminal\\WindowsTerminal.exe", "unknown"],
    ["WindowsTerminal.exe", "C:\\Users\\u\\AppData\\Local\\Programs\\WindowsTerminal.exe", "unknown"],
    ["iTerm2", "/Users/u/Library/Application Support/iTerm2", "unknown"],
    ["Terminal", "/Users/u/.cache/Terminal", "unknown"],
    ["Cursor", "/Applications/Cursor", "unknown"],
    ["code", "/home/u/.config/code", "unknown"],
    ["konsole", "/home/u/konsole", "unknown"],
    ["code", "/usr/share/../../home/u/code", "unknown"],
    ["code", "usr/bin/code", "unknown"],
    // the right place, a different file: the path must end in the image's own name
    ["Code.exe", "C:\\Program Files\\Microsoft VS Code\\evil.exe", "unknown"],
    ["iTerm2", "/Applications/iTerm.app/Contents/MacOS/payload", "unknown"],
    // a terminal or IDE name under C:\Windows off its location is a system-path image; conhost / explorer outside their folders too
    ["Code.exe", "C:\\Windows\\Code.exe", "temp-or-system-path"],
    ["WindowsTerminal.exe", "C:\\Windows\\System32\\WindowsTerminal.exe", "temp-or-system-path"],
    ["conhost.exe", "C:\\Windows\\System32\\drivers\\conhost.exe", "temp-or-system-path"],
    ["conhost.exe", "C:\\Program Files\\conhost.exe", "unknown"],
    ["explorer.exe", "C:\\Windows\\Help\\explorer.exe", "system-host"],
    ["explorer.exe", "C:\\Program Files\\explorer.exe", "system-host"],
    // a temp directory still wins over any name
    ["Code.exe", "C:\\Users\\u\\AppData\\Local\\Temp\\Code.exe", "temp-or-system-path"],
    ["iTerm2", "/private/var/folders/ab/cdef/T/iTerm.app/Contents/MacOS/iTerm2", "temp-or-system-path"]
  ];
  for (const [image, path, cls] of notNormal) {
    assert.equal(inLocation(image, path), false, `${image} @ ${path}`);
    assert.equal(classifyImage(image, path), cls, `${image} @ ${path}`);
  }
  // in a chain: a masquerading terminal above the agent is not normal; the real one is
  assert.equal(assessChain(chain(P("zsh"), P("claude"), P("zsh"), P("iTerm2", "/Users/u/Library/Caches/iTerm2"))).parentClass, "unknown");
  assert.equal(assessChain(chain(P("bash.exe"), P("claude.exe"), P("cmd.exe"), W("Windows", "WindowsTerminal.exe"))).parentClass, "temp-or-system-path");
  assert.equal(assessChain(chain(P("bash.exe"), P("claude.exe"), P("cmd.exe"), W("Users\\u\\AppData\\Local\\Programs\\Microsoft VS Code", "Code.exe"))).parentClass, "normal");
  // the allow-list is by name and still overrides the location
  assert.equal(classifyImage("Code.exe", "D:\\tools\\Code.exe", { allow: parentPolicy({ aiCliParents: { allow: ["code.exe"] } }).allow }), "normal");
  // multiplexers, sshd, launchd / systemd keep their name-only rule
  for (const n of ["tmux: server", "sshd-session", "launchd", "systemd"]) assert.equal(classifyImage(n), "normal", n);
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
    const ok = aiCliParentStep({ policy: { aiCliParents: { mode: "block" } }, sessionId: "n", event: "PreToolUse", readChain: counting(chain(P("zsh"), P("claude"), P("Terminal", "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"))), stateDir: dir });
    assert.deepEqual([ok.alerts.length, ok.deny, ok.result.parentClass], [0, null, "normal"]);
    assert.equal(lastParentClass(dir), "normal");
    const none = aiCliParentStep({ policy: {}, sessionId: "u", readChain: counting([]), stateDir: dir });
    assert.deepEqual([none.alerts.length, none.result.parentClass, lastParentClass(dir)], [0, "unreadable", "unknown"]);
    // a reader that throws is a step that does nothing
    assert.deepEqual(aiCliParentStep({ policy: {}, sessionId: "t", readChain: () => { throw new Error("x"); }, stateDir: dir }).alerts, []);
  } finally { rmTree(dir); }
});

// The Windows walk's output for SIHOST-shaped ancestry (cli/ai-cli-parents-win-walk.mjs writes these lines).
const WIN_SIHOST = ["4242|900|bash.exe|C:\\Program Files\\Git\\usr\\bin\\bash.exe|0", "900|812|claude.exe|C:\\Users\\u\\.local\\bin\\claude.exe|0", "812|700|sihost.exe|C:\\Windows\\System32\\sihost.exe|0"].join("\n");
// An in-memory background walker: start/ask are recorded, take answers once `done` holds a result.
const stubWalker = () => { const w = { started: [], asked: [], done: null, take: () => { const t = w.done; w.done = null; return t; }, ask: (k, p) => w.asked.push(p), start: (k, p) => w.started.push(p) }; return w; };

test("the step, Windows: no walk on the call; one background walk per session; its result classifies, alerts once and blocks from the call that finds it", () => {
  const dir = home();
  try {
    const policy = { aiCliParents: { mode: "block" } };
    const walker = stubWalker();
    const slow = counting(SIHOST); // a reader on the call would be this; the background path never calls it
    const step = (o) => aiCliParentStep({ policy, sessionId: "w1", agent: "claude-code", event: "PreToolUse", walker, readChain: slow, stateDir: dir, ...o });
    const t0 = Date.now();
    const a = step({ startPid: 501, now: t0 });
    assert.deepEqual([a.alerts, a.deny, a.result], [[], null, null], "the first call is judged without the parent class");
    assert.deepEqual(walker.started, [501]);
    assert.equal(slow.calls, 0);
    const b = step({ startPid: 502, now: t0 + 1000 });
    assert.deepEqual([b.alerts, b.deny, walker.started, walker.asked], [[], null, [501], [502]], "a running walk is asked, not started again");
    aiCliParentAsk({ sessionId: "w1", walker, stateDir: dir, startPid: 503, now: t0 + 1500 });
    assert.deepEqual(walker.asked, [502, 503], "the early ask reaches a running walk");
    aiCliParentAsk({ sessionId: "other", walker, stateDir: dir, startPid: 504, now: t0 + 1500 });
    assert.deepEqual(walker.asked, [502, 503], "and only a running one");
    walker.done = WIN_SIHOST;
    const c = step({ startPid: 505, now: t0 + 2000 });
    assert.equal(c.alerts.length, 1);
    assert.deepEqual([c.alerts[0].riskLevel, c.alerts[0].parentImage, c.alerts[0].parentClass, c.alerts[0].chainDepth], ["Blocked", "sihost.exe", "system-host", 1]);
    assert.match(c.deny, /unexpected parent process \(system-host\)/);
    const d = step({ startPid: 506, now: t0 + 3000 });
    assert.deepEqual([d.alerts.length, !!d.deny, walker.started.length, slow.calls], [0, true, 1, 0], "cached: blocked, not alerted or walked again");
    assert.equal(lastParentClass(dir), "system-host");
    // a walk that never answers is started again after its lifetime; a call with no session id is never walked
    const late = stubWalker();
    aiCliParentStep({ policy, sessionId: "w2", walker: late, stateDir: dir, startPid: 601, now: t0 });
    aiCliParentStep({ policy, sessionId: "w2", walker: late, stateDir: dir, startPid: 602, now: t0 + WALK_LIFE_MS + 1 });
    assert.deepEqual(late.started, [601, 602]);
    const anon = stubWalker();
    assert.deepEqual(aiCliParentStep({ policy, walker: anon, stateDir: dir, startPid: 701 }), { alerts: [], deny: null, result: null });
    assert.deepEqual([anon.started, anon.asked], [[], []]);
    // off: nothing is started
    const off = stubWalker();
    aiCliParentStep({ policy: { aiCliParents: { mode: "off" } }, sessionId: "w3", walker: off, stateDir: dir });
    assert.deepEqual(off.started, []);
  } finally { rmTree(dir); }
});

test("the Windows walker: start leaves the request and launches one script; take hands over the result once; the call itself never waits", () => {
  const dir = home();
  try {
    const launched = [];
    const w = windowsWalker({ stateDir: dir, maxLen: 12, launch: (s) => launched.push(s) });
    const t0 = performance.now();
    w.start("k1", 4242);
    const ms = performance.now() - t0;
    assert.ok(ms < 200, `start took ${ms} ms`);
    const { req, res } = walkPaths(dir, "k1");
    assert.equal(readFileSync(req, "utf8"), "4242");
    assert.equal(launched.length, 1);
    assert.ok(launched[0].includes(`$req='${req.replace(/'/g, "''")}'`) && launched[0].includes(`$res='${res.replace(/'/g, "''")}'`));
    assert.match(launched[0], /for\(\$i=0;\$i -lt 12;\$i\+\+\)/);
    w.ask("k1", "77;Remove-Item x");
    assert.equal(readFileSync(req, "utf8"), "0", "a request is a number, never text");
    assert.equal(w.take("k1"), null);
    writeFileSync(res, WIN_SIHOST);
    assert.equal(w.take("k1"), WIN_SIHOST);
    assert.equal(existsSync(res), false);
    assert.equal(w.take("k1"), null, "handed over once");
    assert.match(winWalkScript({ req: "C:\\it's\\r", res: "C:\\r", dir: "C:\\d", maxLen: 3 }), /\$req='C:\\it''s\\r'/, "a quote in a path stays inside the string");
    // on win32 with no injected reader or walker, the step takes the background path: no walk, a request left
    // (off Windows the PowerShell it launches does not exist, and that launch failure is swallowed)
    const r = aiCliParentStep({ policy: {}, sessionId: "p1", platform: "win32", stateDir: dir, startPid: 9191 });
    assert.equal(r.result, null);
    assert.deepEqual(readdirSync(dir).filter((f) => f.endsWith(".req") && join(dir, f) !== req).map((f) => readFileSync(join(dir, f), "utf8")), ["9191"]);
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
