// MXC enforcement, the pure parts (cli/containment-enforce.mjs, cli/mxc-policy.mjs scope "commands"):
// who decides, the decision table, the capability-cache rule, the command-line quoting of the Claude Code
// wrap (checked against an MSVC argv parser and the real /bin/bash), wrap idempotence, and the plan checks.
// The hook wiring is test/containment-enforce-hook.test.mjs.
//
//   node --test --import ./test/hermetic-env.mjs test/containment-enforce.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmTree } from "./fs-cleanup.mjs";
import {
  resolveContainment, containmentDecision, wrapFallback, hostKind, capableForHook, _resetCapableMemoForTests, containmentAlert,
  quoteArgWin, bashQuote, WRAP_SCRIPT, WRAP_ENV, WRAP_MAX_CHARS, WRAP_OUTER_MAX, innerCommandLine, outerCommand, outerFits, planWrap, wrapConfig, writeWrap,
  unwrapCommand, ensureWrapDir, findWxcExec, findGitBash, claudeCodeWrapState, wrappedInput
} from "../cli/containment-enforce.mjs";
import { buildMxcPolicy } from "../cli/mxc-policy.mjs";

// ---- who decides ----
test("resolveContainment: admin binding > signed policy > off; invalid values are skipped with a warning naming source and key only", () => {
  const warns = [];
  const warn = (m) => warns.push(m);
  const W = { platform: "win32", warn };
  assert.deepEqual(resolveContainment(null, W), { required: { mode: "off", source: "default" }, claudeCode: { mode: "off", source: "default" } });
  assert.deepEqual(resolveContainment({ containmentRequired: "block", containmentClaudeCode: "wrap" }, W).required, { mode: "block", source: "policy" });
  assert.deepEqual(resolveContainment({ containmentRequired: "block" }, { ...W, admin: { containmentRequired: "alert" } }).required, { mode: "alert", source: "admin" });
  assert.deepEqual(resolveContainment({ containmentRequired: "block" }, { ...W, admin: { containmentRequired: "BLOCK-ish" } }).required, { mode: "block", source: "policy" });
  assert.deepEqual(resolveContainment({ containmentClaudeCode: "Wrap" }, W).claudeCode, { mode: "off", source: "default" });
  assert.ok(warns.some((m) => /containmentRequired in the admin binding/.test(m)) && warns.every((m) => !/BLOCK-ish|Wrap"/.test(m)), warns.join("|"));
  for (const p of ["darwin", "linux"]) assert.deepEqual(resolveContainment({ containmentRequired: "block", containmentClaudeCode: "wrap" }, { platform: p, admin: { containmentRequired: "block" } }), { required: { mode: "off", source: "platform" }, claudeCode: { mode: "off", source: "platform" } });
});

// ---- the decision table: host × kind × capable × mode ----
const KINDS = ["mxc", "none", "other", "unknown"];
const CAPS = [true, false, null];
function expected(mode, kind, capable) {
  if (mode === "off" || kind === "mxc") return ["allow", null];
  if (capable === false) return ["alert", "CONTAINMENT_UNAVAILABLE"];
  if (kind === "none" || kind === "other") return [mode === "block" ? "deny" : "alert", "CONTAINMENT_MISSING"];
  return [mode === "block" && capable === true ? "deny" : "alert", "CONTAINMENT_MISSING"];
}
test("containmentDecision: the full kind × capable × mode table", () => {
  const rows = [];
  for (const mode of ["off", "alert", "block"]) for (const kind of KINDS) for (const capable of CAPS) {
    const d = containmentDecision({ mode, kind, capable });
    rows.push(`${mode}/${kind}/${capable}=${d.action}:${d.reasonCode}`);
    assert.deepEqual([d.action, d.reasonCode], expected(mode, kind, capable), `${mode} ${kind} ${capable}`);
  }
  assert.equal(rows.length, 36);
  // The rows a regression would most likely flip, spelled out.
  assert.equal(containmentDecision({ mode: "block", kind: "none", capable: null }).action, "deny");
  assert.equal(containmentDecision({ mode: "block", kind: "none", capable: false }).action, "alert", "never deny for what the device cannot do");
  assert.equal(containmentDecision({ mode: "block", kind: "unknown", capable: true }).action, "deny");
  assert.equal(containmentDecision({ mode: "block", kind: "unknown", capable: null }).action, "alert");
  assert.equal(containmentDecision({ mode: "alert", kind: "none", capable: true }).action, "alert");
});

function homeWith(t, files) {
  const home = mkdtempSync(join(tmpdir(), "moorai-ce-"));
  t.after(() => rmTree(home));
  for (const [rel, text] of Object.entries(files)) { mkdirSync(join(home, rel, ".."), { recursive: true }); writeFileSync(join(home, rel), text); }
  return home;
}
test("decision table through each host's real config: codex and copilot", (t) => {
  const cases = [
    ["codex", { ".codex/config.toml": '[windows]\nsandbox = "mxc"\n' }, "mxc"],
    ["codex", { ".codex/config.toml": '[windows]\nsandbox = "elevated"\n' }, "other"],
    ["codex", {}, "none"],
    ["codex", { ".codex/config.toml": "[features]\nprefer_mxc = true\n" }, "unknown"],
    ["copilot", { ".copilot/settings.json": '{"sandbox":{"enabled":true}}' }, "mxc"],
    ["copilot", { ".copilot/settings.json": '{"sandbox":{"enabled":false}}' }, "none"],
    ["copilot", {}, "unknown"]
  ];
  for (const [host, files, kind] of cases) {
    const home = homeWith(t, files);
    const k = hostKind(host, { home, env: {} });
    assert.equal(k.kind, kind, `${host} ${JSON.stringify(files)}`);
    for (const mode of ["off", "alert", "block"]) for (const capable of CAPS) {
      const d = containmentDecision({ mode, kind: k.kind, capable });
      assert.deepEqual([d.action, d.reasonCode], expected(mode, kind, capable), `${host} ${kind} ${mode} ${capable}`);
    }
  }
  assert.equal(hostKind("claude-code", { home: "/nonexistent" }), null);
  assert.equal(hostKind("gemini", { home: "/nonexistent" }), null);
});

test("hostKind (codex): a project config claiming mxc is not believed on its own; one that weakens the user's mxc is caught", (t) => {
  const userNone = homeWith(t, { "proj/.codex/config.toml": '[windows]\nsandbox = "mxc"\n' });
  assert.equal(hostKind("codex", { home: userNone, cwd: join(userNone, "proj") }).kind, "none");
  const userMxc = homeWith(t, { ".codex/config.toml": '[windows]\nsandbox = "mxc"\n', "proj/.codex/config.toml": '[windows]\nsandbox = "elevated"\n' });
  assert.equal(hostKind("codex", { home: userMxc, cwd: join(userMxc, "proj") }).kind, "other");
  const both = homeWith(t, { ".codex/config.toml": '[windows]\nsandbox = "mxc"\n', "proj/.codex/config.toml": "sandbox_mode = \"workspace-write\"\n" });
  assert.equal(hostKind("codex", { home: both, cwd: join(both, "proj") }).kind, "mxc");
});

// ---- the capability cache ----
test("cache tamper: under block mxc-capable.json is never read (registry decides); under alert it is", (t) => {
  const stateDir = mkdtempSync(join(tmpdir(), "moorai-ce-cache-"));
  t.after(() => rmTree(stateDir));
  // The user rewrote the cache: UBR 1, below 26100.9278 → "incapable". The registry says 9300 → capable.
  writeFileSync(join(stateDir, "mxc-capable.json"), JSON.stringify({ release: "10.0.26100", ubr: 1, at: Date.now() }));
  let regReads = 0;
  const readUbr = () => { regReads++; return 9300; };
  _resetCapableMemoForTests();
  assert.equal(capableForHook({ mode: "block", release: "10.0.26100", stateDir, readUbr }), true);
  assert.equal(regReads, 1);
  assert.equal(capableForHook({ mode: "block", release: "10.0.26100", stateDir, readUbr }), true, "memoised per process");
  assert.equal(regReads, 1);
  assert.equal(capableForHook({ mode: "alert", release: "10.0.26100", stateDir, readUbr }), false, "alert mode uses the cache: it only changes an alert's reason");
  // And the decision a tampered cache would have produced under block, had it been read:
  assert.equal(containmentDecision({ mode: "block", kind: "none", capable: false }).action, "alert");
  assert.equal(containmentDecision({ mode: "block", kind: "none", capable: true }).action, "deny");
  // A build older than 26100 is "false" from os.release() alone, with no file and no registry.
  _resetCapableMemoForTests();
  assert.equal(capableForHook({ mode: "block", release: "10.0.22631", stateDir, readUbr }), false);
  assert.equal(regReads, 1);
  _resetCapableMemoForTests();
});

test("wrapFallback: block denies, alert and off allow with UNAVAILABLE", () => {
  assert.deepEqual(wrapFallback("block"), { action: "deny", reasonCode: "CONTAINMENT_UNAVAILABLE" });
  assert.deepEqual(wrapFallback("alert"), { action: "alert", reasonCode: "CONTAINMENT_UNAVAILABLE" });
  assert.deepEqual(wrapFallback("off"), { action: "alert", reasonCode: "CONTAINMENT_UNAVAILABLE" });
});

test("containmentAlert is content-free: fixed category, tokens from fixed lists, no path or command", () => {
  const a = containmentAlert({ host: "codex", tool: "Bash", decision: "deny", reasonCode: "CONTAINMENT_MISSING", mode: "block", kind: "none", source: "codex:unset", capable: true });
  assert.deepEqual(Object.keys(a).sort(), ["category", "containmentKind", "containmentRequired", "containmentSource", "contentHash", "decision", "host", "mxcCapable", "reasonCode", "riskLevel", "stage", "threatId", "tool"].sort());
  assert.equal(a.contentHash, "containment:CONTAINMENT_MISSING:codex");
});

// ---- quoting ----
// CommandLineToArgvW / MSVC CRT rules: 2n backslashes + " → n backslashes, toggle quoting; 2n+1 + " → n + literal ".
function msvcArgv(cmd) {
  const out = []; let i = 0;
  while (i < cmd.length) {
    while (cmd[i] === " " || cmd[i] === "\t") i++;
    if (i >= cmd.length) break;
    let arg = "", q = false;
    for (; i < cmd.length; i++) {
      const ch = cmd[i];
      if (ch === "\\") {
        let n = 0; while (cmd[i] === "\\") { n++; i++; }
        if (cmd[i] === "\"") { arg += "\\".repeat(n >> 1); if (n & 1) arg += "\""; else { q = !q; } }
        else { arg += "\\".repeat(n); i--; }
        continue;
      }
      if (ch === "\"") { if (q && cmd[i + 1] === "\"") { arg += "\""; i++; } else q = !q; continue; }
      if (!q && (ch === " " || ch === "\t")) break;
      arg += ch;
    }
    out.push(arg);
  }
  return out;
}
const HOSTILE = [
  `echo "double" 'single'`, "a & b && c || d", "ls | grep x | wc -l", "echo %PATH% %%x%% !VAR!", "echo ^& ^| ^^",
  "line1\nline2\r\nline3", "printf 'back\\\\slash\\t' C:\\Users\\x\\ trailing\\", "echo \\\"\\\\\"", "$(whoami) `id` ${HOME}",
  "echo 'it'\\''s'", "cat <<'EOF'\n$HOME \"q\"\nEOF", "x=1; exit 3", "  leading and trailing  ", "émoji ✓ 中文", "a\tb", "\"", "\\", "'"
];
test("quoteArgWin round-trips through the MSVC argv rules for hostile strings", () => {
  for (const s of [...HOSTILE, "C:\\Program Files\\Git\\bin\\bash.exe", "", "plain", "ends with backslash\\", "q\"\\\"q"]) {
    assert.deepEqual(msvcArgv(`prog ${quoteArgWin(s)} tail`), ["prog", s, "tail"], JSON.stringify(s));
  }
});
test("innerCommandLine: argv is exactly [bash, --noprofile, --norc, -c, WRAP_SCRIPT], and never holds the command", () => {
  const bash = "C:\\Program Files\\Git\\bin\\bash.exe";
  assert.deepEqual(msvcArgv(innerCommandLine(bash)), [bash, "--noprofile", "--norc", "-c", WRAP_SCRIPT]);
  assert.doesNotMatch(WRAP_SCRIPT, /\\/, "no backslash for MSYS2's parser to read differently");
});

// Git for Windows ships bash 5.x; prefer a bash 5 here. macOS's /bin/bash 3.2 differs in one place: a
// command it cannot parse exits 1 under eval and 2 under -c (bash 5.3 measured: 2 and 2).
const BASH = ["/opt/homebrew/bin/bash", "/usr/local/bin/bash", "/usr/bin/bash", "/bin/bash"].find((p) => spawnSync(p, ["-c", "true"]).status === 0);
const BASH_MAJOR = BASH ? Number(spawnSync(BASH, ["-c", "echo ${BASH_VERSINFO[0]}"], { encoding: "utf8" }).stdout.trim()) : 0;
test("bashQuote: the real bash reads each hostile word back byte for byte", { skip: !BASH && "no bash" }, () => {
  for (const s of [...HOSTILE, "C:\\Users\\O'Brien\\AppData\\Local\\MoorAI Host\\wrap\\wrap-x.json"]) {
    const r = spawnSync(BASH, ["-c", `printf %s ${bashQuote(s)}`], { encoding: "utf8" });
    assert.equal(r.stdout, s, JSON.stringify(s));
  }
});
test("WRAP_SCRIPT under the real bash gives the same output and exit code as bash -c <command>, and the variable does not leak", { skip: !BASH && "no bash" }, (t) => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-ce-sh-"));
  t.after(() => rmTree(dir));
  const cmds = [...HOSTILE.filter((c) => c !== "\"" && c !== "'" && c !== "\\" && !c.startsWith("printf 'back")), "echo $# \"$0\" >/dev/null; echo ok", "env | grep -c MOORAI_WRAP_CMD; true", "false; echo $?", "(exit 7)", "echo a; exit 5"];
  for (const c of cmds) {
    const env = { PATH: process.env.PATH, HOME: dir };
    const direct = spawnSync(BASH, ["--noprofile", "--norc", "-c", c], { cwd: dir, env, encoding: "utf8" });
    const wrapped = spawnSync(BASH, ["--noprofile", "--norc", "-c", WRAP_SCRIPT], { cwd: dir, env: { ...env, [WRAP_ENV]: c }, encoding: "utf8" });
    assert.equal(wrapped.stdout, direct.stdout, JSON.stringify(c));
    if (BASH_MAJOR >= 4 || direct.status !== 2) assert.equal(wrapped.status, direct.status, JSON.stringify(c));
    else assert.notEqual(wrapped.status, 0, JSON.stringify(c));
  }
  const leak = spawnSync(BASH, ["--noprofile", "--norc", "-c", WRAP_SCRIPT], { cwd: dir, env: { PATH: process.env.PATH, HOME: dir, [WRAP_ENV]: "env | grep -c MOORAI_WRAP_CMD || true" }, encoding: "utf8" });
  assert.equal(leak.stdout.trim(), "0", "unset before the command runs");
});

// ---- the wrap: plan, config, write, unwrap ----
const ENV = {
  USERPROFILE: "C:\\Users\\dev", LOCALAPPDATA: "C:\\Users\\dev\\AppData\\Local", ProgramFiles: "C:\\Program Files", SystemRoot: "C:\\Windows",
  ProgramData: "C:\\ProgramData", PATH: "C:\\Windows\\System32;C:\\Program Files\\Microsoft MXC", CLAUDE_PROJECT_DIR: "C:\\src\\proj"
};
const WXC = "C:\\Program Files\\Microsoft MXC\\wxc-exec.exe";
const BASHEXE = "C:\\Program Files\\Git\\bin\\bash.exe";
function memfs(extra = []) {
  const files = new Map(), dirs = new Set(), links = new Set();
  const present = new Set([WXC, BASHEXE, "C:\\src\\proj", "C:\\Program Files\\Git", ...extra]);
  const stat = (kind, mtimeMs = Date.now()) => ({ isDirectory: () => kind === "dir", isFile: () => kind === "file", isSymbolicLink: () => kind === "link", mtimeMs });
  return {
    files, dirs, links,
    exists: (p) => present.has(p) || dirs.has(p) || files.has(p),
    lstat: (p) => { if (links.has(p)) return stat("link"); if (dirs.has(p)) return stat("dir"); if (files.has(p)) return stat("file", files.get(p).mtimeMs); const e = new Error("ENOENT"); e.code = "ENOENT"; throw e; },
    mkdir: (p) => { dirs.add(p); },
    write: (p, text, o) => { if (o.flag === "wx" && files.has(p)) { const e = new Error("EEXIST"); e.code = "EEXIST"; throw e; } files.set(p, { text, mtimeMs: Date.now() }); },
    read: (p) => files.get(p).text,
    list: (d) => [...files.keys()].filter((p) => p.startsWith(d + "\\")).map((p) => p.slice(d.length + 1)),
    unlink: (p) => files.delete(p)
  };
}
const plan0 = (fs, over = {}) => planWrap({ platform: "win32", tool: "Bash", canRewrite: true, env: ENV, cwd: "C:\\src\\proj\\sub", capable: null, exists: fs.exists, lstat: fs.lstat, mkdir: fs.mkdir, ...over });
function wrapOnce(fs, plan, command) {
  const c = wrapConfig(plan, command, { env: ENV, exists: fs.exists });
  assert.ok(c.ok, JSON.stringify(c));
  return writeWrap(plan, c.config, command, { write: fs.write, list: fs.list, lstat: fs.lstat, unlink: fs.unlink });
}

test("planWrap: a usable plan, and each reason it cannot wrap", () => {
  const fs = memfs();
  const p = plan0(fs);
  assert.equal(p.ok, true);
  assert.equal(p.wxc, WXC);
  assert.deepEqual(p.bash, { exe: BASHEXE, root: "C:\\Program Files\\Git" });
  assert.equal(p.workspace, "C:\\src\\proj");
  assert.equal(p.cwd, "C:\\src\\proj\\sub");
  assert.equal(p.wrapDir, "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\wrap");
  assert.equal(plan0(memfs(), { platform: "darwin" }).why, "not-windows");
  assert.equal(plan0(memfs(), { tool: "PowerShell" }).why, "powershell-tool");
  assert.equal(plan0(memfs(), { canRewrite: false }).why, "host-cannot-rewrite");
  assert.equal(plan0(memfs(), { capable: false }).why, "not-capable");
  // wxc-exec on PATH but outside Program Files: not trusted (it runs with full user rights).
  const userWxc = "C:\\Users\\dev\\bin\\wxc-exec.exe";
  assert.equal(plan0(memfs([userWxc]), { env: { ...ENV, PATH: "C:\\Users\\dev\\bin" } }).why, "no-wxc-exec");
  assert.equal(findWxcExec({ ...ENV, PATH: "C:\\Users\\dev\\bin;C:\\Program Files\\..\\Users\\dev\\bin" }, memfs([userWxc]).exists), "");
  const noGit = memfs(); noGit.exists = (p) => p === WXC || p === "C:\\src\\proj";
  assert.equal(plan0(noGit).why, "no-git-bash");
  assert.equal(plan0(memfs(), { env: { ...ENV, CLAUDE_PROJECT_DIR: "" }, cwd: "relative" }).why, "no-workspace");
  // A junction (reported as a symbolic link) or a file where the wrap dir goes.
  const j = memfs(); j.links.add("C:\\Users\\dev\\AppData\\Local\\MoorAI Host");
  assert.equal(plan0(j).why, "wrap-dir-unsafe");
  const f = memfs(); f.files.set("C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\wrap", { text: "", mtimeMs: 0 });
  assert.equal(plan0(f).why, "wrap-dir-unsafe");
});

test("findGitBash: CLAUDE_CODE_GIT_BASH_PATH first; the Git root is granted read-only", () => {
  const custom = "D:\\tools\\Git\\usr\\bin\\bash.exe";
  assert.deepEqual(findGitBash({ ...ENV, CLAUDE_CODE_GIT_BASH_PATH: custom }, (p) => p === custom), { exe: custom, root: "D:\\tools\\Git" });
  assert.equal(findGitBash({ ...ENV, CLAUDE_CODE_GIT_BASH_PATH: "relative\\bash.exe" }, () => false), null);
});

test("wrapConfig: commands scope — only the workspace is writable; no agent or MoorAI state; the command only in env", () => {
  const fs = memfs();
  const p = plan0(fs);
  const cmd = HOSTILE.join(" ; ");
  const c = wrapConfig(p, cmd, { env: ENV, exists: fs.exists });
  assert.equal(c.ok, true);
  const cfg = c.config;
  assert.equal(cfg.version, "1.0.0");
  assert.deepEqual(cfg.filesystem.readwritePaths, ["C:\\src\\proj"]);
  assert.ok(!JSON.stringify(cfg.filesystem).match(/\.claude|\.moorai|MoorAI Host/), JSON.stringify(cfg.filesystem));
  assert.ok(cfg.filesystem.readonlyPaths.includes("C:\\Program Files\\Git"));
  assert.equal(cfg.process.cwd, "C:\\src\\proj\\sub");
  assert.ok(!cfg.process.env.some((e) => /^(TEMP|TMP|ANTHROPIC_BASE_URL|OPENAI_BASE_URL)=/.test(e)));
  const envCmd = JSON.parse(JSON.stringify(cfg)).process.env.find((e) => e.startsWith(`${WRAP_ENV}=`));
  assert.equal(envCmd.slice(WRAP_ENV.length + 1), cmd, "JSON round trip keeps every byte");
  assert.ok(!cfg.process.commandLine.includes("echo"));
  assert.equal(cfg.fallback.allowDaclMutation, false);
  assert.equal(cfg.network.egress.default, "deny");
  assert.equal(wrapConfig(p, "a\0b", { env: ENV, exists: fs.exists }).why, "command-nul");
  assert.equal(wrapConfig(p, "x".repeat(WRAP_MAX_CHARS + 1), { env: ENV, exists: fs.exists }).why, "command-too-long");
  assert.equal(wrapConfig(p, "   ", { env: ENV, exists: fs.exists }).why, "empty-command");
  // The workspace rules of the agent policy still apply: Claude Code started in the profile cannot be wrapped.
  assert.equal(wrapConfig({ ...p, workspace: "C:\\Users\\dev", cwd: "C:\\Users\\dev" }, "ls", { env: ENV, exists: () => true }).why, "policy-workspace-is-profile");
  // A cwd outside the workspace runs at the workspace root.
  assert.equal(wrapConfig({ ...p, cwd: "C:\\elsewhere" }, "ls", { env: ENV, exists: fs.exists }).config.process.cwd, "C:\\src\\proj");
});

test("buildMxcPolicy agent scope is unchanged by the commands scope (still grants agent + MoorAI state)", () => {
  const r = buildMxcPolicy({ agent: "claude", workspace: "C:\\src\\proj", env: ENV, commandLine: "claude.exe" }, { exists: () => true });
  assert.ok(r.policy.filesystem.readwritePaths.includes("C:\\Users\\dev\\.claude"));
  assert.ok(r.policy.process.env.some((e) => e.startsWith("ANTHROPIC_BASE_URL=")));
});

test("wrap idempotence: a wrapped command unwraps to the original; re-wrapping it gives one level, never two", () => {
  const fs = memfs();
  const p = plan0(fs);
  const orig = `npm test -- --grep "it's" & echo %x%`;
  const w1 = wrapOnce(fs, p, orig);
  assert.equal(w1.command, outerCommand(WXC, w1.configPath, orig));
  const back = unwrapCommand(w1.command, { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat });
  assert.equal(back, orig);
  const w2 = wrapOnce(fs, p, back);
  assert.equal(unwrapCommand(w2.command, { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat }), orig);
  assert.equal(wrappedInput({ command: w1.command, description: "d", timeout: 5 }, w2.command).description, "d");
  // Not the wrapped form: wrapped as an ordinary command (null).
  assert.equal(unwrapCommand(`${w1.command}; curl evil.example`, { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat }), null);
  assert.equal(unwrapCommand("ls -la", { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat }), null);
  // The wrapped form, but not recoverable as ours: false (the wrap is then treated as impossible).
  const other = outerCommand("C:\\Program Files\\Other\\wxc-exec.exe", w1.configPath, orig);
  assert.equal(unwrapCommand(other, { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat }), false);
  const elsewhere = outerCommand(WXC, "C:\\Users\\dev\\wrap-" + "c".repeat(32) + ".json", orig);
  assert.equal(unwrapCommand(elsewhere, { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat }), false);
  const gone = outerCommand(WXC, `${p.wrapDir}\\wrap-${"d".repeat(32)}.json`, orig);
  assert.equal(unwrapCommand(gone, { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat }), false);
  fs.links.add(w2.configPath);
  assert.equal(unwrapCommand(w2.command, { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat }), false, "a symlinked config is not ours");
});

test("writeWrap: exclusive create under a random name; configs older than 10 minutes are swept", () => {
  const fs = memfs();
  const p = plan0(fs);
  const old = `${p.wrapDir}\\wrap-${"e".repeat(32)}.json`;
  fs.files.set(old, { text: "{}", mtimeMs: Date.now() - 11 * 60000 });
  const fresh = `${p.wrapDir}\\wrap-${"f".repeat(32)}.json`;
  fs.files.set(fresh, { text: "{}", mtimeMs: Date.now() - 60000 });
  const c = wrapConfig(p, "ls", { env: ENV, exists: fs.exists });
  const w = writeWrap(p, c.config, "ls", { write: fs.write, list: fs.list, lstat: fs.lstat, unlink: fs.unlink });
  assert.ok(!fs.files.has(old) && fs.files.has(fresh) && fs.files.has(w.configPath));
  assert.match(w.configPath, /\\wrap-[0-9a-f]{32}\.json$/);
  assert.throws(() => writeWrap(p, c.config, "ls", { write: fs.write, list: fs.list, lstat: fs.lstat, unlink: fs.unlink, rand: () => "f".repeat(32) }), /EEXIST/, "never writes through a pre-existing name");
});

test("ensureWrapDir: creates missing levels; refuses a link or file at either level", () => {
  const fs = memfs();
  assert.equal(ensureWrapDir("C:\\L\\MoorAI Host\\wrap", fs), true);
  assert.ok(fs.dirs.has("C:\\L\\MoorAI Host") && fs.dirs.has("C:\\L\\MoorAI Host\\wrap"));
  const l = memfs(); l.dirs.add("C:\\L\\MoorAI Host"); l.links.add("C:\\L\\MoorAI Host\\wrap");
  assert.equal(ensureWrapDir("C:\\L\\MoorAI Host\\wrap", l), false);
});

test("claudeCodeWrapState: on / off / unavailable", () => {
  const fs = memfs();
  assert.equal(claudeCodeWrapState({ platform: "darwin", mode: "wrap", env: ENV, exists: fs.exists }), "off");
  assert.equal(claudeCodeWrapState({ platform: "win32", mode: "off", env: ENV, exists: fs.exists }), "off");
  assert.equal(claudeCodeWrapState({ platform: "win32", mode: "wrap", env: ENV, exists: fs.exists }), "on");
  assert.equal(claudeCodeWrapState({ platform: "win32", mode: "wrap", env: ENV, exists: fs.exists, capable: false }), "unavailable");
  assert.equal(claudeCodeWrapState({ platform: "win32", mode: "wrap", env: { ...ENV, PATH: "" }, exists: fs.exists }), "unavailable");
});

// ---- the display prefix ("__moorai_show='<original>'; …") ----
test("display prefix: the outer command shows the original, and the display text is never taken as the command", () => {
  const fs = memfs();
  const p = plan0(fs);
  const orig = "rm -rf build && echo 'done'";
  const w = wrapOnce(fs, p, orig);
  assert.ok(w.command.startsWith(`__moorai_show=${bashQuote(orig)}; MSYS_NO_PATHCONV=1 `), w.command);
  // The display edited to something harmless: the config's command is what comes back (and gets scanned).
  const lying = w.command.replace(bashQuote(orig), bashQuote("ls"));
  assert.notEqual(lying, w.command);
  assert.equal(unwrapCommand(lying, { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat }), orig);
  // The launch without the display prefix is not the wrapped form (wrapped whole, never trusted).
  const bare = w.command.slice(w.command.indexOf("MSYS_NO_PATHCONV=1"));
  assert.equal(unwrapCommand(bare, { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat }), null);
  // A display that smuggles a second statement is not the wrapped form either.
  assert.equal(unwrapCommand(`__moorai_show='x'; touch pwned ; ${bare}`, { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat }), null);
  assert.equal(unwrapCommand(`__moorai_show='x' touch pwned; ${bare}`, { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat }), null);
  // The v1.18.0/1 shape (": '<original>' ;") is not MoorAI's any more: an ordinary command, judged as written.
  assert.equal(unwrapCommand(`: 'x' ; ${bare}`, { wxc: p.wxc, wrapDir: p.wrapDir, read: fs.read, lstat: fs.lstat }), null);
});

test("display prefix: a command whose doubled length no longer fits the command line is 'wrap impossible'", () => {
  const fs = memfs();
  const p = plan0(fs);
  // Fits the 32,767-character env limit, but the display copy (and Claude Code's re-quoting) does not fit.
  const big = "echo " + "a".repeat(WRAP_OUTER_MAX);
  assert.ok(big.length <= WRAP_MAX_CHARS);
  assert.equal(wrapConfig(p, big, { env: ENV, exists: fs.exists }).why, "command-line-too-long");
  // Quotes expand under quoting: ' becomes '\'' in our quoting and again in Claude Code's.
  const quotes = "echo " + "'".repeat(2500);
  assert.equal(wrapConfig(p, quotes, { env: ENV, exists: fs.exists }).why, "command-line-too-long");
  assert.equal(wrapConfig(p, "echo " + "a".repeat(10000), { env: ENV, exists: fs.exists }).ok, true);
  assert.equal(outerFits("x".repeat(WRAP_OUTER_MAX - 2)), true);
  assert.equal(outerFits("x".repeat(WRAP_OUTER_MAX - 1)), false);
});

const INERT = [
  "touch PWNED", "$(touch PWNED)", "`touch PWNED`", "x'; touch PWNED; '", "a\ntouch PWNED\n", "true && touch PWNED", "true ; touch PWNED",
  "echo \"$(touch PWNED)\"", "'$(touch PWNED)'", "\\'; touch PWNED #", "${IFS}touch${IFS}PWNED", "a | touch PWNED", "a & touch PWNED", ">PWNED", "<(touch PWNED)"
];
test("display prefix is inert under the real bash: hostile originals never run; only the launch runs, once, with its exit code", { skip: !BASH && "no bash" }, (t) => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-ce-inert-"));
  t.after(() => rmTree(dir));
  // A stand-in for wxc-exec: records its argv and MSYS_NO_PATHCONV, exits 7.
  const stub = join(dir, "wxc-stub.sh");
  writeFileSync(stub, `#!${BASH}\nprintf '%s\\n' "MSYS_NO_PATHCONV=$MSYS_NO_PATHCONV" "$@" >> "${join(dir, "calls.log")}"\nexit 7\n`, { mode: 0o755 });
  const cfg = "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\wrap\\wrap-" + "a".repeat(32) + ".json";
  const env = { PATH: process.env.PATH, HOME: dir };
  for (const orig of INERT) {
    const outer = outerCommand(stub, cfg, orig);
    for (const [label, script] of [["direct", outer], ["as Claude Code evals it", `eval ${bashQuote(outer)}`]]) {
      writeFileSync(join(dir, "calls.log"), "");
      const r = spawnSync(BASH, ["--noprofile", "--norc", "-c", script], { cwd: dir, env, encoding: "utf8" });
      assert.equal(existsSync(join(dir, "PWNED")), false, `${label}: ${JSON.stringify(orig)} ran`);
      assert.equal(r.status, 7, `${label}: exit code is the launch's (${JSON.stringify(orig)}): ${r.stderr}`);
      const calls = readFileSync(join(dir, "calls.log"), "utf8").split("\n").filter(Boolean);
      assert.deepEqual(calls, ["MSYS_NO_PATHCONV=1", "--config", cfg], `${label}: ${JSON.stringify(orig)}`);
    }
  }
});
