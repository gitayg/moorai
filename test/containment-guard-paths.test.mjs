// The MXC write guard's Win32-style path canonicalization (cli/win-canon.mjs, used by cli/containment-guard.mjs
// resolveTarget / guardHit): every spelling Win32 maps to one file gets one canonical form, and the guard sees each
// spelling of a protected location, by Write/Edit file_path and inside a shell command. Pure: Windows paths on
// any host OS.
//
//   node --test --import ./test/hermetic-env.mjs test/containment-guard-paths.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { winCanon, canonUnder, isShortName, canonSegment } from "../cli/win-canon.mjs";
import { guardHit, resolveTarget } from "../cli/containment-guard.mjs";
import { shellWrites } from "../data/tool-tags.js";

const ENV = {
  USERPROFILE: "C:\\Users\\dev", LOCALAPPDATA: "C:\\Users\\dev\\AppData\\Local", APPDATA: "C:\\Users\\dev\\AppData\\Roaming",
  HOMEDRIVE: "C:", HOMEPATH: "\\Users\\dev", ProgramFiles: "C:\\Program Files", SystemRoot: "C:\\Windows"
};
const CWD = "C:\\src\\proj";
const c = (p, o = {}) => winCanon(p, { env: ENV, cwd: CWD, ...o });
const same = (want, spellings) => { for (const p of spellings) assert.equal(c(p).toUpperCase(), want.toUpperCase(), p); };

// ---- the canonical form, rule by rule ----
test("case and separators: / and \\ alike, compared case-insensitively, case kept in the string", () => {
  same("C:\\Users\\dev\\.bashrc", ["C:/Users/dev/.bashrc", "c:\\users\\DEV\\.BASHRC", "C:\\Users/dev\\.bashrc"]);
  assert.equal(c("C:/Users/dev/.bashrc"), "C:\\Users\\dev\\.bashrc");
  assert.ok(canonUnder("c:\\USERS\\dev\\.BashRC", "C:\\Users\\dev\\.bashrc"));
  assert.ok(!canonUnder("C:\\Users\\dev\\.bashrc2", "C:\\Users\\dev\\.bashrc"), "a longer name is not beneath");
});

test("device and namespace prefixes: \\\\?\\, \\\\.\\, \\??\\ to the drive path; \\\\?\\UNC to \\\\server\\share", () => {
  same("C:\\Users\\dev\\.bashrc", ["\\\\?\\C:\\Users\\dev\\.bashrc", "\\\\.\\C:\\Users\\dev\\.bashrc", "\\??\\C:\\Users\\dev\\.bashrc", "//?/C:/Users/dev/.bashrc", "//./c:/Users/dev/.bashrc"]);
  assert.equal(c("\\\\?\\UNC\\fs01\\home\\dev\\.bashrc"), "\\\\fs01\\home\\dev\\.bashrc");
  assert.equal(c("\\\\.\\UNC\\fs01\\home\\x"), "\\\\fs01\\home\\x");
  assert.equal(c("\\\\fs01\\home\\dev\\..\\x"), "\\\\fs01\\home\\x", "a UNC root is never climbed past");
  // Same disk, other routes: an admin share on any host name, and a volume GUID / device path (the wildcard root).
  same("C:\\Users\\dev\\.bashrc", ["\\\\localhost\\C$\\Users\\dev\\.bashrc", "\\\\127.0.0.1\\c$\\Users\\dev\\.bashrc", "\\\\?\\UNC\\localhost\\c$\\Users\\dev\\.bashrc"]);
  assert.equal(c("\\\\?\\Volume{0f1e2d3c-0000-1111-2222-333344445555}\\Users\\dev\\.bashrc"), "*:\\Users\\dev\\.bashrc");
  assert.equal(c("\\\\?\\GLOBALROOT\\Device\\HarddiskVolume3\\Users\\dev\\.bashrc"), "*:\\Users\\dev\\.bashrc");
  assert.ok(canonUnder(c("\\\\?\\Volume{0f1e2d3c-0000-1111-2222-333344445555}\\Users\\dev\\.bashrc"), "C:\\Users\\dev"));
  assert.equal(c("\\\\.\\pipe\\x"), "", "a device that is not a disk path: unresolvable");
});

test("a trailing dot or space on any segment is removed: .bashrc. / .bashrc  / .bashrc. . name .bashrc", () => {
  same("C:\\Users\\dev\\.bashrc", ["C:\\Users\\dev\\.bashrc.", "C:\\Users\\dev\\.bashrc ", "C:\\Users\\dev\\.bashrc. .", "C:\\Users\\dev\\.bashrc...", "C:\\Users\\dev. \\.bashrc", "C:\\Users.\\dev\\.bashrc"]);
  assert.equal(canonSegment(".bashrc. ."), ".bashrc");
});

test("an NTFS stream suffix is dropped: name::$DATA and name:stream are the file name; the drive colon is not a stream", () => {
  same("C:\\Users\\dev\\.bashrc", ["C:\\Users\\dev\\.bashrc::$DATA", "C:\\Users\\dev\\.bashrc:evil", "C:\\Users\\dev\\.bashrc:evil:$DATA", "C:\\Users\\dev\\.bashrc.::$DATA"]);
  same("C:\\Users\\dev\\.claude\\shell-snapshots\\s.sh", ["C:\\Users\\dev\\.claude:$I30:$INDEX_ALLOCATION\\shell-snapshots\\s.sh"]);
  assert.equal(c("C:\\x"), "C:\\x");
  assert.equal(c("C:x"), "C:\\src\\proj\\x", "drive-relative on cwd's drive");
  assert.equal(c("D:x"), "", "drive-relative on another drive: unresolvable");
});

test(". and .. fold, repeated separators collapse, .. never climbs past the root; a rooted \\x is on cwd's drive", () => {
  same("C:\\Users\\dev\\.bashrc", ["C:\\Users\\.\\dev\\\\\\x\\..\\.bashrc", "C:\\..\\..\\Users\\dev\\.bashrc", "C://Users//dev//.bashrc", "..\\..\\Users\\dev\\.bashrc", "\\Users\\dev\\.bashrc", "/c/Users/dev/.bashrc"]);
  assert.equal(c("C:\\"), "C:\\");
  assert.equal(c("rel\\.\\x\\"), "C:\\src\\proj\\rel\\x");
});

test("a .. component with a trailing space or an NTFS stream still climbs: Win32 strips the trailing run, so .. / '.. ' / '..::$DATA' all name the parent", () => {
  // The guard used to check `raw === \"..\"` before the stream and trailing-dot/space strip, so a decoy segment
  // plus `.. ` dropped the decoy as if it were a literal name and walked straight into the parent.
  same("C:\\Users\\dev\\.bashrc", ["C:\\Users\\dev\\foo\\.. \\.bashrc", "C:\\Users\\dev\\foo\\..  \\.bashrc", "C:\\Users\\dev\\foo\\..::$DATA\\.bashrc", "C:\\Users\\dev\\foo\\.. \\bar\\..\\.bashrc"]);
  assert.ok(canonUnder(c("C:\\Users\\dev\\foo\\.. \\.bashrc"), "C:\\Users\\dev\\.bashrc"), "trailing-space .. climbs to a protected file");
  assert.ok(canonUnder(c("C:\\Users\\dev\\AppData\\Local\\foo\\.. \\MoorAI Host\\x"), "C:\\Users\\dev\\AppData\\Local\\MoorAI Host"), "and into MoorAI Host");
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\foo\\.. \\.bashrc" }), "shell-rc", "a Write past a decoy segment is flagged");
  assert.equal(g("Bash", { command: "echo x >> \"C:\\Users\\dev\\foo\\.. \\.bashrc\"" }), "shell-rc", "a shell redirect past a decoy segment is flagged");
  // A pure run of three or more dots is Win32's empty/current component, never the parent (only two dots climb).
  assert.ok(!canonUnder(c("C:\\Users\\dev\\foo\\...\\.bashrc"), "C:\\Users\\dev\\.bashrc"), "... is current, not parent");
  assert.equal(c("C:\\Users\\dev\\foo\\...\\.bashrc"), "C:\\Users\\dev\\foo\\.bashrc");
  // The leading dot run decides it, not just a trailing space: `.. .` / `.. . ` start with two dots, so the rest
  // being dots-and-spaces still climbs, while a one-dot (`. .`) or three-dot (`... `) run stays current.
  same("C:\\Users\\dev\\.bashrc", ["C:\\Users\\dev\\foo\\.. .\\.bashrc", "C:\\Users\\dev\\foo\\.. . \\.bashrc"]);
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\foo\\.. .\\.bashrc" }), "shell-rc", "a two-dot run with a mixed dot/space tail climbs");
  for (const p of ["C:\\Users\\dev\\foo\\. .\\.bashrc", "C:\\Users\\dev\\foo\\... \\.bashrc"]) {
    assert.ok(!canonUnder(c(p), "C:\\Users\\dev\\.bashrc"), `${p} is current, not parent`);
    assert.equal(g("Write", { file_path: p }), null, `${p} not flagged`);
  }
});

test("a decorated .. run is ambiguous on the host, so the guard flags all three readings: parent (climb), dropped/current, and opaque name", () => {
  // The guard resolves a decorated `..` three ways and flags if ANY lands under a protected path, so no Win32
  // reading of a non-final decorated `..` slips a write past.
  assert.equal(winCanon("C:\\Users\\dev\\.claude\\shell-snapshots\\.. \\s.sh", { env: ENV, cwd: CWD }), "C:\\Users\\dev\\.claude\\s.sh", "the climb reading leaves the protected dir");
  assert.equal(winCanon("C:\\Users\\dev\\.claude\\shell-snapshots\\.. \\s.sh", { env: ENV, cwd: CWD, dots: "drop" }), "C:\\Users\\dev\\.claude\\shell-snapshots\\s.sh", "the dropped reading stays inside it");
  // Only the dropped reading is under a protected path, and the guard still flags it.
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\.claude\\shell-snapshots\\.. \\s.sh" }), "shell-snapshots", "drop reading into shell-snapshots is flagged");
  // A stream-decorated `..` must get the same readings as the space form, not be mistaken for a bare `..`.
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\.claude\\shell-snapshots\\..::$DATA\\s.sh" }), "shell-snapshots", "drop reading of a stream-decorated .. is flagged");
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\.. \\MoorAI Host\\x.json" }), "moorai-host", "drop reading back into MoorAI Host is flagged");
  // The climb reading alone is still caught too (decoy segment plus `.. `).
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\foo\\.. \\.bashrc" }), "shell-rc", "climb reading into a protected file is flagged");

  // The OPAQUE-NAME reading: a decorated run FOLLOWED by a `..` that pops it. Parent and drop both climb out of
  // the protected dir, but Win32 can keep the decorated run as a literal name (under \\?\, or a crafted name),
  // so the following `..` pops the decoy and the write lands back inside. Only the name reading catches this.
  const climbOut = "C:\\Users\\dev\\.claude\\shell-snapshots\\.. \\..\\evil.sh";
  assert.equal(winCanon(climbOut, { env: ENV, cwd: CWD }), "C:\\Users\\dev\\evil.sh", "parent reading climbs two levels out");
  assert.equal(winCanon(climbOut, { env: ENV, cwd: CWD, dots: "drop" }), "C:\\Users\\dev\\.claude\\evil.sh", "drop reading climbs one level out");
  assert.equal(winCanon(climbOut, { env: ENV, cwd: CWD, dots: "name" }), "C:\\Users\\dev\\.claude\\shell-snapshots\\evil.sh", "name reading pops the decoy and stays inside");
  assert.equal(g("Write", { file_path: climbOut }), "shell-snapshots", "opaque-name reading keeps the write under shell-snapshots and is flagged");
  // The same construction for the other decorated forms and for MoorAI Host.
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\.claude\\shell-snapshots\\... \\..\\evil.sh" }), "shell-snapshots", "'... ' decoy then .. is flagged");
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\.claude\\shell-snapshots\\.. .\\..\\evil.sh" }), "shell-snapshots", "'.. .' decoy then .. is flagged");
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\.claude\\shell-snapshots\\..::$DATA\\..\\evil.sh" }), "shell-snapshots", "stream-decorated decoy then .. is flagged");
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\.. \\..\\evil.cfg" }), "moorai-host", "the same construction back into MoorAI Host is flagged");
  // A benign path with a real sibling dir named like a decoy is still not under the protected dir once popped.
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\Documents\\notes\\.. \\..\\todo.txt" }), null, "the name reading does not over-flag an unprotected tree");
});

test("environment forms expand from env: %HOMEDRIVE%%HOMEPATH%, $env:NAME and ${env:NAME} in any case, ~; unknown → \"\"", () => {
  same("C:\\Users\\dev\\.bashrc", ["%HOMEDRIVE%%HOMEPATH%\\.bashrc", "%userprofile%\\.bashrc", "$env:USERPROFILE\\.bashrc", "$ENV:userprofile\\.bashrc", "${env:USERPROFILE}\\.bashrc", "${Env:UserProfile}/.bashrc", "~/.bashrc", "~\\.bashrc", "$HOME/.bashrc", "${HOME}/.bashrc"]);
  same("C:\\Users\\dev\\AppData\\Local\\MoorAI Host", ["%LOCALAPPDATA%\\MoorAI Host", "$env:LocalAppData\\MoorAI Host", "${env:LOCALAPPDATA}\\MoorAI Host"]);
  for (const p of ["%NOPE%\\x", "$env:NOPE\\x", "${env:NOPE}\\x", "$NOPE/x", "${NOPE}/x"]) assert.equal(c(p), "", p);
  assert.equal(c("~/.bashrc", { env: {} }), "", "~ with no USERPROFILE");
  assert.equal(c("%USERPROFILE%\\x", { literal: true }), "C:\\src\\proj\\%USERPROFILE%\\x", "literal: the text as a file API takes it");
  assert.equal(resolveTarget("$env:USERPROFILE/.bashrc", { env: ENV, cwd: CWD }), "C:\\Users\\dev\\.bashrc");
});

test("8.3 short names: a ~digit segment matches any name at its position, on either side; nowhere else", () => {
  for (const s of ["MOORAI~1", "BASHRC~1", "BASH~1.BAS", "PROGRA~1", "SHELL-~1", "CLAUDE~1", "moorai~2", "HEAD~1", "~1"]) assert.ok(isShortName(s), s);
  for (const s of ["MoorAI Host", ".bashrc", "file~name", "TOOLONGNM~1", "ABC~1.LONG", "a~b1", "x.y.z~1"]) assert.ok(!isShortName(s), s);
  assert.ok(canonUnder(c("%LOCALAPPDATA%\\MOORAI~1\\wrap\\x.json"), "C:\\Users\\dev\\AppData\\Local\\MoorAI Host"));
  assert.ok(canonUnder(c("C:\\Users\\dev\\BASHRC~1"), "C:\\Users\\dev\\.bashrc"));
  assert.ok(canonUnder(c("C:\\PROGRA~1\\Git\\etc\\BASH~1.BAS"), "C:\\Program Files\\Git\\etc\\bash.bashrc"));
  assert.ok(canonUnder("C:\\Users\\dev\\.bashrc", "C:\\Users\\DEVELO~1\\.bashrc"), "a short name in the protected path itself");
  assert.ok(!canonUnder("C:\\Users\\dev\\proj\\BASHRC~1", "C:\\Users\\dev\\.bashrc"), "wrong position");
  assert.ok(!canonUnder("C:\\Users\\dev\\APPDAT~1\\Local\\Temp\\x", "C:\\Users\\dev\\AppData\\Local\\MoorAI Host"), "the other segments still have to match");
});

// ---- guardHit: each spelling of each protected location ----
const SPELLINGS = {
  "moorai-host": [
    "%LOCALAPPDATA%\\MoorAI Host\\wrap\\x.json", "$env:LOCALAPPDATA\\MoorAI Host\\wrap\\x.json", "${env:LocalAppData}/MoorAI Host/wrap/x.json",
    "%HOMEDRIVE%%HOMEPATH%\\AppData\\Local\\MoorAI Host\\x.json", "\\\\?\\C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\x.json",
    "C:\\Users\\dev\\AppData\\Local\\MoorAI Host.\\x.json", "C:\\Users\\dev\\AppData\\Local\\MoorAI Host \\x.json", "c:/users/DEV/appdata/local/moorai host/x.json",
    "C:\\Users\\dev\\AppData\\Local\\MOORAI~1\\wrap\\x.json", "C:\\Users\\dev\\AppData\\Local\\MoorAI Host:$I30:$INDEX_ALLOCATION\\x.json",
    "~/AppData/Local/MoorAI Host/x.json"
  ],
  "shell-snapshots": [
    "~/.claude/shell-snapshots/s.sh", "~\\.claude\\shell-snapshots\\s.sh", "$env:USERPROFILE\\.claude\\shell-snapshots\\s.sh", "%USERPROFILE%/.claude/shell-snapshots/s.sh",
    "\\\\.\\C:\\Users\\dev\\.claude\\shell-snapshots\\s.sh", "C:\\Users\\dev\\.claude.\\shell-snapshots \\s.sh", "C:\\Users\\dev\\CLAUDE~1\\SHELL-~1\\s.sh",
    "~/.claude/shell-snapshots/s.sh::$DATA", "C:\\Users\\dev\\.CLAUDE\\Shell-Snapshots\\s.sh"
  ],
  "shell-rc": [
    "~/.bashrc", "~/.bashrc.", "~/.bashrc. .", "~/.bashrc::$DATA", "~/.bashrc:x", "\\??\\C:\\Users\\dev\\.bashrc", "%HOMEDRIVE%%HOMEPATH%\\.bashrc",
    "${env:USERPROFILE}/.bashrc", "$ENV:userprofile\\.bashrc", "~/BASHRC~1", "C:\\Users\\dev\\x\\..\\.bashrc", "\\\\localhost\\c$\\Users\\dev\\.bashrc", "C:\\USERS\\DEV\\.BASHRC"
  ]
};
const g = (tool, ti) => guardHit({ tool, ti, env: ENV, cwd: CWD });

test("guardHit: every spelling of a protected location, by Write/Edit file_path and inside a shell command", () => {
  for (const [cls, list] of Object.entries(SPELLINGS)) {
    for (const p of list) {
      assert.equal(g("Write", { file_path: p }), cls, `Write ${p}`);
      assert.equal(g("Edit", { file_path: p }), cls, `Edit ${p}`);
      assert.equal(g("Bash", { command: `echo x >> "${p}"` }), cls, `Bash ${p}`);
      assert.equal(g("PowerShell", { command: `Add-Content -Path "${p}" -Value x` }), cls, `PowerShell ${p}`);
    }
  }
  assert.equal(g("Bash", { command: "printf x > ~/.bashrc." }), "shell-rc", "unquoted");
  assert.equal(g("PowerShell", { command: "Set-Content -Path:$env:USERPROFILE\\.bashrc -Value x" }), "shell-rc", "-Path:value");
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\%NOPE%\\..\\.bashrc" }), "shell-rc", "an unknown %VAR% that .. folds away, dropped with its segment");
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\%USERPROFILE%\\..\\.bashrc" }), "shell-rc", "a file API takes %USERPROFILE% as text, which .. folds away: read literally too");
  assert.equal(g("Bash", { command: "cd ~ && echo x >> .bashrc." }), "shell-rc", "a bare rc name after cd, canonicalized");
});

test("guardHit: ordinary workspace paths and reads are not flagged", () => {
  for (const p of ["C:\\src\\proj\\src\\app.js", "src/app.js", "C:\\src\\proj\\.bashrc", "C:\\src\\proj\\notes\\.bashrc.md", "C:\\src\\proj\\.claude\\settings.json",
    "C:\\src\\proj\\docs\\README~1.md", "C:\\Users\\dev\\.bashrc.md", "C:\\Users\\dev\\.bashrc_history", "C:\\Users\\dev\\.claude\\settings.json",
    "C:\\Users\\dev\\AppData\\Local\\MoorAI\\state.json", "C:\\Users\\dev\\AppData\\Local\\Temp\\x", "D:\\Users\\dev\\.bashrc", "\\\\fs01\\share\\Users\\dev\\.bashrc"]) {
    assert.equal(g("Write", { file_path: p }), null, p);
  }
  for (const cmd of ["npm test > out.log", "cp a.txt b.txt", "git reset HEAD~1", "echo x 2>&1 > build.log", "Copy-Item src\\a.js dist\\a.js", "cat ~/.bashrc 2>&1",
    "cat ~/.bashrc.", "type $env:USERPROFILE\\.bashrc", "Get-Content ~/.claude/shell-snapshots/s.sh", "sc query wuauserv", "echo hi>out.txt"]) {
    assert.equal(g("Bash", { command: cmd }), null, cmd);
  }
});

test("8.3 false-positive cost, asserted so it stays visible: a short-name segment at a protected position is flagged", () => {
  assert.equal(g("Write", { file_path: "C:\\Users\\dev\\NOTES~1" }), "shell-rc", "a home-level short name could be BASHRC~1");
  assert.equal(guardHit({ tool: "Bash", ti: { command: "git reset HEAD~1" }, env: ENV, cwd: "C:\\Users\\dev" }), "shell-rc", "a ~digit word run from the home directory");
});

test("the guard's own write gate: forms shellWrites misses (cp/mv/tee/install/rsync/dd spelled with a path, .exe, quotes or \\; PowerShell aliases; fd and >| redirects)", () => {
  const forms = [
    "/usr/bin/cp a ~/.bashrc", "/bin/mv a ~/.bashrc", "cp.exe a ~/.bashrc", "\\cp a ~/.bashrc", "\"cp\" a ~/.bashrc", "C:\\PROGRA~1\\Git\\usr\\bin\\cp.exe a ~/.bashrc",
    "echo x | /usr/bin/tee -a ~/.bashrc", "echo x | tee.exe ~/.bashrc", "install.exe a ~/.bashrc", "/usr/bin/install a ~/.bashrc", "rsync.exe a ~/.bashrc", "dd.exe if=a of=~/.bashrc",
    "sc ~/.bashrc x", "ac ~/.bashrc x", "ni ~/.bashrc", "cpi a ~/.bashrc", "copy a ~/.bashrc", "mi a ~/.bashrc", "move a ~/.bashrc", "x | Tee-Object -FilePath ~/.bashrc",
    "echo x 1>~/.bashrc", "echo x 2>~/.bashrc", "echo x 1>>~/.bashrc", "echo x &>~/.bashrc", "echo x &>>~/.bashrc", "echo x >|~/.bashrc", "echo x>|~/.bashrc", "echo x=1>~/.bashrc"
  ];
  for (const cmd of forms) {
    assert.equal(shellWrites(cmd), false, `shellWrites already covers ${cmd}`);
    assert.equal(g("Bash", { command: cmd }), "shell-rc", cmd);
  }
});

test("the protected paths are canonical too: an env value with a \\\\?\\ prefix, a trailing separator or a short name still matches", () => {
  const env = { ...ENV, LOCALAPPDATA: "\\\\?\\C:\\Users\\dev\\AppData\\Local\\", USERPROFILE: "C:\\Users\\DEVELO~1" };
  assert.equal(guardHit({ tool: "Write", ti: { file_path: "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\x.json" }, env, cwd: CWD }), "moorai-host");
  assert.equal(guardHit({ tool: "Write", ti: { file_path: "C:\\Users\\developer\\.bashrc" }, env, cwd: CWD }), "shell-rc");
});
