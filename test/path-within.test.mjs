// Path containment by segments (cli/path-within.mjs): canned root/path pairs per platform. Data in, verdict out.
//
//   node --test test/path-within.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { isWithin, within, splitPath, sameName } from "../cli/path-within.mjs";

const check = (platform, rows) => { for (const [path, root, want] of rows) assert.equal(isWithin(path, root, platform), want, `${platform}: ${path} in ${root}`); };

test("sibling prefix: a root is a sequence of whole segments, never a string prefix", () => {
  check("linux", [
    ["/usr/local/lib/node_modules/x/cli.js", "/usr/local/lib", true],
    ["/usr/local/lib-old/node_modules/x/cli.js", "/usr/local/lib", false],
    ["/usr/local/library/x", "/usr/local/lib", false],
    ["/home/u2/.npm-global/lib/x", "/home/u", false],
    ["/opt/homebrew/lib", "/opt/homebrew/lib", false] // a root is not inside itself
  ]);
  check("darwin", [
    ["/Applications/Claude.app/Contents/MacOS/Claude", "/Applications/Claude.app", true],
    ["/Applications/Claude.app.evil/Contents/MacOS/Claude", "/Applications/Claude.app", false],
    ["/Applications/Claude.apps/x", "/Applications/Claude.app", false]
  ]);
  check("win32", [
    [String.raw`C:\Program Files\Microsoft VS Code\Code.exe`, "C:/Program Files", true],
    [String.raw`C:\Program Files Extra\Code.exe`, "C:/Program Files", false],
    [String.raw`C:\Program Files (x86)\x.exe`, "C:/Program Files", false],
    [String.raw`C:\Users\u\AppData\Local\Programs2\x.exe`, String.raw`C:\Users\u\AppData\Local\Programs`, false]
  ]);
});

test("case: Windows and macOS fold case, Linux does not", () => {
  check("linux", [["/USR/LOCAL/LIB/node_modules/x", "/usr/local/lib", false], ["/home/u/.LOCAL/bin/kitty", "/home/u/.local/bin", false], ["/home/u/.local/bin/kitty", "/home/u/.local/bin", true]]);
  check("darwin", [["/applications/CLAUDE.APP/Contents/MacOS/Claude", "/Applications/Claude.app", true], ["/Users/U/.local/bin/x", "/Users/u/.local/bin", true]]);
  check("win32", [[String.raw`c:\PROGRAM FILES\x\Code.exe`, "C:/Program Files", true], [String.raw`D:\Program Files\x.exe`, "C:/Program Files", false]]);
  // macOS compares NFC: "é" composed and decomposed name the same folder
  check("darwin", [["/Users/re\u0301my/x", "/Users/r\u00e9my", true]]);
  assert.equal(sameName("Claude.EXE", "claude.exe", "win32"), true);
  assert.equal(sameName("Claude", "claude", "linux"), false);
});

test("trailing and repeated separators are dropped", () => {
  check("linux", [["/usr/local/lib//node_modules/x/", "/usr/local/lib/", true], ["/usr/local/lib/", "/usr/local/lib", false]]);
  check("darwin", [["//Applications///Claude.app/Contents", "/Applications/", true]]);
  check("win32", [["C:\\Program Files\\\\x\\", "C:\\Program Files\\", true]]);
});

test(". and .. segments are refused, never resolved", () => {
  check("linux", [
    ["/usr/local/lib/../../../tmp/x", "/usr/local/lib", false],
    ["/usr/local/lib/./node_modules/x", "/usr/local/lib", false],
    ["/usr/local/lib/node_modules/x", "/usr/local/lib/../lib", false]
  ]);
  check("win32", [[String.raw`C:\Program Files\..\Users\u\x.exe`, "C:/Program Files", false], [String.raw`C:\Program Files\...\x.exe`, "C:/Program Files", false]]);
  assert.equal(splitPath("/a/../b", "linux"), null);
  assert.equal(splitPath("/a/..b/c", "linux").segs.join("/"), "a/..b/c", "a name that only starts with dots is a name");
});

test("Windows: \\\\?\\, \\\\.\\, \\??\\ and UNC forms; relative and drive-relative paths are inside nothing", () => {
  check("win32", [
    [String.raw`\\?\C:\Program Files\Microsoft VS Code\Code.exe`, "C:/Program Files", true],
    [String.raw`\\.\C:\Program Files\x.exe`, "C:/Program Files", true],
    [String.raw`\??\C:\Program Files\x.exe`, "C:/Program Files", true],
    [String.raw`\\?\UNC\fs1\apps\Program Files\x.exe`, String.raw`\\fs1\apps\Program Files`, true],
    [String.raw`\\fs1\apps\Program Files\x.exe`, String.raw`\\fs1\apps\Program Files`, true],
    [String.raw`\\fs1\apps\Program Files\x.exe`, "C:/Program Files", false],
    [String.raw`\\FS1\APPS\x.exe`, String.raw`\\fs1\apps`, true],
    [String.raw`\\?\Volume{0a1b}\Program Files\x.exe`, "C:/Program Files", false],
    [String.raw`C:Program Files\x.exe`, "C:/Program Files", false],
    [String.raw`\Program Files\x.exe`, "C:/Program Files", false],
    [String.raw`Program Files\x.exe`, "C:/Program Files", false],
    [String.raw`C:\Program Files\x.exe:evil`, "C:/Program Files", false]
  ]);
  // "*:" in a root is any drive letter, never a UNC share; "*" in a segment stays inside that segment
  check("win32", [
    [String.raw`D:\Program Files\x.exe`, "*:/Program Files", true],
    [String.raw`\\windows\system32\conhost.exe`, "*:/Windows/System32", false],
    [String.raw`C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2025.1_x64__abc\app\ChatGPT.exe`, "*:/Program Files/WindowsApps/OpenAI.ChatGPT-Desktop_*", true],
    [String.raw`C:\Program Files\WindowsApps\Evil_OpenAI.ChatGPT-Desktop_1\ChatGPT.exe`, "*:/Program Files/WindowsApps/OpenAI.ChatGPT-Desktop_*", false]
  ]);
  assert.equal(isWithin(String.raw`C:\Program Files\x.exe`, "*:/Program Files", "linux"), false, "a Windows path under POSIX rules is relative");
  assert.deepEqual(within(String.raw`\\?\C:\Users\u\AppData\Local\Programs\cursor\Cursor.exe`, String.raw`C:\Users\u\AppData\Local\Programs`, "win32"), ["cursor", "Cursor.exe"]);
});

test("globs: * is one segment (or a run inside one); a relative or empty path is inside nothing", () => {
  check("darwin", [
    ["/Users/u/.nvm/versions/node/v22/lib/node_modules/x", "/Users/u/.nvm/versions/node/*/lib", true],
    ["/Users/u/.nvm/versions/node/v22/extra/lib/node_modules/x", "/Users/u/.nvm/versions/node/*/lib", false],
    ["/private/var/folders/ab/cdef/T/x", "/private/var/folders/*/*/T", true]
  ]);
  check("linux", [["usr/local/lib/x", "/usr/local/lib", false], ["", "/", false], ["/x\0/y", "/", false], ["/x", "/", true]]);
});
