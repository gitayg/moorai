// The two location gates apply ONE containment rule (cli/path-within.mjs): the terminal / IDE gate
// (cli/ai-cli-parents.mjs inLocation, isTempPath) and the install-location gate (cli/ai-install-locations.mjs
// packageAt, npmEntry, pythonEntry, venvInterpreter, nativeClaudeExe). Canned paths in, verdict out.
//
//   node --test --import ./test/hermetic-env.mjs test/location-gates.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { inLocation, isTempPath, classifyImage } from "../cli/ai-cli-parents.mjs";
import { npmEntry, packageAt, pythonEntry, venvInterpreter, nativeClaudeExe } from "../cli/ai-install-locations.mjs";

const pkgJson = (name, bin) => JSON.stringify({ name, version: "1.0.0", bin });
const files = (o) => (p) => { const k = String(p).replace(/\\/g, "/"); if (k in o) return o[k]; throw new Error(`ENOENT ${p}`); };
const NPM = ["@anthropic-ai/claude-code", "@google/gemini-cli"];

test("both gates: Linux compares case-sensitively; macOS and Windows fold case", () => {
  // terminal / IDE gate
  assert.equal(inLocation("kitty", "/home/u/.local/bin/kitty", "linux"), true);
  assert.equal(inLocation("kitty", "/home/u/.LOCAL/bin/kitty", "linux"), false, "a sibling .LOCAL folder is not ~/.local on Linux");
  assert.equal(inLocation("konsole", "/USR/bin/konsole", "linux"), false);
  assert.equal(inLocation("Cursor", "/applications/Cursor.app/Contents/MacOS/Cursor", "darwin"), true);
  assert.equal(classifyImage("kitty", "/home/u/.LOCAL/bin/kitty", { platform: "linux" }), "unknown");
  // install-location gate
  const linux = { platform: "linux", home: "/home/u", npm: NPM, readFile: files({
    "/usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json": pkgJson("@anthropic-ai/claude-code", { claude: "cli.js" }),
    "/usr/local/lib/NODE_MODULES/@anthropic-ai/claude-code/package.json": pkgJson("@anthropic-ai/claude-code", { claude: "cli.js" }) }) };
  assert.equal(npmEntry("/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js", linux), "@anthropic-ai/claude-code");
  assert.equal(npmEntry("/usr/local/lib/NODE_MODULES/@anthropic-ai/claude-code/cli.js", linux), null, "NODE_MODULES is another folder on Linux");
  const mac = { platform: "darwin", home: "/Users/u", npm: NPM, readFile: files({
    "/Users/u/.NPM-GLOBAL/lib/node_modules/@anthropic-ai/claude-code/package.json": pkgJson("@anthropic-ai/claude-code", { claude: "cli.js" }) }) };
  assert.equal(npmEntry("/Users/u/.NPM-GLOBAL/lib/node_modules/@anthropic-ai/claude-code/cli.js", mac), "@anthropic-ai/claude-code");
});

test("both gates read Windows \\\\?\\ paths as the drive path", () => {
  assert.equal(inLocation("Code.exe", String.raw`\\?\C:\Program Files\Microsoft VS Code\Code.exe`, "win32"), true);
  assert.equal(inLocation("conhost.exe", String.raw`\\?\C:\Windows\System32\conhost.exe`, "win32"), true);
  assert.equal(classifyImage("Code.exe", String.raw`\\?\C:\Program Files\Microsoft VS Code\Code.exe`, { platform: "win32" }), "normal");
  const W = String.raw`\\?\C:\Users\u\AppData\Roaming\npm\node_modules\@google\gemini-cli\bundle\gemini.js`;
  const win = { platform: "win32", home: String.raw`C:\Users\u`, npm: NPM, readFile: files({ "C:/Users/u/AppData/Roaming/npm/node_modules/@google/gemini-cli/package.json": pkgJson("@google/gemini-cli", { gemini: "bundle/gemini.js" }) }) };
  assert.equal(npmEntry(W, win), "@google/gemini-cli");
  assert.deepEqual(packageAt(W, win), { pkg: "@google/gemini-cli", pkgDir: "C:/Users/u/AppData/Roaming/npm/node_modules/@google/gemini-cli", rest: "bundle/gemini.js" });
  const py = [{ dist: "aider-chat", module: "aider", entry: "aider" }];
  assert.equal(pythonEntry(String.raw`\\?\C:\Users\u\pipx\venvs\aider-chat\Scripts\aider.exe`, { platform: "win32", home: String.raw`C:\Users\u`, py }), "aider-chat");
});

test("both gates: sibling prefixes, trailing separators and .. segments", () => {
  // terminal / IDE gate
  assert.equal(inLocation("Code.exe", String.raw`C:\Program Files Extra\Code.exe`, "win32"), false);
  assert.equal(inLocation("kitty", "/home/u/.local/binx/kitty", "linux"), false);
  assert.equal(inLocation("code", "/usr/share/../../home/u/code", "linux"), false);
  assert.equal(isTempPath("/tmpx/a", "linux"), false);
  assert.equal(isTempPath("/tmp//a", "linux"), true);
  assert.equal(isTempPath("/TMP/a", "linux"), false, "Linux: /TMP is not /tmp");
  assert.equal(isTempPath(String.raw`\\?\C:\Users\u\AppData\Local\Temp\x.exe`, "win32"), true);
  // install-location gate
  const o = { platform: "linux", home: "/home/u/", npm: NPM, readFile: files({ "/usr/local/lib-old/node_modules/@anthropic-ai/claude-code/package.json": pkgJson("@anthropic-ai/claude-code", { claude: "cli.js" }) }) };
  assert.equal(packageAt("/usr/local/lib-old/node_modules/@anthropic-ai/claude-code/cli.js", o), null);
  assert.equal(packageAt("/usr/local/lib/node_modules/../../lib-old/node_modules/@anthropic-ai/claude-code/cli.js", o), null);
  assert.equal(packageAt("/home/u2/.npm-global/lib/node_modules/@anthropic-ai/claude-code/cli.js", o), null, "another home that starts with this one");
  assert.equal(venvInterpreter("/home/u/.local/share/uv/tools/aider-chat/bin/../../../../../../usr/bin/python3", "aider-chat", o), false);
  assert.equal(venvInterpreter("/home/u/.local/share/uv/tools/aider-chat/bin//python3", "aider-chat", o), true);
  assert.equal(nativeClaudeExe("/home/u/.local/share/claude/versions/2.1.295", "2.1.295", o), true, "a home with a trailing separator");
  assert.equal(nativeClaudeExe("/home/u/.local//share/claude/versions/2.1.295/", "2.1.295", o), true, "repeated and trailing separators name the same file");
  assert.equal(nativeClaudeExe("/home/u/.local/share/claude/versions-old/2.1.295", "2.1.295", o), false);
  assert.equal(nativeClaudeExe("/home/u/.local/share/claude/versions/x/../2.1.295", "2.1.295", o), false);
  assert.equal(nativeClaudeExe("/home/u/.LOCAL/share/claude/versions/2.1.295", "2.1.295", o), false, "Linux: case-sensitive");
  assert.equal(nativeClaudeExe("/Users/u/.LOCAL/share/claude/versions/2.1.295", "2.1.295", { platform: "darwin", home: "/Users/u" }), true, "macOS: case-insensitive");
});
