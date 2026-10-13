// A name match alone never makes an AI API caller known (cli/ai-api-callers.mjs): a process named like an AI
// app, agent or browser is known only when its executable, as the OS reports it, is inside that product's
// expected install location (cli/ai-install-locations.mjs), or on macOS when the running process satisfies the
// product's signing identity. Canned process rows (image, executable path, argv) in, verdict out.
//
//   node --test --import ./test/hermetic-env.mjs test/ai-api-callers-identity.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveAiHosts, aiApiCallers } from "../cli/ai-api-callers.mjs";

const RESOLVED = await resolveAiHosts({ lookup: async (h) => (h === "api.anthropic.com" ? [{ address: "160.79.104.10" }] : []) });
const HOME = { darwin: "/Users/u", win32: String.raw`C:\Users\u`, linux: "/home/u" };
const est = (pid, proc) => ({ pid: String(pid), proc, state: "established", lhost: "10.0.0.5", lport: 50000 + pid, rhost: "160.79.104.10", rport: 443 });
// One row: { platform, image, exe (undefined = the OS gave no path), argv?, signed? } → known?
function known({ platform, image, exe, argv, signed = false, sigCalls = [] }) {
  const exeOf = () => new Map(exe === undefined ? [] : [["70", { exe }]]);
  const argvOf = () => new Map(argv ? [["70", { argv, spaced: false }]] : []);
  const sigOf = (pid, req) => { sigCalls.push([pid, req]); return signed; };
  const r = aiApiCallers([est(70, image)], RESOLVED, { moorai: new Set(), exeOf, argvOf, sigOf, platform, home: HOME[platform], realpath: (p) => p, readFile: () => { throw new Error("ENOENT"); } });
  return r.callers[0].known;
}

test("a known name at its expected path is known; the same name elsewhere, or with no path, is not", () => {
  const rows = [
    ["darwin", "Claude", "/Applications/Claude.app/Contents/MacOS/Claude", "/Users/u/Downloads/Claude.app/Contents/MacOS/Claude"],
    ["darwin", "Claude Helper", "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper", "/tmp/Claude Helper"],
    ["win32", "Cursor.exe", String.raw`C:\Users\u\AppData\Local\Programs\cursor\Cursor.exe`, String.raw`C:\Users\u\AppData\Roaming\Cursor.exe`],
    ["linux", "code", "/usr/share/code/code", "/home/u/.cache/code"]
  ];
  for (const [platform, image, good, bad] of rows) {
    assert.equal(known({ platform, image, exe: good }), true, `${image} @ ${good}`);
    assert.equal(known({ platform, image, exe: bad }), false, `${image} @ ${bad}`);
    assert.equal(known({ platform, image, exe: undefined }), false, `${image} with no executable path`);
  }
  // a sibling folder that starts like the product's folder is elsewhere
  assert.equal(known({ platform: "darwin", image: "Claude", exe: "/Applications/Claude.app.old/Contents/MacOS/Claude" }), false);
  assert.equal(known({ platform: "win32", image: "Code.exe", exe: String.raw`C:\Program Files\Microsoft VS Code Extra\Code.exe` }), false);
  // a shared bin folder counts for the product's own file only
  assert.equal(known({ platform: "linux", image: "ollama", exe: "/usr/local/bin/ollama" }), true);
  assert.equal(known({ platform: "linux", image: "ollama", exe: "/usr/local/bin/python3" }), false, "a process that renamed itself ollama");
});

// One case per product: [platform, image as the process table names it, executable path the OS reports].
const PRODUCT_CASES = {
  "claude-desktop": [["darwin", "Claude", "/Applications/Claude.app/Contents/MacOS/Claude"], ["win32", "claude.exe", String.raw`C:\Users\u\AppData\Local\AnthropicClaude\app-0.14.10\claude.exe`]],
  "claude-code": [["darwin", "claude", "/Users/u/Library/Application Support/Claude-Teams/claude-code/2.1.295/9d6405864fdc/claude.app/Contents/MacOS/claude"],
    ["darwin", "claude", "/opt/homebrew/Caskroom/claude-code/2.1.295/claude"], ["win32", "claude.exe", String.raw`C:\Users\u\.local\bin\claude.exe`],
    ["linux", "claude", "/home/u/.npm-global/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"]],
  codex: [["darwin", "Codex (Service)", "/Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/154.0.8037.57/Helpers/Codex (Service).app/Contents/MacOS/Codex (Service)"],
    ["linux", "codex", "/home/u/.nvm/versions/node/v22.22.0/lib/node_modules/@openai/codex/vendor/x86_64-unknown-linux-musl/codex/codex"],
    ["win32", "codex.exe", String.raw`C:\Users\u\AppData\Roaming\npm\node_modules\@openai\codex\vendor\x86_64-pc-windows-msvc\codex\codex.exe`]],
  chatgpt: [["darwin", "ChatGPT", "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"], ["win32", "ChatGPT.exe", String.raw`C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2025.1.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe`]],
  "chatgpt-atlas": [["darwin", "ChatGPT Atlas", "/Applications/ChatGPT Atlas.app/Contents/MacOS/ChatGPT Atlas"]],
  cursor: [["darwin", "Cursor", "/Applications/Cursor.app/Contents/MacOS/Cursor"], ["linux", "cursor", "/usr/share/cursor/cursor"]],
  "cursor-agent": [["darwin", "cursor-agent", "/Users/u/.local/share/cursor-agent/versions/2026.05.27-fe9a6e2/cursor-agent"]],
  vscode: [["darwin", "Code Helper (Plugin)", "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)"],
    ["win32", "Code.exe", String.raw`C:\Program Files\Microsoft VS Code\Code.exe`], ["linux", "code", "/snap/code/171/usr/share/code/code"]],
  windsurf: [["darwin", "Windsurf", "/Applications/Windsurf.app/Contents/MacOS/Windsurf"], ["win32", "Windsurf.exe", String.raw`C:\Users\u\AppData\Local\Programs\Windsurf\Windsurf.exe`]],
  copilot: [["darwin", "copilot", "/opt/homebrew/Caskroom/copilot-cli/0.0.400/copilot"], ["darwin", "Copilot", "/Applications/Copilot.app/Contents/MacOS/Copilot"],
    ["win32", "copilot.exe", String.raw`C:\Users\u\AppData\Local\Microsoft\WinGet\Packages\GitHub.Copilot_Microsoft.Winget.Source_8wekyb3d8bbwe\copilot.exe`]],
  ollama: [["darwin", "ollama", "/Applications/Ollama.app/Contents/Resources/ollama"], ["linux", "ollama", "/usr/local/bin/ollama"], ["win32", "ollama app.exe", String.raw`C:\Users\u\AppData\Local\Programs\Ollama\ollama app.exe`]],
  "lm-studio": [["darwin", "LM Studio", "/Applications/LM Studio.app/Contents/MacOS/LM Studio"], ["darwin", "lms", "/Users/u/.lmstudio/bin/lms"], ["win32", "LM Studio.exe", String.raw`C:\Users\u\AppData\Local\Programs\lm-studio\LM Studio.exe`]],
  opencode: [["darwin", "opencode", "/Users/u/.opencode/bin/opencode"]],
  goose: [["linux", "goose", "/home/u/.local/bin/goose"]],
  amp: [["darwin", "amp", "/Users/u/.amp/bin/amp"]],
  crush: [["darwin", "crush", "/opt/homebrew/Cellar/crush/0.7.0/bin/crush"]],
  kiro: [["darwin", "Kiro", "/Applications/Kiro.app/Contents/MacOS/Kiro"]],
  trae: [["win32", "Trae.exe", String.raw`C:\Users\u\AppData\Local\Programs\Trae\Trae.exe`]],
  zed: [["darwin", "zed", "/Applications/Zed.app/Contents/MacOS/zed"]],
  moorai: [["darwin", "moorai", "/Applications/MoorAI.app/Contents/MacOS/moorai"], ["win32", "moorai.exe", String.raw`C:\Users\u\AppData\Local\MoorAI\moorai.exe`]],
  chrome: [["darwin", "Google Chrome Helper (Renderer)", "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/154.0.8037.98/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)"],
    ["win32", "chrome.exe", String.raw`C:\Program Files\Google\Chrome\Application\chrome.exe`], ["linux", "chrome", "/opt/google/chrome/chrome"]],
  chromium: [["linux", "chromium", "/usr/lib/chromium/chromium"]],
  firefox: [["darwin", "firefox", "/Applications/Firefox.app/Contents/MacOS/firefox"], ["win32", "firefox.exe", String.raw`C:\Program Files\Mozilla Firefox\firefox.exe`], ["linux", "firefox", "/snap/firefox/6000/usr/lib/firefox/firefox"]],
  safari: [["darwin", "com.apple.WebKit.Networking", "/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"]],
  edge: [["win32", "msedge.exe", String.raw`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`]],
  brave: [["darwin", "Brave Browser", "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"]],
  arc: [["win32", "Arc.exe", String.raw`C:\Program Files\WindowsApps\TheBrowserCompany.Arc_1.36.1.0_x64__ttt1ap7aakyb4\Arc.exe`]],
  opera: [["win32", "opera.exe", String.raw`C:\Users\u\AppData\Local\Programs\Opera\opera.exe`]],
  vivaldi: [["linux", "vivaldi", "/opt/vivaldi/vivaldi"]],
  dia: [["darwin", "Dia", "/Applications/Dia.app/Contents/MacOS/Dia"]],
  comet: [["win32", "comet.exe", String.raw`C:\Users\u\AppData\Local\Perplexity\Comet\Application\comet.exe`]],
  iexplore: [["win32", "iexplore.exe", String.raw`C:\Program Files\Internet Explorer\iexplore.exe`]],
  // desktop apps located through data/ai-catalog.json
  "catalog:jan": [["darwin", "Jan", "/Applications/Jan.app/Contents/MacOS/Jan"]],
  "catalog:msty": [["win32", "Msty.exe", String.raw`C:\Users\u\AppData\Local\Programs\Msty\Msty.exe`]],
  "catalog:perplexity": [["darwin", "Perplexity", "/Users/u/Applications/Perplexity.app/Contents/MacOS/Perplexity"]],
  "catalog:raycast": [["darwin", "Raycast", "/Applications/Raycast.app/Contents/MacOS/Raycast"]]
};
const ELSEWHERE = { darwin: "/Users/u/Downloads/x/", win32: "C:\\Users\\u\\Downloads\\x\\", linux: "/home/u/.cache/x/" };
const base = (p) => p.slice(Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\")) + 1);

test("one case per product: known at its install location, unknown with the same name and file anywhere else", () => {
  for (const [id, cases] of Object.entries(PRODUCT_CASES)) {
    for (const [platform, image, exe] of cases) {
      assert.equal(known({ platform, image, exe }), true, `${id}: ${image} @ ${exe}`);
      assert.equal(known({ platform, image, exe: ELSEWHERE[platform] + base(exe) }), false, `${id}: ${image} elsewhere`);
    }
  }
});

test("every product in the table has a case above, and every name it lists is a candidate name", async () => {
  const { PRODUCTS } = await import("../cli/ai-install-locations.mjs");
  const { KNOWN_NAMES } = await import("../cli/ai-api-callers.mjs");
  const names = KNOWN_NAMES();
  for (const p of PRODUCTS) {
    assert.ok(PRODUCT_CASES[p.id], `a case for ${p.id}`);
    for (const n of p.names) assert.ok(names.has(n), `${n} (${p.id}) is a candidate name`);
  }
  // candidate names with no install location anywhere: the CLIs that run as scripts (judged by their program)
  const { appLocations } = await import("../cli/ai-install-locations.mjs");
  const { catalogApps } = await import("../cli/ai-api-callers.mjs");
  const located = new Set(["darwin", "win32", "linux"].flatMap((os) => [...appLocations(os, HOME[os], { catalog: catalogApps() }).entries()].filter(([, l]) => l.length).map(([n]) => n)));
  assert.deepEqual([...names].filter((n) => !located.has(n)).sort(), ["aider", "gemini", "qwen"]);
});

test("macOS: off its location, a product with a signing identity is known only if the running process satisfies it; checked once per pid", () => {
  const calls = [];
  assert.equal(known({ platform: "darwin", image: "Claude", exe: "/Users/u/Downloads/Claude.app/Contents/MacOS/Claude", signed: true, sigCalls: calls }), true);
  assert.match(calls[0][1], /identifier "com\.anthropic\.claudefordesktop"/);
  assert.match(calls[0][1], /certificate leaf\[subject\.OU\] = "Q6L2SF6YDW"/);
  assert.equal(known({ platform: "darwin", image: "Claude", exe: "/Users/u/Downloads/Claude.app/Contents/MacOS/Claude", signed: false }), false);
  const none = [];
  assert.equal(known({ platform: "darwin", image: "Claude", exe: "/Applications/Claude.app/Contents/MacOS/Claude", signed: false, sigCalls: none }), true);
  assert.deepEqual(none, [], "at its location: no signature check");
  const cursor = [];
  assert.equal(known({ platform: "darwin", image: "Cursor", exe: "/Users/u/Downloads/Cursor.app/Contents/MacOS/Cursor", signed: true, sigCalls: cursor }), false, "no measured signing identity: the location alone decides");
  assert.deepEqual(cursor, []);
  assert.equal(known({ platform: "linux", image: "chrome", exe: "/home/u/chrome/chrome", signed: true }), false, "Linux has no signature to check");
  assert.equal(known({ platform: "darwin", image: "Claude", exe: undefined, signed: true }), false, "no executable path: not known, and not asked");
  // two connections from one pid: one check
  const twice = [];
  const exeOf = () => new Map([["71", { exe: "/Users/u/Downloads/Google Chrome.app/Contents/MacOS/Google Chrome" }]]);
  const r = aiApiCallers([est(71, "Google Chrome"), est(71, "Google Chrome")], RESOLVED, { moorai: new Set(), exeOf, argvOf: () => new Map(), sigOf: (p, q) => { twice.push(p); return true; }, platform: "darwin", home: "/Users/u" });
  assert.deepEqual(r.callers, [{ processImage: "Google Chrome", provider: "anthropic", known: true, connections: 2 }]);
  assert.deepEqual(twice, ["71"]);
});

test("a named process whose executable is a script host is judged by the program it runs (Linux #! scripts keep their name)", () => {
  const AIDER = "/home/u/.local/share/uv/tools/aider-chat/bin/aider";
  const opts = { platform: "linux", image: "aider", exe: "/home/u/.local/share/uv/python/cpython-3.12-linux-x86_64-gnu/bin/python3.12" };
  assert.equal(known({ ...opts, argv: ["/home/u/.local/share/uv/tools/aider-chat/bin/python3", AIDER, "--model", "x"] }), true);
  assert.equal(known({ ...opts, argv: ["/usr/bin/python3", "/tmp/evil.py"] }), false);
  assert.equal(known({ ...opts }), false, "no command line");
  assert.equal(known({ platform: "linux", image: "gemini", exe: "/home/u/.local/bin/gemini" }), false, "no install location for a name that runs as a script");
});
