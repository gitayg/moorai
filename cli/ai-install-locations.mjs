// Where a known AI CLI's program must sit for a script host running it to count as that CLI, and whether a
// resolved path is that package's own entry. Used by cli/ai-api-callers.mjs only.
//
// WHY A LOCATION AND AN ENTRY, NOT A NAME. A package name anywhere in a path (…/node_modules/@anthropic-ai/
// claude-code/… under /tmp, or nested inside some other package) proves nothing: anyone can create that
// folder. A path counts only when it is <root>/node_modules/<pkg>/<bin> for a root below that a package
// manager installs global packages into, <pkg> is the FIRST package under that root (a known package nested
// in another package's node_modules does not count), the package.json there names <pkg>, and <bin> is one
// of the files its "bin" field lists: the file the package manager's shim runs. The script host resolves
// its main script through symlinks (realpath), so a shim in a bin folder lands on that file.
//
// npm-style roots (<root>/node_modules/<pkg>/<bin>), macOS and Linux (H = the user's home):
//   /usr/local/lib, /usr/lib, /opt/homebrew/lib, /home/linuxbrew/.linuxbrew/lib   npm's global prefix (nodejs.org,
//     distro, Homebrew and Linuxbrew node); H/.npm-global/lib, H/.npm-packages/lib, H/.local/lib (a user prefix);
//   H/.nvm/versions/node/*/lib, H/.local/share/fnm/…, H/Library/Application Support/fnm/…, H/.fnm/node-versions/*/
//     installation/lib, H/.asdf/installs/nodejs/*/lib, H/.local/share/mise/installs/node/*/lib (version managers);
//   H/.volta/tools/image/packages/<pkg>/lib (Volta, one prefix per package); H/.config/yarn/global (yarn);
//   H/.bun/install/global (bun).
// Windows (R = H\AppData\Roaming, L = H\AppData\Local): R\npm (npm's default prefix), C:\Program Files\nodejs,
//   R\nvm\* (nvm-windows), R\fnm\node-versions\*\installation, L\Volta\tools\image\packages\<pkg>,
//   L\Yarn\Data\global, H\.bun\install\global.
// pnpm (<root>/node_modules/<pkg>, which resolves into <root>/.pnpm/<id>/node_modules/<pkg>): H/Library/pnpm/
//   global/*, H/.local/share/pnpm/global/*, L\pnpm\global\*.
// deno's npm cache (<root>/<pkg>/<version>/<bin>): H/Library/Caches/deno/npm/registry.npmjs.org, H/.cache/deno/
//   npm/registry.npmjs.org, L\deno\npm\registry.npmjs.org.
// aider (python): the console script <venv>/bin/aider (Windows <venv>\Scripts\aider.exe) of a pipx or uv tool
//   venv named aider-chat: H/.local/pipx/venvs, H/.local/share/pipx/venvs, H/Library/Application Support/pipx/
//   venvs, H/.local/share/uv/tools; Windows H\pipx\venvs, H\.local\pipx\venvs, L\pipx\pipx\venvs, R\uv\data\tools.
// A prefix moved elsewhere (npm config prefix, DENO_DIR, PIPX_HOME, a relocated AppData) is not recognised and
// the caller stays unknown. Every per-user root is writable by the user, so this tells an installed CLI from a
// script elsewhere; it does not prove the installed files are unmodified.
//
// Every containment test here is cli/path-within.mjs: by normalised segments, with the platform's case rule
// (Windows and macOS fold case, Linux does not), never a string prefix.
import { readFileSync } from "node:fs";
import { within, splitPath, joinHead, sameName, foldsCase } from "./path-within.mjs";

const slash = (p) => String(p ?? "").replace(/\\/g, "/");
// The user's home as a root prefix. A home holding "*" would read as a glob, so it yields no per-user roots.
const homeOf = (home) => { const H = slash(home).replace(/\/+$/, ""); return H && !H.includes("*") ? H : null; };

// "*" is one path segment (cli/path-within.mjs globs); "{pkg}" is a package name, scoped or not.
export function installRoots(platform, home) {
  const H = homeOf(home);
  if (platform === "win32") {
    const R = `${H}/AppData/Roaming`, L = `${H}/AppData/Local`;
    return {
      npm: ["C:/Program Files/nodejs", ...(H ? [`${R}/npm`, `${R}/nvm/*`, `${R}/fnm/node-versions/*/installation`, `${L}/Volta/tools/image/packages/{pkg}`, `${L}/Yarn/Data/global`, `${H}/.bun/install/global`] : [])],
      pnpm: H ? [`${L}/pnpm/global/*`] : [],
      deno: H ? [`${L}/deno/npm/registry.npmjs.org`] : []
    };
  }
  return {
    npm: ["/usr/local/lib", "/usr/lib", "/opt/homebrew/lib", "/home/linuxbrew/.linuxbrew/lib", ...(H ? [`${H}/.npm-global/lib`, `${H}/.npm-packages/lib`, `${H}/.local/lib`,
      `${H}/.nvm/versions/node/*/lib`, `${H}/.local/share/fnm/node-versions/*/installation/lib`, `${H}/Library/Application Support/fnm/node-versions/*/installation/lib`,
      `${H}/.fnm/node-versions/*/installation/lib`, `${H}/.volta/tools/image/packages/{pkg}/lib`, `${H}/.asdf/installs/nodejs/*/lib`,
      `${H}/.local/share/mise/installs/node/*/lib`, `${H}/.config/yarn/global`, `${H}/.bun/install/global`] : [])],
    pnpm: H ? [`${H}/Library/pnpm/global/*`, `${H}/.local/share/pnpm/global/*`] : [],
    deno: H ? [`${H}/Library/Caches/deno/npm/registry.npmjs.org`, `${H}/.cache/deno/npm/registry.npmjs.org`] : []
  };
}
// A template's {pkg} as globs: one segment, or an @scope segment and a name.
const pkgGlobs = (tpl) => (tpl.includes("{pkg}") ? [tpl.replace("{pkg}", "*"), tpl.replace("{pkg}", "@*/*")] : [tpl]);

// path → { pkg, pkgDir, rest } for the first package under an install root, or null. rest is "/"-joined.
export function packageAt(path, { platform, home }) {
  const sp = splitPath(path, platform);
  if (!sp) return null;
  const is = (seg, name) => sameName(seg, name, platform);
  for (const [kind, list] of Object.entries(installRoots(platform, home))) {
    for (const tpl of list.flatMap(pkgGlobs)) {
      const t = within(path, tpl, platform);
      if (!t) continue;
      let i = 0;
      if (kind === "pnpm" && is(t[0], ".pnpm") && t.length > 2) i = 2;
      if (kind !== "deno") { if (!is(t[i] ?? "", "node_modules")) continue; i++; }
      const n = String(t[i] ?? "").startsWith("@") ? 2 : 1;
      if (t.length < i + n + 1 || (n === 2 && t[i + 1].startsWith("@"))) continue;
      const pkg = t.slice(i, i + n).join("/");
      i += n;
      if (kind === "deno") { if (t.length < i + 2) continue; i++; }
      const base = sp.segs.length - t.length;
      return { pkg, pkgDir: joinHead(sp, base + i), rest: t.slice(i).join("/") };
    }
  }
  return null;
}

// A bin entry as package-relative segments: "./bin/x.js" → ["bin", "x.js"]; an absolute path, a drive, a "."
// or ".." segment never matches.
const binSegs = (b) => {
  const s = slash(b);
  if (!s || s.startsWith("/") || /^[A-Za-z]:/.test(s)) return null;
  const segs = s.split("/").filter(Boolean);
  while (segs[0] === ".") segs.shift();
  return segs.length && !segs.some((g) => g === "." || g === "..") ? segs : null;
};

// A resolved script path → the known npm package whose own bin entry it is, or null.
export function npmEntry(path, { platform, home, npm, readFile = readFileSync }) {
  const at = packageAt(path, { platform, home });
  if (!at) return null;
  const want = at.pkg.toLowerCase();
  if (!npm.includes(want) || (!foldsCase(platform) && at.pkg !== want)) return null;
  let pj;
  try { pj = JSON.parse(readFile(`${at.pkgDir}/package.json`, "utf8")); } catch { return null; }
  if (!pj || typeof pj.name !== "string" || pj.name.toLowerCase() !== want) return null;
  const bins = typeof pj.bin === "string" ? [pj.bin] : pj.bin && typeof pj.bin === "object" ? Object.values(pj.bin) : [];
  const rest = at.rest.split("/");
  return bins.some((b) => { const r = binSegs(b); return !!r && r.length === rest.length && r.every((g, k) => sameName(g, rest[k], platform)); }) ? want : null;
}

export function venvRoots(platform, home, dist) {
  const H = homeOf(home);
  if (!H) return [];
  if (platform === "win32") return [`${H}/pipx/venvs/${dist}`, `${H}/.local/pipx/venvs/${dist}`, `${H}/AppData/Local/pipx/pipx/venvs/${dist}`, `${H}/AppData/Roaming/uv/data/tools/${dist}`];
  return [`${H}/.local/pipx/venvs/${dist}`, `${H}/.local/share/pipx/venvs/${dist}`, `${H}/Library/Application Support/pipx/venvs/${dist}`, `${H}/.local/share/uv/tools/${dist}`];
}
// <venv>/<dir>/<file> exactly, for one of dist's venvs; file is tested by a whole-name pattern.
const inVenv = (path, platform, home, dist, dir, file) => venvRoots(platform, home, dist).some((v) => {
  const t = within(path, v, platform);
  return !!t && t.length === 2 && sameName(t[0], dir, platform) && new RegExp(`^(?:${file})$`, foldsCase(platform) ? "i" : "").test(t[1]);
});
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// A resolved python script → the dist whose console script it is (<venv>/bin/aider, <venv>\Scripts\aider.exe).
export function pythonEntry(path, { platform, home, py }) {
  const hit = py.find((x) => (platform === "win32" ? inVenv(path, platform, home, x.dist, "Scripts", `${esc(x.entry)}\\.exe`) : inVenv(path, platform, home, x.dist, "bin", esc(x.entry))));
  return hit ? hit.dist : null;
}
// python -m <module>: the interpreter as invoked (argv[0], not resolved: a venv's python links to the base
// interpreter) must be that dist's venv python, so its site-packages are the venv's.
export function venvInterpreter(argv0, dist, { platform, home }) {
  return platform === "win32" ? inVenv(argv0, platform, home, dist, "Scripts", "pythonw?(\\d+(\\.\\d+)*)?\\.exe") : inVenv(argv0, platform, home, dist, "bin", "python(\\d+(\\.\\d+)*)?");
}

// Claude Code's native install keeps each version as $HOME/.local/share/claude/versions/<version>.
export const isVersionImage = (image) => /^\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.-]*)?$/.test(String(image || ""));
export function nativeClaudeExe(exe, image, { platform, home }) {
  const H = homeOf(home);
  if (platform === "win32" || !isVersionImage(image) || !exe || !H) return false;
  const t = within(exe, `${H}/.local/share/claude/versions`, platform);
  return !!t && t.length === 1 && sameName(t[0], image, platform);
}

// ---- AI apps, agents and browsers known by name: where each one installs (cli/ai-api-callers.mjs) ----
// A process named like one of these counts as that product only when its executable, as the OS reports it,
// is inside one of the product's locations for this platform. A location is "<dir>" (anything below it is the
// product's own code) or "<dir>|<file>" (a shared folder, where only that file counts). Tokens: "~" the home;
// %L = ~\AppData\Local, %R = ~\AppData\Roaming, %PF = <drive>:\Program Files, %PF86 = <drive>:\Program Files
// (x86), %WA = <drive>:\Program Files\WindowsApps; "app:<X.app>" = /Applications/<X.app> and ~/Applications/
// <X.app>; "brew:<name>" = Homebrew's Cellar and Caskroom folders for <name>; "npm:<pkg>" = <root>/
// node_modules/<pkg> under every npm-style and pnpm install root above. The desktop apps in data/ai-catalog.json
// add their catalog locations (the .app on macOS; on Windows the catalog folder under %LOCALAPPDATA%, Program
// Files and Program Files (x86), the roots the AIBOM searches). sign (macOS only): the product's stable signing
// identity, a second way to be known (cli/ai-api-callers.mjs signRequirement).
export const PRODUCTS = Object.freeze([
  { id: "claude-desktop", names: ["claude"], mac: ["app:Claude.app"], win: ["%L/AnthropicClaude", "%L/Programs/Claude"],
    sign: { team: "Q6L2SF6YDW", ids: ["com.anthropic.claudefordesktop", "com.anthropic.claudefordesktop.helper"] } },
  { id: "claude-code", names: ["claude"], mac: ["~/Library/Application Support/Claude/claude-code", "~/Library/Application Support/Claude-Teams/claude-code", "brew:claude-code", "npm:@anthropic-ai/claude-code"],
    linux: ["npm:@anthropic-ai/claude-code"], win: ["~/.local/bin|claude.exe", "npm:@anthropic-ai/claude-code"], sign: { team: "Q6L2SF6YDW", ids: ["com.anthropic.claude-code"] } },
  { id: "codex", names: ["codex"], mac: ["app:ChatGPT.app", "app:Codex.app", "brew:codex", "npm:@openai/codex"], linux: ["npm:@openai/codex"], win: ["npm:@openai/codex"],
    sign: { team: "2DC432GLL2", ids: ["codex", "com.openai.codex", "com.openai.codex.helper"] } },
  { id: "chatgpt", names: ["chatgpt"], mac: ["app:ChatGPT.app"], win: ["%L/Programs/ChatGPT", "%WA/OpenAI.ChatGPT-Desktop_*"],
    sign: { team: "2DC432GLL2", ids: ["com.openai.chat", "com.openai.codex", "com.openai.codex.helper"] } },
  { id: "chatgpt-atlas", names: ["chatgpt atlas"], mac: ["app:ChatGPT Atlas.app"], win: ["%L/Programs/ChatGPT Atlas"],
    sign: { team: "2DC432GLL2", ids: ["com.openai.atlas", "com.openai.atlas.web", "com.openai.atlas.web.helper"] } },
  { id: "cursor", names: ["cursor"], mac: ["app:Cursor.app"], win: ["%L/Programs/cursor"], linux: ["/usr/share/cursor", "/opt/cursor", "/opt/Cursor"] },
  { id: "cursor-agent", names: ["cursor-agent"], mac: ["~/.local/share/cursor-agent"], linux: ["~/.local/share/cursor-agent"], win: ["%L/cursor-agent"] },
  { id: "vscode", names: ["code", "code - insiders"], mac: ["app:Visual Studio Code.app", "app:Visual Studio Code - Insiders.app"],
    win: ["%L/Programs/Microsoft VS Code", "%PF/Microsoft VS Code", "%L/Programs/Microsoft VS Code Insiders", "%PF/Microsoft VS Code Insiders"],
    linux: ["/usr/share/code", "/usr/share/code-insiders", "/snap/code", "/snap/code-insiders", "/var/lib/flatpak/app/com.visualstudio.code"] },
  { id: "windsurf", names: ["windsurf"], mac: ["app:Windsurf.app"], win: ["%L/Programs/Windsurf"], linux: ["/usr/share/windsurf"] },
  { id: "copilot", names: ["copilot", "github-copilot"], mac: ["app:Copilot.app", "brew:copilot-cli", "npm:@github/copilot"], linux: ["npm:@github/copilot"],
    win: ["%L/Programs/Copilot", "%WA/Microsoft.Copilot_*", "%L/Microsoft/WinGet/Packages/GitHub.Copilot_*", "npm:@github/copilot"], sign: { team: "UBF8T346G9", ids: ["com.microsoft.copilot-mac"] } },
  // Droid (docs.factory.com/droid-cli/quickstart.md): "brew install --cask droid", "npm install -g droid"; the
  // `curl -fsSL https://app.factory.ai/cli | sh` install location is not documented, so it is not listed.
  { id: "droid", names: ["droid"], mac: ["brew:droid", "npm:droid"], linux: ["npm:droid"], win: ["npm:droid"] },
  // Antigravity CLI (antigravity.google/docs/getting-started?tab=cli): "~/.local/bin/agy" on macOS / Linux,
  // "C:\Users\<username>\AppData\Local\agy\bin" on Windows.
  { id: "antigravity-cli", names: ["agy"], mac: ["~/.local/bin|agy"], linux: ["~/.local/bin|agy"], win: ["%L/agy/bin"] },
  // Kiro CLI (kiro.dev/docs/getting-started/installation): `brew install kiro-cli`; the zip install puts files in
  // ~/.local/bin. Where the install script puts it is not documented, so it is not listed separately.
  { id: "kiro-cli", names: ["kiro-cli"], mac: ["brew:kiro-cli", "~/.local/bin|kiro-cli"], linux: ["~/.local/bin|kiro-cli"] },
  // Cline CLI (docs.cline.bot/usage/cli-overview): `npm i -g cline`.
  { id: "cline", names: ["cline"], mac: ["npm:cline"], linux: ["npm:cline"], win: ["npm:cline"] },
  { id: "ollama", names: ["ollama", "ollama app"], mac: ["app:Ollama.app", "brew:ollama"], win: ["%L/Programs/Ollama"],
    linux: ["/usr/local/bin|ollama", "/usr/bin|ollama", "/usr/local/lib/ollama", "/usr/lib/ollama", "/snap/ollama"] },
  { id: "lm-studio", names: ["lm studio", "lms", "llmster"], mac: ["app:LM Studio.app", "~/.lmstudio"], win: ["%L/Programs/lm-studio", "%L/Programs/LM Studio", "~/.lmstudio"], linux: ["~/.lmstudio"] },
  { id: "opencode", names: ["opencode"], mac: ["~/.opencode", "brew:opencode", "npm:opencode-ai"], linux: ["~/.opencode", "npm:opencode-ai"], win: ["~/.opencode", "npm:opencode-ai"] },
  { id: "goose", names: ["goose"], mac: ["app:Goose.app", "~/.local/bin|goose"], linux: ["~/.local/bin|goose"] },
  { id: "amp", names: ["amp"], mac: ["~/.amp", "npm:@sourcegraph/amp"], linux: ["~/.amp", "npm:@sourcegraph/amp"], win: ["npm:@sourcegraph/amp"] },
  { id: "crush", names: ["crush"], mac: ["brew:crush", "npm:@charmland/crush"], linux: ["npm:@charmland/crush"], win: ["npm:@charmland/crush"] },
  { id: "kiro", names: ["kiro"], mac: ["app:Kiro.app"], win: ["%L/Programs/Kiro"], linux: ["/usr/share/kiro"] },
  { id: "trae", names: ["trae"], mac: ["app:Trae.app"], win: ["%L/Programs/Trae"] },
  { id: "zed", names: ["zed"], mac: ["app:Zed.app"], linux: ["~/.local/zed.app"] },
  { id: "moorai", names: ["moorai", "moorai-desktop"], mac: ["app:MoorAI.app"], win: ["%L/MoorAI"], linux: ["/usr/bin|moorai", "/usr/bin|moorai-desktop"] },
  // browsers
  { id: "chrome", names: ["google chrome", "chrome"], mac: ["app:Google Chrome.app"], win: ["%PF/Google/Chrome", "%PF86/Google/Chrome", "%L/Google/Chrome"], linux: ["/opt/google/chrome"],
    sign: { team: "EQHXZ8M8AV", ids: ["com.google.Chrome", "com.google.Chrome.helper", "com.google.Chrome.helper.renderer"] } },
  { id: "chromium", names: ["chromium"], mac: ["app:Chromium.app"], win: ["%L/Chromium"], linux: ["/usr/lib/chromium", "/usr/lib/chromium-browser", "/usr/lib64/chromium-browser", "/snap/chromium"] },
  { id: "firefox", names: ["firefox"], mac: ["app:Firefox.app"], win: ["%PF/Mozilla Firefox", "%PF86/Mozilla Firefox", "%L/Mozilla Firefox"], linux: ["/usr/lib/firefox", "/usr/lib64/firefox", "/opt/firefox", "/snap/firefox"],
    sign: { team: "43AQ936H96", ids: ["org.mozilla.firefox"] } },
  { id: "safari", names: ["safari", "com.apple.webkit.networking"], mac: ["/Applications/Safari.app", "/System/Library/Frameworks/WebKit.framework", "/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework", "/System/Cryptexes/OS/System/Library/Frameworks/WebKit.framework"] },
  { id: "edge", names: ["msedge", "microsoft edge"], mac: ["app:Microsoft Edge.app"], win: ["%PF86/Microsoft/Edge", "%PF/Microsoft/Edge"], linux: ["/opt/microsoft/msedge"] },
  { id: "brave", names: ["brave", "brave browser"], mac: ["app:Brave Browser.app"], win: ["%PF/BraveSoftware", "%PF86/BraveSoftware", "%L/BraveSoftware"], linux: ["/opt/brave.com/brave", "/snap/brave"] },
  { id: "arc", names: ["arc"], mac: ["app:Arc.app"], win: ["%WA/TheBrowserCompany.Arc_*"] },
  { id: "opera", names: ["opera"], mac: ["app:Opera.app"], win: ["%L/Programs/Opera"], linux: ["/usr/lib/x86_64-linux-gnu/opera", "/snap/opera"] },
  { id: "vivaldi", names: ["vivaldi"], mac: ["app:Vivaldi.app"], win: ["%L/Vivaldi"], linux: ["/opt/vivaldi"] },
  { id: "dia", names: ["dia"], mac: ["app:Dia.app"] },
  { id: "comet", names: ["comet"], mac: ["app:Comet.app"], win: ["%L/Perplexity/Comet"] },
  { id: "iexplore", names: ["iexplore"], win: ["%PF/Internet Explorer", "%PF86/Internet Explorer"] }
]);
const OS_KEY = { darwin: "mac", win32: "win" };

// One location token → [{ root, file }]. A per-user location is dropped when the home is unusable.
function expand(loc, platform, H) {
  const [spec, file] = loc.split("|");
  let roots;
  if (spec.startsWith("app:")) roots = ["/Applications", ...(H ? [`${H}/Applications`] : [])].map((a) => `${a}/${spec.slice(4)}`);
  else if (spec.startsWith("brew:")) roots = ["/opt/homebrew/Cellar", "/opt/homebrew/Caskroom", "/usr/local/Cellar", "/usr/local/Caskroom"].map((b) => `${b}/${spec.slice(5)}`);
  else if (spec.startsWith("npm:")) {
    const pkg = spec.slice(4), r = installRoots(platform, H);
    roots = [...r.npm.map((t) => `${t.replace("{pkg}", pkg)}/node_modules/${pkg}`), ...r.pnpm.map((t) => `${t}/.pnpm/*/node_modules/${pkg}`)];
  } else {
    const m = /^(~|%PF86|%PF|%WA|%L|%R)(?=\/|$)/.exec(spec);
    const base = !m ? "" : m[1] === "~" ? H : m[1] === "%L" ? H && `${H}/AppData/Local` : m[1] === "%R" ? H && `${H}/AppData/Roaming`
      : m[1] === "%PF" ? "*:/Program Files" : m[1] === "%PF86" ? "*:/Program Files (x86)" : "*:/Program Files/WindowsApps";
    if (m && !base) return [];
    roots = [m ? base + spec.slice(m[1].length) : spec];
  }
  return roots.map((root) => ({ root, file: file || "" }));
}

// → Map(name → [{ root, file }]) for this platform. catalog: [{ names: [image keys], mac: ["X.app"], win:
// ["Programs/X/X.exe"] }] from data/ai-catalog.json.
export function appLocations(platform, home, { catalog = [], products = PRODUCTS } = {}) {
  const H = homeOf(home), os = OS_KEY[platform] || "linux", out = new Map();
  const add = (names, locs) => { for (const n of names) out.set(n, [...(out.get(n) || []), ...locs.flatMap((l) => expand(l, platform, H))]); };
  for (const p of products) add(p.names, p[os] || []);
  for (const a of catalog) {
    if (os === "mac") add(a.names, (a.mac || []).map((x) => `app:${x}`));
    if (os === "win") add(a.names, (a.win || []).flatMap((w) => {
      const s = slash(w), cut = s.lastIndexOf("/"), dir = s.slice(0, Math.max(cut, 0)), file = s.slice(cut + 1);
      return ["%L", "%PF", "%PF86"].map((b) => (dir ? `${b}/${dir}` : `${b}|${file}`));
    }));
  }
  return out;
}

// Is exe inside one of name's locations? exe: the executable path the OS reports for the process.
export function atAppLocation(name, exe, { platform, locations }) {
  if (!exe) return false;
  return (locations.get(name) || []).some(({ root, file }) => {
    const t = within(exe, root, platform);
    return !!t && (!file || (t.length === 1 && sameName(t[0], file, platform)));
  });
}

// macOS: the code-signing requirement a running process named `name` may satisfy instead of the location
// (each product's Developer ID team and signing identifiers, measured on installed copies), or "".
export function signRequirement(name, { products = PRODUCTS } = {}) {
  const parts = products.filter((p) => p.sign && p.names.includes(name)).map(({ sign }) =>
    `(anchor apple generic and (${sign.ids.map((i) => `identifier "${i}"`).join(" or ")}) and certificate leaf[subject.OU] = "${sign.team}")`);
  return parts.join(" or ");
}
