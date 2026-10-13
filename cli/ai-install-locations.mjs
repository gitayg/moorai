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
import { readFileSync } from "node:fs";

const fold = (platform) => platform === "darwin" || platform === "win32";
const slash = (p) => String(p ?? "").replace(/\\/g, "/");
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// A root template → regex source: "*" is one path segment, "{pkg}" a package name (scoped or not).
const tplRe = (tpl) => esc(slash(tpl)).replace(/\\\*/g, "[^/]+").replace(/\\\{pkg\\\}/g, "(?:@[^/]+/)?[^/]+");

export function installRoots(platform, home) {
  const H = slash(home).replace(/\/+$/, "");
  if (platform === "win32") {
    const R = `${H}/AppData/Roaming`, L = `${H}/AppData/Local`;
    return {
      npm: [`${R}/npm`, "C:/Program Files/nodejs", `${R}/nvm/*`, `${R}/fnm/node-versions/*/installation`, `${L}/Volta/tools/image/packages/{pkg}`, `${L}/Yarn/Data/global`, `${H}/.bun/install/global`],
      pnpm: [`${L}/pnpm/global/*`],
      deno: [`${L}/deno/npm/registry.npmjs.org`]
    };
  }
  return {
    npm: ["/usr/local/lib", "/usr/lib", "/opt/homebrew/lib", "/home/linuxbrew/.linuxbrew/lib", `${H}/.npm-global/lib`, `${H}/.npm-packages/lib`, `${H}/.local/lib`,
      `${H}/.nvm/versions/node/*/lib`, `${H}/.local/share/fnm/node-versions/*/installation/lib`, `${H}/Library/Application Support/fnm/node-versions/*/installation/lib`,
      `${H}/.fnm/node-versions/*/installation/lib`, `${H}/.volta/tools/image/packages/{pkg}/lib`, `${H}/.asdf/installs/nodejs/*/lib`,
      `${H}/.local/share/mise/installs/node/*/lib`, `${H}/.config/yarn/global`, `${H}/.bun/install/global`],
    pnpm: [`${H}/Library/pnpm/global/*`, `${H}/.local/share/pnpm/global/*`],
    deno: [`${H}/Library/Caches/deno/npm/registry.npmjs.org`, `${H}/.cache/deno/npm/registry.npmjs.org`]
  };
}

// path → { pkg, pkgDir, rest } for the first package under an install root, or null.
export function packageAt(path, { platform, home }) {
  const p = slash(path), flags = fold(platform) ? "i" : "";
  for (const [kind, list] of Object.entries(installRoots(platform, home))) {
    for (const tpl of list) {
      const m = new RegExp(`^${tplRe(tpl)}/`, flags).exec(p);
      if (!m) continue;
      let pre = m[0], tail = p.slice(pre.length);
      if (kind === "pnpm") { const x = /^\.pnpm\/[^/]+\//.exec(tail); if (x) { pre += x[0]; tail = tail.slice(x[0].length); } }
      if (kind !== "deno") { if (!/^node_modules\//i.test(tail)) continue; pre += tail.slice(0, 13); tail = tail.slice(13); }
      const pm = /^((?:@[^/]+\/)?[^/@][^/]*)\/(.+)$/.exec(tail);
      if (!pm) continue;
      let pkgDir = pre + pm[1], rest = pm[2];
      if (kind === "deno") { const v = /^([^/]+)\/(.+)$/.exec(rest); if (!v) continue; pkgDir += `/${v[1]}`; rest = v[2]; }
      return { pkg: pm[1], pkgDir, rest };
    }
  }
  return null;
}

// A bin entry as a package-relative path: "./bin/x.js" → "bin/x.js"; ".." or an absolute path never matches.
const binRel = (b) => {
  const s = slash(b).replace(/^(\.\/)+/, "").replace(/\/{2,}/g, "/");
  return !s || s.startsWith("/") || /^[A-Za-z]:/.test(s) || s.split("/").includes("..") ? "" : s;
};

// A resolved script path → the known npm package whose own bin entry it is, or null.
export function npmEntry(path, { platform, home, npm, readFile = readFileSync }) {
  const at = packageAt(path, { platform, home });
  if (!at) return null;
  const want = at.pkg.toLowerCase();
  if (!npm.includes(want) || (!fold(platform) && at.pkg !== want)) return null;
  let pj;
  try { pj = JSON.parse(readFile(`${at.pkgDir}/package.json`, "utf8")); } catch { return null; }
  if (!pj || typeof pj.name !== "string" || pj.name.toLowerCase() !== want) return null;
  const bins = typeof pj.bin === "string" ? [pj.bin] : pj.bin && typeof pj.bin === "object" ? Object.values(pj.bin) : [];
  const rest = fold(platform) ? at.rest.toLowerCase() : at.rest;
  return bins.some((b) => { const r = binRel(b); return !!r && (fold(platform) ? r.toLowerCase() : r) === rest; }) ? want : null;
}

export function venvRoots(platform, home, dist) {
  const H = slash(home).replace(/\/+$/, "");
  if (platform === "win32") return [`${H}/pipx/venvs/${dist}`, `${H}/.local/pipx/venvs/${dist}`, `${H}/AppData/Local/pipx/pipx/venvs/${dist}`, `${H}/AppData/Roaming/uv/data/tools/${dist}`];
  return [`${H}/.local/pipx/venvs/${dist}`, `${H}/.local/share/pipx/venvs/${dist}`, `${H}/Library/Application Support/pipx/venvs/${dist}`, `${H}/.local/share/uv/tools/${dist}`];
}
const inVenv = (path, platform, home, dist, tail) => {
  const flags = fold(platform) ? "i" : "";
  return venvRoots(platform, home, dist).some((v) => new RegExp(`^${esc(v)}/${tail}$`, flags).test(slash(path)));
};
// A resolved python script → the dist whose console script it is (<venv>/bin/aider, <venv>\Scripts\aider.exe).
export function pythonEntry(path, { platform, home, py }) {
  const hit = py.find((x) => inVenv(path, platform, home, x.dist, platform === "win32" ? `Scripts/${esc(x.entry)}\\.exe` : `bin/${esc(x.entry)}`));
  return hit ? hit.dist : null;
}
// python -m <module>: the interpreter as invoked (argv[0], not resolved: a venv's python links to the base
// interpreter) must be that dist's venv python, so its site-packages are the venv's.
export function venvInterpreter(argv0, dist, { platform, home }) {
  return inVenv(argv0, platform, home, dist, platform === "win32" ? "Scripts/pythonw?(\\d+(\\.\\d+)*)?\\.exe" : "bin/python(\\d+(\\.\\d+)*)?");
}

// Claude Code's native install keeps each version as $HOME/.local/share/claude/versions/<version>.
export const isVersionImage = (image) => /^\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.-]*)?$/.test(String(image || ""));
export function nativeClaudeExe(exe, image, { platform, home }) {
  if (platform === "win32" || !isVersionImage(image) || !exe) return false;
  const want = `${slash(home).replace(/\/+$/, "")}/.local/share/claude/versions/${image}`;
  return fold(platform) ? slash(exe).toLowerCase() === want.toLowerCase() : slash(exe) === want;
}
