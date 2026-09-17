// Package-specific static heuristics for a downloaded MCP server package. They complement, not replace,
// the shipped engine (scanPath): the engine reads text the way the agent would; these read CODE the way
// an installer would run it. Every regex is bounded (no nested quantifiers) because the input is hostile.
//
// Findings use the scan-core shape — {relativePath, surfaceKind, threatId, category, intentLabels,
// contentHash, tier} — with a string threatId from HEURISTICS. The matched span is only ever hashed.

import { readFileSync, statSync } from "node:fs";
import { relative, basename, join } from "node:path";
import { safeRelPath } from "./archive.mjs";
import { contentHash } from "../content-hash.mjs";
import { classifyPackage } from "../../data/popular-packages.js";

export const HEURISTICS = {
  "pkg-install-script": { category: "install-time-exec", tier: "justify", intent: "untrusted-install" },
  "pkg-install-script-remote": { category: "install-time-exec", tier: "block", intent: "untrusted-install" },
  "pkg-setup-cmdclass": { category: "install-time-exec", tier: "justify", intent: "untrusted-install" },
  "pkg-setup-cmdclass-exec": { category: "install-time-exec", tier: "block", intent: "untrusted-install" },
  "pkg-setup-spawn": { category: "install-time-exec", tier: "justify", intent: "untrusted-install" },
  "pkg-pth-autoexec": { category: "install-time-exec", tier: "justify", intent: "untrusted-install" },
  "pkg-install-script-download": { category: "install-time-exec", tier: "justify", intent: "untrusted-install" },
  "pkg-spawn-egress": { category: "spawn-with-egress", tier: "notify", intent: "external-network-egress" },
  "pkg-runtime-install": { category: "runtime-install", tier: "justify", intent: "untrusted-install" },
  "pkg-socket-shell": { category: "remote-code", tier: "block", intent: "obfuscated-payload" },
  "pkg-credential-read-egress": { category: "credential-harvest", tier: "justify", intent: "reads-credential-files" },
  "pkg-env-dump-egress": { category: "credential-harvest", tier: "block", intent: "instructs-exfiltration" },
  "pkg-obfuscated-exec": { category: "obfuscation", tier: "block", intent: "obfuscated-payload" },
  "pkg-decode-exec": { category: "obfuscation", tier: "justify", intent: "obfuscated-payload" },
  "pkg-remote-code": { category: "remote-code", tier: "block", intent: "obfuscated-payload" },
  "pkg-remote-code-browser": { category: "remote-code", tier: "notify", intent: "obfuscated-payload" },
  "pkg-typosquat": { category: "typosquat", tier: "justify", intent: "typosquat-install" },
  "pkg-known-malicious": { category: "typosquat", tier: "block", intent: "typosquat-install" },
  "pkg-ecosystem-confusion": { category: "typosquat", tier: "notify", intent: "typosquat-install" }
};

const CODE_EXT = /\.(m?js|cjs|jsx|m?ts|cts|tsx|py|sh|bash|ps1)$/i;
const MAX_BYTES = 2 * 1024 * 1024;
const LIFECYCLE = ["preinstall", "install", "postinstall"];

// Spawn / egress are matched on CALL or IMPORT forms, never on a bare word, and on code with full-line
// comments and docstrings removed — a comment that says "fetch" or a docstring that lists
// `subprocess.run` is not a capability. Loopback-only sockets (free-port probes, test harnesses) are not
// egress; a socket wired to a shell is its own heuristic (pkg-socket-shell).
const RE = {
  // Remote at install time means the script itself fetches or pipes something in. Inline code
  // (`node -e`, `python -c`) is only remote when it fetches: a chmod one-liner is a local install step.
  lifecycleRemote: /\b(curl|wget|Invoke-WebRequest|iwr)\b|https?:\/\/|\|\s*(ba|z)?sh\b|\b(?:node\s+-e|python\d?\s+-c)\b[^\n]{0,400}?\b(?:fetch|https?\.(?:get|request)|urlopen|requests\.|http\.client|net\.connect)\b/i,
  lifecycleNodeFile: /^\s*node\s+([\w./-]+\.(?:c|m)?js)\b/,
  spawn: /\b(?:require|import)\s*\(\s*["'`](?:node:)?child_process["'`]\s*\)|\bfrom\s+["'`](?:node:)?child_process["'`]|\bBun\.spawn(?:Sync)?\s*\(|\bnew\s+Deno\.Command\s*\(|\bsubprocess\.(?:Popen|run|call|check_output|check_call)\s*\(|\bos\.(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?)\s*\(|\bpty\.spawn\s*\(|\basyncio\.create_subprocess_(?:exec|shell)\s*\(/,
  egress: /\bfetch\s*\(|\bhttps?\.(?:request|get)\s*\(|\baxios(?:\.\w+)?\s*\(|\b(?:require|import)\s*\(\s*["'`](?:axios|undici|node-fetch|got)["'`]\s*\)|\bfrom\s+["'`](?:axios|undici|node-fetch|got)["'`]|\bnew\s+WebSocket\s*\(|\bnew\s+XMLHttpRequest\s*\(|\brequests\.(?:post|get|put|patch|request)\s*\(|\burlopen\s*\(|\bhttpx\.(?:post|get|put|patch|request|AsyncClient|Client)\s*\(|\baiohttp\.ClientSession\s*\(|\bhttp\.client\.HTTPS?Connection\s*\(/,
  credPath: /\.ssh[/\\'"`]|\.aws[/\\'"`]|\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials\b|\bid_(rsa|ed25519|ecdsa)\b|\.kube[/\\]config\b|\.docker[/\\]config\.json\b/,
  envDump: /JSON\.stringify\(\s*process\.env\s*[,)]|Object\.(entries|keys|values)\(\s*process\.env\s*\)[^;\n]{0,60}(join|stringify|map)|json\.dumps\(\s*(dict\(\s*)?os\.environ\b|str\(\s*os\.environ\s*\)/,
  decodeExec: /\b(eval|Function|exec|compile|runInThisContext|runInNewContext)\s*\([^;\n]{0,80}?\b(atob|b64decode|Buffer\.from|fromhex|decompress|unhexlify)\s*\(/,
  blob: /["'`][A-Za-z0-9+/]{200,}={0,2}["'`]|["'`](?:[0-9a-fA-F]{2}){100,}["'`]|(?:\\x[0-9a-fA-F]{2}){60,}/,
  sourceMap: /sourceMappingURL=data:[^\s]*/g,
  remote: /\beval\s*\(\s*(await\s+)?\(?\s*(await\s+)?(fetch|axios|got|https?\.get)\b|\brequire\s*\(\s*['"`]https?:|\.then\(\s*eval\s*\)|\bnew\s+Function\s*\([^;\n]{0,40}?\b(fetch|axios)\s*\(|\bexec\s*\([^;\n]{0,60}?\b(urlopen|requests\.get|httpx\.get)\s*\(/,
  remoteImport: /\bimport\s*\(\s*['"`]https?:/,
  pipeToShell: /\b(curl|wget)\b[^|\n]{0,200}\|\s*(ba|z)?sh\b|\b(irm|iwr|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]{0,200}\|\s*iex\b/i,
  execCall: /\b(?:exec|execSync|execFile|execFileSync|execa|spawn|spawnSync|system|popen|Popen|run|call|check_output|check_call|create_subprocess_shell)\s*\(/,
  shellQuietLine: /^\s*(#|echo\b|printf\b|:\s)|["'][^"'\n]{0,200}\b(curl|wget)\b/,
  pmLiteral: /["'`](?:npm|pnpm|yarn|bun|pip3?|uv|pipx|brew)(?:\.cmd|\.exe)?["'`]/,
  installVerb: /["'`](?:install|upgrade)["'`]/,
  globalInstallArgv: /["'`](?:i|add|update|install|upgrade)["'`]\s*,\s*["'`](?:-g|--global|-U|--upgrade)["'`]/,
  installCmdCall: /\b(?:exec|execSync|spawn|spawnSync|system|run|Popen|check_call|check_output)\s*\(\s*[fr]?["'`](?:npm|pnpm|yarn|pip3?|pipx|uv\s+(?:tool|pip)|brew)\s+(?:install|i|add|upgrade)\b/,
  pySocketShell: /\bos\.dup2\s*\(/,
  pyShell: /\bpty\.spawn\s*\(|["'`]\/bin\/(?:ba|z)?sh["'`]/,
  sockConnect: /\.connect\s*\(|\bnet\.(?:connect|createConnection)\s*\(|\bnew\s+net\.Socket\s*\(/,
  jsShellPipe: /\bspawn\s*\(\s*["'`](?:\/bin\/)?(?:ba|z)?sh["'`]|\bspawn\s*\(\s*["'`]cmd(?:\.exe)?["'`]/,
  cmdclass: /\bcmdclass\s*=/
};

const BROWSER_ASSET = /(^|\/)(assets|static|public|www)\/|\.worker[-.][^/]*\.m?js$/i;
const SHELL_FILE = /\.(sh|bash|zsh)$/i;

// Full-line comments, block comments and Python docstrings → blank, keeping line structure. Bounded.
export function stripComments(code, name) {
  let t = code;
  if (/\.py$/i.test(name)) t = t.replace(/("""|\'\'\')[\s\S]{0,20000}?\1/g, (m) => m.replace(/[^\n]/g, " "));
  else if (!SHELL_FILE.test(name)) t = t.replace(/\/\*[\s\S]{0,20000}?\*\//g, (m) => m.replace(/[^\n]/g, " "));
  return t.replace(/^[ \t]*(?:\/\/|#(?!!)).*$/gm, "");
}

// A `curl … | sh` that actually runs: in a shell file, a line that is not a comment/echo and where the
// command is not inside a quoted string; elsewhere, only on a line that also calls an exec-style API.
// Everywhere else it is an install HINT printed for the user.
function pipeToShellExec(code, name) {
  const shell = SHELL_FILE.test(name);
  const re = new RegExp(RE.pipeToShell.source, "gi");
  let m;
  while ((m = re.exec(code))) {
    const start = code.lastIndexOf("\n", m.index) + 1;
    const end = code.indexOf("\n", m.index);
    const line = code.slice(start, end < 0 ? code.length : end);
    if (shell ? !RE.shellQuietLine.test(line) : RE.execCall.test(line)) return m[0];
  }
  return null;
}

function finding(id, relativePath, span) {
  const h = HEURISTICS[id];
  return {
    relativePath,
    surfaceKind: null,
    threatId: id,
    category: h.category,
    intentLabels: [h.intent],
    contentHash: contentHash(span || id),
    tier: h.tier
  };
}

// Test code and fixtures are not run when a package is installed or used, and a security tool's tests
// are full of attack samples; block-level evidence there is reported for review, not as a verdict.
const TEST_PATH = /(^|\/)(tests?|__tests__|spec|fixtures?|testdata)\/|(^|\/)test_[^/]+\.py$|_test\.py$|\.(test|spec)\.[cm]?[jt]sx?$/i;

// A block-level match that is only present in comments cannot execute. Keep it visible at review level.
function capped(f, why) {
  return f.tier === "block" ? { ...f, tier: "justify", intentLabels: [...f.intentLabels, why] } : f;
}

function readText(full) {
  try {
    if (statSync(full).size > MAX_BYTES) return null;
    const buf = readFileSync(full);
    if (buf.subarray(0, 8000).includes(0)) return null;
    return buf.toString("utf8");
  } catch { return null; }
}

// `node install.js` whose target downloads something: still an install script (REVIEW), but named for
// what it does. The target path is resolved inside the package root only.
function installTargetDownloads(script, root) {
  const m = RE.lifecycleNodeFile.exec(script);
  if (!m || !root) return false;
  const rel = safeRelPath(m[1]);
  if (!rel) return false;
  const t = readText(join(root, rel));
  return !!(t && RE.egress.test(stripComments(t, rel)));
}

function packageJsonFindings(text, rel, root) {
  let pj;
  try { pj = JSON.parse(text); } catch { return []; }
  const scripts = pj && typeof pj.scripts === "object" && pj.scripts ? pj.scripts : {};
  const out = [];
  for (const k of LIFECYCLE) {
    const s = scripts[k];
    if (typeof s !== "string" || !s.trim()) continue;
    const id = RE.lifecycleRemote.test(s) ? "pkg-install-script-remote" : installTargetDownloads(s, root) ? "pkg-install-script-download" : "pkg-install-script";
    out.push(finding(id, rel, s));
  }
  return out;
}

function codeFindings(text, rel, name) {
  const out = [];
  const code = text.replace(RE.sourceMap, "");
  const live = stripComments(code, name);
  const hit = (re, t = code) => { const m = re.exec(t); return m ? m[0] : null; };

  if (name === "setup.py") {
    const spawn = hit(RE.spawn);
    const cmd = hit(RE.cmdclass);
    if (cmd && spawn) out.push(finding("pkg-setup-cmdclass-exec", rel, spawn));
    else if (cmd) out.push(finding("pkg-setup-cmdclass", rel, cmd));
    else if (spawn) out.push(finding("pkg-setup-spawn", rel, spawn));
  }

  // Block-tier evidence is matched on the RAW code so a fake comment cannot hide it; only the
  // capability signals below (justify / notify) use the comment-stripped view.
  const remote = hit(RE.remote) || pipeToShellExec(code, name);
  const remoteLive = remote && (hit(RE.remote, live) || pipeToShellExec(live, name));
  if (remote) out.push(remoteLive ? finding("pkg-remote-code", rel, remote) : capped(finding("pkg-remote-code", rel, remote), "comment-only"));
  const remoteImport = hit(RE.remoteImport);
  if (remoteImport && !remote) out.push(finding(BROWSER_ASSET.test(rel) ? "pkg-remote-code-browser" : "pkg-remote-code", rel, remoteImport));

  const decode = hit(RE.decodeExec);
  if (decode) out.push(finding(RE.blob.test(code) ? "pkg-obfuscated-exec" : "pkg-decode-exec", rel, decode));

  if (hit(RE.sockConnect) && (hit(RE.pySocketShell) && hit(RE.pyShell) || hit(RE.jsShellPipe) && /\.pipe\s*\(/.test(code))) {
    out.push(finding("pkg-socket-shell", rel, hit(RE.sockConnect)));
  }

  const env = hit(RE.envDump);
  if (env && hit(RE.egress)) out.push(finding("pkg-env-dump-egress", rel, env));

  const egress = hit(RE.egress, live);
  if (egress) {
    const cred = hit(RE.credPath, live);
    if (cred) out.push(finding("pkg-credential-read-egress", rel, cred));
    const spawn = hit(RE.spawn, live);
    if (spawn && name !== "setup.py") {
      const install = hit(RE.installCmdCall, live) || hit(RE.globalInstallArgv, live) || (hit(RE.pmLiteral, live) && hit(RE.installVerb, live));
      out.push(install ? finding("pkg-runtime-install", rel, install) : finding("pkg-spawn-egress", rel, spawn));
    }
  }
  return out;
}

// files: absolute paths under root (already symlink-free, from scan-core's walk).
export function packageHeuristics(root, files) {
  const out = [];
  for (const full of files) {
    const rel = relative(root, full).split("\\").join("/");
    const name = basename(full);
    if (rel === "package.json") {
      const t = readText(full);
      if (t) out.push(...packageJsonFindings(t, rel, root));
      continue;
    }
    if (/\.pth$/i.test(name)) {
      const t = readText(full);
      if (t && /^\s*import\s/m.test(t)) out.push(finding("pkg-pth-autoexec", rel, name));
      continue;
    }
    if (!CODE_EXT.test(name) || /\.d\.[cm]?ts$/i.test(name)) continue;
    const t = readText(full);
    if (t) out.push(...codeFindings(t, rel, name).map((f) => (TEST_PATH.test(rel) ? capped(f, "test-code") : f)));
  }
  return out;
}

export function nameFindings(ref) {
  const v = classifyPackage(ref.name, ref.ecosystem);
  if (v === "malicious") return [finding("pkg-known-malicious", null, ref.name)];
  if (v === "typosquat") return [finding("pkg-typosquat", null, ref.name)];
  if (v === "confused") return [finding("pkg-ecosystem-confusion", null, ref.name)];
  return [];
}
