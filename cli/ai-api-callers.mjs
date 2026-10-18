// Which processes are talking to an AI provider API right now: AI_API_CALLER_UNKNOWN.
//
// An implant that "lives off the AI" calls a provider's API from its own process with a stolen key; no
// hook and no model proxy sees that call. What the device does see is the TCP connection: this module
// samples the established connections (cli/local-ai-inventory.mjs tcpTable, inside the inventory scan,
// never on the hook's decision path), matches each remote address against the addresses the known AI
// API hosts resolve to, and names the owning process by its image basename.
//
// ADDRESS MATCHING. AI_API_HOSTS are resolved at scan time (dns.lookup, all addresses, both families) and
// the result is cached in the state dir for CACHE_TTL_MS. Shared front ends make an address ambiguous:
// MEASURED 2026-10-13 from this repo's dev machine, generativelanguage.googleapis.com resolved to exactly
// the same 16 addresses as www.googleapis.com (Google's front end serves every googleapis.com API), so a
// connection there is as likely Drive, gcloud or Chrome sync as Gemini. DECISION: an address that also
// answers for a CONTROL host (a non-AI name on the same front end, CONTROL_HOSTS) or for two different
// providers is AMBIGUOUS. Ambiguous connections are counted (ambiguous) but never attributed, never put
// in the posture and never alerted on. In the same measurement api.openai.com and api.mistral.ai sat on
// Cloudflare addresses no control shared, and api.anthropic.com on Anthropic's own address (shared with
// claude.ai, the same provider), so those were attributable. The check runs on every resolution, so a
// provider that moves onto a shared address stops alerting instead of alerting on everything.
//
// KNOWN callers (known: true, never alerted): MoorAI's own pids (this scan's process and parent, and a node
// process listening on the model proxy's or moorai-serve's port), and a process named like an AI app, agent
// CLI, editor or browser (data/ai-catalog.json, KNOWN_AGENTS, BROWSERS, MOORAI_IMAGES; Electron helpers count
// as their app: "Claude Helper" → claude, "Google Chrome Helper (Renderer)" → google chrome) ONLY when its
// executable, as the OS reports it (macOS: codesign -d <pid>, which reads the kernel's path for the pid;
// Linux: /proc/<pid>/exe; Windows: Win32_Process.ExecutablePath), is inside that product's expected install
// location (cli/ai-install-locations.mjs PRODUCTS and appLocations, compared by path segments with
// cli/path-within.mjs). On macOS a product with a stable signing identity is also known when the running
// process satisfies that identity's code-signing requirement (signRequirement; checked only when the
// location does not match, once per pid per scan). A name with no executable path, or with one anywhere
// else, is unknown and reported: a name is a claim any program can make. A named process whose executable is
// a script host (on Linux a #! script runs under its interpreter and keeps the script's name) is judged by
// the program it runs, below. A script host (node, nodejs, bun,
// deno, python) is known ONLY by the program it runs: its argv, read with that runtime's own option grammar
// (cli/script-host-argv.mjs), must name one main script and load nothing else (no preload, import, loader,
// inline code, stdin, env or config file, inspector), and the script must resolve to the own bin entry of a
// known AI CLI package (AI_NPM: the npm names in data/host-versions.json plus EXTRA_NPM; PY_PACKAGES for
// python) inside a package manager's install location (cli/ai-install-locations.mjs lists them and why).
// Any other script, a package spec (deno run npm:…, bun x …) and anything unparseable stay unknown: an
// implant is as likely a script as an agent. An image named like a version ("2.1.295") is Claude Code's
// native install (~/.local/share/claude/versions/<version>, MEASURED on this repo's dev machine 2026-10-13:
// lsof names the process by that file) and is known only when its executable, as the kernel reports it, is
// that file, and on macOS the process also satisfies Anthropic's code-signing requirement. The command line
// is read LOCALLY for those pids only (ps -ww -o pid=,args= on macOS, /proc/<pid>/cmdline on Linux,
// Win32_Process.CommandLine through one PowerShell on Windows) and is never stored, posted or alerted on:
// the posture and the alert keep the image basename only.
// LIMITS (spoofing): the command line is the process's own claim, so a process started with a forged argv
// (exec -a, an argv[0] holding spaces on macOS, where ps joins arguments with spaces) or one that rewrites
// its own argv is classed by what it claims. NODE_OPTIONS, PYTHONPATH and a .pth file, a bunfig.toml preload
// in bun's working directory, and the contents of a user-writable install location are not read.
//
// ALERT: AI_API_CALLER_UNKNOWN (High) per unknown (image, provider), at most once per UTC day, unless the
// signed policy says aiApiCallers "off".
//
// STATED LIMIT: only the listed provider hosts are recognised. A C2 server of the attacker's own behind
// TLS, a provider reached through a relay, a corporate proxy or a VPN tunnel (the connection then goes to
// the proxy), and a provider address this resolver was not given (geo or round-robin DNS answering the
// implant differently) are NOT identified. Process attribution sees only processes this user may inspect
// on macOS and Linux.
import { lookup as dnsLookup } from "node:dns/promises";
import { readFileSync, writeFileSync, mkdirSync, renameSync, realpathSync, readlinkSync, existsSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { systemTool } from "./machine-dir.mjs";
import { mainProgram, winArgv } from "./script-host-argv.mjs";
import { npmEntry, pythonEntry, venvInterpreter, nativeClaudeExe, isVersionImage, appLocations, atAppLocation, signRequirement } from "./ai-install-locations.mjs";
import { splitPath } from "./path-within.mjs";

export const CALLER_REASON = "AI_API_CALLER_UNKNOWN";
export const CALLER_CATEGORY = "Unknown process calling an AI provider API";
export const CACHE_TTL_MS = 60 * 60 * 1000;
export const CACHE_FILE = "ai-api-hosts.json";

export const AI_API_HOSTS = Object.freeze([
  ["api.openai.com", "openai"],
  ["api.anthropic.com", "anthropic"],
  ["generativelanguage.googleapis.com", "google"],
  ["aiplatform.googleapis.com", "google"],
  ["api.mistral.ai", "mistral"],
  ["codestral.mistral.ai", "mistral"],
  ["api.groq.com", "other"],
  ["api.x.ai", "other"],
  ["api.deepseek.com", "other"],
  ["openrouter.ai", "other"],
  ["api.cohere.com", "other"],
  ["api.cohere.ai", "other"],
  ["api.perplexity.ai", "other"],
  ["api.together.xyz", "other"],
  ["api.fireworks.ai", "other"],
  ["router.huggingface.co", "other"]
]);
// Non-AI names served by the same front ends as hosts above (Google's googleapis.com front end;
// Cloudflare, which fronts the OpenAI, Mistral, Groq, xAI, OpenRouter, Perplexity and Together hosts).
export const CONTROL_HOSTS = Object.freeze(["www.googleapis.com", "storage.googleapis.com", "oauth2.googleapis.com", "www.cloudflare.com", "discord.com"]);

const SELF_DIR = dirname(fileURLToPath(import.meta.url));
export const KNOWN_AGENTS = Object.freeze(["claude", "codex", "gemini", "cursor", "cursor-agent", "copilot", "github-copilot", "droid", "aider", "opencode", "goose", "amp", "crush", "qwen", "kiro", "trae", "zed", "windsurf", "code", "code - insiders", "ollama", "lm studio", "lms", "llmster", "jan", "msty"]);
export const BROWSERS = Object.freeze(["google chrome", "chrome", "chromium", "firefox", "safari", "com.apple.webkit.networking", "msedge", "microsoft edge", "brave", "brave browser", "arc", "opera", "vivaldi", "dia", "comet", "chatgpt atlas", "iexplore"]);
export const MOORAI_IMAGES = Object.freeze(["moorai", "moorai-desktop"]);
export const MOORAI_PORTS = Object.freeze([8791, 8790]); // model-proxy/server.mjs, cli/moorai-serve.mjs DEFAULTS.port

// "Claude Helper (Renderer)" → "claude"; "python.exe" → "python"; "Codex (Service)" → "codex".
export function imageKey(image) {
  return String(image || "").toLowerCase().replace(/\.(exe|app)$/, "").replace(/\s+\([^)]*\)$/, "").replace(/\s+helper$/, "").trim();
}

let CATALOG = null;
// data/ai-catalog.json apps → [{ names: [image keys], mac: ["X.app"], win: ["Programs/X/X.exe"] }].
export function catalogApps() {
  if (CATALOG) return CATALOG;
  const out = [];
  try {
    const cat = JSON.parse(readFileSync(join(SELF_DIR, "..", "data", "ai-catalog.json"), "utf8"));
    for (const a of cat.apps || []) {
      const mac = (a.mac || []).map(String), win = (a.win || []).map(String);
      const names = [...new Set([...mac.map((m) => imageKey(m.split("/").pop())), ...win.map((w) => imageKey(w.split(/[\\/]/).pop()))])];
      out.push({ names, mac, win });
    }
  } catch { /* an unreadable catalog leaves the agent and browser lists */ }
  return (CATALOG = out);
}
export const catalogImages = () => new Set(catalogApps().flatMap((a) => a.names));
// The names that make a process a candidate: it is known only at its product's location (see the header).
export const KNOWN_NAMES = () => new Set([...catalogImages(), ...KNOWN_AGENTS, ...BROWSERS, ...MOORAI_IMAGES]);

// ---- script hosts: which program is node / bun / deno / python running? ----
// npm names checked with `npm view <name> name bin` on 2026-10-13. Several of these packages now ship a
// native binary (claude-code bin/claude.exe, opencode, amp), which runs under its own image; the list still
// covers older installs and the ones that stay JavaScript (gemini-cli bundle/gemini.js, copilot npm-loader.js,
// qwen-code cli-entry.js, codex bin/codex.js).
export const EXTRA_NPM = Object.freeze(["@qwen-code/qwen-code", "@charmland/crush", "opencode-ai", "@sourcegraph/amp", "@ampcode/cli"]);
export const PY_PACKAGES = Object.freeze([{ dist: "aider-chat", module: "aider", entry: "aider" }]); // pypi.org/pypi/aider-chat
let NPM = null;
export function aiNpmPackages() {
  if (NPM) return NPM;
  const s = new Set(EXTRA_NPM);
  try {
    const hv = JSON.parse(readFileSync(join(SELF_DIR, "..", "data", "host-versions.json"), "utf8"));
    for (const h of Object.values(hv.hosts || {})) if (h && typeof h.npm === "string" && h.npm) s.add(h.npm.toLowerCase());
  } catch { /* the extra list stands */ }
  return (NPM = [...s]);
}
const hostKind = (k) => (k === "node" || k === "nodejs" ? "node" : k === "bun" || k === "deno" ? k : /^python(\d+(\.\d+)*)?w?$/.test(k) || k === "py" ? "python" : "");
export { mainProgram, winArgv, isVersionImage };

const realpathOr = (p, realpath = realpathSync) => { try { return realpath(p); } catch { return p; } };
const absPath = (s, platform) => splitPath(s, platform) !== null; // cli/path-within.mjs: absolute, no "." or ".." segment
// The main script argv[i] names, resolved through symlinks, or null. macOS `ps` joins argv with spaces, so a
// path with a space arrives split: each join of argv[i..i+7] that is an absolute existing path is a reading,
// and only a single reading is taken (two, e.g. "/tmp/a" and a planted "/tmp/a /x/cli.js", is ambiguous).
// ps prints a newline in an argument as \012 and a backslash as itself (MEASURED, macOS 27), so a backslash
// in a joined path cannot be decoded and the reading is dropped.
function resolveArg(a, i, spaced, realpath, platform) {
  const max = spaced ? Math.min(a.length - i, 8) : 1, hits = [];
  for (let n = 1; n <= max; n++) {
    const c = a.slice(i, i + n).join(" ");
    if (!absPath(c, platform) || (spaced && c.includes("\\"))) continue;
    try { hits.push(realpath(c)); } catch { /* not this join */ }
  }
  return hits.length === 1 ? hits[0] : null;
}
// The known AI package a script host's argv runs, or null. entry: { argv: [..], spaced }.
// Known only when the runtime's own grammar finds one main script and nothing else that loads code
// (cli/script-host-argv.mjs), and that script resolves to a known package's own entry in an install
// location (cli/ai-install-locations.mjs). deno also needs --no-config: otherwise it reads a deno.json from
// the working directory, whose import map can replace any module. python -m needs -I or -P (otherwise the
// working directory is first on sys.path; MEASURED, python 3.14: a planted ./json_tool ran under -m json_tool
// and did not under -P or -I) and the interpreter of that tool's venv.
export function packageOf(entry, kind, { realpath = realpathSync, readFile = readFileSync, platform = process.platform, home = realpathOr(homedir()), npm = aiNpmPackages(), py = PY_PACKAGES } = {}) {
  const a = entry && Array.isArray(entry.argv) ? entry.argv.map(String) : [];
  const m = mainProgram(a, kind);
  if (entry && entry.spaced && a.slice(0, m.at ?? a.length).some((t) => t.includes("\\"))) return null;
  if (m.module !== undefined) {
    const mod = String(m.module).toLowerCase(), hit = py.find((p) => mod === p.module || mod.startsWith(`${p.module}.`));
    return kind === "python" && m.safePath && hit && venvInterpreter(a[0], hit.dist, { platform, home }) ? hit.dist : null;
  }
  if (m.script === undefined || (kind === "deno" && !m.noConfig)) return null;
  const p = resolveArg(a, m.at, !!(entry && entry.spaced), realpath, platform);
  if (!p) return null;
  if (kind === "python") return pythonEntry(p, { platform, home, py });
  return npmEntry(p, { platform, home, npm, readFile });
}
// Claude Code's native install: an image named like a version whose EXECUTABLE (as the kernel reports it, not
// argv[0]) is $HOME/.local/share/claude/versions/<that version>. That folder is the user's own, so on macOS
// the running process must also satisfy Anthropic's code-signing requirement (signed() → true); on Linux
// there is no signature to check and the location alone decides. Windows' native install runs as claude.exe.
// exe: { exe } from readExe; signed: () → boolean, asked only when the location matches on macOS.
export function nativeClaude(exe, image, { platform = process.platform, home = realpathOr(homedir()), signed = () => false } = {}) {
  if (!exe || !nativeClaudeExe(exe.exe, image, { platform, home })) return false;
  return platform === "darwin" ? signed() === true : platform === "linux";
}

// ---- reading a pid's command line and executable, locally (never stored or sent) ----
// Windows: ONE Win32_Process query per scan gives both. CommandLine and ExecutablePath go out base64
// (UTF-16LE), one "<pid>|<base64 cmd>|<base64 exe>" line per process, because a command line may itself hold
// a line break and a "<pid>|…" that would read as another process's line.
export function winArgvScript(pids) {
  const f = pids.map((p) => `ProcessId=${Number(p) | 0}`).join(" OR ");
  const b64 = (v) => `[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes([string]${v}))`;
  return ["$ErrorActionPreference='SilentlyContinue'",
    `Get-CimInstance -ClassName Win32_Process -Filter "${f}" -Property ProcessId,CommandLine,ExecutablePath | ForEach-Object { [Console]::Out.WriteLine(('{0}|{1}|{2}' -f $_.ProcessId,${b64("$_.CommandLine")},${b64("$_.ExecutablePath")})) }`].join("\n");
}
// "<pid>|<base64 CommandLine>[|<base64 ExecutablePath>]" lines → Map(pid → { argv, exe }). A pid seen twice
// or a line that is not base64 is left out; a command line winArgv cannot read one way (cli/script-host-argv.mjs)
// gives argv null, so that process stays unknown as a script host.
export function parseWinProcs(text) {
  const m = new Map(), dup = new Set();
  const dec = (b) => (b ? Buffer.from(b, "base64").toString("utf16le") : "");
  for (const line of String(text || "").split(/\r?\n/)) {
    const x = /^(\d+)\|([A-Za-z0-9+/]*={0,2})(?:\|([A-Za-z0-9+/]*={0,2}))?$/.exec(line);
    if (!x || (!x[2] && !x[3])) continue;
    if (m.has(x[1]) || dup.has(x[1])) { m.delete(x[1]); dup.add(x[1]); continue; }
    const argv = x[2] ? winArgv(dec(x[2])) : null;
    m.set(x[1], { argv: argv && argv.length ? argv : null, exe: dec(x[3]) });
  }
  return m;
}
// → Map(pid → { argv, spaced: false }) for the processes whose command line reads one way.
export function parseWinCommandLines(text) {
  return new Map([...parseWinProcs(text)].filter(([, e]) => e.argv).map(([p, e]) => [p, { argv: e.argv, spaced: false }]));
}
const MAX_WIN_PIDS = 128;
const powershell = (script) => execFileSync(systemTool("WindowsPowerShell\\v1.0\\powershell.exe"), ["-NoProfile", "-NonInteractive", "-NoLogo", "-Command", script], { encoding: "utf8", timeout: 8000, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
// One query per scan: scan.want (every pid the scan will ask about) is fetched the first time and kept.
function winProcs(ids, { run, scan } = {}) {
  if (scan && scan.win) return scan.win;
  const all = [...new Set([...(scan && Array.isArray(scan.want) ? scan.want : []), ...ids].map(String).filter((p) => /^\d+$/.test(p)))].slice(0, MAX_WIN_PIDS);
  let out = new Map();
  try { if (all.length) out = parseWinProcs((run || powershell)(winArgvScript(all))); } catch { /* unknown */ }
  if (scan) scan.win = out;
  return out;
}
// `ps -ww -o pid=,args=` lines → Map(pid → { argv, spaced: true }).
export function parsePsArgs(text) {
  const m = new Map();
  for (const line of String(text || "").split("\n")) { const x = /^\s*(\d+)\s+(.*\S)\s*$/.exec(line); if (x) m.set(x[1], { argv: x[2].split(/\s+/), spaced: true }); }
  return m;
}
const PS = ["/bin/ps", "/usr/bin/ps"].find((p) => { try { return existsSync(p); } catch { return false; } }) || "/bin/ps";
const MAX_ARGV_PIDS = 64;
// pids → Map(pid → { argv, spaced }). One spawn at most; never throws.
export function readArgv(pids, { platform = process.platform, run, readFile = readFileSync, scan } = {}) {
  const ids = [...new Set((pids || []).map(String).filter((p) => /^\d+$/.test(p)))].slice(0, MAX_ARGV_PIDS);
  if (!ids.length) return new Map();
  try {
    if (platform === "linux") {
      const m = new Map();
      for (const p of ids) { try { const a = readFile(`/proc/${p}/cmdline`, "utf8").split("\0"); while (a.length && a[a.length - 1] === "") a.pop(); if (a.length) m.set(p, { argv: a, spaced: false }); } catch { /* gone, or another user's */ } }
      return m;
    }
    if (platform === "win32") {
      const w = winProcs(ids, { run, scan }), m = new Map();
      for (const p of ids) { const e = w.get(p); if (e && e.argv) m.set(p, { argv: e.argv, spaced: false }); }
      return m;
    }
    // ps exits 1 when one of the pids is gone, after printing the rest.
    const r = run || ((args) => { try { return execFileSync(PS, args, { encoding: "utf8", timeout: 3000, maxBuffer: 4 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] }); } catch (e) { return typeof e?.stdout === "string" ? e.stdout : ""; } });
    return parsePsArgs(r(["-ww", "-o", "pid=,args=", "-p", ids.join(",")]));
  } catch { return new Map(); }
}

// The executable of each pid as the OS reports it → Map(pid → { exe }). macOS: `codesign -d <pid>` prints the
// kernel's path for the running pid as "Executable=" (MEASURED on this repo's dev Mac, 2026-10-13: 0.01 to 0.05 s
// per pid); a process codesign cannot read (gone, another user's, unsigned on Intel) gives none. Linux:
// /proc/<pid>/exe (a deleted file reads "… (deleted)" and so matches no location). Windows: ExecutablePath from
// the scan's one Win32_Process query. At most MAX_EXE_PIDS pids; the rest stay unknown.
export const MAX_EXE_PIDS = 64;
export function readExe(pids, { platform = process.platform, run, readlink, scan } = {}) {
  const ids = [...new Set((pids || []).map(String).filter((p) => /^\d+$/.test(p)))].slice(0, MAX_EXE_PIDS);
  const m = new Map();
  if (!ids.length) return m;
  if (platform === "win32") {
    const w = winProcs(ids, { run, scan });
    for (const p of ids) { const e = w.get(p); if (e && e.exe) m.set(p, { exe: e.exe }); }
    return m;
  }
  for (const p of ids) {
    try {
      if (platform === "linux") { m.set(p, { exe: (readlink || readlinkSync)(`/proc/${p}/exe`) }); continue; }
      if (platform !== "darwin") continue;
      const d = (run || codesign)(["-d", p]);
      const x = /^Executable=(.+)$/m.exec(String(d && d.stderr || ""));
      if (x) m.set(p, { exe: x[1] });
    } catch { /* gone, or not ours to inspect */ }
  }
  return m;
}
const codesign = (args) => spawnSync("/usr/bin/codesign", args, { encoding: "utf8", timeout: 5000, stdio: ["ignore", "ignore", "pipe"] });
// macOS: does the RUNNING pid satisfy a code-signing requirement? `codesign --verify -R=<req> <pid>` exits 0
// when it does (MEASURED on this repo's dev Mac, 2026-10-13: 0.24 to 0.53 s when it passes, 0.01 to 0.03 s
// when it fails, 3 for an Apple-signed shell against Anthropic's requirement).
// Claude Code's native versions are signed "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)", identifier
// com.anthropic.claude-code, hardened runtime.
export const CLAUDE_CODE_REQUIREMENT = 'anchor apple generic and identifier "com.anthropic.claude-code" and certificate leaf[subject.OU] = "Q6L2SF6YDW"';
export function codeSigned(pid, requirement, { run } = {}) {
  if (!/^\d+$/.test(String(pid)) || !requirement) return false;
  try { const v = (run || codesign)(["--verify", `-R=${requirement}`, String(pid)]); return !!v && v.status === 0; } catch { return false; }
}

const normIp = (a) => String(a || "").replace(/^\[|\]$/g, "").toLowerCase().replace(/^::ffff:(?=\d+\.)/, "");

// → { byIp: { ip: provider }, ambiguous: [ip], at }. lookup(host) → [{ address }] (dns.promises.lookup all).
export async function resolveAiHosts({ lookup = (h) => dnsLookup(h, { all: true }), now = Date.now(), stateDir = null, ttlMs = CACHE_TTL_MS, timeoutMs = 3000 } = {}) {
  const file = stateDir ? join(stateDir, CACHE_FILE) : null;
  if (file) {
    try {
      const c = JSON.parse(readFileSync(file, "utf8"));
      if (c && typeof c.at === "number" && now - c.at >= 0 && now - c.at < ttlMs && c.byIp && Array.isArray(c.ambiguous)) return c;
    } catch { /* no cache */ }
  }
  const res = async (h) => {
    let timer;
    try {
      const r = await Promise.race([lookup(h), new Promise((_, rej) => { timer = setTimeout(() => rej(new Error("timeout")), timeoutMs); })]);
      return (r || []).map((x) => normIp(x.address));
    } catch { return []; } finally { clearTimeout(timer); }
  };
  const [ai, ctl] = await Promise.all([Promise.all(AI_API_HOSTS.map(([h]) => res(h))), Promise.all(CONTROL_HOSTS.map(res))]);
  const providers = new Map(), ambiguous = new Set(ctl.flat());
  AI_API_HOSTS.forEach(([, p], i) => { for (const ip of ai[i]) { const s = providers.get(ip) || new Set(); s.add(p); providers.set(ip, s); } });
  const byIp = {};
  for (const [ip, ps] of providers) { if (ps.size > 1) ambiguous.add(ip); else if (!ambiguous.has(ip)) byIp[ip] = [...ps][0]; }
  const amb = [...ambiguous].filter((ip) => providers.has(ip)).sort();
  const out = { at: now, byIp, ambiguous: amb };
  if (file && (Object.keys(byIp).length || amb.length)) {
    try { mkdirSync(stateDir, { recursive: true }); const tmp = `${file}.${process.pid}.tmp`; writeFileSync(tmp, JSON.stringify(out), { mode: 0o600 }); renameSync(tmp, file); } catch { /* cache is an optimisation */ }
  }
  return out;
}

// pids that are MoorAI: this process, its parent, and a node process listening on a MoorAI port.
export function mooraiPids(sockets, { self = process.pid, parent = process.ppid, ports = MOORAI_PORTS } = {}) {
  const s = new Set([String(self), String(parent)]);
  for (const x of sockets || []) if (x.state === "listen" && ports.includes(x.lport) && imageKey(x.proc) === "node" && x.pid) s.add(String(x.pid));
  return s;
}

// sockets: tcpTable().sockets; resolved: resolveAiHosts(). → { callers: [{ processImage, provider, known, connections }], ambiguous }
// exeOf(pids, { scan }) → Map(pid → { exe }) is asked once, for named and version-named pids; argvOf(pids,
// { scan }) → Map(pid → { argv, spaced }) once, for script-host pids (and named pids whose executable is a
// script host); sigOf(pid, requirement) → boolean on macOS only, at most once per pid per scan, and only when
// the location did not already decide. On Windows one Win32_Process query (scan) answers exeOf and argvOf.
// Rows are per (image, provider, known): an unknown node script is never folded into a known node process.
export function aiApiCallers(sockets, resolved, { moorai = mooraiPids(sockets), argvOf = readArgv, exeOf = readExe, sigOf = codeSigned, realpath = realpathSync, readFile = readFileSync, platform = process.platform, home = realpathOr(homedir(), realpath), locations } = {}) {
  const byIp = (resolved && resolved.byIp) || {}, amb = new Set((resolved && resolved.ambiguous) || []);
  const names = KNOWN_NAMES(), groups = new Map(), hits = [];
  const locs = locations || appLocations(platform, home, { catalog: catalogApps() });
  let ambiguous = 0;
  for (const s of sockets || []) {
    if (s.state !== "established" || !s.rhost) continue;
    const ip = normIp(s.rhost);
    if (amb.has(ip)) { ambiguous++; continue; }
    const provider = byIp[ip];
    if (!provider) continue;
    const processImage = String(s.proc || "").slice(0, 64) || "unknown";
    const key = imageKey(processImage), pid = s.pid ? String(s.pid) : "";
    const self = !!(pid && moorai.has(pid)), named = !self && names.has(key);
    hits.push({ processImage, provider, pid, key, self, named, kind: self || named ? "" : hostKind(key), version: !self && !named && isVersionImage(processImage) });
  }
  const ids = (pick) => [...new Set(hits.filter((h) => h.pid && pick(h)).map((h) => h.pid))];
  const scan = { want: [...new Set([...ids((h) => h.kind), ...ids((h) => h.named || h.version)])] };
  const ask = (list, fn) => { if (!list.length) return new Map(); try { return fn(list, { scan }) || new Map(); } catch { return new Map(); } };
  const exe = ask(ids((h) => h.named || h.version), exeOf);
  const at = (h, x) => !!x && atAppLocation(h.key, x.exe, { platform, locations: locs });
  for (const h of hits) {
    const x = h.named && exe.get(h.pid), via = x ? hostKind(imageKey(baseName(x.exe))) : "";
    if (via && !at(h, x)) { h.kind = via; h.named = false; }
  }
  const argv = ask(ids((h) => h.kind), argvOf);
  const sig = new Map();
  const signed = (pid, req) => { const k = `${pid}|${req}`; if (!sig.has(k)) { let v = false; try { v = sigOf(pid, req) === true; } catch { /* unsigned */ } sig.set(k, v); } return sig.get(k); };
  const opts = { realpath, readFile, platform, home };
  for (const h of hits) {
    const e = argv.get(h.pid), x = exe.get(h.pid);
    let isKnown = false;
    if (h.self) isKnown = true;
    else if (h.kind) isKnown = !!e && !!packageOf(e, h.kind, opts);
    else if (h.named) {
      const req = platform === "darwin" && x ? signRequirement(h.key) : "";
      isKnown = at(h, x) || (!!req && signed(h.pid, req));
    } else if (h.version) isKnown = nativeClaude(x, h.processImage, { platform, home, signed: () => signed(h.pid, CLAUDE_CODE_REQUIREMENT) });
    const k = `${h.processImage}|${h.provider}|${isKnown}`;
    const g = groups.get(k) || { processImage: h.processImage, provider: h.provider, known: isKnown, connections: 0 };
    g.connections++;
    groups.set(k, g);
  }
  const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0); // code-point order: the same on every locale
  const callers = [...groups.values()].sort((a, b) => cmp(a.processImage, b.processImage) || cmp(a.provider, b.provider) || Number(a.known) - Number(b.known));
  return { callers, ambiguous };
}
const baseName = (p) => { const s = String(p || ""); return s.slice(Math.max(s.lastIndexOf("/"), s.lastIndexOf("\\")) + 1); };

export const callerPolicy = (policy) => (policy && policy.aiApiCallers === "off" ? "off" : "alert");
// Pure. prev: { day, seen: ["image|provider"] }. → { alerts, next }.
export function callerAlerts(callers, { policy = null, prev = null, ts = new Date().toISOString() } = {}) {
  const day = ts.slice(0, 10);
  const seen = new Set(prev && prev.day === day && Array.isArray(prev.seen) ? prev.seen : []);
  if (callerPolicy(policy) === "off") return { alerts: [], next: { day, seen: [...seen] } };
  const alerts = [];
  for (const c of callers || []) {
    if (c.known) continue;
    const k = `${c.processImage}|${c.provider}`;
    if (seen.has(k)) continue;
    seen.add(k);
    alerts.push({ threatId: 0, reasonCode: CALLER_REASON, category: CALLER_CATEGORY, riskLevel: "High", stage: "inventory", tool: "inventory:ai-api",
      ts, contentHash: `ai-api:${k}`, processImage: c.processImage, provider: c.provider, connections: c.connections });
  }
  return { alerts, next: { day, seen: [...seen].sort() } };
}

// Posture rows: the contract's { processImage, provider, known } (the connection count rides on alerts only).
export const callerPosture = (callers) => (callers || []).map(({ processImage, provider, known }) => ({ processImage, provider, known }));
