// AI CLI started by an unexpected parent (AI_CLI_PARENT). An implant that "lives off the AI" (C2Agent)
// drives the victim's own coding CLIs (`claude -p`, `codex exec`, Gemini CLI, Copilot CLI) from a process
// it injected into: sihost.exe, RuntimeBroker.exe, a random exe under C:\Windows\. The agent then runs
// with the user's own credentials and the hook sees ordinary-looking calls. What gives it away is who
// started the agent.
//
// Once per agent session (cached per session_id) the hook walks its own process ancestry: past the shell
// the agent ran the hook command in (and, for Codex / Gemini / Copilot / Cursor / Droid, the adapter's node) to the
// agent process, then up from the agent through shells and interpreters to the first ancestor that is
// neither, and classifies that one by image name and path:
//   normal               a terminal or an IDE whose image path is an expected install location for it
//                        (inLocation), a multiplexer or sshd, launchd / systemd, an AI desktop app, another
//                        AI CLI, a CI runner in server mode, or a name on policy aiCliParents.allow
//   system-host          sihost, RuntimeBroker, svchost, dllhost, taskhostw, WmiPrvSE and other Windows
//                        system hosts; an explorer.exe outside C:\Windows or started by one of these
//   office               Word, Excel, Outlook, PowerPoint (Windows and macOS)
//   script-host          wscript, cscript, mshta, rundll32, regsvr32 (and kin), osascript
//   temp-or-system-path  an image in a temp directory (any name), or under C:\Windows with a name that is
//                        not a known Windows program (a terminal or IDE name off its location included)
//   unknown              none of the above; recorded for posture, not alerted
//
// Signed policy aiCliParents: { mode: "off"|"alert"|"block" (default "alert"), allow: [image names] }.
// "block" denies the session's PreToolUse calls (an unenrolled device is coached: alerts only).
// The alert carries the image BASENAME only, never a path or a command line (either can carry user data).
//
// WHERE THE WALK RUNS. macOS and Linux walk on the call itself (ps or /proc: 7.4 ms on a quiet Mac, 0.08 ms
// on Linux, once per session). Windows never walks on a call: a background PowerShell does
// (cli/ai-cli-parents-win-walk.mjs), and the call that finds its result classifies, caches and alerts.
// LIMIT (Windows): the calls of a session before that one are judged without the parent class, so "block"
// denies from the call that finds the result (normally the session's second or third), not from its first;
// a call with no session_id is not walked at all (its key would be its own shell's pid, new on every call).
//
// LIMIT: the per-session cache is in the user's own state directory, so a same-user process can pre-seed
// a session as "normal" before the agent's first call. The root-owned helper is where this moves to.
import { readFileSync, writeFileSync, renameSync, mkdirSync, readlinkSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { systemTool } from "./machine-dir.mjs";
import { splitPath, within, isWithin, looksWindows, foldsCase } from "./path-within.mjs";
import { windowsWalker, WALK_LIFE_MS } from "./ai-cli-parents-win-walk.mjs";

export const AI_CLI_PARENT = "AI_CLI_PARENT";
export const AI_CLI_PARENT_CATEGORY = "AI CLI started by an unexpected parent";
export const SUSPICIOUS_CLASSES = Object.freeze(["system-host", "office", "script-host", "temp-or-system-path"]);
export const MAX_ABOVE_AGENT = 6; // ancestors examined above the agent process
const MAX_TO_AGENT = 4;           // hook-command shell(s) and the adapter's node between the hook and the agent
export const CACHE_FILE = "ai-cli-parents.json";
const CACHE_CAP = 256;
const CACHE_TTL_MS = 14 * 24 * 3600 * 1000;
const MODES = new Set(["off", "alert", "block"]);

const set = (s) => new Set(s.split(/\s*,\s*/).filter(Boolean));
// Walked through, not classified: what the hook command, a user or a launcher wraps a program in.
// Interpreters are here so that sihost.exe → python → claude still reads as sihost.exe.
const TRANSPARENT = set("sh,bash,zsh,fish,dash,ksh,mksh,tcsh,csh,ash,nu,xonsh,elvish,cmd,powershell,pwsh,login,sudo,doas,su,env,nohup,timeout,script,nice,caffeinate,time,xargs,stdbuf,npm,npx,pnpm,pnpx,yarn,bunx,node,nodejs,bun,deno,python,python3,pythonw,py,ruby,perl,uv,uvx,pipx,wsl,winpty,winpty-agent,disclaimer,git-bash");
// What an agent runs its hook command in: skipped on the way from the hook up to the agent process.
const SHELLS = set("sh,bash,zsh,fish,dash,ksh,mksh,tcsh,csh,ash,nu,cmd,powershell,pwsh,env,winpty,git-bash");
const AGENTS = set("claude,codex,gemini,copilot,cursor-agent,droid,aider,opencode,goose,amp,qwen,crush");
// Terminals and IDEs are normal only at an expected install location (inLocation): a name alone is a claim
// any program can make.
const TERMINALS = set("terminal,iterm2,iterm,wezterm,wezterm-gui,alacritty,kitty,ghostty,warp,stable,hyper,tabby,konsole,gnome-terminal,gnome-terminal-server,gnome-terminal-,xterm,uxterm,urxvt,rxvt,st,foot,footclient,tilix,terminator,xfce4-terminal,mate-terminal,lxterminal,qterminal,terminology,guake,yakuake,rio,contour,windowsterminal,openconsole,conhost,conemu,conemu64,conemuc,conemuc64,mintty,cmder,termius,waveterm");
const IDES = set("code,code-insiders,code - insiders,codium,vscodium,cursor,windsurf,zed,zed-editor,idea,idea64,pycharm,pycharm64,webstorm,webstorm64,goland,goland64,clion,clion64,rider,rider64,phpstorm,phpstorm64,rubymine,rubymine64,datagrip,datagrip64,fleet,studio,studio64,xcode,nvim,vim,emacs,sublime_text,sublime text,devenv");
const NORMAL = set([
  // multiplexers, remote shells, user-service managers
  "tmux,tmux: server,screen,zellij,sshd,sshd-session,mosh-server,dropbear,launchd,systemd,init",
  // AI desktop apps
  "claude helper,chatgpt,conductor"
].join(","));
const IDE_HELPER = /^(code|cursor|windsurf|code - insiders|vscodium|claude) helper( \(.+\))?$/;
const CI = set("runner.worker,runner.listener,gitlab-runner,buildkite-agent,agent.worker,agent.listener,circleci-agent,tini,dumb-init,docker-init,containerd-shim,containerd-shim-runc-v2");
const SYSTEM_HOST = set("sihost,runtimebroker,svchost,dllhost,taskhostw,taskhost,taskhostex,wmiprvse,backgroundtaskhost,applicationframehost,shellexperiencehost,startmenuexperiencehost,textinputhost,searchhost,searchindexer,searchprotocolhost,spoolsv,lsass,winlogon,userinit,services,csrss,wininit,smss,fontdrvhost,ctfmon,audiodg,werfault");
const OFFICE = set("winword,excel,outlook,powerpnt,msaccess,mspub,onenote,visio,microsoft word,microsoft excel,microsoft outlook,microsoft powerpoint");
const SCRIPT_HOST = set("wscript,cscript,mshta,rundll32,regsvr32,msbuild,installutil,regasm,regsvcs,cmstp,hh,osascript");
// Programs that live under C:\Windows and are not, by themselves, suspicious as a parent. Terminal and IDE
// names are not here: under C:\Windows they are normal only where inLocation puts them (conhost, explorer).
const WINDOWS_KNOWN = new Set([...TRANSPARENT, ...NORMAL]);

// "C:\\Windows\\System32\\RuntimeBroker.exe" → "RuntimeBroker.exe"; "-zsh" → "zsh". Printable, capped.
export function imageBase(p) {
  const s = String(p || "").replace(/\0/g, "");
  const b = s.slice(Math.max(s.lastIndexOf("/"), s.lastIndexOf("\\")) + 1).replace(/^-/, "").replace(/ \(deleted\)$/, "");
  return b.replace(/[^\x20-\x7e]/g, "?").slice(0, 64);
}
const key = (image) => imageBase(image).toLowerCase().replace(/\.exe$/, "");
const winOr = (p, platform) => (looksWindows(p) ? "win32" : platform);

// Temp directories, by segments (cli/path-within.mjs): /tmp, /var/tmp, /dev/shm, the macOS per-user TMPDIR
// (/var/folders/<a>/<b>/T, also under /private); on Windows a drive path with a Temp or Tmp folder anywhere.
const TEMP_ROOTS = ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/dev/shm", "/var/folders/*/*/T", "/private/var/folders/*/*/T"];
export function isTempPath(p, platform = process.platform) {
  const plat = winOr(p, platform);
  if (plat === "win32") {
    const sp = splitPath(p, plat);
    return !!sp && /^[a-z]:$/.test(sp.head) && sp.keys.slice(0, -1).some((k) => k === "temp" || k === "tmp");
  }
  return TEMP_ROOTS.some((r) => isWithin(p, r, plat));
}
const underWindows = (p) => looksWindows(p) && isWithin(p, "*:/Windows", "win32");

// Expected install locations of a terminal or IDE (and of explorer.exe), by segments (cli/path-within.mjs,
// the same rule as cli/ai-install-locations.mjs): the image path must be absolute, have no "." or ".."
// segment, end in the image's own name, and sit where that product installs. A Windows-shaped path is judged
// with Windows rules; any other with the host's (macOS folds case, Linux does not).
const WIN_SYSTEM_DIRS = ["*:/Windows", "*:/Windows/System32"];
const WIN_STORE_APPS = ["*:/Program Files/WindowsApps"];
const WIN_PROGRAMS = ["*:/Program Files", "*:/Program Files (x86)", "*:/Users/*/AppData/Local/Programs"];
const MAC_APPS = ["/Applications", "/System/Applications", "/Users/*/Applications"];
const UNIX_DIRS = ["/usr/bin", "/usr/sbin", "/usr/share", "/usr/lib", "/usr/lib64", "/usr/libexec", "/usr/local/bin", "/usr/local/share", "/usr/local/lib",
  "/bin", "/sbin", "/opt", "/snap", "/var/lib/flatpak", "/nix/store", ...["/home/*", "/root", "/Users/*"].flatMap((h) => [`${h}/.local/bin`, `${h}/.local/share`])];
// Below an applications folder: <…/>X.app/Contents/<…/>MacOS/<image>.
const bundleTail = (t, platform) => new RegExp("^([^/]+/)*[^/]+\\.app/Contents/(.+/)?MacOS/[^/]+$", foldsCase(platform) ? "i" : "").test(t.join("/"));
export function inLocation(image, path, platform = process.platform) {
  const plat = winOr(path, platform);
  const sp = splitPath(path, plat);
  const k = key(image);
  if (!sp || !k || !sp.segs.length || key(sp.segs[sp.segs.length - 1]) !== k) return false;
  const any = (roots, ok = () => true) => roots.some((r) => { const t = within(path, r, plat); return !!t && ok(t); });
  if (plat === "win32") {
    if (k === "conhost" || k === "explorer") return any(WIN_SYSTEM_DIRS, (t) => t.length === 1);
    if (k === "windowsterminal" || k === "openconsole") return any(WIN_STORE_APPS);
    return any(WIN_PROGRAMS);
  }
  return any(MAC_APPS, (t) => bundleTail(t, plat)) || any(UNIX_DIRS);
}

// The class of one ancestor. "transparent" means walk past it; "agent" means another AI CLI (normal).
export function classifyImage(image, path = "", { allow = new Set(), serverMode = false, platform = process.platform } = {}) {
  const k = key(image || path);
  if (!k) return "unknown";
  if (allow.has(k)) return "normal";
  if (path && isTempPath(path, platform)) return "temp-or-system-path";
  if (SYSTEM_HOST.has(k)) return "system-host";
  if (OFFICE.has(k)) return "office";
  if (SCRIPT_HOST.has(k)) return "script-host";
  if (k === "explorer") return inLocation(image || path, path, platform) ? "normal" : path && looksWindows(path) ? "system-host" : "unknown";
  if (TRANSPARENT.has(k) || /^python[\d.]+$/.test(k)) return "transparent";
  if (AGENTS.has(k)) return "agent";
  if ((TERMINALS.has(k) || IDES.has(k) || IDE_HELPER.test(k)) && inLocation(image || path, path, platform)) return "normal";
  if (NORMAL.has(k)) return "normal";
  if (serverMode && CI.has(k)) return "normal";
  if (path && underWindows(path) && !WINDOWS_KNOWN.has(k)) return "temp-or-system-path";
  return "unknown";
}

export function parentPolicy(policy) {
  const p = policy && typeof policy === "object" && policy.aiCliParents && typeof policy.aiCliParents === "object" ? policy.aiCliParents : {};
  const mode = MODES.has(p.mode) ? p.mode : "alert";
  const allow = new Set((Array.isArray(p.allow) ? p.allow : []).filter((s) => typeof s === "string" && s && s.length <= 256).slice(0, 256).map((s) => key(s)));
  return { mode, allow };
}

// chain: [{ pid, ppid, image, path, created? }] starting at the hook's parent. → { parentImage, parentClass,
// chainDepth, agentImage } where parentClass is one of SUSPICIOUS_CLASSES, "normal", "unknown" or
// "unreadable" (the agent process could not be found). chainDepth counts from the agent (1 = its parent).
export function assessChain(chain, { shim = false, allow = new Set(), serverMode = false, platform = process.platform } = {}) {
  const c = Array.isArray(chain) ? chain : [];
  let i = 0;
  const skipShells = () => { while (i < c.length && i < MAX_TO_AGENT && SHELLS.has(key(c[i].image))) i++; };
  skipShells();
  if (shim && i < c.length && /^(node|nodejs)$/.test(key(c[i].image))) { i++; skipShells(); }
  if (i >= c.length) return { parentImage: "", parentClass: "unreadable", chainDepth: 0, agentImage: "" };
  const agent = c[i];
  for (let d = 1; d <= MAX_ABOVE_AGENT; d++) {
    const cur = c[i + d - 1];
    const p = c[i + d];
    const rootReached = !cur || cur.pid === 1 || cur.ppid === 0;
    if (!p) return { parentImage: "", parentClass: rootReached ? "normal" : "unknown", chainDepth: d, agentImage: imageBase(agent.image) };
    let cls = classifyImage(p.image, p.path, { allow, serverMode, platform });
    if (cls === "transparent") { if (p.pid === 1) return { parentImage: imageBase(p.image), parentClass: "normal", chainDepth: d, agentImage: imageBase(agent.image) }; continue; }
    // explorer.exe started by a system host (or other suspicious parent) is that parent's child, not the shell's.
    if (cls === "normal" && key(p.image) === "explorer" && !allow.has("explorer")) {
      const pp = c[i + d + 1];
      if (pp && SUSPICIOUS_CLASSES.includes(classifyImage(pp.image, pp.path, { allow, serverMode, platform })) && key(pp.image) !== "userinit" && key(pp.image) !== "winlogon") cls = "system-host";
    }
    if (cls === "agent") cls = "normal";
    return { parentImage: imageBase(p.image), parentClass: cls, chainDepth: d, agentImage: imageBase(agent.image) };
  }
  return { parentImage: "", parentClass: "unknown", chainDepth: MAX_ABOVE_AGENT, agentImage: imageBase(agent.image) };
}

// ---- process-table readers: (startPid, maxLen) → chain, never throws ([] when unreadable) ----
const PS = ["/bin/ps", "/usr/bin/ps"].find((p) => { try { return existsSync(p); } catch { return false; } }) || "/bin/ps";
export function readChainPs(startPid, maxLen, run = (args) => execFileSync(PS, args, { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"] })) {
  const out = [];
  let pid = startPid;
  try {
    for (let n = 0; n < maxLen && pid > 0; n++) {
      const line = String(run(["-o", "ppid=,comm=", "-p", String(pid)])).split("\n").find((l) => l.trim());
      const m = line && /^\s*(\d+)\s+(.+?)\s*$/.exec(line);
      if (!m) break;
      const comm = m[2];
      out.push({ pid, ppid: Number(m[1]), image: imageBase(comm), path: comm.includes("/") ? comm : "" });
      pid = Number(m[1]);
    }
  } catch { /* what was read stands */ }
  return out;
}
export function readChainProc(startPid, maxLen, fs = { readFileSync, readlinkSync }) {
  const out = [];
  let pid = startPid;
  try {
    for (let n = 0; n < maxLen && pid > 0; n++) {
      let stat;
      try { stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8"); } catch { break; }
      const close = stat.lastIndexOf(")");
      const comm = stat.slice(stat.indexOf("(") + 1, close);
      const ppid = Number(stat.slice(close + 2).split(" ")[1]);
      let path = "";
      try { path = fs.readlinkSync(`/proc/${pid}/exe`).replace(/ \(deleted\)$/, ""); } catch { /* another user's process */ }
      out.push({ pid, ppid, image: path ? imageBase(path) : imageBase(comm), path });
      pid = ppid;
    }
  } catch { /* what was read stands */ }
  return out;
}
// Windows: ONE PowerShell process walks the chain with filtered CIM queries (the whole Win32_Process table
// is not needed). A parent created after its child is a reused pid: the chain ends there.
export function winChainScript(startPid, maxLen) {
  return [
    "$ErrorActionPreference='SilentlyContinue'",
    `$p=${Number(startPid) | 0}`,
    `for($i=0;$i -lt ${Number(maxLen) | 0};$i++){`,
    "$x=Get-CimInstance -ClassName Win32_Process -Filter \"ProcessId=$p\" -Property ProcessId,ParentProcessId,Name,ExecutablePath,CreationDate",
    "if(-not $x){break}",
    "$t=0; if($x.CreationDate){$t=$x.CreationDate.ToFileTimeUtc()}",
    "[Console]::Out.WriteLine(('{0}|{1}|{2}|{3}|{4}' -f $x.ProcessId,$x.ParentProcessId,$x.Name,$x.ExecutablePath,$t))",
    "if($x.ParentProcessId -le 4){break}",
    "$p=$x.ParentProcessId}"
  ].join("\n");
}
export function parseWinChain(text) {
  const out = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    const f = line.split("|");
    if (f.length < 5 || !/^\d+$/.test(f[0]) || !/^\d+$/.test(f[1])) continue;
    const created = Number(f[f.length - 1]) || 0;
    const path = f.slice(3, f.length - 1).join("|");
    const prev = out[out.length - 1];
    if (prev && (Number(f[0]) !== prev.ppid || (created && prev.created && created > prev.created))) break;
    out.push({ pid: Number(f[0]), ppid: Number(f[1]), image: imageBase(f[2] || path), path, created });
  }
  return out;
}
export function readChainWindows(startPid, maxLen, run = (script) => execFileSync(systemTool("WindowsPowerShell\\v1.0\\powershell.exe"), ["-NoProfile", "-NonInteractive", "-NoLogo", "-Command", script], { encoding: "utf8", timeout: 8000, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] })) {
  try { return parseWinChain(run(winChainScript(startPid, maxLen))); } catch { return []; }
}
export function defaultReadChain(platform = process.platform) {
  if (platform === "win32") return readChainWindows;
  if (platform === "linux" && existsSync("/proc/self/stat")) return readChainProc;
  return readChainPs;
}

// ---- the per-session cache (user-writable: see LIMIT above) ----
const sessionKey = (sessionId, fallback) => createHash("sha256").update(sessionId ? `s:${sessionId}` : `p:${fallback}`).digest("hex").slice(0, 24);
function readCache(dir) {
  try { const o = JSON.parse(readFileSync(join(dir, CACHE_FILE), "utf8")); if (o && typeof o === "object" && o.sessions && typeof o.sessions === "object") return o; } catch { /* absent or unreadable */ }
  return { v: 1, sessions: {} };
}
function writeCache(dir, cache, now) {
  try {
    const keep = Object.entries(cache.sessions).filter(([, e]) => e && now - (e.t || 0) < CACHE_TTL_MS).sort((a, b) => (b[1].t || 0) - (a[1].t || 0)).slice(0, CACHE_CAP);
    cache.sessions = Object.fromEntries(keep);
    mkdirSync(dir, { recursive: true });
    const p = join(dir, CACHE_FILE), tmp = `${p}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(cache), { mode: 0o600 });
    renameSync(tmp, p);
  } catch { /* the next session call walks again */ }
}
// For the posture heartbeat: the class of the most recently classified session's parent ("" when none).
export function lastParentClass(dir = STATE_DIR) {
  const l = readCache(dir).last;
  return l && typeof l.c === "string" ? l.c : "";
}

const CHAIN_LEN = MAX_TO_AGENT + MAX_ABOVE_AGENT + 2;
// The background walker (Windows), or null for a walk on the call. An injected readChain is a walk on the call.
const walkerFor = ({ walker, readChain, platform, stateDir }) => walker || (!readChain && platform === "win32" ? windowsWalker({ stateDir, maxLen: CHAIN_LEN }) : null);
const pending = (r, now) => !!r && typeof r.c !== "string" && now - (r.w || 0) >= 0 && now - (r.w || 0) < WALK_LIFE_MS;

// As early as the hook knows the session (before its policy load): when this session's background walk is
// running, leave this call's parent pid for it, so the walk can start while this call's shell is alive.
export function aiCliParentAsk({ sessionId = "", startPid = process.ppid, walker = null, readChain = null, platform = process.platform, stateDir = STATE_DIR, now = Date.now() } = {}) {
  try {
    const bg = walkerFor({ walker, readChain, platform, stateDir });
    if (!bg || !sessionId) return;
    const k = sessionKey(sessionId, startPid);
    if (pending(readCache(stateDir).sessions[k], now)) bg.ask(k, startPid);
  } catch { /* the step asks again */ }
}

// One hook invocation's step. → { alerts: [alert-without-ts/identity], deny: reason|null, result }
// result is null while a background walk (Windows) has not answered: nothing is alerted or denied yet.
export function aiCliParentStep({ policy, sessionId = "", agent = "", event = "PreToolUse", coach = false, serverMode = false, shim = false, startPid = process.ppid, readChain = null, walker = null, platform = process.platform, stateDir = STATE_DIR, now = Date.now() } = {}) {
  const out = { alerts: [], deny: null, result: null };
  try {
    const { mode, allow } = parentPolicy(policy);
    if (mode === "off") return out;
    const bg = walkerFor({ walker, readChain, platform, stateDir });
    if (bg && !sessionId) return out;
    const cache = readCache(stateDir);
    const k = sessionKey(sessionId, startPid);
    let r = cache.sessions[k];
    if (!r || typeof r.c !== "string") {
      let chain;
      if (bg) {
        const text = bg.take(k);
        if (text === null) {
          if (pending(r, now)) bg.ask(k, startPid);
          else { cache.sessions[k] = { w: now, t: now }; writeCache(stateDir, cache, now); bg.start(k, startPid); }
          return out;
        }
        chain = parseWinChain(text);
      } else chain = (readChain || defaultReadChain(platform))(startPid, CHAIN_LEN);
      const a = assessChain(chain, { shim, allow, serverMode });
      r = { c: a.parentClass, i: a.parentImage, d: a.chainDepth, t: now };
      cache.sessions[k] = r;
      cache.last = { c: a.parentClass === "unreadable" ? "unknown" : a.parentClass, t: now };
      writeCache(stateDir, cache, now);
      if (SUSPICIOUS_CLASSES.includes(r.c)) {
        const blocked = mode === "block" && !coach;
        out.alerts.push({ threatId: 0, category: AI_CLI_PARENT_CATEGORY, riskLevel: blocked ? "Blocked" : "High", reasonCode: AI_CLI_PARENT, stage: "policy", decision: blocked ? "deny" : "notify", contentHash: `ai-cli-parent:${r.c}:${r.i.toLowerCase()}`, agentName: agent || "unknown", parentImage: r.i, parentClass: r.c, chainDepth: r.d });
      }
    }
    out.result = { parentClass: r.c, parentImage: r.i, chainDepth: r.d };
    // Re-judged against the current policy every call: a session classified earlier is blocked as soon as
    // the policy says block, and an image added to the allow-list later releases it.
    if (event === "PreToolUse" && mode === "block" && !coach && SUSPICIOUS_CLASSES.includes(r.c) && !allow.has(key(r.i))) {
      out.deny = `this agent session was started by an unexpected parent process (${r.c}); its tool calls are blocked by policy aiCliParents`;
    }
  } catch { /* a signal and a session gate, never a crash */ }
  return out;
}
