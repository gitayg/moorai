// Local AI inventory for the AIBOM (cli/moorai-aibom.mjs): which local model runtimes are RUNNING, on
// which ports, and whether each listens beyond loopback; which are INSTALLED; and, on Windows only,
// the Windows AI platform and the ODR agent connectors (cli/local-ai-windows.mjs). Content-free: runtime names, versions, ports,
// counts and booleans. Never a path, a model file name, an address beyond loopback/network, a
// command line or an environment value.
//
// This extends cli/aibom-runtime.mjs's RUNTIMES (ollama, lmstudio, llama.cpp, vllm — the table
// test/aibom-rust-parity.test.mjs pins to the desktop host's Rust mirror) without editing it: the
// first four rows below keep those runtime ids, names and ports, so a report made with this table is
// a superset of the old one for the same machine.
//
// A listener on a DEFAULT port counts on its own only where the port is distinctive (portAlone).
// Generic defaults (8080, 8000, 5001, 1337, 1234) need the process name too.
// Sources (defaults quoted from each project's own docs):
//   ollama      11434   docs.ollama.com/faq — "Ollama binds 127.0.0.1 port 11434 by default."
//   lmstudio    1234    lmstudio.ai/docs/app/api/endpoints/openai — base URL "http://localhost:1234/v1";
//                       lmstudio.ai/docs/cli/server-start — port: "If not provided, uses the last used
//                       port"; "llmster" is the headless daemon (lmstudio.ai/docs/developer/core/headless).
//   llama.cpp   8080    github.com/ggml-org/llama.cpp tools/server/README.md — --host default
//                       "127.0.0.1", --port default "8080". Binaries llama-server, llama-cli.
//   llamafile   8080    docs.mozilla.ai/llamafile/getting-started/quickstart — "http://localhost:8080/".
//                       A llamafile runs under its own file name (<model>.llamafile[.exe]); it is matched
//                       by the suffix and reported only as "llamafile" (the model name is never kept).
//   vllm        8000    docs.vllm.ai/en/latest/cli/serve.html — --port "Default: 8000" (no --host default
//                       documented). On macOS the console script runs as python, so the name probe misses it.
//   localai     8080    localai.io/docs/basics/getting_started — "http://localhost:8080"; CLI `local-ai`.
//   jan         1337    jan.ai/docs/desktop/api-server — "JAN API listening at http://127.0.0.1:1337".
//   gpt4all     4891    docs.gpt4all.io/gpt4all_api_server/home.html — "The server listens on port 4891
//                       by default", off until "Enable Local API Server" is checked; localhost only.
//   koboldcpp   5001    github.com/LostRuins/koboldcpp/wiki — "By default KoboldCpp uses port 5001".
//                       Release binaries are koboldcpp[-<platform>], matched by prefix.
//   foundry-local  —    learn.microsoft.com/azure/foundry-local/reference/reference-rest — "Foundry
//                       Local dynamically assigns a port each time the service starts", so no port rule.
//                       CLI `foundry`; the service process is Inference.Service.Agent
//                       (github.com/microsoft/Foundry-Local/issues/146 — an issue, not Learn docs).
//   docker-model-runner 12434  docs.docker.com/.../settings-reference — "Enable host-side TCP support",
//                       "Default | 12434". The listener is Docker's backend process, so the port alone counts.
//   winml-server 8080   devblogs.microsoft.com/foundry-on-windows (preview URL) — `WinMLServer.exe model.gguf
//                       ... --port 8080` (experimental, Windows ML 2.7.2021). Name required.
//   text-generation-webui  installed only: its server is `python server.py` (no distinctive process name)
//                       on Gradio's generic 7860 / API 5000 (README), so "running" cannot be told apart.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { probeSockets } from "./listen-sockets.mjs";
import { windowsAiPlatform, odrAgentConnectors } from "./local-ai-windows.mjs";

export const LOCAL_AI_RUNTIMES = [
  { runtime: "ollama", names: ["ollama", "ollama app"], ports: [11434], portAlone: true },
  { runtime: "lmstudio", names: ["lm studio", "lms", "llmster"], ports: [1234], portAlone: false },
  { runtime: "llama.cpp", names: ["llama-server"], ports: [8080], portAlone: false },
  { runtime: "vllm", names: ["vllm"], ports: [8000], portAlone: false },
  { runtime: "llamafile", names: ["llamafile"], suffixes: [".llamafile"], ports: [8080], portAlone: false },
  { runtime: "localai", names: ["local-ai"], ports: [8080], portAlone: false },
  { runtime: "jan", names: ["jan"], ports: [1337], portAlone: false },
  { runtime: "gpt4all", names: ["gpt4all"], ports: [4891], portAlone: true },
  { runtime: "koboldcpp", names: ["koboldcpp"], prefixes: ["koboldcpp"], ports: [5001], portAlone: false },
  { runtime: "foundry-local", names: ["inference.service.agent", "foundry"], ports: [], portAlone: false },
  { runtime: "docker-model-runner", names: [], ports: [12434], portAlone: true },
  { runtime: "winml-server", names: ["winmlserver"], ports: [8080], portAlone: false }
];

const matches = (r, name) => !!name && (r.names.includes(name)
  || (r.prefixes || []).some((p) => name.startsWith(p))
  || (r.suffixes || []).some((s) => name.endsWith(s)));

// → [{ runtime, running: true, ports, bind, listening, detectedBy }]. `bind` keeps the shape the
// console already validates (loopback | network | unknown); `listening` is the same fact with "none"
// for "running, no listening socket", and null when the socket probe could not run.
export function runningRuntimes({ listeners, processes } = {}, table = LOCAL_AI_RUNTIMES) {
  const L = Array.isArray(listeners) ? listeners : [], P = Array.isArray(processes) ? processes : [];
  const out = [];
  for (const r of table) {
    const byName = L.filter((l) => matches(r, l.proc));
    const byPort = r.portAlone ? L.filter((l) => r.ports.includes(l.port)) : [];
    const procSeen = P.some((n) => matches(r, n)) || byName.length > 0;
    if (!procSeen && !byPort.length) continue;
    const ls = [...byName, ...byPort];
    const ports = [...new Set(ls.map((l) => l.port))].sort((a, b) => a - b);
    const bind = !ls.length ? "unknown" : ls.some((l) => l.bind === "network") ? "network" : "loopback";
    const listening = !Array.isArray(listeners) ? null : !ls.length ? "none" : bind;
    out.push({ runtime: r.runtime, running: true, ports, bind, listening, detectedBy: [procSeen && "process", byPort.length && "port"].filter(Boolean) });
  }
  return out;
}

// Install locations. bins: names looked up on PATH and the usual bin dirs (no execution, existence
// only). apps: macOS .app bundles under /Applications and ~/Applications. files: fixed per-OS
// [path, class] pairs ("~" = home, "%LOCALAPPDATA%" = that variable); the Windows paths are the
// installers' per-user defaults and are NOT verified on a Windows machine. Each hit reports a CLASS (path | app | cli-plugin |
// install-dir), never the path.
export const LOCAL_AI_INSTALLS = [
  { runtime: "ollama", bins: ["ollama"], apps: ["Ollama.app"], files: { win32: [["%LOCALAPPDATA%/Programs/Ollama/ollama.exe", "app"]] } },
  { runtime: "lmstudio", bins: ["lms"], apps: ["LM Studio.app"], files: { all: [["~/.lmstudio/bin/lms", "path"], ["~/.lmstudio/bin/lms.exe", "path"]], win32: [["%LOCALAPPDATA%/Programs/LM Studio/LM Studio.exe", "app"]] } },
  { runtime: "llama.cpp", bins: ["llama-server", "llama-cli"] },
  { runtime: "llamafile", bins: ["llamafile"] },
  { runtime: "vllm", bins: ["vllm"] },
  { runtime: "localai", bins: ["local-ai"] },
  { runtime: "jan", apps: ["Jan.app"] },
  { runtime: "gpt4all", apps: ["gpt4all/bin/gpt4all.app"], files: { win32: [["~/gpt4all/bin/chat.exe", "app"]] } },
  { runtime: "koboldcpp", bins: ["koboldcpp"] },
  { runtime: "text-generation-webui", dirs: ["~/text-generation-webui/server.py"] },
  { runtime: "foundry-local", bins: ["foundry"] },
  { runtime: "docker-model-runner", plugins: ["~/.docker/cli-plugins/docker-model", "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-model", "/usr/libexec/docker/cli-plugins/docker-model", "/usr/local/lib/docker/cli-plugins/docker-model", "C:/Program Files/Docker/Docker/resources/cli-plugins/docker-model.exe", "~/.docker/cli-plugins/docker-model.exe"] },
  { runtime: "winml-server", bins: ["WinMLServer"], only: "win32" }
];

const VERSION_RE = /^[0-9][0-9A-Za-z.+-]{0,31}$/;
// CFBundleShortVersionString from an XML Info.plist; a binary plist (or anything else) → null.
export function plistVersion(txt) {
  const m = String(txt || "").match(/<key>CFBundleShortVersionString<\/key>\s*<string>([^<]*)<\/string>/);
  return m && VERSION_RE.test(m[1].trim()) ? m[1].trim() : null;
}

// → [{ runtime, via: [class], version }]
export function installedRuntimes({ platform = process.platform, env = process.env, home = homedir(), exists = existsSync, readFile = readFileSync } = {}, table = LOCAL_AI_INSTALLS) {
  const win = platform === "win32";
  const expand = (p) => p.replace(/^~(?=\/|$)/, home).replace(/%LOCALAPPDATA%/g, env.LOCALAPPDATA || join(home, "AppData", "Local"));
  const pathDirs = String(env.PATH || env.Path || "").split(win ? ";" : ":").filter(Boolean);
  const binDirs = [...new Set([...pathDirs, ...(win ? [] : ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", join(home, ".local", "bin"), join(home, "bin")])])];
  const appDirs = platform === "darwin" ? ["/Applications", join(home, "Applications")] : [];
  const has = (p) => { try { return exists(p); } catch { return false; } };
  const out = [];
  for (const r of table) {
    if (r.only && r.only !== platform) continue;
    const via = new Set();
    let version = null;
    for (const b of r.bins || []) for (const d of binDirs) if (has(join(d, win ? `${b}.exe` : b))) via.add("path");
    for (const a of r.apps || []) for (const d of appDirs) {
      const app = join(d, a);
      if (!has(app)) continue;
      via.add("app");
      if (!version) { try { version = plistVersion(readFile(join(app, "Contents", "Info.plist"), "utf8")); } catch { /* unreadable: no version */ } }
    }
    for (const [f, cls] of [...((r.files || {}).all || []), ...((r.files || {})[platform] || [])]) if (has(expand(f))) via.add(cls);
    for (const f of r.plugins || []) if (has(expand(f))) via.add("cli-plugin");
    for (const f of r.dirs || []) if (has(expand(f))) via.add("install-dir");
    if (via.size) out.push({ runtime: r.runtime, via: [...via].sort(), version });
  }
  return out;
}

export function runCmd(cmd, args, timeout = 5000) {
  try {
    return execFileSync(cmd, args, { encoding: "utf8", timeout, maxBuffer: 8 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"], windowsHide: true });
  } catch (e) {
    // lsof exits 1 when it has nothing to list but still printed what it had
    return typeof e?.stdout === "string" && e.stdout ? e.stdout : null;
  }
}

// The whole collector. Fail-open: any probe that cannot run leaves its part empty / null.
export function localAiInventory({ runner = runCmd, platform = process.platform, env = process.env, home = homedir(), exists = existsSync, readFile = readFileSync } = {}) {
  let sockets = { listeners: null, processes: null, source: "none" };
  try { sockets = probeSockets(runner, platform, readFile); } catch { /* fail-open */ }
  let installed = [];
  try { installed = installedRuntimes({ platform, env, home, exists, readFile }); } catch { /* fail-open */ }
  let windowsAi = null, agentConnectors = null;
  if (platform === "win32") {
    try { windowsAi = windowsAiPlatform(runner); } catch { windowsAi = null; }
    try { agentConnectors = odrAgentConnectors(runner); } catch { agentConnectors = null; }
  }
  return {
    runtimes: runningRuntimes(sockets),
    installed,
    windowsAi,
    agentConnectors,
    listeners: sockets.listeners,
    status: sockets.listeners == null && sockets.processes == null ? "unavailable" : "ok",
    socketSource: sockets.source
  };
}
