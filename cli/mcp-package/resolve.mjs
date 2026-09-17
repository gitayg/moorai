// MCP server launch command → package reference. Pure and offline: parses config text only.
//
// Config shapes covered (every MCP client listed in data/skill-surface.js):
//   mcpServers {name:{command,args}}  — Claude Code/Desktop, Cursor, Cline, Windsurf, Amazon Q, Kiro, Continue
//   servers    {name:{command,args}}  — VS Code .vscode/mcp.json, and `mcp.servers` inside VS Code settings
//   context_servers {name:{command:{path,args}} | {command,args}} — Zed
//   mcp_servers — Codex (TOML [mcp_servers.x], or the same key in JSON)
//   arrays of {name?, command, args} — Continue's list form
// The keys are searched recursively, so `.claude.json` → projects.<dir>.mcpServers is found too.

import { parseGithubSpec } from "./github.mjs";

const SERVER_KEYS = new Set(["mcpServers", "servers", "context_servers", "mcp_servers", "mcpservers"]);
const MAX_DEPTH = 8;

export function splitCommand(s) {
  const out = [];
  const re = /"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(String(s)))) out.push(m[1] !== undefined ? m[1].replace(/\\(.)/g, "$1") : m[2] !== undefined ? m[2] : m[3]);
  return out;
}

function strArray(v) {
  return Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
}

function serverArgv(entry) {
  if (!entry || typeof entry !== "object") return null;
  let cmd = entry.command;
  let args = strArray(entry.args);
  if (cmd && typeof cmd === "object") { args = strArray(cmd.args); cmd = cmd.path; }
  if (typeof cmd !== "string" || !cmd.trim()) return null;
  const argv = entry.args === undefined && /\s/.test(cmd.trim()) ? splitCommand(cmd) : [cmd, ...args];
  return argv.length ? argv : null;
}

function collectServers(node, depth, out) {
  if (!node || typeof node !== "object" || depth > MAX_DEPTH) return;
  if (Array.isArray(node)) { for (const v of node) collectServers(v, depth + 1, out); return; }
  for (const [k, v] of Object.entries(node)) {
    if (SERVER_KEYS.has(k) && v && typeof v === "object") {
      const list = Array.isArray(v) ? v : Object.values(v);
      for (const entry of list) {
        const argv = serverArgv(entry);
        if (argv) out.push(argv);
      }
    } else if (v && typeof v === "object") {
      collectServers(v, depth + 1, out);
    }
  }
}

function tomlStrings(s) {
  const out = [];
  const re = /"((?:[^"\\]|\\.)*)"|'([^']*)'/g;
  let m;
  while ((m = re.exec(s))) out.push(m[1] !== undefined ? m[1].replace(/\\(.)/g, "$1") : m[2]);
  return out;
}

// Just enough TOML for Codex: [mcp_servers.<name>] tables with `command = "…"` and `args = [ … ]`.
export function parseCodexToml(text) {
  const out = [];
  let cur = null;
  const flush = () => { if (cur && cur.command) out.push({ command: cur.command, args: cur.args }); };
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith("[")) {
      flush();
      cur = /^\[\s*mcp_servers\.[^\].]+\s*\]$/.test(line) || /^\[\s*mcp_servers\."[^"]+"\s*\]$/.test(line) ? { command: null, args: [] } : null;
      continue;
    }
    if (!cur) continue;
    const m = /^(command|args)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    if (m[1] === "command") cur.command = tomlStrings(m[2])[0] || null;
    else {
      let buf = m[2];
      while (!buf.includes("]") && i + 1 < lines.length) buf += "\n" + lines[++i];
      cur.args = tomlStrings(buf.slice(0, buf.lastIndexOf("]") + 1));
    }
  }
  flush();
  return out;
}

const NPM_RUNNERS = {
  npx: { valueFlags: ["--registry", "--cache", "--userconfig", "-c", "--call"], pkgFlags: ["-p", "--package"] },
  bunx: { valueFlags: ["--registry"], pkgFlags: ["-p", "--package"] },
  "pnpm dlx": { valueFlags: ["--registry", "--reporter"], pkgFlags: ["--package"] },
  "yarn dlx": { valueFlags: [], pkgFlags: ["-p", "--package"] },
  "npm exec": { valueFlags: ["--registry", "-c", "--call", "-w", "--workspace"], pkgFlags: ["--package"] },
  "pnpx": { valueFlags: [], pkgFlags: ["--package"] }
};
const PY_VALUE_FLAGS = ["--python", "-p", "--with", "--with-requirements", "--with-editable", "--index-url", "-i", "--index",
  "--extra-index-url", "--default-index", "--find-links", "-f", "--constraints", "-c", "--overrides", "--directory",
  "--python-preference", "--cache-dir", "--config-file", "--pip-args", "--env-file", "--index-strategy", "--keyring-provider"];
const DOCKER_VALUE_FLAGS = new Set(["-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "--network", "--net", "-p",
  "--publish", "-w", "--workdir", "--entrypoint", "-u", "--user", "--platform", "--pull", "-l", "--label", "--cap-add",
  "--cap-drop", "-m", "--memory", "--cpus", "--add-host", "--dns", "-h", "--hostname", "--security-opt", "--tmpfs",
  "--ulimit", "--device", "--gpus", "--runtime", "--restart", "--log-driver", "--log-opt", "--ipc", "--pid", "--shm-size"]);

function base(cmd) {
  return String(cmd).replace(/\\/g, "/").split("/").pop().replace(/\.(exe|cmd|bat)$/i, "").toLowerCase();
}

function isPathLike(s) {
  return /^(\/|\.\.?[/\\]|~[/\\]|[a-zA-Z]:[/\\]|file:)/.test(String(s));
}

export function parseNpmSpec(spec) {
  const s = String(spec).trim();
  if (!s || isPathLike(s) || /^(git\+|git:|https?:|github:|gitlab:|bitbucket:|npm:)/i.test(s) || s.endsWith(".tgz")) return null;
  const at = s.lastIndexOf("@");
  const name = at > 0 ? s.slice(0, at) : s;
  const version = at > 0 ? s.slice(at + 1) || null : null;
  if (!/^(@[a-z0-9][\w.~-]*\/)?[a-z0-9][\w.~-]*$/i.test(name) || name.length > 214) return null;
  return { ecosystem: "npm", name, version };
}

export function parsePypiSpec(spec) {
  const s = String(spec).trim();
  if (!s || isPathLike(s) || /^(git\+|https?:)/i.test(s) || /\.(whl|tar\.gz|zip)$/i.test(s)) return null;
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(?:(==|@)\s*([A-Za-z0-9.!+_-]+)|[<>=!~].*)?$/.exec(s);
  if (!m) return null;
  return { ecosystem: "pypi", name: m[1], version: m[4] && m[4] !== "latest" ? m[4] : null };
}

function npmFromArgs(args, runner) {
  const { valueFlags, pkgFlags } = NPM_RUNNERS[runner];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") { i++; return args[i] ? parseNpmSpec(args[i]) : null; }
    const eq = a.indexOf("=");
    const flag = eq > 0 ? a.slice(0, eq) : a;
    if (pkgFlags.includes(flag)) return parseNpmSpec(eq > 0 ? a.slice(eq + 1) : args[i + 1] || "");
    if (a.startsWith("-")) { if (eq < 0 && valueFlags.includes(a)) i++; continue; }
    return parseNpmSpec(a);
  }
  return null;
}

function pypiFromArgs(args) {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const eq = a.indexOf("=");
    const flag = a.startsWith("-") && eq > 0 ? a.slice(0, eq) : a;
    if (flag === "--from" || flag === "--spec") return parsePypiSpec(eq > 0 ? a.slice(eq + 1) : args[i + 1] || "");
    if (a === "--") { i++; return args[i] ? parsePypiSpec(args[i]) : null; }
    if (a.startsWith("-")) { if (eq < 0 && PY_VALUE_FLAGS.includes(a)) i++; continue; }
    return parsePypiSpec(a);
  }
  return null;
}

function dockerImage(args) {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith("-")) { if (!a.includes("=") && DOCKER_VALUE_FLAGS.has(a)) i++; continue; }
    return a;
  }
  return null;
}

function firstNonFlag(args) {
  return args.find((a) => !a.startsWith("-")) || null;
}

// argv (command + args) → a package reference, or {ecosystem:"unknown"}.
export function resolveLaunch(argvIn) {
  let argv = argvIn.slice();
  const b0 = base(argv[0] || "");
  if (b0 === "cmd" && /^\/c$/i.test(argv[1] || "")) argv = argv.slice(2);
  else if ((b0 === "sh" || b0 === "bash" || b0 === "zsh") && argv[1] === "-c" && argv[2]) argv = splitCommand(argv[2]);
  if (!argv.length) return { ecosystem: "unknown" };
  const cmd = base(argv[0]);
  const rest = argv.slice(1);

  if (cmd === "npx" || cmd === "bunx" || cmd === "pnpx") return npmFromArgs(rest, cmd) || { ecosystem: "unknown", runner: cmd };
  if ((cmd === "pnpm" || cmd === "yarn") && rest[0] === "dlx") return npmFromArgs(rest.slice(1), `${cmd} dlx`) || { ecosystem: "unknown", runner: cmd };
  if (cmd === "npm" && (rest[0] === "exec" || rest[0] === "x")) return npmFromArgs(rest.slice(1), "npm exec") || { ecosystem: "unknown", runner: cmd };
  if (cmd === "bun" && rest[0] === "x") return npmFromArgs(rest.slice(1), "bunx") || { ecosystem: "unknown", runner: cmd };

  if (cmd === "uvx") return pypiFromArgs(rest) || { ecosystem: "unknown", runner: cmd };
  if (cmd === "uv" && rest[0] === "tool" && rest[1] === "run") return pypiFromArgs(rest.slice(2)) || { ecosystem: "unknown", runner: cmd };
  if (cmd === "pipx" && rest[0] === "run") return pypiFromArgs(rest.slice(1)) || { ecosystem: "unknown", runner: cmd };
  if (/^python(\d(\.\d+)?)?$/.test(cmd) || cmd === "py") {
    const mi = rest.indexOf("-m");
    if (mi >= 0 && rest[mi + 1]) {
      const mod = rest[mi + 1];
      if (/mcp/i.test(mod)) return { ecosystem: "pypi", name: mod.replace(/_/g, "-"), version: null, inferred: true };
      return { ecosystem: "unknown", runner: cmd };
    }
    const p = firstNonFlag(rest);
    return p ? { ecosystem: "local", path: p } : { ecosystem: "unknown", runner: cmd };
  }

  if (cmd === "docker" || cmd === "podman") {
    const ri = rest.indexOf("run");
    const img = ri >= 0 ? dockerImage(rest.slice(ri + 1)) : null;
    return img ? { ecosystem: "docker", name: img } : { ecosystem: "unknown", runner: cmd };
  }

  if (cmd === "node" || cmd === "deno" || cmd === "bun" || cmd === "tsx" || cmd === "ts-node") {
    const p = rest[0] === "run" ? firstNonFlag(rest.slice(1)) : firstNonFlag(rest);
    return p ? { ecosystem: "local", path: p } : { ecosystem: "unknown", runner: cmd };
  }
  if (cmd === "uv" && rest[0] === "run") {
    const di = rest.indexOf("--directory");
    return { ecosystem: "local", path: di >= 0 && rest[di + 1] ? rest[di + 1] : firstNonFlag(rest.slice(1)) || "." };
  }
  if (isPathLike(argv[0])) return { ecosystem: "local", path: argv[0] };
  return { ecosystem: "unknown", runner: cmd };
}

// config (parsed object, JSON text, or Codex TOML text) → [{ecosystem, name, version} | {ecosystem:"local", path} | …].
// Duplicates (same ecosystem+name+version or path) are collapsed.
export function resolveMcpPackages(config) {
  let obj = config;
  const argvs = [];
  if (typeof config === "string") {
    try { obj = JSON.parse(config); } catch { obj = null; }
    if (obj === null) {
      for (const s of parseCodexToml(config)) argvs.push([s.command, ...s.args]);
    }
  }
  if (obj) collectServers(obj, 0, argvs);
  const seen = new Set();
  const out = [];
  for (const argv of argvs) {
    const ref = resolveLaunch(argv);
    const key = [ref.ecosystem, ref.name, ref.version, ref.path, ref.runner].join("\0");
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(ref);
  }
  return out;
}

// "npm:@scope/pkg@1.2.3" / "pypi:mcp-server-fetch==1.0" / "github:owner/repo/skills/x@ref" → ref
// (the CLI's --package form).
export function parsePackageArg(arg) {
  const m = /^(npm|pypi|github):(.+)$/i.exec(String(arg || "").trim());
  if (!m) return null;
  const eco = m[1].toLowerCase();
  if (eco === "github") return parseGithubSpec(m[2]);
  return eco === "npm" ? parseNpmSpec(m[2]) : parsePypiSpec(m[2]);
}
