#!/usr/bin/env node
// MoorAI policy + an agent's workspace -> a Microsoft Execution Containers (MXC) launch request, the
// JSON `wxc-exec.exe` reads. Pure: no filesystem, no environment, no clock — every input is passed in,
// so the same input gives the same JSON on any OS (tests run it on macOS against Windows paths).
//
// The desktop host spawns agents (src-tauri/src/lib.rs term_open), so the launch-time copy of this
// logic lives in Rust (src-tauri/src/mxc.rs). The two are pinned to one output by the shared golden
// cases in test/fixtures/mxc/policy-cases.json, which BOTH `node --test` and `cargo test` replay.
// This module is the reference and the operator tool for building a policy by hand on a test box:
//
//   node cli/mxc-policy.mjs --agent claude --workspace C:\src\proj --command "\"C:\...\claude.exe\"" [--out policy.json]
//
// Contract: microsoft/mxc @ 7cd00d1, schemas/stable/mxc-config.schema.1.0.0.json (exact version "1.0.0";
// docs/schema.md "Schema Versioning"). Design notes: docs/CAPABILITY_SPEC.md "Windows: launching
// agents inside MXC (wxc-exec)".

import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { mxcEgress, mxcNetwork } from "./sandbox-policy.mjs";

export const MXC_SCHEMA_VERSION = "1.0.0";
export const DEFAULT_MODEL_PROXY_PORT = 8791; // model-proxy/server.mjs DEFAULTS.port
export const AGENT_TMP = "{HOME}\\.moorai\\agent-tmp";
// In BaseContainer, Node's main-module realpathSync lstat()s every ancestor of the script and gets
// `EPERM: lstat 'C:\'`, so every Node workload (the hook, Codex, Copilot) dies before it runs. Granting
// enumeration on the ancestors is not an option: listing C:\ cascades to the profile and its .ssh.
export const NODE_PRESERVE_SYMLINKS = ["--preserve-symlinks", "--preserve-symlinks-main"];

// Read-write state each agent needs to run. Without its own dir the agent cannot persist a session,
// its settings or its login. `.claude.json` is a FILE next to the profile root, granted on its own so
// the profile root itself stays ungranted (docs/schema.md: "Avoid ... granting broad profile roots").
export const AGENT_STATE = {
  claude: ["{HOME}\\.claude", "{HOME}\\.claude.json"],
  codex: ["{HOME}\\.codex"],
  copilot: ["{HOME}\\.copilot"]
};

// Read-only extras per agent beyond the directory holding its binary. Claude's native installer keeps
// versions under ~/.local/share/claude while ~/.local/bin holds the launcher.
export const AGENT_RO = {
  claude: ["{HOME}\\.local\\share\\claude"],
  codex: [],
  copilot: []
};

// MoorAI's hook runs INSIDE the container (it is a child of the agent). It writes the three
// user-scope state legs of cli/state-dirs.mjs (STATE_DIR, LATCH_DIR, BREADCRUMB_DIR); without them
// every hook call fails its ledger/pin/latch writes.
export const MOORAI_STATE = ["{HOME}\\.moorai", "{APPDATA}\\MoorAI", "{LOCALAPPDATA}\\MoorAI"];

// Toolchain the agent shells out to. Windows' own directories are readable by AppContainer tokens
// through their ALL APPLICATION PACKAGES ACEs, so they are not listed; these are the usual installs
// that need an explicit grant (tests/playground/playground-limitations.md: per-user installs lack it).
export const TOOLCHAIN_RO = [
  "{PROGRAMFILES}\\nodejs",
  "{PROGRAMFILES}\\Git",
  "{PROGRAMFILES}\\PowerShell\\7",
  "{HOME}\\.gitconfig",
  "{PROGRAMDATA}\\MoorAI"
];

// Path classes, most specific first. A denial is reported by class id, never by path. Classes with
// `deny: true` are the Windows mirror of the macOS Seatbelt deny-list (src-tauri/src/platform.rs):
// persistence and credential locations. Under MXC's deny-by-default they are already unreachable
// unless a grant covers them; they become explicit `deniedPaths` as described in buildMxcPolicy.
export const PATH_CLASSES = [
  // The desktop host's own launch state (MXC settings, run dirs, denial reports). Never granted: a
  // contained agent that could write it would choose the policy of its own next launch.
  { id: "moorai-host", risk: "High", deny: true, paths: ["{LOCALAPPDATA}\\MoorAI Host"] },
  { id: "startup-folder", risk: "High", deny: true, paths: ["{APPDATA}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "{PROGRAMDATA}\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"] },
  { id: "scheduled-tasks", risk: "High", deny: true, paths: ["{SYSTEMROOT}\\System32\\Tasks", "{SYSTEMROOT}\\Tasks"] },
  { id: "shell-profile", risk: "High", deny: true, paths: ["{HOME}\\Documents\\WindowsPowerShell", "{HOME}\\Documents\\PowerShell", "{HOME}\\.bashrc", "{HOME}\\.bash_profile", "{HOME}\\.profile"] },
  { id: "credential-store", risk: "High", deny: true, paths: ["{APPDATA}\\Microsoft\\Credentials", "{LOCALAPPDATA}\\Microsoft\\Credentials", "{APPDATA}\\Microsoft\\Protect", "{APPDATA}\\Microsoft\\Crypto", "{LOCALAPPDATA}\\Microsoft\\Vault", "{PROGRAMDATA}\\Microsoft\\Vault"] },
  { id: "ssh-keys", risk: "High", deny: true, paths: ["{HOME}\\.ssh"] },
  { id: "cloud-credentials", risk: "High", deny: true, paths: ["{HOME}\\.aws", "{HOME}\\.azure", "{HOME}\\.kube", "{HOME}\\.docker", "{APPDATA}\\gcloud", "{HOME}\\.config\\gcloud"] },
  { id: "package-credentials", risk: "High", deny: true, paths: ["{HOME}\\.npmrc", "{HOME}\\.pypirc", "{HOME}\\.netrc", "{HOME}\\_netrc", "{HOME}\\.git-credentials", "{HOME}\\.config\\gh", "{APPDATA}\\GitHub CLI"] },
  { id: "browser-profile", risk: "High", deny: true, paths: ["{LOCALAPPDATA}\\Google\\Chrome\\User Data", "{LOCALAPPDATA}\\Microsoft\\Edge\\User Data", "{LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\User Data", "{APPDATA}\\Mozilla\\Firefox\\Profiles"] },
  { id: "moorai-state", risk: "Medium", deny: false, paths: ["{HOME}\\.moorai", "{APPDATA}\\MoorAI", "{LOCALAPPDATA}\\MoorAI", "{PROGRAMDATA}\\MoorAI"] },
  { id: "agent-state", risk: "Low", deny: false, paths: ["{HOME}\\.claude", "{HOME}\\.claude.json", "{HOME}\\.codex", "{HOME}\\.copilot"] },
  { id: "workspace", risk: "Low", deny: false, paths: ["{WORKSPACE}"] },
  { id: "system", risk: "Medium", deny: false, paths: ["{SYSTEMROOT}", "{PROGRAMFILES}", "{PROGRAMFILES86}", "{PROGRAMDATA}"] },
  { id: "user-profile", risk: "Medium", deny: false, paths: ["{HOME}"] }
];

export const SUPPORTED_AGENTS = Object.keys(AGENT_STATE);

// ---- Windows path helpers (string-only, so they behave the same on every host OS) ----

export function winNorm(p) {
  let s = String(p ?? "").trim().replace(/\//g, "\\");
  const unc = s.startsWith("\\\\");
  s = s.replace(/\\{2,}/g, "\\");
  if (unc) s = "\\" + s;
  if (/^[A-Za-z]:$/.test(s)) s += "\\";
  if (s.length > 3 && s.endsWith("\\")) s = s.replace(/\\+$/, "");
  return s;
}
const key = (p) => winNorm(p).toLowerCase();
export function isAbsoluteWin(p) {
  const s = winNorm(p);
  return /^[A-Za-z]:\\/.test(s) || /^\\\\[^\\]+\\[^\\]+/.test(s);
}
export function isVolumeRoot(p) {
  const s = winNorm(p);
  return /^[A-Za-z]:\\$/.test(s) || /^\\\\[^\\]+\\[^\\]+$/.test(s);
}
// child equals parent or lies beneath it (case-insensitive, separator-aware)
export function isUnder(child, parent) {
  const c = key(child), p = key(parent);
  if (!c || !p) return false;
  if (c === p) return true;
  return c.startsWith(p.endsWith("\\") ? p : p + "\\");
}
export function winDirname(p) {
  const s = winNorm(p);
  const i = s.lastIndexOf("\\");
  if (i < 0) return "";
  const d = s.slice(0, i);
  return /^[A-Za-z]:$/.test(d) ? d + "\\" : d;
}

function envGet(env, name) {
  if (!env) return "";
  const k = Object.keys(env).find((x) => x.toLowerCase() === name.toLowerCase());
  return k ? String(env[k] ?? "") : "";
}

// Token values. APPDATA/LOCALAPPDATA fall back to the profile defaults exactly as cli/state-dirs.mjs
// does; a token with no absolute value drops every template that uses it.
export function tokens(env, workspace = "") {
  const home = winNorm(envGet(env, "USERPROFILE"));
  const abs = (v) => (isAbsoluteWin(v) ? winNorm(v) : "");
  const t = {
    HOME: abs(home),
    APPDATA: abs(envGet(env, "APPDATA")) || (isAbsoluteWin(home) ? home + "\\AppData\\Roaming" : ""),
    LOCALAPPDATA: abs(envGet(env, "LOCALAPPDATA")) || (isAbsoluteWin(home) ? home + "\\AppData\\Local" : ""),
    PROGRAMDATA: abs(envGet(env, "ProgramData")),
    PROGRAMFILES: abs(envGet(env, "ProgramFiles")),
    PROGRAMFILES86: abs(envGet(env, "ProgramFiles(x86)")),
    SYSTEMROOT: abs(envGet(env, "SystemRoot")),
    WORKSPACE: abs(workspace)
  };
  return t;
}
export function expand(template, t) {
  let missing = false;
  const out = template.replace(/\{([A-Z0-9]+)\}/g, (_, name) => {
    const v = t[name];
    if (!v) { missing = true; return ""; }
    return v;
  });
  return missing ? "" : winNorm(out);
}

// The host's NODE_OPTIONS with NODE_PRESERVE_SYMLINKS appended where missing; the host's own options are kept.
// ASCII whitespace only, so src-tauri/src/mxc.rs splits the same way.
export function nodeOptions(env) {
  const own = envGet(env, "NODE_OPTIONS").replace(/^[ \t\n\r\f\v]+|[ \t\n\r\f\v]+$/g, "");
  const have = new Set(own.split(/[ \t\n\r\f\v]+/));
  return [own, ...NODE_PRESERVE_SYMLINKS.filter((f) => !have.has(f))].filter(Boolean).join(" ");
}

// Which class a path belongs to. First match in PATH_CLASSES order; "other" when none.
export function classifyPath(path, t) {
  if (!isAbsoluteWin(path)) return "other";
  for (const c of PATH_CLASSES) {
    for (const tpl of c.paths) {
      const p = expand(tpl, t);
      if (p && isUnder(path, p)) return c.id;
    }
  }
  return "other";
}

const CIDR4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;
const CIDR6 = /^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*\/(\d{1,3})$/;
export function isNumericCidr(s) {
  const v = String(s ?? "").trim();
  const m4 = v.match(CIDR4);
  if (m4) return m4.slice(1, 5).every((o) => Number(o) <= 255) && Number(m4[5]) <= 32;
  const m6 = v.match(CIDR6);
  return !!m6 && Number(m6[1]) <= 128;
}

function dedupe(list) {
  const seen = new Set(), out = [];
  for (const p of list) {
    if (!p) continue;
    const k = key(p);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(p);
  }
  return out;
}

const fail = (reasonCode, reason) => ({ ok: false, reasonCode, reason });

// input: { agent, workspace, env, agentBin, nodeDir, hookRoots[], modelProxyPort, egressAllow[],
//          egressRules, egressDefault, extraCaCerts, commandLine, denialsOutputPath, captureDenials,
//          fsDenySupported, hostAppDir }
// egressRules/egressDefault: MoorAI's rule set (cli/egress-rules.mjs), mapped by cli/sandbox-policy.mjs into
// numeric egress allow/deny rules; what MXC cannot express comes back as `egressUnexpressed`.
// hostAppDir: the desktop host's install directory. Nothing overlapping it is ever granted — a per-user
// install can sit at %LOCALAPPDATA%\MoorAI, the same directory as the hook's breadcrumb leg.
// exists(path) -> bool: the host's view of which paths exist (tests inject it).
// Returns { ok:true, policy, ensureDirs, egressUnexpressed? } or { ok:false, reasonCode, reason }.
export function buildMxcPolicy(input, { exists = () => true } = {}) {
  const i = input || {};
  const agent = String(i.agent || "");
  if (!SUPPORTED_AGENTS.includes(agent)) return fail("unsupported-agent", `agent must be one of ${SUPPORTED_AGENTS.join(", ")}`);
  const t = tokens(i.env, i.workspace);
  if (!t.HOME) return fail("no-profile", "USERPROFILE is not an absolute path");
  if (!String(i.workspace || "").trim()) return fail("workspace-unset", "no agent workspace is configured; MXC grants one project directory, never the whole profile");
  if (!t.WORKSPACE) return fail("workspace-not-absolute", "the agent workspace must be an absolute Windows path");
  const ws = t.WORKSPACE;
  if (isVolumeRoot(ws)) return fail("workspace-volume-root", "a volume root cannot be the workspace (BaseContainer grants on a root do not cascade; docs/schema.md)");
  if (isUnder(t.HOME, ws)) return fail("workspace-is-profile", "the workspace contains the user profile; pick a project directory");
  for (const sys of [t.SYSTEMROOT, t.PROGRAMFILES, t.PROGRAMFILES86, t.PROGRAMDATA]) {
    if (sys && isUnder(ws, sys)) return fail("workspace-in-system", "the workspace is inside a system directory");
  }
  for (const c of PATH_CLASSES.filter((x) => x.deny)) {
    for (const tpl of c.paths) {
      const p = expand(tpl, t);
      if (p && isUnder(ws, p)) return fail("workspace-in-protected", `the workspace is inside a protected location (${c.id})`);
    }
  }
  for (const c of PATH_CLASSES.filter((x) => x.deny)) {
    for (const tpl of c.paths) {
      const p = expand(tpl, t);
      if (p && isUnder(p, ws)) return fail("workspace-contains-protected", `the workspace contains a protected location (${c.id})`);
    }
  }
  const appDir = isAbsoluteWin(i.hostAppDir) ? winNorm(i.hostAppDir) : "";
  const touchesApp = (g) => !!appDir && (isUnder(g, appDir) || isUnder(appDir, g));
  if (touchesApp(ws)) return fail("workspace-overlaps-host-app", "the workspace overlaps the MoorAI desktop host's install directory");
  if (!exists(ws)) return fail("workspace-missing", "the workspace directory does not exist");
  const commandLine = String(i.commandLine || "").trim();
  if (!commandLine) return fail("no-command", "no agent command line");
  const port = i.modelProxyPort === undefined || i.modelProxyPort === null ? DEFAULT_MODEL_PROXY_PORT : Number(i.modelProxyPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return fail("bad-proxy-port", "modelProxyPort must be 1-65535");
  const egressAllow = (i.egressAllow || []).map((c) => String(c).trim()).filter(Boolean);
  const bad = egressAllow.find((c) => !isNumericCidr(c));
  if (bad !== undefined) return fail("egress-not-numeric", "egress allow entries must be numeric CIDRs; MXC rules cannot name hosts (networking.md, 1.1 Out of GA scope)");

  const agentTmp = expand(AGENT_TMP, t);
  const ensureDirs = dedupe([
    ...MOORAI_STATE.map((x) => expand(x, t)),
    agentTmp,
    expand(AGENT_STATE[agent][0], t)
  ]);
  const ensured = (p) => ensureDirs.some((d) => key(d) === key(p));
  const present = (p) => p && (ensured(p) || exists(p));

  const rw = dedupe([
    ws,
    ...AGENT_STATE[agent].map((x) => expand(x, t)),
    ...MOORAI_STATE.map((x) => expand(x, t))
  ]).filter((p) => p === ws || (present(p) && !touchesApp(p)));

  const caFiles = dedupe([i.extraCaCerts, envGet(i.env, "NODE_EXTRA_CA_CERTS"), envGet(i.env, "SSL_CERT_FILE")]
    .map((p) => (isAbsoluteWin(p) ? winNorm(p) : "")));
  const agentBinDir = isAbsoluteWin(i.agentBin) ? winDirname(i.agentBin) : "";
  const roCandidates = dedupe([
    agentBinDir,
    ...AGENT_RO[agent].map((x) => expand(x, t)),
    isAbsoluteWin(i.nodeDir) ? winNorm(i.nodeDir) : "",
    ...TOOLCHAIN_RO.map((x) => expand(x, t)),
    ...(i.hookRoots || []).map((p) => (isAbsoluteWin(p) ? winNorm(p) : "")),
    ...caFiles
  ]);
  const denyClassPaths = PATH_CLASSES.filter((c) => c.deny).flatMap((c) => c.paths.map((x) => expand(x, t))).filter(Boolean);
  const inDenied = (p) => denyClassPaths.some((d) => isUnder(p, d));
  // A read-only root may never cover the profile, its parent, or a whole AppData tree: hook roots are
  // validated by the host, but this is the last line if a broad one slips through.
  const broad = [t.HOME, t.APPDATA, t.LOCALAPPDATA, winDirname(t.HOME)].filter(Boolean);
  const tooBroad = (p) => broad.some((b) => isUnder(b, p));
  const ro = roCandidates.filter((p) => present(p) && !isVolumeRoot(p) && !tooBroad(p) && !touchesApp(p) && !rw.some((g) => isUnder(p, g)) && !inDenied(p));

  // Explicit deniedPaths. Everything outside rw/ro is already denied (MXC is deny-by-default), so an
  // explicit entry only adds protection where a grant would otherwise cover a protected path. When
  // the host advertises native FS deny (wxc-exec --probe: probes.baseContainerSupportsDenyPaths) every
  // existing protected path is listed — the explicit mirror of the Seatbelt deny-list. Without it, an
  // explicit deny would push MXC to the DACL-mutating AppContainer tier that `allowDaclMutation:false`
  // refuses (docs/schema.md "Filesystem Policy"), so only the overlapping carve-outs are kept and the
  // host refuses MXC if any remain.
  const grants = [...rw, ...ro];
  const overlapping = (d) => grants.some((g) => isUnder(d, g));
  // The host's install dir is denied explicitly too (reads included: the agent has no use for it).
  const denied = dedupe([...denyClassPaths, appDir].filter((d) => d && exists(d) && (i.fsDenySupported === true || overlapping(d))));

  const env = [`TEMP=${agentTmp}`, `TMP=${agentTmp}`, `NODE_OPTIONS=${nodeOptions(i.env)}`];
  if (agent === "claude") {
    env.push(`ANTHROPIC_BASE_URL=http://127.0.0.1:${port}/anthropic`);
    env.push("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1");
    env.push("DISABLE_AUTOUPDATER=1");
  } else if (agent === "codex") {
    env.push(`OPENAI_BASE_URL=http://127.0.0.1:${port}/openai`);
  }
  // git refuses a repo whose owner differs from the caller, and a contained token never matches a repo
  // created while elevated (playground-limitations.md "git and files created by an elevated process").
  // safe.directory is honoured only from protected config; GIT_CONFIG_COUNT/KEY/VALUE is the command
  // scope, which git-config(1) counts as protected. Scoped to this one workspace, never "*".
  env.push("GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory", `GIT_CONFIG_VALUE_0=${ws.replace(/\\/g, "/")}`);
  // BaseContainer does not inherit the user's CurrentUser Root store (anthropics/sandbox-runtime PR #640).
  // NODE_EXTRA_CA_CERTS is additive to Node's bundled roots, so it is the one variable set for the
  // operator's extra roots; SSL_CERT_FILE replaces OpenSSL's bundle and is only passed through if the
  // user already exported it (granted read above).
  if (isAbsoluteWin(i.extraCaCerts)) env.push(`NODE_EXTRA_CA_CERTS=${winNorm(i.extraCaCerts)}`);

  // Direct mode with host loopback: the agent reaches moorai-model-proxy (a base-URL reverse proxy, not a
  // WinHTTP/CONNECT proxy, so it cannot be runtimeConfig.networkProxy) on 127.0.0.1. egress.default stays
  // "deny" whatever egressDefault says; egressRules only add numeric allows and denies (deny wins in MXC).
  const hasRules = (i.egressRules !== undefined && i.egressRules !== null) || (i.egressDefault !== undefined && i.egressDefault !== null);
  const egress = hasRules ? mxcEgress({ egressRules: i.egressRules, egressDefault: i.egressDefault }) : null;
  const network = mxcNetwork(egressAllow, egress);

  const processContainer = {
    leastPrivilege: false,
    // PowerShell 5.1 and 7 fail with STATUS_DLL_INIT_FAILED under the default UI limits (0x03FF) and
    // with Win32k disabled; isolation "desktop" is the documented relaxation
    // (tests/playground/playground-limitations.md "PowerShell in BaseContainer"). Everything else stays
    // at its most restrictive value.
    ui: { isolation: "desktop", desktopSystemControl: false, systemSettings: "none", ime: false }
  };
  if (i.captureDenials === true && String(i.denialsOutputPath || "").trim()) {
    processContainer.captureDenials = { mode: "block", outputPath: winNorm(i.denialsOutputPath) };
  }

  const policy = {
    version: MXC_SCHEMA_VERSION,
    containment: "processcontainer",
    process: { commandLine, cwd: ws, env, inheritDefaultEnv: true },
    filesystem: { readwritePaths: rw, readonlyPaths: ro, deniedPaths: denied },
    // Never let MXC rewrite host ACLs: refusing Tier 3 makes a host without BaseContainer fail the
    // launch instead of silently weakening it (docs/schema.md "Fallback Policy").
    fallback: { allowDaclMutation: false },
    network,
    ui: { disable: false, clipboard: "none", injection: false },
    processContainer
  };
  return { ok: true, policy, ensureDirs, ...(egress && egress.unexpressed.length ? { egressUnexpressed: egress.unexpressed } : {}) };
}

// ---- CLI ----
const HELP = `mxc-policy — build a Microsoft Execution Containers launch request for an agent

  node cli/mxc-policy.mjs --agent claude|codex|copilot --workspace <dir> --command <command line>
                          [--agent-bin <path>] [--node-dir <dir>] [--hook-root <dir>]...
                          [--proxy-port 8791] [--egress-allow <cidr>]... [--egress-rules <file.json>]
                          [--extra-ca <pem>]
                          [--denials <path>] [--fs-deny] [--out <file>]

Reads USERPROFILE/APPDATA/LOCALAPPDATA/ProgramData/ProgramFiles/SystemRoot from the environment.
Paths are checked on this machine: a grant or --fs-deny entry that does not exist is left out (wxc-exec
fails a missing deniedPath with 0x80070003), and the read-write state dirs are created, as the desktop
host does; one that exists but is not a plain directory refuses the build.
--egress-rules reads egressRules/egressDefault from a JSON object; rules MXC cannot express go to stderr.
Run with:  wxc-exec.exe --log-file <log> <file>
`;

function main(argv) {
  if (argv.includes("--help") || argv.includes("-h") || !argv.length) { process.stdout.write(HELP); return 0; }
  const o = { env: process.env, hookRoots: [], egressAllow: [], captureDenials: false };
  for (let k = 0; k < argv.length; k++) {
    const a = argv[k], v = () => argv[++k];
    if (a === "--agent") o.agent = v();
    else if (a === "--workspace") o.workspace = v();
    else if (a === "--command") o.commandLine = v();
    else if (a === "--agent-bin") o.agentBin = v();
    else if (a === "--node-dir") o.nodeDir = v();
    else if (a === "--hook-root") o.hookRoots.push(v());
    else if (a === "--proxy-port") o.modelProxyPort = Number(v());
    else if (a === "--egress-allow") o.egressAllow.push(v());
    else if (a === "--egress-rules") {
      const doc = JSON.parse(readFileSync(v(), "utf8"));
      o.egressRules = doc.egressRules;
      o.egressDefault = doc.egressDefault;
    }
    else if (a === "--extra-ca") o.extraCaCerts = v();
    else if (a === "--denials") { o.denialsOutputPath = v(); o.captureDenials = true; }
    else if (a === "--fs-deny") o.fsDenySupported = true;
    else if (a === "--out") o.out = v();
    else { process.stderr.write(`unknown argument ${a}\n`); return 2; }
  }
  const r = buildMxcPolicy(o, { exists: (p) => existsSync(p) });
  if (!r.ok) { process.stderr.write(`mxc-policy: ${r.reasonCode}: ${r.reason}\n`); return 1; }
  // src-tauri/src/mxc_launch.rs ensure_dir: each must be a plain directory before and after it is created.
  const plain = (d) => { try { const s = lstatSync(d); return s.isDirectory() && !s.isSymbolicLink(); } catch { return null; } };
  for (const d of r.ensureDirs) {
    if (plain(d) === false) { process.stderr.write(`mxc-policy: ${d} is not a plain directory; the contained agent can write there (remove it and rerun)\n`); return 1; }
    mkdirSync(d, { recursive: true });
    if (plain(d) !== true) { process.stderr.write(`mxc-policy: ${d} is not a plain directory after creating it\n`); return 1; }
  }
  const text = JSON.stringify(r.policy, null, 2) + "\n";
  for (const u of r.egressUnexpressed || []) process.stderr.write(`not expressed: ${JSON.stringify(u)}\n`);
  if (o.out) writeFileSync(o.out, text);
  else process.stdout.write(text);
  return 0;
}

const isMain = (() => { try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (isMain) process.exit(main(process.argv.slice(2)));
