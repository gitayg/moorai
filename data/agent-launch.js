// #88 (AML.T0103 Deploy AI Agent): a shell command that starts another AI agent headless, installs an agent
// CLI, or schedules an agent run. Read structurally with data/shell-parse.js, the reader the egress rules
// and data/net-exec.js use, so an agent CLI counts only where the shell would run it: the command word of
// a segment (after env assignments and wrappers such as sudo, env, nohup, timeout, xargs), inside `sh -c` /
// `bash -c` / `pwsh -Command` / `cmd /c` / `eval`, a heredoc fed to a shell, or a command another program
// runs (ssh, tmux, screen, watch, setsid, systemd-run, at). A name in an argument (`git commit -m "claude
// -p"`, `echo`, `grep "codex exec"`) or in a heredoc written to a file is data, not a launch.
//
// Launch: each CLI's documented non-interactive form (AGENT_CLIS). `--help`, `-h`, `--version` and `-V`
// (and a lone `-v`) are not a launch. Install: a global npm / pnpm / yarn / bun install, a pip / pipx / uv
// install, a Homebrew or winget install of an agent CLI package, or a vendor install script fetched and run.
// Schedule: a cron, launchd, systemd, at or Windows scheduled-task command (data/persistence.js plus the
// forms below) whose text names an agent CLI.
//
// Bounded: the reader caps the command, the segment count and the nesting depth; every regex here is linear
// (test/agent-deploy-detectors.test.mjs). Browser-safe. Never throws: each export returns false on error.
import { splitShell, commandOf, SHELLS, PWSH, MAX_CMD, MAX_DEPTH } from "./shell-parse.js";
import { persistenceHit } from "./persistence.js";
import { fetchExecFacts } from "./net-exec.js";

// The reader's own cap (as data/net-exec.js): padding a command past a smaller one must not hide a launch.
const MAX = MAX_CMD;

// Each agent CLI's non-interactive form. flags: any one of them makes the run headless (`--flag=value`
// counts for a long flag). subs: a subcommand that runs one task and exits. need: flags required on top of
// the subcommand. Sources: the CLIs' own references (data/host-versions.json pins claude -p, copilot -p,
// cursor-agent -p and gemini -p); the rest from each vendor's CLI documentation.
export const AGENT_CLIS = Object.freeze({
  claude: { flags: ["-p", "--print"] },
  codex: { subs: ["exec", "e"], flags: ["-q", "--quiet"] },
  gemini: { flags: ["-p", "--prompt"] },
  qwen: { flags: ["-p", "--prompt"] },
  copilot: { flags: ["-p", "--prompt"] },
  "cursor-agent": { flags: ["-p", "--print"] },
  auggie: { flags: ["-p", "--print"] },
  aider: { flags: ["-m", "--message", "-f", "--message-file", "--yes", "--yes-always"] },
  opencode: { subs: ["run"] },
  goose: { subs: ["run"] },
  crush: { subs: ["run"] },
  droid: { subs: ["exec"] },
  amp: { flags: ["-x", "--execute"] },
  openhands: { flags: ["--headless"] },
  "kiro-cli": { subs: ["chat"], need: ["--no-interactive"] },
  q: { subs: ["chat"], need: ["--no-interactive"] }
});

// Registry packages that install (or, run through npx / uvx / pipx, start) an agent CLI → its command.
export const AGENT_PACKAGES = Object.freeze({
  "@anthropic-ai/claude-code": "claude", "@openai/codex": "codex", "@google/gemini-cli": "gemini",
  "@qwen-code/qwen-code": "qwen", "@github/copilot": "copilot", "opencode-ai": "opencode",
  "@charmland/crush": "crush", "@sourcegraph/amp": "amp", "@augmentcode/auggie": "auggie",
  droid: "droid", cline: "cline"
});
export const AGENT_PYPI = Object.freeze({ "aider-chat": "aider", "aider-install": "aider", "openhands-ai": "openhands", openhands: "openhands", "open-interpreter": "interpreter" });
// Homebrew formula / cask names (the last path component, so `sst/tap/opencode` is opencode).
export const AGENT_BREW = Object.freeze(["claude-code", "codex", "gemini-cli", "opencode", "block-goose-cli", "aider", "crush", "qwen-code", "copilot-cli", "droid", "kiro-cli"]);
export const AGENT_WINGET = Object.freeze(["anthropic.claudecode", "github.copilot"]);
export const AGENT_GO = Object.freeze(["github.com/charmbracelet/crush"]);
// Vendor install scripts, as host + path. `www.` is optional; the query string is ignored.
const INSTALLERS = [
  ["claude.ai", /^\/install\.(?:sh|ps1|cmd)$/], ["cursor.com", /^\/install$/], ["opencode.ai", /^\/install$/],
  ["github.com", /^\/block\/goose\/releases\/download\/[^/]{1,64}\/download_cli\.(?:sh|ps1)$/],
  ["app.factory.ai", /^\/cli(?:\/windows)?$/], ["aider.chat", /^\/install\.(?:sh|ps1)$/], ["ampcode.com", /^\/install\.sh$/],
  ["gh.io", /^\/copilot-install$/], ["cli.kiro.dev", /^\/install$/]
];

const HELP = new Set(["--help", "-h", "--version", "-V"]);
const FETCHERS = new Set(["curl", "wget", "wget2", "invoke-webrequest", "invoke-restmethod"]);
const PIPS = /^pip[0-9.]*$/;
const PYTHONS = /^(?:python[0-9.]*|py)$/;
const NPM_INSTALL = new Set(["install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add"]);
const GLOBAL = (t) => t === "-g" || t === "--global" || t === "--location=global";

const flagHit = (args, list) => args.some((t) => list.some((f) => t === f || (f.startsWith("--") && t.startsWith(f + "="))));
// The subcommand: a token equal to one of `subs` with only options (and one value after each) before it.
function subHit(args, subs) {
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (subs.includes(t)) return true;
    if (!t.startsWith("-") || t === "--") return false;
    if (!t.includes("=") && args[i + 1] != null && !args[i + 1].startsWith("-") && !subs.includes(args[i + 1])) i++;
  }
  return false;
}
// True when `args` run CLI `name` non-interactively.
export function headless(name, args) {
  const rule = AGENT_CLIS[name];
  if (!rule) return false;
  if (args.some((t) => HELP.has(t)) || (args.length === 1 && args[0] === "-v")) return false;
  if (rule.need && !flagHit(args, rule.need)) return false;
  if (rule.subs && subHit(args, rule.subs)) return true;
  return !!rule.flags && flagHit(args, rule.flags);
}

const npmName = (t) => { const s = String(t).toLowerCase(); const at = s.indexOf("@", 1); return at > 0 ? s.slice(0, at) : s; };
const pypiName = (t) => String(t).toLowerCase().replace(/_/g, "-").replace(/\[.*$/, "").replace(/[=<>!~;@ ].*$/, "");
const positional = (args) => args.filter((t) => !t.startsWith("-"));

// npx / bunx / npm exec / pnpm dlx / uvx / pipx run: the agent CLI and the arguments it gets, or null.
const RUNNER_VALUED = new Set(["-p", "--package", "--from", "--spec", "--with", "--python", "--call", "-c", "--index-url", "--pip-args"]);
function runnerTarget(args) {
  let pkgGiven = false;
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (t === "--") continue;
    if (t.startsWith("-")) {
      const eq = t.indexOf("=");
      const name = eq > 0 ? t.slice(0, eq) : t;
      if (name === "-p" || name === "--package" || name === "--from" || name === "--spec") pkgGiven = true;
      if (eq < 0 && RUNNER_VALUED.has(t)) i++;
      continue;
    }
    const rest = args.slice(i + 1).filter((x, k) => !(k === 0 && x === "--"));
    const bin = t.replace(/^.*[/\\]/, "").toLowerCase();
    if (pkgGiven && AGENT_CLIS[bin]) return { cli: bin, args: rest };
    const cli = AGENT_PACKAGES[npmName(t)] || AGENT_PYPI[pypiName(t)] || (AGENT_CLIS[bin] && !pkgGiven ? bin : null);
    return cli ? { cli, args: rest } : null;
  }
  return null;
}

// What one segment does: "launch", "install", or a command string it runs elsewhere ({ run, ps }).
function segmentAct(seg, cw, rest) {
  const b = cw.binary;
  if (AGENT_CLIS[b]) {
    // Start-Process claude -ArgumentList "-p","task": the argument list is one value.
    const ai = seg.ps ? rest.findIndex((t) => /^-(?:argumentlist|args)$/i.test(t)) : -1;
    const args = ai >= 0 && rest[ai + 1] != null ? [...rest.slice(0, ai), ...rest[ai + 1].split(/[,\s]+/).filter(Boolean)] : rest;
    return headless(b, args) ? "launch" : null;
  }
  const r0 = rest[0], r1 = rest[1];
  // Runners that start a package's binary.
  let run = null;
  if (b === "npx" || b === "bunx" || b === "pnpx" || b === "uvx" || b === "pipx" && r0 === "run") run = runnerTarget(b === "pipx" ? rest.slice(1) : rest);
  else if ((b === "npm" && (r0 === "exec" || r0 === "x")) || ((b === "pnpm" || b === "yarn") && (r0 === "dlx" || r0 === "exec")) || (b === "bun" && r0 === "x")) run = runnerTarget(rest.slice(1));
  else if (b === "uv" && r0 === "tool" && r1 === "run") run = runnerTarget(rest.slice(2));
  if (run) return headless(run.cli, run.args) ? "launch" : null;
  // Installs.
  let pkgs = null, map = null;
  if (b === "npm" || b === "cnpm") { if (NPM_INSTALL.has(r0) && rest.some(GLOBAL)) { pkgs = positional(rest.slice(1)).map(npmName); map = AGENT_PACKAGES; } }
  else if (b === "pnpm" || b === "bun") { if ((r0 === "add" || r0 === "install" || r0 === "i" || r0 === "a") && rest.some(GLOBAL)) { pkgs = positional(rest.slice(1)).map(npmName); map = AGENT_PACKAGES; } }
  else if (b === "yarn") { if (r0 === "global" && r1 === "add") { pkgs = positional(rest.slice(2)).map(npmName); map = AGENT_PACKAGES; } }
  else if (PIPS.test(b) || b === "pipx") { if (r0 === "install") { pkgs = positional(rest.slice(1)).map(pypiName); map = AGENT_PYPI; } }
  else if (PYTHONS.test(b)) { const mi = rest.indexOf("-m"); if (mi >= 0 && PIPS.test(rest[mi + 1] || "") && rest[mi + 2] === "install") { pkgs = positional(rest.slice(mi + 3)).map(pypiName); map = AGENT_PYPI; } }
  else if (b === "uv") { if ((r0 === "tool" || r0 === "pip") && r1 === "install") { pkgs = positional(rest.slice(2)).map(pypiName); map = AGENT_PYPI; } }
  else if (b === "brew") { if (r0 === "install" || r0 === "reinstall") return positional(rest.slice(1)).some((t) => AGENT_BREW.includes(t.toLowerCase().replace(/^.*\//, ""))) ? "install" : null; }
  else if (b === "winget") { if (r0 === "install" || r0 === "add") return rest.slice(1).some((t) => AGENT_WINGET.includes(t.toLowerCase())) ? "install" : null; }
  else if (b === "go") { if (r0 === "install") return positional(rest.slice(1)).some((t) => AGENT_GO.includes(t.toLowerCase().replace(/@.*$/, ""))) ? "install" : null; }
  if (pkgs) return pkgs.some((p) => Object.prototype.hasOwnProperty.call(map, p)) ? "install" : null;
  // Programs that run a command string of their own.
  const tail = (from, valued = new Set(), clusterValued = "") => {
    let i = from;
    while (i < rest.length && rest[i].startsWith("-") && rest[i] !== "--") {
      const t = rest[i];
      i += !t.includes("=") && (valued.has(t) || (clusterValued && !t.startsWith("--") && clusterValued.includes(t[t.length - 1]))) ? 2 : 1;
    }
    if (rest[i] === "--") i++;
    return rest.slice(i);
  };
  if (b === "ssh") { const t = tail(0, new Set(), "BbcDEeFIiJLlmOoPpQRSWw"); return t.length > 1 ? { run: t.slice(1).join(" ") } : null; }
  if (b === "tmux" && /^(?:new|new-session|new-window|neww|split-window|splitw|respawn-pane|respawnp)$/.test(r0 || "")) { const t = tail(1, new Set(["-s", "-n", "-c", "-t", "-x", "-y", "-e", "-F", "-l"])); return t.length ? { run: t.join(" ") } : null; }
  if (b === "screen") { const t = tail(0, new Set(), "SctTLp"); return t.length ? { run: t.join(" ") } : null; }
  if (b === "watch") { const t = tail(0, new Set(["-n", "--interval", "-q", "--equexit"])); return t.length ? { run: t.join(" ") } : null; }
  if (b === "setsid") { const t = tail(0); return t.length ? { run: t.join(" ") } : null; }
  if (b === "systemd-run") { const t = tail(0, new Set(["-p", "--property", "-u", "--unit", "-E", "--setenv", "--slice", "--description", "--on-calendar", "--on-active", "--on-boot", "--on-startup", "--on-unit-active", "--uid", "--gid", "--nice", "--working-directory", "-M", "--machine", "-H", "--host", "--timer-property"])); return t.length ? { run: t.join(" ") } : null; }
  if (b === "launchctl" && r0 === "submit") { const di = rest.indexOf("--"); return di >= 0 && rest[di + 1] ? { run: rest.slice(di + 1).join(" ") } : null; }
  return null;
}

function installerUrl(t) {
  const m = /^(?:https?:\/\/)?([^/?#\s]{1,253})(\/[^?#\s]{0,512})?/i.exec(t);
  if (!m) return false;
  const host = m[1].toLowerCase().replace(/^www\./, "").replace(/:\d+$/, "");
  const path = (m[2] || "/").replace(/\/+$/, "") || "/";
  return INSTALLERS.some(([h, p]) => h === host && p.test(path));
}
const runsStdin = (cw) => !!cw && (SHELLS.has(cw.binary) || PWSH.has(cw.binary) || cw.binary === "iex" || cw.binary === "invoke-expression");

// Segments of one reading, with the scripts a shell runs expanded in place.
function walk(cmd, ps, depth, out, budget) {
  if (depth > MAX_DEPTH || budget.n <= 0) return out;
  const segs = splitShell(String(cmd || "").slice(0, MAX), ps, 0, { segs: [], heredocs: [], nscope: 0 }).segs;
  for (let k = 0; k < segs.length && budget.n-- > 0; k++) {
    const seg = segs[k];
    const cw = commandOf(seg.tokens.map((t) => (/^(?:\.{1,2}[/\\])/.test(t) ? "_" + t : t)), seg.ps);
    const rest = cw ? seg.tokens.slice(cw.at + 1) : [];
    out.push({ seg, cw, rest, prev: segs[k - 1] });
    if (!cw) continue;
    const b = cw.binary;
    const prev = segs[k - 1];
    // A heredoc run as code: `bash <<EOF`, or `cat <<EOF | bash`.
    const body = seg.heredoc != null ? seg.heredoc : prev && prev.sep === "|" && prev.heredoc != null ? prev.heredoc : null;
    if (body != null && runsStdin(cw)) walk(body, PWSH.has(b) || b === "iex" || b === "invoke-expression", depth + 1, out, budget);
    // `echo "claude -p x" | at now`, or an at / batch heredoc.
    if ((b === "at" || b === "batch")) {
      if (body != null) walk(body, false, depth + 1, out, budget);
      else if (prev && prev.sep === "|") { const pc = commandOf(prev.tokens, prev.ps); if (pc && (pc.binary === "echo" || pc.binary === "printf")) walk(prev.tokens.slice(pc.at + 1).join(" "), false, depth + 1, out, budget); }
    }
    if (SHELLS.has(b)) { const ci = rest.findIndex((t) => /^-[a-z]*c[a-z]*$/.test(t)); if (ci >= 0 && rest[ci + 1] != null) walk(rest[ci + 1], false, depth + 1, out, budget); }
    else if (PWSH.has(b)) { const ci = rest.findIndex((t) => /^-c(?:ommand)?$/i.test(t)); if (ci >= 0) walk(rest.slice(ci + 1).join(" "), true, depth + 1, out, budget); }
    else if (b === "cmd") { const ci = rest.findIndex((t) => /^\/[ck]$/i.test(t)); if (ci >= 0) walk(rest.slice(ci + 1).join(" "), false, depth + 1, out, budget); }
    else if (b === "eval" || b === "iex" || b === "invoke-expression") { if (rest.length) walk(rest.join(" "), seg.ps || b !== "eval", depth + 1, out, budget); }
    else {
      const act = segmentAct(seg, cw, rest);
      if (act && typeof act === "object") walk(act.run, seg.ps, depth + 1, out, budget);
    }
  }
  return out;
}

const PS_HINT = /\b(?:irm|iwr|iex|Invoke-(?:WebRequest|RestMethod|Expression)|Start-Process|Register-ScheduledTask|New-ScheduledTaskAction)\b|\$env:/i;

// A launched or installed agent in the command. ps: the text is a PowerShell command (true), a POSIX one
// (false), or unknown (undefined: POSIX, and PowerShell as well when it carries PowerShell's cmdlets).
export function agentCommandHit(cmd, { ps } = {}) {
  try {
    const s = String(cmd || "");
    if (!s || s.length > MAX) return false;
    const readings = ps === true ? [true] : ps === false ? [false] : PS_HINT.test(s) ? [false, true] : [false];
    for (const r of readings) {
      const items = walk(s, r, 0, [], { n: 512 });
      const anyIex = items.some((x) => x.cw && (x.cw.binary === "iex" || x.cw.binary === "invoke-expression")) || /\[scriptblock\]::create/i.test(s);
      let fetchRun = null;
      for (let i = 0; i < items.length; i++) {
        const { seg, cw, rest } = items[i];
        if (!cw) continue;
        if (FETCHERS.has(cw.binary) && rest.some(installerUrl)) {
          // A vendor install script counts once it is run: piped into a shell or iex, fed by `bash <(curl …)`,
          // iex'd in the same command, or downloaded and then run (fetchExecFacts, #57's own reader).
          const next = items[i + 1];
          const prev = items[i - 1];
          if ((seg.sep === "|" && next && runsStdin(next.cw)) || (prev && prev.seg.sep === "(" && runsStdin(prev.cw)) || anyIex) return true;
          if (fetchRun === null) fetchRun = fetchExecFacts(s, { ps: r }).hit;
          if (fetchRun) return true;
          continue;
        }
        const act = segmentAct(seg, cw, rest);
        if (act === "launch" || act === "install") return true;
      }
    }
  } catch { return false; }
  return false;
}

// ---- scheduled runs ----
// An agent CLI named where a scheduler would run it: a word on its own, after whitespace, a quote, `=`
// (ExecStart=), `>` (a plist <string>), a path separator or an operator.
export const AGENT_WORD = /(?<![^\s"'=>/\\(;|&`])(?:claude(?:-code)?|codex|gemini(?:-cli)?|qwen(?:-code)?|copilot|cursor-agent|auggie|aider(?:-chat)?|opencode|goose|crush|droid|amp|openhands|kiro-cli|cline)(?:\.exe|\.cmd)?(?![^\s"'<;|&)`])/;
// Schedulers data/persistence.js does not cover.
const SCHEDULE_EXTRA = [
  /(?<![\w-])(?:Register-ScheduledTask|New-ScheduledTaskAction)(?![\w-])/i,
  /(?<![\w-])launchctl\s{1,8}submit\b/i,
  /(?<![\w-])systemctl\s{1,8}(?:--user\s{1,8})?(?:--now\s{1,8})?enable\b/i,
  /\|\s{0,8}(?:at|batch)(?![\w./-])/,
  /(?<![\w./-])at\s{1,8}(?:-[a-zA-Z]{1,4}\s{1,8}){0,3}(?:now|noon|midnight|teatime|tomorrow)\b/
];
const UNIT_PATH = /(?:\/etc\/systemd\/system|systemd\/user)\/[\w@.-]{1,80}\.(?:service|timer)\b/;
const WRITE_OP = />|(?<![\w-])(?:tee|cp|mv|install|ln)(?![\w-])/;

export function agentScheduleHit(text) {
  try {
    if (typeof text !== "string" || !text || text.length > MAX) return false;
    if (!AGENT_WORD.test(text)) return false;
    return persistenceHit(text) || SCHEDULE_EXTRA.some((r) => r.test(text)) || (UNIT_PATH.test(text) && WRITE_OP.test(text));
  } catch { return false; }
}

// A file a scheduler runs from: a launchd plist, a systemd unit or timer, a cron table.
const SCHEDULE_FILE = /(?:^|[/\\])Library[/\\]Launch(?:Agents|Daemons)[/\\][^/\\]{1,255}\.plist$|(?:^|\/)(?:etc\/systemd\/system|systemd\/user)\/[^/]{1,255}\.(?:service|timer)$|(?:^|\/)etc\/cron(?:tab$|\.[a-z]{1,16}\/[^/]{1,255}$)|(?:^|\/)var\/spool\/cron\/(?:crontabs\/)?[^/]{1,255}$/i;
export function agentScheduleFileHit(path, text) {
  try {
    if (typeof path !== "string" || !path || path.length > 4096 || typeof text !== "string" || !text || text.length > MAX) return false;
    return SCHEDULE_FILE.test(path.replace(/\\/g, "/")) && AGENT_WORD.test(text);
  } catch { return false; }
}

// A name a sentence of prose can mention (data/destructive-mention.js mentionOnly reads the turn around it).
export const AGENT_MENTION = /\b(?:claude|codex|gemini|qwen|copilot|cursor-agent|auggie|aider|opencode|goose|crush|droid|amp|openhands|kiro-cli|cline)\b/i;
// Cheap gate before the parse: some agent CLI, runner, package or installer host is named.
export const AGENT_HINT = /claude|codex|gemini|qwen|copilot|cursor|auggie|aider|opencode|goose|crush|droid|\bamp\b|openhands|kiro|cline|\bq\s+chat\b|interpreter|factory\.ai|gh\.io/i;
