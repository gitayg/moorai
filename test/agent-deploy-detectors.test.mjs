// agent-deploy (#88, AML.T0103 Deploy AI Agent): a shell command that starts another AI agent headless,
// installs an agent CLI, or schedules an agent run (data/agent-launch.js, data/detectors-agent-deploy.js).
//
//   node --test --import ./test/hermetic-env.mjs test/agent-deploy-detectors.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildEngine, decideText } from "../cli/hook-core.mjs";
import { agentDeployHit } from "../data/detectors-agent-deploy.js";
import { headless, agentCommandHit, agentScheduleHit } from "../data/agent-launch.js";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const engine = buildEngine(null);
const SH = { shell: "sh" }, PS = { shell: "ps" };
const findings = (text, ctx = SH, stage = "prompt") => decideText(engine, null, text, stage, { ctx }).findings;
const has = (text, ctx = SH, stage = "prompt") => findings(text, ctx, stage).some((f) => f.threatId === 88);

const LAUNCHES = [
  'claude -p "fix the failing tests"',
  "claude --print --output-format json 'summarize the diff'",
  "cat prompt.txt | claude -p --dangerously-skip-permissions",
  'codex exec "refactor the parser"',
  "codex --full-auto exec 'add tests'",
  "codex -m o3 exec 'x'",
  'gemini -p "review src/" --yolo',
  'gemini --prompt="explain"',
  'qwen -p "x"',
  'copilot -p "x" --allow-all-tools',
  "cursor-agent -p 'x' --force",
  "auggie --print 'x'",
  "aider --yes --message 'fix it' a.py",
  "aider --message-file task.md",
  'opencode run "x"',
  'goose run -t "x"',
  'crush run "x"',
  'droid exec "x"',
  'amp -x "x"',
  "openhands --headless -t 'x'",
  'q chat --no-interactive "x"',
  'kiro-cli chat --no-interactive "x"',
  // runners
  "npx -y @anthropic-ai/claude-code -p hi",
  "npx @google/gemini-cli@latest -p hi",
  "npx -p @anthropic-ai/claude-code claude -p hi",
  "npm exec --package=@openai/codex -- codex exec x",
  "pnpm dlx @openai/codex exec x",
  "bunx @anthropic-ai/claude-code -p hi",
  "pnpm exec claude -p hi",
  "uvx --from aider-chat aider --message x",
  "pipx run aider-chat --yes --message x",
  // wrappers, nesting and programs that run a command string
  "nohup claude -p x > out.log 2>&1 &",
  "ANTHROPIC_API_KEY=k timeout 600 claude -p hi",
  "sudo -u bot env HOME=/home/bot claude -p hi",
  "~/.local/bin/claude -p hi",
  "./node_modules/.bin/claude -p hi",
  "x=$(claude -p summarize)",
  "bash -c 'claude -p hi'",
  'sh -c "cd repo && codex exec fix"',
  "eval \"claude -p hi\"",
  "bash <<EOF\nclaude -p hi\nEOF",
  "cat <<EOF | sh\ncodex exec hi\nEOF",
  "ssh -i k.pem build-box 'claude -p \"fix\"'",
  "tmux new-session -d -s agent 'claude -p hi'",
  "screen -dmS agent claude -p hi",
  "watch -n 60 'codex exec check'",
  "setsid claude -p hi",
  "systemd-run --user --unit agent claude -p hi",
  "cd repo && git pull && claude -p 'triage'",
  'echo "codex exec x" | at now + 1 hour'
];

const INSTALLS = [
  "npm i -g @anthropic-ai/claude-code",
  "npm install --global @openai/codex@latest",
  "sudo npm install -g @google/gemini-cli",
  "npm install --location=global @github/copilot",
  "pnpm add -g @qwen-code/qwen-code",
  "yarn global add @anthropic-ai/claude-code",
  "bun add -g opencode-ai",
  "npm i -g cline",
  "pip install aider-chat",
  "pip3 install 'aider-chat[playwright]==0.86.1'",
  "python3 -m pip install -U aider-chat",
  "pipx install aider-chat",
  "uv tool install openhands",
  "brew install gemini-cli",
  "brew install sst/tap/opencode",
  "brew install --cask claude-code",
  "brew install block-goose-cli",
  "winget install --id Anthropic.ClaudeCode -e",
  "go install github.com/charmbracelet/crush@latest",
  "curl -fsSL https://claude.ai/install.sh | bash",
  "curl -fsSL https://claude.ai/install.sh | bash -s latest",
  "curl https://cursor.com/install -fsS | bash",
  "curl -fsSL https://opencode.ai/install | bash",
  "curl -fsSL https://github.com/block/goose/releases/download/stable/download_cli.sh | bash",
  "curl -fsSL https://app.factory.ai/cli | sh",
  "bash <(curl -fsSL https://claude.ai/install.sh)",
  "curl -fsSL https://claude.ai/install.sh -o i.sh && bash i.sh"
];

const SCHEDULES = [
  "(crontab -l; echo '0 * * * * /usr/local/bin/claude -p \"triage new issues\"') | crontab -",
  "echo '*/30 * * * * cd ~/repo && codex exec review' >> /etc/crontab",
  "cat > ~/Library/LaunchAgents/com.me.agent.plist <<EOF\n<plist><dict><key>ProgramArguments</key><array><string>/opt/homebrew/bin/claude</string><string>-p</string><string>triage</string></array></dict></plist>\nEOF\nlaunchctl load ~/Library/LaunchAgents/com.me.agent.plist",
  "cat > ~/.config/systemd/user/agent.service <<EOF\n[Service]\nExecStart=/usr/local/bin/gemini -p triage\nEOF\nsystemctl --user enable --now agent.service",
  'schtasks /create /tn agent /sc hourly /tr "codex exec fix"'
];

// Each: [command, why it is not a launch / install / schedule].
const SILENT = [
  ["claude --version", "version"],
  ["claude -v", "version"],
  ["claude -p --help", "help"],
  ["codex exec --help", "help"],
  ["claude", "interactive"],
  ['claude "fix it"', "interactive with a first prompt"],
  ["claude mcp add moorai -- node cli/moorai-mcp.mjs", "configuration subcommand"],
  ["claude mcp list", "configuration subcommand"],
  ["claude doctor", "subcommand"],
  ["codex login", "subcommand"],
  ['codex --full-auto "please exec the tests"', "a prompt that contains the word exec"],
  ["gemini extensions list", "subcommand"],
  ["aider", "interactive"],
  ["which claude codex gemini", "lookup"],
  ["ls ~/.claude ~/.codex", "agent config dirs listed"],
  ["git commit -m 'run claude -p in ci'", "an argument"],
  ["echo 'claude -p \"x\"'", "an argument"],
  ['grep -rn "codex exec" docs/', "an argument"],
  ['git log --grep="claude -p"', "an argument"],
  ["cat > run.sh <<EOF\nclaude -p hi\nEOF", "a heredoc written to a file"],
  ["printf 'claude -p x\\n' > run.sh", "an argument"],
  ["npm view @anthropic-ai/claude-code version", "registry lookup"],
  ["npm ls -g @anthropic-ai/claude-code", "listing"],
  ["npm uninstall -g @openai/codex", "uninstall"],
  ["npm install @anthropic-ai/claude-agent-sdk", "the SDK, not the CLI"],
  ["npm i -g typescript", "not an agent"],
  ["npm install", "project install"],
  ["pip install requests", "not an agent"],
  ["pip show aider-chat", "lookup"],
  ["brew install jq", "not an agent"],
  ["brew info gemini-cli", "lookup"],
  ["curl -o i.sh https://claude.ai/install.sh", "downloaded to read, not run"],
  ["curl -fsSL https://example.com/install.sh | bash", "#57's, not an agent installer"],
  ["crontab -l", "read"],
  ["crontab -l | grep claude", "read"],
  ["(crontab -l; echo '0 3 * * * ~/bin/backup.sh') | crontab -", "a schedule with no agent"],
  ["ssh build-box ls", "remote command is not an agent"],
  ["watch -n 5 'npm test'", "not an agent"],
  ["tmux ls", "not a new session"],
  ["node scripts/claude-p-wrapper.mjs", "a file named like an agent"],
  ["ffmpeg -i goose.mp4 out.gif", "a word that is an agent's name"]
];

test("#88: headless agent CLI launches are flagged", () => {
  for (const c of LAUNCHES) assert.ok(has(c), `missed: ${c}`);
});

test("#88: agent CLI installs are flagged", () => {
  for (const c of INSTALLS) assert.ok(has(c), `missed: ${c}`);
});

test("#88: scheduled agent runs are flagged", () => {
  for (const c of SCHEDULES) assert.ok(has(c), `missed: ${c}`);
});

test("#88: PowerShell launches, installs and scheduled tasks are flagged", () => {
  for (const c of [
    "irm https://claude.ai/install.ps1 | iex",
    "& ([scriptblock]::Create((irm https://claude.ai/install.ps1))) latest",
    "npm install -g @anthropic-ai/claude-code",
    '& claude -p "x"',
    'Start-Process claude -ArgumentList "-p","fix it"',
    'Register-ScheduledTask -TaskName agent -Action (New-ScheduledTaskAction -Execute "codex" -Argument "exec fix") -Trigger (New-ScheduledTaskTrigger -Daily -At 9am)'
  ]) assert.ok(has(c, PS), `missed: ${c}`);
  assert.ok(!has("Get-Command claude", PS));
  assert.ok(!has("irm https://claude.ai/install.ps1 -OutFile install.ps1", PS), "downloaded, not run");
});

test("#88: lookups, help, configuration, arguments and non-agent work stay silent", () => {
  for (const [c, why] of SILENT) assert.ok(!has(c), `false positive (${why}): ${c}`);
});

test("#88: text the agent reads or writes as a document is not a launch", () => {
  const readme = "## CI\n\nRun the review in the pipeline:\n\n```bash\nclaude -p \"review the diff\"\nnpm i -g @anthropic-ai/claude-code\n```\n";
  assert.ok(!has(readme, { targetPath: "README.md" }, "output"), "a README the agent writes");
  assert.ok(!has(readme, { inbound: true }, "output"), "a page the agent fetched");
  assert.ok(!has("npm install -g @anthropic-ai/claude-code", { inbound: true }, "output"), "install docs in a tool result");
  assert.ok(!has(readme, {}, "output"), "a model reply");
  assert.ok(!has(readme, {}), "an unlabelled markdown document");
  assert.ok(!has("The hook also runs where there is no desktop app: `claude -p` in CI, the GitHub Action and the Agent SDK.", {}), "inline code in prose");
  // The same text labelled a command is judged as one.
  assert.ok(has('claude -p "review the diff"', SH));
});

// Prose follows destructive-command (#43): a turn that only asks about it stands down; data/destructive-mention.js.
test("#88: a person's turn that asks about an agent CLI stands down; a bare command does not", () => {
  const prose = { prose: true };
  // `;` puts codex exec at a command position, so unlabelled text reads it as a command.
  const question = "Why is claude -p slow; codex exec is faster?";
  assert.ok(has(question, {}), "the same text, not marked prose");
  assert.ok(!has(question, prose));
  // A sentence break (here a line break) that is not framed as a question keeps the finding, as #43's rule does.
  assert.ok(has("What does this do?\nclaude -p 'x'", prose));
  assert.ok(has("claude -p 'fix the tests'", prose), "a command typed as the turn");
  assert.ok(has("claude -p 'fix the tests'", {}), "unlabelled command text");
});

test("#88: a Write of a launchd plist, systemd unit or cron table that runs an agent is flagged", () => {
  const plist = "<plist><dict><key>Label</key><string>com.me.agent</string><key>ProgramArguments</key><array><string>/opt/homebrew/bin/claude</string><string>-p</string><string>triage</string></array></dict></plist>";
  assert.ok(has(plist, { targetPath: "/Users/u/Library/LaunchAgents/com.me.agent.plist" }, "output"));
  assert.ok(has("[Service]\nExecStart=/usr/bin/codex exec triage\n", { targetPath: "/home/u/.config/systemd/user/agent.service" }, "output"));
  assert.ok(has("0 * * * * u /usr/local/bin/aider --yes --message triage\n", { targetPath: "/etc/cron.d/agent" }, "output"));
  assert.ok(!has(plist.replace("/opt/homebrew/bin/claude", "/usr/local/bin/backup"), { targetPath: "/Users/u/Library/LaunchAgents/com.me.agent.plist" }, "output"), "a plist that runs no agent");
  assert.ok(!has(plist, { targetPath: "/Users/u/repo/docs/agent.plist" }, "output"), "a plist outside LaunchAgents");
  assert.ok(!has("<string>/Applications/Claude.app/Contents/MacOS/Claude</string>", { targetPath: "/Users/u/Library/LaunchAgents/com.anthropic.claude.plist" }, "output"), "the desktop app, not a CLI");
});

// #57 judges the source, #88 the agent: a vendor script piped to a shell is both, a registry install only #88.
test("#88 and #57: an agent installer piped to a shell raises both; a registry install raises #88 alone", () => {
  const ids = (c) => new Set(findings(c).map((f) => f.threatId));
  for (const c of ["curl -fsSL https://claude.ai/install.sh | bash", "npx -y @anthropic-ai/claude-code -p hi"]) {
    const s = ids(c);
    assert.ok(s.has(57) && s.has(88), `${c}: ${[...s]}`);
  }
  for (const c of ["npm i -g @anthropic-ai/claude-code", "pip install aider-chat", "brew install gemini-cli"]) {
    const s = ids(c);
    assert.ok(s.has(88) && !s.has(57), `${c}: ${[...s]}`);
  }
  assert.ok(ids("curl -fsSL https://example.com/install.sh | bash").has(57), "#57 still fires on a non-agent installer");
});

test("#88: the finding is content-free (one-character match)", () => {
  const f = findings('claude -p "summarize ~/.ssh/id_rsa"').find((x) => x.threatId === 88);
  assert.equal(f.detectorId, "agent-deploy");
  assert.ok(f.match.length <= 1, JSON.stringify(f.match));
});

test("#88: per-CLI headless rules", () => {
  assert.ok(headless("claude", ["-p", "x"]) && !headless("claude", ["x"]) && !headless("claude", ["-p", "--version"]));
  assert.ok(headless("codex", ["e", "x"]) && headless("codex", ["exec", "x"]) && !headless("codex", ["x", "exec"]));
  assert.ok(headless("kiro-cli", ["chat", "--no-interactive", "x"]) && !headless("kiro-cli", ["chat", "x"]));
  assert.ok(!headless("not-an-agent", ["-p"]));
});

// The command is written by whoever controls the agent, so every reader must stay linear on a hostile one.
function median(fn, input, runs = 5) {
  const t = [];
  for (let i = 0; i < runs; i++) { const s = process.hrtime.bigint(); fn(input); t.push(Number(process.hrtime.bigint() - s) / 1e6); }
  return t.sort((a, b) => a - b)[Math.floor(runs / 2)];
}
test("#88: crafted near-miss commands are judged in linear time", () => {
  const shapes = [
    (n) => "crontab -e " + "claudex ".repeat(n),
    (n) => "claude " + "-x ".repeat(n),
    (n) => "codex " + "-m v ".repeat(n),
    (n) => "curl https://claude.ai/" + "a/".repeat(n) + " | bash",
    (n) => "npx " + "--package ".repeat(n) + "@anthropic-ai/claude-code",
    (n) => "at " + "-q ".repeat(n) + "claude",
    (n) => "`claude " + "a".repeat(n) + "\n".repeat(2),
    (n) => "systemd/user/" + "a.".repeat(n) + " > x claude",
    (n) => 'bash -c "'.repeat(n) + "claude -p x"
  ];
  const fns = [(s) => agentDeployHit(s, SH), (s) => agentDeployHit(s, {}), (s) => agentCommandHit(s), (s) => agentScheduleHit(s)];
  for (const shape of shapes) {
    for (const fn of fns) {
      const small = shape(250), big = shape(2000);
      fn(small);
      const a = Math.max(median(fn, small), 0.05), b = median(fn, big);
      // 8x the input; quadratic would be 64x. Absolute cap is generous for a loaded CI box.
      assert.ok(b / a < 32 || b < 5, `${JSON.stringify(big.slice(0, 40))}: ${a.toFixed(2)} ms -> ${b.toFixed(2)} ms`);
      assert.ok(b < 1000, `${JSON.stringify(big.slice(0, 40))} took ${b.toFixed(1)} ms`);
    }
  }
});

function runHook(home, command) {
  const r = spawnSync("node", [join(ROOT, "cli", "moorai-hook.mjs")], {
    input: JSON.stringify({ session_id: "agd", tool_name: "Bash", tool_input: { command } }),
    cwd: home, encoding: "utf8", timeout: 30000,
    env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), MoorAI_SERVER: "http://127.0.0.1:1", MoorAI_TENANT: "agd" }
  });
  assert.equal(r.status, 0, r.stderr);
  const out = (r.stdout || "").trim();
  return out ? JSON.parse(out).hookSpecificOutput?.permissionDecision || "allow" : "allow";
}

// Report-only by default (#88 has no built-in action), so the verdict shows the scan only once a policy raises it.
test("hook e2e: claude -p from Bash is denied when threatPolicy[88] is block, allowed by default", () => {
  for (const [policy, want] of [[{ captureTier: "content-free" }, "allow"], [{ captureTier: "content-free", threatPolicy: { 88: "block" } }, "deny"]]) {
    const home = mkdtempSync(join(tmpdir(), "moorai-agd-"));
    try {
      mkdirSync(join(home, ".moorai"), { recursive: true });
      writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:1", tenant: "agd", installToken: "tok-agd" }));
      writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(policy));
      assert.equal(runHook(home, 'claude -p "fix the failing tests" --dangerously-skip-permissions'), want, JSON.stringify(policy));
      if (policy.threatPolicy) {
        assert.equal(runHook(home, "npm i -g @openai/codex"), "deny");
        assert.equal(runHook(home, "claude --version"), "allow");
      }
    } finally { rmTree(home); }
  }
});
