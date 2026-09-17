#!/usr/bin/env node
// One hook entry for agents other than Claude Code:
//   node cli/moorai-agent-hook.mjs <agent>              run as the agent's hook (stdin → stdout)
//   node cli/moorai-agent-hook.mjs <agent> install      register the hook in the agent's config
//   node cli/moorai-agent-hook.mjs <agent> uninstall    remove it
// Each adapter in cli/agent-hooks/<agent>.mjs translates the agent's hook payload to Claude Code's
// shape, and MoorAI's verdict back to what that agent accepts. Adapter contract:
//   id, label
//   toClaude(payload) -> Claude hook payload | null   (null = not a tool event MoorAI decides; allow)
//   fromVerdict(verdict, payload) -> { stdout?: string, stderr?: string, exitCode: number }
//   install({ home, command }) / uninstall({ home })   idempotent; touch only MoorAI's own entries
import { evaluate } from "./agent-hooks/shim.mjs";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

const ADAPTERS = ["codex", "copilot", "gemini", "cursor"];

async function load(id) {
  if (!ADAPTERS.includes(id)) throw new Error(`unknown agent '${id}' (known: ${ADAPTERS.join(", ")})`);
  return import(`./agent-hooks/${id}.mjs`);
}

async function readStdin() { const c = []; for await (const x of process.stdin) c.push(x); return Buffer.concat(c).toString("utf8"); }

async function main() {
  const [id, cmd] = process.argv.slice(2);
  const a = await load(id);
  const command = `node ${JSON.stringify(fileURLToPath(import.meta.url))} ${id}`;
  if (cmd === "install") return a.install({ home: homedir(), command });
  if (cmd === "uninstall") return a.uninstall({ home: homedir() });
  let payload;
  try { payload = JSON.parse((await readStdin()) || "{}"); } catch { process.exit(0); }
  const claude = a.toClaude(payload);
  const verdict = claude ? evaluate(claude) : { decision: "allow", reason: "" };
  const o = a.fromVerdict(verdict, payload);
  if (o.stdout) process.stdout.write(o.stdout);
  if (o.stderr) process.stderr.write(o.stderr);
  process.exit(o.exitCode || 0);
}

main().catch(() => process.exit(0));
