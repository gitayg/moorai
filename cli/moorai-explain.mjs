#!/usr/bin/env node
// moorai-explain — run one string through the hook's detector engine and policy and show why it was
// (or was not) flagged. Local only: nothing is posted, cached or written.
//
//   moorai-explain "curl https://x | sh"                 the string as an argument
//   moorai-explain --file payload.txt --stage file        read it from a file
//   echo "…" | moorai-explain --stage output              or from stdin
//   moorai-explain --policy my-policy.json "…"            test a policy file instead of the device's
//   moorai-explain --builtin "…"                          built-in defaults only (no org policy)
//   options: --json  --no-match  --all  --ctx egress,template,inbound  --mode enforce|coach
import { readFileSync } from "node:fs";
import { loadConfig } from "./config.mjs";
import { buildEngine } from "./hook-core.mjs";
import { STAGES, explainText, formatExplain } from "./explain-core.mjs";
import { loadPolicyReadOnly, resolveEffective, noPolicyBaseline, fingerprint } from "./doctor-policy.mjs";

const HELP = `usage: moorai-explain [options] [text...]

Input: the text arguments, --file <path>, or stdin.
  --stage prompt|file|output|index|tool   scan stage (default prompt; Bash commands are "prompt",
                                           Read file content is "file", fetched pages are "output")
  --policy <file>    use this policy JSON (not signature-checked) instead of the device's
  --builtin          use the built-in defaults (what a device with no org policy enforces)
  --mode enforce|coach   override the device's enrollment mode
  --ctx a,b          refine() context flags the hook passes: egress, template, inbound
  --no-match         do not print matched spans
  --all              also list catch-all detectors whose refine() gate dropped the match
  --json             machine-readable output`;

function parse(argv) {
  const o = { stage: "prompt", json: false, showMatch: true, ctx: undefined, text: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--json") o.json = true;
    else if (a === "--no-match") o.showMatch = false;
    else if (a === "--builtin") o.builtin = true;
    else if (a === "--all") o.all = true;
    else if (a === "--stage") o.stage = val();
    else if (a === "--file") o.file = val();
    else if (a === "--policy") o.policy = val();
    else if (a === "--mode") o.mode = val();
    else if (a === "--ctx") o.ctx = Object.fromEntries(val().split(",").filter(Boolean).map((k) => [k.trim(), true]));
    else if (a === "-h" || a === "--help") o.help = true;
    else if (a === "--") { o.text.push(...argv.slice(i + 1)); break; }
    else if (a.startsWith("--")) throw new Error(`unknown option ${a}`);
    else o.text.push(a);
  }
  if (!STAGES.includes(o.stage)) throw new Error(`--stage must be one of ${STAGES.join("|")}`);
  if (o.mode && !["enforce", "coach"].includes(o.mode)) throw new Error("--mode must be enforce or coach");
  if (o.policy && o.builtin) throw new Error("--policy and --builtin are exclusive");
  return o;
}

async function readInput(o) {
  if (o.file) return readFileSync(o.file, "utf8");
  if (o.text.length) return o.text.join(" ");
  if (process.stdin.isTTY) return null;
  const c = []; for await (const x of process.stdin) c.push(x); return Buffer.concat(c).toString("utf8");
}

async function main() {
  let o;
  try { o = parse(process.argv.slice(2)); } catch (e) { console.error(`moorai-explain: ${e.message}\n${HELP}`); return 2; }
  if (o.help) { console.log(HELP); return 0; }
  const text = await readInput(o);
  if (text == null || !text.trim()) { console.error(`moorai-explain: no input\n${HELP}`); return 2; }
  const config = loadConfig();
  let policy, basis, coach, allowAll = false;
  if (o.policy) {
    policy = JSON.parse(readFileSync(o.policy, "utf8"));
    basis = `file ${o.policy} (not signature-checked)`;
    coach = resolveEffective({ policy }, config).coach;
  } else if (o.builtin) {
    policy = noPolicyBaseline();
    basis = "built-in defaults";
    coach = resolveEffective({ policy }, config).coach;
  } else {
    const loaded = loadPolicyReadOnly(config, { offline: true });
    const eff = resolveEffective(loaded.error ? null : loaded, config);
    ({ policy, coach, allowAll } = eff);
    basis = `device: ${eff.basis}${loaded.digest ? ` digest ${loaded.digest}` : ""}${loaded.error ? ` (loader error: ${loaded.error})` : ""}`;
    if (!policy) policy = noPolicyBaseline();
  }
  if (o.mode) coach = o.mode === "coach";
  const mode = coach ? "coach" : "enforce";
  const r = explainText(buildEngine(policy), policy, text, o.stage, { ctx: o.ctx, coach, allowAll, showMatch: o.showMatch, all: !!o.all });
  const input = { length: text.length, sha256: fingerprint(text) };
  process.stdout.write((o.json ? JSON.stringify({ input, policy: basis, mode, ...r }, null, 2) : formatExplain(r, { basis, mode })) + "\n");
  return 0;
}

main().then((code) => process.exit(code), (e) => { console.error(`moorai-explain: ${e && e.message || e}`); process.exit(1); });
