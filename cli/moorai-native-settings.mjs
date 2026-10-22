#!/usr/bin/env node
// moorai-native-settings — compile one MoorAI policy into each agent host's own settings files, and check
// whether the files on this machine still say what MoorAI compiled. Never writes a system path itself:
// `compile --out <dir>` writes into <dir>, and the administrator (or MDM) places the files.
//
//   moorai-native-settings compile --policy <file> [--host all|<host>[,<host>]] [--platform darwin|linux|win32]
//                                  [--out <dir>] [--mcp-identities <file>] [--pubkey <file> --tenant <id>]
//   moorai-native-settings check   --policy <file> [--host ...] [--platform ...] [--root <dir>] [--home <dir>]
//
// Exit codes: 0 ok, 1 bad arguments (unknown host or platform), 2 the policy cannot be read or its
// signature does not verify, 3 (check) a host's file has drifted or cannot be read, 4 (check) no file where
// MoorAI's should be (and none drifted).

import { readFileSync, writeFileSync, mkdirSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { nativeSettings, renderFile, NATIVE_HOSTS, NATIVE_PLATFORMS } from "./native-settings.mjs";
import { nativeDrift, nativeSettingsPosture } from "./native-settings-drift.mjs";
import { verifyPolicySignature, parseTrustedKeys } from "./hook-core.mjs";

const HELP = `moorai-native-settings — one MoorAI policy as each agent host's own settings

  compile --policy <file> [--host all|claude-code,codex,copilot,cursor,gemini] [--platform darwin|linux|win32]
          [--out <dir>] [--mcp-identities <file>] [--pubkey <file> --tenant <id>]
      Prints { hosts:[{ host, files:[{ path, format, scope, merge, text }], unexpressed, notes }] }.
      --out writes <dir>/<host>/<file name> and <dir>/<host>/unexpressed.json.
  check --policy <file> [--host ...] [--platform ...] [--root <dir>] [--home <dir>]
      Compares each host's file on this machine (under --root when given) with what MoorAI compiles.
      Prints { v, hosts:{ <host>: { state, files, findings, weakening, unexpressed } }, detail }.
      Exits 3 when a file has drifted or cannot be read, 4 when a file is missing, 0 when all are in sync.

<file> is the policy JSON (the console's signed policy works; give --pubkey to verify its signature).
--mcp-identities is { "<server name>": { "command": "..." } | { "url": "..." } } for Codex, which matches MCP
servers by command or URL.
`;

function args(argv) {
  const o = { cmd: argv[0], host: "all" };
  const flags = { "--policy": "policy", "--host": "host", "--platform": "platform", "--out": "out", "--mcp-identities": "ids", "--pubkey": "pubkey", "--tenant": "tenant", "--root": "root", "--home": "home" };
  for (let k = 1; k < argv.length; k++) {
    const f = flags[argv[k]];
    if (!f || k + 1 >= argv.length) return { error: `unknown or incomplete argument ${argv[k]}` };
    o[f] = argv[++k];
  }
  return o;
}

const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
const baseName = (p) => p.split(/[\\/]/).pop();

function loadPolicy(o) {
  let policy;
  try { policy = readJson(o.policy); } catch (e) { return { code: 2, msg: `cannot read policy ${o.policy || "(no --policy)"}: ${e.message}` }; }
  if (o.pubkey) {
    let keys;
    try { keys = parseTrustedKeys(readFileSync(o.pubkey, "utf8")); } catch (e) { return { code: 2, msg: `cannot read --pubkey: ${e.message}` }; }
    if (!keys.length) return { code: 2, msg: "no usable key in --pubkey" };
    const v = verifyPolicySignature(policy, { keys, tenant: o.tenant || "" });
    if (!v.trusted) return { code: 2, msg: `policy signature ${v.status}` };
  } else if (policy && policy.policySig) process.stderr.write("moorai-native-settings: signature not checked (no --pubkey)\n");
  return { policy };
}

function main(argv) {
  if (!argv.length || argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); return 0; }
  const o = args(argv);
  if (o.error || !["compile", "check"].includes(o.cmd)) { process.stderr.write(`moorai-native-settings: ${o.error || `unknown command ${o.cmd}`}\n`); return 1; }
  const hosts = o.host === "all" ? [...NATIVE_HOSTS] : o.host.split(",");
  const bad = hosts.find((h) => !NATIVE_HOSTS.includes(h));
  if (bad) { process.stderr.write(`moorai-native-settings: unsupported host (one of ${NATIVE_HOSTS.join(", ")})\n`); return 1; }
  const platform = o.platform || (NATIVE_PLATFORMS.includes(process.platform) ? process.platform : "linux");
  if (!NATIVE_PLATFORMS.includes(platform)) { process.stderr.write(`moorai-native-settings: unsupported platform (one of ${NATIVE_PLATFORMS.join(", ")})\n`); return 1; }
  const lp = loadPolicy(o);
  if (lp.code) { process.stderr.write(`moorai-native-settings: ${lp.msg}\n`); return lp.code; }
  let mcpIdentities = {};
  if (o.ids) { try { mcpIdentities = readJson(o.ids); } catch (e) { process.stderr.write(`moorai-native-settings: cannot read --mcp-identities: ${e.message}\n`); return 2; } }

  if (o.cmd === "compile") {
    const report = { hosts: [] };
    for (const host of hosts) {
      const r = nativeSettings(lp.policy, host, { platform, mcpIdentities });
      report.hosts.push({ host, platform, files: r.files.map((f) => ({ path: f.path, format: f.format, scope: f.scope, merge: f.merge, text: renderFile(f) })), unexpressed: r.unexpressed, notes: r.notes });
      if (o.out) {
        const dir = join(o.out, host);
        mkdirSync(dir, { recursive: true });
        for (const f of r.files) writeFileSync(join(dir, baseName(f.path)), renderFile(f));
        writeFileSync(join(dir, "unexpressed.json"), JSON.stringify(r.unexpressed, null, 2) + "\n");
      }
    }
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    return 0;
  }
  const opts = { root: o.root || "", home: o.home || homedir() };
  const posture = nativeSettingsPosture({ policy: lp.policy, platform, mcpIdentities, hosts, ...opts });
  const detail = {};
  for (const host of hosts) detail[host] = nativeDrift(nativeSettings(lp.policy, host, { platform, mcpIdentities }), opts).files;
  process.stdout.write(JSON.stringify({ ...posture, detail }, null, 2) + "\n");
  const states = Object.values(posture.hosts).map((h) => h.state);
  if (states.some((x) => x === "drift" || x === "unreadable")) return 3;
  return states.includes("absent") ? 4 : 0;
}

const isMain = (() => { try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (isMain) process.exit(main(process.argv.slice(2)));
