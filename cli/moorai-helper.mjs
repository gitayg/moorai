#!/usr/bin/env node
// moorai-helper — is the MoorAI privileged helper (moorai-guardd) installed and healthy on this device?
//
//   moorai-helper status          # human-readable
//   moorai-helper status --json   # the content-free status object (the same shape the posture carries)
//
// Read-only: it installs nothing and needs no privileges. It takes no path or root option, because the
// endpoint and the files it checks are fixed per OS (contract §3.1, §10.2).
import { helperInstallStatus } from "./guardd-install.mjs";

const HELP = `moorai-helper — status of the MoorAI privileged helper (moorai-guardd)

Usage:
  moorai-helper status [--json]

States:
  not-installed          no helper binary and no service definition
  partial                one of the binary and the service definition is missing
  installed-not-running  installed, but the endpoint is not there
  healthy                the helper answered with a valid device-key proof
  not-ready              the helper answered but has no console binding yet (/etc/moorai)
  unreachable            the endpoint is there but the helper did not answer
  untrusted              the endpoint or device.pub fails the ownership check, or the proof is wrong
  unverified             the endpoint is there but device.pub is missing
Install it with the script for your OS under guardd/packaging/ (run as root / elevated).
`;

const NEXT = {
  "not-installed": "Install: sudo sh guardd/packaging/<linux|macos>/install.sh /abs/path/moorai-guardd, or install.ps1 on Windows.",
  partial: "Re-run the installer for your OS; it lays out the binary and the service together.",
  "installed-not-running": "Start it: systemctl start moorai-guardd.socket moorai-guardd.service (Linux), launchctl kickstart system/<label> (macOS), sc.exe start MoorAIGuard (Windows).",
  "not-ready": "Write the console binding: /etc/moorai/config.json and secret.json (Windows: ProgramData\\MoorAI).",
  unreachable: "Check the service log: journalctl -u moorai-guardd (Linux), /Library/Logs/MoorAI/guardd.log (macOS), the Application event log (Windows).",
  untrusted: "Something other than the helper may own the endpoint. Do not rely on it; reinstall as root and check ownership.",
  unverified: "The helper has not published device.pub yet; check its log."
};

async function main(argv) {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") { process.stdout.write(HELP); return 0; }
  if (cmd !== "status") { process.stderr.write(`moorai-helper: unknown command ${cmd}\n${HELP}`); return 2; }
  let json = false;
  for (const a of rest) {
    if (a === "--json") json = true;
    else { process.stderr.write(`moorai-helper: unknown option ${a}\n`); return 2; }
  }
  const s = await helperInstallStatus({ timeoutMs: 1000 });
  if (json) { process.stdout.write(`${JSON.stringify(s)}\n`); return 0; }
  const lines = [
    `moorai-guardd: ${s.state}${s.helperVersion ? ` (helper ${s.helperVersion})` : ""}`,
    `  binary: ${s.binary ? "present" : "missing"}   service: ${s.service ? "registered" : "missing"}`,
    `  endpoint: ${s.endpoint}   device.pub: ${s.devicePub}   hello: ${s.hello}`
  ];
  if (NEXT[s.state]) lines.push(`  next: ${NEXT[s.state]}`);
  process.stdout.write(`${lines.join("\n")}\n`);
  return 0;
}

main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
