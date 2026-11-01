// Service files that keep moorai-hookd running for the user: a launchd user agent (macOS) or a systemd --user
// unit (Linux). Generated, never loaded: `moorai-hookd unit --out <dir>` writes the file and prints the commands
// that install it. Windows has no generator: there the hook stays on the command transport.
import { join } from "node:path";

export const LAUNCHD_LABEL = "dev.moorai.hookd";
export const SYSTEMD_UNIT = "moorai-hookd.service";

const xml = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
// systemd: a word with whitespace, quotes, backslashes or % is double-quoted with those escaped.
const sdWord = (s) => (/^[A-Za-z0-9_@+=:,./-]+$/.test(s) ? s : `"${String(s).replace(/\\/g, "\\\\").replace(/"/g, "\\\"").replace(/%/g, "%%")}"`);

export function launchdPlist({ node, script, args = [], logFile }) {
  const argv = [node, script, ...args].map((a) => `    <string>${xml(a)}</string>`).join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${argv}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Interactive</string>
  <key>StandardErrorPath</key>
  <string>${xml(logFile)}</string>
  <key>StandardOutPath</key>
  <string>${xml(logFile)}</string>
</dict>
</plist>
`;
}

export function systemdUnit({ node, script, args = [] }) {
  return `[Unit]
Description=MoorAI hook daemon (Claude Code HTTP hooks)

[Service]
ExecStart=${[node, script, ...args].map(sdWord).join(" ")}
Restart=always
RestartSec=1

[Install]
WantedBy=default.target
`;
}

// -> { file, text, install: [commands], uninstall: [commands] } for this platform, or null (Windows).
export function unitFor({ platform = process.platform, node, script, args = [], outDir, logFile }) {
  if (platform === "darwin") {
    const file = join(outDir, `${LAUNCHD_LABEL}.plist`);
    return { file, text: launchdPlist({ node, script, args, logFile }), install: [`launchctl bootstrap gui/$(id -u) ${JSON.stringify(file)}`], uninstall: [`launchctl bootout gui/$(id -u)/${LAUNCHD_LABEL}`] };
  }
  if (platform === "linux") {
    const file = join(outDir, SYSTEMD_UNIT);
    return { file, text: systemdUnit({ node, script, args }), install: ["systemctl --user daemon-reload", `systemctl --user enable --now ${SYSTEMD_UNIT}`], uninstall: [`systemctl --user disable --now ${SYSTEMD_UNIT}`] };
  }
  return null;
}
