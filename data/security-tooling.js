// The defensive tooling an agent turns off to blind the host: EDR and audit daemons (ATT&CK T1685 Disable
// or Modify Tools), the host firewall (T1686), and macOS Gatekeeper's quarantine flag (T1553.001). These
// extend action-security-config (#46) past the first bounds it shipped (ufw/firewalld/netsh, Defender,
// spctl). The service list is DATA so it is reviewable; each name is a service/daemon identifier, not an
// English word, to keep a project called "falcon" or a file named "auditd.log" from matching.
//
// Each name checked against the vendor's own service/label naming (2026-10). Bare "falcon", "crowdstrike",
// "osquery", "wazuh" are deliberately omitted — too close to ordinary project names; the daemon forms
// (falcon-sensor, falcond, osqueryd, wazuh-agent) are specific.
export const EDR_AUDIT_SERVICES = [
  "falcon-sensor", "falcond", "com.crowdstrike.falcon.agent",
  "sentineld", "sentinelagent", "com.sentinelone.sentineld",
  "cbdaemon", "cbagent", "cbdefense", "cbsensor",
  "osqueryd",
  "auditd",
  "wazuh-agent", "ossec", "ossec-hids",
  "mdatp", "wdavdaemon", "com.microsoft.mdatp",
  "elastic-endpoint", "elastic-agent"
];

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const SVC = EDR_AUDIT_SERVICES.map(esc).join("|");

export const SECURITY_TOOLING_DISABLE = [
  // Stop / unload / disable a known EDR or audit daemon. launchctl (macOS), systemctl / service (Linux),
  // sc / Stop-Service / Set-Service (Windows). Status, list, start and restart are not these verbs.
  new RegExp(`(?<![\\w-])launchctl\\s+(?:unload|bootout|disable|remove)\\b[^\\n;|&]{0,200}?\\b(?:${SVC})\\b`, "i"),
  new RegExp(`(?<![\\w-])systemctl\\s+(?:stop|disable|mask)\\b[^\\n;|&]{0,100}?\\b(?:${SVC})\\b`, "i"),
  new RegExp(`(?<![\\w-])service\\s+(?:${SVC})\\s+(?:stop|disable)\\b`, "i"),
  new RegExp(`(?<![\\w-])(?:sc(?:\\.exe)?\\s+(?:stop|config|delete)|Stop-Service|Set-Service)\\b[^\\n;|&]{0,100}?\\b(?:${SVC})\\b`, "i"),
  // Windows Defender exclusions — an agent carving a hole for itself without disabling the whole product.
  /\bAdd-MpPreference\b[^\n;|]{0,100}?-Exclusion(?:Path|Process|Extension)\b/i,
  // Host firewall flushed or disabled: iptables / ip6tables -F, nft flush ruleset, pfctl -d / -F all.
  /(?<![\w-])(?:ip6?tables(?:-legacy)?)\s+(?:-[A-Za-z]+\s+){0,3}(?:-F\b|--flush\b)/i,
  /(?<![\w-])nft\s+flush\s+ruleset\b/i,
  /(?<![\w-])pfctl\s+(?:-[A-Za-z]+\s+){0,2}(?:-d\b|-F\s+(?:all|rules)\b)/i,
  // macOS Gatekeeper: remove the com.apple.quarantine attribute, or clear all attributes (which removes it).
  /(?<![\w-])xattr\s+(?:-[A-Za-z]+\s+){0,3}-[A-Za-z]*d[A-Za-z]*\b[^\n;|&]{0,40}?\bcom\.apple\.quarantine\b/i,
  /(?<![\w-])xattr\s+-[A-Za-z]*c[A-Za-z]*\b/i
];
