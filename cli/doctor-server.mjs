// The doctor's server-mode check (cli/server-mode.mjs): where each part of the binding came from, the
// install token as a fingerprint only, the service identity the console will see, what a "justify" verdict
// becomes with no approver, and any MOORAI_* name a settings file tried to set. Shown only when server mode
// is on or was asked for, so a laptop's report is unchanged.
import { headlessAskMode, serviceWho, systemConfigPath, HEADLESS_NOTE } from "./server-mode.mjs";
import { readRootOwned } from "./hook-core.mjs";
import { fingerprint } from "./doctor-policy.mjs";

const POLICY_ANCHOR = process.platform === "win32" ? `${process.env.ProgramData || "C:\\ProgramData"}\\MoorAI\\policy.pub` : "/etc/moorai/policy.pub";

export function policyAnchored(env = process.env, readAnchor = () => readRootOwned(POLICY_ANCHOR)) {
  if (String(readAnchor() || "").trim()) return "system";
  if (String(env.MOORAI_POLICY_PUBKEY || "").trim()) return "env";
  return "";
}
function isLoopback(url) {
  try { const h = new URL(url).hostname; return h === "localhost" || h === "::1" || h === "[::1]" || /^127\./.test(h); } catch { return false; }
}

export function checkServerMode(sm, eff, { env = process.env, anchored = policyAnchored(env) } = {}) {
  if (!sm || (!sm.active && !(sm.tamper && sm.tamper.length))) return null;
  const base = { id: "server", group: "server", title: "Server mode" };
  const refused = sm.refused || [];
  const tamper = refused.length ? `refused ${refused.join(", ")}: set by ${sm.tamper.length} user/project/local settings file(s) (${sm.tamper.map((t) => t.file).join(", ")}) — the hook reports this as tampering` : "";
  if (!sm.active) return { ...base, status: "fail", summary: `server mode was asked for by a settings file and refused; ${tamper}`, fix: "set MOORAI_MODE in the job/pod environment or /etc/moorai/config.json, never in a settings file's env block", details: { refused, settingsFiles: sm.tamper.map((t) => t.file) } };

  const c = sm.config;
  const token = c.installToken ? `sha256:${fingerprint(c.installToken)} (${sm.sources.installToken})` : "none";
  const who = serviceWho(sm);
  const ask = headlessAskMode(sm, eff && eff.policy);
  const details = {
    requestedBy: sm.requestedBy,
    systemConfig: systemConfigPath(),
    serverUrl: `${c.serverUrl} (${sm.sources.serverUrl})`,
    tenant: `${c.tenant} (${sm.sources.tenant})`,
    installToken: token,
    serviceId: `${sm.serviceId} (${sm.serviceIdSource})`,
    identity: `${who.user} / ${who.device}`,
    headlessAsk: `${ask.mode} (${ask.source})`,
    policyAnchor: anchored || "none",
    refused
  };
  const askText = ask.mode === "deny" ? `a "justify" verdict is denied — ${HEADLESS_NOTE}` : `a "justify" verdict is ALLOWED and reported (${ask.source})`;
  const summary = `on (${sm.requestedBy}) · console ${c.serverUrl} [${sm.sources.serverUrl}] · tenant ${c.tenant} · token ${token} · workload ${who.device} · ${askText}`;
  const warns = [];
  const fixes = [];
  if (tamper) return { ...base, status: "fail", summary: `${summary}; ${tamper}`, fix: "remove the MOORAI_* keys from those settings files; put the binding in the job/pod environment or a root-owned /etc/moorai/config.json", details };
  if (!c.installToken) { warns.push("no install token: the hook enforces the built-in defaults but reports nothing and fetches no org policy"); fixes.push("set MOORAI_INSTALL_TOKEN (or installToken in /etc/moorai/config.json)"); }
  if (sm.serviceIdSource === "unnamed") { warns.push("no workload name: every unnamed workload in this tenant shares one actor"); fixes.push("set MOORAI_SERVICE_ID"); }
  if (sm.headless.envRefused) { warns.push(`MOORAI_HEADLESS_ASK="${String(env.MOORAI_HEADLESS_ASK).trim()}" ignored: the environment may only say "deny"`); fixes.push('set "headlessAsk" in /etc/moorai/config.json or the org policy'); }
  if (c.installToken && !anchored) { warns.push("no policy trust anchor: container state is discarded between runs, so the TOFU key pin never forms and an unsigned policy is accepted"); fixes.push("ship the tenant key as /etc/moorai/policy.pub (root-owned) or MOORAI_POLICY_PUBKEY"); }
  if (c.installToken && !/^https:/.test(c.serverUrl) && !isLoopback(c.serverUrl)) { warns.push("the console URL is plain http: the install token travels unencrypted"); fixes.push("use an https console URL"); }
  if (warns.length) return { ...base, status: "warn", summary: `${summary}; ${warns.join("; ")}`, fix: fixes.join("; "), details };
  return { ...base, status: "ok", summary, details };
}
