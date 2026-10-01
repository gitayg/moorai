// The doctor's report: runs every check in order and renders it. See cli/moorai-doctor.mjs.
import { loadConfig } from "./config.mjs";
import { hostTable, checkHost, checkManaged, readManagedSettings, PLUGIN_INSTALL } from "./doctor-hosts.mjs";
import { checkNode, checkEnrollment, checkConsole, checkPolicy, checkPosture, checkBreakGlass, checkStateDir, checkSelfTest, pkg } from "./doctor-checks.mjs";
import { loadPolicyReadOnly, resolveEffective } from "./doctor-policy.mjs";
import { checkServerMode } from "./doctor-server.mjs";

export async function runDoctor({ offline = false, selftest = true } = {}) {
  const config = loadConfig();
  const checks = [checkNode()];
  const managed = checkManaged(readManagedSettings());
  const table = hostTable();
  const hosts = table.map((h) => checkHost(h, { managedHooks: managed.managedHooks, managedPlugins: managed.managedPlugins }));
  checks.push(managed, ...hosts);
  if (!hosts.some((h) => h.installed)) checks.push({ id: "hosts:any", group: "hosts", title: "Any host", status: "fail", summary: "MoorAI is not registered in any agent host on this machine: nothing calls the hook", fix: `${table[0].fix} (or: node ${JSON.stringify(table[1].install[0])} <codex|cursor|gemini|copilot> install; or the Claude Code plugin: ${PLUGIN_INSTALL})` });
  const loaded = loadPolicyReadOnly(config, { offline });
  const eff = loaded.error ? resolveEffective(null, config) : resolveEffective(loaded, config);
  checks.push(checkEnrollment(config, eff), await checkConsole(config, { offline }));
  const server = checkServerMode(eff.server, eff);
  if (server) checks.push(server);
  checks.push(checkPolicy(loaded, eff, config), checkPosture(eff), checkBreakGlass(eff));
  checks.push(checkStateDir());
  // The self-test child reads the same root-owned /etc/moorai/config.json as the hook, and a sandbox HOME
  // cannot override it: when that file binds a console, the child would post to it.
  const sysBound = eff.server.active && (eff.server.sources.serverUrl === "system" || eff.server.sources.installToken === "system");
  if (selftest && sysBound) checks.push({ id: "selftest", group: "selftest", title: "Live self-test", status: "skip", summary: "skipped: /etc/moorai/config.json binds the console, and the self-test child would post to it" });
  else if (selftest) checks.push(checkSelfTest(config, eff));
  else checks.push({ id: "selftest", group: "selftest", title: "Live self-test", status: "skip", summary: "skipped (--no-selftest)" });
  for (const c of checks) { delete c.managedHooks; delete c.managedPlugins; }
  const summary = { ok: 0, warn: 0, fail: 0, skip: 0 };
  for (const c of checks) summary[c.status]++;
  return { version: pkg().version || "", offline, checks, summary, exitCode: summary.fail ? 1 : 0 };
}

const TAG = { ok: "ok  ", warn: "WARN", fail: "FAIL", skip: "skip" };
export function formatHuman(r) {
  const lines = [`MoorAI doctor v${r.version}${r.offline ? " (offline)" : ""}`, ""];
  let group = "";
  for (const c of r.checks) {
    if (c.group !== group) { group = c.group; lines.push(`[${group}]`); }
    lines.push(`  ${TAG[c.status]}  ${c.title}: ${c.summary}`);
    if (c.fix && (c.status === "fail" || c.status === "warn")) lines.push(`        fix: ${c.fix}`);
  }
  lines.push("", `${r.summary.ok} ok, ${r.summary.warn} warn, ${r.summary.fail} fail, ${r.summary.skip} skipped`);
  return lines.join("\n");
}
