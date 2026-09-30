// The doctor's report: runs every check in order and renders it. See cli/moorai-doctor.mjs.
import { loadConfig } from "./config.mjs";
import { hostTable, checkHost, checkManaged, readManagedSettings, PLUGIN_INSTALL } from "./doctor-hosts.mjs";
import { checkNode, checkEnrollment, checkConsole, checkPolicy, checkPosture, checkBreakGlass, checkStateDir, checkSelfTest, pkg } from "./doctor-checks.mjs";
import { loadPolicyReadOnly, resolveEffective } from "./doctor-policy.mjs";

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
  checks.push(checkPolicy(loaded, eff, config), checkPosture(eff), checkBreakGlass(eff));
  checks.push(checkStateDir());
  if (selftest) checks.push(checkSelfTest(config, eff));
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
