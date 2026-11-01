// Doctor: which transport Claude Code uses to run the MoorAI hook (cli/hook-transport.mjs), and for the http
// transport whether moorai-hookd answers and whether a settings allowlist stops Claude Code from calling it.
// settings reference, allowedHttpHookUrls: "When you define this key, Claude Code runs an HTTP hook only if its
// URL matches one of the patterns and blocks the rest without running them; an empty array blocks every HTTP
// hook." "Arrays merge across settings files."
import { readJson } from "./doctor-hosts.mjs";
import { listenerOwner } from "./hookd-listener.mjs";

const PROBE_MS = 1500;

// `*` is a wildcard; everything else is literal. Hostnames compare case-insensitively.
export function urlAllowed(url, patterns) {
  return patterns.some((p) => typeof p === "string" && new RegExp(`^${p.split("*").map((x) => x.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i").test(url));
}

// sources: [{ source, data }] — the user settings file and the managed settings (cli/doctor-hosts.mjs).
export function allowlistProblem(url, sources) {
  const lists = sources.filter((s) => s && s.data && Array.isArray(s.data.allowedHttpHookUrls));
  if (!lists.length) return "";
  const merged = lists.flatMap((s) => s.data.allowedHttpHookUrls);
  return urlAllowed(url, merged) ? "" : `allowedHttpHookUrls in ${lists.map((s) => s.source).join(", ")} does not match ${url}: Claude Code will not call moorai-hookd`;
}

// host: the claude-code host check (checkHost); managed: readManagedSettings(); version: this package's.
// owner: whether the port's listener is this user's (cli/hookd-listener.mjs); another account can take the port.
export async function checkHookTransport(host, { managed = [], settingsFile = "", version = "", fetchImpl = globalThis.fetch, owner = listenerOwner } = {}) {
  const base = { id: "hook:transport", group: "hosts", title: "Claude Code hook transport" };
  if (!host || !host.installed) return { ...base, status: "skip", summary: "MoorAI is not registered in Claude Code" };
  const d = host.details || {};
  if (d.transport !== "http") return { ...base, status: "ok", summary: "command (Claude Code starts node cli/moorai-hook.mjs for each event)", transport: "command" };
  const url = d.urls[0];
  const problems = [];
  if (d.urls.length > 1) problems.push(`MoorAI's entries name ${d.urls.length} different URLs`);
  const user = settingsFile ? { source: settingsFile, data: readJson(settingsFile).data } : null;
  const allow = allowlistProblem(url, [user, ...managed].filter(Boolean));
  if (allow) problems.push(allow);
  let health = null;
  try {
    const r = await fetchImpl(new URL("/healthz", url), { signal: AbortSignal.timeout(PROBE_MS) });
    health = r.ok ? await r.json() : null;
    if (!health) problems.push(`moorai-hookd at ${new URL(url).origin} answered ${r.status}`);
    const own = owner(Number(new URL(url).port || 80));
    if (!own.ok) problems.push(`the listener on ${new URL(url).origin} is not moorai-hookd run by this user (${own.why}): it receives every hook event and the token, and its answers decide`);
  } catch { problems.push(`moorai-hookd does not answer at ${new URL(url).origin}: every hook call is a failed HTTP hook (onFailure decides: "block" refuses the tool call, "continue" lets it run unchecked)`); }
  if (health && version && health.version !== version) problems.push(`moorai-hookd runs ${health.version}, this package is ${version}: restart it`);
  const fix = "start it (moorai-hookd, or install its service: moorai-hookd unit --out <dir>), or go back to the command transport: moorai-hook install";
  if (problems.length) return { ...base, status: "fail", summary: `http: ${problems.join("; ")}`, fix, transport: "http", url };
  return { ...base, status: "ok", summary: `http: moorai-hookd ${health.version} answers at ${new URL(url).origin} (${health.workers ? health.workers.waiting : 0} workers warm)`, transport: "http", url };
}
