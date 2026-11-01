// Which transport Claude Code uses to run the MoorAI hook, and the settings.json handler for each.
//   command  (default) Claude Code starts `node cli/moorai-hook.mjs` for every event
//   http     Claude Code POSTs the event to moorai-hookd on loopback (cli/moorai-hookd.mjs), which runs the same
//            hook in a pre-warmed worker. Every event MoorAI registers supports http hooks (hooks reference:
//            only SessionStart and Setup do not, and MoorAI registers neither).
// onFailure (Claude Code v2.1.295+): "block" makes an unanswered request, a non-2xx answer or a timeout do what
// exit 2 does. It follows the hook's fail mode (cli/hook-fail.mjs, surface "hook") on PreToolUse, the one event
// the hook itself refuses when it cannot decide (failClosedApplies); every other event is "continue".
import { readFileSync, writeFileSync, mkdirSync, statSync, chmodSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { HOOK_PATH, FORWARDED_ENV, envHeader, MARKER_HEADER } from "./hook-http.mjs";

export const TRANSPORTS = Object.freeze(["command", "http"]);
export const HOOKD_DEFAULT_PORT = 8793;
// Seconds. Above moorai-hookd's own worker timeout (30 s), so the daemon answers a slow run itself.
export const HTTP_HOOK_TIMEOUT_S = 60;
export const HOOKD_TOKEN_FILE = "hookd.token";

export const tokenPath = (stateDir = STATE_DIR) => join(stateDir, HOOKD_TOKEN_FILE);

// The per-device bearer token moorai-hookd checks: 32 random bytes, hex, in a 0600 file. Created on first use;
// a file that others can read is narrowed to 0600.
export function hookdToken({ stateDir = STATE_DIR, create = true } = {}) {
  const p = tokenPath(stateDir);
  try {
    const t = readFileSync(p, "utf8").trim();
    if (/^[0-9a-f]{64}$/.test(t)) {
      try { if (statSync(p).mode & 0o077) chmodSync(p, 0o600); } catch { /* checked again at start-up */ }
      return t;
    }
  } catch { /* absent */ }
  if (!create) return "";
  const t = randomBytes(32).toString("hex");
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  writeFileSync(p, `${t}\n`, { mode: 0o600 });
  return t;
}

export function onFailureFor(event, failMode) {
  return event === "PreToolUse" && failMode === "closed" ? "block" : "continue";
}

// The http handler for one event. The token is written literally (Claude Code would read it from its own
// environment only through allowedEnvVars, which needs the user to export it); the forwarded variables are
// interpolated by Claude Code from its environment.
export function httpHandler({ event, port = HOOKD_DEFAULT_PORT, token, failMode = "open" }) {
  return {
    type: "http",
    url: `http://127.0.0.1:${port}${HOOK_PATH}`,
    headers: { Authorization: `Bearer ${token}`, [MARKER_HEADER]: "claude-code", ...Object.fromEntries(FORWARDED_ENV.map((n) => [envHeader(n), `\${${n}}`])) },
    allowedEnvVars: [...FORWARDED_ENV],
    timeout: HTTP_HOOK_TIMEOUT_S,
    onFailure: onFailureFor(event, failMode)
  };
}

export const isHttpHandler = (h) => !!h && h.type === "http" && typeof h.url === "string";
export const isHttpEntry = (e) => !!e && Array.isArray(e.hooks) && e.hooks.length > 0 && e.hooks.every(isHttpHandler);

// The installed transport across our entries: "http" when any of them is an http entry.
export function installedTransport(settings, ours) {
  const hooks = settings && settings.hooks && typeof settings.hooks === "object" ? settings.hooks : {};
  for (const list of Object.values(hooks)) if (Array.isArray(list) && list.filter(ours).some(isHttpEntry)) return "http";
  return "command";
}

// The URLs our http entries name (the doctor probes them).
export function httpUrls(settings, ours) {
  const out = new Set();
  const hooks = settings && settings.hooks && typeof settings.hooks === "object" ? settings.hooks : {};
  for (const list of Object.values(hooks)) if (Array.isArray(list)) for (const e of list.filter(ours)) if (isHttpEntry(e)) for (const h of e.hooks) out.add(h.url);
  return [...out];
}

// Our http handler for an event, rebuilt from one already installed (url and token kept), for converge.
export function httpTemplate(settings, ours) {
  const hooks = settings && settings.hooks && typeof settings.hooks === "object" ? settings.hooks : {};
  // PreToolUse first: its onFailure is the one that follows the fail mode.
  for (const [event, list] of Object.entries(hooks).sort(([a], [b]) => (b === "PreToolUse") - (a === "PreToolUse"))) {
    if (!Array.isArray(list)) continue;
    const e = list.filter(ours).find(isHttpEntry);
    if (e) return { event, handler: e.hooks[0] };
  }
  return null;
}

// Converge-time strengthening only: when the resolved fail mode is closed, every PreToolUse http entry of ours
// gets onFailure "block". A resolved "open" never relaxes a "block" here (a policy that failed to load must not
// weaken the device); `install` rewrites the entries from the fail mode it resolves.
export function strengthenOnFailure(settings, ours, failMode) {
  if (failMode !== "closed") return false;
  const list = settings && settings.hooks && Array.isArray(settings.hooks.PreToolUse) ? settings.hooks.PreToolUse : [];
  let changed = false;
  for (const e of list.filter(ours)) for (const h of e.hooks || []) if (isHttpHandler(h) && h.onFailure !== "block") { h.onFailure = "block"; changed = true; }
  return changed;
}

export function transportArg(argv) {
  const i = argv.indexOf("--hook-transport");
  const v = i >= 0 ? argv[i + 1] : "command";
  if (!TRANSPORTS.includes(v)) throw new Error(`--hook-transport must be one of ${TRANSPORTS.join(", ")}`);
  const j = argv.indexOf("--hookd-port");
  const port = j >= 0 ? Number(argv[j + 1]) : HOOKD_DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("--hookd-port must be 1-65535");
  return { transport: v, port };
}
