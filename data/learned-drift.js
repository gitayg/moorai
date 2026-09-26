// Learned per-agent drift — "this agent has never done THAT before".
//
// The entitlement envelope (#64, cli/hook-core.mjs decideEnvelope) is declared by hand: an org lists
// the tools, paths and MCP servers an agent may use. Most orgs never write one, so most agents run with
// no envelope at all. This module LEARNS one instead. Per actor (the same ACTOR key the behaviour log in
// cli/moorai-hook.mjs uses), it remembers which values of five kinds it has already seen:
//
//   tool           the tool name (Read, Bash, mcp__github__create_issue, ...)
//   mcp            the MCP server a tool call belongs to
//   host           a network destination host (data/model-endpoints.js extractHosts)
//   repo           the git repository the agent works in (normalised remote URL, else the repo root)
//   cloud-profile  a cloud credential profile named on a command line (AWS / gcloud / kube / az)
//
// During a learning period (the first N events or the first D days of an actor, whichever ends first)
// every value is recorded silently. After it, a value never seen before yields one "first seen" alert
// per type per actor per rate-limit window (default 24h). Report-only: nothing here changes allow/deny.
//
// Pure: state in, state + alerts out. The caller hashes every value with the keyed content hash before
// it gets here, so this module never holds a raw value, and neither does the state it returns. The I/O
// (read/write of the state file, repo discovery) lives in cli/drift-state.mjs.

export const DRIFT_TYPES = ["tool", "mcp", "host", "repo", "cloud-profile"];
const DAY = 86400000;
const HOUR = 3600000;

export const DRIFT_DEFAULTS = {
  mode: "alert",       // "alert" (report-only) | "off"
  learnEvents: 50,     // learning ends after this many events for the actor ...
  learnDays: 7,        // ... or this many days after the actor's first event, whichever comes first
  maxPerActor: 128,    // seen values kept per actor (LRU by last-seen)
  maxActors: 32,       // actors kept (LRU by last activity)
  rateLimitHours: 24   // one alert per type per actor per this many hours
};

const posInt = (v, d) => (Number.isFinite(v) && v >= 0 ? Math.floor(v) : d);

// policy.learnedDrift = { mode, learnEvents, learnDays, maxPerActor, maxActors, rateLimitHours }.
// Anything missing or malformed falls back to the default; mode is "off" only when set to exactly "off".
export function driftConfig(policy) {
  const p = policy && typeof policy.learnedDrift === "object" && policy.learnedDrift ? policy.learnedDrift : {};
  return {
    mode: p.mode === "off" ? "off" : "alert",
    learnEvents: posInt(p.learnEvents, DRIFT_DEFAULTS.learnEvents),
    learnDays: posInt(p.learnDays, DRIFT_DEFAULTS.learnDays),
    maxPerActor: Math.max(1, posInt(p.maxPerActor, DRIFT_DEFAULTS.maxPerActor)),
    maxActors: Math.max(1, posInt(p.maxActors, DRIFT_DEFAULTS.maxActors)),
    rateLimitHours: posInt(p.rateLimitHours, DRIFT_DEFAULTS.rateLimitHours)
  };
}

const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);

// Keep only well-formed actors; a broken file reads as an empty baseline (every actor back in learning,
// so a corrupted state file can only make the feature quieter, never louder).
function cleanState(state) {
  const out = { v: 1, actors: {} };
  const actors = state && typeof state === "object" && state.actors && typeof state.actors === "object" && !Array.isArray(state.actors) ? state.actors : {};
  for (const [k, a] of Object.entries(actors)) {
    if (!a || typeof a !== "object" || num(a.first) === null || num(a.n) === null || num(a.last) === null) continue;
    const seen = {}, alerted = {};
    if (a.seen && typeof a.seen === "object" && !Array.isArray(a.seen)) for (const [sk, t] of Object.entries(a.seen)) if (num(t) !== null) seen[sk] = t;
    if (a.alerted && typeof a.alerted === "object" && !Array.isArray(a.alerted)) for (const [ty, t] of Object.entries(a.alerted)) if (DRIFT_TYPES.includes(ty) && num(t) !== null) alerted[ty] = t;
    out.actors[k] = { first: a.first, n: a.n, last: a.last, seen, alerted };
  }
  return out;
}

// items = [{ type, key }] where key is ALREADY a keyed one-way hash. Returns the new state, the alerts to
// post ([{ type, key }]), whether the actor is still learning, and whether the state needs writing.
export function observeDrift(state, actor, items, now, cfg = driftConfig(null)) {
  const s = cleanState(state);
  let dirty = false;
  let a = s.actors[actor];
  if (!a) { a = s.actors[actor] = { first: now, n: 0, last: now, seen: {}, alerted: {} }; dirty = true; }
  const learning = a.n < cfg.learnEvents && now - a.first < cfg.learnDays * DAY;
  // n stops counting once it reaches the learning length, so after learning a call that sees only known
  // values writes nothing — the steady state is one small read per hook call.
  if (a.n < cfg.learnEvents) { a.n++; dirty = true; }
  if (now - a.last > HOUR) { a.last = now; dirty = true; }
  const alerts = [];
  for (const it of items || []) {
    if (!it || !DRIFT_TYPES.includes(it.type) || typeof it.key !== "string" || !it.key) continue;
    const k = `${it.type}|${it.key}`;
    if (Object.prototype.hasOwnProperty.call(a.seen, k)) {
      if (now - a.seen[k] > HOUR) { a.seen[k] = now; dirty = true; } // LRU refresh, at most hourly
      continue;
    }
    a.seen[k] = now; dirty = true;
    if (learning || cfg.mode === "off") continue;
    const lastAlert = a.alerted[it.type];
    if (lastAlert == null || now - lastAlert >= cfg.rateLimitHours * HOUR) {
      a.alerted[it.type] = now;
      alerts.push({ type: it.type, key: it.key });
    }
  }
  const keys = Object.keys(a.seen);
  if (keys.length > cfg.maxPerActor) {
    keys.sort((x, y) => a.seen[x] - a.seen[y]);
    for (const k of keys.slice(0, keys.length - cfg.maxPerActor)) delete a.seen[k];
    dirty = true;
  }
  const actors = Object.keys(s.actors);
  if (actors.length > cfg.maxActors) {
    const others = actors.filter((k) => k !== actor).sort((x, y) => s.actors[x].last - s.actors[y].last);
    for (const k of others.slice(0, actors.length - cfg.maxActors)) delete s.actors[k];
    dirty = true;
  }
  return { state: s, alerts, learning, events: a.n, baseline: Object.keys(a.seen).length, dirty };
}

// A git remote URL in one canonical form, so https / ssh / scp-style spellings of the same repository
// compare equal and credentials or ports never reach the hash input:
//   https://user:tok@GitHub.com:443/Acme/App.git  ->  github.com/acme/app
//   git@github.com:acme/app.git                    ->  github.com/acme/app
//   ssh://git@github.com/acme/app                  ->  github.com/acme/app
// A local-path remote comes back as its path without a trailing .git.
export function normalizeRemote(url) {
  let s = String(url || "").trim();
  if (!s) return "";
  let host = "", path = "";
  const scp = s.match(/^(?:[^@\s/]+@)?([A-Za-z0-9.-]+):(?!\/\/)(.+)$/);
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    try { const u = new URL(s); host = u.protocol === "file:" ? "" : u.hostname; path = decodeURIComponent(u.pathname); } catch { return ""; }
  } else if (scp && !/^[A-Za-z]$/.test(scp[1])) { // a Windows drive letter (C:\repo) is a path, not a host
    host = scp[1]; path = scp[2];
  } else {
    path = s;
  }
  path = path.replace(/\\/g, "/").replace(/\/+$/, "").replace(/\.git$/i, "").replace(/\/+$/, "");
  if (host) path = path.replace(/^\/+/, "");
  return (host ? `${host}/${path}` : path).toLowerCase();
}

// Cloud credential profiles named on a command line. Returns "provider:name" strings; the caller hashes
// them. `--profile` is only read after an AWS-family command, because cargo, npm and others take a
// `--profile` of their own that is not a credential. Every repetition is bounded so the regexes stay
// linear on hostile input.
const NAME = String.raw`["']?([A-Za-z0-9_.@:/-]{1,128})`;
const SEG = String.raw`[^;&|\n]{0,300}?`;
const PROFILE_RES = [
  ["aws", new RegExp(String.raw`\bAWS_(?:DEFAULT_)?PROFILE\s{0,4}=\s{0,4}${NAME}`, "g")],
  ["aws", new RegExp(String.raw`\b(?:aws|sam|cdk|copilot|eb)\b${SEG}\s--profile(?:=|\s{1,8})${NAME}`, "g")],
  ["gcloud", new RegExp(String.raw`\bCLOUDSDK_ACTIVE_CONFIG_NAME\s{0,4}=\s{0,4}${NAME}`, "g")],
  ["gcloud", new RegExp(String.raw`\bgcloud\b${SEG}\s--configuration(?:=|\s{1,8})${NAME}`, "g")],
  ["gcloud", new RegExp(String.raw`\bgcloud\s{1,8}config\s{1,8}configurations\s{1,8}activate\s{1,8}${NAME}`, "g")],
  ["kube", new RegExp(String.raw`\b(?:kubectl|oc)\b${SEG}\s--context(?:=|\s{1,8})${NAME}`, "g")],
  ["kube", new RegExp(String.raw`\bhelm\b${SEG}\s--kube-context(?:=|\s{1,8})${NAME}`, "g")],
  ["kube", new RegExp(String.raw`\b(?:kubectl|oc)\s{1,8}config\s{1,8}use-context\s{1,8}${NAME}`, "g")],
  ["kube", new RegExp(String.raw`(?<![\w-])kubectx\s{1,8}(?!-)${NAME}`, "g")],
  ["az", new RegExp(String.raw`\baz\s{1,8}account\s{1,8}set\b${SEG}\s(?:--subscription|-s)(?:=|\s{1,8})${NAME}`, "g")]
];
export function cloudProfiles(command) {
  const cmd = String(command || "").slice(0, 16384);
  const out = new Set();
  for (const [provider, re] of PROFILE_RES) {
    re.lastIndex = 0;
    for (const m of cmd.matchAll(re)) {
      const name = m[1].replace(/["']+$/, "");
      if (name && !name.startsWith("$")) out.add(`${provider}:${name}`);
    }
  }
  return [...out];
}
