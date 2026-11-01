#!/usr/bin/env node
// moorai-profile — declared workload profiles from the device's side. `learn` drafts one from what MoorAI
// already recorded on this device (the session ledger and the destination map), in report mode, with the
// diff against the profile in force. Local only: it reads on-device records and the cached verified
// policy, writes nothing but --out, and sends nothing anywhere. See cli/profile-learn.mjs.
//
//   moorai-profile learn --service-id ci-build                 report + draft on stdout
//   moorai-profile learn --repo github:acme/app --days 30 --json
//   moorai-profile learn --service-id ci-build --out draft.json
import { readFileSync, writeFileSync } from "node:fs";
import { readDestinations, DESTINATIONS_PATH } from "./signals.mjs";
import { readLedgerRows } from "./session-ledger.mjs";
import { learnProfile, formatLearn, DEFAULT_DAYS, DEFAULT_MIN_SESSIONS, DEFAULT_MIN_DAYS } from "./profile-learn.mjs";

const HELP = `usage: moorai-profile learn (--service-id <id> | --repo <remote>) [options]

Drafts a declared workload profile from this device's own records, in report mode:
  tools and MCP servers   from the session ledger (every PreToolUse call)
  hosts                   from the destination map (${DESTINATIONS_PATH})
Names and hosts only: no path, command, argument or response is read or written. Calls MoorAI
denied (or coached) are not learned. Nothing is sent anywhere.

  --service-id <id>     match.serviceId of the draft (server mode's workload name); hosts are
                        narrowed to that workload's records
  --repo <remote>       match.repo of the draft (github:owner/name, gitlab:group/name, host:path)
  --days <n>            observation window in days, ending at --until (default ${DEFAULT_DAYS})
  --until <date>        window end (default now)
  --id <slug>           draft profile id (default learned-<serviceId or repo>)
  --min-sessions <n>    refuse with fewer sessions observed (default ${DEFAULT_MIN_SESSIONS})
  --min-days <n>        refuse with fewer distinct days observed (default ${DEFAULT_MIN_DAYS})
  --force               write the draft even when too little was observed (warning kept)
  --policy <file>       compare with the workloadProfiles in this JSON (a policy or a list)
                        instead of the device's verified policy and machine-wide config
  --compare <id>        compare with this profile id instead of the one that matches
  --json                print { profile, observation, diff, excluded, skipped, warnings }
  --out <file>          also write the draft profile alone to <file>

Exit 0 with a draft, 3 when too little was observed (without --force), 2 on a usage error.
Adopt the draft by adding it to the policy's workloadProfiles list; flip "action" to "block"
once report mode shows no drift.`;

function fail(msg) { process.stderr.write(`moorai-profile: ${msg}\n`); process.exit(2); }

function parse(argv) {
  const o = {};
  const VALUED = new Set(["--service-id", "--repo", "--days", "--until", "--id", "--min-sessions", "--min-days", "--policy", "--compare", "--out"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") o.help = true;
    else if (a === "--json") o.json = true;
    else if (a === "--force") o.force = true;
    else if (VALUED.has(a)) { if (i + 1 >= argv.length) fail(`${a} needs a value`); o[a.slice(2)] = argv[++i]; }
    else if (!o.cmd && !a.startsWith("-")) o.cmd = a;
    else fail(`unknown argument ${a}`);
  }
  return o;
}

function num(v, name) {
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) fail(`${name} must be a non-negative number`);
  return n;
}

// The documents the profiles in force come from: --policy, or the device's verified policy (loaded from
// its local cache with the console unreachable, as moorai-doctor does) and the root-owned machine config.
async function declaredDocs(file) {
  if (file) {
    let doc;
    try { doc = JSON.parse(readFileSync(file, "utf8")); } catch (e) { fail(`--policy ${file}: ${e.message}`); }
    return { policy: Array.isArray(doc) ? { workloadProfiles: doc } : doc, system: null };
  }
  const out = { policy: null, system: null };
  try {
    const { loadConfig } = await import("./config.mjs");
    const { loadPolicyReadOnly } = await import("./doctor-policy.mjs");
    const loaded = loadPolicyReadOnly(loadConfig(), { offline: true });
    if (loaded && loaded.policy) out.policy = loaded.policy;
  } catch { /* no verified policy: compare with the machine config only */ }
  try { const { systemConfig } = await import("./server-mode.mjs"); out.system = systemConfig(); } catch { /* none */ }
  return out;
}

const o = parse(process.argv.slice(2));
if (o.help || !o.cmd) { process.stdout.write(HELP + "\n"); process.exit(o.help ? 0 : 2); }
if (o.cmd !== "learn") fail(`unknown command ${o.cmd} (try: learn)`);

const r = learnProfile({
  destinations: readDestinations(),
  sessionRows: readLedgerRows(),
  serviceId: o["service-id"],
  repo: o.repo,
  id: o.id,
  days: num(o.days, "--days") ?? DEFAULT_DAYS,
  until: o.until === undefined ? Date.now() : o.until,
  minSessions: num(o["min-sessions"], "--min-sessions") ?? DEFAULT_MIN_SESSIONS,
  minDays: num(o["min-days"], "--min-days") ?? DEFAULT_MIN_DAYS,
  declared: await declaredDocs(o.policy),
  compareId: o.compare
});
if (!r.ok) fail(r.error);
if (r.thin && !o.force) {
  const w = r.warnings.find((x) => x.code === "thin-data");
  if (o.json) process.stdout.write(JSON.stringify({ ok: false, refused: "thin-data", observation: r.observation, warnings: r.warnings }, null, 2) + "\n");
  process.stderr.write(`moorai-profile: too little observed to draft a profile — ${w.text}. Widen --days, wait for more sessions, or pass --force.\n`);
  process.exit(3);
}
if (o.out) writeFileSync(o.out, JSON.stringify(r.profile, null, 2) + "\n");
if (o.json) {
  const { profile, observation, items, diff, excluded, skipped, warnings } = r;
  process.stdout.write(JSON.stringify({ ok: true, profile, observation, items, diff, excluded, skipped, warnings }, null, 2) + "\n");
} else process.stdout.write(formatLearn(r));
