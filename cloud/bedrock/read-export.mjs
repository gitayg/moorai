// The export directory: AWS CLI JSON the customer produced (by hand, by their own pipeline, or with
// `--run --export DIR`), read into the same in-memory bundle the `--run` collector builds. Layout in
// commands.mjs. Only files named by the command table are read; nothing else in the directory is opened.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { COMMANDS } from "./commands.mjs";

export const REGION_RE = /^[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d{1,2}$/;
export const ACCOUNT_RE = /^\d{12}$/;
// Agent and action-group ids: `[0-9a-zA-Z]{10}` (API_agent_AgentSummary, API_agent_AgentActionGroup).
const KEY_RE = { agent: /^[0-9a-zA-Z]{10}$/, "action-group": /^[0-9a-zA-Z]{10}\.[0-9a-zA-Z]{10}$/ };

export const emptyBundle = () => ({ account: null, regions: {}, errors: [] });

function readJson(path, bundle, region, command) {
  try { return JSON.parse(readFileSync(path, "utf8")); }
  catch { bundle.errors.push({ region, command, class: "unreadable" }); return undefined; }
}

export function readExport(dir, { regions } = {}) {
  const b = emptyBundle();
  const acct = join(dir, "account.json");
  if (existsSync(acct)) {
    const a = readJson(acct, b, null, "account");
    if (a && ACCOUNT_RE.test(String(a.Account))) b.account = String(a.Account);
  }
  const found = readdirSync(dir).filter((n) => REGION_RE.test(n) && statSync(join(dir, n)).isDirectory()).sort();
  for (const region of found) {
    if (regions && !regions.includes(region)) continue;
    const out = (b.regions[region] = {});
    for (const c of COMMANDS) {
      if (c.scope === "region") {
        const f = join(dir, region, `${c.name}.json`);
        if (existsSync(f)) { const j = readJson(f, b, region, c.name); if (j !== undefined) out[c.name] = j; }
        continue;
      }
      const sub = join(dir, region, c.name);
      if (!existsSync(sub)) continue;
      out[c.name] = {};
      for (const fn of readdirSync(sub)) {
        const key = fn.replace(/\.json$/, "");
        if (!fn.endsWith(".json") || !KEY_RE[c.scope].test(key)) continue;
        const j = readJson(join(sub, fn), b, region, c.name);
        if (j !== undefined) out[c.name][key] = j;
      }
    }
  }
  return b;
}

// The inverse, for `--run --export DIR`. Keys are re-validated before they become file names.
export function writeExport(bundle, dir) {
  mkdirSync(dir, { recursive: true });
  if (bundle.account) writeFileSync(join(dir, "account.json"), JSON.stringify({ Account: bundle.account }, null, 2) + "\n");
  for (const [region, cmds] of Object.entries(bundle.regions)) {
    if (!REGION_RE.test(region)) continue;
    mkdirSync(join(dir, region), { recursive: true });
    for (const c of COMMANDS) {
      const v = cmds[c.name];
      if (v === undefined) continue;
      if (c.scope === "region") { writeFileSync(join(dir, region, `${c.name}.json`), JSON.stringify(v, null, 2) + "\n"); continue; }
      mkdirSync(join(dir, region, c.name), { recursive: true });
      for (const [key, obj] of Object.entries(v)) {
        if (KEY_RE[c.scope].test(key)) writeFileSync(join(dir, region, c.name, `${key}.json`), JSON.stringify(obj, null, 2) + "\n");
      }
    }
  }
}
