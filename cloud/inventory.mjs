// Bundle → the inventory document this tool prints and posts. Refuses without an enrollment key: the
// keyed hash would otherwise be the constant h2:nokey for every resource (cli/content-hash.mjs), which is
// not an inventory.
import { hashWithKey } from "../cli/content-hash.mjs";
import { normalizeBedrock } from "./bedrock/normalize.mjs";
import { assertContentFree } from "./record-schema.mjs";

export const SCHEMA = "moorai.cloud-inventory/1";

export function buildInventory(bundle, { key } = {}) {
  if (!key) throw new Error("not enrolled: no install token in ~/.moorai/config.json, so resource ids cannot be keyed to your tenant");
  const hash = (s) => hashWithKey(key, s);
  const { account, records, errors } = normalizeBedrock(bundle, hash);
  assertContentFree(records);
  const inventory = { schema: SCHEMA, platform: "bedrock", account: hash(account), regions: Object.keys(bundle.regions).sort(), records };
  const flags = {};
  for (const r of records) for (const f of r.flags) flags[f] = (flags[f] || 0) + 1;
  return { inventory, errors, summary: { records: records.length, regions: inventory.regions.length, flags } };
}

// What POST /api/cloud-inventory accepts: exactly these four fields.
export const postBody = (inv) => ({ platform: inv.platform, account: inv.account, regions: inv.regions, records: inv.records });
