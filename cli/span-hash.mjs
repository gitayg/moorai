// The contentHash of a finding's matched span. For most threats it is the tenant-keyed hash (content-hash.mjs),
// so the console can correlate the same value across devices. For a threat whose value comes from a space small
// enough to enumerate (#90 cardholder data, data/cardholder.js), anyone holding the install token could hash
// every candidate and read the number back, so its hash is an HMAC under a key random to this process
// ("proc:" and 16 hex): the same span hashes alike within the process; nothing outside it — the console, another
// device, the next hook process — can link or reverse it. The model proxy does the same for a card or personal
// data in a reply (model-proxy/server.mjs findingHash).
import { createHmac, randomBytes } from "node:crypto";
import { contentHash } from "./content-hash.mjs";
import { PROCESS_KEYED_THREATS } from "../data/cardholder.js";

export const PROC_PREFIX = "proc:";
const KEY = randomBytes(32);
const PROCESS_KEYED = new Set(PROCESS_KEYED_THREATS);

export function processHash(s) {
  return PROC_PREFIX + createHmac("sha256", KEY).update(String(s == null ? "" : s), "utf8").digest("hex").slice(0, 16);
}

// tenantHash: the caller's tenant-keyed hash when it holds its own key (the Agent SDK, the model proxy).
export function spanHash(threatId, s, tenantHash = contentHash) {
  return PROCESS_KEYED.has(threatId) ? processHash(s) : tenantHash(s);
}
