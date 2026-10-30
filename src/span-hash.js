// Browser-side twin of cli/span-hash.mjs (read that file first). A #90 cardholder-data finding's contentHash is an
// HMAC under a key random to this page ("proc:" and 16 hex), not the tenant-keyed hash, which the install token
// could enumerate back to the card number. Every other threat keeps contentHash().
import { hashWithKey, contentHash, HASH_PREFIX } from "./content-hash.js";
import { PROCESS_KEYED_THREATS } from "../data/cardholder.js";

export const PROC_PREFIX = "proc:";
const KEY = globalThis.crypto.getRandomValues(new Uint8Array(32));

export function spanHash(threatId, s) {
  return PROCESS_KEYED_THREATS.includes(threatId) ? PROC_PREFIX + hashWithKey(KEY, s).slice(HASH_PREFIX.length) : contentHash(s);
}
