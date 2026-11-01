// This device's owner as the MCP gateway and the model proxy see it (cli/owner-assertion.mjs): the console-signed
// assertion in ~/.moorai/agent-owner.json, checked with the keys that verify this device's policy (anchor or pin) for the
// device key the verifiers check session tokens against. The keys are re-read at most every 30 s.
import { policyTrustKeys } from "./hook-core.mjs";
import { deviceOwner } from "./owner-assertion.mjs";
import { devicePublicKey, keyIdOf } from "./agent-session-identity.mjs";

let keysAt = 0, keys = [];
// → { status: "ok" | "none" | "untrusted" | "foreign" | "expired" | "invalid", oid?, aid? }.
export function localOwner(tenant, { now = Date.now() } = {}) {
  if (!keysAt || now - keysAt > 30000) { keys = policyTrustKeys({ tenant }); keysAt = now; }
  const pub = devicePublicKey();
  if (!pub) return { status: "none" };
  return deviceOwner({ keys, tenant: String(tenant || ""), kid: keyIdOf(pub), now });
}
