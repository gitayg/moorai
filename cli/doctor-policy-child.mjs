// Child process for cli/doctor-policy.mjs. Runs the hook's OWN policy loader (loadVerifiedPolicy) with
// HOME pointed at a sandbox copy of the device state, so whatever the loader writes (cache, pin,
// last-known-good) lands in the copy. The config arrives on stdin, never argv or env, and is never
// written to disk. Prints one JSON object: the selected policy plus content-free trust facts.
import { loadVerifiedPolicy, verifyPolicySignature, publicKeyId, policyDigest } from "./hook-core.mjs";
import { createHash } from "node:crypto";

const fp = (s) => createHash("sha256").update(String(s)).digest("hex").slice(0, 12);

async function readStdin() { const c = []; for await (const x of process.stdin) c.push(x); return Buffer.concat(c).toString("utf8"); }

const config = JSON.parse((await readStdin()) || "{}");
const t0 = Date.now();
const r = await loadVerifiedPolicy(config);
const ms = Date.now() - t0;
const keys = (r.trust && r.trust.keys) || [];
const sig = r.policy ? verifyPolicySignature(r.policy, { keys, tenant: config.tenant }) : null;
let digest = "";
try { digest = r.policy ? fp(policyDigest(r.policy)) : ""; } catch { /* malformed body */ }
process.stdout.write(JSON.stringify({
  policy: r.policy,
  source: r.source,
  lkgCopy: r.lkgCopy || "",
  rejected: r.rejected || [],
  trustMode: r.trust ? r.trust.mode : "",
  trustKeys: keys.map((k) => fp(publicKeyId(k))),
  pin: r.pin ? { pinned: !!r.pin.pinned, corrupt: !!r.pin.corrupt, evidenceMissing: !!r.pin.evidenceMissing, tenantConflict: !!r.pin.tenantConflict, keys: (r.pin.keys || []).map(fp), iat: r.pin.iat || "", states: r.pin.states || {} } : null,
  absence: r.absence || null,
  signature: sig ? sig.status : "",
  signed: !!(r.policy && r.policy.policySig && r.policy.policySig.sig),
  iat: (r.policy && r.policy.policySig && r.policy.policySig.iat) || "",
  digest,
  ms
}));
