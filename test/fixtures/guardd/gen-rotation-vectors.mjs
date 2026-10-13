// Regenerate test/fixtures/guardd/policy-rotation-vectors.json:
//   node test/fixtures/guardd/gen-rotation-vectors.mjs > test/fixtures/guardd/policy-rotation-vectors.json
// Policy-key rotation scenarios shared by the JS hook (test/policy-key-rotation.test.mjs, end to end
// through cli/moorai-hook.mjs) and guardd's PolicyStore (a harness that feeds each step to
// PolicyStore::apply). Keys come from fixed seeds and ed25519 signatures are deterministic, so the file is
// stable across regenerations. Each step is one fetch: the /api/policy body and the /api/policy/pubkey
// body (null = 404). `expect` is the state after the step: pin keys (sorted base64 SPKI DER), whether
// this step's policy became the current one, and the content-free rejected (source, status) pairs from
// the server/nextKeys/revocation channels.
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const core = await import(join(ROOT, "cli", "hook-core.mjs"));
const TENANT = "acme";
const key = (n) => {
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, n)]), format: "der", type: "pkcs8" });
  return { priv, id: createPublicKey(priv).export({ type: "spki", format: "der" }).toString("base64"), pem: createPublicKey(priv).export({ type: "spki", format: "pem" }).toString() };
};
const K1 = key(1), K2 = key(2), K3 = key(3), EVIL = key(66);
const T = (min) => new Date(Date.parse("2026-10-12T09:00:00.000Z") + min * 60000).toISOString();
function signed(body, k, iat) {
  const p = { ...body };
  const msg = core.policyCanonical({ v: 1, tenant: TENANT, iat, digest: core.policyDigest(p) });
  p.policySig = { v: 1, alg: "ed25519", tenant: TENANT, iat, sig: sign(null, Buffer.from(msg), k.priv).toString("base64") };
  return JSON.stringify(p);
}
const pub = (...ks) => JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: ks[0].id, keys: ks.map((k) => k.id) });
const pin = (...ks) => ks.map((k) => k.id).sort();
const rej = (source, status) => ({ source, status });
const first = { policy: signed({}, K1, T(0)), published: pub(K1), expect: { pin: pin(K1), accepted: true, rejected: [] } };

const scenarios = [
  {
    name: "impersonator replays the current policy and publishes its own key",
    steps: [
      first,
      { policy: signed({}, K1, T(0)), published: pub(K1, EVIL), expect: { pin: pin(K1), accepted: true, rejected: [] } },
      { policy: signed({ threatPolicy: {} }, EVIL, T(5)), published: pub(EVIL), expect: { pin: pin(K1), accepted: false, rejected: [rej("server", "untrusted")] } }
    ]
  },
  {
    name: "signed nextKeys newer than the mark rotates, then revocation",
    steps: [
      first,
      { policy: signed({ nextKeys: [K2.id] }, K1, T(1)), published: null, expect: { pin: pin(K1, K2), accepted: true, rejected: [] } },
      { policy: signed({ a: 2 }, K2, T(2)), published: null, expect: { pin: pin(K1, K2), accepted: true, rejected: [] } },
      { policy: signed({ revokedKeys: [K1.id] }, K2, T(3)), published: null, expect: { pin: pin(K2), accepted: true, rejected: [] } },
      { policy: signed({ revokedKeys: [K2.id] }, K2, T(4)), published: null, expect: { pin: pin(K2), accepted: true, rejected: [rej("revocation", "self")] } }
    ]
  },
  {
    name: "nextKeys in PEM form",
    steps: [first, { policy: signed({ nextKeys: [K2.pem] }, K1, T(1)), published: null, expect: { pin: pin(K1, K2), accepted: true, rejected: [] } }]
  },
  {
    name: "replayed nextKeys at or below the mark teaches nothing",
    steps: [
      first,
      { policy: signed({ nextKeys: [K3.id] }, K1, T(0)), published: pub(K1, K3), expect: { pin: pin(K1), accepted: true, rejected: [rej("nextKeys", "not-newer")] } },
      { policy: signed({ nextKeys: [K3.id] }, K1, T(-60)), published: null, expect: { pin: pin(K1), accepted: false, rejected: [rej("server", "rollback")] } },
      { policy: signed({ b: 1 }, K3, T(6)), published: null, expect: { pin: pin(K1), accepted: false, rejected: [rej("server", "untrusted")] } }
    ]
  },
  {
    name: "first contact pins only the verifying key, nextKeys counts from the next fetch",
    steps: [
      { policy: signed({ nextKeys: [K2.id] }, K1, T(0)), published: pub(K1), expect: { pin: pin(K1), accepted: true, rejected: [] } },
      { policy: signed({ nextKeys: [K2.id] }, K1, T(1)), published: null, expect: { pin: pin(K1, K2), accepted: true, rejected: [] } }
    ]
  },
  {
    name: "first contact with no published key forms no pin",
    steps: [{ policy: signed({}, K1, T(0)), published: null, expect: { pin: [], accepted: true, rejected: [] } }]
  }
];

const canonical = [
  { name: "base64 SPKI", policy: { nextKeys: [K2.id] }, keys: [K2.id] },
  { name: "PEM", policy: { nextKeys: [K2.pem] }, keys: [K2.id] },
  { name: "junk and non-strings dropped, duplicates collapsed", policy: { nextKeys: [K2.id, "junk", 7, null, "", K2.pem] }, keys: [K2.id] },
  { name: "not an array", policy: { nextKeys: K2.id }, keys: [] },
  { name: "absent", policy: {}, keys: [] }
];

console.log(JSON.stringify({ comment: "generated by test/fixtures/guardd/gen-rotation-vectors.mjs; shared by the JS hook and guardd PolicyStore", tenant: TENANT, scenarios, canonical }, null, 1));
