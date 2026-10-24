// cli/quarantine-owner.mjs with the peer's uids shifted by 1000 (a different OS user). See quarantine-peer-register.mjs.
import * as real from "../../cli/quarantine-owner.mjs?real";
export * from "../../cli/quarantine-owner.mjs?real";
export function verifyReaderPeer(o) {
  return real.verifyReaderPeer({ ...o, gather: (a) => { const f = real.peerFacts(a); if (Array.isArray(f.uids)) f.uids = f.uids.map((u) => u + 1000); return f; } });
}
