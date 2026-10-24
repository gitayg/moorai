// Where a cloud file-scanning provider's API key comes from — only the server's own administrator:
//   1. the root-owned admin binding (/etc/moorai/config.json; %ProgramData% on Windows), key "fileScanKeys":
//      { "metadefender": "...", "virustotal": "..." } — read through cli/server-mode.mjs systemConfig(), which
//      ignores the file unless root-owned and not group/world-writable;
//   2. a key file per provider (--file-scan-key-file metadefender=/etc/moorai/metadefender.key), read only when
//      root-owned and not group/world-writable (hook-core readRootOwned); its first line is the key;
//   3. the server's environment: MOORAI_METADEFENDER_API_KEY, MOORAI_VIRUSTOTAL_API_KEY.
// Never from the signed policy (the console would then hold every tenant's provider keys, and the policy
// is readable by the agent's user), never logged, never in an alert or a posture report, never sent anywhere
// but the provider's documented header. A value that is not 8-512 printable non-space ASCII characters is
// ignored (nothing about it is printed).
import { readRootOwned } from "./hook-core.mjs";

export const KEY_ENV = Object.freeze({ metadefender: "MOORAI_METADEFENDER_API_KEY", virustotal: "MOORAI_VIRUSTOTAL_API_KEY" });
const KEY_RE = /^[\x21-\x7e]{8,512}$/;
const clean = (v) => { const s = typeof v === "string" ? v.trim() : ""; return KEY_RE.test(s) ? s : ""; };

export function loadFileScanKeys({ admin = null, keyFiles = {}, env = process.env, read = readRootOwned } = {}) {
  const keys = {}, sources = {};
  const table = admin && typeof admin === "object" && admin.fileScanKeys && typeof admin.fileScanKeys === "object" ? admin.fileScanKeys : {};
  for (const p of Object.keys(KEY_ENV)) {
    const fromAdmin = clean(table[p]);
    if (fromAdmin) { keys[p] = fromAdmin; sources[p] = "admin"; continue; }
    const path = keyFiles && typeof keyFiles[p] === "string" ? keyFiles[p] : "";
    const fromFile = path ? clean(String(read(path) || "").split(/\r?\n/)[0]) : "";
    if (fromFile) { keys[p] = fromFile; sources[p] = "file"; continue; }
    const fromEnv = clean(env && env[KEY_ENV[p]]);
    if (fromEnv) { keys[p] = fromEnv; sources[p] = "env"; }
  }
  return { keys, sources };
}
