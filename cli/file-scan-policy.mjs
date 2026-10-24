// The signed policy's `fileScan` object: whether, how and with which cloud provider MoorAI for AI Servers
// scans a file before it is sent to a model (model proxy, moorai-serve /v1/file-scan; cli/file-scan.mjs).
//
//   fileScan: {
//     provider:      "metadefender" (OPSWAT MetaDefender Cloud, the default) | "virustotal"
//     mode:          "off" (default) | "hash" (only the SHA-256 leaves) | "upload" (a file the hash lookup did
//                    not know is uploaded; explicit opt-in: see each provider module for what leaves and where)
//     onMalicious:   "block" (default) | "report"
//     onUnknown:     "allow" (default) | "ask" (no approver on a server: the headless rule, deny by default) | "block"
//     maxBytes:      largest file uploaded, default 33554432 (VirusTotal's direct-upload size); 1 - 681574400
//     timeoutMs:     the whole scan of one request's files, default 10000; 100 - 120000
//     iocHash:       true puts the raw SHA-256 in a MALICIOUS file's alert (a public indicator); default false
//     privateScan:   MetaDefender only: true sends samplesharing: 0 on upload (a paid licence feature)
//     region:        MetaDefender only: one of the documented regional endpoints by name (cli/file-scan-metadefender.mjs
//                    REGIONS); never a URL
//     ratePerMinute: provider requests per minute from this process, default 4 for VirusTotal (its public API)
//                    and 60 for MetaDefender; 1 - 10000
//   }
//
// The policy never carries an API key (cli/file-scan-keys.mjs). A value that is not one of the documented
// ones falls back to its default; a provider or mode that is not one turns scanning off.
import { REGIONS } from "./file-scan-metadefender.mjs";

export const PROVIDERS = Object.freeze(["metadefender", "virustotal"]);
export const MODES = Object.freeze(["off", "hash", "upload"]);
export const DEFAULT_RATE = Object.freeze({ metadefender: 60, virustotal: 4 });
export const FILE_SCAN_DEFAULTS = Object.freeze({ provider: "metadefender", mode: "off", onMalicious: "block", onUnknown: "allow", maxBytes: 33554432, timeoutMs: 10000, iocHash: false, privateScan: false, region: null });
const MAX_UPLOAD = 650 * 1024 * 1024;

const intIn = (v, lo, hi) => (Number.isInteger(v) && v >= lo && v <= hi ? v : null);

export function fileScanPolicy(policy) {
  const f = policy && typeof policy === "object" && policy.fileScan && typeof policy.fileScan === "object" && !Array.isArray(policy.fileScan) ? policy.fileScan : {};
  const problems = [];
  const pick = (k, allowed) => {
    if (f[k] === undefined) return FILE_SCAN_DEFAULTS[k];
    if (allowed.includes(f[k])) return f[k];
    problems.push(`fileScan.${k}`);
    return FILE_SCAN_DEFAULTS[k];
  };
  let mode = pick("mode", MODES);
  let provider = FILE_SCAN_DEFAULTS.provider;
  if (f.provider !== undefined) {
    if (PROVIDERS.includes(f.provider)) provider = f.provider;
    else { problems.push("fileScan.provider"); mode = "off"; }
  }
  if (f.mode !== undefined && !MODES.includes(f.mode)) mode = "off";
  const num = (k, lo, hi) => { if (f[k] === undefined) return null; const v = intIn(f[k], lo, hi); if (v === null) problems.push(`fileScan.${k}`); return v; };
  const region = f.region === undefined ? null : Object.prototype.hasOwnProperty.call(REGIONS, f.region) ? f.region : (problems.push("fileScan.region"), null);
  return {
    provider, mode,
    onMalicious: pick("onMalicious", ["block", "report"]),
    onUnknown: pick("onUnknown", ["allow", "ask", "block"]),
    maxBytes: num("maxBytes", 1, MAX_UPLOAD) ?? FILE_SCAN_DEFAULTS.maxBytes,
    timeoutMs: num("timeoutMs", 100, 120000) ?? FILE_SCAN_DEFAULTS.timeoutMs,
    iocHash: f.iocHash === true,
    privateScan: f.privateScan === true,
    region,
    ratePerMinute: num("ratePerMinute", 1, 10000) ?? DEFAULT_RATE[provider],
    problems
  };
}
