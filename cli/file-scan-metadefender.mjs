// OPSWAT MetaDefender Cloud, API v4, as documented (read 2026-10-23):
//   https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4 — base https://api.metadefender.com/v4;
//     GET /hash/{hash} (MD5, SHA-1 or SHA-256), POST /file (upload), GET /file/{dataId} (the result);
//     "Free API users are sent to different queues with a lower priority"; the upload size limit is per key
//     (max_upload_file_size, MB).
//   https://www.opswat.com/docs/mdcloud/integrations/api-authentication-mechanisms — "MetaDefender Cloud v4
//     API uses the custom HTTP header apikey. Every request must send this header."; the upload names the
//     file in a `filename` header.
//   https://www.opswat.com/docs/mdcloud/integrations/rate-limiting — HTTP 429 over a limit;
//     X-RateLimit-Reset-In is the seconds left in the window.
//   https://www.opswat.com/docs/mdcloud/integrations/throttling — free 9 requests/hour, standard licence 75
//     requests/minute, professional 150, enterprise 500+ (uploads and bulk lookups).
//   https://www.opswat.com/docs/mdcloud/integrations/description-on-scan-result-codes — scan_all_result_i.
//   https://www.opswat.com/docs/mdcloud/operation/private-scanning-with-metadefender-cloud-apis — the
//     `samplesharing` header (paid licence only): "All files scanned in private mode are not stored or shared."
//   https://www.opswat.com/docs/mdcloud/compliance/locations — the regional endpoints (REGIONS below).
// WHAT LEAVES: hash mode, the SHA-256 in the URL path. Upload mode, the file's bytes (POST /file) to
// OPSWAT's cloud; by default "submitting a file gives OPSWAT permission to share results with the
// cybersecurity community" (private-scanning page); with fileScan.privateScan, samplesharing: 0.
import { call, cleanThreat, int, FileScanError } from "./file-scan-http.mjs";

export const NAME = "metadefender";
export const DEFAULT_BASE = "https://api.metadefender.com/v4";
export const REGIONS = Object.freeze({
  "us-west": "https://api-prod-uswest2.metadefender.com/v4",
  "eu-central": "https://api-prod-eucentral1.metadefender.com/v4",
  "ca-central": "https://api-prod-cacentral1.metadefender.com/v4",
  "ap-southeast": "https://api-prod-apsoutheast2.metadefender.com/v4",
  "ap-northeast": "https://api-prod-apnortheast1.metadefender.com/v4",
  "ap-south": "https://api-prod-apsouth1.metadefender.com/v4",
  "il-central": "https://api-prod-ilcentral1.metadefender.com/v4"
});

// scan_all_result_i (the documented code table): 1 Infected/Known, 8 Skipped Infected, 27 Likely Malicious
// and 28 Malicious (sandbox) are malicious; 0 No Threats Found and 7 Skipped Clean are clean; 2 Suspicious,
// 18 Potentially Vulnerable File and 26 Suspicious (sandbox) are suspicious (onUnknown decides); 254 In queue
// and 255 In progress are pending; 253 "Not Scanned. Rate Limit Exceeded" is a rate limit; every other code
// (failed, encrypted, archive limits, not supported, empty …) is an incomplete scan.
const MALICIOUS = new Set([1, 8, 27, 28]);
const CLEAN = new Set([0, 7]);
const SUSPICIOUS = new Set([2, 18, 26]);
const PENDING = new Set([254, 255]);

function threatOf(body, details) {
  const top = cleanThreat(body && body.threat_name);
  if (top) return top;
  const counts = new Map();
  for (const d of Object.values(details && typeof details === "object" ? details : {})) {
    const t = cleanThreat(d && d.threat_found);
    if (t) counts.set(t, (counts.get(t) || 0) + 1);
  }
  let best, n = 0;
  for (const [t, c] of counts) if (c > n) { best = t; n = c; }
  return best;
}

// A hash-lookup or file-result body -> { state: "found", verdict, detections, engines, threat }
// | { state: "unknown", why } | { state: "pending" }.
export function parseReport(body) {
  const sr = body && typeof body === "object" ? body.scan_results : null;
  if (!sr || typeof sr !== "object") return { state: "unknown", why: "not-found" };
  const code = sr.scan_all_result_i;
  const progress = sr.progress_percentage;
  if (code === 253) throw new FileScanError("rate-limit");
  if (PENDING.has(code) || (typeof progress === "number" && progress < 100)) return { state: "pending" };
  const detections = int(sr.total_detected_avs), engines = int(sr.total_avs);
  if (MALICIOUS.has(code)) return { state: "found", verdict: "malicious", detections, engines, threat: threatOf(body, sr.scan_details) };
  if (CLEAN.has(code)) return { state: "found", verdict: "clean", detections, engines };
  return { state: "unknown", why: SUSPICIOUS.has(code) ? "suspicious" : "incomplete", detections, engines };
}

export function createMetaDefender({ key, base = DEFAULT_BASE, fetch: fetchImpl = globalThis.fetch, privateScan = false } = {}) {
  const root = String(base).replace(/\/+$/, "");
  const auth = () => ({ apikey: key });
  return {
    name: NAME,
    async lookup(sha256, { signal } = {}) {
      const r = await call(fetchImpl, `${root}/hash/${sha256}`, { headers: auth(), signal });
      if (r.status === 404) return { state: "unknown", why: "not-found" };
      const p = parseReport(r.body);
      // A hash whose scan is still running: its data_id is the thing to poll.
      if (p.state === "pending") return r.body && typeof r.body.data_id === "string" ? { state: "pending", id: r.body.data_id } : { state: "unknown", why: "incomplete" };
      return p;
    },
    async upload(bytes, { signal, filename = "file" } = {}) {
      const headers = { ...auth(), "content-type": "application/octet-stream", filename: String(filename).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 128) || "file" };
      if (privateScan) headers.samplesharing = "0";
      const r = await call(fetchImpl, `${root}/file`, { method: "POST", headers, body: bytes, signal });
      const id = r.body && r.body.data_id;
      if (typeof id !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(id)) throw new FileScanError("provider", { status: r.status });
      return { id };
    },
    async poll(id, { signal } = {}) {
      const r = await call(fetchImpl, `${root}/file/${encodeURIComponent(id)}`, { headers: auth(), signal });
      if (r.status === 404) throw new FileScanError("provider", { status: 404 });
      return parseReport(r.body);
    }
  };
}
