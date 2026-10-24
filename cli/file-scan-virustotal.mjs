// VirusTotal, API v3, as documented (read 2026-10-23):
//   https://docs.virustotal.com/reference/file-info — GET /api/v3/files/{id}, id "SHA-256, SHA-1 or MD5";
//     the key in the `x-apikey` header.
//   https://docs.virustotal.com/reference/files — last_analysis_stats: confirmed-timeout, failure, harmless,
//     malicious, suspicious, timeout, type-unsupported, undetected; last_analysis_results per engine
//     {category, engine_name, result}.
//   https://docs.virustotal.com/reference/files-scan — POST /api/v3/files, multipart field `file`, up to
//     32 MB; larger files through GET /files/upload_url (up to 650 MB); answers {data: {type: "analysis", id}}.
//     "Any IoC submitted or queried via the API will be scanned and added to the VirusTotal dataset".
//   https://docs.virustotal.com/reference/files-upload-url — {data: "<url>"}, "Each upload URL can be used only once".
//   https://docs.virustotal.com/reference/analyses-object — status "queued" | "in-progress" | "completed".
//   https://docs.virustotal.com/reference/errors — {error: {code, message}}; 404 NotFoundError; 429
//     QuotaExceededError / TooManyRequestsError; 401 WrongCredentialsError.
//   https://docs.virustotal.com/reference/public-vs-premium-api — the public API: "500 requests per day and a
//     rate of 4 requests per minute", and it "must not be used in commercial products or services".
//   https://docs.virustotal.com/docs/how-it-works — "Scanning reports produced by VirusTotal are shared with
//     the public VirusTotal community." "The contents of submitted files or pages may also be shared with
//     premium VirusTotal customers."
// WHAT LEAVES: hash mode, the SHA-256 in the URL path (a queried indicator is itself added to VirusTotal's
// dataset). Upload mode, the file's bytes — which VirusTotal may share with its premium customers, and whose
// report is public.
import { call, cleanThreat, int, FileScanError } from "./file-scan-http.mjs";

export const NAME = "virustotal";
export const DEFAULT_BASE = "https://www.virustotal.com/api/v3";
export const DIRECT_MAX = 32 * 1024 * 1024;

const total = (s) => Object.values(s && typeof s === "object" ? s : {}).reduce((n, v) => n + int(v), 0);
function threatOf(attrs, results) {
  const label = cleanThreat(attrs && attrs.popular_threat_classification && attrs.popular_threat_classification.suggested_threat_label);
  if (label) return label;
  const counts = new Map();
  for (const r of Object.values(results && typeof results === "object" ? results : {})) {
    if (!r || r.category !== "malicious") continue;
    const t = cleanThreat(r.result);
    if (t) counts.set(t, (counts.get(t) || 0) + 1);
  }
  let best, n = 0;
  for (const [t, c] of counts) if (c > n) { best = t; n = c; }
  return best;
}
// stats (+ attrs for the label, results for the engine names) -> the common result shape. Malicious when any
// engine says malicious; suspicious only -> unknown/suspicious; no engine verdict at all -> unknown/incomplete.
function verdictOf(stats, attrs, results) {
  const s = stats && typeof stats === "object" ? stats : {};
  const detections = int(s.malicious), engines = total(s);
  if (detections > 0) return { state: "found", verdict: "malicious", detections, engines, threat: threatOf(attrs, results) };
  if (int(s.suspicious) > 0) return { state: "unknown", why: "suspicious", detections: 0, engines };
  if (int(s.harmless) + int(s.undetected) > 0) return { state: "found", verdict: "clean", detections: 0, engines };
  return { state: "unknown", why: "incomplete", detections: 0, engines };
}

export function parseFile(body) {
  const attrs = body && body.data && body.data.attributes;
  if (!attrs || typeof attrs !== "object") throw new FileScanError("provider");
  return verdictOf(attrs.last_analysis_stats, attrs, attrs.last_analysis_results);
}
export function parseAnalysis(body) {
  const attrs = body && body.data && body.data.attributes;
  if (!attrs || typeof attrs !== "object") throw new FileScanError("provider");
  if (attrs.status !== "completed") return { state: "pending" };
  return verdictOf(attrs.stats, null, attrs.results);
}

export function createVirusTotal({ key, base = DEFAULT_BASE, fetch: fetchImpl = globalThis.fetch, directMax = DIRECT_MAX } = {}) {
  const root = String(base).replace(/\/+$/, "");
  const origin = new URL(root).origin;
  const auth = () => ({ "x-apikey": key });
  return {
    name: NAME,
    async lookup(sha256, { signal } = {}) {
      const r = await call(fetchImpl, `${root}/files/${sha256}`, { headers: auth(), signal });
      if (r.status === 404) return { state: "unknown", why: "not-found" };
      return parseFile(r.body);
    },
    async upload(bytes, { signal, filename = "file" } = {}) {
      let url = `${root}/files`;
      if (bytes.length > directMax) {
        const u = await call(fetchImpl, `${root}/files/upload_url`, { headers: auth(), signal });
        let target = null;
        try { target = typeof (u.body && u.body.data) === "string" ? new URL(u.body.data) : null; } catch { target = null; }
        // The key goes only to the provider's own origin, whatever URL the answer names.
        if (!target || target.origin !== origin) throw new FileScanError("provider");
        url = target.href;
      }
      const form = new FormData();
      form.append("file", new Blob([bytes]), String(filename).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 128) || "file");
      const r = await call(fetchImpl, url, { method: "POST", headers: auth(), body: form, signal });
      const id = r.body && r.body.data && r.body.data.id;
      if (typeof id !== "string" || !/^[A-Za-z0-9=_:-]{1,256}$/.test(id)) throw new FileScanError("provider", { status: r.status });
      return { id };
    },
    async poll(id, { signal } = {}) {
      const r = await call(fetchImpl, `${root}/analyses/${encodeURIComponent(id)}`, { headers: auth(), signal });
      if (r.status === 404) throw new FileScanError("provider", { status: 404 });
      return parseAnalysis(r.body);
    }
  };
}
