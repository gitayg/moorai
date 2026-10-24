// Fake MetaDefender Cloud v4 and VirusTotal v3 servers for the file-scan tests. The response shapes follow
// each provider's documentation (cli/file-scan-metadefender.mjs and cli/file-scan-virustotal.mjs name the
// pages); nothing real is called and no real key exists anywhere. Each fake records every request it saw
// (method, path, headers, body length and bytes) so a test can assert what left the server.
import http from "node:http";
import { createHash } from "node:crypto";

export const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
export const TEST_KEY = "test-key-NOT-REAL-7f3a9c1e5b2d4086";

function serve(handler) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const r = { method: req.method, url: req.url, path: req.url.split("?")[0], headers: req.headers, body: Buffer.concat(chunks) };
      requests.push(r);
      Promise.resolve(handler(r, res)).catch(() => { try { res.writeHead(500); res.end(); } catch { /* closed */ } });
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({
    url: `http://127.0.0.1:${server.address().port}`,
    requests,
    server,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); })
  })));
}
const json = (res, status, body, headers = {}) => { const b = Buffer.from(JSON.stringify(body)); res.writeHead(status, { "content-type": "application/json", "content-length": b.length, ...headers }); res.end(b); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// MetaDefender Cloud: GET /v4/hash/{hash}, POST /v4/file, GET /v4/file/{data_id}; header `apikey`.
// known: sha256 -> { result: scan_all_result_i, detected, total, threat }. Uploaded files become known
// after `pendingPolls` polls. opts.delayMs delays every answer; opts.rateLimit answers 429 (documented body).
export async function startMetaDefender({ key = TEST_KEY, known = {}, pendingPolls = 1, delayMs = 0, rateLimit = false, uploadVerdict = { result: 0, detected: 0, total: 30 } } = {}) {
  const state = { known: { ...known }, uploads: new Map(), rateLimit, delayMs };
  const report = (h, v, progress = 100) => ({
    data_id: `d-${h.slice(0, 12)}`,
    scan_results: {
      scan_details: v.threat ? { EngineA: { threat_found: v.threat, scan_result_i: 1, def_time: "2026-10-01T00:00:00.000Z" }, EngineB: { threat_found: "", scan_result_i: 0 } } : { EngineA: { threat_found: "", scan_result_i: 0 } },
      scan_all_result_i: progress < 100 ? 255 : v.result,
      scan_all_result_a: progress < 100 ? "In Progress" : v.result === 1 ? "Infected" : v.result === 0 ? "No Threat Detected" : "Suspicious",
      total_avs: v.total ?? 30, total_detected_avs: v.detected ?? 0, progress_percentage: progress
    },
    file_info: { sha256: h.toUpperCase(), file_size: 12 }
  });
  const f = await serve(async (r, res) => {
    if (state.delayMs) await sleep(state.delayMs);
    if (r.headers.apikey !== key) return json(res, 401, { error: { code: 401006, messages: ["Invalid API key"] } });
    if (state.rateLimit) return json(res, 429, { error: { code: 429000, messages: ["Rate limit exceeded, retry after the limit is reset. Limit: 100 requests / day"] } }, { "x-ratelimit-limit": "100", "x-ratelimit-remaining": "0", "x-ratelimit-reset-in": "60s" });
    let m;
    if (r.method === "GET" && (m = /^\/v4\/hash\/([0-9A-Fa-f]{64})$/.exec(r.path))) {
      const h = m[1].toLowerCase();
      const v = state.known[h];
      if (!v) return json(res, 404, { error: { code: 404003, messages: ["The hash was not found"] } });
      return json(res, 200, report(h, v));
    }
    if (r.method === "POST" && r.path === "/v4/file") {
      const h = sha256(r.body);
      const id = `up${state.uploads.size + 1}${h.slice(0, 8)}`;
      state.uploads.set(id, { h, polls: 0 });
      return json(res, 200, { data_id: id, status: "inqueue", in_queue: 1, queue_priority: "normal", sha1: "", sha256: h });
    }
    if (r.method === "GET" && (m = /^\/v4\/file\/([A-Za-z0-9]+)$/.exec(r.path))) {
      const u = state.uploads.get(m[1]);
      if (!u) return json(res, 404, { error: { code: 404008, messages: ["The data_id was not found"] } });
      u.polls++;
      if (u.polls <= pendingPolls) return json(res, 200, report(u.h, uploadVerdict, 40));
      return json(res, 200, report(u.h, uploadVerdict));
    }
    return json(res, 404, { error: { code: 404000, messages: ["not found"] } });
  });
  return Object.assign(f, { state, base: `${f.url}/v4` });
}

// VirusTotal: GET /api/v3/files/{id}, POST /api/v3/files (multipart, field `file`), GET /api/v3/files/upload_url,
// GET /api/v3/analyses/{id}; header `x-apikey`. known: sha256 -> { malicious, suspicious, undetected, harmless, label }.
export async function startVirusTotal({ key = TEST_KEY, known = {}, pendingPolls = 1, delayMs = 0, rateLimit = false, uploadVerdict = { malicious: 0, undetected: 60 } } = {}) {
  const state = { known: { ...known }, analyses: new Map(), rateLimit, delayMs };
  const stats = (v) => ({ "confirmed-timeout": 0, failure: 0, harmless: v.harmless || 0, malicious: v.malicious || 0, suspicious: v.suspicious || 0, timeout: 0, "type-unsupported": 0, undetected: v.undetected || 0 });
  const results = (v) => (v.malicious ? { EngineA: { category: "malicious", engine_name: "EngineA", result: v.engineResult || "Trojan.Generic", method: "blacklist" }, EngineB: { category: "undetected", engine_name: "EngineB", result: null, method: "blacklist" } } : { EngineB: { category: "undetected", engine_name: "EngineB", result: null, method: "blacklist" } });
  let f;
  f = await serve(async (r, res) => {
    if (state.delayMs) await sleep(state.delayMs);
    if (r.headers["x-apikey"] !== key) return json(res, 401, { error: { code: "WrongCredentialsError", message: "Wrong API key" } });
    if (state.rateLimit) return json(res, 429, { error: { code: "QuotaExceededError", message: "Quota exceeded" } });
    let m;
    if (r.method === "GET" && r.path === "/api/v3/files/upload_url") return json(res, 200, { data: `${f.url}/_ah/upload/fake-once` });
    if (r.method === "GET" && (m = /^\/api\/v3\/files\/([0-9a-fA-F]{64})$/.exec(r.path))) {
      const h = m[1].toLowerCase();
      const v = state.known[h];
      if (!v) return json(res, 404, { error: { code: "NotFoundError", message: `File "${h}" not found` } });
      return json(res, 200, { data: { id: h, type: "file", attributes: { sha256: h, last_analysis_stats: stats(v), last_analysis_results: results(v), ...(v.label ? { popular_threat_classification: { suggested_threat_label: v.label } } : {}) } } });
    }
    if (r.method === "POST" && (r.path === "/api/v3/files" || r.path === "/_ah/upload/fake-once")) {
      const ct = String(r.headers["content-type"] || "");
      const b = /boundary=(.+)$/.exec(ct);
      if (!b) return json(res, 400, { error: { code: "BadRequestError", message: "not multipart" } });
      // The file part's bytes: between the first blank line after the part headers and the closing boundary.
      const raw = r.body;
      const start = raw.indexOf("\r\n\r\n") + 4;
      const end = raw.lastIndexOf(Buffer.from(`\r\n--${b[1].replace(/^"|"$/g, "")}`));
      const fileBytes = raw.subarray(start, end);
      const id = `an-${state.analyses.size + 1}`;
      state.analyses.set(id, { h: sha256(fileBytes), polls: 0, size: fileBytes.length });
      return json(res, 200, { data: { type: "analysis", id, links: { self: `${f.url}/api/v3/analyses/${id}` } } });
    }
    if (r.method === "GET" && (m = /^\/api\/v3\/analyses\/([A-Za-z0-9-]+)$/.exec(r.path))) {
      const a = state.analyses.get(m[1]);
      if (!a) return json(res, 404, { error: { code: "NotFoundError", message: "not found" } });
      a.polls++;
      const done = a.polls > pendingPolls;
      return json(res, 200, { data: { id: m[1], type: "analysis", attributes: { status: done ? "completed" : "queued", stats: done ? stats(uploadVerdict) : stats({}), results: done ? results(uploadVerdict) : {} } }, meta: { file_info: { sha256: a.h, size: a.size } } });
    }
    return json(res, 404, { error: { code: "NotFoundError", message: "not found" } });
  });
  return Object.assign(f, { state, base: `${f.url}/api/v3` });
}
