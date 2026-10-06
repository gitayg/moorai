// Shared by test/model-proxy*.test.mjs: start the real CLI process, a fake console, and raw HTTP requests
// that return the exact response bytes.
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const CLI = join(ROOT, "model-proxy", "moorai-model-proxy.mjs");

export function sandbox() {
  const home = mkdtempSync(join(tmpdir(), "moorai-model-proxy-"));
  mkdirSync(join(home, "proj"), { recursive: true });
  return home;
}

// Alerts posted to /api/alerts, raw bodies. /api/policy answers 404, so the built-in baseline applies.
export async function startConsole() {
  const alerts = [];
  const srv = http.createServer((q, r) => { let b = ""; q.on("data", (d) => (b += d)); q.on("end", () => { if (q.url === "/api/alerts") alerts.push(b); r.writeHead(q.url.startsWith("/api/policy") ? 404 : 201); r.end("{}"); }); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, parsed: () => alerts.map((a) => JSON.parse(a)), close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(() => r()); }) };
}

export function startProxy(home, args = [], env = {}) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [CLI, "--port", "0", ...args], {
      cwd: join(home, "proj"),
      env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), MOORAI_SERVICE_ID: "model-bot", MOORAI_SERVER_URL: "http://127.0.0.1:1", ...env }
    });
    let out = "", err = "";
    const t = setTimeout(() => { c.kill(); rej(new Error(`proxy did not start: ${err}`)); }, 15000);
    c.stderr.on("data", (d) => (err += d));
    c.stdout.on("data", (d) => {
      out += d;
      const nl = out.indexOf("\n");
      if (nl < 0 || t._done) return;
      t._done = true;
      clearTimeout(t);
      res({ ...JSON.parse(out.slice(0, nl)), proc: c, stderr: () => err, stop: () => new Promise((r) => { if (c.exitCode !== null) return r(); c.once("close", r); c.kill("SIGTERM"); }) });
    });
    c.on("close", (code) => { clearTimeout(t); if (!out) rej(new Error(`proxy exited ${code}: ${err}`)); });
  });
}

// Raw request: resolves { status, headers, raw: Buffer, json, chunks: [{ t, data }] } — `chunks` with arrival
// times, `onChunk` called as each arrives.
export function request(base, path, { method = "POST", body, headers = {}, onChunk } = {}) {
  const u = new URL(path, base);
  const data = body === undefined ? undefined : Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  return new Promise((res, rej) => {
    const r = http.request({ host: u.hostname, port: u.port, path: u.pathname + u.search, method, headers: { ...(data ? { "content-type": "application/json", "content-length": data.length } : {}), ...headers } }, (resp) => {
      const chunks = [];
      resp.on("data", (d) => { chunks.push({ t: performance.now(), data: d }); if (onChunk) onChunk(d); });
      resp.on("end", () => { const raw = Buffer.concat(chunks.map((c) => c.data)); res({ status: resp.statusCode, headers: resp.headers, raw, chunks, json: (() => { try { return JSON.parse(raw.toString("utf8")); } catch { return null; } })() }); });
      resp.on("error", rej);
    });
    r.on("error", rej);
    if (data) r.write(data);
    r.end();
  });
}

export async function waitFor(fn, ms = 4000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (fn()) return true; await new Promise((r) => setTimeout(r, 25)); }
  return fn();
}

// SSE events of a raw body, as an SDK sees them: [{ event, data }].
export function sseEvents(raw) {
  return raw.toString("utf8").split(/\n\n/).filter((b) => b.trim()).map((b) => {
    let event = null; const data = [];
    for (const line of b.split("\n")) { if (line.startsWith("event:")) event = line.slice(6).trim(); else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, "")); }
    return { event, data: data.join("\n") };
  });
}
