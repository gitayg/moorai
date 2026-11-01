// A test console for the guardd policy tests: the device routes moorai-guardd calls (register, beat, alerts,
// commands) and GET /api/policy, which signs the policy with a console key exactly as RAISEME-server
// policy-sign.js does and puts an approval's receipt in it only when the console's own check passes:
// receiptAuthFor (copied verbatim in ./console-verifier.mjs) over req.url and the request headers, a BOUND
// device key, the key's device equal to the request's device and the install token equal to the posting one.
import http from "node:http";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { canonicalJson } from "../../../cli/canonical-json.mjs";
import { verifySignedRequest, receiptAuthFor, receiptTokenFp, keyIdOfSpki } from "./console-verifier.mjs";

export function consoleKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { privateKey, spki: publicKey.export({ type: "spki", format: "der" }).toString("base64") };
}

export function signPolicy(body, key, tenant, iat = new Date().toISOString()) {
  const digest = createHash("sha256").update(canonicalJson(body)).digest("hex");
  const sig = edSign(null, Buffer.from(`moorai-policy|v1|${tenant}|${iat}|${digest}`), key.privateKey).toString("base64");
  return JSON.stringify({ ...body, policySig: { v: 1, alg: "ed25519", tenant, iat, sig } });
}

// opts: tenant, token, key (consoleKeyPair), enrollSecret, approvals [{ requestId, actor, device (raw
// hostname), token, receipt }], hangPolicy (never answer /api/policy), basePolicy.
export async function startFakeConsole(opts) {
  const { tenant, token, key } = opts;
  const devices = new Map(); // deviceId -> { publicKey, keyId, device, bound }
  const nonces = new Set();
  const log = [];
  const seenNonce = (keyId, nonce) => { const k = `${keyId}|${nonce}`; if (nonces.has(k)) return true; nonces.add(k); return false; };
  const lookupKey = (t, deviceId, keyId) => { const d = t === tenant && devices.get(deviceId); return d && d.keyId === keyId ? { publicKey: d.publicKey } : null; };
  const boundRow = (t, deviceId, keyId) => { const d = t === tenant && devices.get(deviceId); return d && d.keyId === keyId ? { device: d.device, bound: d.bound } : null; };
  const send = (res, code, body) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(body === undefined ? "" : typeof body === "string" ? body : JSON.stringify(body)); };
  const open = new Set();
  const server = http.createServer((req, res) => {
    open.add(res);
    res.on("close", () => open.delete(res));
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks);
      const url = new URL(req.url, "http://x");
      const entry = { method: req.method, url: req.url, path: url.pathname, signed: !!req.headers["x-device-sig"], token: req.headers["x-install-token"] || "" };
      log.push(entry);
      if (entry.token !== token) return send(res, 401, { error: "enrollment required" });
      if (req.method === "POST" && url.pathname === "/api/devices/register") {
        let b;
        try { b = JSON.parse(raw.toString("utf8")); } catch { return send(res, 400, { error: "bad json" }); }
        const v = verifySignedRequest({ method: "POST", path: req.url, headers: req.headers, rawBody: raw, tenant, publicKey: b.publicKey, seenNonce });
        if (!v.ok) return send(res, v.status, { error: v.error });
        const bound = !!opts.enrollSecret && req.headers["x-enroll-secret"] === opts.enrollSecret;
        devices.set(v.deviceId, { publicKey: b.publicKey, keyId: keyIdOfSpki(b.publicKey), device: b.device, bound });
        entry.registered = { bound, device: b.device };
        return send(res, 201, { ok: true, deviceId: v.deviceId, keyId: v.keyId, status: "registered", bound, serverTime: new Date().toISOString(), beatIntervalSec: 300 });
      }
      if (req.method === "POST" && url.pathname === "/api/devices/beat") return send(res, 200, { ok: true, serverTime: new Date().toISOString(), beatIntervalSec: 300 });
      if (req.method === "POST" && url.pathname === "/api/devices/alerts") return send(res, 201, { ok: true });
      if (req.method === "POST" && url.pathname === "/api/devices/commands/ack") return send(res, 200, { ok: true });
      if (req.method === "GET" && url.pathname === "/api/devices/commands") { setTimeout(() => send(res, 204), 1500).unref(); return; }
      if (req.method === "GET" && url.pathname === "/api/policy/pubkey") return send(res, 200, { tenant, publicKey: key.spki });
      if (req.method === "GET" && url.pathname === "/api/policy") {
        if (opts.hangPolicy) return; // accepted, never answered
        const auth = receiptAuthFor({ lookupKey, seenNonce, boundRow }, tenant, { method: "GET", url: req.url, headers: req.headers, installToken: entry.token });
        entry.receiptAuth = !!auth;
        const actor = url.searchParams.get("actor");
        const approvals = (opts.approvals || []).filter((a) => actor && a.actor === actor).map((a) => {
          const authed = !!auth && auth.device === a.device && auth.tokenFp === receiptTokenFp(a.token);
          return { requestId: a.requestId, ruleId: "hub-priv", actionHash: a.actionHash || "h2:0000000000000000", decision: "approve", grant: "once",
            decidedAt: new Date().toISOString(), validUntil: new Date(Date.now() + 600000).toISOString(), ...(authed ? { receipt: a.receipt } : {}) };
        });
        return send(res, 200, signPolicy({ ...(opts.basePolicy || { captureTier: "content-free" }), tenant, approvals }, key, tenant));
      }
      return send(res, 404, { error: "not found" });
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    log,
    devices,
    close: () => new Promise((r) => { for (const res of open) { try { res.destroy(); } catch { /* gone */ } } server.close(() => r()); })
  };
}
