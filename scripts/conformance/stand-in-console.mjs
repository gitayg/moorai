// A loopback stand-in for the MoorAI console, for the live conformance tier. It serves one policy signed
// with a key generated for the run (published at /api/policy/pubkey, so the device pins it on first use
// exactly as it pins a real console's key), and records the alerts and posture heartbeats devices post.
// /api/alerts/batch answers 404, so the alert outbox falls back to one POST per alert.
import http from "node:http";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../../cli/hook-core.mjs";

export const CONFORMANCE_TENANT = "conformance";

export function signPolicy(policy, privateKey, tenant = CONFORMANCE_TENANT, iat = new Date().toISOString()) {
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant, iat, digest: policyDigest(policy) })), privateKey).toString("base64");
  return { ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant, iat, sig } };
}

export async function startStandInConsole({ policy = {}, tenant = CONFORMANCE_TENANT } = {}) {
  const key = generateKeyPairSync("ed25519");
  const signed = JSON.stringify(signPolicy(policy, key.privateKey, tenant));
  const pubkey = JSON.stringify({ tenant, alg: "ed25519", publicKey: publicKeyId(key.publicKey) });
  const alerts = [], postures = [];
  const server = http.createServer((req, res) => {
    const path = (req.url || "").split("?")[0];
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      const json = (code, text) => { res.writeHead(code, { "content-type": "application/json" }); res.end(text); };
      if (path === "/api/policy/pubkey") return json(200, pubkey);
      if (path === "/api/policy") return json(200, signed);
      if (req.method === "POST" && path === "/api/alerts") { try { alerts.push(JSON.parse(body)); } catch { /* ignore */ } return json(201, "{}"); }
      if (req.method === "POST" && path === "/api/agent-posture") { try { postures.push(JSON.parse(body)); } catch { /* ignore */ } return json(201, "{}"); }
      if (req.method === "POST") return json(path === "/api/alerts/batch" ? 404 : 201, "{}");
      return json(404, "{}");
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${server.address().port}`, tenant, alerts, postures,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); })
  };
}
