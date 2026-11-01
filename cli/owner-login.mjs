// `moorai-identity login`, the device's half of owner sign-in (console server/owner-idp-flow.js). The console is the
// OAuth client at the company identity provider; this side shows the person what to do, relays, and keeps the
// console-signed owner assertion it gets back (cli/owner-assertion.mjs). No client secret, device code, ID token or
// access token reaches this device. Every request to the console is signed with the device key over
//   moorai-owner-bind-v1|<op>|<tenant>|<kid>|<ref>|<ts>
// so the console binds the person to the key that asked (ref: the flow id for a poll, sha256 hex of the code).
//
// DEVICE CODE (default; RFC 8628): the console starts the device authorization; this prints the verification URI and
// user code, then polls the console no faster than the interval it names (§3.5: +5 s on slow_down).
// BROWSER (--browser; RFC 6749 §4.1 with RFC 7636 S256 and an RFC 8252 §7.3 loopback redirect): this listens on
// http://127.0.0.1:<random port>/callback, opens the provider's authorization endpoint with code_challenge
// = BASE64URL(SHA256(code_verifier)), a state and a nonce, checks the state on the callback, and sends the code, the
// verifier, the redirect URI and the nonce to the console, which redeems the code and checks the nonce.
import http from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { keyIdOf } from "./agent-session-identity.mjs";

export const requestCanonical = (op, tenant, r) => `moorai-owner-bind-v1|${op}|${tenant}|${r.kid}|${r.ref || ""}|${r.ts}`;
export const codeRef = (code) => createHash("sha256").update(String(code)).digest("hex");
const b64u = (b) => Buffer.from(b).toString("base64url");

export function signedBody(op, { tenant, signer, who = {}, ref = "", now = Date.now(), extra = {} }) {
  const kid = keyIdOf(signer.publicKey), ts = new Date(now).toISOString();
  const sig = signer.sign(Buffer.from(requestCanonical(op, tenant, { kid, ref, ts }))).toString("base64");
  return { v: 1, kid, pub: signer.publicKey, alg: "ed25519", ts, sig, ...(who.user ? { user: who.user } : {}), ...(who.device ? { device: who.device } : {}), ...(who.actor ? { actor: who.actor } : {}), ...extra };
}

async function call(config, path, { method = "POST", body, fetchImpl = fetch, timeoutMs = 20000 } = {}) {
  let r;
  try {
    r = await fetchImpl(`${config.serverUrl}${path}`, { method, headers: { "Content-Type": "application/json", "X-Install-Token": config.installToken }, ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(timeoutMs) });
  } catch { return { status: 0, json: { error: "console unreachable" } }; }
  let json = null;
  try { json = await r.json(); } catch { json = null; }
  return { status: r.status, json: json || {} };
}

const sleeper = (ms) => new Promise((r) => setTimeout(r, ms));

// → the console's final answer: { status: "bound", owner, keyId, keyVerified, assertion, expiresAt } or
// { status: "denied" | "expired" | "refused" | "error", reason?, error? }.
export async function deviceLogin({ config, signer, who, say = () => {}, fetchImpl = fetch, sleep = sleeper, timeoutSec = 900 }) {
  const st = await call(config, "/api/owner-identity/device/start", { body: signedBody("start", { tenant: config.tenant, signer, who }), fetchImpl });
  if (st.status !== 200 || !st.json.flow) return { status: "error", error: st.json.error || `HTTP ${st.status}` };
  const s = st.json;
  say(`To sign in, open ${s.verificationUri} and enter the code ${s.userCode}${s.verificationUriComplete ? `\n(or open ${s.verificationUriComplete})` : ""}\nThe code expires in ${Math.round(s.expiresIn / 60)} min. Enter it only if you started this sign-in on this device.`);
  let interval = Math.max(1, s.interval || 5);
  const until = Date.now() + Math.min(s.expiresIn || 900, timeoutSec) * 1000;
  while (Date.now() < until) {
    await sleep(interval * 1000);
    const p = await call(config, "/api/owner-identity/device/poll", { body: signedBody("poll", { tenant: config.tenant, signer, who, ref: s.flow, extra: { flow: s.flow } }), fetchImpl });
    if (p.status === 0) { interval = Math.min(interval * 2, 60); continue; }
    if (p.json.status === "pending") { interval = Math.max(interval, p.json.interval || interval); continue; }
    if (p.json.status) return p.json;
    return { status: "error", error: p.json.error || `HTTP ${p.status}` };
  }
  return { status: "expired" };
}

function openBrowser(url) {
  const [cmd, args] = process.platform === "darwin" ? ["open", [url]] : process.platform === "win32" ? ["rundll32", ["url.dll,FileProtocolHandler", url]] : ["xdg-open", [url]];
  try { const c = spawn(cmd, args, { stdio: "ignore", detached: true }); c.on("error", () => {}); c.unref(); return true; } catch { return false; }
}

const PAGE = (ok) => `<!doctype html><meta charset="utf-8"><title>MoorAI sign-in</title><p>${ok ? "Signed in. You can close this window and return to the terminal." : "Sign-in did not complete. Return to the terminal."}</p>`;

export async function browserLogin({ config, signer, who, say = () => {}, fetchImpl = fetch, open = true, timeoutSec = 300 }) {
  const c = await call(config, "/api/owner-identity/config", { method: "GET", fetchImpl });
  if (c.status !== 200 || !c.json.authorizationEndpoint) return { status: "error", error: c.json.error || (c.status === 200 ? "the identity provider has no authorization endpoint" : `HTTP ${c.status}`) };
  if (c.json.pkceS256 === false) return { status: "error", error: "the identity provider does not list PKCE S256 (RFC 7636); use the device code sign-in" };
  const verifier = b64u(randomBytes(32)), state = b64u(randomBytes(16)), nonce = b64u(randomBytes(16));
  const challenge = b64u(createHash("sha256").update(verifier).digest());
  let done;
  const result = new Promise((r) => { done = r; });
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, "http://127.0.0.1");
    if (u.pathname !== "/callback") { res.writeHead(404); res.end(); return; }
    const ok = u.searchParams.get("state") === state && !!u.searchParams.get("code");
    res.writeHead(ok ? 200 : 400, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    res.end(PAGE(ok));
    if (u.searchParams.get("state") !== state) return; // not our request: keep waiting
    done(ok ? { code: u.searchParams.get("code") } : { error: /^[a-z_]{1,64}$/.test(u.searchParams.get("error") || "") ? u.searchParams.get("error") : "no code" });
  });
  await new Promise((r, j) => { srv.once("error", j); srv.listen(0, "127.0.0.1", r); });
  const redirectUri = `http://127.0.0.1:${srv.address().port}/callback`;
  const auth = new URL(c.json.authorizationEndpoint);
  for (const [k, v] of Object.entries({ response_type: "code", client_id: c.json.clientId, redirect_uri: redirectUri, scope: c.json.scopes, state, nonce, code_challenge: challenge, code_challenge_method: "S256" })) auth.searchParams.set(k, v);
  say(`Opening your browser to sign in. If it does not open, visit:\n${auth.href}`);
  if (open) openBrowser(auth.href);
  const timer = setTimeout(() => done({ error: "timed out" }), timeoutSec * 1000);
  const got = await result;
  clearTimeout(timer);
  srv.closeAllConnections?.();
  srv.close();
  if (got.error) return { status: "refused", reason: got.error };
  const body = signedBody("code", { tenant: config.tenant, signer, who, ref: codeRef(got.code), extra: { code: got.code, codeVerifier: verifier, redirectUri, nonce } });
  const r = await call(config, "/api/owner-identity/code", { body, fetchImpl });
  if (r.json.status) return r.json;
  return { status: "error", error: r.json.error || `HTTP ${r.status}` };
}

export async function deviceLogout({ config, signer, who, fetchImpl = fetch }) {
  const r = await call(config, "/api/owner-identity/unbind", { body: signedBody("unbind", { tenant: config.tenant, signer, who }), fetchImpl, timeoutMs: 5000 });
  return r.status === 200 ? (r.json.alreadyUnbound ? "already unbound" : "unbound") : r.status === 404 ? "no binding on the console" : `console: ${r.json.error || `HTTP ${r.status}`}`;
}
