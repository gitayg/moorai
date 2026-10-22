// Workload token for a cloud coding agent (CONTRACT-F28 §5.2): exchange a GitHub Actions OIDC ID token for a
// scoped MoorAI workload token (mwt_…), which the hook then sends as X-Install-Token. The console accepts an
// mwt_ token only on the telemetry and policy-read routes (policy:read, alerts:write, posture:write,
// actions:write, usage:write, approvals:read); it cannot download installers, claim, or register a device
// key. It is a MoorAI-only telemetry token, not a credential for the agent's own tools.
//
// GITHUB ID TOKEN. docs.github.com/en/actions/reference/security/oidc: ACTIONS_ID_TOKEN_REQUEST_URL is "The
// URL for GitHub's OIDC provider", ACTIONS_ID_TOKEN_REQUEST_TOKEN the "Bearer token for the request to the
// OIDC provider", requested as `curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN"
// "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=…"`, and "Without `id-token: write`, the OIDC JWT ID token cannot
// be requested". The answer's field is `value` (actions/toolkit packages/core/src/oidc-utils.ts:
// `const id_token = res.result?.value`). The audience is `moorai:<tenant>`, the value the console's workload
// record checks.
//
// WHERE IT RUNS. In the host's setup step (cli/moorai-cloud-setup.mjs), which is where the ID-token request
// variables exist: the Copilot coding agent's setup job is a GitHub Actions job, and GitHub's own Copilot
// docs show `id-token: write` in a copilot-setup-steps.yml job (the Azure DevOps example in "Extending
// Copilot cloud agent with MCP"). The agent phase is not assumed to have them. Never on the verdict path: a
// hook never waits on the network for a decision.
//
// NEVER LOGGED: the request token, the ID token and the minted token. Errors carry a code and a fixed
// sentence only; the console's refusal reason is passed through only when it is one of the contract's codes.
import { WORKLOAD_ID_RE, WORKLOAD_TOKEN_RE } from "./server-mode.mjs";

export const REFUSAL_CODES = Object.freeze(["bad-signature", "claim-not-allowed", "expired", "unknown-workload"]);
const TIMEOUT_MS = 10000;

export class WorkloadTokenError extends Error {
  constructor(code, message) { super(message); this.name = "WorkloadTokenError"; this.code = code; }
  toJSON() { return { code: this.code, message: this.message }; }
}

export const validWorkloadToken = (t) => typeof t === "string" && WORKLOAD_TOKEN_RE.test(t);
export const audienceFor = (tenant) => `moorai:${tenant}`;

function validServerUrl(v) {
  try { const u = new URL(String(v || "")); return u.protocol === "https:" || u.protocol === "http:" ? String(v).replace(/\/+$/, "") : ""; } catch { return ""; }
}
async function readJson(res) { try { return await res.json(); } catch { return null; } }

export async function requestGithubIdToken({ env = process.env, audience, fetchImpl = fetch } = {}) {
  const url = env.ACTIONS_ID_TOKEN_REQUEST_URL, bearer = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !bearer) throw new WorkloadTokenError("oidc-unavailable", "no GitHub Actions ID-token request variables: the job needs `permissions: id-token: write`");
  const full = `${url}${String(url).includes("?") ? "&" : "?"}audience=${encodeURIComponent(audience)}`;
  let res;
  try { res = await fetchImpl(full, { method: "GET", headers: { Authorization: `bearer ${bearer}`, Accept: "application/json" }, signal: AbortSignal.timeout(TIMEOUT_MS) }); }
  catch { throw new WorkloadTokenError("oidc-request-failed", "the GitHub ID-token request did not complete"); }
  const body = res && res.ok ? await readJson(res) : null;
  const value = body && typeof body.value === "string" ? body.value : "";
  if (!value) throw new WorkloadTokenError("oidc-request-failed", `the GitHub ID-token request failed${res && !res.ok ? ` (HTTP ${res.status})` : ""}`);
  return value;
}

export async function exchangeWorkloadToken({ serverUrl, workloadId, idToken, fetchImpl = fetch } = {}) {
  const base = validServerUrl(serverUrl);
  if (!base) throw new WorkloadTokenError("bad-server-url", "the console URL is not http(s)");
  if (!WORKLOAD_ID_RE.test(String(workloadId || ""))) throw new WorkloadTokenError("bad-workload-id", "the workload id is not wkl- followed by 12 hex characters");
  let res;
  try { res = await fetchImpl(`${base}/api/workload/token`, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify({ workloadId, idToken }), signal: AbortSignal.timeout(TIMEOUT_MS) }); }
  catch { throw new WorkloadTokenError("exchange-failed", "the console did not answer the workload token exchange"); }
  const body = await readJson(res);
  if (res.status === 404 || res.status === 405) throw new WorkloadTokenError("exchange-unsupported", "this console has no workload token exchange (needs a console with workload identity)");
  if (!res.ok) {
    const code = body && REFUSAL_CODES.includes(body.error) ? body.error : "exchange-refused";
    throw new WorkloadTokenError(code, `the console refused the workload token exchange (HTTP ${res.status}, ${code})`);
  }
  if (!body || !validWorkloadToken(body.token) || typeof body.expiresAt !== "string" || !Number.isFinite(Date.parse(body.expiresAt))) throw new WorkloadTokenError("bad-response", "the console's workload token answer is malformed");
  return { token: body.token, expiresAt: body.expiresAt };
}

export async function mintWorkloadToken({ env = process.env, serverUrl, tenant, workloadId, fetchImpl = fetch } = {}) {
  const idToken = await requestGithubIdToken({ env, audience: audienceFor(tenant), fetchImpl });
  const r = await exchangeWorkloadToken({ serverUrl, workloadId, idToken, fetchImpl });
  return { ...r, attestation: "github-oidc" };
}
