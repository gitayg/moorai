// The hook reads its signed policy through moorai-guardd, the privileged helper, when the helper is installed
// and answers (contract docs/proposals/guardd-contract.md §3.4 `policy`, §10.3).
//
// Why: the console puts a console-signed approval receipt in `approvals[].receipt` only for a /api/policy
// fetch signed by the device's BOUND helper key (RAISEME-server server/approval-receipts.js receiptAuthFor).
// That key is root-only in the helper's state directory, so the helper makes the fetch (device-signed,
// naming the hook's actor) and hands the hook the console's exact bytes. The hook's only own key
// (~/.moorai/agency-ed25519.key) is readable by every process of the agent's OS user and is never used for it.
//
// The helper is a transport, not a trust root: the caller (cli/hook-core.mjs loadVerifiedPolicy) verifies
// what comes back with the same policy keys and rollback marks as a direct fetch, and anything else
// (helper absent, not answering in time, not proving the key in device.pub, another tenant, a policy that
// is not fresh, unsigned or does not verify) falls back to the direct install-token path unchanged.
import { connect, POLICY_FETCH_TIMEOUT_MS, CONNECT_BUDGET_MS } from "./guardd-client.mjs";

// What the hook may ask with: the machine config's `helper` mode ("off" never connects), and, for tests
// only, the injected tree options of connect() (root, trustUid, endpoint, devicePubPath) and the budgets.
// No environment variable or user file reaches any of them (contract §10.2).
// → { raw, source: "fresh", iat? } or { skip: <content-free reason> }. Never throws.
export async function readPolicyViaHelper({ tenant, actor = "", mode = "optional", clientVersion = "0.0.0", connectOpts = {}, budgetMs = CONNECT_BUDGET_MS, policyTimeoutMs = POLICY_FETCH_TIMEOUT_MS } = {}) {
  if (mode === "off") return { skip: "off" };
  let c;
  try { c = await connect({ ...connectOpts, budgetMs, clientVersion }); } catch { return { skip: "error" }; }
  if (!c || !c.client) return { skip: (c && c.reason) || "error" };
  try {
    if (String(c.hello.tenant) !== String(tenant || "")) return { skip: "tenant" };
    const r = await c.client.policy({ actor: /^h2:[0-9a-f]{16,64}$/.test(String(actor || "")) ? actor : undefined }, policyTimeoutMs);
    // Only a policy the helper fetched and verified within its max age: a stale helper copy (console
    // unreachable) is left to the hook's own offline path, which already knows cache and last-known-good.
    if (r.source !== "fresh") return { skip: `source-${r.source}` };
    if (typeof r.policy !== "string" || !r.policy.trim()) return { skip: "empty" };
    return { raw: r.policy, source: "fresh", ...(typeof r.iat === "string" ? { iat: r.iat } : {}) };
  } catch (e) {
    return { skip: e && e.code === "timeout" ? "timeout" : "error" };
  } finally {
    c.client.close();
  }
}
