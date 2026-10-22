// F15 usage budgets in the model proxy (contract F28 §4.4). The console computes, at serve time, each
// budget's state for THIS user and device and serves it inside the ed25519-signed policy:
//   usageBudgets: [{ id, scope, match, period, limitUsd, limitTokens, warnAt, action: "alert" | "block" }]
//   budgetState:  [{ budgetId, state: "ok" | "warn" | "exceeded", periodStart, until, asOf }]
// The proxy is the only surface that can stop a model call, so it is the only one that blocks: a model
// request while a budget with action "block" is "exceeded" is answered HTTP 429 with
//   { "error": { "type": "budget_exceeded", "budgetId": "<id>", "message": "…" } }
// and `x-should-retry: false` (the Anthropic and OpenAI TypeScript SDKs check it before the status code and do not
// retry on "false": shouldRetry read in @anthropic-ai/sdk 0.8.1 and openai 4.104.0; other SDKs not read), never
// forwarded, and posts one BUDGET_EXCEEDED alert per budget and period from this process. In report mode the request is
// forwarded and the alert says "notify".
//
// NEVER BLOCKS on: a policy that is not the console-signed policy this device verified (context.mjs
// VERIFIED_SOURCES), no budgetState, a state older than BUDGET_STALE_MS (1 h) or dated in the future, a
// period that has ended, a state that is not "exceeded", or a budget whose action is not "block". Budgets
// are cost control, so a missing or stale state is "allow" whatever the surface's failMode says.
// The state lags real spend by the usage flush (5 min) plus a policy refresh; an overshoot of that size
// is expected.
import { VERIFIED_SOURCES } from "./context.mjs";

export const BUDGET_STALE_MS = 3600_000;
export const BUDGET_REASON = "BUDGET_EXCEEDED";
const SLUG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const t = (s) => (typeof s === "string" ? Date.parse(s) : NaN);

// → { budgetId, periodStart } of the first blocking budget, or null.
export function budgetBlock(policy, { source = "", now = Date.now() } = {}) {
  try {
    if (!policy || !VERIFIED_SOURCES.has(source)) return null;
    const budgets = Array.isArray(policy.usageBudgets) ? policy.usageBudgets : [];
    const states = Array.isArray(policy.budgetState) ? policy.budgetState : [];
    for (const s of states) {
      if (!s || s.state !== "exceeded" || typeof s.budgetId !== "string" || !SLUG.test(s.budgetId)) continue;
      const asOf = t(s.asOf), until = t(s.until);
      if (!Number.isFinite(asOf) || asOf > now + 60_000 || now - asOf > BUDGET_STALE_MS) continue;
      if (!Number.isFinite(until) || until <= now) continue;
      const b = budgets.find((x) => x && x.id === s.budgetId);
      if (!b || b.action !== "block") continue;
      return { budgetId: s.budgetId, periodStart: typeof s.periodStart === "string" ? s.periodStart : "" };
    }
  } catch { /* unreadable: never a block */ }
  return null;
}

export const budgetErrorBody = (budgetId) => ({ error: { type: "budget_exceeded", budgetId, message: `MoorAI model-proxy: usage budget ${budgetId} is exceeded for this period` } });

// The alert, without identity (the runtime's reporter adds it). enforce: whether the request was refused.
export const budgetAlert = (hit, enforce, hash) => ({
  threatId: 0, category: "Usage budget exceeded", riskLevel: "Medium", stage: "prompt", tool: "model-proxy:budget",
  decision: enforce ? "deny" : "notify", reasonCode: BUDGET_REASON, budgetId: hit.budgetId, contentHash: hash(`budget:${hit.budgetId}:${hit.periodStart}`)
});
