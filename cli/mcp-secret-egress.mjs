// #65 (local secret value egress) for the stdio MCP guard (mcp-proxy/moorai-mcp-guard.mjs): the check the
// Claude Code hook (checkSecretEgress) and the HTTP MCP gateway (mcp-gateway/guard.mjs) already run on a
// tool call's arguments. A value from this machine's secret stores (cwd .env*, ~/.aws/credentials, ~/.npmrc,
// ~/.netrc, .git-credentials; cli/secret-egress.mjs) or one this server's results carried earlier (an
// in-memory tracker under a per-process key, for the session-risk window) found in the serialized
// arguments, verbatim or encoded. Only the hash prefixes, the encoding and the source kind leave.
import { egressMatches, secretEgressVerdict, unverifiedLevel } from "./secret-egress.mjs";
import { memoryTracker } from "./secret-taint.mjs";
import { learnableSecrets, learnSource } from "./secret-learn.mjs";
import { sessionRiskConfig } from "../data/session-risk.js";

export function createOutboundSecrets() {
  const tracker = memoryTracker();
  const ttl = (policy) => { try { return sessionRiskConfig(policy).windowMin * 60000; } catch { return 30 * 60000; } };
  return {
    // A tool result: its secrets join the tracked set, as in the gateway. Evidence only; never throws.
    learn(result, policy) {
      try {
        const src = learnSource(result);
        const r = learnableSecrets(src.text);
        const cut = src.truncated || r.truncated;
        if (r.values.length || cut) tracker.learn(r.values, { ttl: ttl(policy), truncated: cut });
      } catch { /* evidence only */ }
    },
    // → null, or { hits, matches, verdict: "deny" | "ask" | "report" }. actionFor: threatActionFor.
    check({ args, policy, admin, actionFor }) {
      const em = egressMatches(args, undefined, { tracker: { kr: tracker.kr, entries: () => tracker.entries({ ttl: ttl(policy) }), overflowed: () => tracker.overflowed() } });
      const hits = [...new Set(em.matches.map((m) => m.hash))];
      if (!hits.length) return null;
      return { hits, matches: em.matches, verdict: secretEgressVerdict(em.matches, { action: actionFor(policy, 65), level: unverifiedLevel(policy, admin) }) };
    }
  };
}

// The content-free #65 alert body (the gateway's alertEgress fields); the caller adds tool, server, ts, identity.
export function secretEgressAlert(eg, blocked) {
  return {
    threatId: 65, category: "Local secret value egress", riskLevel: blocked ? "Blocked" : "Critical", stage: "egress", decision: blocked ? "deny" : "notify",
    contentHash: "egress:" + eg.hits.join("."),
    secretEgress: eg.matches.slice(0, 16).map((m) => ({ hashPrefix: m.hash.slice(0, 11), encoding: m.encoding, source: m.source }))
  };
}
