// --report: content-free console alerts for replayed findings, marked historical.
//
// Each alert has the shape the live hook posts (threatId, category, riskLevel, stage, tool, ts,
// contentHash, identity, session, policyId, reasonCode) with these differences, so the console can
// tell a replay from a live event and never count it as an enforcement:
//   replayed: true          the marker
//   ts                      the ORIGINAL time of the recorded call, from the transcript
//   ingestedAt              when this replay ran
//   source: "ingest", agent the transcript's agent ("claude-code" | "codex")
//   wouldDecision           what enforce mode would have decided (deny | ask | mask | allow)
//   enforcement             "UNEVALUATED" — no control ran on this event when it happened
//   riskLevel               the finding's own level, never "Blocked": nothing was blocked
//   replayId                keyed hash of (session, call id, event, threat), so a re-run can be deduped
// `session` is computed exactly as the hook computes it (cli/moorai-hook.mjs main(): contentHash of the
// raw session id, omitted when there is no id or the device has no key), so these join live metrics.
// Never sent: the prompt, command, path, URL, arguments or matched text. contentHash is the same keyed
// one-way fingerprint of the matched span the live alert carries.
import os from "node:os";
import { contentHash, actorHash, NO_KEY } from "../content-hash.mjs";
import { reasonCodeOf, ENFORCEMENT } from "../provenance.mjs";
import { isEnrolled } from "../hook-core.mjs";

export function sessionKey(rawSessionId) {
  if (typeof rawSessionId !== "string" || !rawSessionId) return "";
  const h = contentHash(rawSessionId);
  return h === NO_KEY ? "" : h;
}

const identity = (config) => {
  const user = os.userInfo().username, device = os.hostname();
  return { user, device, platform: os.platform(), tenant: config.tenant, actor: actorHash(user, device) };
};

export function historicalAlert(config, { agent, sessionId, toolUseId = "", event, tool, ts, finding, wouldDecision, policyId, now = new Date() }) {
  const session = sessionKey(sessionId);
  const alert = {
    threatId: finding.threatId,
    category: finding.category,
    riskLevel: finding.riskLevel === "Blocked" ? "High" : finding.riskLevel,
    stage: finding.stage,
    tool: tool ? `hook:${tool}` : "hook:UserPromptSubmit",
    ts: ts || now.toISOString(),
    contentHash: contentHash(finding.match || ""),
    ...identity(config),
    ...(session ? { session } : {}),
    replayed: true,
    source: "ingest",
    agent,
    ingestedAt: now.toISOString(),
    wouldDecision,
    policyId,
    enforcement: ENFORCEMENT.UNEVALUATED,
    replayId: contentHash(`${sessionId}|${toolUseId}|${event}|${finding.threatId}|${finding.category}|${ts}`)
  };
  alert.reasonCode = reasonCodeOf(alert);
  return alert;
}

// POST with bounded concurrency; each request times out like the hook's (1500ms) and never throws.
export async function postAlerts(config, alerts, { concurrency = 8, fetchImpl = fetch } = {}) {
  if (!isEnrolled(config)) return { sent: 0, failed: 0, skipped: alerts.length, reason: "not enrolled" };
  let sent = 0, failed = 0, i = 0;
  const worker = async () => {
    while (i < alerts.length) {
      const a = alerts[i++];
      try {
        const r = await fetchImpl(`${config.serverUrl}/api/alerts`, { method: "POST", headers: { "Content-Type": "application/json", "X-Install-Token": config.installToken }, body: JSON.stringify(a), signal: AbortSignal.timeout(1500) });
        if (r && r.ok) sent++; else failed++;
      } catch { failed++; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, alerts.length) }, worker));
  return { sent, failed, skipped: 0 };
}
