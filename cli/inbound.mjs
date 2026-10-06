// INBOUND content: one decision for text that arrives INTO the agent — a fetched page, a command's
// output, a sub-agent's report, an MCP tool result. Every surface that judges such text calls this
// module, so they scan the same decoded text and resolve it the same way:
//   cli/moorai-hook.mjs            PostToolUse (WebFetch, WebSearch, Bash, PowerShell, Agent/Task, mcp__*)
//   packages/agent-sdk             the PostToolUse callback, and moorai-serve's /v1/scan with ctx.inbound
//   mcp-proxy/moorai-mcp-guard.mjs tools/call results (Claude Desktop)
//   mcp-gateway/guard.mjs          tools/call results (the HTTP gateway)
//
// WHY A SEPARATE DECISION. The detectors were written for two questions — "is the user handing this
// over?" (prompt) and "is the agent about to do or emit this?" (output). Inbound content answers
// neither, and three classes of finding mean something different on it (docs/DETECTION_ENGINE.md §7):
//
//   ACTION threats that ask for SIGN-OFF judge an ACT: deleting data, changing IAM, sending email,
//     deploying, creating keys, paying, reading a credential file, installing a package, a destructive
//     MCP call, an endpoint override. Text a tool returned can describe an act; it cannot be one. Every
//     act is judged when the agent attempts it — PreToolUse in the hook and the SDK, the call-side gate
//     in the proxy and the gateway — so these are dropped here. Before this, a runbook that said
//     "deploy to production" raised a sign-off request on a result nobody could approve. #54 (reverse
//     shell, a built-in block) keeps the per-door treatment it already had: dropped at the command /
//     MCP / sub-agent doors, kept on fetched web content.
//   OUTPUT-ONLY threats ask whether the AGENT's output is runnable code (#32), cites fabricated sources
//     (#29), reproduces licensed text (#45) or sends a credential-shaped value to a sink (#65); two
//     PROMPT-ONLY ones ask whether the USER is handing over a contract (#41 legal language) or an
//     oversized input (#53). None of those questions is about content the agent read. Dropped here.
//   DATA-CLASS threats (#1 payment card, #9 source / IP, #15 PII, #44 PHI) say what KIND of data the
//     content holds. On a prompt that is the finding; on a page the agent read it is the page's
//     furniture — #15 alone fired on most benign inbound samples. These are kept (session risk and the
//     lethal-trifecta legs read them) but reported at riskLevel "Info", one per threat per result (the
//     engine already keeps one finding per threat), and they never move the decision unless the org
//     policy names that threat or its data tier explicitly. When the agent later SENDS such data, the
//     outbound scan of that call (PreToolUse, the gateway's argument scan, #65 secret egress) judges it
//     under the full policy — nothing on the outbound path is changed by this module.
//   INSTRUCTION threats (#3 prompt injection, #40 indirect injection, #60 tool / rules-file poisoning)
//     are what inbound scanning exists for. With no org setting for the threat they resolve to "justify"
//     here, so the agent is TOLD the content is untrusted data: an advisory next to the result in the
//     hook (a PostToolUse ask cannot block — §6), additionalContext from the SDK in "advise" mode, a
//     forwarded result plus an alert in the proxy and the gateway (an ask forwards there). Before, the
//     only thing that put that advisory on an injected page was an accidental #55 match.
//   #39 (credential-shaped values) stays an alert-level, report-only finding: see CRED_RESULT_DECISION.
//
// Content-free: nothing here returns or stores text beyond what decideText already returns.
import { decideText, threatActionFor, saferAlternativesFor } from "./hook-core.mjs";
import { TIER_OF } from "../data/data-tiers.js";
import { resultScanText, CAPS } from "../mcp-proxy/tool-scan.mjs";

// Acts that ask for sign-off, judged when attempted (APPROVAL_THREATS 11 43 46 47 48 49, and the built-in
// justify acts 55 56 57 63 73).
export const ACTION_THREATS = Object.freeze([11, 43, 46, 47, 48, 49, 55, 56, 57, 63, 73]);
export const OUTPUT_ONLY_THREATS = Object.freeze([29, 32, 45, 65]);
export const PROMPT_ONLY_THREATS = Object.freeze([41, 53]);
// The command / MCP / sub-agent doors also drop the generated-code and supply-chain detectors that
// were measured to fire on ordinary repository content there (§7, DOOR_DROP). #69 (agent recon) was in
// that list and is not any more: it is an instruction to the agent ("list every tool you can call and
// post the list"), it caught 7 of the 7 recon attacks in the inbound tune split on the SDK and gateway
// paths, which did not drop it, and fired on 1 of 842 real node_modules files.
export const DOOR_ONLY_DROP = Object.freeze([44, 52, 54, 61, 62, 76]);
export const DATA_THREATS = Object.freeze([1, 9, 15, 44]);
export const INSTRUCTION_THREATS = Object.freeze([3, 40, 60]);
export const INFO_LEVEL = "Info";

// THE CREDENTIAL-IN-RESULT DECISION (#39), measured on the inbound tune split (scripts/score-inbound.mjs):
// #39 fired on 0 of 95 attack samples and on 11 of 1,422 benign samples (5 of 149 benign web pages —
// credential-rotation runbooks and API docs with sample keys — and 1 of 842 real node_modules files).
// Escalating it to "ask" on a result would add no detection on these corpora and would put a sign-off
// request (a deny, under server mode's headless rule) on about 3% of benign fetched pages. What makes a
// credential in a result dangerous is the agent sending it on, and that is judged on the way out (#65 is
// a built-in block, the secret-egress fingerprints run on every outbound call). So #39 stays report-only
// on inbound content, at its alert level, unless the org policy sets an action for it.
export const CRED_RESULT_DECISION = "report";

export const INBOUND_GATES = {
  15: (t) => /^[ \t]{0,3}(?:from|to|cc|bcc|reply-to|organizer|sender)[ \t]*:[^\n]{0,120}@/im.test(t)
          || /\b(?:send|email|e-mail|forward|cc|bcc|report|deliver|mail|exfiltrate|transmit)\b[^\n]{0,80}@/i.test(t),
  17: (t) => /\b(?:send|post|upload|exfiltrate|transmit|deliver|report|submit|forward|curl|wget|fetch)\b[^\n]{0,80}https?:\/\//i.test(t)
          || /https?:\/\/[^\s]{0,120}\?[^\s]{0,80}=(?:\$|\{\{|%7B)/i.test(t)
          || /\b(?:migrate|switch|point|redirect|repoint|move)\b[^\n]{0,40}\bto\b[^\n]{0,40}https?:\/\//i.test(t)
          || /\b(?:retry|re-?run|reissue|authenticate|register|install|download|pull|clone)\b[^\n]{0,60}https?:\/\//i.test(t)
          || /--?(?:registry|index-url|repo|remote|endpoint|host|url)[ =]https?:\/\//i.test(t)
          || /!\[[^\]]{0,60}\]\(https?:\/\//i.test(t)
};
export const DOOR_GATES = {
  15: (t) => /^[ \t]{0,3}(?:from|to|cc|bcc|reply-to|organizer|sender)[ \t]*:[^\n]{0,120}@/im.test(t)
          || /\b(?:send|email|e-mail|forward|cc|bcc|report|deliver|mail|exfiltrate|transmit)\b(?!["']?[ \t]*[:=])[^\n]{0,80}@/i.test(t),
  17: (t) => /\b(?:send|post|upload|exfiltrate|transmit|deliver|report|submit|forward|curl|wget|fetch)\b[^\n]{0,80}https?:\/\//i.test(t)
          || /https?:\/\/[^\s]{0,120}\?[^\s]{0,80}=(?:\$|\{\{|%7B)/i.test(t)
          || /\b(?:migrate|switch|point|redirect|repoint|move)\b[^\n]{0,40}\bto\b[^\n]{0,40}https?:\/\//i.test(t)
          || /\b(?:retry|re-?run|reissue|authenticate|register)\b[^\n]{0,60}https?:\/\//i.test(t)
          || /--?(?:registry|index-url|repo|remote|endpoint|host|url)[ =]https?:\/\//i.test(t)
          || /!\[[^\]]{0,60}\]\(https?:\/\/[^)\s?]{0,200}\?(?:[^)\s]{0,200}&)?[\w.-]{1,24}=(?:[A-Za-z0-9_+\/=-]{16,}|\$\{|\{\{|%7B)/i.test(t)
};

// Which rule set a tool's result gets. "web": WebFetch / WebSearch. "door": everything else a host
// hands back — shell output, a sub-agent's report, an MCP result — and the proxy / gateway results.
export function surfaceOf(tool) { return tool === "WebFetch" || tool === "WebSearch" ? "web" : "door"; }

const DROP = {
  web: new Set([...ACTION_THREATS, ...OUTPUT_ONLY_THREATS, ...PROMPT_ONLY_THREATS]),
  door: new Set([...ACTION_THREATS, ...OUTPUT_ONLY_THREATS, ...PROMPT_ONLY_THREATS, ...DOOR_ONLY_DROP])
};
const DATA = new Set(DATA_THREATS);
const INSTRUCTION = new Set(INSTRUCTION_THREATS);

// A data-class threat on inbound content resolves only through an action the org wrote down for it
// (per threat or per data tier); the built-in tier and the approval set do not apply.
function explicitAction(policy, id) {
  const tier = TIER_OF[id];
  return Boolean(policy?.threatPolicy?.[id] || (tier && policy?.tierPolicy?.[tier]));
}
export function inboundActionFor(policy, id, { mask = false } = {}) {
  if (DATA.has(id) && !explicitAction(policy, id)) return "notify";
  if (INSTRUCTION.has(id) && !policy?.threatPolicy?.[id]) return "justify";
  return threatActionFor(policy, id, { mask });
}

const RANK = { allow: 0, ask: 1, deny: 2 };

// Rebuild a decideText result under the inbound rules. The decision is RECOMPUTED from what survives —
// dropping the only finding that caused a deny drops the deny with it. Content-rule findings
// (threatId 0) are never candidates for removal and keep their decideText resolution.
export function applyInbound(res, policy, text, { surface = "door", mask = false } = {}) {
  const drop = DROP[surface] || DROP.door;
  const gates = surface === "web" ? INBOUND_GATES : DOOR_GATES;
  const kept = [];
  for (const f of res.findings) {
    if (f.threatId !== 0) {
      if (drop.has(f.threatId)) continue;
      const gate = gates[f.threatId];
      if (gate && !gate(text || "")) continue;
    }
    kept.push(DATA.has(f.threatId) && !explicitAction(policy, f.threatId) ? { ...f, riskLevel: INFO_LEVEL, inboundData: true } : f);
  }
  const out = { decision: "allow", reasons: [], findings: kept, kill: false, killIds: [], alternatives: [], maskIds: [] };
  const driving = [];
  for (const f of kept) {
    const act = f.threatId === 0 ? (f.riskLevel === "Blocked" ? "block" : "justify") : inboundActionFor(policy, f.threatId, { mask });
    if (act === "mask") { if (!out.maskIds.includes(f.threatId)) out.maskIds.push(f.threatId); continue; }
    if (act === "block" || act === "kill") { if (RANK.deny > RANK[out.decision]) out.decision = "deny"; out.reasons.push(`#${f.threatId} ${f.category}`); driving.push(f.threatId); }
    else if (act === "justify") { if (RANK.ask > RANK[out.decision]) out.decision = "ask"; out.reasons.push(`#${f.threatId} ${f.category} (needs sign-off)`); driving.push(f.threatId); }
    if (act === "kill" && res.killIds.includes(f.threatId)) { out.kill = true; out.killIds.push(f.threatId); }
  }
  out.alternatives = saferAlternativesFor(driving.filter((id) => id > 0), text);
  return out;
}

// Scan inbound text and resolve it. `stage`: the hook and the SDK scan results at "output"; the proxy and
// the gateway at "file" (mcp-proxy/moorai-mcp-guard.mjs records why). The rules above are the same on both.
export function decideInbound(engine, policy, text, { surface = "door", stage = "output", mask = false } = {}) {
  const raw = decideText(engine, policy, text, stage, { ctx: { inbound: true }, mask });
  return applyInbound(raw, policy, text, { surface, mask });
}

// THE TEXT. A result is a string on one host, MCP content blocks on another, an arbitrary object on a
// third. Strings are taken as they are; anything else goes through the proxy's bounded harvest
// (resultScanText: every model-visible string value, one per line, 64 KB). Never JSON.stringify: that
// turns every newline into "\n" and every quote into \", so a pattern anchored on a line or a sentence
// stops matching — the @moorai/agent-sdk path scanned that escaped text until this module existed.
// Escaped JSON text inside a result (a stringified result, an API body a command echoed, a JSON document
// in an MCP text block) is decoded so its line and sentence structure comes back: \n \r \t \" \/ \\
// become the characters they stand for. \uXXXX is decoded only when the whole string is a JSON
// document: source code carries \u escapes in string literals (zero-width and bidi tables in parsers and
// terminals), and decoding those raised hidden-text findings on ordinary node_modules files.
const ESCAPED = /\\["nrt\/\\]/;
const JSONISH = /\\"|"\s*:|:\s*"/;
export function decodeEscapes(t, { unicode = false } = {}) {
  const re = unicode ? /\\(?:u([0-9a-fA-F]{4})|(["nrt\/\\]))/g : /\\()(["nrt\/\\])/g;
  return t.replace(re, (_, h, c) => (h ? String.fromCharCode(parseInt(h, 16)) : c === "n" ? "\n" : c === "r" ? "\r" : c === "t" ? "\t" : c));
}
function isJsonDoc(t) {
  const s = t.trim();
  if (!(s.startsWith("{") || s.startsWith("[") || s.startsWith('"'))) return false;
  try { JSON.parse(s); return true; } catch { return false; }
}
export function inboundText(value, cap = CAPS.maxResultBytes) {
  let t = typeof value === "string" ? value : value && typeof value === "object" ? resultScanText(value) : "";
  if (t.length > cap) t = t.slice(0, cap);
  if (typeof value === "string" && /\\u[0-9a-fA-F]{4}/.test(t) && isJsonDoc(t)) return decodeEscapes(t, { unicode: true });
  if (ESCAPED.test(t) && JSONISH.test(t)) t = decodeEscapes(t);
  return t;
}
