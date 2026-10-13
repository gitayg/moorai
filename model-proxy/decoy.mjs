// Decoy AI keys at the model proxy (cli/decoy-keys.mjs). A decoy is a key that was never issued, planted
// where real keys live; a request that carries one is a stolen key being used. Checked before anything is
// forwarded: every request header value (Authorization, x-api-key, x-goog-api-key, and any other header a
// client may put a key in), the query string (Gemini's `?key=`) and the request body. A hit is refused with
// 403 in report and enforce mode alike (a decoy authenticates nowhere, so refusing loses nothing) and raises
// one Critical alert naming the decoy's id only, never the token, a header name or a hash of either.
import os from "node:os";
import { decoyTokens, matchDecoy, DECOY_REASON } from "../cli/decoy-keys.mjs";
import { machineDir } from "../cli/machine-dir.mjs";
import { ENFORCEMENT } from "../cli/provenance.mjs";

export const DECOY_CATEGORY = "Decoy AI key used";
export const DECOY_REFUSAL = "MoorAI model-proxy refused this request: it carries a MoorAI decoy AI key (a planted key that was never issued)";
const RELOAD_MS = 60000;

// opts.tokens: an array, or a function returning one (tests); default: the registry, reloaded once a minute
// so a decoy placed after the proxy started is matched without a restart. opts.match: the matcher (tests).
export function createDecoyCheck({ tokens, match = matchDecoy, now = Date.now } = {}) {
  let cached = null, at = 0;
  const list = () => {
    if (Array.isArray(tokens)) return tokens;
    if (typeof tokens === "function") return tokens();
    if (!cached || now() - at > RELOAD_MS) {
      try { cached = decoyTokens({ home: os.homedir(), machineDir: machineDir() }); } catch { cached = []; }
      at = now();
    }
    return cached;
  };
  const hit = (text) => { try { return match(text, list()) || null; } catch { return null; } };
  return {
    // rawHeaders: Node's [name, value, name, value, …]; only the values are searched.
    request(rawHeaders, query) {
      const vals = [];
      for (let i = 1; i < (rawHeaders || []).length; i += 2) vals.push(String(rawHeaders[i]));
      if (query) vals.push(String(query));
      return vals.length ? hit(vals.join("\n")) : null;
    },
    body(buf) { return buf && buf.length ? hit(Buffer.isBuffer(buf) ? buf.toString("utf8") : String(buf)) : null; }
  };
}

export function decoyAlert(rt, decoyId, part) {
  return rt.ready().then((s) => rt.reporter.post({
    threatId: 0, category: DECOY_CATEGORY, riskLevel: "Critical", reasonCode: DECOY_REASON, decoyId, where: "model-proxy:request",
    stage: "prompt", tool: `model-proxy:decoy-${part}`, decision: "deny", enforcement: ENFORCEMENT.AS_CONFIGURED, contentHash: rt.hash(`decoy:${decoyId}`)
  }, { prov: { policyId: s.policyId, policySource: s.source, event: "ModelRequest" } })).catch(() => {});
}
