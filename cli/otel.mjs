// #1 / market-fit — content-free OpenTelemetry export.
//
// MoorAI emits the SAME wire envelope the observability field standardized on — OTLP over HTTP/JSON,
// OpenTelemetry GenAI semantic conventions — but carries NO prompt, response, argument, or file-path
// content. Only governance metadata and the tenant-keyed argument HASH leave. So a MoorAI device can
// feed Datadog / Dynatrace / Grafana / Elastic / any OTLP collector WITHOUT the prompt/output
// exfiltration that OTel GenAI normally implies. That inversion — the standard telemetry envelope,
// none of the content — is the whole point: "governance you can pipe into your SIEM without a
// data-residency problem, and without vendor lock-in."
//
// Off unless an endpoint is configured (MOORAI_OTLP_ENDPOINT or config.otlpEndpoint). Like every other
// MoorAI emitter it is best-effort and bounded: a failure NEVER changes an enforcement decision.

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { contentHash } from "./content-hash.mjs";
import { nextLink } from "./record-chain.mjs";

let VERSION = "unknown";
try { VERSION = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8")).version; } catch { /* version is cosmetic */ }

// The OTLP endpoint base (no path). Env wins over config; empty string means "disabled".
export function otlpEndpoint(config = {}) {
  const e = process.env.MOORAI_OTLP_ENDPOINT || config.otlpEndpoint || "";
  return e.trim().replace(/\/+$/, "");
}

// Optional extra headers (e.g. an ingest key), as "k=v,k2=v2" in env or an object in config.
function otlpHeaders(config = {}) {
  const h = {};
  const raw = process.env.MOORAI_OTLP_HEADERS;
  if (raw) for (const pair of raw.split(",")) { const i = pair.indexOf("="); if (i > 0) h[pair.slice(0, i).trim()] = pair.slice(i + 1).trim(); }
  if (config.otlpHeaders && typeof config.otlpHeaders === "object") Object.assign(h, config.otlpHeaders);
  return h;
}

const s = (v) => ({ stringValue: String(v) });
const i = (v) => ({ intValue: String(v) });
const attr = (key, value) => ({ key, value });

// Whitelist mapping alert -> OTLP attributes. This is an ALLOW-LIST, not a spread: only these keys are
// ever emitted, so a content field that slips into an alert object can never reach the collector. Every
// value here is metadata or a one-way hash — none of it is prompt/response/argument/path content.
function spanAttrs(alert = {}) {
  const out = [];
  if (alert.tool) { out.push(attr("gen_ai.tool.name", s(alert.tool))); out.push(attr("gen_ai.operation.name", s("execute_tool"))); }
  if (alert.category != null) out.push(attr("moorai.category", s(alert.category)));
  if (alert.threatId != null) out.push(attr("moorai.threat_id", i(alert.threatId)));
  if (alert.riskLevel != null) out.push(attr("moorai.risk", s(alert.riskLevel)));
  // allow / ask / deny — explicit if the call site set it, else inferred from a Blocked risk. A plain
  // allow/deny verdict is governance metadata, not content.
  out.push(attr("moorai.decision", s(alert.decision || (alert.riskLevel === "Blocked" ? "deny" : "allow"))));
  if (alert.stage != null) out.push(attr("moorai.stage", s(alert.stage)));
  if (alert.tool != null) out.push(attr("moorai.tool", s(alert.tool)));
  // contentHash is the tenant-keyed HMAC of the matched span — content-free by construction (see
  // cli/content-hash.mjs). It is the correlatable id, NOT the content.
  if (alert.contentHash != null) out.push(attr("moorai.args_hash", s(alert.contentHash)));
  if (alert.tenant != null) out.push(attr("moorai.tenant", s(alert.tenant)));
  // A signed agency token or a behavior-signature level are content-free governance metadata.
  if (alert.signature && alert.signature.level != null) out.push(attr("moorai.signature.level", s(alert.signature.level)));
  return out;
}

// A governed decision maps to one span. A blocked/denied call is an ERROR span so backends flag it.
const BLOCKED = new Set(["Blocked"]);
// Tamper-evidence for the record once it has left the device. A tenant-keyed HMAC over the record's
// canonical content-free fields: an attacker who alters a field in the SIEM copy can't recompute a
// matching hash without the tenant key, so the modification is detectable. Inputs are all metadata or
// existing hashes — no content. (Gap/reorder detection across records — a linked prev-hash chain with
// a locked monotonic sequence — is the tracked follow-on; see docs/ROADMAP.md.)
// The exact bytes the record hash is taken over — a pipe-joined, fixed-order list of the record's
// content-free fields. Exported + pure so the field set, order, and decision inference are testable
// without depending on whether contentHash is keyed on this box.
export function canonicalRecord(alert = {}, tenant, nanos) {
  const decision = alert.decision || (alert.riskLevel === "Blocked" ? "deny" : "allow");
  return [alert.tool, alert.category, alert.riskLevel, decision, alert.stage, alert.contentHash, tenant, nanos]
    .map((v) => (v == null ? "" : String(v))).join("|");
}
function recordHash(alert, tenant, nanos) {
  return contentHash(canonicalRecord(alert, tenant, nanos));
}

export function buildTracePayload(alert = {}, { tenant, version = VERSION, now = Date.now(), chain = false } = {}) {
  const nanos = String(BigInt(now) * 1000000n);
  const t = tenant ?? alert.tenant;
  const attrs = spanAttrs({ ...alert, tenant: t });
  const rhash = recordHash(alert, t, nanos);
  attrs.push(attr("moorai.record_hash", s(rhash)));
  // Chain the emitted stream so the collector can detect a dropped, reordered, or inserted span — the
  // record hash alone proves a single record, the seq/prev links prove the sequence. Opt-in so the
  // payload builder stays pure for tests; emitOtel turns it on. Fail-open: nextLink never throws.
  if (chain) {
    const link = nextLink("otel", rhash, { tenant: t });
    attrs.push(attr("moorai.record_seq", i(link.seq)));
    attrs.push(attr("moorai.record_prev", s(link.prev)));
    attrs.push(attr("moorai.record_chash", s(link.chash)));
  }
  return {
    resourceSpans: [{
      resource: { attributes: [
        attr("service.name", s("moorai")),
        attr("service.version", s(version)),
        attr("telemetry.sdk.name", s("moorai")),
        attr("telemetry.sdk.language", s("nodejs")),
        ...(tenant ? [attr("moorai.tenant", s(tenant))] : [])
      ] },
      scopeSpans: [{
        scope: { name: "moorai", version },
        spans: [{
          traceId: randomBytes(16).toString("hex"),
          spanId: randomBytes(8).toString("hex"),
          name: `moorai.${alert.category || alert.tool || "event"}`,
          kind: 1, // SPAN_KIND_INTERNAL
          startTimeUnixNano: nanos,
          endTimeUnixNano: nanos,
          attributes: attrs,
          status: { code: BLOCKED.has(alert.riskLevel) ? 2 : 0 } // 2 = ERROR, 0 = UNSET
        }]
      }]
    }]
  };
}

// Emit one content-free span for a governed event. Returns the in-flight promise (so the caller can
// drain it) or null when export is disabled. Bounded + swallows every error.
export function emitOtel(alert, { config = {}, identity = {}, fetchImpl = fetch } = {}) {
  const base = otlpEndpoint(config);
  if (!base) return null;
  const tenant = identity.tenant || alert?.tenant;
  let body;
  try { body = JSON.stringify(buildTracePayload(alert || {}, { tenant, chain: true })); } catch { return null; }
  try {
    return fetchImpl(`${base}/v1/traces`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...otlpHeaders(config) },
      body,
      signal: AbortSignal.timeout(1500)
    }).catch(() => {});
  } catch { return null; }
}
