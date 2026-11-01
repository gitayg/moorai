// The words the weakening-oversight checks (#84) read keys, identifiers and paths with. DATA, so it is
// reviewable: which key names count as an alert / notification / paging switch, which as a monitoring,
// audit-log or tracing switch, which as a recipient list or route, and which identifier stems count as
// monitoring wiring. Pure; no I/O.
//
// Deliberately absent, each a measured or obvious false positive:
//   telemetry   NEXT_TELEMETRY_DISABLED, DOTNET_CLI_TELEMETRY_OPTOUT, DO_NOT_TRACK: vendor opt-outs, not the
//               project's own oversight (kept as a wiring stem only, where removing the project's own
//               telemetry client is the act);
//   page, ping  disable_web_page_preview, pages_enabled, ping_interval: only as recipient lists
//               (ping_recipients, page_recipients);
//   trace       stack_trace_enabled; tracing / tracer / ddtrace are kept;
//   metrics     too generic for a switch;
//   on          notify_on_success: false is tuning, not suppression.

export const ALERT_WORDS = new Set(["alert", "alerts", "alerting", "alarm", "alarms", "notify", "notifier", "notifiers", "notification", "notifications", "paging", "pager", "pagers", "pagerduty", "oncall", "escalation", "escalations", "opsgenie"]);
export const MONITOR_WORDS = new Set(["monitor", "monitors", "monitoring", "audit", "auditing", "auditlog", "auditlogs", "audittrail", "tracing", "tracer", "ddtrace", "otel", "opentelemetry", "otlp", "sentry", "apm", "observability", "watchdog", "newrelic", "datadog"]);
export const SUPPRESS_WORDS = new Set(["suppress", "suppressed", "suppression", "silence", "silenced", "mute", "muted", "squelch", "squelched", "snooze", "snoozed", "inhibit", "inhibited", "disable", "disabled", "skip", "no", "off", "pause", "paused"]);
export const ENABLE_WORDS = new Set(["enabled", "enable", "active"]);
// A key that is only a state word (enabled: false) takes its family from the enclosing block.
const STATE_ONLY = new Set([...ENABLE_WORDS, "disabled", "suppressed", "muted", "silenced", "off", "paused"]);

// Recipient lists and routes. A strong key names the alert family itself (ping_recipients, alert_emails,
// oncall); a weak one (recipients, receivers, routes) counts only inside an alert-family block or file.
const RECIP_NOUNS = new Set(["recipients", "recipient", "receivers", "receiver", "targets", "target", "emails", "email", "channels", "channel", "contacts", "contact", "routes", "route", "webhooks", "webhook", "to", "list", "users", "groups", "addresses", "numbers", "subscribers"]);
const PERSON_NOUNS = new Set(["recipients", "recipient", "receivers", "receiver", "targets", "contacts", "emails", "users", "groups", "numbers", "subscribers"]);
const WEAK_RECIP = new Set(["recipients", "receivers", "routes", "subscribers"]);
const ROUTE_KEYS = new Set(["oncall", "pagers", "escalation", "escalations"]);
// Where monitoring data is sent: emptying or deleting one switches the sink off.
const SINK_VENDORS = new Set(["sentry", "otlp", "otel", "datadog", "newrelic", "honeycomb", "statsd", "prometheus", "pagerduty", "opsgenie"]);
const SINK_NOUNS = new Set(["dsn", "endpoint", "url", "key", "apikey", "token", "host"]);

// Identifier stems that make a line monitoring wiring. Matched on a word part (camelCase / snake_case split).
export const WIRING_FAMILIES = [
  ["monitor", (w) => /^monitor(?:s|ing|ed)?$/.test(w)],
  ["alert", (w) => /^alert(?:s|ing|manager|er)?$/.test(w)],
  ["alarm", (w) => /^alarms?$/.test(w)],
  ["paging", (w) => /^(?:pager|pagers|pagerduty|paging|opsgenie|oncall|victorops)$/.test(w)],
  ["audit", (w) => /^audit(?:s|ing|or|ors|log|logs|logger|trail)?$/.test(w)],
  ["telemetry", (w) => /^telemetry$/.test(w)],
  ["tracing", (w) => /^(?:tracer|tracers|tracing|otel|opentelemetry|otlp|ddtrace)$/.test(w)],
  ["vendor", (w) => /^(?:sentry|datadog|newrelic|prometheus|statsd|honeycomb)$/.test(w)],
  ["watchdog", (w) => /^watchdogs?$/.test(w)],
  ["notifier", (w) => /^notifiers?$/.test(w)]
];
// Words a test name or path carries when the test guards oversight.
export const TEST_GUARD_WORDS = /^(?:monitor\w*|alert\w*|alarm\w*|notif\w*|pager\w*|paging|oncall|audit\w*|telemetry|tracing|tracer|safety|guardrails?|watchdog)$/;

// Words of a key or identifier: camelCase and snake/kebab/dot split, lowercased, with each adjacent pair also
// joined (new_relic -> newrelic, audit_log -> auditlog, on_call -> oncall, dd_trace -> ddtrace).
export function words(s) {
  const parts = String(s || "").replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/([A-Z])(?=[A-Z][a-z])/g, "$1 ").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const out = [...parts];
  for (let i = 0; i + 1 < parts.length; i++) out.push(parts[i] + parts[i + 1]);
  return out;
}
const anyIn = (ws, set) => ws.some((w) => set.has(w));

// The family of a wiring identifier, or "". The bare token `alert` / `Alert` is a browser dialog or a UI
// component far more often than wiring, so it never counts on its own.
export function wiringFamily(ident) {
  if (/^alert$/i.test(ident)) return "";
  for (const w of words(ident)) for (const [fam, ok] of WIRING_FAMILIES) if (ok(w)) return fam;
  return "";
}

// The kind of a value token: "true", "false", "empty" or "other".
export function valueKind(raw) {
  const s = String(raw == null ? "" : raw).trim();
  if (/^(?:""|''|``)$/.test(s)) return "empty";
  const v = s.replace(/^["'`]|["'`]$/g, "").trim().toLowerCase();
  if (["true", "yes", "on", "1", "y", "enabled", "enable"].includes(v)) return "true";
  if (["false", "no", "off", "0", "n", "disabled", "disable"].includes(v)) return "false";
  if (["", "null", "none", "nil", "undefined", "~"].includes(v)) return "empty";
  if (/^(?:\[\s*\]|\{\s*\}|\(\s*\)|(?:set|list|dict|frozenset|tuple)\(\s*\))$/.test(v)) return "empty";
  return "other";
}

// A key + value that switches oversight off: "suppression-flag" (alerts, notifications, paging),
// "monitoring-off" (monitoring, audit logging, tracing), or null. parent: the enclosing block's key.
export function switchKind(key, parent, raw) {
  const own = words(key);
  let ws = own;
  const fam = (w) => (anyIn(w, ALERT_WORDS) ? "suppression-flag" : anyIn(w, MONITOR_WORDS) ? "monitoring-off" : null);
  let f = fam(own);
  const base = String(key || "").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  if (!f && base.length === 1 && STATE_ONLY.has(base[0]) && parent) { const pw = words(parent); f = fam(pw); ws = [...pw, ...own]; }
  if (!f) return null;
  const k = valueKind(raw);
  const s = anyIn(ws, SUPPRESS_WORDS) || (base.length === 1 && STATE_ONLY.has(base[0]) && !ENABLE_WORDS.has(base[0]));
  const e = anyIn(ws, ENABLE_WORDS);
  if (s && !e && k === "true") return f;
  if (e && !s && k === "false") return f;
  // A bare family key set to a boolean false (alerting: false, audit_log: false).
  if (!s && !e && k === "false" && own.every((w) => ALERT_WORDS.has(w) || MONITOR_WORDS.has(w) || w === "log" || w === "logs" || w === "logging")) return f;
  // An OpenTelemetry exporter set to none.
  if (own.includes("exporter") && (own.includes("otel") || own.includes("otlp") || own.includes("opentelemetry")) && /^["']?none["']?$/i.test(String(raw || "").trim())) return "monitoring-off";
  return null;
}

// A recipient list or alert route ("recipients"), a monitoring sink ("sink"), or null. context: the
// enclosing block's key and the file path, for the weak keys.
export function listKind(key, context = "") {
  const own = words(key);
  const base = String(key || "").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  if (anyIn(own, SINK_VENDORS) && anyIn(base, SINK_NOUNS)) return own.some((w) => w === "pagerduty" || w === "opsgenie") ? "recipients" : "sink";
  if (base.length === 1 && ROUTE_KEYS.has(base[0])) return "recipients";
  if (own.includes("oncall") && anyIn(base, RECIP_NOUNS)) return "recipients";
  const alerty = base.some((w) => ALERT_WORDS.has(w) || w === "incident");
  if (alerty && anyIn(base, RECIP_NOUNS)) return "recipients";
  if ((base.includes("ping") || base.includes("page")) && anyIn(base, PERSON_NOUNS)) return "recipients";
  if (base.length === 1 && WEAK_RECIP.has(base[0]) && anyIn(words(context), ALERT_WORDS)) return "recipients";
  return null;
}
