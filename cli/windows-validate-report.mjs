// The content-free report of the Windows runtime validation (cli/moorai-windows-validate.mjs). Everything
// in it is a fixed id, an enum, a count, a boolean, a Windows build number or an hour-rounded time. Probe
// results and alerts pass through allowlists here, so a probe that returned free text (a path, a command,
// an error message) cannot carry it into the file an operator shares.
import { PROBE_INFO, NOT_COVERED } from "./windows-validate-table.mjs";

export const REPORT_SCHEMA = "moorai-windows-validation/1";
export const STATUSES = Object.freeze(["pass", "fail", "skipped", "error"]);
// Every value a probe may report as expected or observed. Anything else reads as "other".
export const OUTCOMES = Object.freeze(["allow", "deny", "ask", "alert", "refused", "forwarded", "mxc", "none", "unknown", "ubr-read", "no-ubr",
  "delivered", "missing", "leaked", "error", "timeout", "other"]);
export const REASONS = Object.freeze(["not-windows", "not-run", "spawn-failed", "timeout", "no-decision", "bad-output", "not-listening",
  "machine-anchor", "precondition"]);
const REASON_CODE_RE = /^[A-Z][A-Z0-9_]{1,63}$/;
const SEMVER_RE = /^\d{1,4}\.\d{1,4}\.\d{1,6}$/;

const pick = (v, list, dflt) => (list.includes(v) ? v : dflt);
const bool = (v) => v === true;
const tri = (v) => (v === true || v === false ? v : null);

export function hourRounded(ms) {
  const d = new Date(Number.isFinite(ms) ? ms : Date.now());
  d.setUTCMinutes(0, 0, 0);
  return d.toISOString();
}

function cleanProbe(p) {
  const info = p && PROBE_INFO[p.id];
  if (!info) return null;
  const ms = Number(p.ms);
  return {
    id: p.id,
    surface: info.surface,
    status: pick(p.status, STATUSES, "error"),
    expected: pick(p.expected, OUTCOMES, "other"),
    observed: pick(p.observed, OUTCOMES, "other"),
    reason: pick(p.reason, REASONS, null),
    ms: Number.isFinite(ms) && ms > 0 ? Math.round(ms) : 0,
    proves: info.proves
  };
}

// The alerts the loopback console received: counted by decision and by reasonCode only. contentFree is
// false if any alert's serialized form contains the run's marker (a string planted in every command, URL
// and argument the probes send).
export function summarizeAlerts(alerts, marker) {
  const list = Array.isArray(alerts) ? alerts : [];
  const byReasonCode = {};
  let deny = 0, leaked = false;
  for (const a of list) {
    if (!a || typeof a !== "object") continue;
    if (a.decision === "deny") deny++;
    if (typeof a.reasonCode === "string" && REASON_CODE_RE.test(a.reasonCode)) byReasonCode[a.reasonCode] = (byReasonCode[a.reasonCode] || 0) + 1;
    if (marker) { try { if (JSON.stringify(a).includes(marker)) leaked = true; } catch { leaked = true; } }
  }
  return { received: list.length, deny, contentFree: !leaked, byReasonCode };
}

// pass: nothing failed and (Windows not required, or nothing skipped). incomplete: Windows required and a
// probe skipped. fail: anything failed or errored, or nothing ran at all.
export function verdictOf(probes, { requireWindows = false } = {}) {
  if (!Array.isArray(probes) || probes.length === 0) return "fail";
  if (probes.some((p) => p.status === "fail" || p.status === "error")) return "fail";
  if (requireWindows && probes.some((p) => p.status === "skipped")) return "incomplete";
  return "pass";
}
export const strictExitCode = (report) => (report && report.summary && report.summary.verdict === "pass" ? 0 : 1);

function platformOf(p) { return ["win32", "darwin", "linux"].includes(p) ? p : "other"; }
function osBuildOf(platform, rel) {
  if (platform !== "win32") return null;
  const m = /^10\.0\.(\d{4,6})(?:$|\.)/.exec(String(rel || ""));
  return m ? Number(m[1]) : null;
}

// raw: { probes: [{ id, status, expected, observed, reason, ms }], alerts: [alert bodies], marker, meta }.
export function buildReport(raw = {}) {
  const meta = raw.meta || {};
  const probes = (Array.isArray(raw.probes) ? raw.probes : []).map(cleanProbe).filter(Boolean);
  const requireWindows = bool(meta.requireWindows);
  const count = (s) => probes.filter((p) => p.status === s).length;
  const platform = platformOf(meta.platform);
  const nodeMajor = /^v?(\d{1,3})\./.exec(String(meta.node || ""));
  return {
    schema: REPORT_SCHEMA,
    generatedAt: hourRounded(meta.now),
    agentVersion: SEMVER_RE.test(String(meta.agentVersion || "")) ? meta.agentVersion : null,
    platform,
    arch: pick(meta.arch, ["x64", "arm64", "ia32"], "other"),
    osBuild: osBuildOf(platform, meta.release),
    node: nodeMajor ? Number(nodeMajor[1]) : null,
    mxcCapable: tri(meta.mxcCapable),
    machineBinding: bool(meta.machineBinding),
    machineAnchor: bool(meta.machineAnchor),
    requireWindows,
    probes,
    alerts: summarizeAlerts(raw.alerts, raw.marker),
    summary: { pass: count("pass"), fail: count("fail"), skipped: count("skipped"), error: count("error"), verdict: verdictOf(probes, { requireWindows }) },
    notCovered: NOT_COVERED.map((n) => ({ ...n }))
  };
}

// The operator's console view: one line per probe with what a pass proves, then the verdict.
export function formatText(report) {
  const lines = [`MoorAI Windows validation (${report.schema})`,
    `platform ${report.platform} ${report.arch}${report.osBuild ? ` build ${report.osBuild}` : ""}, node ${report.node}, agent ${report.agentVersion || "unknown"}, mxcCapable ${report.mxcCapable}`,
    ""];
  for (const p of report.probes) {
    lines.push(`${p.id.padEnd(24)} ${p.status.padEnd(8)} expected ${p.expected}, observed ${p.observed}${p.reason ? ` (${p.reason})` : ""}, ${p.ms} ms`);
    lines.push(`${"".padEnd(24)} ${p.proves}`);
  }
  const a = report.alerts;
  lines.push("", `alerts at the loopback console: ${a.received} received, ${a.deny} deny, content-free ${a.contentFree}`);
  if (report.machineBinding || report.machineAnchor) lines.push("note: this device has a machine-wide MoorAI binding or policy anchor; an admin setting can change what a probe observes");
  lines.push("", "not covered by this run:");
  for (const n of report.notCovered) lines.push(`  ${n.id}: ${n.why}`);
  const s = report.summary;
  lines.push("", `${s.pass} pass, ${s.fail} fail, ${s.skipped} skipped, ${s.error} error`, `verdict: ${s.verdict}`);
  return lines.join("\n") + "\n";
}
