// MoorAI conformance report: the signed, content-free record the live conformance tier writes.
//
//   scripts/host-conformance.mjs    agent hosts (Claude Code, Cursor, ...) and MCP clients
//   scripts/server-conformance.mjs  AI Servers pieces (model proxy, MCP gateway) against real software
//
// A report says which target ran, at which version, against which model kind, and for each case what
// was expected, what was observed and whether that is a pass. It never carries a prompt, command, tool
// argument, path, host output or model output: every target and case passes through a strict allowlist
// (enums, booleans, integers, version strings), and verifyReport() re-applies that allowlist and refuses a
// report that carried anything it would drop.
//
// Signature: ed25519 over the SHA-256 of the canonical JSON (keys sorted) of the report without its
// `signature` field. The signing key is the conformance key passed with --key (a stable key whose public
// half can be published and pinned), or an ephemeral one generated for the run (the report then proves
// integrity only, and says so: signature.ephemeral true).
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { dirname } from "node:path";
import { cleanVersion } from "./agent-hooks/host-version.mjs";

export const HOST_REPORT_TYPE = "moorai.host-conformance/v1";
export const SERVER_REPORT_TYPE = "moorai.server-conformance/v1";
const TYPES = new Set([HOST_REPORT_TYPE, SERVER_REPORT_TYPE]);

export const CASE_STATUS = ["pass", "fail", "skip", "inconclusive", "gap"];
export const SURFACES = ["agent-turn", "prompt", "mcp-client", "mcp-handshake", "model-proxy", "mcp-gateway", "static"];
export const OUTCOMES = ["allow", "deny", "withhold", "forward", "refuse", "handshake", "unscanned", "none"];
export const TARGET_KINDS = ["host", "mcp-client", "desktop-client", "provider-api", "sdk", "image"];
export const MODEL_KINDS = ["scripted", "ollama", "none"];

// Why a target did not run (or ran only in part). The text is MoorAI's own, never host output.
export const REASONS = {
  "not-installed": "not installed on the machine that ran the tier",
  "auth-required": "a headless turn needs the vendor's account login or API key; the tier uses no account and no key",
  "separate-build-required": "a local-model mode exists only in a separate vendor build that is not installed",
  "no-headless-mode": "a desktop GUI app with no headless mode; driving it would use the person's real profile and account",
  "sdk-not-installed": "the official SDK package is not installed; the tier installs nothing",
  "image-not-present": "the container image is not present locally; the tier pulls nothing",
  "model-unavailable": "the local model server or model is not available",
  "no-live-tier": "no live tier exists for this target",
  "unspecified": "no reason recorded"
};

const ID_RE = /^[a-z0-9][a-z0-9.@-]{0,63}$/;
const CHECK_RE = /^[a-zA-Z][a-zA-Z0-9]{0,39}$/;
const MODEL_RE = /^[a-z0-9][a-z0-9._:-]{0,63}$/;
const CATEGORY_RE = /^[A-Za-z0-9 &:/.,()'+-]{1,80}$/;
const SHORT_RE = /^[A-Za-z-]{1,20}$/;
const CODE_RE = /^[A-Z0-9_]{1,40}$/;
const pick = (v, list, dflt) => (list.includes(v) ? v : dflt);
const intOrNull = (v) => (Number.isInteger(v) && v >= 0 && v < 1e9 ? v : null);
const match = (v, re) => (typeof v === "string" && re.test(v) ? v : null);

function sanitizeChecks(c) {
  const out = {};
  if (!c || typeof c !== "object") return out;
  for (const [k, v] of Object.entries(c).slice(0, 24)) if (CHECK_RE.test(k) && typeof v === "boolean") out[k] = v;
  return out;
}
function sanitizeAlert(a) {
  if (!a || typeof a !== "object") return null;
  return { category: match(a.category, CATEGORY_RE), riskLevel: match(a.riskLevel, SHORT_RE), decision: match(a.decision, SHORT_RE), reasonCode: match(a.reasonCode, CODE_RE) };
}

export function sanitizeCase(c = {}) {
  return {
    id: match(c.id, ID_RE) || "invalid",
    surface: pick(c.surface, SURFACES, "unknown"),
    expect: pick(c.expect, OUTCOMES, "unknown"),
    observed: pick(c.observed, OUTCOMES, "unknown"),
    status: pick(c.status, CASE_STATUS, "fail"),
    checks: sanitizeChecks(c.checks),
    alert: sanitizeAlert(c.alert),
    latencyMs: intOrNull(c.latencyMs)
  };
}

export function sanitizeTarget(t = {}) {
  const out = {
    kind: pick(t.kind, TARGET_KINDS, "unknown"),
    id: match(t.id, ID_RE) || "invalid",
    label: match(t.label, CATEGORY_RE),
    version: cleanVersion(t.version),
    tested: cleanVersion(t.tested),
    ran: t.ran === true,
    model: pick(t.model, MODEL_KINDS, "none"),
    modelName: match(t.modelName, MODEL_RE),
    cases: (Array.isArray(t.cases) ? t.cases : []).slice(0, 64).map(sanitizeCase)
  };
  if (t.reason !== undefined && t.reason !== null) out.reason = Object.hasOwn(REASONS, t.reason) ? t.reason : "unspecified";
  return out;
}

export function summarize(targets = []) {
  const s = { targets: targets.length, ran: 0, notRun: 0, cases: 0, pass: 0, fail: 0, skip: 0, inconclusive: 0, gap: 0 };
  for (const t of targets) {
    if (t.ran === true) s.ran++; else s.notRun++;
    for (const c of t.cases || []) { s.cases++; const st = pick(c.status, CASE_STATUS, "fail"); s[st]++; }
  }
  return s;
}

function sanitizePlatform(p = {}) {
  return { os: match(p.os, /^[a-z0-9]{1,16}$/), arch: match(p.arch, /^[a-z0-9_]{1,16}$/), node: cleanVersion(String(p.node || "").replace(/^v/, "")) };
}

export function buildReport({ type, targets = [], platform = {}, moorai = null, generatedAt = new Date().toISOString() } = {}) {
  const ts = typeof generatedAt === "string" && !Number.isNaN(Date.parse(generatedAt)) ? new Date(generatedAt).toISOString() : null;
  const clean = targets.map(sanitizeTarget);
  return { type: TYPES.has(type) ? type : HOST_REPORT_TYPE, moorai: cleanVersion(moorai), generatedAt: ts, platform: sanitizePlatform(platform), summary: summarize(clean), targets: clean, reasons: Object.fromEntries([...new Set(clean.filter((t) => t.reason).map((t) => t.reason))].map((r) => [r, REASONS[r]])) };
}

export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  return JSON.stringify(v === undefined ? null : v);
}
const digestOf = (body) => createHash("sha256").update(canonical(body)).digest("hex");
const pubB64 = (k) => createPublicKey(k).export({ type: "spki", format: "der" }).toString("base64");
const keyIdOf = (pub) => createHash("sha256").update(Buffer.from(pub, "base64")).digest("hex").slice(0, 16);

export function signReport(report, privateKey, { ephemeral = false } = {}) {
  const { signature: _drop, ...body } = report;
  const digest = digestOf(body);
  const pub = pubB64(privateKey);
  const sig = edSign(null, Buffer.from(digest), privateKey).toString("base64");
  return { ...body, signature: { alg: "ed25519", keyId: keyIdOf(pub), pub, digest, sig, ephemeral: ephemeral === true } };
}

// Re-build the body through the allowlist; a report that changes under it carried something extra.
function resanitize(body) {
  return buildReport({ type: body.type, targets: body.targets, platform: body.platform, moorai: body.moorai, generatedAt: body.generatedAt });
}

export function verifyReport(report, { pub = null } = {}) {
  const no = (reason) => ({ ok: false, reason, keyId: report && report.signature ? report.signature.keyId || null : null });
  if (!report || typeof report !== "object") return no("malformed");
  if (!TYPES.has(report.type)) return no("unknown-type");
  const s = report.signature;
  if (!s || s.alg !== "ed25519" || !s.pub || !s.sig || !s.digest) return no("unsigned");
  const { signature: _s, ...body } = report;
  if (digestOf(body) !== s.digest) return no("digest-mismatch");
  if (canonical(resanitize(body)) !== canonical(body)) return no("not-content-free");
  if (pub && pub !== s.pub) return no("pin-mismatch");
  let ok = false;
  try { ok = edVerify(null, Buffer.from(s.digest), createPublicKey({ key: Buffer.from(s.pub, "base64"), format: "der", type: "spki" }), Buffer.from(s.sig, "base64")); } catch { ok = false; }
  if (!ok) return no("bad-signature");
  if (keyIdOf(s.pub) !== s.keyId) return no("bad-key-id");
  return { ok: true, reason: null, keyId: s.keyId };
}

export function loadOrCreateKey(path) {
  if (existsSync(path)) return createPrivateKey(readFileSync(path));
  const { privateKey } = generateKeyPairSync("ed25519");
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch { /* best effort on platforms without modes */ }
  return privateKey;
}

export function ephemeralKey() { return generateKeyPairSync("ed25519").privateKey; }
