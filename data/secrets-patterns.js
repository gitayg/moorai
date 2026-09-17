// #7 — battle-tested secrets engine. A broad, maintainable set of prefix-anchored secret detectors
// (all → threat #39; the engine dedups findings by threatId, so many detectors never spam), plus an
// entropy + allowlist gate for the two "shapeless" cases (generic assignments, AWS secret keys) that
// would otherwise false-positive on UUIDs, git SHAs, base64 images, etc. False-positive blocks are
// the #1 killer of guardrail adoption, so the shapeless detectors only fire on genuinely high-entropy
// values that aren't a known-benign shape.

// Shannon entropy in bits/char.
export function shannonEntropy(s) {
  if (!s) return 0;
  const freq = Object.create(null);
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let e = 0;
  const n = s.length;
  for (const c in freq) { const p = freq[c] / n; e -= p * Math.log2(p); }
  return e;
}

// Known-benign shapes that are high-length but NOT secrets — reject these before the entropy test.
const BENIGN = [
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i, // UUID v1-5
  /^[0-9a-f]{40}$/i,                 // git SHA-1
  /^[0-9a-f]{64}$/i,                 // SHA-256 hex digest
  /^\d{4}-\d{2}-\d{2}T[\d:.]+/,      // ISO-8601 timestamp
  /^(true|false|null|undefined|changeme|password|example|redacted|xxxx+|todo|placeholder)$/i
];
function looksBenign(v) { return BENIGN.some((r) => r.test(v)); }

// Does a candidate value look like a real secret? High entropy, long enough, not a benign shape,
// not a media blob. Hex gets a lower bar than base64 (smaller alphabet → lower max entropy).
export function looksLikeSecret(v) {
  const val = String(v).replace(/^["'\s]+|["'\s]+$/g, "");
  if (val.length < 20 || val.length > 512) return false;
  if (/^data:[a-z]+\//i.test(val)) return false; // data URI / media blob
  if (looksBenign(val)) return false;
  const hex = /^[0-9a-f]+$/i.test(val);
  return shannonEntropy(val) >= (hex ? 3.0 : 3.5);
}

// The value side of a `NAME = "value"` match, for the entropy check. (The old tail-anchored extractor
// admitted `_` and `=`, so on `SECRET_KEY=abc…` it returned the whole assignment, name included.)
const assignedValue = (m) => String(m).replace(/^[^:=]*[:=]\s*/, "");

// Placeholder words that fill template values ("your-api-key-goes-here", "EXAMPLE_SECRET_KEY_VALUE").
const FILLER = /your|here|goes|example|sample|placeholder|change[_-]?me|replace|insert|dummy|fake|redacted|todo|secret|password|passwd|token|api|access|key|value|xxx+/gi;
// A monotonic run like 0123456 / abcdefg is a typed placeholder, not generator output.
const SEQUENTIAL = /0123456|1234567|2345678|3456789|abcdefg|bcdefgh|cdefghi|defghij|qwertyu/i;
// Template-only markers: in a committed env template an EXAMPLE-bearing value is documentation.
const TEMPLATE_MARKER = /example|sample|placeholder|dummy|fake/i;

// looksLikeSecret plus placeholder rejection, for values found beside a secret-like NAME. `ctx` is the
// engine's optional scan context; ctx.template marks a committed env template (.env.example …).
export function looksLikeAssignedSecret(v, ctx) {
  const val = String(v).replace(/^["'\s]+|["'\s]+$/g, "");
  if (!looksLikeSecret(val)) return false;
  if (SEQUENTIAL.test(val)) return false;
  if (/^[a-z]+(?:[-_.][a-z]+){3,}$/i.test(val)) return false; // "replace-me-with-a-random-string"
  if (ctx?.template && TEMPLATE_MARKER.test(val)) return false;
  const core = val.replace(FILLER, "").replace(/[^A-Za-z0-9]/g, "");
  return core.length >= 16 && shannonEntropy(core) >= 3.5;
}

const S = (detectorId, hint, patterns, refine) => {
  const d = { detectorId, threatId: 39, stage: "prompt", stages: ["prompt", "output"], mode: "warn", hint, patterns };
  if (refine) d.refine = refine;
  return d;
};

export const SECRET_DETECTORS = [
  // ---- Prefix-anchored provider tokens (structurally unmistakable → no entropy needed) ----
  S("secret-github", "Looks like a GitHub token.", [
    /\bgh[posru]_[A-Za-z0-9]{36,}\b/,
    /\bgithub_pat_[A-Za-z0-9_]{22,}\b/
  ]),
  S("secret-gitlab", "Looks like a GitLab token.", [/\bglpat-[A-Za-z0-9\-_]{20,}\b/]),
  S("secret-slack", "Looks like a Slack token.", [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/]),
  S("secret-stripe", "Looks like a Stripe key.", [/\b[rs]k_(live|test)_[A-Za-z0-9]{16,}\b/]),
  S("secret-aws-akia", "Looks like an AWS access key ID.", [/\b(AKIA|ASIA)[A-Z0-9]{16}\b/]),
  S("secret-google-api", "Looks like a Google API key.", [/\bAIza[A-Za-z0-9\-_]{35}\b/]),
  S("secret-openai-anthropic", "Looks like an OpenAI / Anthropic API key.", [/\bsk-(ant-|proj-)?[A-Za-z0-9\-_]{20,}\b/]),
  S("secret-npm", "Looks like an npm token.", [/\bnpm_[A-Za-z0-9]{36}\b/]),
  S("secret-pypi", "Looks like a PyPI token.", [/\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{40,}/]),
  S("secret-sendgrid", "Looks like a SendGrid API key.", [/\bSG\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{30,}\b/]),
  S("secret-twilio", "Looks like a Twilio key/SID.", [/\bSK[0-9a-fA-F]{32}\b/, /\bAC[0-9a-fA-F]{32}\b/]),
  S("secret-azure", "Looks like an Azure storage connection string.", [/AccountKey=[A-Za-z0-9\/+]{40,}={0,2}/i]),
  S("secret-gcp-sa", "Looks like a GCP service-account key.", [/"type"\s*:\s*"service_account"[\s\S]{0,300}?"private_key"\s*:\s*"-----BEGIN/i]),
  S("secret-db-conn", "Looks like a database connection string with an embedded password.", [
    /\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp):\/\/[^:@\s/]+:[^@\s/]+@/i
  ]),
  // ---- Shapeless: only fire when the value is genuinely high-entropy (entropy + allowlist gate) ----
  //
  // EVERY quantifier below is bounded, and that is load-bearing. These detectors carry a refine(), so
  // src/engine.js _matchDetector recompiles their patterns through safeRegex — which refuses a pattern
  // with more than one unbounded quantifier. From v0.63.2 to this change both of the original patterns
  // (`\s*[:=]\s*…{20,}`) were refused and the two detectors never fired at all: a lone
  // `AWS_SECRET_ACCESS_KEY=…` line produced no finding. test/hook-gaps-named-secret.test.mjs pins it.
  S("secret-generic-assignment", "High-entropy value assigned to a secret-like variable.", [
    /\b(?:api[_-]?key|secret|token|passwd|password|client[_-]?secret|access[_-]?key|auth[_-]?token|private[_-]?key)\b\s{0,8}[:=]\s{0,8}["']?[A-Za-z0-9\-_.\/+=]{20,512}["']?/i
  ], (m, _t, ctx) => looksLikeAssignedSecret(assignedValue(m), ctx)),
  S("secret-aws-secret", "Looks like an AWS secret access key.", [
    /aws_secret_access_key["']?\s{0,8}[:=]\s{0,8}["']?[A-Za-z0-9\/+]{40}["']?/i
  ], (m, _t, ctx) => looksLikeAssignedSecret(assignedValue(m), ctx)),
  // Env-style NAMED secret: FOO_API_KEY / FOO_SECRET_KEY / FOO_TOKEN / FOO_PASSWORD = <high-entropy>.
  // Upper-case names only — the env-var / .env convention. Lower-case `page_token` / `csrf_token` in
  // code carry high-entropy values that are not credentials.
  S("secret-named-assignment", "High-entropy value assigned to a named secret variable (…_API_KEY, …_TOKEN, …).", [
    /\b(?:[A-Z0-9_]{0,60}_)?(?:SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|TOKEN|PASSWORD)["']?\s{0,8}[:=]\s{0,8}["']?[A-Za-z0-9\-_.\/+=]{20,512}["']?/
  ], (m, _t, ctx) => looksLikeAssignedSecret(assignedValue(m), ctx))
];
