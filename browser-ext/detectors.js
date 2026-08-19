// MoorAI Browser Guard — on-device, content-free detection engine.
//
// This is a SMALL, self-contained, faithful SUBSET of the MoorAI agent's detectors. It mirrors
//   - data/detectors.js            (dlp-email, dlp-national-id, dlp-payment-card, dlp-private-key,
//                                    dlp-jwt, dlp-phone, inj-ignore, and the secret detectors)
//   - data/secrets-patterns.js     (prefix-anchored provider tokens + the entropy/allowlist gate
//                                    for the two "shapeless" cases)
//   - data/content-rules.js        (nothing ported here — parental content rules are out of scope
//                                    for a prompt guard)
// Only a small, high-signal cross-section is ported so the extension stays reviewable. The regexes
// are copied VERBATIM from the agent so a finding here means the same thing it would in the CLI hook.
//
// CONTENT-FREE BY CONSTRUCTION: this module returns only { threatId, category, riskLevel, label,
// and a one-way djb2 hash of the matched span }. The matched text is used solely to compute the hash
// and is never returned to, stored by, or transmitted by the caller. Detection runs entirely locally.
//
// Loadable two ways from ONE file:
//   * Chrome MV3 content script  → sets globalThis.MoorAIDetectors (content.js reads it; same isolated world)
//   * Node (unit test)           → module.exports = api   (test-detectors.mjs requires it)

(function (root) {
  "use strict";

  // ---- one-way content-free hash — copied VERBATIM from cli/moorai-hook.mjs `djb2` ----
  // Kept byte-identical so a hash computed in the browser matches the agent's hash for the same span.
  function djb2(s) {
    let h = 5381;
    for (let i = 0; i < String(s).length; i++) h = ((h << 5) + h + String(s).charCodeAt(i)) >>> 0;
    return "h" + h.toString(16);
  }

  // ---- entropy + allowlist gate — copied from data/secrets-patterns.js ----
  // The two "shapeless" secret detectors (generic assignment, AWS secret key) would false-positive on
  // UUIDs, git SHAs, base64 images, etc., so they only fire on genuinely high-entropy values.
  function shannonEntropy(s) {
    if (!s) return 0;
    const freq = Object.create(null);
    for (const c of s) freq[c] = (freq[c] || 0) + 1;
    let e = 0;
    const n = s.length;
    for (const c in freq) { const p = freq[c] / n; e -= p * Math.log2(p); }
    return e;
  }
  const BENIGN = [
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i, // UUID v1-5
    /^[0-9a-f]{40}$/i,                 // git SHA-1
    /^[0-9a-f]{64}$/i,                 // SHA-256 hex digest
    /^\d{4}-\d{2}-\d{2}T[\d:.]+/,      // ISO-8601 timestamp
    /^(true|false|null|undefined|changeme|password|example|redacted|xxxx+|todo|placeholder)$/i
  ];
  function looksBenign(v) { return BENIGN.some((r) => r.test(v)); }
  function looksLikeSecret(v) {
    const val = String(v).replace(/^["'\s]+|["'\s]+$/g, "");
    if (val.length < 20 || val.length > 512) return false;
    if (/^data:[a-z]+\//i.test(val)) return false; // data URI / media blob
    if (looksBenign(val)) return false;
    const hex = /^[0-9a-f]+$/i.test(val);
    return shannonEntropy(val) >= (hex ? 3.0 : 3.5);
  }
  const valueOf = (m) => {
    const mm = String(m).match(/["']?([A-Za-z0-9\-_.\/+=]{20,})["']?\s*$/);
    return mm ? mm[1] : m;
  };

  // ---- ported detector set ----
  // Each detector carries the agent's threatId + threat category + riskLevel (so a posted alert is
  // shape-identical to the CLI hook), plus a short human `label` used only for the inline coach banner.
  // `category` values mirror data/threats.json ("Information & Privacy", "Prompt Injection").
  const DETECTORS = [
    // === Secrets — threat #39 "Information & Privacy" / Critical (from data/secrets-patterns.js) ===
    { detectorId: "secret-aws-akia", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "an AWS access key ID", patterns: [/\b(AKIA|ASIA)[A-Z0-9]{16}\b/] },
    { detectorId: "secret-github", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "a GitHub token", patterns: [/\bgh[posru]_[A-Za-z0-9]{36,}\b/, /\bgithub_pat_[A-Za-z0-9_]{22,}\b/] },
    { detectorId: "secret-slack", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "a Slack token", patterns: [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/] },
    { detectorId: "secret-stripe", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "a Stripe key", patterns: [/\b[rs]k_(live|test)_[A-Za-z0-9]{16,}\b/] },
    { detectorId: "secret-google-api", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "a Google API key", patterns: [/\bAIza[A-Za-z0-9\-_]{35}\b/] },
    { detectorId: "secret-openai-anthropic", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "an OpenAI / Anthropic API key", patterns: [/\bsk-(ant-|proj-)?[A-Za-z0-9\-_]{20,}\b/] },
    { detectorId: "secret-db-conn", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "a database connection string with an embedded password",
      patterns: [/\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp):\/\/[^:@\s/]+:[^@\s/]+@/i] },
    // Shapeless — entropy/allowlist-gated (refine mirrors data/secrets-patterns.js S(...) refines).
    { detectorId: "secret-generic-assignment", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "a high-entropy secret assigned to a credential-like variable",
      patterns: [/\b(?:api[_-]?key|secret|token|passwd|password|client[_-]?secret|access[_-]?key|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*["']?[A-Za-z0-9\-_.\/+=]{20,}["']?/i],
      refine: (m) => looksLikeSecret(valueOf(m)) },
    { detectorId: "secret-aws-secret", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "an AWS secret access key",
      patterns: [/aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9\/+]{40}["']?/i],
      refine: (m) => looksLikeSecret(valueOf(m)) },

    // === Credentials / keys — threat #39 (from data/detectors.js) ===
    { detectorId: "dlp-private-key", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "a private key block", patterns: [/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/] },
    { detectorId: "dlp-jwt", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "a JWT / bearer token",
      patterns: [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/, /\bBearer\s+[A-Za-z0-9._-]{20,}/i] },

    // === PII — threat #15 "Information & Privacy" / High (from data/detectors.js) ===
    { detectorId: "dlp-email", threatId: 15, category: "Information & Privacy", riskLevel: "High",
      label: "an email address", patterns: [/\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b/] },
    { detectorId: "dlp-national-id", threatId: 15, category: "Information & Privacy", riskLevel: "High",
      label: "a 9-digit national ID", patterns: [/(?<!\d)\d{9}(?!\d)/] },
    // SSN-shaped (ddd-dd-dddd). Not a distinct detector in the agent (its dlp-national-id catches the
    // 9-digit form); added here so the common dashed US SSN shape is caught in the browser too.
    { detectorId: "dlp-ssn", threatId: 15, category: "Information & Privacy", riskLevel: "High",
      label: "a Social-Security-number-shaped value", patterns: [/(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/] },
    { detectorId: "dlp-phone", threatId: 15, category: "Information & Privacy", riskLevel: "High",
      label: "a phone number", patterns: [/(?<!\d)(?:\+?\d{1,3}[ .-]?)?\(?\d{2,4}\)?[ .-]?\d{3}[ .-]?\d{4}(?!\d)/] },

    // === Payment data — threat #1 "Information & Privacy" / Critical (from data/detectors.js) ===
    { detectorId: "dlp-payment-card", threatId: 1, category: "Information & Privacy", riskLevel: "Critical",
      label: "a payment-card number", patterns: [/\b(?:\d[ -]?){13,16}\b/] },
    { detectorId: "dlp-iban", threatId: 1, category: "Information & Privacy", riskLevel: "High",
      label: "an IBAN / bank account", patterns: [/\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/] },

    // === Prompt injection — threat #3 "Prompt Injection" / Critical (from data/detectors.js inj-ignore) ===
    { detectorId: "inj-ignore", threatId: 3, category: "Prompt Injection", riskLevel: "High",
      label: "an instruction-override / prompt-injection phrase",
      patterns: [
        /ignore (the |all |any )?(previous|above|prior|earlier) (instructions?|prompts?|messages?)/i,
        /disregard (all |any )?(previous|prior|above|earlier)/i,
        /\b(reveal|print|show) (your |the )?(system prompt|instructions|developer message)\b/i,
        /\b(jailbreak|do anything now|\bDAN\b)\b/i
      ] }
  ];

  // Severity ranking — matches the agent's ordering. High and above are "high severity" for block mode.
  const RISK_RANK = { Low: 1, Medium: 2, High: 3, Critical: 4, Blocked: 5 };
  function isHighSeverity(riskLevel) { return (RISK_RANK[riskLevel] || 0) >= RISK_RANK.High; }

  // Scan text and return content-free findings. Mirrors src/engine.js scan(): for each detector, the
  // first matching pattern (after an optional refine) yields one finding per detector. `match` is the
  // matched span and is used ONLY to compute contentHash — callers must never surface or transmit it.
  function scan(text) {
    const findings = [];
    if (!text || !String(text).trim()) return findings;
    const str = String(text);
    for (const d of DETECTORS) {
      for (const re of d.patterns) {
        const m = str.match(re);
        if (!m) continue;
        const span = m[0];
        if (d.refine && !d.refine(span, str)) continue;
        findings.push({
          detectorId: d.detectorId,
          threatId: d.threatId,
          category: d.category,
          riskLevel: d.riskLevel,
          label: d.label,
          contentHash: djb2(span)  // one-way; the span itself is discarded by the caller
        });
        break; // one finding per detector, like the engine's per-detector dedup
      }
    }
    return findings;
  }

  // Reduce findings to the single highest-severity one (for the decision + which label to show).
  function worst(findings) {
    return findings.reduce((a, f) => (!a || (RISK_RANK[f.riskLevel] || 0) > (RISK_RANK[a.riskLevel] || 0) ? f : a), null);
  }

  const api = { DETECTORS, scan, worst, djb2, isHighSeverity, shannonEntropy, looksLikeSecret, RISK_RANK };

  if (typeof module !== "undefined" && module.exports) module.exports = api; // Node (unit test)
  root.MoorAIDetectors = api;                                               // content-script isolated world
})(typeof globalThis !== "undefined" ? globalThis : this);
