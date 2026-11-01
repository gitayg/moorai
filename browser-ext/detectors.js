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
// and a KEYED one-way hash of the matched span }. The matched text is used solely to compute the
// hash and is never returned to, stored by, or transmitted by the caller. Detection runs entirely
// locally. Requires content-hash.js to be loaded first (manifest.json lists it ahead of this file).
//
// Loadable two ways from ONE file:
//   * Chrome MV3 content script  → sets globalThis.MoorAIDetectors (content.js reads it; same isolated world)
//   * Node (unit test)           → module.exports = api   (test-detectors.mjs requires it)

(function (root) {
  "use strict";

  // ---- keyed one-way content hash — content-hash.js, loaded ahead of this file ----
  // HMAC-SHA-256 under the tenant's install token, so the fingerprint of a matched span cannot be
  // enumerated back to the span by anyone holding only the alert stream. Byte-identical to the
  // agent's for the same token and span. See browser-ext/content-hash.js for the full rationale.
  const H = root.MoorAIContentHash;

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
  // #90 — a payment-card number: 13-19 digits, the Luhn check digit, and an issuer range and length a card
  // network issues — copied from data/card-iin.js (test-detectors.mjs fails if the two differ).
  const CARD_NETWORKS = [
    { network: "visa", ranges: [[4, 4]], lengths: [13, 16, 19] },
    { network: "mastercard", ranges: [[51, 55], [2221, 2720]], lengths: [16] },
    { network: "amex", ranges: [[34, 34], [37, 37]], lengths: [15] },
    { network: "discover", ranges: [[6011, 6011], [644, 649], [65, 65], [622126, 622925]], lengths: [16, 17, 18, 19] },
    { network: "jcb", ranges: [[3528, 3589]], lengths: [16, 17, 18, 19] },
    { network: "diners", ranges: [[300, 305], [3095, 3095], [36, 36], [38, 39]], lengths: [14, 15, 16, 17, 18, 19] },
    { network: "unionpay", ranges: [[62, 62], [8100, 8171]], lengths: [16, 17, 18, 19] },
    { network: "maestro", ranges: [[5018, 5018], [5020, 5020], [5038, 5038], [5893, 5893], [6304, 6304], [6759, 6759], [6761, 6763]], lengths: [13, 14, 15, 16, 17, 18, 19] }
  ];
  function luhnValid(d) {
    let sum = 0;
    for (let i = 0; i < d.length; i++) {
      let n = d.charCodeAt(d.length - 1 - i) - 48;
      if (i % 2) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
    }
    return sum % 10 === 0;
  }
  function cardNetwork(d) {
    for (const n of CARD_NETWORKS) {
      if (!n.lengths.includes(d.length)) continue;
      for (const [lo, hi] of n.ranges) {
        const p = Number(d.slice(0, String(lo).length));
        if (p >= lo && p <= hi) return n.network;
      }
    }
    return null;
  }
  function cardNumberValid(m) {
    const d = String(m).replace(/\D/g, "");
    if (d.length < 13 || d.length > 19) return false;
    return luhnValid(d) && cardNetwork(d) !== null;
  }
  // A card number's hash is keyed per page load, not with the install token, which could enumerate it back
  // to the number (data/cardholder.js); "proc:" says so. Every other finding keeps the tenant-keyed hash.
  const PROC_KEY = root.crypto.getRandomValues(new Uint8Array(32));
  const PROCESS_KEYED = [90];
  function spanHash(threatId, span) {
    return PROCESS_KEYED.includes(threatId) ? "proc:" + H.hashWithKey(PROC_KEY, span).slice(H.HASH_PREFIX.length) : H.contentHash(span);
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
      // A template in the password slot (<NEW_PASSWORD>, ${DB_PASSWORD}, $PGPASS, %s, ****) is not a credential.
      patterns: [/\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp):\/\/[^:@\s/]{1,256}:[^@\s/]{1,256}@/i],
      refine: (m) => !/^(?:<[^<>]*>|\$\{[^}]*\}|\$[A-Za-z_]\w*|\{\{[^}]*\}\}|%[sd]|\*+|x{3,}|\.{3,}|\[[^\]]*\])$/i.test((/:\/\/[^:@\s/]+:([^@\s/]+)@/.exec(m) || [])[1] || "") },
    // Shapeless — entropy/allowlist-gated (refine mirrors data/secrets-patterns.js S(...) refines).
    { detectorId: "secret-generic-assignment", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "a high-entropy secret assigned to a credential-like variable",
      patterns: [/\b(?:api[_-]?key|secret|token|passwd|password|client[_-]?secret|access[_-]?key|auth[_-]?token|private[_-]?key)\b\s{0,8}[:=]\s{0,8}["']?[A-Za-z0-9\-_.\/+=]{20,512}["']?/i],
      refine: (m) => looksLikeSecret(valueOf(m)) },
    { detectorId: "secret-aws-secret", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "an AWS secret access key",
      patterns: [/aws_secret_access_key["']?\s{0,8}[:=]\s{0,8}["']?[A-Za-z0-9\/+]{40}["']?/i],
      refine: (m) => looksLikeSecret(valueOf(m)) },

    // === Credentials / keys — threat #39 (from data/detectors.js) ===
    { detectorId: "dlp-private-key", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "a private key block", patterns: [/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/] },
    { detectorId: "dlp-jwt", threatId: 39, category: "Information & Privacy", riskLevel: "Critical",
      label: "a JWT / bearer token",
      patterns: [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/, /\bBearer\s+[A-Za-z0-9._-]{20,}/i] },

    // === PII — threat #15 "Information & Privacy" / High (from data/detectors.js) ===
    { detectorId: "dlp-email", threatId: 15, category: "Information & Privacy", riskLevel: "High",
      label: "an email address", patterns: [/\b(?<!\w[.+-]*)[\w.+-]+@[\w-]+\.[\w.-]{2,}\b/] }, // linear; see test/dlp-email-redos.test.mjs
    { detectorId: "dlp-national-id", threatId: 15, category: "Information & Privacy", riskLevel: "High",
      label: "a 9-digit national ID", patterns: [/(?<!\d)\d{9}(?!\d)/] },
    // SSN-shaped (ddd-dd-dddd). Not a distinct detector in the agent (its dlp-national-id catches the
    // 9-digit form); added here so the common dashed US SSN shape is caught in the browser too.
    { detectorId: "dlp-ssn", threatId: 15, category: "Information & Privacy", riskLevel: "High",
      label: "a Social-Security-number-shaped value", patterns: [/(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/] },
    { detectorId: "dlp-phone", threatId: 15, category: "Information & Privacy", riskLevel: "High",
      label: "a phone number", patterns: [/(?<!\d)(?:\+?\d{1,3}[ .-]?)?\(?\d{2,4}\)?[ .-]?\d{3}[ .-]?\d{4}(?!\d)/] },

    // === Payment data — #90 cardholder data / Critical and #1 IBAN (from data/detectors.js) ===
    { detectorId: "dlp-payment-card", threatId: 90, category: "Information & Privacy", riskLevel: "Critical",
      label: "a payment-card number", patterns: [/\b(?:\d[ -]?){13,19}\b/], refine: (m) => cardNumberValid(m) },
    { detectorId: "dlp-iban", threatId: 1, category: "Information & Privacy", riskLevel: "High",
      label: "an IBAN / bank account", patterns: [/\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/] },

    // === Prompt injection — threat #3 "Prompt Injection" / Critical (from data/detectors.js inj-ignore) ===
    { detectorId: "inj-ignore", threatId: 3, category: "Prompt Injection", riskLevel: "High",
      label: "an instruction-override / prompt-injection phrase",
      // Patterns verbatim from data/detectors.js. The agent's defensive-framing refine (data/injection-tells.js:
      // "never reveal your system prompt" is a rule, not an attack) is not ported: it is an ES module the
      // content script cannot import, and a user typing into a chat page rarely writes the host's warnings.
      patterns: [
        /ignore (the |all |any )?(previous|above|prior|earlier) (instructions?|prompts?|messages?)/i,
        /disregard (all |any )?(previous|prior|above|earlier)/i,
        /\b(reveal|print|show) (your |the )?(system prompt|instructions|developer message)\b/i,
        /\bdo anything now\b/i,
        /\bDAN\b(?![-\s]{1,2}(?:style|like|type|prompts?|jailbreaks?|attacks?)\b)/,
        /\bjailbr(?:eak|oken|eaked)\s{1,4}(?:mode|persona|state)\b/i,
        /\b(?:you(?:['’]re|\s{1,4}are|\s{1,4}have\s{1,4}been|['’]ve\s{1,4}been|\s{1,4}were|\s{1,4}will\s{1,4}be)|act(?:ing)?\s{1,4}as|pretend(?:ing)?\s{1,4}to\s{1,4}be|respond(?:ing)?\s{1,4}as|behav(?:e|ing)\s{1,4}(?:as|like)|role-?play(?:ing)?\s{1,4}as|simulat(?:e|ing)|becom(?:e|ing)|are\s{1,4}now)\s{1,4}(?:(?:now|a|an|the|fully|completely|totally|officially)\s{1,4}){0,2}jailbr(?:oken|eaked)\b/i,
        /\b(?:enter(?:ing)?|activat(?:e|ing)|enabl(?:e|ing)|engag(?:e|ing)|initiat(?:e|ing)|unlock(?:ing)?|turn(?:ing)?\s{1,4}on|switch(?:ing)?\s{1,4}(?:to|into)|go(?:ing)?\s{1,4}into)\s{1,4}(?:(?:the|your|a|full)\s{1,4}){0,1}jailbr(?:eak|oken)(?:ed)?\b(?!\s{1,4}(?:detect|protect|prevent|filter|classif|test|research|defen|scan|guard|monitor|evaluat|benchmark|attempt|attack|technique|prompt))/i,
        /\bjailbreak(?:ing)?\s{1,4}(?:yourself|you(?![a-z'’])|your\s{1,4}(?:own\s{1,4})?(?:rules|restrictions|filters|guardrails|safety|programming|constraints|guidelines|limitations|alignment))\b/i,
        /\[[^\]\n]{0,4}jailbr(?:eak|oken)[^\]\n]{0,4}\]|(?:^|\s)\/jailbr(?:eak|oken)\b/im
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
        // With a refine, every occurrence is tried until one passes (src/engine.js _matchDetector), so a
        // failing digit run ahead of a real card does not hide the card.
        const span = d.refine ? firstRefined(str, re, d.refine) : (str.match(re) || [])[0];
        if (!span) continue;
        findings.push({
          detectorId: d.detectorId,
          threatId: d.threatId,
          category: d.category,
          riskLevel: d.riskLevel,
          label: d.label,
          contentHash: spanHash(d.threatId, span)  // keyed one-way; the span itself is discarded by the caller
        });
        break; // one finding per detector, like the engine's per-detector dedup
      }
    }
    return findings;
  }

  function firstRefined(str, re, refine) {
    const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    for (const m of str.matchAll(g)) if (refine(m[0], str)) return m[0];
    return null;
  }

  // Reduce findings to the single highest-severity one (for the decision + which label to show).
  function worst(findings) {
    return findings.reduce((a, f) => (!a || (RISK_RANK[f.riskLevel] || 0) > (RISK_RANK[a.riskLevel] || 0) ? f : a), null);
  }

  const api = { DETECTORS, scan, worst, isHighSeverity, shannonEntropy, looksLikeSecret, RISK_RANK, CARD_NETWORKS, cardNumberValid };

  if (typeof module !== "undefined" && module.exports) module.exports = api; // Node (unit test)
  root.MoorAIDetectors = api;                                               // content-script isolated world
})(typeof globalThis !== "undefined" ? globalThis : this);
