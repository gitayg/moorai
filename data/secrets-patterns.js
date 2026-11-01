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

// ---- Labeled credentials (no entropy bar) ----
// A credential written as a labeled line (a "Master Password:" or "API Key:" line in a memo or a config
// dump) carries an unknown prefix and low entropy, so neither the provider prefixes nor the entropy gate see it.
// The label is the evidence instead, and the value gate below carries the false-positive burden:
// placeholders, references, code, type names (a bare word), URLs, paths, versions, dates and prose never pass.
const VALUE_PLACEHOLDER = [
  /^<[^>]*>?$/, /…|\.{3}/, /\$\{|\{\{|\}\}|%\(|%[sd]\b/, /^\$[A-Za-z_({]/, /\{\}|\{\d{1,2}\}|\{[A-Za-z_]\w{0,40}\}/, /^\[[^\]]*\]?$/, /^x{3,}/i, /^\*{3,}/, /^\.{3,}/,
  /change[_-]?me|your[_-]|[_-]here\b|example|sample|placeholder|redacted|dummy|fake|insert[_-]|replace[_-]?(?:me|with)|\btodo\b|\btbd\b/i,
  /^test/i,
  /^(?:none|null|nil|true|false|undefined|empty|admin|root|user|guest|demo|default|pass|letmein|qwerty)\d*[!.]?$/i,
  /pass(?:wor)?d|passwd|secret|token|api[_-]?key|apikey/i // a reference to another variable, or the label itself
];
const VALUE_NOT_SECRET = [
  /^[A-Za-z]+(?:[-_.][A-Za-z]+)*[-_.!]?$/,                // a word, or words joined by - _ .
  /^--?[A-Za-z]/,                                        // a command-line flag
  /\?\.|\?\?|\]\{\d|\\[dwsbDWS\][]/,                       // optional chaining, ??, regex syntax
  /\w\(|\w\[/,                                           // a call or an index: os.environ.get(…), Optional[str]
  /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/,           // member access (self.token) or a hostname
  /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/,                     // a CONSTANT_NAME reference
  /:\/\//, /^(?:~|\.{1,2})?\//,                          // a URL or a path
  /^[^@\s]+@[\w-]+(?:\.[\w-]+)+$/,                       // an email address
  /^v?\d+(?:\.\d+)+(?:[-+.][\w.]+)?$/i,                  // a version
  /^\d{4}-\d{2}-\d{2}/,                                  // a date or timestamp
  /^[\d.,:/+-]+$/                                        // a number, a ratio, a phone number
];
// Strip the quoting and trailing punctuation a value picks up in JSON, YAML, INI and Markdown.
const cleanValue = (v) => String(v).replace(/^[\s*"'`]+/, "").replace(/["'`]?[,;})\]]*[*"'`]*$/, "");
// A base64 value that decodes to printable text is judged on the text too: a Kubernetes Secret manifest
// in a tutorial carries `password: cGxhY2Vob2xkZXI=`, which is "placeholder".
function decodedPlaceholder(v) {
  if (v.length % 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(v) || typeof atob !== "function") return false;
  let d;
  try { d = atob(v); } catch { return false; }
  if (!/^[\x20-\x7e]+$/.test(d)) return false;
  return VALUE_PLACEHOLDER.some((r) => r.test(d)) || VALUE_NOT_SECRET[0].test(d);
}
export function plausibleLabeledSecret(raw) {
  const v = cleanValue(raw);
  if (v.length < 8 || v.length > 256 || /\s/.test(v)) return false;
  if (new Set(v.toLowerCase()).size < 5) return false;     // aaaaaaaa, a1a1a1a1
  if (SEQUENTIAL.test(v) || looksBenign(v)) return false;   // UUID, git SHA, digest, timestamp
  if (VALUE_PLACEHOLDER.some((r) => r.test(v)) || VALUE_NOT_SECRET.some((r) => r.test(v))) return false;
  return !decodedPlaceholder(v);
}
// A token label with a non-credential prefix: pagination cursors, CSRF and request nonces.
const NON_CREDENTIAL_TOKEN = /(?:^|[_\s-])(?:page|next|prev(?:ious)?|csrf|xsrf|continuation|cursor|sync|pagination|nonce|state|request|idempotency|resume)[_\s-]?token$/i;
// One labeled pair, re-run over the matched span so a pair that the pattern's tail swallowed is still read.
const LABELED_PAIR = /\b(?:[A-Za-z0-9]{1,30}[_-]){0,4}(?:pass(?:wor)?d|pwd|secret|api[ _-]?key|apikey|access[ _-]?key|(?:auth[ _-]?)?token|private[ _-]?key|client[ _-]?secret|credentials?)["'*_]{0,3}[ \t]{0,4}[:=](?!=)[ \t*]{0,6}["'`]?[^\s"'`<>]{8,128}/gi;
// Text straight after the value that reads as a continuation ("abc12345 is the default") is prose or code.
const PROSE_TAIL = /^[ \t]+[A-Za-z]{2,}/;
// `text` is the full scanned text: it tells a value the 60-character tail cut short from one that ends there.
export function labeledSecretIn(span, text) {
  span = String(span);
  const at = typeof text === "string" ? text.indexOf(span) : -1;
  const cutShort = at >= 0 && /[^\s"'`<>]/.test(text[at + span.length] || "");
  for (const m of span.matchAll(LABELED_PAIR)) {
    const cut = m[0].search(/[:=]/);
    const label = m[0].slice(0, cut).replace(/["'*_\s]+$/, "");
    if (NON_CREDENTIAL_TOKEN.test(label)) continue;
    const rest = m[0].slice(cut + 1).replace(/^[\s*"'`]+/, "");
    const value = (/^[^\s"'`<>]+/.exec(rest) || [""])[0];
    // A later pair whose value the pattern's tail cut short is unreadable.
    if (cutShort && m.index > 0 && m.index + m[0].length >= span.length) continue;
    const after = span.slice(m.index + cut + 1).replace(/^[\s*"'`]+/, "").slice(value.length).replace(/^["'`*]+/, "");
    if (PROSE_TAIL.test(after)) continue;
    if (plausibleLabeledSecret(value)) return true;
  }
  return false;
}

// ---- Heading-scoped credential lists ----
// "Current Production API Keys:\n- Main API: api_prod_…" — the label names a service, not a secret, so
// the heading is the evidence. Its scope is the list that follows; it ends at a blank line followed by a
// non-list line, or at the next heading. A heading-scoped value must also look generated (three or more
// letter/digit transitions), because the entry label says nothing about it.
const CRED_HEADING_WORD = /\b(?:api[ _-]?keys|credentials|passwords|secrets|tokens)\b/i;
const LIST_MARK = /^[ \t]*(?:[-*+•]|\d{1,3}[.)])[ \t]+/;
const LIST_ENTRY = /^[ \t]*(?:[-*+•]|\d{1,3}[.)])[ \t]+[*_`]{0,2}[A-Za-z][\w .()/&'-]{0,40}?[*_`]{0,2}[ \t]{0,4}[:=](?!=)[ \t]*[*_`"']{0,3}([^\s"'`<>]{8,256})(.*)$/;
const words = (t) => t.split(/\s+/).filter(Boolean).length;
const UNDERLINE = /^[ \t]*(?:={3,}|-{3,})[ \t]*$/;
function headingKind(line, next) {
  const t = line.trim();
  if (!t || t.length > 100 || LIST_MARK.test(line) || UNDERLINE.test(line)) return null;
  if (/^#{1,6}\s/.test(t) || UNDERLINE.test(next || "")) return "section";
  if (/^(?:\*\*|__)[^*_]{1,80}(?:\*\*|__):?$/.test(t) && words(t) <= 10) return "section";
  if (t === t.toUpperCase() && /[A-Z]{3}/.test(t) && words(t) <= 10) return "section";
  if (/^[^:]{1,80}:$/.test(t) && words(t) <= 6) return "label";
  return null;
}
const transitions = (v) => (v.match(/[A-Za-z](?=\d)|\d(?=[A-Za-z])/g) || []).length;
export function headingScopedSecretIn(span) {
  const lines = String(span).split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (!headingKind(lines[i], lines[i + 1]) || !CRED_HEADING_WORD.test(lines[i])) continue;
    let blank = false;
    for (let j = i + 1; j < lines.length; j++) {
      const line = lines[j];
      if (j === i + 1 && UNDERLINE.test(line)) continue;
      if (!line.trim()) { blank = true; continue; }
      const e = LIST_ENTRY.exec(line);
      if (e) {
        if (!PROSE_TAIL.test(e[2].replace(/^["'`*]+/, "")) && plausibleLabeledSecret(e[1]) && transitions(cleanValue(e[1])) >= 3) return true;
      } else if (LIST_MARK.test(line)) {
        // a list entry without a value: still inside the list
      } else if (headingKind(line, lines[j + 1]) === "section" || blank) break;
      blank = false;
    }
  }
  return false;
}

// ---- Application-specific passwords (MITRE ATT&CK T1697) ----
// 16 lowercase letters: Google shows four groups of four joined by spaces, Apple joins them with hyphens,
// Microsoft prints them contiguous. Letters only, so the entropy bar and the labeled-prose value gate (which
// reads a letter run as a word) never see one. A label carries the evidence; an unlabeled hyphenated token
// must also hold a group with no vowel, which an English slug never does. Unlabeled spaced or contiguous
// letters are ordinary text and never fire.
const ASP_SEP = /[ \t]{0,4}[:=](?!=)|[ \t]{1,4}is:?(?=[ \t])/i;
const ASP_VALUE = /^[\s*"'`]*([A-Za-z]{4}([ -]?)[A-Za-z]{4}\2[A-Za-z]{4}\2[A-Za-z]{4})(?![A-Za-z0-9])/;
// Common four-letter words: a group that is one is prose or a slug, not a generated password.
const COMMON4 = new Set(("this that with from have they will what when your been were them more some than into only over also such each " +
  "make like just know take come time year good very well back much then here even want look most give need find tell work call case same " +
  "both part used uses sure mean does done many must open read keep show seem left feel high long last next home name real line text font " +
  "bold gray size type file data user code test flow docs feat auth main page view form list item node path true null void base mode safe " +
  "sign mail send note link info help zero full free fast slow easy hard best tips pros news blog post edit save load copy move wait stop " +
  "push pull tags once pass word apps step turn days able away down").split(" "));
const vowelless = (g) => !/[aeiouy]/.test(g);
// The value gate every app-password form shares: lowercase, varied, not typed in sequence, not a placeholder.
function plausibleAppPassword(value) {
  if (!/^[a-z]{4}([ -]?)[a-z]{4}\1[a-z]{4}\1[a-z]{4}$/.test(value)) return false;
  const letters = value.replace(/[ -]/g, "");
  if (new Set(letters).size < 8 || SEQUENTIAL.test(letters)) return false;
  if (VALUE_PLACEHOLDER.some((r) => r.test(value) || r.test(letters))) return false;
  return !letters.match(/.{4}/g).some((g) => COMMON4.has(g));
}
export function appPasswordIn(span) {
  const s = String(span);
  const sep = ASP_SEP.exec(s);
  if (!sep) return false;
  const v = ASP_VALUE.exec(s.slice(sep.index + sep[0].length));
  if (!v || !plausibleAppPassword(v[1])) return false;
  const tail = s.slice(sep.index + sep[0].length + v[0].length);
  if (/^[-_.][A-Za-z0-9]/.test(tail)) return false;                              // part of a longer identifier
  if (v[2] === " " && /^ [a-z]{4}(?![A-Za-z0-9])/.test(tail) && !COMMON4.has(tail.slice(1, 5))) return false; // a fifth group
  // Spaced groups followed by more words: only a group with no vowel tells random letters from English.
  if (v[2] === " " && /^[ \t]+[A-Za-z0-9]/.test(tail)) return v[1].split(" ").some(vowelless);
  return true;
}
export function hyphenatedAppPasswordIn(span) {
  const v = String(span);
  return plausibleAppPassword(v) && v.split("-").some(vowelless);
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
  // A connection-string TEMPLATE is not a credential: `<NEW_PASSWORD>`, `${DB_PASSWORD}`, `$PGPASS`,
  // `%s`, `****` in the password slot are what runbooks and env examples print (a credential-rotation
  // runbook was a benign web FP, scripts/score-webfetch-benign.mjs). Literal passwords, however weak,
  // still fire. The quantifiers are bounded because a refine routes the pattern through safeRegex.
  S("secret-db-conn", "Looks like a database connection string with an embedded password.", [
    /\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp):\/\/[^:@\s/]{1,256}:[^@\s/]{1,256}@/i
  ], (m) => !/^(?:<[^<>]*>|\$\{[^}]*\}|\$[A-Za-z_]\w*|\{\{[^}]*\}\}|%[sd]|\*+|x{3,}|\.{3,}|\[[^\]]*\])$/i.test((/:\/\/[^:@\s/]+:([^@\s/]+)@/.exec(m) || [])[1] || "")),
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
  ], (m, _t, ctx) => looksLikeAssignedSecret(assignedValue(m), ctx)),
  // ---- Labeled credentials, below the entropy bar ----
  // Patterns are bounded throughout: the refine routes them through safeRegex (one unbounded quantifier
  // at most, 400 characters). The trailing [^\n]{0,60} hands the refine the rest of the line, so prose
  // after the value can be told apart from a credential.
  S("secret-labeled-prose", "A credential written as a labeled value (Password: …, API key: …, token = …).", [
    /\b(?:[A-Za-z0-9]{1,30}[_-]){0,4}(?:pass(?:wor)?d|pwd|secret|api[ _-]?key|apikey|access[ _-]?key|(?:auth[ _-]?)?token|private[ _-]?key|client[ _-]?secret|credentials?)["'*_]{0,3}[ \t]{0,4}[:=](?!=)[ \t*]{0,6}["'`]?[^\s"'`<>]{8,128}[^\n]{0,60}/i
  ], (m, text) => labeledSecretIn(m, text)),
  // A heading naming API keys / credentials / passwords / secrets / tokens, and up to 40 lines after it;
  // the refine walks the heading's scope and reads its `- label: value` entries.
  S("secret-heading-list", "A list of credentials under an API keys / credentials / passwords heading.", [
    /^[ \t]{0,12}(?:#{1,6}[ \t]{1,4})?[^\n:]{0,60}\b(?:api[ _-]?keys|credentials|passwords|secrets|tokens)\b[^\n]{0,40}(?:\n[^\n]{0,300}){1,40}/im
  ], (m) => headingScopedSecretIn(m)),
  // An application-specific password (T1697): an app-password label, then `:`, `=` or "is", then 16 letters,
  // contiguous or 4x4 joined by spaces or hyphens. The refine requires lowercase and rejects placeholders.
  S("secret-app-password", "Looks like an application-specific password (app password).", [
    /\b(?:[A-Za-z0-9]{1,30}[_-]){0,4}app(?:lication)?[ _-]?(?:specific[ _-]?)?(?:pass(?:wor)?d|passwd|pwd)["'*_]{0,3}(?:[ \t]{0,4}[:=](?!=)|[ \t]{1,4}is:?[ \t])[ \t*]{0,6}["'`]?[a-z]{4}[ -]?[a-z]{4}[ -]?[a-z]{4}[ -]?[a-z]{4}(?![a-z0-9])[^\n]{0,40}/i
  ], (m) => appPasswordIn(m)),
  // An Apple-style 4-4-4-4 hyphenated lowercase token with no label; a group with no vowel is required.
  S("secret-app-password-hyphenated", "Looks like an application-specific password (xxxx-xxxx-xxxx-xxxx).", [
    /(?<![A-Za-z0-9_.\/-])[a-z]{4}-[a-z]{4}-[a-z]{4}-[a-z]{4}(?![A-Za-z0-9_\/-]|\.[A-Za-z0-9])/
  ], (m) => hyphenatedAppPasswordIn(m))
];
