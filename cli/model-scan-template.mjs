// Chat-template checks for the GGUF scanner (cli/model-scan-gguf.mjs). A GGUF file's
// tokenizer.chat_template is a Jinja template the runtime renders around every conversation, so it is
// code that reaches the model on every turn. Three things are looked for:
//
//   jinja-python-internals  critical  a dunder attribute (__class__, __globals__, __builtins__,
//                                     __subclasses__, __init__ …), a gadget global followed by one
//                                     (cycler.__init__.__globals__, lipsum.__globals__,
//                                     config.__class__, namespace.__init__), or a Python call reached
//                                     from the template (os.popen, subprocess, __import__, eval, exec).
//                                     Server-side template injection payloads take exactly this shape.
//   jinja-obfuscated-access high      |attr(…) or an escaped/concatenated underscore ("\x5f\x5f",
//                                     "_" ~ "_", "_"*2), the ways those payloads hide a dunder.
//   jinja-gadget-global     medium    a bare reference to lipsum, config, cycler, joiner, request,
//                                     url_for or self in a code block. NOT `namespace(…)`: Llama 3 and
//                                     Qwen templates use it for loop state, so only reaching THROUGH it
//                                     to a dunder counts.
//   template-instructions   high      text the template injects that addresses the model against the
//                                     user: override phrases, concealment ("do not tell the user"),
//                                     sending data to a URL, a markdown image with a URL.
//   template-url            medium    a URL in the template's literal output
//   hidden-text             high      zero-width, bidi override or Unicode tag characters
//   obfuscated-text         medium    a long base64 run or a burst of \x / \u escapes in string literals
//   oversized-template      low       longer than the cap; only the first part was read
// Content-free: the caller gets classes and counts. Details are short pattern names, never the text.

const DUNDER = /__(?:class|globals|builtins|subclasses|mro|bases?|init|import|getattribute|getattr|dict|code|func|self|module|loader|spec|reduce|reduce_ex|call)__/;
const GADGET_THROUGH = /\b(?:cycler|joiner|namespace|lipsum|config|self|request|url_for|get_flashed_messages|range|dict|lipsum)\s{0,4}(?:\.|\[)\s{0,4}['"]?_/;
const PY_CALL = /\b(?:os\s{0,2}\.\s{0,2}(?:popen|system|exec\w{0,3}|spawn\w{0,3}|remove|unlink)|subprocess|__import__|import_module|\beval\s{0,2}\(|\bexec\s{0,2}\(|popen\s{0,2}\()/;
const ATTR_FILTER = /\|\s{0,4}attr\s{0,4}\(/;
const ESC_UNDERSCORE = /\\x5f|\\u005f|\\137|['"]_['"]\s{0,4}(?:~|\+|\*\s{0,4}2)|_['"]\s{0,4}~\s{0,4}['"]_|\|\s{0,4}join\b[^}]{0,80}_/i;
const GADGET_BARE = /\b(?:lipsum|config|cycler|joiner|request|url_for|self)\b/;

const OVERRIDE = /\b(?:ignore|disregard|forget|override)\s{1,4}(?:all\s{1,4}|any\s{1,4}|the\s{1,4})?(?:previous|prior|above|earlier|preceding|system|user'?s?|safety|original)\s{1,4}(?:instructions?|messages?|prompts?|rules?|guidelines?|polic(?:y|ies))\b/i;
const CONCEAL = /\b(?:do\s{1,4}not|don'?t|never)\s{1,4}(?:tell|reveal|mention|disclose|inform|show|let)\s{1,4}(?:the\s{1,4})?(?:user|anyone|them|human)\b|\bwithout\s{1,4}(?:the\s{1,4})?(?:user|them|anyone)\s{1,4}(?:knowing|noticing|seeing)\b|\bsecretly\b|\bhidden\s{1,4}instructions?\b/i;
const EXFIL = /\b(?:send|post|upload|exfiltrate|forward|transmit|leak)\b[^\n]{0,120}?\bhttps?:\/\//i;
const MD_IMAGE_URL = /!\[[^\]\n]{0,200}\]\(\s{0,4}https?:\/\//i;
const URL = /\bhttps?:\/\/[^\s"'<>{}]{3,}/i;
const HIDDEN = /[​-‍⁠﻿‪-‮⁦-⁩]|\uDB40[\uDC00-\uDC7F]|\uDB40[\uDD00-\uDDEF]/;
const B64_RUN = /[A-Za-z0-9+/]{200,}={0,2}/;
const ESCAPES = /(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){8,}/;

// Splits a template into code ({{ … }}, {% … %}) and literal text, and pulls string literals out of
// the code (a template can also inject text as {{ 'Ignore …' }}). One linear pass with indexOf, so an
// unterminated block or quote cannot make it quadratic.
const CLOSE = { "{": "}}", "%": "%}", "#": "#}" };
function stringsOf(code, out) {
  let i = 0;
  while (i < code.length) {
    const q = code[i];
    if (q !== "'" && q !== '"') { i++; continue; }
    let j = i + 1, s = "";
    while (j < code.length && code[j] !== q) { if (code[j] === "\\" && j + 1 < code.length) { s += code[j] + code[j + 1]; j += 2; } else s += code[j++]; }
    out.push(s);
    i = j + 1;
  }
}
export function splitTemplate(t) {
  const code = [], literal = [], strings = [];
  let i = 0;
  while (i < t.length) {
    const open = t.indexOf("{", i);
    if (open < 0 || open + 1 >= t.length) { literal.push(t.slice(i)); break; }
    const kind = t[open + 1];
    if (!CLOSE[kind]) { literal.push(t.slice(i, open + 1)); i = open + 1; continue; }
    literal.push(t.slice(i, open));
    const close = t.indexOf(CLOSE[kind], open + 2);
    const body = t.slice(open + 2, close < 0 ? t.length : close);
    if (kind !== "#") { code.push(body); stringsOf(body, strings); }
    if (close < 0) break;
    i = close + 2;
  }
  return { code: code.join("\n"), literal: literal.join("\n"), strings: strings.join("\n") };
}

// Instructions and hidden text in any free text (a template's output, or another metadata string).
export function textChecks(text, add, prefix = "template") {
  if (!text) return;
  if (OVERRIDE.test(text)) add(`${prefix}-instructions`, "high", "override phrase");
  if (CONCEAL.test(text)) add(`${prefix}-instructions`, "high", "concealment phrase");
  if (EXFIL.test(text)) add(`${prefix}-instructions`, "high", "send-to-URL phrase");
  if (MD_IMAGE_URL.test(text)) add(`${prefix}-instructions`, "high", "markdown image with a URL");
  if (HIDDEN.test(text)) add("hidden-text", "high", "zero-width, bidi or tag characters");
}

function withoutStrings(code) {
  let out = "", i = 0;
  while (i < code.length) {
    const q = code[i];
    if (q !== "'" && q !== '"') { out += q; i++; continue; }
    let j = i + 1;
    while (j < code.length && code[j] !== q) j += code[j] === "\\" ? 2 : 1;
    out += "''";
    i = j + 1;
  }
  return out;
}

// → findings via add(class, severity, detail)
export function templateChecks(template, add, { truncated = false } = {}) {
  const t = String(template || "");
  const { code, literal, strings } = splitTemplate(t);
  if (DUNDER.test(code) || GADGET_THROUGH.test(code)) add("jinja-python-internals", "critical", "dunder attribute access");
  if (PY_CALL.test(code)) add("jinja-python-internals", "critical", "python call");
  if (ATTR_FILTER.test(code) || ESC_UNDERSCORE.test(code)) add("jinja-obfuscated-access", "high", "attr filter or escaped underscore");
  if (GADGET_BARE.test(withoutStrings(code))) add("jinja-gadget-global", "medium", "gadget global referenced");
  const out = `${literal}\n${strings}`;
  textChecks(out, add, "template");
  if (URL.test(out)) add("template-url", "medium", "URL in template output");
  if (HIDDEN.test(code)) add("hidden-text", "high", "zero-width, bidi or tag characters in code");
  if (B64_RUN.test(t)) add("obfuscated-text", "medium", "long base64 run");
  if (ESCAPES.test(strings)) add("obfuscated-text", "medium", "escape burst in string literals");
  if (truncated) add("oversized-template", "low", "template longer than the read cap");
}
