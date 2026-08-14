// Intra-file taint-lite — a dependency-free source→sink proximity check that raises confidence on
// the insecure-code detectors (threat #61, LLM05). The pattern-only code-* detectors fire on any
// dangerous SINK, including ones fed a hardcoded literal (some false positives). This module confirms
// a TAINT FLOW: an untrusted SOURCE appears on the same line as, or within a small line window of, a
// dangerous SINK. Pure regex/string logic, no deps, content-free (returns a boolean / a rule-shaped
// pair, never the surrounding code).

// Untrusted-input SOURCES. Kept deliberately high-signal so a benign hardcoded literal never looks
// like tainted input.
const SOURCES = [
  // JS/Express request objects
  /\breq(?:uest)?\.(?:body|query|params|cookies|headers)\b/,
  // Flask / Django / generic Python request objects
  /\brequest\.(?:args|form|values|json|data|files|GET|POST|COOKIES)\b/,
  // process / CLI args
  /\bprocess\.argv\b/,
  /\bsys\.argv\b/,
  /(?<![\w.])argv\s*\[/,
  // interactive / stdin input
  /\binput\s*\(/,
  /\braw_input\s*\(/,
  /\bsys\.stdin\b/,
  /\bscanf\s*\(/,
  /\breadline\s*\(/,
  // environment
  /\bos\.environ\b/,
  /\b(?:os\.)?getenv\s*\(/,
  /\bprocess\.env\.[A-Za-z_]/,
  // fetched / response bodies (untrusted network data)
  /\bawait\s+[\w.$]*\.(?:json|text)\s*\(\s*\)/,
  /\b(?:res|response|resp|reply)\.(?:data|body|text|json)\b/,
  // handler event params (serverless / webhooks)
  /\bevent\.(?:body|queryStringParameters|pathParameters|headers|arguments|Records)\b/,
  // generic params bag
  /\bparams\s*\[/,
  // browser-controllable inputs
  /\blocation\.(?:search|hash|href)\b/,
  /\bdocument\.location\b/,
  /\bwindow\.name\b/,
  /\bdocument\.URL\b/,
  /\bdocument\.referrer\b/
];

// Dangerous SINKS. Mirrors the sink families of the existing pattern detectors (SQL exec, shell,
// dynamic-eval, HTML injection, unsafe deserialization) but only cares that SOME sink is present.
const SINKS = [
  // SQL execution
  /\b(?:execute|executemany|executescript|cursor\.execute|query|prepare|raw)\s*\(/i,
  // shell / command execution
  /\bos\.system\s*\(/,
  /\bos\.popen\s*\(/,
  /\bsubprocess\.(?:run|call|check_output|check_call|Popen)\s*\(/,
  /\bchild_process\.(?:exec|execSync|spawn|spawnSync)\s*\(/,
  /\b(?:^|[^.\w])exec(?:Sync)?\s*\(/,
  // dynamic code evaluation
  /\beval\s*\(/,
  /\bnew\s+Function\s*\(/,
  // HTML sinks (DOM XSS)
  /\.innerHTML\s*=/,
  /\.outerHTML\s*=/,
  /\.insertAdjacentHTML\s*\(/,
  /\bdocument\.write(?:ln)?\s*\(/,
  // unsafe deserialization
  /\b(?:c?[Pp]ickle)\.loads?\s*\(/,
  /\byaml\.load\s*\(/,
  /\b(?:unserialize|Marshal\.load)\s*\(/
];

// Whether a line window (same line ± SINK_WINDOW lines) contains a SOURCE.
const SINK_WINDOW = 2;

function firstMatch(text, patterns) {
  for (const p of patterns) {
    const m = text.match(p);
    if (m) return m[0];
  }
  return null;
}

// Core: find a SINK line whose surrounding window contains a SOURCE. Returns the matched pair
// { source, sink, line } (1-based line of the sink) or null. Content-free: the returned strings are
// the matched *tokens* (e.g. "request.args", "execute("), never the full surrounding line.
export function findTaintedFlow(text) {
  if (!text) return null;
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const sink = firstMatch(lines[i], SINKS);
    if (!sink) continue;
    const lo = Math.max(0, i - SINK_WINDOW);
    const hi = Math.min(lines.length - 1, i + SINK_WINDOW);
    for (let j = lo; j <= hi; j++) {
      const source = firstMatch(lines[j], SOURCES);
      if (source) return { source, sink: sink.trim(), line: i + 1 };
    }
  }
  return null;
}

// Boolean convenience: a SOURCE is present and near a SINK.
export function taintedFlow(text) {
  return findTaintedFlow(text) !== null;
}
