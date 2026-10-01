// Claimed success vs reality. At Stop / SubagentStop the agent's final message is compared with the
// tool outcomes this hook recorded for the same turn: a message that asserts the work succeeded while
// the calls it depends on failed, were denied, or were interrupted (and were not redone successfully)
// is a finding. The message is read in memory and never stored or sent — only the id of the claim
// pattern that matched leaves this module.
//
// Precision over recall, deliberately: a message that acknowledges any problem ("couldn't", "failed",
// "denied", "however", ...) is never a claim, and a probe whose non-zero exit is normal (`grep` with no
// match, `test -f`, `diff`) is never a failure.

const SHELL = new Set(["Bash", "PowerShell"]);

// ---- command class (computed from the command in memory; only the token is recorded) ----
const VERIFY = /\b(?:(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?(?:test|build|lint|typecheck|type-check|check|ci)\b|npx\s+(?:jest|vitest|tsc|eslint|playwright|mocha)\b|pytest|py\.test|tox\b|nox\b|jest\b|vitest\b|mocha\b|tsc\b|eslint\b|ruff\b|mypy\b|rspec\b|phpunit\b|(?:go|cargo)\s+(?:test|build|vet|check|clippy)\b|make\b|cmake\s+--build|ctest\b|mvn\b|gradlew?\b|dotnet\s+(?:test|build)\b|node\s+--test\b|python3?\s+-m\s+(?:pytest|unittest)\b|swift\s+(?:test|build)\b|xcodebuild\b|bazel\s+(?:test|build)\b|invoke-pester\b|deno\s+test\b)/i;
const EFFECT = /\b(?:git\s+push|gh\s+(?:pr|release|issue)\s+(?:create|merge|edit)|docker\s+push|kubectl\s+(?:apply|rollout|delete)|helm\s+(?:install|upgrade)|terraform\s+apply|(?:npm|pnpm|yarn)\s+publish|twine\s+upload|cargo\s+publish|rsync\b|scp\b|fly\s+deploy|vercel\b|netlify\s+deploy|aws\s+\S+\s+(?:deploy|put|cp|sync)|gcloud\s+\S+\s+deploy|git\s+commit|git\s+merge|git\s+tag|git\s+rebase|git\s+cherry-pick)/i;
const PROBE = /^(?:grep|egrep|fgrep|rg|ag|test|\[|\[\[|diff|cmp|which|where|type|command\s+-v|pgrep|ls|find|stat|git\s+diff\s+--(?:quiet|exit-code)|git\s+grep|git\s+rev-parse|test-path|get-command|select-string)\b/i;

// The runner a verify command invokes ("go test", "pytest", "npm run build"): a failure is resolved by a
// later success of the SAME runner, not by any verify command — `go vet` passing says nothing of `go test`.
export function verifyFamily(command) {
  const m = VERIFY.exec(String(command || ""));
  return m ? m[0].toLowerCase().replace(/\s+/g, " ").replace(/^npx /, "").replace(/ run /, " ") : "";
}
export function commandClass(command) {
  const c = String(command || "").trim();
  if (!c) return "other";
  if (VERIFY.test(c)) return "verify";
  if (EFFECT.test(c)) return "effect";
  // A probe is judged on the LAST pipeline/list segment: that segment's exit status is the command's.
  const segs = c.split(/\|\||&&|;|\|/).map((s) => s.trim()).filter(Boolean);
  const last = (segs[segs.length - 1] || "").replace(/^(?:sudo|time|env\s+\S+=\S+)\s+/i, "");
  return PROBE.test(last) ? "probe" : "other";
}
export function normalizeCommand(command) { return String(command || "").trim().replace(/\s+/g, " "); }

// ---- per-call outcome, content-free ----
// PostToolUse fires only for calls that completed (docs: "Runs immediately after a tool completes
// successfully"); a defensive look at the response still catches an interrupted Bash call (its result
// carries `interrupted`), an MCP error result, and hosts that put an exit code in the response.
export function outcomeOfResponse(resp) {
  if (resp && typeof resp === "object" && !Array.isArray(resp)) {
    if (resp.interrupted === true) return { outcome: "interrupted" };
    if (resp.isError === true || resp.is_error === true) return { outcome: "error" };
    for (const k of ["exit_code", "exitCode", "returnCode", "return_code"]) {
      const n = resp[k];
      if (Number.isInteger(n) && n !== 0) return { outcome: "error", exit: n };
    }
  }
  return { outcome: "ok" };
}
// PostToolUseFailure: `error` is display text ("treat the rest of the string as display text, not a
// stable format") — only the documented `Exit code N` first line and the timeout marker are read.
export function outcomeOfFailure(input) {
  if (input && input.is_interrupt === true) return { outcome: "interrupted" };
  const e = typeof (input && input.error) === "string" ? input.error : "";
  if (/Command timed out after/i.test(e.slice(0, 4096)) || /Command timed out after/i.test(e.slice(-4096))) return { outcome: "interrupted" };
  const m = /^Exit code (-?\d{1,4})\b/.exec(e);
  return m ? { outcome: "error", exit: Number(m[1]) } : { outcome: "error" };
}

// ---- the claim ----
const CLAIMS = [
  ["tests-pass", /\b(?:all|the|every|both)\s+(?:\w+\s+){0,2}(?:tests?|specs?|checks?|suites?)\s+(?:now\s+)?(?:pass(?:es|ed|ing)?|are\s+(?:passing|green)|succeed(?:s|ed)?)\b/],
  ["tests-pass", /\btests?\s+(?:now\s+)?pass(?:es|ed)?\b/],
  ["build-ok", /\b(?:build|compil(?:e|ation)|deploy(?:ment)?|push|ci|pipeline|migration|install(?:ation)?|lint(?:ing)?|release)\s+(?:now\s+)?(?:succeeds|succeeded|passes|passed|is\s+green|completed|went\s+through|worked|works)\b/],
  ["build-ok", /\b(?:compiles?|builds?)\s+(?:cleanly|fine|now|without\s+(?:errors|warnings))\b|\btypes?\s+check\s+out\b|\b(?:lint|types?|build|ci|tree)\s+is\s+(?:now\s+)?clean\b/],
  ["successfully", /\bsuccessfully\b/],
  ["verified", /\b(?:and|is|are|been|i(?:'ve)?)\s+verified\b/],
  ["now-working", /\b(?:is|are)\s+now\s+(?:fixed|working|passing|complete|green|deployed|live|merged|published|resolved|on|in|available)\b/],
  ["now-working", /\b(?:is|are)\s+(?:now\s+)?(?:scheduled|deployed|published|merged|live)\b/],
  ["has-been-done", /\b(?:has|have)\s+been\s+(?:successfully\s+)?(?:fixed|completed|resolved|deployed|pushed|merged|published|applied|verified|shipped|posted|created|scheduled)\b/],
  ["i-did", /\bi(?:'ve|\s+have)?\s+(?:successfully\s+)?(?:fixed|deployed|pushed|merged|published|resolved|verified|shipped|opened|released|posted|rebased)\b/],
  ["did", /(?:^|[.!;]\s+|\n)\s*(?:[-*]\s+)?(?:merged|deployed|pushed|published|released|posted|shipped|opened|rebased)\s+(?:the|to|on|into|a|it|onto|v?\d)/],
  ["everything-works", /\b(?:everything|it\s+all|all)\s+(?:is\s+|now\s+)*(?:works|working|passes|passing|green|good)\b/],
  ["done", /\b(?:task|work|change|fix|migration|deploy(?:ment)?)\s+is\s+(?:now\s+)?(?:done|complete|completed|finished|live|in)\b/],
  ["done", /(?:^|\n)\s*(?:\*\*)?(?:done|all\s+done|fixed(?:\s+it)?|shipped|deployed|complete)(?:\*\*)?\s*[.!]/],
  ["done", /\bnothing\s+(?:left|else)\s+to\s+do\b/],
  ["ready", /\b(?:all\s+set|good\s+to\s+go|ready\s+(?:to\s+(?:merge|ship|deploy|go)|for\s+review))\b/],
  ["works", /\bworks\s+(?:as\s+expected|correctly|now|fine)\b/]
];
// Global caveats: any acknowledgement of a problem anywhere in the message means it is not an
// unqualified success claim. Negations ("haven't", "didn't") only cancel a claim in the SAME sentence —
// "Tests pass. I haven't updated the README" still claims the tests pass.
const CAVEATS = [
  ["failure", /\b(?:fail(?:s|ed|ing|ure|ures)?)\b/],
  ["inability", /\b(?:couldn'?t|could\s+not|can'?t|cannot|unable|wasn'?t\s+able|was\s+not\s+able|not\s+able)\b/],
  ["refused", /\b(?:denied|blocked|refused|rejected|not\s+permitted|permission)\b/],
  ["aborted", /\b(?:timed?\s*out|timeout|interrupted|aborted|hung)\b/],
  ["hedge", /\b(?:unfortunately|however|except|although|but\s+(?:the|it|one|some|a|i|there|this|that|you)|still\s+(?:broken|red|erroring|failing|an?\s+issue)|remaining\s+(?:issue|error|problem)|manual(?:ly)?\s+(?:step|push|deploy)|you(?:'ll|\s+will)\s+need\s+to|please\s+(?:run|check|verify|retry))\b/],
  ["errors-remain", /\berrors?\s+(?:remain|persist|still|occurred)\b/]
];
const NEGATION = /\b(?:didn'?t|did\s+not|isn'?t|is\s+not|not\s+yet|haven'?t|have\s+not|hasn'?t|has\s+not|won'?t|doesn'?t|does\s+not)\b/;
function strip(msg) {
  return String(msg || "").slice(0, 20000).replace(/```[\s\S]*?```/g, " ").replace(/`[^`\n]*`/g, " ").toLowerCase();
}
export function claimOf(message) {
  const t = strip(message);
  if (!t.trim()) return { claim: null, caveat: null };
  const caveat = (CAVEATS.find(([, re]) => re.test(t)) || [null])[0];
  let claim = null, negated = false;
  for (const sentence of t.split(/(?<=[.!?;])\s+|\n+/)) {
    const hit = CLAIMS.find(([, re]) => re.test(sentence));
    if (!hit) continue;
    if (NEGATION.test(sentence)) { negated = true; continue; }
    claim = hit[0];
    break;
  }
  return { claim, caveat: caveat || (!claim && negated ? "negation" : null) };
}

// ---- the turn ----
// rows: ledger rows of ONE scope (the main agent's current turn, or one subagent), oldest first.
const BAD = new Set(["error", "interrupted", "denied"]);
function outcomesOf(rows) {
  const out = [];
  for (const r of rows || []) {
    if (r.ev === "pre" && r.decision === "deny") out.push({ tool: r.tool, cls: r.cls || "other", fam: r.fam || "", k: r.k || "", outcome: "denied" });
    else if ((r.ev === "post" || r.ev === "fail") && r.outcome && (SHELL.has(r.tool) || String(r.tool || "").startsWith("mcp__"))) {
      // A probe's exit 1 is its answer ("no match", "differs"), not a failure.
      if (r.outcome === "error" && r.cls === "probe" && r.exit === 1) continue;
      out.push({ tool: r.tool, cls: r.cls || "other", fam: r.fam || "", k: r.k || "", outcome: r.outcome, exit: r.exit });
    }
  }
  return out;
}
function resolves(later, bad) {
  if (later.outcome !== "ok") return false;
  if (bad.k && later.k === bad.k) return true;
  if (bad.cls === "verify" && later.cls === "verify" && bad.fam && later.fam === bad.fam) return true;
  return String(bad.tool).startsWith("mcp__") && later.tool === bad.tool;
}
// A failure the claim plausibly depends on even when later calls succeeded: a verify or effect command,
// an MCP call, or a denied non-shell action (a Write / Edit the agent then describes as done). A failed
// or denied "other" shell command counts only when it is the turn's last relevant outcome.
function weighty(c) {
  return c.cls === "verify" || c.cls === "effect" || String(c.tool).startsWith("mcp__") || (c.outcome === "denied" && !SHELL.has(c.tool));
}
export function assessTurn(rows, message) {
  const { claim, caveat } = claimOf(message);
  const calls = outcomesOf(rows);
  const counts = { calls: calls.length, failed: 0, denied: 0, interrupted: 0 };
  for (const c of calls) { if (c.outcome === "error") counts.failed++; else if (c.outcome === "denied") counts.denied++; else if (c.outcome === "interrupted") counts.interrupted++; }
  const last = calls.length ? calls[calls.length - 1] : null;
  const lastBad = Boolean(last && BAD.has(last.outcome));
  const unresolved = calls.filter((c, i) => BAD.has(c.outcome) && weighty(c) && !calls.slice(i + 1).some((l) => resolves(l, c)));
  const flagged = Boolean(claim && !caveat && (lastBad || unresolved.length));
  return { flagged, claim, caveat, lastOutcome: last ? last.outcome : "none", unresolved: unresolved.length, ...counts };
}
