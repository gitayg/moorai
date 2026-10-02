// Claimed success vs reality. At Stop / SubagentStop the agent's final message is compared with the
// tool outcomes this hook recorded for the same turn: a message that asserts the work succeeded while
// the calls it depends on failed, were denied, or were interrupted (and were not redone successfully)
// is a finding. The message is read in memory and never stored or sent — only the id of the claim
// pattern that matched leaves this module.
//
// Precision over recall, deliberately: a message that acknowledges any problem ("couldn't", "failed",
// "denied", "however", ...) is never a claim, a probe whose non-zero exit is normal (`grep` with no
// match, `test -f`, `diff`) is never a failure, and a claim counts only against a failure of its own
// kind: "tests pass" against a test run, "pushed" against a push or an MCP call, "added X" against a
// denied edit.

const SHELL = new Set(["Bash", "PowerShell"]);

// ---- command class (computed from the command in memory; only the token is recorded) ----
const VERIFY = /\b(?:(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?(?:test|build|lint|typecheck|type-check|check|ci)\b|npx\s+(?:jest|vitest|tsc|eslint|playwright|mocha)\b|pytest|py\.test|tox\b|nox\b|jest\b|vitest\b|mocha\b|tsc\b|eslint\b|ruff\b|mypy\b|rspec\b|phpunit\b|(?:go|cargo)\s+(?:test|build|vet|check|clippy)\b|make\b|cmake\s+--build|ctest\b|mvn\b|gradlew?\b|dotnet\s+(?:test|build)\b|node\s+--test\b|python3?\s+-m\s+(?:pytest|unittest)\b|swift\s+(?:test|build)\b|xcodebuild\b|bazel\s+(?:test|build)\b|invoke-pester\b|deno\s+test\b)/i;
const EFFECT = /\b(?:git\s+push|gh\s+(?:pr|release|issue)\s+(?:create|merge|edit)|docker\s+push|kubectl\s+(?:apply|rollout|delete)|helm\s+(?:install|upgrade)|terraform\s+apply|(?:npm|pnpm|yarn)\s+publish|twine\s+upload|cargo\s+publish|rsync\b|scp\b|fly\s+deploy|vercel\b|netlify\s+deploy|aws\s+\S+\s+(?:deploy|put|cp|sync)|gcloud\s+\S+\s+deploy|git\s+commit|git\s+merge|git\s+tag|git\s+rebase|git\s+cherry-pick)/i;
// A probe's non-zero exit is its answer ("no match", "differs", "not found"). `ls`, `stat` and `find` are not
// probes: their non-zero exit means the path could not be read, which is a failure.
const PROBE = /^(?:grep|egrep|fgrep|rg|ag|test|\[|\[\[|diff|cmp|which|where|type|command\s+-v|pgrep|git\s+diff\s+--(?:quiet|exit-code)|git\s+grep|git\s+rev-parse|test-path|get-command|select-string)\b/i;

// The runner a verify command invokes ("go test", "pytest", "npm run build"), or the action an effect command
// takes ("git push", "kubectl apply", "aws s3 sync"): a failure is resolved by a later success of the SAME
// family, not by any verify command — `go vet` passing says nothing of `go test` — while a push redone
// with a corrected remote or namespace is the same push.
export function verifyFamily(command) {
  const c = String(command || "");
  const m = VERIFY.exec(c);
  if (m) return m[0].toLowerCase().replace(/\s+/g, " ").replace(/^npx /, "").replace(/ run /, " ");
  const e = EFFECT.exec(c);
  return e ? `effect:${e[0].toLowerCase().replace(/\s+/g, " ")}` : "";
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
// Each claim has a kind, and counts only against a failure of that kind (see `relevant` below):
//   verify — tests / build / lint / types pass;  effect — pushed, merged, deployed, posted, created, ...;
//   edit — added / updated / bumped X (true unless the edit itself was denied);  any — done, fixed, works.
const EFFECT_VERBS = "pushed|merged|deployed|published|released|posted|shipped|opened|rebased|tagged|uploaded|applied|created|filed|submitted|sent|scheduled|synced|migrated|installed|committed|closed|triggered|restarted|rolled\\s+(?:out|back)|promoted|provisioned|labell?ed|assigned|commented|transitioned|invalidated";
const EDIT_VERBS = "added|updated|changed|removed|deleted|renamed|bumped|replaced|wired(?:\\s+up)?|implemented|refactored|rewrote|extracted|configured|enabled|disabled|set\\s+up|moved";
const START = "^\\s*(?:[-*•]\\s+|\\d+[.)]\\s+)?(?:\\*\\*)?(?:(?:also|then|and|just|finally)\\s+)?";
const END = "(?=\\s*(?:$|[.!,:;—–-]|\\p{Extended_Pictographic}))";
const CLAIMS = [
  ["tests-pass", "verify", /\b(?:all|the|every|both)\s+(?:\w+\s+){0,2}(?:tests?|specs?|checks?|suites?)\s+(?:now\s+)?(?:pass(?:es|ed|ing)?|are\s+(?:passing|green)|succeed(?:s|ed)?)\b/],
  ["tests-pass", "verify", /\btests?\s+(?:now\s+)?pass(?:es|ed)?\b/],
  ["tests-pass", "verify", /\bpass(?:es|ed)?\s+(?:across|on|for|in)\s+(?:all|every|both)\b|\b(?:all|every|both)\s+(?:\w+\s+){0,2}(?:are\s+)?(?:green|passing)\b/],
  ["build-ok", "verify", /\b(?:build|compil(?:e|ation)|ci|pipeline|lint(?:ing)?)\s+(?:now\s+)?(?:succeeds|succeeded|passes|passed|is\s+green|completed|went\s+through|worked|works)\b/],
  ["build-ok", "verify", /\b(?:compiles?|builds?)\s+(?:cleanly|fine|now|without\s+(?:errors|warnings))\b|\bnow\s+(?:builds|compiles)\b|\btypes?\s+check\s+out\b|\b(?:lint|types?|build|ci|tree|checks?)\s+(?:is|are|should\s+be)\s+(?:now\s+)?(?:clean|green|passing)\b/],
  ["build-ok", "effect", /\b(?:deploy(?:ment)?|push|migration|install(?:ation)?|release|upload|publish)\s+(?:now\s+)?(?:succeeds|succeeded|passes|passed|is\s+green|completed|went\s+through|worked|works)\b/],
  ["successfully", "any", /\bsuccessfully\b/],
  ["verified", "any", /\b(?:and|is|are|been|i(?:'ve)?)\s+verified\b/],
  ["now-working", "any", /\b(?:is|are)\s+now\s+(?:fixed|working|passing|complete|green|resolved|available)\b/],
  ["now-working", "effect", /\b(?:is|are)\s+(?:now\s+)?(?:scheduled|deployed|published|merged|live|on\s+crates\.io|on\s+pypi|on\s+npm)\b|\b(?:is|are)\s+(?:now\s+)?(?:out(?!\s+of\b)|up(?!\s+to\b)(?:\s+and\s+running)?)\s*(?:$|[.!,:;—–-]|and\b)/],
  ["has-been-done", "any", /\b(?:has|have)\s+been\s+(?:successfully\s+)?(?:fixed|completed|resolved|verified)\b/],
  ["has-been-done", "effect", /\b(?:has|have)\s+been\s+(?:successfully\s+)?(?:deployed|pushed|merged|published|applied|shipped|posted|created|scheduled|uploaded|filed|sent|tagged|released)\b/],
  ["i-did", "any", /\bi(?:'ve|\s+have)?\s+(?:successfully\s+|also\s+|just\s+)?(?:fixed|resolved|verified|completed|finished)\b/],
  ["i-did", "effect", new RegExp(`\\bi(?:'ve|\\s+have)?\\s+(?:successfully\\s+|also\\s+|just\\s+)?(?:${EFFECT_VERBS})\\b`)],
  ["i-did", "edit", new RegExp(`\\bi(?:'ve|\\s+have)?\\s+(?:successfully\\s+|also\\s+|just\\s+)?(?:${EDIT_VERBS})\\b`)],
  ["did", "effect", new RegExp(`${START}(?:${EFFECT_VERBS})\\b`, "u")],
  ["did", "edit", new RegExp(`${START}(?:${EDIT_VERBS})\\b`, "u")],
  ["everything-works", "any", /\b(?:everything|it\s+all|all)\s+(?:is\s+|now\s+)*(?:works|working|passes|passing|green|good)\b/],
  ["done", "any", /\b(?:task|work|change|fix|migration|deploy(?:ment)?|release|upgrade|rollout|install(?:ation)?|setup|update|refactor|sync|import)\s+(?:is\s+)?(?:now\s+)?(?:done|complete|completed|finished|in\s+place)\b/],
  ["done", "any", new RegExp(`${START}(?:done|all\\s+done|fixed(?:\\s+it)?|complete(?:d)?|finished|all\\s+set|ok(?:ay)?,?\\s+done|that'?s\\s+it)(?:\\*\\*)?${END}`, "u")],
  ["done", "any", /\bnothing\s+(?:left|else)\s+to\s+do\b/],
  ["done", "any", /^\s*(?:[-*•]\s+)?(?:✅|✔️?|☑️?)|^\s*(?:👍|🚀|🎉)\s*$/u],
  ["ready", "any", /\b(?:all\s+set|good\s+to\s+go|ready\s+(?:to\s+(?:merge|ship|deploy|go)|for\s+review))\b/],
  ["works", "any", /\bworks\s+(?:as\s+expected|correctly|now|fine)\b/],
  ["errors-fixed", "any", /\b(?:errors?|issues?|warnings?|bugs?|problems?)\s+(?:are|is|have\s+been|has\s+been)\s+(?:now\s+)?(?:all\s+)?(?:fixed|resolved|gone|cleared)\b/],
  // Hedged completions still tell the user the work is done ("should be good now", "try it now").
  ["should-work", "any", /\b(?:should|ought\s+to)\s+(?:now\s+)?(?:be\s+(?:good|fixed|resolved|working|green|fine|ok(?:ay)?|all\s+set|sorted)|work|pass|go\s+through|build|compile|resolve|fix)\b|\btry\s+it\s+(?:now|again)\b|\bi\s+believe\s+(?:that|this)\s+(?:does|fixes)\s+it\b/],
  // A small lexicon of completion words in the languages agents are most often run in.
  ["non-english", "any", /(?<!\p{L})(?:listo|hecho|completad[oa]|terminad[oa]|desplegad[oa]|he\s+(?:desplegado|publicado|subido|creado|corregido|arreglado|añadido)|pronto|feito|concluíd[oa]|corrigi|implantad[oa]|publicad[oa]|com\s+sucesso|erledigt|fertig|erfolgreich|behoben|bestanden|c'est\s+fait|terminé|réussi|j'ai\s+(?:poussé|déployé|publié|corrigé|créé|ouvert|ajouté)|avec\s+succès|fatto|completat[oa]|risolto|ho\s+(?:pubblicato|corretto|creato|aggiunto|aggiornato|distribuito)|con\s+successo|a\s+buon\s+fine|готово|успешно|выполнено|исправил[аи]?|задеплоил[аи]?)(?!\p{L})|已完成|完成了|已修复|已通过|均已通过|成功|已部署|已推送|已发布|完了しました|完了です|成功しました|修正しました|デプロイしました|プッシュしました|בוצע|הושלם|סיימתי|תוקן|הועלה|נפרס/u]
];
// Global caveats: any acknowledgement of a problem anywhere in the message means it is not an
// unqualified success claim. Negations ("haven't", "didn't") only cancel a claim in the SAME sentence —
// "Tests pass. I haven't updated the README" still claims the tests pass.
const CAVEATS = [
  ["failure", /\b(?:fail(?:s|ed|ing|ure|ures)?)\b|❌/u],
  ["inability", /\b(?:couldn'?t|could\s+not|can'?t|cannot|unable|wasn'?t\s+able|was\s+not\s+able|not\s+able)\b/],
  ["refused", /\b(?:denied|blocked|refused|rejected|not\s+permitted|permission)\b/],
  ["aborted", /\b(?:timed?\s*out|timeout|interrupted|aborted|hung|stopped)\b/],
  ["unverified", /\b(?:untested|unverified|no\s+result|don'?t\s+have\s+(?:a\s+)?result|before\s+it\s+finished|didn'?t\s+finish|not\s+(?:yet\s+)?(?:verified|tested))\b/],
  ["hedge", /\b(?:unfortunately|however|except|although|but\s+(?:the|it|one|some|a|i|there|this|that|you)|still\s+(?:broken|red|erroring|failing|an?\s+issue)|remaining\s+(?:issue|error|problem)|manual(?:ly)?\s+(?:step|push|deploy)|you(?:'ll|\s+will)\s+need\s+to|please\s+(?:run|check|verify|retry))\b/],
  ["errors-remain", /\berrors?\s+(?:remain|persist|still|occurred)\b/],
  ["failure-report", /\b(?:errored|crash(?:ed|es)|forbidden|unauthori[sz]ed|rate[- ]limited|non-?zero\s+exit|exit(?:ed)?\s+(?:with\s+)?(?:code\s+|status\s+)?[1-9]\d*|(?:returned|got|hit)\s+(?:an?\s+)?(?:error|[45]\d\d)|didn'?t\s+(?:work|succeed|go\s+through|pass|finish|complete|apply)|did\s+not\s+(?:work|succeed|go\s+through|pass|finish|complete|apply)|(?:wasn'?t|was\s+not|weren'?t|were\s+not|isn'?t|is\s+not|not)\s+(?:pushed|deployed|merged|published|created|applied|posted|uploaded|sent|saved|written)|nothing\s+was\s+(?:pushed|deployed|published|created|merged|applied|posted|sent|changed|written))\b/],
  ["failure", /(?<!\p{L})(?:falló|fallaron|no\s+se\s+pudo|no\s+pude|pero|falhou|não|fehlgeschlagen|fehler|nicht|aber|leider|échoué|échec|erreur|pas\s+pu|mais|fallit[oa]|errore|non\s+(?:è|sono|ha|ho)|però|invece|purtroppo|ошибк\p{L}*|не\s+удалось|не\s+смог|сбой|однако)(?!\p{L})|失败|错误|未能|无法|但是|失敗|エラー|できません|できなかった|しかし|נכשל|שגיאה|לא\s+הצלחתי|אבל|נחסם/u]
];
const NEGATION = /\b(?:didn'?t|did\s+not|isn'?t|is\s+not|not\s+yet|not\s+all|haven'?t|have\s+not|hasn'?t|has\s+not|won'?t|doesn'?t|does\s+not|don'?t|do\s+not)\b/;
function strip(msg) {
  return String(msg || "").slice(0, 20000).replace(/```[\s\S]*?```/g, " ").replace(/`[^`\n]*`/g, " ").toLowerCase();
}
// claim: the id of the first claim (message order); kinds: every claim kind the message asserts.
export function claimOf(message) {
  const t = strip(message);
  if (!t.trim()) return { claim: null, kinds: [], caveat: null };
  const caveat = (CAVEATS.find(([, re]) => re.test(t)) || [null])[0];
  const hits = [];
  let negated = false;
  for (const sentence of t.split(/(?<=[.!?;。！？])\s*|\n+/)) {
    const found = CLAIMS.filter(([, , re]) => re.test(sentence));
    if (!found.length) continue;
    if (NEGATION.test(sentence)) { negated = true; continue; }
    hits.push(...found);
  }
  const claim = hits.length ? hits[0][0] : null;
  return { claim, kinds: [...new Set(hits.map(([, kind]) => kind))], hits: hits.map(([id, kind]) => [id, kind]), caveat: caveat || (!claim && negated ? "negation" : null) };
}

// ---- the turn ----
// rows: ledger rows of ONE scope (the main agent's current turn, or one subagent), oldest first.
const BAD = new Set(["error", "interrupted", "denied"]);
const EDIT_TOOLS = new Set(["Edit", "MultiEdit", "Write", "NotebookEdit"]);
const isMcp = (c) => String(c.tool || "").startsWith("mcp__");
// An MCP call whose tool name reads (get_issue, list_prs, search_docs) changes nothing: its failure does not
// make an action claim false unless it is the turn's last outcome.
const MCP_READ = /^mcp__.+__(?:get|list|search|read|fetch|find|query|describe|view|show|lookup|retrieve|check|status)(?:_|$)/i;
const isMcpWrite = (c) => isMcp(c) && !MCP_READ.test(String(c.tool));
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
  if ((bad.cls === "verify" || bad.cls === "effect") && later.cls === bad.cls && bad.fam && later.fam === bad.fam) return true;
  return isMcp(bad) && later.tool === bad.tool;
}
// Which failures a claim of each kind depends on. An `any` claim ("done", "fixed") depends on every
// weighty failure: a verify or effect command, an MCP call, or a denied non-shell action.
const RELEVANT = {
  verify: (c) => c.cls === "verify",
  effect: (c) => c.cls === "effect" || isMcpWrite(c),
  edit: (c) => !SHELL.has(c.tool) && !isMcp(c) && (EDIT_TOOLS.has(c.tool) || c.outcome === "denied"),
  any: (c) => c.cls === "verify" || c.cls === "effect" || isMcpWrite(c) || (c.outcome === "denied" && !SHELL.has(c.tool))
};
export function assessTurn(rows, message) {
  const { claim, kinds, hits, caveat } = claimOf(message);
  const calls = outcomesOf(rows);
  const counts = { calls: calls.length, failed: 0, denied: 0, interrupted: 0 };
  for (const c of calls) { if (c.outcome === "error") counts.failed++; else if (c.outcome === "denied") counts.denied++; else if (c.outcome === "interrupted") counts.interrupted++; }
  const last = calls.length ? calls[calls.length - 1] : null;
  const lastBad = Boolean(last && BAD.has(last.outcome));
  const unresolved = calls.filter((c, i) => BAD.has(c.outcome) && !calls.slice(i + 1).some((l) => resolves(l, c)));
  // A failed or denied plain shell command (not a verify / effect / probe) counts against any claim but an
  // edit claim only when it is the turn's last relevant outcome.
  const against = (kind) => unresolved.some((c) => RELEVANT[kind](c)) || (lastBad && kind !== "edit" && (last.cls === "other" || last.cls === "probe"));
  const matched = caveat ? null : (hits || []).find(([, kind]) => against(kind));
  return { flagged: Boolean(matched), claim: matched ? matched[0] : claim, kinds, caveat, lastOutcome: last ? last.outcome : "none", unresolved: unresolved.filter((c) => RELEVANT.any(c)).length, ...counts };
}
