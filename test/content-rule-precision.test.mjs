// Precision of the three NSFW content categories (data/content-rules.js: sexual, violence, profanity), which run in
// notify by default (data/content-defaults.js), so every false positive is a finding someone sees.
//
// MEASURED with scripts/measure-content-defaults.mjs --dir ~/Documents, before → after this change:
//   benign corpora           1 / 1,393   →  0 / 1,393
//   benign-web-content TUNE  0 / 149     →  0 / 149
//   hard negatives          13 / 46      →  1 / 46   (dev-007 "shit-test suite": crude language, kept — see below)
//   real source / markdown 450 / 110,536 → 10 / 110,537 (left: five copies of this rule file, docs and a TLD list
//                                           that quote the keywords, and two true positives)
// Every MUST-NOT-FIRE case below except the "never fired" group was a hit on the rules before this change (each one
// was run against the old file and seen red); the MUST-FIRE cases are test/fixtures/content-defaults/nsfw-positives.json.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CONTENT_RULES } from "../data/content-rules.js";
import { NSFW_CONTENT_RULES } from "../data/content-defaults.js";
import { DetectionEngine } from "../src/engine.js";
import { scalingRatio } from "./timing.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const rd = (p) => JSON.parse(readFileSync(join(ROOT, p), "utf8"));
const engine = new DetectionEngine({ threats: [] }, [], CONTENT_RULES);
const NSFW = [...NSFW_CONTENT_RULES];
const hits = (text, cats = NSFW) => engine.scanContent(text, cats).map((h) => `${h.ruleId}:${h.match}`);

function silent(cases) {
  for (const t of cases) test(`must not fire: ${JSON.stringify(t).slice(0, 90)}`, () => assert.deepEqual(hits(t), [], t));
}

// --- Measured: test/fixtures/content-defaults/hard-negatives.json ---------------------------------------------------
const HARD = rd("test/fixtures/content-defaults/hard-negatives.json").samples;
// The 13 rows that fired before, minus dev-007: "The shit-test suite (our name for the smoke tests)" is crude language
// in workplace text, which is exactly what the profanity category reports. Kept firing on purpose.
const HARD_FP = ["bio-001", "bio-005", "sec-004", "sec-005", "dev-001", "dev-003", "dev-008", "his-001", "his-004", "his-008", "edu-001", "he-003"];
silent(HARD_FP.map((id) => HARD.find((s) => s.id === id).text));

test("hard negatives: the only row left firing is dev-007, the crude 'shit-test' name", () => {
  const fired = HARD.filter((s) => hits(s.text).length).map((s) => s.id);
  assert.deepEqual(fired, ["dev-007"]);
});

// --- Measured: the benign corpora (חרא inside אחראי, "responsible") --------------------------------------------------
silent([rd("test/redteam/benign-hebrew.json").benign.find((s) => s.id === "he-news-021").text]);

// --- Measured: real source and markdown files (excerpts of the hit lines) ---------------------------------------------
silent([
  // "xxx" as a placeholder, mask, path, identifier, TODO marker or list item — 433 of the 448 files.
  "Use placeholders like sk-xxx or XXX-XX-XXXX in docs",
  "curl https://xxx.example.com/api",
  "login({ email: \"email or username\", password: \"xxx\", app: \"slug\" })",
  "placeholder: \"https://example.okta.com/app/xxx/sso/saml\"",
  "return \"/xxx/yyy/zzz\"",
  "v = get_pallaton_value(ctx, \"egd.frame.xxx\")",
  "\"\"\"Givent ip xxx.xx.yy.xx/zz :return xxx.xx.yy.xx\"\"\"",
  "CURLOPT_INTERFACE => 'xxx.xxx.xxx.xxx'",
  "self.bytes_sent += len(data)  # XXX check for overflow",
  "# XXX: cache that somewhere",
  "var xxx = elements.filter(function (e) { return e; });",
  "single-pair SCADAFuse SKUs (`2[^8]xxx` / non-281)",
  "if user says \"Reference TC-XXX\" use the existing case",
  "**TC-XXX: [Clear title describing WHAT is verified]**",
  "= \"biz|com|edu|gov|net|org|pro|web|xxx|aero|asia|coop\"",
  "// Optional query: ?app_slug=xxx — if admin, also returns requests",
  "Examples include 'a = xxx', '{ p: a } = xxx', '[{ a }] = xxx'.",
  "React.createElement(\"div\", { xxx: \"val\" })",
  "# xxx/newdir/. exists if xxx/newdir exists",
  "found \"\\0\" byte around offset XXX)",
  "// Decode \\uXXXX, \\xXX and HTML numeric entities",
  "Possible forms are T[xxx], xxx[T], or xxx[keyof T]",
  "declare let combo2: { [x: `${string}xxx${string}`]: string }",
  "the equivalent of any of the `--iptables-xxx` options",
  "follow the pattern `NewXxx(deps...) *Xxx`",
  "20XX-XX-XX XX:XX:XX.XXX INFO [/] 1252 --- [oss-http-*:9411]",
  "pad the patch number of \"vim-patch:xxx\" for stable sort",
  "tracked as `// TODO(R-xxx):` in code",
  "settings(LANGUAGE_CODE=\"xxx\")",
  "The \"Add another XXX\" link must use the correct verbose_name",
  "export declare const outer: ProxyMap<XXX>;",
  "use 'django.db.backends.XXX', where XXX is one of",
  // "NSFW" as the name of the feature, in its own docs and code.
  "**NSFW content is reported and coached by default.**",
  "// The built-in NSFW default (notify) under the org's explicit entries",
  "### The built-in content default — NSFW in notify",
  "the three NSFW categories of `data/content-rules.js`",
  "NSFW here means the three categories that name not-safe-for-work material itself",
  "Prices the built-in NSFW content default (data/content-defaults.js)",
  "reports an NSFW hit as a content finding and the decision stays allow",
  "The non-NSFW categories (self-harm, drugs, …) stay off by default.",
  // "Dick" as a name.
  "self.assertEqual(output, \"Tom & Dick & Harry\")"
]);

// --- Probed: technical and everyday uses that fired before this change -----------------------------------------------
silent([
  "How to kill the process listening on port 3000 on macOS",
  "how to kill -9 a stuck process",
  "how to kill all node processes with pkill",
  "how to kill the build when it hangs",
  "how to kill a zombie process",
  "how to kill a docker container that won't stop",
  "how to kill time at the airport",
  "how to kill weeds in the lawn",
  "how to make a bomb calorimeter for the chemistry lab",
  "build a bomb shelter in the basement",
  "the massacre of 1572 is covered in chapter four",
  "school shooting coverage in the local paper",
  "nude lipstick and nude heels",
  "Moby Dick and Philip K. Dick",
  "bastard sword, bastard file",
  "we use an NSFW filter and an NSFW classifier",
  "config: { nsfw: true }",
  "install a porn filter or a porn blocker on the family router",
  "OnlyFans payout phishing is on the rise",
  "האוניברסיטה מחפשת אחראית משמרת",
  "תזונה נכונה לספורטאים",
  "ניקוי ארובה לפני החורף",
  "שיעור סקסופון ביום שלישי",
  "אקדח דבק ואקדח חום",
  "השרת מפגר אחרי המאסטר",
  "רצח העם ברואנדה"
]);

// --- Never fired, before or after: pinned so a broadened rule cannot start ---------------------------------------------
silent([
  "the register is at 0xxx in the datasheet", "kill -9 1234", "pkill node", "killall Dock", "SIGKILL the worker", "kill(pid, SIGTERM)", "kill the build", "kill the job",
  "the killer feature of this release", "this is overkill", "add a kill switch", "the OOM killer will kill your container",
  "execute the script", "abort the build", "photo shoot tomorrow", "strip whitespace from the string",
  "loosen the screw", "cache hit ratio", "hit the endpoint", "fork bomb", "logic bomb", "nuke the cache",
  "sex education", "sextortion scams", "Sussex and Essex", "brief nudity", "Dickens", "Scunthorpe", "cockpit"
]);

// --- MUST FIRE: the positive set -------------------------------------------------------------------------------------
for (const s of rd("test/fixtures/content-defaults/nsfw-positives.json").samples) {
  test(`must fire ${s.category}: ${s.id}`, () => {
    assert.ok(engine.scanContent(s.text, [s.category]).length, `${s.id} missed: ${s.text}`);
  });
}

// --- Linear time -----------------------------------------------------------------------------------------------------
// Every refusal is a lookaround after a literal, with bounded quantifiers. Each shape is a near-miss that a refusal
// turns away at every repetition, so no rule stops early and every rule scans the whole input; the trailing "." keeps
// a whitespace-only input from short-circuiting scanContent. 8x the input must cost ~8x, not ~64x (scalingRatio: CPU
// time, best of samples). Falsified: an added `\s+qz` branch read 60.62x (13.66ms → 827.83ms) on the " " shape.
test("the NSFW content rules scale linearly on repeated near-matches", () => {
  const rep = (u) => (n) => u.repeat(Math.ceil(n / u.length)).slice(0, n) + ".";
  const shapes = [
    "how to kill time ", "how to kill -", "xxx ", "xxx-", "a.xxx.", "not to send nudes ", "nude ", "nsfw content default ",
    "flags porn ", "fuuu", "bastard sword ", "going to ", "school ", "make a bomb shelter ", "onlyfans ",
    "אחראי ", "תזונה ", "מפגר אחרי ", "רצח עם ", " ", "a"
  ];
  for (const u of shapes) {
    const mk = rep(u), a = mk(4000), b = mk(32000);
    const r = scalingRatio(() => engine.scanContent(a, NSFW), () => engine.scanContent(b, NSFW), 3, 5);
    assert.ok(r.ratio < 20, `${JSON.stringify(u)}: 8x the input cost ${r.ratio.toFixed(2)}x (${r.small.toFixed(2)}ms → ${r.large.toFixed(2)}ms)`);
  }
});
