// Per-file runner:  node --test test/dlp-app-password.test.mjs
//
// An application-specific password (ASP) lets a legacy app or device that cannot do MFA sign in to an
// account, so it bypasses MFA (MITRE ATT&CK v20 T1697, Steal Application Specific Passwords). Its shape is
// 16 lowercase letters: Google shows four groups of four separated by spaces, Apple joins the groups with
// hyphens, Microsoft prints them contiguous. No #39 detector saw one: the value is letters only (below the
// entropy bar, and a "word" to the labeled-prose value gate) and carries no provider prefix.
//
// Two detectors close it:
//   secret-app-password             an app-password label ("app password", "app-specific password",
//                                   "application-specific password", "app passwd" …), then `:`, `=` or "is",
//                                   then 16 lowercase letters, contiguous or 4x4 joined by spaces or hyphens.
//   secret-app-password-hyphenated  a standalone 4-4-4-4 lowercase token joined by hyphens, with no label,
//                                   only when one group has no vowel (English slugs always carry one).
// Placeholders, prose, unlabeled space-separated words and unlabeled contiguous letters stay silent.
//
// Every value below is fabricated for this test; none is a real credential.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEngine } from "../cli/hook-core.mjs";
import { SECRET_DETECTORS, appPasswordIn } from "../data/secrets-patterns.js";
import { redosReason, safeRegex, MAX_PATTERN_LEN } from "../src/safe-regex.js";

const engine = buildEngine({});
const has39 = (text, stage = "prompt") => engine.scan(text, stage).some((f) => f.threat.id === 39);
const LABELED = "secret-app-password";
const HYPHENATED = "secret-app-password-hyphenated";
const NEW_IDS = [LABELED, HYPHENATED];
const detector = (id) => {
  const d = SECRET_DETECTORS.find((x) => x.detectorId === id);
  assert.ok(d, `${id} detector exists`);
  return d;
};
const firesOne = (text, id) => engine._matchDetector(text, detector(id)) !== null;
const fires = (text) => NEW_IDS.some((id) => firesOne(text, id));

// Fabricated values in each vendor's display shape.
const GOOGLE = "qmzv trkp lwhx bnse";
const APPLE = "vqkd-hzmt-pwrx-fjcl";
const MICROSOFT = "tkwzqbfmhxrpdvlc";

const LABELED_POSITIVES = [
  `Google app password: ${GOOGLE}`,
  `Gmail App Password: ${GOOGLE}\n`,
  `App-specific password: ${APPLE}`,
  `Application-specific password: ${APPLE}`,
  `apple app specific password = ${APPLE}`,
  `app_password = ${MICROSOFT}`,
  `{"app_password": "${MICROSOFT}"}`,
  `My Microsoft app password is ${MICROSOFT}`,
  `SMTP_APP_PASSWORD=${MICROSOFT}`,
  `app passwd: qmzv-trkp-lwhx-bnse`,
  `App password: ${MICROSOFT} (Outlook on the old laptop)`,
  `SMTP settings:\n  user: ops@example.test\n  app password: ${GOOGLE}\n`,
  // spaced groups followed by more words still fire when a group has no vowel (an English word always has one)
  `here is my app password: ${GOOGLE} can you set up the mail client`
];

const HYPHENATED_POSITIVES = [
  APPLE,
  `use ${APPLE} to sign in to Mail`,
  `the code was "${APPLE}".`
];

const NEGATIVES = [
  // placeholders
  "App password: xxxx xxxx xxxx xxxx",
  "app-specific password: xxxx-xxxx-xxxx-xxxx",
  "app password: abcd efgh ijkl mnop",
  "abcd-efgh-ijkl-mnop",
  "App password: abcdefghijklmnop",
  "App password: your app password",
  "app_password: <app-password>",
  "app_password=${APP_PASSWORD}",
  "APP_PASSWORD=$GMAIL_APP_PASSWORD",
  "app password: aaaa bbbb cccc dddd",
  "app password: abab-abab-abab-abab",
  "app password: qwer tyui opas dfgh",
  "app password: [REDACTED]",
  "app password: ****-****-****-****",
  "app password: your-apps-pass-word",
  "app password: <xxxx xxxx xxxx xxxx>",
  "app_password=placeholdervalue",
  // prose
  "An app password is a 16-digit passcode that gives a less secure app access to your account.",
  "The app password: this will make sure that you stay signed in",
  "App password: what does this mean?",
  "the app password is used only once when signing in",
  "Generate an app-specific password at the account page, then paste it into Mail.",
  "Your app password: enter it in the Mail settings",
  "app password: they come with more than four letters",
  // English words that are not on the common-word list, followed by more prose: every group has a vowel
  "app password: rule sets kick nine times a day",
  // no separator between the label and the value
  `Gmail app password ${GOOGLE}`,
  // unlabeled space-separated groups: random or English, never fire
  GOOGLE,
  `Paste ${GOOGLE} into the field`,
  "this that with from",
  // unlabeled contiguous letters, random or word-like
  MICROSOFT,
  "characterization",
  "The characterization of the compartmentalized interdisciplinary programme was uncontroversial.",
  // long English text
  "When your mail client asks for a password after you turn on two-step verification, open your account " +
    "security page and create a new one for that device. Name each one after the device that uses it, keep " +
    "them out of shared notes, and revoke the ones you no longer need. Most modern clients sign in with the " +
    "browser instead and need none of this.",
  // unlabeled hyphenated words, slugs, identifiers, and tokens that are part of something longer
  "font-bold-text-gray",
  "feat-auth-flow-docs",
  "best-tips-from-pros",
  "dark-blue-card-grid",
  "rule-sets-kick-nine",
  "https://example.test/blog/vqkd-hzmt-pwrx-fjcl",
  `my-${APPLE}`,
  `${APPLE}-abcd`,
  `${APPLE}.example.test`,
  `app password: ${MICROSOFT}.example.test`,
  `app_password=${MICROSOFT}_backup`,
  "VQKD-HZMT-PWRX-FJCL",
  // the vendor shapes in upper case, or with the wrong group count
  "App password: QMZV TRKP LWHX BNSE",
  "App password: qmzv trkp lwhx",
  "App password: qmzv trkp lwhx bnse qrst",
  `App password: ${MICROSOFT}x`,
  // a plain password label is the labeled-prose detector's job, not this one's
  "password: tkwzqbfm"
];

test("secret-app-password: each vendor format fires when labeled", () => {
  for (const t of LABELED_POSITIVES) assert.ok(firesOne(t, LABELED), `labeled: ${JSON.stringify(t)}`);
  for (const t of LABELED_POSITIVES) for (const stage of ["prompt", "output", "file"]) assert.ok(has39(t, stage), `${stage}: ${JSON.stringify(t)}`);
});

test("secret-app-password-hyphenated: a standalone 4-4-4-4 lowercase token fires without a label", () => {
  for (const t of HYPHENATED_POSITIVES) assert.ok(firesOne(t, HYPHENATED), `hyphenated: ${JSON.stringify(t)}`);
  for (const t of HYPHENATED_POSITIVES) assert.ok(has39(t, "prompt"), `engine #39: ${JSON.stringify(t)}`);
});

test("app-password detectors: placeholders, prose, unlabeled words and word-like strings stay silent", () => {
  for (const t of NEGATIVES) assert.equal(fires(t), false, `detector: ${JSON.stringify(t)}`);
});

test("app-password detectors: unlabeled spaced or contiguous letters reach no #39 detector at all", () => {
  for (const t of [GOOGLE, MICROSOFT, "this that with from", "characterization"]) assert.equal(has39(t, "prompt"), false, JSON.stringify(t));
});

test("app-password detectors: the existing labeled-prose detector did not already catch these", () => {
  // The value is letters only, which the labeled-prose value gate reads as a word: the new detector is load-bearing.
  for (const t of LABELED_POSITIVES) assert.equal(firesOne(t, "secret-labeled-prose"), false, JSON.stringify(t));
});

test("app-password detectors: the label must be followed by `:`, `=` or \"is\", in the pattern and in the refine", () => {
  const [p] = detector(LABELED).patterns;
  for (const t of [`app password ${GOOGLE}`, `app password ${MICROSOFT}`, `app-specific password ${APPLE}`]) {
    assert.equal(new RegExp(p.source, p.flags).test(t), false, `pattern: ${t}`);
    assert.equal(appPasswordIn(t), false, `refine: ${t}`);
  }
});

test("app-password detectors: mask mode redacts the value", () => {
  const out = engine.redact(`Gmail app password: ${GOOGLE}`, "prompt");
  assert.ok(!out.includes(GOOGLE), out);
  assert.match(out, /\[REDACTED:#39\]/);
});

test("app-password detectors: every pattern survives the engine's ReDoS gate", () => {
  for (const id of NEW_IDS) {
    const d = detector(id);
    assert.ok(d.refine, `${id} is refine-gated`);
    assert.equal(d.threatId, 39);
    assert.ok(d.patterns.length > 0);
    for (const p of d.patterns) {
      assert.ok(p.source.length <= MAX_PATTERN_LEN, `${id}: ${p.source.length} chars`);
      assert.equal(redosReason(p.source), "", `${id}: ${p.source}`);
      assert.ok(safeRegex(p.source, p.flags.includes("g") ? p.flags : p.flags + "g"), `${id} compiles under safeRegex`);
    }
  }
});

test("app-password detectors: adversarial 256 KB inputs scan quickly", () => {
  const inputs = [
    "app password: ".repeat(18000),
    "app-password-app-password-".repeat(10000),
    "abcd-".repeat(52000),
    "app password: " + "qmzv ".repeat(52000),
    "SMTP_APP_" .repeat(29000) + "PASSWORD=" + "q".repeat(16)
  ];
  for (const t of inputs) {
    const t0 = Date.now();
    for (const id of NEW_IDS) engine._matchDetector(t, detector(id));
    assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms on ${JSON.stringify(t.slice(0, 20))}`);
  }
});
