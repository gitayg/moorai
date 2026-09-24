// Multilingual prompt-injection / jailbreak signatures. The core injection intent — "ignore the
// previous instructions" and "reveal the system prompt" — expressed across ~29 languages, so the
// on-device review inspects non-English prompts too (parity with inline gateways that scan in many
// languages). English is covered by the base `inj-ignore` detector; this adds the rest, Hebrew
// included (it is NOT covered by inj-ignore, whose four patterns are English-only; see HEBREW below).
// Patterns match the distinctive verb+object of each phrase, tolerant of inflection.
//
// Split in two because the halves have different reach. The instruction-OVERRIDE half is also run on the
// inbound stages (tool metadata, ingested tool output) by sibling detectors in data/detectors.js — an
// override phrase planted in content the agent reads is indirect injection in any language. The
// REVEAL-system-prompt half stays prompt-only, matching English: sysprompt-extract is prompt-stage and
// "reveal your system prompt" on a fetched page or a tool description fires nothing, so widening only
// the non-English form would make the two languages disagree about the same sentence.

// HEBREW. Three things make a Hebrew phrase miss a literal pattern, and none of them fits the one-line
// shape the other languages use, so the Hebrew entries are written as readable templates and compiled
// by hebrew() below:
//   * No \b. Prefixes (ו ה ל ב מ ש כ) attach directly to the word — "מההוראות" is מ+ה+הוראות — so
//     words match as substrings, as in data/content-rules.js. Where a substring would be WRONG (the
//     imperative "חשוף" inside the infinitive "לחשוף", "גלה" inside the present "מגלה"), a verb is
//     anchored with (?<![א-ת]) and only the conjunction ו may precede it.
//   * Niqqud. Vowel points and cantillation (U+0591-U+05C7, maqaf U+05BE included) sit BETWEEN the
//     letters, so pointed text shares no substring with the unpointed pattern. hebrew() inserts a
//     bounded run of marks after every Hebrew letter; maqaf also counts as a word gap.
//   * Final letters. ך ם ן ף ץ turn medial when a suffix follows (התעלם -> התעלמו) and a writer can use
//     either form at a word end, so each of the five pairs matches both forms wherever it appears.
// Template tokens: `~` is a word gap (1-3 spaces or maqaf), `%` an optional one (0-3). Every quantifier
// the compiler emits is bounded, so no pattern can backtrack catastrophically; the compiled sources
// exceed safe-regex's MAX_PATTERN_LEN (400, a cap for policy-supplied DATA) only because of the niqqud
// classes, and pass its shape rules (test/hebrew-injection.test.mjs).
//
// Hebrew-specific precision choices (each has a negative in the test file):
//   * The masculine imperative is spelled like the past tense (התעלם = "ignore!" and "he ignored"; שכח
//     likewise), so those forms fire only at the start of a sentence / line / list item, after a colon
//     or comma, or after a lead-in (אנא, בבקשה, נא, עכשיו, please ...). "המודל התעלם מההוראות" is news.
//   * Forms that are unambiguously directive (התעלמי, תתעלמו, שכחי, אל תתייחס ...) fire anywhere, unless
//     negated or conditional: "אל תתעלמו", "אין להתעלם", "אם תתעלמו" are how a manual says "follow them".
//   * An infinitive fires only after an obligation (עליך / חייב / צריך + להתעלם), not after "כדי" / "יש".
//   * The object is instructions / directives / commands / prompt — not "הודעה" (message): "התעלם
//     מההודעה הקודמת שלי" is a customer correcting a typo, not an attack.
//   * Reveal wants a SYSTEM or secret/hidden object ("הנחיות המערכת", "ההוראות הנסתרות", "system
//     prompt") and an imperative; a bare "הצג הוראות" is a UI label.
const HE_MARKS = "[\\u0591-\\u05C7]{0,4}";
const HE_FINAL_PAIR = { "כ": "ך", "ך": "כ", "מ": "ם", "ם": "מ", "נ": "ן", "ן": "נ", "פ": "ף", "ף": "פ", "צ": "ץ", "ץ": "צ" };
const isHebrewLetter = (c) => c >= "\u05D0" && c <= "\u05EA";   // א..ת, finals included

// Compile a Hebrew template: a mark run after every Hebrew letter (or Hebrew-bearing class), both
// forms of each final-letter pair, and the `~` / `%` gap tokens. A quantifier that followed a letter or
// class in the template is moved onto a group holding the letter AND its marks, so `ו?` stays "optional
// vav" rather than becoming "vav, then optional marks".
function hebrew(template) {
  let out = "";
  for (let i = 0; i < template.length; i++) {
    const c = template[i];
    let unit = null;
    if (c === "\\") { out += c + template[++i]; continue; }
    if (c === "~") { out += "[\\s\\u05BE]{1,3}"; continue; }
    if (c === "%") { out += "[\\s\\u05BE]{0,3}"; continue; }
    if (c === "[") {
      let body = "", hasHebrew = false, j = i + 1;
      for (; template[j] !== "]"; j++) {
        if (template[j] === "\\") { body += template[j] + template[++j]; continue; }
        const ch = template[j];
        body += ch;
        if (isHebrewLetter(ch)) {
          hasHebrew = true;
          const pair = HE_FINAL_PAIR[ch];
          if (pair && !template.slice(i, template.indexOf("]", i)).includes(pair)) body += pair;
        }
      }
      i = j;
      if (!hasHebrew) { out += "[" + body + "]"; continue; }
      unit = "[" + body + "]" + HE_MARKS;
    } else if (isHebrewLetter(c)) {
      unit = (HE_FINAL_PAIR[c] ? `[${c}${HE_FINAL_PAIR[c]}]` : c) + HE_MARKS;
    }
    if (unit === null) { out += c; continue; }
    const q = template.slice(i + 1).match(/^(?:\?|\{\d+,\d+\})/);
    if (q) { out += `(?:${unit})${q[0]}`; i += q[0].length; } else out += unit;
  }
  return new RegExp(out, "i");
}

// Shared template pieces.
const HE_NEG = "(?:אל|אין|לא|אסור|בלי|מבלי|אם|כאשר|שלא)";           // don't / must not / without / if
const HE_WORD_START = "(?<![א-ת])";                                     // not inside a longer word
const HE_CONTEXT = String.raw`(?:^|[\n.,:;!?"'״׳()\[\]*>•\-–—/])%`;     // sentence / line / item start
const HE_LEAD_IN = String.raw`(?:^|\s)ו?(?:אנא|בבקשה|נא|עכשיו|מעכשיו|מעתה|כעת|please|now)~`;
const HE_IGNORE_IMP = "(?:(?:הת|תת)על[מם]|ת?שכח)(?:ו|י)?";           // התעלם/תתעלם/שכח/תשכח (+ו/י)
const HE_IGNORE_INF = "(?:להתעל[מם]|לשכו?ח)";                          // להתעלם / לשכוח / לשכח
const HE_OBJECT = "(?:(?:הורא|הנחי|פקוד|פרומפט)[א-ת]{0,4}|instructions?|prompts?)";
const HE_QUALIFIER = String.raw`(?:ה?קוד[מם]|שלפני|שקיבלת|שניתנו|לעיל|הנ["״]?ל|(?:ש|מ)?ל?מעלה|שמעל|ה?מקורי|ה?ראשוני)`;
// [את|מן] [מ|ל-prefix] then either "כל <object>" (all instructions) or "<object> [שלך] <qualifier>".
const HE_OVERRIDE_TAIL = `~(?:(?:את|מן)~)?[מל]?(?:כל~(?:ה-?)?${HE_OBJECT}|(?:ה-?)?${HE_OBJECT}(?:~של(?:ך|כם))?~${HE_QUALIFIER})`;
const HE_REVEAL_VERB =
  "(?:הצג|הציגי|תציג[יו]?|הרא[הי]|תרא[הי]|חשוף|חשפי|תחשו?ף|תחשפי|גל[הי]|תגל[הי]|הדפס|הדפיסי|תדפיס(?:י)?" +
  "|שתף|שתפי|תשתף|תשתפי|חזור~על|חזרי~על|תחזור~על)";
const HE_REVEAL_OBJECT =
  "(?:ה-?)?(?:system[\\s-]{0,2}prompt|(?:פרומפט|הנחי[א-ת]{0,3}|הורא[א-ת]{0,3})(?:~של)?~ה?מערכת" +
  "|(?:פרומפט|הנחי[א-ת]{0,3}|הורא[א-ת]{0,3})~ה?(?:סודי|נסתר))";

const HEBREW_OVERRIDE = [
  // "ignore / forget the previous instructions": imperative that is also a past tense -> needs context
  hebrew(`(?:${HE_CONTEXT}ו?${HE_IGNORE_IMP}|${HE_LEAD_IN}(?:${HE_IGNORE_IMP}|${HE_IGNORE_INF}))${HE_OVERRIDE_TAIL}`),
  // unambiguous directive forms, anywhere, unless negated / conditional
  hebrew(`${HE_WORD_START}(?<!${HE_NEG}~)ו?(?:התעלמי|תתעלמ[יו]|שכחי|תשכח[יו]|אל~תתייחס[יו]?)${HE_OVERRIDE_TAIL}`),
  // obligation + infinitive: "עליך להתעלם", "אתה חייב לשכוח", "עליך לא להתייחס"
  hebrew(`(?<!${HE_NEG}~)(?:עלי(?:ך|יך|כם|כן)|חייב(?:ת|ים|ות)?|צרי(?:ך|כה|כים|כות))~(?:${HE_IGNORE_INF}|לא~להתייחס)${HE_OVERRIDE_TAIL}`)
];

const HEBREW_REVEAL = [
  // "show / reveal / print / repeat the system prompt (the hidden instructions)"
  hebrew(`${HE_WORD_START}(?<!${HE_NEG}~)ו?${HE_REVEAL_VERB}~(?:ל(?:י|נו)~)?(?:את~)?(?:כל~)?${HE_REVEAL_OBJECT}`)
];

export const INJECTION_I18N_OVERRIDE = [
  // "ignore the previous instructions" — instruction-override, per language
  /ignora\s+(las\s+)?(instrucciones|indicaciones)\s+(anteriores|previas)/i,        // Spanish
  /ignore[rz]?\s+(les\s+)?(instructions|consignes)\s+(précédentes|antérieures)/i,   // French
  /ignoriere\s+(die\s+)?(vorherigen|vorigen|obigen)\s+(anweisungen|anordnungen)/i,  // German
  /ignora\s+(le\s+)?istruzioni\s+(precedenti|sopra)/i,                              // Italian
  /ignore\s+(as\s+)?instruções\s+(anteriores|prévias)/i,                           // Portuguese
  /negeer\s+(de\s+)?(vorige|bovenstaande)\s+(instructies|aanwijzingen)/i,           // Dutch
  /игнорир[а-яё]*\s+(предыдущие|все|вышеуказанные)\s+(инструкц|указани)[а-яё]*/i,    // Russian
  /ігнор[а-яіїєґ]*\s+(попередні|усі)\s+(інструкці|вказівк)[а-яіїєґ]*/i,              // Ukrainian
  /zignoruj\s+(poprzednie|wcześniejsze)\s+(instrukcje|polecenia)/i,                 // Polish
  /önceki\s+(tüm\s+)?(talimatları|komutları)\s+(yoksay|görmezden\s+gel)/i,          // Turkish
  /تجاهل\s+(كل\s+)?(التعليمات|الأوامر)\s+السابقة/,                                   // Arabic
  /دستور(ات|های)?\s+قبلی\s+را\s+نادیده\s+بگیر/,                                      // Persian
  /(पिछले|पूर्व)\s+निर्देश[^\s]{0,4}\s*(को\s*)?(अनदेखा|नज़रअंदाज़)/,                          // Hindi
  /忽略(之前|上面|以上|先前)的?(指令|指示|说明|提示)/,                                    // Chinese (Simplified)
  /(以前|前|上記|これまで)の(指示|指令|命令)を?\s*無視/,                                   // Japanese
  /(이전|위의|앞의)\s*(지시|명령|지침)(을|를)?\s*무시/,                                    // Korean
  /(bỏ\s+qua|phớt\s+lờ)\s+(các\s+)?hướng\s+dẫn\s+(trước|phía\s+trên)/i,             // Vietnamese
  /abaikan\s+(instruksi|arahan)\s+(sebelumnya|di\s+atas)/i,                          // Indonesian / Malay
  /(เพิกเฉย|ละเว้น|เพิกเฉยต่อ)\s*คำสั่ง(ก่อนหน้า|ด้านบน)/,                                  // Thai
  /αγνόησε\s+(τις\s+)?(προηγούμενες|παραπάνω)\s+(οδηγίες|εντολές)/i,                // Greek
  /ignor[ăa]\s+(instrucțiunile|comenzile)\s+(anterioare|precedente|de\s+mai\s+sus)/i, // Romanian
  /ignoruj\s+(předchozí|výše\s+uvedené)\s+(pokyny|instrukce)/i,                     // Czech
  /ignorera\s+(tidigare|föregående|ovanstående)\s+(instruktioner|anvisningar)/i,    // Swedish
  /ignor(er|ér)\s+(tidligere|forrige|ovenstående)\s+(instruksjoner|instruktioner)/i, // Norwegian / Danish
  /(jätä\s+huomiotta|ohita)\s+(aiemmat|edelliset|yllä\s+olevat)\s+ohjeet/i,          // Finnish
  /hagyd\s+figyelmen\s+kívül\s+(az\s+)?(előző|fenti)\s+utasításokat/i,               // Hungarian
  ...HEBREW_OVERRIDE,                                                                 // Hebrew (see HEBREW above)
];

export const INJECTION_I18N_REVEAL = [
  // "reveal / show the system prompt" — a few high-value languages (English handled by base rule)
  /(muestra|revela)\s+(tu\s+)?(prompt\s+del\s+sistema|instrucciones\s+del\s+sistema)/i, // Spanish
  /(montre|révèle)\s+(ton\s+)?(prompt|invite)\s+système/i,                          // French
  /(zeige|verrate)\s+(deinen\s+)?system[-\s]?prompt/i,                              // German
  /(显示|展示|透露)(你的)?(系统提示|系统指令|系统提示词)/,                                  // Chinese
  /システム\s*プロンプト(を)?\s*(表示|教えて|見せて)/,                                     // Japanese
  ...HEBREW_REVEAL,                                                                   // Hebrew (see HEBREW above)
];

export const INJECTION_I18N = [...INJECTION_I18N_OVERRIDE, ...INJECTION_I18N_REVEAL];
