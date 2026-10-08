// Parental-control content categories — distinct from the 40 AI-security threats. Tier-1
// keyword heuristics (a real deployment would use a local classifier). Applied to content
// both shared (outgoing) and received (AI response). Enforced when the admin enables it.
// Each category carries an English pattern + a Hebrew keyword pack (Hebrew has no \b word
// boundary, so Hebrew terms match as substrings, catching prefixed forms like ה/ו/ל/ב).
//
// PRECISION (sexual / violence / profanity run in notify by default — data/content-defaults.js). A bare keyword
// was not enough for these three. Measured with scripts/measure-content-defaults.mjs before this change: 433 of the
// 450 real source / markdown files that fired (of 110,536) were the placeholder "xxx" (sk-xxx, XXX-XX-XXXX), and the
// hard negatives (test/fixtures/content-defaults/hard-negatives.json) fired on "how to kill the process", "nude
// mice", "the Srebrenica massacre", "Dick Grune", "Bastard feudalism", a moderation spec that "flags porn", and the
// Hebrew חרא inside אחראי ("responsible"). Every refusal below is a lookaround evaluated after a literal has matched
// and every quantifier inside one is bounded, so the cost stays linear in the input. Each case, both ways, is pinned
// in test/content-rule-precision.test.mjs.
const alt = (parts, flags) => new RegExp(parts.join("|"), flags);

// Words that make "how to kill X" a technical or household question rather than violence: X is a process, job,
// signal, container, build, a pest, or time ("how to kill the process on port 3000", "kill -9", "kill weeds").
const KILL_MOD = String.raw`(?:the|a|an|all|any|every|each|this|that|these|those|my|your|our|their|its|stuck|hung|hanging|frozen|running|old|zombie|orphan(?:ed)?|child|parent|background|idle|stale|existing|remaining|other|unresponsive|java|node|python|chrome|docker|rogue)`;
const KILL_OBJ = String.raw`(?:process(?:es)?|pids?|tasks?|jobs?|threads?|sessions?|containers?|pods?|servers?|apps?|applications?|programs?|daemons?|services?|quer(?:y|ies)|connections?|ports?|signals?|instances?|vms?|nodes?|workers?|tabs?|windows?|terminals?|shells?|tmux|screen|loops?|scripts?|commands?|switch(?:es)?|builds?|deploys?|deployments?|time|weeds?|mold|mould|moss|bacteria|germs|fleas?|ants?|roaches|cockroaches|bed\s?bugs|fruit\s{1,3}flies|flies|wasps?|termites?|mosquito(?:es)?|lice|aphids?)`;

export const CONTENT_RULES = [
  {
    id: "profanity",
    label: "Profanity",
    severity: "moderate",
    description: "Swearing or crude language in content shared with or returned by the AI.",
    patterns: [
      alt([
        String.raw`\b(?:mother)?f+u+c+k\w*`,
        String.raw`\b(?:bull|horse|dip|chicken)?sh[i1]t\w*`,
        String.raw`\bbitch(?:es|y)?\b`,
        String.raw`\bassholes?\b`,
        // "bastard feudalism", "bastard sword", "bastard file" (the metalworking tool), "bastard son of …".
        String.raw`\bbastards?\b(?![ \t]{1,3}(?:feudalism|swords?|files?|sons?|daughters?)\b)`
      ], "i"),
      // Case-sensitive: "Dick" capitalised is a name (Dick Grune, Moby Dick, Tom, Dick and Harry).
      /\b(?:dick(?:head)?s?|Dickheads?|DICK(?:HEAD)?S?)\b/,
      // חרא inside אחראי ("responsible"), זונה inside תזונה ("nutrition"), מפגר אחרי ("lagging behind").
      /(?:חרא(?<!אחרא)|מניאק|בן ?זונה|זונה(?<![תמ]זונה)|תזדיין|מזדיין|שמוק|מטומטם|אידיוט|מפגר(?![א-ת]{0,2}\s{1,3}אחרי)|דביל|טמבל)/
    ]
  },
  {
    id: "sexual",
    label: "Sexual / explicit",
    severity: "high",
    description: "Sexual, pornographic, or sexually explicit material (prompt and AI response).",
    patterns: [
      alt([
        // Not right after a moderation verb ("the classifier flags porn") nor before filter / blocker / classifier.
        String.raw`\bporn(?:ography|ographic|o|hub)?\b(?<!\b(?:flags?|flagging|detects?|detecting|blocks?|blocking|filters?|filtering|bans?|banning|moderates?|moderating|classif(?:y|ies|ying))\s{1,3}porn\w{0,8})(?![\s-]{1,2}(?:filters?|filtering|blockers?|blocking|detectors?|detection|classifiers?|classification)\b)`,
        // Not after a negated send: "why not to send nudes", "never share nudes".
        String.raw`\bnudes\b(?<!\b(?:not|never|don'?t|doesn'?t|didn'?t|won'?t|shouldn'?t|stop|avoid)\s{1,3}(?:to\s{1,3})?(?:send|sending|share|sharing|post|posting)\s{1,3}nudes)`,
        // Singular "nude" is a colour and a mouse strain ("nude lipstick", "nude mice"): only before a media word.
        String.raw`\bnude[\s-]{1,2}(?:pics?|pictures?|photos?|images?|videos?|selfies?|snaps?|leaks?|shots?|scenes?|content|models?|photoshoots?)\b`,
        String.raw`\bsex[\s-]?tapes?\b`,
        String.raw`\bexplicit sexual\b`,
        // The brand alone is news / phishing talk ("kits impersonate OnlyFans creator payouts"): needs a content word.
        String.raw`\bonlyfans(?:\.com)?[\s-]{1,2}(?:leaks?|leaked|content|pics?|photos?|videos?|vids?|nudes|models?|girls?|accounts?|pages?|links?)\b`,
        String.raw`\b(?:free|leaked|her|his|their|my|your)\s{1,3}onlyfans\b`,
        String.raw`\bsexting\b`,
        String.raw`\bdick[\s-]?pics?\b`,
        // "nsfw" is also a label in code and docs ("NSFW filter", "the NSFW content default", "nsfw: true"): it
        // counts before a media / venue word, or as a tag ([nsfw], (nsfw), #nsfw).
        String.raw`\bnsfw(?<!non-nsfw)(?=[\s-]{1,2}(?:pics?|pictures?|photos?|images?|videos?|vids?|clips?|gifs?|art|artwork|content(?![\s-]{1,2}(?:defaults?|categor(?:y|ies)|filters?|filtering|classifiers?|detection|moderation|polic(?:y|ies)|rules?|settings?|warnings?)\b|\s{1,3}(?:is|are|was|were|gets?)\s{1,3}(?:reported|flagged|blocked|filtered|detected|removed|moderated|coached|hidden))|chats?|roleplay|rp|stories|story|subreddits?|sites?|servers?|discord|accounts?|posts?|reddit|pages?|channels?)\b)`,
        String.raw`[[(#]nsfw\b`,
        // "xxx" only as a standalone token (no identifier, path, placeholder, mask or hex character on either side:
        // sk-xxx, XXX-XX-XXXX, xxx.example, 0xxx, /xxx/, id=xxx) AND next to a sexual-media word.
        String.raw`(?<![\w./\\@$#=:*%&+~^|-])xxx(?![\w./\\@$#:*%&+~^|]|-(?!rated\b))(?:(?<=\b(?:free|watch|watching|hot|hardcore|amateur|rated|hd|stream|streaming)\s{1,3}xxx)|(?=[\s-]{1,3}(?:videos?|vids?|movies?|films?|clips?|pics?|photos?|porn|sex|cams?|tube|rated|scenes?|dvds?|content|chat|sites?|websites?|stories)\b))`
      ], "i"),
      // סקס inside סקסופון ("saxophone").
      /(?:פורנו|פורנוגרפ|תמונות עירום|עירום מלא|סקס(?!ופו)|זיון|אורגזמה|חשפנ|סקסטינג)/
    ]
  },
  {
    id: "violence",
    label: "Violence / weapons",
    severity: "high",
    description: "Graphic violence, gore, or instructions for weapons or attacks.",
    patterns: [
      alt([
        String.raw`\b(?:behead|mutilate)\b`,
        String.raw`\bhow\s{1,3}to\s{1,3}murder\b`,
        String.raw`\bhow\s{1,3}to\s{1,3}kill\b(?!\s{1,3}(?:${KILL_MOD}\s{1,3}){0,4}${KILL_OBJ}\b|\s{1,3}-)`,
        // "bomb calorimeter" (chemistry), "bomb shelter".
        String.raw`\b(?:make|build)\s{1,3}a\s{1,3}bomb\b(?![\s-]{1,2}(?:calorimeters?|calorimetry|shelters?|proof)\b)`,
        // A massacre or a school shooting as intent or a plan, not a news / history mention ("the Srebrenica massacre",
        // "a novel about a school shooting").
        String.raw`\b(?:how\s{1,3}to|plan(?:s|ning|ned)?\s{1,3}(?:to|a)|going\s{1,3}to|gonna|want\s{1,3}to|wanna|i'?ll|we'?ll|let'?s|i\s{1,3}will|we\s{1,3}will)\s{1,3}(?:a\s{1,3})?massacre\b`,
        String.raw`\bmassacre\s{1,3}(?:them|everyone|everybody|people|all\s{1,3}of\s{1,3}(?:them|you)|the\s{1,3}(?:whole|entire|people|crowd|students|kids|villagers))\b`,
        String.raw`\b(?:plan(?:s|ning|ned)?|commit(?:ting)?|carry(?:ing)?\s{1,3}out|do(?:ing)?|pull(?:ing)?\s{1,3}off|stage|how\s{1,3}to\s{1,3}(?:do|plan|commit|carry\s{1,3}out|pull\s{1,3}off))\s{1,3}(?:a\s{1,3}|another\s{1,3})?school\s{1,3}shooting\b`,
        String.raw`\bshoot\s{1,3}up\s{1,3}(?:my|the|our|a|this)\s{1,3}school\b`
      ], "i"),
      // רצח עם / רצח העם ("genocide" — the hate category's term), אקדח דבק / חום ("glue / heat gun"), רובה inside ארובה
      // ("chimney").
      /(?:לרצוח|רצח(?!\s{1,3}ה?עם(?![א-ת]))|לפוצץ|פצצה|אקדח(?!\s{1,3}(?:דבק|חום|סיליקון|מסמרים|צבע))|רובה(?<!ארובה)|לדקור|טבח|פיגוע|חומר נפץ|ירי בבית ספר)/
    ]
  },
  {
    id: "self-harm",
    label: "Self-harm",
    severity: "high",
    description: "Content that encourages or describes self-harm or suicide.",
    patterns: [/\b(suicide|kill myself|self[- ]harm|end my life|how to die)\b/i, /(להתאבד|התאבדות|לפגוע בעצמי|פגיעה עצמית|לשים קץ לחיי|איך למות|רוצה למות|אובדני)/]
  },
  {
    id: "hate",
    label: "Hate / extremism",
    severity: "high",
    description: "Hateful, discriminatory, or extremist content targeting a group.",
    patterns: [/\b(ethnic cleansing|genocide|hate speech|white supremacy)\b/i, /(טיהור אתני|רצח עם|שיח שנאה|עליונות לבנה|גזענות|נאצי|אנטישמיות)/]
  },
  {
    id: "drugs",
    label: "Drugs / alcohol / vaping",
    severity: "moderate",
    description: "Illicit drugs, plus underage alcohol, vaping, or nicotine.",
    patterns: [/\b(cocaine|heroin|meth(amphetamine)?|how to (make|cook) (drugs|meth)|buy drugs|vap(e|ing)|juul|e-?cig(arette)?|nicotine|get drunk|buy (alcohol|weed|vape)|fake id)\b/i, /(סמים|קוקאין|הרואין|קנאביס|מריחואנה|אקסטזי|לקנות סמים|איך להכין סמים|קריסטל|אלכוהול|להשתכר|וייפ|סיגריה אלקטרונית|ניקוטין|לקנות אלכוהול)/]
  },
  {
    id: "eating-disorder",
    label: "Eating disorders",
    severity: "high",
    description: "Pro-anorexia/bulimia content, purging, or unsafe extreme dieting.",
    patterns: [/\b(pro[- ]?ana|pro[- ]?mia|thinspo|thinspiration|how to purge|make myself throw up|starv(e|ing) myself|stop eating to lose|laxative diet)\b/i, /(אנורקסיה|בולימיה|להקיא את האוכל|להרעיב את עצמי|הפרעת אכילה|לרזות מהר|פרו אנה)/]
  },
  {
    id: "harassment",
    label: "Bullying / harassment",
    severity: "high",
    description: "Cyberbullying, threats, or harassing language — as target or author.",
    patterns: [/\b(kill yourself|kys|go die|nobody likes you|everyone hates you|you('re| are) (worthless|a loser|ugly|pathetic))\b/i, /(לך תמות|תהרוג את עצמך|אף אחד לא אוהב אותך|כולם שונאים אותך|את מכוערת|אתה מכוער|לוזר|חתיכת כושל)/]
  },
  {
    id: "grooming",
    label: "Grooming / predatory",
    severity: "high",
    description: "Predatory grooming patterns: secrecy, requests for photos, meeting up alone.",
    patterns: [/\b(don'?t tell your (parents|mom|dad)|our (little )?secret|send me a (pic|photo|nude)|are you (home )?alone|how old are you really|let'?s meet (up|in person)|what are you wearing)\b/i, /(אל תספר להורים|זה הסוד שלנו|שלח לי תמונה שלך|אתה לבד בבית|בת כמה את באמת|בוא ניפגש לבד|מה את לובשת)/]
  }
];
