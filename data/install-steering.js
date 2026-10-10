// #40 — install-path steering in content the agent reads: text that tells the agent NOT to install a tool
// the official way (the registry package, `npx <pkg>`, `npm install <pkg>`, `pip install <pkg>`) and to
// install or run it from somewhere else instead (a cloned repository, a checkout, a raw script URL).
//
// MEASURED MOTIVATION. A public write-up describes a skill file that told a coding agent the "supported
// install path" was to clone one repository and run the tool from that checkout, told it not to use the
// official package from the registry, and pointed it to a second file with the setup steps. The agent
// followed it and ran the attacker's code. On v1.9.x neither the instruction text (file stage) nor the
// resulting `git clone … && cd … && pnpm install && pnpm start` was flagged. The command half is
// clone-then-run (#80, data/net-exec.js); this module is the instruction half.
//
// Either half alone is ordinary documentation. "Build from source: git clone …" is in half the READMEs on
// GitHub, and "don't install X globally, use npx X" is ordinary advice. The pair is the steering:
//
//   AWAY   an instruction against the official install: "do not / don't / never / avoid" + use / run /
//          install + a registry install that NAMES a package (`npx pkg`, `npm i -g pkg`, `pip install pkg`,
//          "the published package", "from npm"), or "instead of / rather than" + that install. A bare
//          `npm install` / `pip install .` names no package: "don't use npm install, this repo uses pnpm"
//          is a local dependency install, not a registry install of the tool, and does not count.
//   TOWARD an alternative source: `git clone`, "clone the repository", "run it from the checkout",
//          "install from source", a git+ / github: spec, a raw.githubusercontent / gist URL, a .git URL or a
//          URL to a script or archive.
//
// Both within WINDOW characters, and no other registry install offered as the replacement in the words
// that follow the AWAY instruction. The words between the AWAY verb and the install may not contain another
// verb ("don't run anything from the checkout, use npx pkg" steers TOWARD the registry), and may not
// cross a sentence or clause end.
//
// Content-free: a boolean. Bounded: the text is capped, every quantifier is bounded, the number of AWAY
// matches examined is capped.

export const WINDOW = 400;
const MAX = 200_000;
const MAX_AWAY = 32;

// A registry install that names a package, or a reference to the published / registry package. The word
// after the install must be a package name, not the next word of the sentence: `pnpm install from the
// checkout` and `npm install in the root` name no package.
const NOT_PKG = String.raw`(?:from|in|inside|within|into|with|without|to|for|and|or|then|instead|at|on|first|again|the|a|an|it|this|that|here|there|once|now|locally|globally|only|as|if|before|after|when)\b`;
const PKG = String.raw`[\`'"]?(?!${NOT_PKG})[@A-Za-z0-9]`;
const INSTALL = String.raw`(?:` + [
  String.raw`(?:npx|bunx|pnpx|uvx)\s+(?:(?:-y|--yes)\s+)?${PKG}`,
  String.raw`(?:npm|pnpm|yarn|bun)\s+(?:install|i|add)\s+(?:(?:-g|--global|-D|-S|-E|--save|--save-dev|--save-exact)\s+){0,4}${PKG}`,
  String.raw`(?:pnpm|yarn)\s+dlx\s+${PKG}`,
  String.raw`(?:pip3?|python3?\s+-m\s+pip)\s+install\s+(?:(?:-U|--upgrade|--user|--pre)\s+){0,4}${PKG}`,
  String.raw`(?:pipx\s+(?:install|run)|uv\s+(?:tool\s+install|pip\s+install|add)|cargo\s+install|gem\s+install|brew\s+install)\s+${PKG}`,
  String.raw`(?:the\s+|an?\s+|its\s+)?(?:official|published|released|prebuilt|registry|npm|pypi|crates\.io|rubygems|homebrew)\s+(?:package|release|version|build|binary|distribution|module|installer)s?\b`,
  String.raw`(?:from|via|through|off)\s+(?:the\s+)?(?:npm|pypi|registry|package\s+registry|crates\.io|rubygems|homebrew)\b`
].join("|") + ")";

const GAP = String.raw`([^.;:!?\n]{0,40}?)`;
const QUOTE = String.raw`[\`'"*\s]{0,6}`;
const AWAY = [
  new RegExp(String.raw`\b(?:do\s+not|don['’]t|never|avoid|stop)\s+(?:use|using|run|running|install|installing|invoke|invoking|pull|pulling|rely\s+on|try|trying)\b${GAP}${QUOTE}${INSTALL}`, "gi"),
  new RegExp(String.raw`\b(?:instead\s+of|rather\s+than|in\s+place\s+of)\s+(?:(?:using|running|installing|via|the|with)\s+){0,3}${QUOTE}${INSTALL}`, "gi"),
  new RegExp(String.raw`\b(?:avoid|skip|bypass|ignore)\s+${QUOTE}${INSTALL}`, "gi")
];
// The same sentence naming ANOTHER registry install as the thing to do ("don't use `npm i -g pkg`, use
// `npx pkg` instead") steers between two official installs, not away from the registry.
const REGISTRY_ALT = new RegExp(String.raw`\b(?:use|run|try|prefer|call|invoke)\b${QUOTE}${INSTALL}`, "gi");
// An install qualified as running in the checkout or from source is the alternative, not another
// registry install: `run pnpm install relnotes from the checkout`.
const IN_CHECKOUT = /^[^.;:!?\n]{0,60}?\b(?:from|in|inside|within)\s+(?:the\s+|a\s+|this\s+|that\s+|your\s+|its\s+)?(?:local\s+|cloned\s+|git\s+)?(?:checkout|clone|source|repo|repository|working\s+copy)\b/i;
function registryAlternative(tail) {
  REGISTRY_ALT.lastIndex = 0;
  let m, n = 0;
  while ((m = REGISTRY_ALT.exec(tail)) && n++ < 8) {
    if (!IN_CHECKOUT.test(tail.slice(m.index + m[0].length))) return true;
  }
  return false;
}
const TAIL = 160;
// A second verb in the first form's gap means the negation governs something else.
const GAP_VERB = /\b(?:use|using|run|running|install|installing|clone|cloning|build|building|from)\b/i;

const TOWARD = new RegExp(String.raw`(?:` + [
  String.raw`\bgit\s+clone\b`,
  String.raw`\bgh\s+repo\s+clone\b`,
  String.raw`\bclon(?:e|ing)\s+(?:(?:the|this|our|that|its|a|their|my|your)\s+)?(?:[\w.-]+\s+){0,2}?(?:repo|repository|source|project|fork)\b`,
  String.raw`\bclon(?:e|ing)\s+https?:\/\/`,
  String.raw`\b(?:from|in|inside|within|out\s+of)\s+(?:the|a|this|that|your|its)\s+(?:local\s+|cloned\s+|git\s+|fresh\s+)?(?:checkout|clone|source\s+tree|working\s+copy)\b`,
  String.raw`\b(?:run|use|install|build|launch|start)(?:ing)?\s+(?:(?:it|the\s+(?:tool|cli|server|package|app))\s+)?(?:directly\s+)?from\s+(?:the\s+)?(?:source|repo|repository|checkout|clone|git(?:hub)?)\b`,
  String.raw`\bgit\+(?:https?|ssh):\/\/`,
  String.raw`\bgithub:[\w.-]+\/`,
  String.raw`\b(?:raw|gist)\.githubusercontent\.com\/`,
  String.raw`https?:\/\/[^\s"'<>\`]{1,200}?\.git\b`,
  String.raw`https?:\/\/[^\s"'<>\`]{1,200}?\.(?:sh|ps1|tgz|tar\.gz|zip)\b`
].join("|") + ")", "i");

const PREFILTER = /\b(?:do\s+not|don['’]t|never|avoid|stop|skip|bypass|ignore|instead\s+of|rather\s+than|in\s+place\s+of)\b/i;
const PREFILTER_TOWARD = /clon|checkout|source|git|\.sh\b|\.ps1\b|\.tgz\b|\.zip\b|\.tar\.gz\b/i;

export function installSteeringHit(text) {
  try {
    if (typeof text !== "string" || !text || text.length > MAX) return false;
    if (!PREFILTER.test(text) || !PREFILTER_TOWARD.test(text)) return false;
    let seen = 0;
    for (const re of AWAY) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) && seen < MAX_AWAY) {
        seen++;
        if (m[0].length === 0) { re.lastIndex++; continue; }
        if (re === AWAY[0] && m[1] && GAP_VERB.test(m[1])) continue;
        const tail = text.slice(m.index + m[0].length, m.index + m[0].length + TAIL).split(/\n\s*\n/)[0];
        if (registryAlternative(tail)) continue;
        const from = Math.max(0, m.index - WINDOW), to = Math.min(text.length, m.index + m[0].length + WINDOW);
        if (TOWARD.test(text.slice(from, to))) return true;
      }
    }
    return false;
  } catch { return false; }
}
