// text-storage-upload (ATT&CK T1567.003 Exfiltration to Text Storage Sites): a shell command that posts data
// to a public paste site (pastebin, termbin, hastebin, dpaste, rentry, ix.io, sprunge, paste.rs, paste.ee), creates
// or extends a GitHub gist (`gh gist create`, `gh api gists -f …`, a POST to api.github.com/gists) or a GitLab
// snippet. Read structurally (data/exfil-channels.js textStorageHit): a GET of a paste, `gh gist view` or a name in
// prose is not a send. Report-only by default (the threat is not in BUILTIN_DEFAULT_ACTIONS); a policy raises
// threatPolicy[<id>] to ask or block.
//
// Commands only: the text must be labelled a Bash / PowerShell command (ctx.shell, as the hook, the replayer and
// the Agent SDK label one). A prompt, a file the agent reads and a file it writes are silent. ONCE: the reported
// match is one character, so no command, host or path reaches a finding.
import { textStorageHit, TEXT_STORAGE_MENTION, TEXT_STORAGE_THREAT } from "./exfil-channels.js";

const ONCE = /^[\s\S]/;
const shellOf = (ctx) => (ctx && (ctx.shell === "sh" || ctx.shell === "ps") ? ctx.shell : "");

export const EXFIL_DETECTORS = [
  {
    detectorId: "text-storage-upload",
    threatId: TEXT_STORAGE_THREAT,
    stages: ["prompt"],
    mode: "warn",
    hint: "Posts data to a paste site (pastebin, termbin, hastebin, dpaste, rentry, ix.io, sprunge, paste.rs, paste.ee), a GitHub gist or a GitLab snippet.",
    patterns: [ONCE],
    refine: (_m, text, ctx) => !!shellOf(ctx) && TEXT_STORAGE_MENTION.test(text) && !!textStorageHit(text, { ps: shellOf(ctx) === "ps" })
  }
];
