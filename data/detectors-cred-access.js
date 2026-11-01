// #55 credential access read structurally (data/cred-access.js): a command that reads, copies, searches or
// prints a credential store the cred-file-access patterns do not name, through any reader, in Bash or
// PowerShell. Spread into DETECTORS just before cred-file-access: the engine keeps a threat's last warn
// finding, so where both fire the pattern detector is the one reported.
//
// Prompt and output stages, like cred-file-access. Content the agent READS (a README that shows
// `cat ~/.npmrc`, a file being written) is not a command the agent runs, so it is not judged here; the
// hook and the Agent SDK label it with ctx.inbound / ctx.targetPath / ctx.template. A tool call's shell
// (ctx.shell "ps") selects the PowerShell reading; text with no ctx.shell (a prompt, a model's output, MCP
// arguments) is read strictly: a path counts only as the argument of a known reader. Content-free: refine
// runs once per text and the reported match is one character, so no path or command reaches a finding.
import { credAccessKind } from "./cred-access.js";

const ONCE = /^[\s\S]/;
const readContent = (ctx) => !!ctx && (!!ctx.inbound || !!ctx.targetPath || Object.prototype.hasOwnProperty.call(ctx, "template"));

export const CRED_ACCESS_DETECTORS = [
  {
    detectorId: "cred-access",
    threatId: 55,
    stages: ["prompt", "output"],
    mode: "warn",
    hint: "Reads, copies, searches or prints a credential store: a credential or token file through any reader, a private key, a browser or keychain store, a password-hash store, a CLI access token, or shell history searched for secrets.",
    patterns: [ONCE],
    refine: (_m, text, ctx) => !readContent(ctx) && credAccessKind(text, { ps: !!ctx && ctx.shell === "ps", strict: !ctx || (ctx.shell !== "sh" && ctx.shell !== "ps") }) !== null
  }
];
