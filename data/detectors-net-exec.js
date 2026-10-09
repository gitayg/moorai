// Command-shape detectors read structurally (data/net-exec.js), not by pattern: a download that a later
// part of the same command runs, a secret file handed to a network client, and data sent to a public
// out-of-band collection host. Spread into DETECTORS after the catalogue is built, because the secret-file
// test is cred-file-access's own (#55) definition and must not drift from it.
//
// Threats:
//   #57 fetch-then-exec — the same supply-chain act as `curl … | sh` (pkg-install-untrusted), split into
//       "write the script to a file" and "run the file". Same threat, same default (justify).
//   #55 secret-file-upload — the file is a credential file by #55's definition; it is being sent, not just
//       read. #65 is not used: it means a known secret VALUE matched on egress, and here only the path is
//       known.
//   #78 / #79 oast-exfil / oast-contact — no existing threat names a request-capture or OAST endpoint.
//       #1 is about sensitive content in text, #63 about model endpoints, #71 about rendered output. Two
//       ids rather than one because a threat carries one risk level and one policy action, and "data
//       sent" (High) and a bare GET or lookup (Medium) need different ones.
//
// ONCE: refine() runs once per text and the reported match is one character, so no command, path or host
// ever reaches a finding. Each refine checks a cheap prefilter before parsing.
import { fetchExecFacts, uploadedFiles, netDestinations, urlDestinations } from "./net-exec.js";
import { oastHost, OAST_MENTION } from "./oast-hosts.js";

const ONCE = /^[\s\S]/;
const FETCH_HINT = /\b(?:curl|wget2?|aria2c|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)\b/i;
const UPLOAD_HINT = /\b(?:curl|wget2?|nc|ncat|netcat|telnet|socat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i;

// One parse per (text, ctx) for the two OAST detectors, which ask opposite questions of the same result.
let memoText = null, memoEgress = null, memoVerdict = null;
export function oastVerdict(text, ctx) {
  const egress = !!(ctx && ctx.egress);
  if (text === memoText && egress === memoEgress) return memoVerdict;
  let v = null;
  if (OAST_MENTION.test(text)) {
    // A command names its destinations; other egress text (a WebFetch URL, MCP arguments) is read for URLs.
    const dests = [...netDestinations(text), ...(egress ? urlDestinations(text) : [])].filter((d) => oastHost(d.host));
    v = dests.some((d) => d.send) ? "send" : dests.length ? "contact" : null;
  }
  memoText = text; memoEgress = egress; memoVerdict = v;
  return v;
}

export function netExecDetectors(detectors) {
  const cred = detectors.find((d) => d.detectorId === "cred-file-access");
  // #55's definition, applied to a path: the verdict `cat <path>` gets from cred-file-access.
  const isSecretFile = (p) => !!cred && !/[\r\n]/.test(p) && cred.patterns.some((r) => r.test(`cat ${p}`));
  return [
    {
      detectorId: "fetch-then-exec",
      threatId: 57,
      stages: ["prompt", "output"],
      mode: "warn",
      hint: "Downloads a file and then runs it in the same command (curl -o / wget -O / Invoke-WebRequest -OutFile, then sh / source / ./file / python file).",
      patterns: [ONCE],
      refine: (_m, text) => FETCH_HINT.test(text) && fetchExecFacts(text).hit
    },
    {
      detectorId: "secret-file-upload",
      threatId: 55,
      stages: ["prompt", "output"],
      mode: "warn",
      hint: "Sends a credential / secret file to a network client (curl -d @.env / -F f=@ / -T, wget --post-file, nc < file, Invoke-RestMethod -InFile).",
      patterns: [ONCE],
      refine: (_m, text) => UPLOAD_HINT.test(text) && uploadedFiles(text).some(isSecretFile)
    },
    {
      detectorId: "oast-exfil",
      threatId: 78,
      stages: ["prompt", "output"],
      mode: "warn",
      hint: "Sends data to a public out-of-band / request-capture host (interactsh, Burp Collaborator, webhook.site, Pipedream, Request Catcher, Beeceptor, Canarytokens).",
      patterns: [ONCE],
      refine: (_m, text, ctx) => oastVerdict(text, ctx) === "send"
    },
    {
      detectorId: "oast-contact",
      threatId: 79,
      stages: ["prompt", "output"],
      mode: "warn",
      hint: "Contacts a public out-of-band / request-capture host with no data attached (a GET or DNS lookup).",
      patterns: [ONCE],
      refine: (_m, text, ctx) => oastVerdict(text, ctx) === "contact"
    }
  ];
}
