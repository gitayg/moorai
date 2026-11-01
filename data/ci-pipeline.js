// Poisoned Pipeline Execution (ATT&CK T1677): the agent writes a CI/CD configuration file with a step that
// runs attacker-controlled code or exfiltrates the pipeline's secrets, or switches a trigger to one that
// runs with repository secrets on untrusted pull requests. The hook's Write/Edit branch scans the content
// at the output stage and passes the target path as ctx.targetPath, so this fires only when the file being
// written IS a pipeline definition AND the change is one of the dangerous shapes. Credited on #32 (dangerous
// code the agent writes). Content-free at the finding: refine returns a boolean, the engine reports one span.
//
// Ordinary CI edits — `uses: actions/checkout`, `run: npm ci && npm test`, a secret referenced as an env var
// for a legitimate publish — are the hard negatives (test/ci-pipeline-poisoning.test.mjs).

const CI_PATH = /(?:\.github[\/\\]workflows[\/\\][^\n]*\.ya?ml|(?:^|[\/\\])\.gitlab-ci\.yml|(?:^|[\/\\])Jenkinsfile(?:\.[\w.]+)?|(?:^|[\/\\])azure-pipelines\.ya?ml|\.circleci[\/\\]config\.yml|(?:^|[\/\\])bitbucket-pipelines\.yml|(?:^|[\/\\])action\.ya?ml|\.(?:gitea|forgejo)[\/\\]workflows[\/\\][^\n]*\.ya?ml|\.gitlab[\/\\]ci[\/\\][^\n]*\.ya?ml|\.buildkite[\/\\][^\n]*\.ya?ml|(?:^|[\/\\])\.(?:travis|drone|woodpecker)\.ya?ml|\.woodpecker[\/\\][^\n]*\.ya?ml|(?:^|[\/\\])(?:cloudbuild|buildspec|bitrise|codemagic)\.ya?ml|\.tekton[\/\\][^\n]*\.ya?ml)$/i;
const MAX = 50_000;

// A download piped straight into a shell, inside a pipeline step.
const FETCH_TO_SHELL = /\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/i;
// The other ways a step runs what it just fetched: process substitution, `sh -c "$(curl …)"`, a pipe into an
// interpreter, and PowerShell's download-and-invoke (iex / Invoke-Expression over iwr / irm / DownloadString).
const FETCH_TO_SHELL_MORE = [
  /(?:\b(?:ba|z|da|k)?sh|\bsource|(?:^|[\s;&|])\.)\s+<\(\s*(?:curl|wget)\b/im,
  /\b(?:ba|z|da|k)?sh\s+-c\s+["']?\$\(\s*(?:curl|wget)\b/i,
  /\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(?:python[0-9.]*|node|perl|ruby|php)(?:\s+-)?\s*$/im,
  /\b(?:iex|Invoke-Expression)\b[^\n]{0,40}?(?:\(\s*)?(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|\(?New-Object\s+(?:System\.)?Net\.WebClient\)?\.DownloadString)\b|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,200}\|\s*(?:iex|Invoke-Expression)\b/i
];
// The whole secrets context serialized, or one secret re-encoded so the runner's log masking no longer
// recognises it (base64, hex, reversed, spaced out) — a disclosure through the build log or an artifact.
const SECRET_DUMP = [
  /\btoJSON\s*\(\s*secrets\s*\)/i,
  /\$\{\{\s*secrets\.[\w.]+\s*\}\}[^\n]{0,160}?\|\s*(?:base64|xxd|od|hexdump|rev|openssl\s+(?:base64|enc))\b/i,
  /\$\{\{\s*secrets\.[\w.]+\s*\}\}[^\n]{0,160}?\|\s*sed\s+["']?s\/\.\/&\s/i,
  /\b(?:env|printenv)\b\s*\|\s*(?:base64|xxd|od|hexdump|rev|curl|wget|nc|ncat)\b/i
];
// CI-provided credentials other than GitHub's secrets context, handed to a network client: GitLab's job,
// registry and deploy tokens on a line that also sends to a literal URL off a GitLab host (the job token's own
// API use goes to $CI_API_V4_URL or the instance), and a Jenkins withCredentials / credentials() binding used
// with a network client in the same block.
const NET = /\b(?:curl|wget|ncat|nc|Invoke-WebRequest|Invoke-RestMethod)\b/;
const GL_TOKEN = /\$\{?CI_(?:JOB_TOKEN|REGISTRY_PASSWORD|DEPLOY_PASSWORD|JOB_JWT(?:_V2)?)\b/;
const JENKINS_CRED = /\b(?:withCredentials|credentials\s*\()[\s\S]{0,400}?\b(?:curl|wget|ncat|nc|Invoke-WebRequest|Invoke-RestMethod)\b/;
function ciTokenEgress(s) {
  if (JENKINS_CRED.test(s)) return true;
  if (!GL_TOKEN.test(s)) return false;
  for (const line of s.split("\n").slice(0, 5000)) {
    if (line.length > 4000 || !GL_TOKEN.test(line) || !NET.test(line)) continue;
    for (const m of line.matchAll(/https?:\/\/([^\s"'/:]{1,253})/g)) if (!/gitlab/i.test(m[1])) return true;
  }
  return false;
}
// The pull_request_target trigger — runs with repo secrets in the context of a fork PR (GitHub's canonical PPE).
const PR_TARGET = /\bpull_request_target\b/;
// A pipeline secret handed to a network client in either order (exfiltration of the CI secret).
const SECRET_EGRESS = /(?:\$\{\{\s*secrets\.[\w.]+[\s\S]{0,160}?\b(?:curl|wget|ncat|nc|Invoke-WebRequest|Invoke-RestMethod)\b|\b(?:curl|wget|ncat|nc|Invoke-WebRequest|Invoke-RestMethod)\b[\s\S]{0,200}?\$\{\{\s*secrets\.[\w.]+)/i;

export function ciPipelinePoisoningHit(text, ctx) {
  const path = ctx && ctx.targetPath;
  if (typeof path !== "string" || !CI_PATH.test(path)) return false;
  if (typeof text !== "string" || !text) return false;
  const s = text.length > MAX ? text.slice(0, MAX) : text;
  return FETCH_TO_SHELL.test(s) || PR_TARGET.test(s) || SECRET_EGRESS.test(s)
    || FETCH_TO_SHELL_MORE.some((r) => r.test(s)) || SECRET_DUMP.some((r) => r.test(s)) || ciTokenEgress(s);
}

// A shell command that writes a pipeline definition (a redirect, tee, heredoc, Add-Content / Set-Content /
// Out-File): the targets and the text written, read the way #22's shell memory writes are
// (data/poisoning-tells.js shellWritesTo). The hook judges each with ciPipelinePoisoningHit.
export const isCiPath = (p) => typeof p === "string" && p.length <= 4096 && CI_PATH.test(p);
