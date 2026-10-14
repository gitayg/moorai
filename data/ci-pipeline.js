// Poisoned Pipeline Execution (ATT&CK T1677): the agent writes a CI/CD configuration file with a step that
// runs attacker-controlled code or exfiltrates the pipeline's secrets, or switches a trigger to one that
// runs with repository secrets on untrusted pull requests. The hook's Write/Edit branch scans the content
// at the output stage and passes the target path as ctx.targetPath, so this fires only when the file being
// written IS a pipeline definition AND the change is one of the dangerous shapes. Credited on #32 (dangerous
// code the agent writes). Content-free at the finding: refine returns a boolean, the engine reports one span.
//
// Ordinary CI edits — `uses: actions/checkout`, `run: npm ci && npm test`, a secret referenced as an env var
// for a legitimate publish — are the hard negatives (test/ci-pipeline-poisoning.test.mjs).

const CI_PATH = /(?:\.github[\/\\]workflows[\/\\][^\n]*\.ya?ml|(?:^|[\/\\])\.gitlab-ci\.yml|(?:^|[\/\\])Jenkinsfile(?:\.[\w.]+)?|(?:^|[\/\\])azure-pipelines\.ya?ml|\.circleci[\/\\]config\.yml|(?:^|[\/\\])bitbucket-pipelines\.yml)$/i;
const MAX = 50_000;

// A download piped straight into a shell, inside a pipeline step.
const FETCH_TO_SHELL = /\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/i;
// The pull_request_target trigger — runs with repo secrets in the context of a fork PR (GitHub's canonical PPE).
const PR_TARGET = /\bpull_request_target\b/;
// A pipeline secret handed to a network client in either order (exfiltration of the CI secret).
const SECRET_EGRESS = /(?:\$\{\{\s*secrets\.[\w.]+[\s\S]{0,160}?\b(?:curl|wget|ncat|nc|Invoke-WebRequest|Invoke-RestMethod)\b|\b(?:curl|wget|ncat|nc|Invoke-WebRequest|Invoke-RestMethod)\b[\s\S]{0,200}?\$\{\{\s*secrets\.[\w.]+)/i;

export function ciPipelinePoisoningHit(text, ctx) {
  const path = ctx && ctx.targetPath;
  if (typeof path !== "string" || !CI_PATH.test(path)) return false;
  if (typeof text !== "string" || !text) return false;
  const s = text.length > MAX ? text.slice(0, MAX) : text;
  return FETCH_TO_SHELL.test(s) || PR_TARGET.test(s) || SECRET_EGRESS.test(s);
}
