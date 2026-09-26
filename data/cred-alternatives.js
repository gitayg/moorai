// #55 safer alternatives per credential KIND. When #55 (credential / secret-file access) drives a
// decision, the "Safer:" line comes from the first kind whose pattern matches earliest in the scanned
// text; anything unmatched falls back to #55's own saferAlternative in data/threats.json (the generic
// line). Every hint is FIXED text: it never includes the matched path or any other part of the input.
//
// Each suggested command is one whose documentation says it does not print the secret:
//   aws configure list          — access_key / secret_key shown as ****…ABCD (AWS CLI reference)
//   aws sts get-caller-identity — returns UserId, Account and Arn only (AWS CLI reference)
//   ssh-add -l                  — "Lists fingerprints of all identities currently represented by the agent"
//   kubectl config view         — sensitive data only with --raw (kubectl reference)
//   npm whoami                  — "Display the npm username of the currently logged-in user"
//   git config --get credential.helper — the configured helper string (gitcredentials)
//   gcloud auth list            — lists credentialed accounts and the active one
//   az account show             — details of the default subscription (tokens are get-access-token)
// Docker documents no command that reports the logged-in account, so its hint names the documented
// credsStore setting instead of a command.
export const CRED_ALTERNATIVES = [
  { kind: "aws", re: /\.aws[\/\\](?:credentials|config)\b/i,
    hint: "Let the AWS CLI or SDK load the profile itself; `aws sts get-caller-identity` or `aws configure list` (keys masked) shows which identity is active." },
  { kind: "ssh", re: /\.ssh[\/\\]id_[a-z0-9_]+|[\w-]\.(?:pem|key)(?![\w.])/i,
    hint: "Let ssh use the key through ssh-agent; `ssh-add -l` lists loaded keys by fingerprint. Never read the private key itself." },
  { kind: "kube", re: /\.kube[\/\\]config\b/i,
    hint: "Let kubectl load the kubeconfig; `kubectl config current-context` or `kubectl config view --minify` (secrets redacted by default) shows the active context." },
  { kind: "npm", re: /\.npmrc\b/i,
    hint: "Let npm read .npmrc itself; `npm whoami` shows which account the registry token belongs to." },
  { kind: "git", re: /\.git-credentials\b/i,
    hint: "Let git's credential helper supply the login; `git config --get credential.helper` shows which helper is set without printing the secret." },
  { kind: "docker", re: /\.docker[\/\\]config\.json\b/i,
    hint: "Let docker read its own config at pull and push time, and keep registry logins in a `credsStore` helper instead of reading config.json." },
  { kind: "gcloud", re: /\.config[\/\\]gcloud\b|\bgcloud\s+auth\b/i,
    hint: "Let gcloud load its own credentials; `gcloud auth list` shows which account is active without printing a token." },
  { kind: "azure", re: /\.azure[\/\\]/i,
    hint: "Let the Azure CLI load its own credentials; `az account show` shows the active subscription without printing a token." },
  { kind: "env", re: /(?:^|[\s"'`;|&<>()=\/\\])\.env\b(?!\.(?:example|sample|template)\b)/i,
    hint: "Read .env.example for the variable names and let the app load the values at runtime." }
];

// The hint for the credential kind that appears earliest in `text`, or null when none matches.
export function credAlternative(text) {
  const s = String(text || "");
  let best = null, at = Infinity;
  for (const c of CRED_ALTERNATIVES) {
    const m = c.re.exec(s);
    if (m && m.index < at) { at = m.index; best = c.hint; }
  }
  return best;
}
