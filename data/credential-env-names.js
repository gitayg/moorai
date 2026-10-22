// Credential environment variable NAMES that the credential exposure map (cli/credential-exposure.mjs)
// may report by name. A fixed allow-list: a name that is not here is never sent. It is only counted
// (envOtherCount) when it looks like a credential (CREDENTIAL_ENV_SHAPE), because a custom name such as
// ACME_BILLING_DB_PASSWORD can reveal an internal system. Values are never read here: the map looks at
// which names are set, nothing else.
//
// Each name maps to the credential kind the map groups it under (the kinds of data/cred-alternatives.js
// plus gh and ai-key).
export const CREDENTIAL_ENV_NAMES = Object.freeze({
  AWS_ACCESS_KEY_ID: "aws",
  AWS_SECRET_ACCESS_KEY: "aws",
  AWS_SESSION_TOKEN: "aws",
  AWS_PROFILE: "aws",
  GITHUB_TOKEN: "gh",
  GH_TOKEN: "gh",
  GH_ENTERPRISE_TOKEN: "gh",
  GITLAB_TOKEN: "git",
  NPM_TOKEN: "npm",
  NODE_AUTH_TOKEN: "npm",
  ANTHROPIC_API_KEY: "ai-key",
  ANTHROPIC_AUTH_TOKEN: "ai-key",
  OPENAI_API_KEY: "ai-key",
  GEMINI_API_KEY: "ai-key",
  GOOGLE_API_KEY: "ai-key",
  MISTRAL_API_KEY: "ai-key",
  GROQ_API_KEY: "ai-key",
  OPENROUTER_API_KEY: "ai-key",
  GOOGLE_APPLICATION_CREDENTIALS: "gcloud",
  CLOUDSDK_AUTH_ACCESS_TOKEN: "gcloud",
  AZURE_CLIENT_SECRET: "azure",
  AZURE_CLIENT_ID: "azure",
  AZURE_TENANT_ID: "azure",
  KUBECONFIG: "kube",
  DOCKER_AUTH_CONFIG: "docker",
  PGPASSWORD: "pgpass"
});

// A custom name that looks like a credential: counted, never sent.
export const CREDENTIAL_ENV_SHAPE = /(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS?)$/i;
