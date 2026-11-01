// High-impact agent ACTIONS that should require explicit human approval by default — the
// "always require human approval" set from defense-in-depth guidance. The agent defaults these
// threats to the "justify" action (gate the prompt + log a business reason) unless the tenant
// policy sets a different action. A per-threat or data-tier policy still overrides this.
export const APPROVAL_THREATS = new Set([
  11, // transferring money / making payments
  43, // deleting data / destructive commands
  46, // changing security settings, IAM, or firewall
  47, // sending external email or notifications
  48, // creating users, tokens, or API keys
  49, // deploying to a production environment
  84  // weakening oversight: monitoring, alerting, audit logging or safety tests
]);
