// Tool capability tags — what a tool call can DO, as five coarse labels a policy rule can name:
//
//   read-private  reads a credential / secret file, or reads content a detector classified as private
//                 data (secrets, PII, regulated data, credential-file access)
//   read          reads local data (a file, a directory listing, a query result)
//   write         changes local state (a file write, a move, a delete)
//   network       reaches another host
//   exec          runs a program (every shell call; an MCP tool that runs code)
//
// Pure and browser-safe: names, regexes and set logic only. The hook glue (parsing a command, the session
// record, the policy sources) is cli/tool-tags.mjs. Content-free by construction: every function here
// returns tag NAMES and rule ids, never a path, a host or an argument.

export const TAGS = Object.freeze(["read-private", "read", "write", "network", "exec"]);
const TAG_SET = new Set(TAGS);
export const isTag = (t) => TAG_SET.has(t);

// Threats whose finding on a READ means the call read private data. The data tiers that carry private
// data (data/data-tiers.js: 15 PII, 39 secrets, 1 payment card, 44 PHI) and #55 credential-file access.
// Tier "source" (#9: roadmap / architecture prose) is left out: it fires on ordinary design documents.
export const PRIVATE_FINDING_IDS = Object.freeze([1, 15, 39, 44, 55]);

// The built-in host tools. Bash / PowerShell get `exec` here and the rest from the parsed command.
export const BUILTIN_TOOL_TAGS = Object.freeze({
  Read: ["read"],
  Glob: ["read"],
  Grep: ["read"],
  LS: ["read"],
  NotebookRead: ["read"],
  Write: ["write"],
  Edit: ["write"],
  MultiEdit: ["write"],
  NotebookEdit: ["write"],
  WebFetch: ["network"],
  WebSearch: ["network"],
  Bash: ["exec"],
  PowerShell: ["exec"]
});

// A path that names a credential or secret store. The locations #55 (cred-file-access) and the #55
// credential kinds name, as a path test rather than a command-text test, so a Read, a parsed shell read
// path and an MCP file argument are judged alike. An env TEMPLATE is not a secret.
const CRED_PATH = /(?:^|[\/\\])(?:\.env(?:\.[A-Za-z0-9_-]+)?|\.aws[\/\\](?:credentials|config)|\.ssh[\/\\](?:id_[a-z0-9_]+|.*_key)|\.npmrc|\.pypirc|\.git-credentials|\.netrc|_netrc|\.pgpass|\.docker[\/\\]config\.json|\.kube[\/\\]config|\.config[\/\\]gcloud[\/\\](?:credentials\.db|access_tokens\.db|application_default_credentials\.json|legacy_credentials)|\.azure[\/\\](?:accessTokens\.json|msal_token_cache\.json)|[^\/\\]+\.(?:pem|key|p12|pfx|jks|keystore|kdbx)|shadow|gshadow|master\.key|credentials\.json|secrets?\.(?:json|ya?ml|toml))$/i;
const ENV_TEMPLATE = /(?:^|[\/\\])\.env\.(?:example|sample|template|dist|defaults)$/i;
export function isCredentialPath(p) {
  if (typeof p !== "string" || !p || p.length > 4096) return false;
  if (ENV_TEMPLATE.test(p)) return false;
  return CRED_PATH.test(p.replace(/[\/\\]+$/, ""));
}

// A shell command that changes local state. A coarse test on the command text, on purpose: a redirect
// target, a write/delete/move verb at a command position, an in-place edit, a PowerShell write cmdlet.
const SHELL_WRITE = /(?:^|[^<>&0-9=-])>{1,2}(?!&)\s*(?!\/dev\/null\b)[^\s&|;]|(?:^|[\s;&|(`])(?:tee|cp|mv|rm|rmdir|mkdir|touch|truncate|install|ln|chmod|chown|dd|rsync|shred|unlink|patch)(?=\s)|\bsed\s+(?:-[A-Za-z]*\s+)*-i|\bperl\s+-[A-Za-z]*i|\b(?:Set-Content|Add-Content|Out-File|New-Item|Remove-Item|Copy-Item|Move-Item|Rename-Item|Clear-Content)\b|\bgit\s+(?:commit|push|reset|checkout|clean|rm|mv|apply|stash|merge|rebase)\b/i;
export function shellWrites(command) {
  return typeof command === "string" && command.length <= 65536 && SHELL_WRITE.test(command);
}

// A shell command that reaches another host through a client that names no URL: git remotes, package
// managers, remote shells, cloud CLIs. Hosts and URLs named in the command are parsed separately
// (data/net-exec.js netDestinations / urlDestinations) by cli/tool-tags.mjs.
const SHELL_NETWORK = /(?:^|[\s;&|(`])(?:ssh|scp|sftp|ftp|telnet|mosh|gh|aws|gcloud|gsutil|az|kubectl|helm|terraform|heroku|flyctl|vercel|netlify|wrangler)(?=\s|$)|\bgit\s+(?:push|pull|fetch|clone|ls-remote|remote\s+update|submodule\s+update)\b|\b(?:npm|pnpm|yarn|bun)\s+(?:install|i|add|publish|update|upgrade|ci|dlx|create)\b|\bnpx\s|\b(?:pip3?|pipx|uv)\s+(?:install|download)\b|\b(?:cargo|go)\s+(?:install|get|publish|fetch)\b|\bgem\s+(?:install|push)\b|\bbrew\s+(?:install|upgrade|update|tap)\b|\b(?:apt|apt-get|yum|dnf|apk)\s+(?:install|update|upgrade)\b|\bdocker\s+(?:push|pull|login|run|build)\b|\brsync\b[^\n|;&]*\s[^\s:]+:|\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer|Send-MailMessage|Test-NetConnection)\b/i;
export function shellNetworks(command) {
  return typeof command === "string" && command.length <= 65536 && SHELL_NETWORK.test(command);
}
// A shell command that reads local data beyond the paths the read-path parser names (listings, searches,
// repository history).
const SHELL_READ = /(?:^|[\s;&|(`])(?:ls|dir|find|fd|grep|egrep|rg|ag|ack|tree|du|stat|wc|diff|file|jq|yq|awk|sort|uniq|Get-ChildItem|gci|Select-String|sls)(?=\s|$)|\bgit\s+(?:log|show|diff|status|blame|grep|ls-files)\b/i;
export function shellReads(command) {
  return typeof command === "string" && command.length <= 65536 && SHELL_READ.test(command);
}

// ---- MCP tools: declared tags, then name heuristics (marked inferred) ----
//
// A tool's self-declared tags come from its definition's `_meta` (key "moorai/tags", or "tags"). They are
// ADDED to the inferred ones, never a replacement: a server cannot under-declare a capability its name
// gives away and slip past a rule. Inferred tags are what the tool's words suggest, so a rule hit that
// rests on one says so ("inferred") in the alert.
const MCP_WORDS = [
  ["read-private", /^(?:secret|secrets|credential|credentials|password|passwords|token|tokens|vault|keychain|apikey|keyring)$/],
  ["exec", /^(?:exec|execute|run|shell|command|cmd|eval|evaluate|spawn|terminal|script|bash|python|sandbox|repl|code)$/],
  ["write", /^(?:write|create|update|delete|remove|edit|set|put|insert|upsert|move|rename|append|save|commit|push|merge|patch|modify|replace|drop|add|upload|publish|post|send|archive|close|assign|comment|reply)$/],
  ["network", /^(?:fetch|http|https|request|url|web|browse|browser|navigate|download|upload|send|post|email|mail|slack|message|messages|webhook|publish|tweet|notify|api|curl|crawl|scrape|search|sms|invite|share)$/],
  ["read", /^(?:read|get|list|search|query|find|view|show|describe|cat|open|fetch|lookup|retrieve|load|download|export|dump|select|browse|scan|inspect|history|logs)$/]
];
// Servers whose every tool talks to a remote service. A local server (filesystem, sqlite, git on disk)
// gets network only from its tool's words.
const REMOTE_SERVERS = /^(?:github|gitlab|bitbucket|slack|gmail|google|gdrive|drive|notion|jira|confluence|atlassian|linear|asana|trello|figma|sentry|stripe|salesforce|hubspot|zendesk|intercom|discord|teams|outlook|office365|dropbox|box|fetch|brave|brave-search|tavily|exa|perplexity|browser|puppeteer|playwright|firecrawl|aws|gcp|azure|cloudflare|vercel|supabase|neon|postgres|mysql|mongodb|redis|twilio|sendgrid|mailgun|zapier|make|n8n|airtable|hugging-?face|openai|anthropic)$/i;

function words(s) {
  return String(s || "").replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}
function declaredOf(meta) {
  if (!meta || typeof meta !== "object") return [];
  const v = meta["moorai/tags"] ?? meta.tags;
  return Array.isArray(v) ? [...new Set(v.filter((t) => typeof t === "string" && isTag(t)))] : [];
}
// { declared: [tag], inferred: [tag] } for mcp__<server>__<tool>.
export function mcpToolTags(tool, meta) {
  const parts = String(tool || "").split("__");
  const server = parts[1] || "", name = parts.slice(2).join("_");
  const inferred = new Set();
  for (const w of words(name)) for (const [tag, re] of MCP_WORDS) if (re.test(w)) inferred.add(tag);
  if (REMOTE_SERVERS.test(server)) inferred.add("network");
  if (inferred.has("read-private")) inferred.add("read");
  const declared = declaredOf(meta);
  return { declared, inferred: TAGS.filter((t) => inferred.has(t) && !declared.includes(t)) };
}

// ---- tag rules ----
//
//   { id?, if: { sessionHas: [tag, ...] }, deny: [tag, ...], action?: "block" | "alert" }
//
// Fires on a call when the SESSION (every earlier call that ran, plus this one) has every tag in
// if.sessionHas, and THIS call has any tag in `deny`. action "block" denies the call; "alert" (the
// default) only reports it. Ids: [A-Za-z0-9._-], at most 64; a rule without one is "<source>#<index>".
const RULE_ID = /^[A-Za-z0-9._-]{1,64}$/;
const ACTIONS = new Set(["block", "alert"]);
export const MAX_TAG_RULES = 64;

function validRule(r, source, i) {
  if (!r || typeof r !== "object" || Array.isArray(r)) return { error: "not an object" };
  const has = r.if && typeof r.if === "object" ? r.if.sessionHas : undefined;
  if (!Array.isArray(has) || !has.length || !has.every(isTag)) return { error: "if.sessionHas must list known tags" };
  if (!Array.isArray(r.deny) || !r.deny.length || !r.deny.every(isTag)) return { error: "deny must list known tags" };
  if (r.action !== undefined && !ACTIONS.has(r.action)) return { error: "action must be block or alert" };
  if (r.id !== undefined && (typeof r.id !== "string" || !RULE_ID.test(r.id))) return { error: "id must match [A-Za-z0-9._-]{1,64}" };
  return { rule: { id: r.id || `${source}#${i}`, sessionHas: [...new Set(has)], deny: [...new Set(r.deny)], action: r.action || "alert", source } };
}

// Rules from the verified org policy and the root-owned machine-wide config, in that order. Anything else
// (a repo file, a user-scope file, an environment variable) is never a source. Invalid rules are skipped
// and returned in `rejected` as { source, index, error } — no rule content.
export function tagRulesFrom({ policy = null, system = null } = {}) {
  const rules = [], rejected = [];
  for (const [source, doc] of [["policy", policy], ["system", system]]) {
    const list = doc && typeof doc === "object" ? doc.tagRules : undefined;
    if (list === undefined) continue;
    if (!Array.isArray(list)) { rejected.push({ source, index: -1, error: "tagRules must be an array" }); continue; }
    list.slice(0, MAX_TAG_RULES).forEach((r, i) => {
      const v = validRule(r, source, i);
      if (v.rule) rules.push(v.rule); else rejected.push({ source, index: i, error: v.error });
    });
  }
  return { rules, rejected };
}

// The rules a call trips. sessionTags: tags of earlier calls of this session that ran; callTags: this
// call's tags. Returns [{ id, action, source, sessionHas, deny, matched }], block rules first.
export function evaluateTagRules(rules, sessionTags, callTags) {
  const call = new Set(callTags || []);
  const session = new Set([...(sessionTags || []), ...call]);
  const hits = [];
  for (const r of rules || []) {
    if (!r.sessionHas.every((t) => session.has(t))) continue;
    const matched = r.deny.filter((t) => call.has(t));
    if (matched.length) hits.push({ id: r.id, action: r.action, source: r.source, sessionHas: r.sessionHas, deny: r.deny, matched });
  }
  return hits.sort((a, b) => (a.action === b.action ? 0 : a.action === "block" ? -1 : 1));
}

// ---- tag actions: a static action per tag ----
//
//   tagActions: { exec: "block", network: "block", write: "ask", read: "alert" }
//
// Applies to every call carrying the tag, whatever the session did before. "block" denies, "ask" halts for
// sign-off, "alert" reports, "allow" does nothing. Policy and the machine-wide config are both read; where
// they name the same tag, the stricter action wins.
const TAG_ACTION_RANK = { allow: 0, alert: 1, ask: 2, block: 3 };
export const TAG_ACTION_VALUES = Object.freeze(Object.keys(TAG_ACTION_RANK));
export function tagActionsFrom({ policy = null, system = null } = {}) {
  const actions = {}, rejected = [];
  for (const [source, doc] of [["policy", policy], ["system", system]]) {
    const m = doc && typeof doc === "object" ? doc.tagActions : undefined;
    if (m === undefined) continue;
    if (!m || typeof m !== "object" || Array.isArray(m)) { rejected.push({ source, tag: "", error: "tagActions must be an object" }); continue; }
    for (const [tag, act] of Object.entries(m)) {
      if (!isTag(tag)) { rejected.push({ source, tag: "", error: "unknown tag" }); continue; }
      if (!(act in TAG_ACTION_RANK)) { rejected.push({ source, tag, error: "action must be block, ask, alert or allow" }); continue; }
      if (!(tag in actions) || TAG_ACTION_RANK[act] > TAG_ACTION_RANK[actions[tag]]) actions[tag] = act;
    }
  }
  return { actions, rejected };
}
// [{ tag, action }] for this call's tags whose action is not "allow", strictest first, then in TAGS order.
export function evaluateTagActions(actions, callTags) {
  const call = new Set(callTags || []);
  return TAGS.filter((t) => call.has(t) && actions && actions[t] && actions[t] !== "allow")
    .map((t) => ({ tag: t, action: actions[t] }))
    .sort((a, b) => TAG_ACTION_RANK[b.action] - TAG_ACTION_RANK[a.action]);
}
