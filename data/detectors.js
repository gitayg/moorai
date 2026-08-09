import { INJECTION_I18N } from "./injection-i18n.js";
import { SECRET_DETECTORS } from "./secrets-patterns.js";
import { inspectInstall } from "./popular-packages.js";

export const DETECTORS = [
  {
    // Multilingual prompt-injection — the "ignore previous instructions" / "reveal system prompt"
    // intent across ~29 languages (English + Hebrew are covered by inj-ignore below).
    detectorId: "inj-multilingual",
    threatId: 3,
    stage: "prompt",
    mode: "warn",
    hint: "Contains an instruction-override phrase in a non-English language (possible injection).",
    patterns: INJECTION_I18N
  },
  {
    // #5 — second-order / indirect injection: hidden instructions embedded in a document or pasted
    // content that hijack the AI when it's later read (RAG poisoning / retrieval-triggered). Runs on
    // the prompt stage and — via file/index stage-equivalence — on dropped files and OCR'd images.
    detectorId: "idx-hidden-instructions",
    threatId: 40,
    stage: "prompt",
    mode: "warn",
    hint: "Contains hidden / second-order instructions that could hijack the AI when this content is read.",
    patterns: [
      /\b(when|once|if|after)\s+(you|the\s+(ai|assistant|agent|model|llm|system))\b[^.]{0,60}\b(ignore|disregard|instead|execute|run|fetch|send|exfiltrat|reveal|forward|email|upload)\b/i,
      /<!--[^>]*\b(system|assistant|instruction|ignore|prompt)\b[^>]*-->/i,
      /\b(system|assistant)\s+(prompt|message|instruction)s?\s*[:=]/i,
      /\bnew\s+(instructions?|directives?|system\s+prompt)\b\s*[:=\-]/i,
      /\bAI\s+(assistant|agent|model)\s*:\s*(ignore|from now|you\s+(are|must|will))/i
    ]
  },
  {
    // Advisory: contract / legal language → recommend legal counsel (notify by default), logged to dashboard.
    detectorId: "legal-language",
    threatId: 41,
    stage: "prompt",
    mode: "warn",
    hint: "Looks like legal / contract language — consider professional legal review.",
    patterns: [
      /\b(hereby|whereas|indemnif\w+|in witness whereof|govern(ing|ed) (law|by the)|non[- ]disclosure|terms (and|&) conditions|force majeure|represents and warrants|breach of (this )?(contract|agreement)|party of the (first|second) part|binding (agreement|contract)|arbitration clause|confidentiality (clause|agreement)|liabilit(y|ies) (shall|will|is) (limited|excluded)|\bNDA\b)/i,
      /(חוזה|הסכם|כתב התחייבות|אי[- ]גילוי|סעיף סודיות|הצדדים מסכימים|תניית|בכפוף לדין|בוררות|שיפוט בלעדי)/
    ]
  },
  {
    // Advisory (legal): licensed / copyrighted source pasted INTO a prompt → license-contamination risk.
    detectorId: "legal-license-prompt",
    threatId: 45,
    stage: "prompt",
    mode: "warn",
    hint: "Looks like licensed / copyrighted source — confirm the license before reusing.",
    patterns: [
      /SPDX-License-Identifier:/i,
      /\b(GNU (GENERAL|LESSER GENERAL) PUBLIC LICENSE|Mozilla Public License|Apache License,? Version|BSD [23]-Clause|Creative Commons)\b/i,
      /\bLicensed under the .{0,40}License\b/i,
      /Permission is hereby granted, free of charge/i,
      /Copyright\s*(\([cC]\)|©)\s*\d{4}/,
      /\bAll rights reserved\b/i,
      /\b([AL]?GPL(v?[23](\.0)?)?|MPL-2\.0|BSD-[23]-Clause)\b/
    ]
  },
  {
    // Advisory (legal): the AGENT OUTPUT reproduces a large verbatim licensed/copyrighted block.
    detectorId: "legal-license-output",
    threatId: 45,
    stage: "output",
    mode: "warn",
    hint: "AI output contains a licensed / copyrighted block — verify provenance before reuse.",
    patterns: [
      /SPDX-License-Identifier:/i,
      /\b(GNU (GENERAL|LESSER GENERAL) PUBLIC LICENSE|Mozilla Public License|Apache License,? Version|BSD [23]-Clause)\b/i,
      /Permission is hereby granted, free of charge/i,
      /Copyright\s*(\([cC]\)|©)\s*\d{4}[^\n]{0,60}\ball rights reserved\b/i,
      /This (program|file|software) is free software.{0,60}(GNU|redistribute)/is
    ]
  },
  {
    // Advisory: employee-relations / PIP language → recommend HR + legal (notify), logged to dashboard.
    detectorId: "hr-employee-relations",
    threatId: 42,
    stage: "prompt",
    mode: "warn",
    hint: "Looks like an employee-relations / PIP action — involve HR and legal.",
    patterns: [
      /\b(performance improvement plan|written warning|final warning|verbal warning|disciplinary (action|process|hearing|measure)|corrective action|wrongful termination|terminat(e|ing|ion)( of)?( (the|an|his|her|their))? (employment|employee)|severance( pay| package)?|lay(\s|-)?off|laid off|gross misconduct|harassment complaint|place(d)? (\w+ )?on probation)/i,
      /\bPIP\b/,
      /(תוכנית שיפור ביצועים|שימוע|פיטורי(ם|ן)|מכתב התראה|הליך משמעתי|פיצויי פיטורים|סיום העסקה|תלונת הטרדה|אזהרה בכתב)/
    ]
  },
  {
    detectorId: "dlp-email",
    threatId: 15,
    stage: "prompt",
    stages: ["prompt", "output"], // #4 — screen PII in agent output too, content-free
    mode: "warn",
    hint: "Looks like an email address (personal data).",
    patterns: [/\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b/]
  },
  {
    detectorId: "dlp-national-id",
    threatId: 15,
    stage: "prompt",
    stages: ["prompt", "output"], // #4
    mode: "warn",
    hint: "Looks like a 9-digit national ID.",
    patterns: [/(?<!\d)\d{9}(?!\d)/]
  },
  {
    detectorId: "dlp-payment-card",
    threatId: 1,
    stage: "prompt",
    stages: ["prompt", "output"], // #4
    mode: "warn",
    hint: "Looks like a payment-card number.",
    patterns: [/\b(?:\d[ -]?){13,16}\b/]
  },
  {
    detectorId: "dlp-iban",
    threatId: 1,
    stage: "prompt",
    mode: "warn",
    hint: "Looks like an IBAN / bank account.",
    patterns: [/\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/]
  },
  // #7 — battle-tested secrets engine: broad prefix-anchored provider tokens + entropy-gated shapeless
  // detectors (see data/secrets-patterns.js). All map to threat #39 (deduped by threatId).
  ...SECRET_DETECTORS,
  {
    detectorId: "dlp-private-key",
    threatId: 39,
    stage: "prompt",
    stages: ["prompt", "output"],
    mode: "warn",
    hint: "Contains a private key block.",
    patterns: [/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/]
  },
  {
    detectorId: "dlp-jwt",
    threatId: 39,
    stage: "prompt",
    stages: ["prompt", "output"],
    mode: "warn",
    hint: "Looks like a JWT / bearer token.",
    patterns: [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/, /\bBearer\s+[A-Za-z0-9._-]{20,}/i]
  },
  {
    detectorId: "dlp-phone",
    threatId: 15,
    stage: "prompt",
    stages: ["prompt", "output"], // #4
    mode: "warn",
    hint: "Looks like a phone number (personal data).",
    patterns: [/(?<!\d)(?:\+?\d{1,3}[ .-]?)?\(?\d{2,4}\)?[ .-]?\d{3}[ .-]?\d{4}(?!\d)/]
  },
  {
    detectorId: "dlp-ip-markers",
    threatId: 9,
    stage: "prompt",
    mode: "warn",
    hint: "Mentions intellectual property (roadmap, architecture, source, trade secret).",
    patterns: [/\b(confidential|proprietary|internal[ -]use[ -]only|road[ -]?map|architecture diagram|source code|trade secret|pricing strategy)\b/i]
  },
  {
    detectorId: "inj-ignore",
    threatId: 3,
    stage: "prompt",
    mode: "warn",
    hint: "Contains an instruction-override phrase (possible prompt injection).",
    patterns: [
      /ignore (the |all |any )?(previous|above|prior|earlier) (instructions?|prompts?|messages?)/i,
      /disregard (all |any )?(previous|prior|above|earlier)/i,
      /\b(reveal|print|show) (your |the )?(system prompt|instructions|developer message)\b/i,
      /\b(jailbreak|do anything now|\bDAN\b)\b/i
    ]
  },
  {
    // Multi-turn jailbreak scaffolding — persona/role-play setup that primes a later payload.
    // Evaluated over the recent conversation window (stage "session"), not a single prompt.
    detectorId: "inj-multiturn-persona",
    threatId: 3,
    stage: "session",
    mode: "warn",
    hint: "Conversation is setting up a jailbreak persona / role-play across turns.",
    patterns: [
      /(from now on|starting now|for the rest of (this|our))\s+you\s+(are|will be|act|must)/i,
      /you are now\s+(a|an|dan|in\s+developer\s+mode|jailbroken)/i,
      /let'?s\s+play\s+a\s+(game|role.?play|scenario)/i,
      /(pretend|imagine|suppose)\s+(that\s+)?you\s+(are|have\s+no|can\s+ignore)/i,
      /\b(developer\s+mode|do\s+anything\s+now|\bDAN\b|opposite\s+day)\b/i,
      /this\s+is\s+(just\s+)?(a\s+)?(hypothetical|fictional|story|thought\s+experiment)/i
    ]
  },
  {
    detectorId: "inj-exfil",
    threatId: 2,
    stage: "prompt",
    mode: "warn",
    hint: "Asks to send data out / to an external destination.",
    patterns: [/\b(exfiltrate|send (the )?(data|info|information|file)s? (out|to)|post (it )?to https?:)/i]
  },
  {
    detectorId: "bec-payment",
    threatId: 11,
    stage: "prompt",
    mode: "coach",
    hint: "Payment / bank-detail change context — verify on a pre-known channel.",
    patterns: [/\b(change (the )?bank (details|account)|new (bank )?account number|update (the )?payment details|wire transfer|urgent payment|pay (this|the) invoice|iban change)\b/i]
  },
  {
    detectorId: "out-code-exec",
    threatId: 32,
    stage: "output",
    mode: "warn",
    hint: "Output contains runnable code / a risky command.",
    patterns: [
      /```/,
      /\b(powershell|invoke-webrequest|set-executionpolicy|cmd\.exe|reg add|schtasks)\b/i,
      /curl\s+[^\n]*\|\s*(ba)?sh/i,
      /\brm\s+-rf\b/,
      /\b(macro|vba|autoopen|enablemacros)\b/i
    ]
  },
  {
    detectorId: "out-links",
    threatId: 17,
    stage: "output",
    mode: "warn",
    hint: "Output contains a link — do not open without checking.",
    patterns: [/https?:\/\/[^\s)<>]+/i]
  },
  {
    detectorId: "out-citation",
    threatId: 29,
    stage: "output",
    mode: "coach",
    hint: "Output cites a source/standard — verify it exists before using it.",
    patterns: [/\b(et al\.|doi:|ISO\s?\d{3,}|APA|section\s?\d+(\.\d+)?|\[\d+\])\b/i]
  },
  {
    detectorId: "destructive-command",
    threatId: 43,
    stage: "prompt",
    mode: "warn",
    hint: "Contains a destructive, hard-to-reverse command — review before it runs.",
    patterns: [
      /\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r/i,
      /\bsudo\s+rm\b/i,
      /\bgit\s+push\s+(--force\b|-f\b)/i,
      /\bgit\s+reset\s+--hard\b/i,
      /\bdrop\s+(database|table|schema)\b/i,
      /\btruncate\s+table\b/i,
      /\bdelete\s+from\s+\w+\s*;?\s*$/i,
      /\b(mkfs|diskutil\s+erase|dd\s+if=\S+\s+of=\/dev\/)/i,
      /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/
    ]
  },
  {
    detectorId: "phi-hipaa",
    threatId: 44,
    stage: "prompt",
    stages: ["prompt", "output"], // #4
    mode: "warn",
    hint: "Looks like protected health information (PHI) — don't send patient data to the AI.",
    patterns: [
      /\b(diagnos(is|es|ed)|prescri(be|bed|ption)|patient (record|id|name|chart)|medical record|health insurance (number|claim|id)|protected health information|\bPHI\b|lab results|prognosis|treatment plan)\b/i,
      /\bMRN[:#\s]*[A-Z0-9-]{4,}/i,
      /\bNPI[:#\s]*\d{10}\b/i,
      /\bDEA[:#\s]*[A-Z]{2}\d{7}\b/i,
      /\b[A-TV-Z]\d{2}\.\d{1,4}\b/
    ]
  },
  {
    detectorId: "pii-passport",
    threatId: 15,
    stage: "prompt",
    stages: ["prompt", "output"], // #4
    mode: "warn",
    hint: "Looks like a passport number (regulated personal data).",
    patterns: [/\bpassport\b.{0,20}?\b[A-Z]{0,2}\d[A-Z0-9]{4,8}\b/i]
  },
  {
    detectorId: "pci-cvv",
    threatId: 1,
    stage: "prompt",
    stages: ["prompt", "output"], // #4
    mode: "warn",
    hint: "Looks like a card security code (PCI data).",
    patterns: [/\b(cvv2?|cvc2?|security code|card verification)\s*(no\.?|#|:)?\s*\d{3,4}\b/i]
  },
  {
    // #46 — changing security settings / IAM / firewall (human-approval action).
    detectorId: "action-security-config",
    threatId: 46,
    stage: "prompt",
    mode: "warn",
    hint: "Asks to change security, IAM, or firewall settings — should require approval.",
    patterns: [
      /\b(disable|turn off|stop)\b.{0,20}\b(firewall|ufw|firewalld|windows defender|real[- ]?time protection|gatekeeper|\bSIP\b)\b/i,
      /\bufw\s+disable\b|netsh\s+advfirewall.*\boff\b|Set-MpPreference\s+-Disable|csrutil\s+disable|spctl\s+--master-disable/i,
      /\b(iam|role|policy)\b.{0,40}\b(AdministratorAccess|full[- ]?access|\*:\*|grant all|attach.*policy)\b/i,
      /\b(0\.0\.0\.0\/0|::\/0)\b.{0,25}\b(ingress|inbound|security ?group|allow)\b/i,
      /\bchmod\s+777\b|add\b.{0,15}\bsudoers\b|\baws\s+iam\b|\baz\s+role\s+assignment\b|gcloud\s+(iam|projects add-iam)/i
    ]
  },
  {
    // #47 — sending external email / notifications (human-approval action).
    detectorId: "action-external-comms",
    threatId: 47,
    stage: "prompt",
    mode: "warn",
    hint: "Asks to send an external email / message / notification — should require approval.",
    patterns: [
      /\bsend\b.{0,20}\b(email|e-mail|sms|text message|notification|message)\b.{0,15}\bto\b/i,
      /\b(smtp|sendgrid|mailgun|postmark|nodemailer|twilio)\b|ses\.(send|SendEmail)/i,
      /hooks\.slack\.com|discord(app)?\.com\/api\/webhooks|chat\.googleapis\.com/i,
      /\b(sendmail|mailx|mail)\s+-s\b/i
    ]
  },
  {
    // #48 — creating users / tokens / API keys (human-approval action).
    detectorId: "action-credential-create",
    threatId: 48,
    stage: "prompt",
    mode: "warn",
    hint: "Asks to create a user, token, or API key — should require approval.",
    patterns: [
      /\b(create|add|provision|generate|mint|issue)\b.{0,25}\b(service account|api[- ]?key|access[- ]?key|personal access token|oauth client|client secret|credential)\b/i,
      /\baws\s+iam\s+create-(access-key|user)\b|gcloud\s+iam\s+service-accounts\s+keys?\s+create/i,
      /\b(adduser|useradd|New-LocalUser)\b|net\s+user\s+\S+\s+\/add/i,
      /\bssh-keygen\b|openssl\s+genrsa\b/i
    ]
  },
  {
    // #49 — deploying to production (human-approval action).
    detectorId: "action-prod-deploy",
    threatId: 49,
    stage: "prompt",
    mode: "warn",
    hint: "Asks to deploy or release to production — should require approval.",
    patterns: [
      /\b(deploy|release|ship|promote|roll ?out)\b.{0,25}\b(to\s+)?(prod|production|live)\b/i,
      /\bterraform\s+apply\b|kubectl\s+apply\b.{0,45}\b(prod|production)\b|helm\s+(install|upgrade)\b.{0,45}\bprod/i,
      /\bvercel\b.{0,15}--prod\b|\bfirebase\s+deploy\b|\bnpm\s+publish\b|serverless\s+deploy\b.{0,20}(prod|production)/i,
      /\bgit\s+push\b.{0,20}\b(prod|production|release)\b|docker\s+push\b.{0,45}(prod|production|:latest)\b/i
    ]
  }
,
  {
    // #50 (LLM08) — invisible / obfuscated text: zero-width & bidirectional (Trojan-Source) chars
    // that hide steering text from humans but not the model. High-signal RAG/embedding-poisoning tell.
    detectorId: "idx-invisible-text",
    threatId: 50,
    stage: "prompt",
    mode: "warn",
    hint: "Zero-width run or direction-override characters that hide instructions from humans (RAG / embedding poisoning).",
    patterns: [
      // FP-scoped: a RUN of \u22652 consecutive zero-widths (stego signal) \u2014 a single ZWJ between emoji
      // scalars or one leading BOM never matches. Bidi is limited to the two OVERRIDES (Trojan Source);
      // plain RTL embeddings/isolates are legitimate and no longer flagged.
      /[\u200B-\u200D\u2060\uFEFF]{2,}/,
      /[\u202D\u202E]/
    ]
  },
  {
    // #51 (LLM07) — system-prompt extraction probes.
    detectorId: "sysprompt-extract",
    threatId: 51,
    stage: "prompt",
    mode: "warn",
    hint: "Looks like an attempt to extract the system prompt / hidden instructions.",
    patterns: [
      /\b(repeat|print|show|reveal|output|display|give me|tell me)\b[^.\n]{0,40}\b(the\s+)?(system|initial|developer|above|previous|your)\s+(prompt|instructions?|message|rules?|directives?)\b/i,
      /\b(what|which)\s+(are|were)\s+your\s+(instructions?|rules?|system\s+prompt|directives?|guidelines?)\b/i,
      /\brepeat (the words|everything) above\b/i
    ]
  },
  {
    // #52 (LLM07) — system-prompt / instruction leakage in the model's OUTPUT.
    detectorId: "sysprompt-echo",
    threatId: 52,
    stage: "output",
    mode: "warn",
    hint: "The reply appears to recite the system prompt / instruction block.",
    patterns: [
      /\bYou are (a|an|the)\b[^.\n]{0,60}\b(assistant|model|agent|AI|LLM)\b[\s\S]{0,80}\b(rules?|instructions?|guidelines?|you must|do not|never)\b/i,
      /\b(my (system )?instructions are|the system prompt (is|says)|i was instructed to)\b/i
    ]
  },
  {
    // #53 (LLM10) — oversized single input (token-blowup / unbounded consumption). Linear regex.
    detectorId: "oversized-input",
    threatId: 53,
    stage: "prompt",
    mode: "warn",
    hint: "Extremely large single input — possible token-blowup / unbounded consumption.",
    patterns: [
      /[\s\S]{60000,}/
    ]
  },
  {
    // #54 (LLM05) — reverse shell / remote code execution the agent proposes or runs. Prompt + output:
    // a user may ask for it, or the model may emit it. Distinct from destructive-command (#43): this
    // hands a remote host a live shell rather than destroying local state.
    detectorId: "exec-reverse-shell",
    threatId: 54,
    stages: ["prompt", "output"],
    mode: "warn",
    hint: "Reverse-shell / remote-exec pattern — would hand a remote host a live shell.",
    patterns: [
      /\/dev\/(tcp|udp)\/[^\s/]+\/\d+/i,
      /\bbash\s+-i\b[\s\S]{0,40}(>&|>|\d>)/i,
      /\bn(c|cat)\b[^\n]{0,40}\s-[a-z]*e[a-z]*\b[^\n]{0,20}\b(sh|bash|cmd(\.exe)?|powershell)\b/i,
      /\bsocat\b[^\n]{0,60}\bexec:/i,
      /\bpython[23]?\b[^\n]{0,80}\b(socket|pty\.spawn)\b[\s\S]{0,80}\b(sh|bash)\b/i,
      /\bperl\b[^\n]{0,40}-e\b[^\n]{0,80}\b(socket|Socket)\b/i,
      /New-Object\s+System\.Net\.Sockets\.TCPClient/i,
      /\bmkfifo\b[^\n]{0,40}\|[^\n]{0,40}\b(sh|bash)\b/i
    ]
  },
  {
    // #55 (LLM02) — the agent reads a credential / secret file. Prompt + output (agent proposes the read).
    // Anchored on read verbs + credential paths, plus a few bare high-signal paths.
    detectorId: "cred-file-access",
    threatId: 55,
    stages: ["prompt", "output"],
    mode: "warn",
    hint: "Reads a credential / secret file (.env, cloud creds, SSH key, /etc/shadow).",
    patterns: [
      /\b(cat|less|more|head|tail|type|Get-Content|xxd|base64|strings|nano|vi|vim|open)\b[^\n]{0,50}(\.env\b|\.aws[\/\\]credentials|\.ssh[\/\\]id_[a-z0-9]+|\.npmrc\b|\.git-credentials\b|\.netrc\b|\.pgpass\b|\.docker[\/\\]config\.json|\.kube[\/\\]config)/i,
      /[~\/][^\s"']*\.aws[\/\\]credentials\b/i,
      /\.ssh[\/\\]id_(rsa|ed25519|ecdsa|dsa)\b/i,
      /(^|[\s"'=])\/etc\/shadow\b/,
      /\.git-credentials\b/i,
      /\bsecurity\s+find-generic-password\b/i,
      /\bgcloud\s+auth\s+(print-access-token|application-default\s+print-access-token)\b/i,
      /\b(printenv|env)\b[^\n]{0,20}\|\s*grep\s+-i[^\n]{0,20}\b(secret|token|key|password|aws)\b/i
    ]
  },
  {
    // #56 (LLM06) — destructive TOOL / MCP call (ORM/driver/cloud/API), as opposed to a destructive
    // SHELL command (#43). Excessive-agency: the agent invokes an irreversible operation via a tool.
    detectorId: "mcp-destructive-call",
    threatId: 56,
    stages: ["prompt", "output"],
    mode: "warn",
    hint: "Destructive tool / MCP call (mass delete, resource teardown, drop).",
    patterns: [
      /\b(dropDatabase|dropCollection|deleteMany|deleteAll|dropTable|truncateTable)\s*\(/i,
      /\bdb\.\w+\.(drop|remove|deleteMany|deleteOne)\s*\(/i,
      /\baws\s+(s3\s+rb\b|s3\s+rm\b[^\n]{0,40}--recursive|ec2\s+terminate-instances\b|rds\s+delete-db-\w+\b|dynamodb\s+delete-table\b)/i,
      /\b(kubectl|helm)\s+delete\b[^\n]{0,40}(--all\b|-n\s+\w+|namespace\b)/i,
      /\bgh\s+repo\s+delete\b/i,
      /\bgit\s+push\b[^\n]{0,40}--delete\b/i,
      /\bDELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1\b/i
    ]
  },
  {
    // #57 (LLM03) — install of code from an untrusted source (supply-chain). Prompt + output.
    // Overlaps out-code-exec (#32) on curl|bash but maps to a distinct supply-chain threat.
    detectorId: "pkg-install-untrusted",
    threatId: 57,
    stages: ["prompt", "output"],
    mode: "warn",
    hint: "Installs code from an untrusted source (remote script, alt index, git/URL package).",
    patterns: [
      /\b(curl|wget)\b[^\n]{0,120}\|\s*(sudo\s+)?(ba)?sh\b/i,
      /\bpip3?\s+install\b[^\n]{0,80}(git\+|https?:\/\/|--index-url|--extra-index-url|--trusted-host)/i,
      /\b(npm|pnpm|yarn)\s+(install|add|i)\b[^\n]{0,80}(git\+|github:|https?:\/\/|file:)/i,
      /\b(cargo|go)\s+install\b[^\n]{0,80}(git|https?:\/\/)/i,
      /\bgem\s+install\b[^\n]{0,80}--source\b[^\n]{0,40}https?:\/\//i,
      /\bnpx\s+(-y|--yes)\b/i,
      /\bpowershell\b[^\n]{0,80}\b(iwr|Invoke-WebRequest|irm)\b[^\n]{0,60}\|\s*(iex|Invoke-Expression)\b/i
    ]
  },
  // #4 / #61 (LLM05) — on-device output screening for INSECURE CODE the agent generates. Distinct from
  // executing a dangerous command (#32/#43/#54): this flags injection-prone SOURCE the agent writes into
  // the codebase. Output-stage so it screens replies without ever inspecting the repo; the finding is
  // content-free (rule id + severity + one-way hash of the matched span), so nothing readable egresses.
  {
    detectorId: "code-sql-injection",
    threatId: 61,
    stage: "output",
    mode: "warn",
    hint: "SQL query built from string concatenation / interpolation — use parameterized queries.",
    patterns: [
      /\b(execute|executemany|executescript|query|prepare|raw)\s*\(\s*f["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE|DROP|MERGE)\b/i,
      /["'`]\s*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"'`]*["'`]\s*\+\s*[\w.$([]/i,
      /`[^`]*\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^`]*\$\{/i,
      /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"'`;\n]*["']\s*%\s*\(?\s*[\w.$]/i
    ]
  },
  {
    detectorId: "code-xss-sink",
    threatId: 61,
    stage: "output",
    mode: "warn",
    hint: "Untrusted value flows to an HTML sink (innerHTML / dangerouslySetInnerHTML / document.write).",
    patterns: [
      /\.innerHTML\s*=\s*(?!["'`]\s*;?\s*$)[^"'`;\n]*[\w$)\]]/,
      /dangerouslySetInnerHTML\s*[:=]\s*\{\{?\s*__html/,
      /\bdocument\.write(ln)?\s*\(\s*(?!["'`])[^)]*[\w$)\]]/i,
      /\.insertAdjacentHTML\s*\(\s*[^,]+,\s*(?!["'`])/i,
      /\bv-html\s*=/
    ]
  },
  {
    detectorId: "code-command-injection",
    threatId: 61,
    stage: "output",
    mode: "warn",
    hint: "Shell invoked with a built/interpolated string or shell=True — command-injection risk.",
    patterns: [
      /\bsubprocess\.(run|call|check_output|check_call|Popen)\s*\([^)]*shell\s*=\s*True/i,
      /\bos\.system\s*\(\s*(f["']|[^)]*[+%]\s*[\w.$])/i,
      /\bos\.popen\s*\(\s*(f["']|[^)]*[+%])/i,
      /\bchild_process\.(exec|execSync)\s*\(\s*(`[^`]*\$\{|[^)]*\+\s*[\w.$])/i,
      /\bexec[AS]?[a-z]*\s*\(\s*`[^`]*\$\{/i
    ]
  },
  {
    detectorId: "code-eval-dynamic",
    threatId: 61,
    stage: "output",
    mode: "warn",
    hint: "Dynamic code execution (eval / new Function / string-arg timer / exec of input).",
    patterns: [
      /\beval\s*\(\s*(?!["'`)\s])/,
      /\bnew\s+Function\s*\(/,
      /\b(setTimeout|setInterval)\s*\(\s*["'`]/,
      /\bexec\s*\(\s*f["']/i,
      /\b(exec|eval)\s*\([^)]*\b(input|request|argv|params|req\.(body|query|params))\b/i
    ]
  },
  {
    detectorId: "code-weak-crypto",
    threatId: 61,
    stage: "output",
    mode: "warn",
    hint: "Weak / broken cryptographic primitive (MD5, SHA-1, DES, RC4, ECB).",
    patterns: [
      /\bhashlib\.(md5|sha1)\s*\(/i,
      /\bcreateHash\s*\(\s*["'](md5|sha1)["']\s*\)/i,
      /\bMessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-?1)["']/i,
      /\b(DES|RC4)\b\s*[\/(.]/,
      /["'](AES|DES)[\/-]ECB[\/-]/i
    ]
  },
  {
    detectorId: "code-insecure-deser",
    threatId: 61,
    stage: "output",
    mode: "warn",
    hint: "Unsafe deserialization of untrusted data (pickle / yaml.load / unserialize).",
    patterns: [
      /\bc?[Pp]ickle\.loads?\s*\(/,
      /\byaml\.load\s*\((?![^)]*Safe(Loader)?)/i,
      /\b(unserialize|Marshal\.load)\s*\(/i,
      /\bnew\s+ObjectInputStream\s*\(/
    ]
  },
  {
    // T1-1 / #63 (LLM02) — base-URL override that redirects an agent's model traffic to a non-official
    // endpoint (the classic exfil-via-rogue-endpoint / logging-proxy vector). Flags the override itself;
    // hook-core additionally enforces the org's endpoint allow-list on the extracted host. Content-free
    // (host + env-var name only). Loopback overrides (local models) are intentionally NOT matched here.
    detectorId: "model-endpoint-override",
    threatId: 63,
    stages: ["prompt", "output"],
    mode: "warn",
    hint: "Model base-URL override to a non-official endpoint — possible rogue-LLM egress.",
    patterns: [
      /\b(ANTHROPIC_BASE_URL|ANTHROPIC_API_URL|OPENAI_BASE_URL|OPENAI_API_BASE|OPENAI_PROXY|AZURE_OPENAI_ENDPOINT|HF_ENDPOINT|GROQ_BASE_URL|MISTRAL_BASE_URL|TOGETHER_BASE_URL|OPENROUTER_BASE_URL|COHERE_BASE_URL|LITELLM_PROXY_URL|OLLAMA_BASE_URL)\s*[=:]\s*["']?https?:\/\/(?!(?:localhost|127\.0\.0\.1|\[::1\]))/i
    ]
  },
  {
    // T1-3 / #50 (LLM08) - net-new invisible-text coverage beyond idx-invisible-text: Unicode Tag block
    // (ASCII smuggling), ANSI/OSC terminal escapes, and the variation-selector supplement (byte
    // smuggling). Near-certainly malicious in prompts/files/output, so they flag on presence.
    // Content-free - matches the control chars themselves, never surrounding content.
    detectorId: "obf-invisible-instructions",
    threatId: 50,
    stages: ["prompt", "output"],
    mode: "warn",
    hint: "Hidden/invisible text (Unicode tag block, ANSI escape, or variation-selector smuggling).",
    patterns: [
      /[\u{E0000}-\u{E007F}]/u,
      /\x1b[\[\]P^_]/,
      /[\u{E0100}-\u{E01EF}]/u
    ]
  },
  {
    // T1-4 / #2 (LLM01) — direct jailbreak / persona-bypass phrasings, a curated high-precision subset
    // (DAN lineage, developer/god-mode unlock, named personas, restriction-removal, prefix injection,
    // safety-bypass, chat-template control-token injection, grandma/fiction framings). Each object noun
    // is scoped so normal dev prompts ("act as a code reviewer", "enable developer mode in webpack",
    // "disable the safety check in the test harness") do NOT match. Content-free (phrasing only).
    detectorId: "inj-jailbreak",
    threatId: 2,
    stage: "prompt",
    mode: "warn",
    hint: "Direct jailbreak / persona-bypass phrasing (possible prompt injection).",
    patterns: [
      /\byou\s+are\s+(?:now\s+)?in\s+(?:developer|dev|debug|god|dan|jailbreak|unrestricted|unfiltered|uncensored|sudo|root|kernel)\s+mode\b|\b(?:enable|enter|activate|turn\s+on|switch\s+(?:in)?to|unlock)\s+(?:the\s+)?(?:god|dan|jailbreak|unrestricted|unfiltered|uncensored|do[\s-]?anything|no[\s-]?holds?[\s-]?barred)\s+mode\b/i,
      /\bDAN\b[\s\S]{0,60}?\bdo\s+anything\s+now\b|\bdo\s+anything\s+now\b[\s\S]{0,60}?\bDAN\b|\byou\s+are\s+(?:going\s+to\s+(?:act|pretend)\s+(?:as|to\s+be)\s+)?DAN\b/i,
      /\b(?:you\s+are|act\s+as|roleplay\s+as|role-?play\s+as|pretend\s+to\s+be|become|simulate|behave\s+like)\s+(?:now\s+)?(?:AIM|STAN|DUDE|Mongo\s+Tom|Evil\s+Confidant|AntiGPT|BetterDAN|UnfilteredGPT|JailBreak)\b/i,
      /\byou\s+are\s+(?:now\s+)?(?:a\s+|an\s+)?[\w\s,'-]{0,45}?(?:with\s+no|without\s+(?:any\s+)?|free\s+(?:from|of)|that\s+(?:has\s+no|ignores))\s*(?:restriction|filter|limit|rule|guideline|censorship|guardrail|boundar|constraint)s?\b/i,
      /\byou\s+are\s+(?:now\s+)?no\s+longer\s+(?:bound|restricted|limited|constrained|governed|subject\s+to|obligated)\b/i,
      /\b(?:start|begin|preface|prefix|open)\s+(?:your\s+)?(?:response|reply|answer|output|message)\s+(?:with|by\s+saying)\b[^"'“\n]{0,30}["'“](?:sure|of\s+course|certainly|absolutely|here(?:'s|\s+is|\s+are)|yes,?\s+i)/i,
      /\b(?:bypass|disable|turn\s+off|deactivate|circumvent|evade|switch\s+off|suppress|lift)\s+(?:(?:your|the|all)\s+){0,2}(?:safety|content|ethical|moderation)\s+(?:filter|guardrail|restriction|polic(?:y|ies)|mechanism|constraint)s?\b/i,
      /<\|(?:im_start|im_end|eot_id|start_header_id|end_header_id|endoftext|assistant|system|user)\|>|\[INST\]|\[\/INST\]|<<SYS>>/i,
      /\b(?:my\s+)?(?:deceased|dead|late|dying|departed)\s+(?:grand\s?ma|grand\s?mother|granny|nana|gran|grandpa|grand\s?father)\b[\s\S]{0,90}?(?:used\s+to|would\s+(?:always\s+)?(?:tell|read|recite|sing|whisper|list)|tell\s+me|read\s+me|recite|whisper)/i,
      /\b(?:in\s+(?:a|this)\s+(?:fictional|hypothetical|imaginary|purely\s+theoretical)\s+(?:world|scenario|story|setting|universe)|(?:this\s+is|it['’]s)\s+(?:just|purely|only)?\s*(?:a\s+)?(?:fiction|hypothetical|thought\s+experiment|role[\s-]?play))\b[\s\S]{0,80}?\b(?:no\s+(?:rules|restrictions|limits|consequences|filters|boundaries)|anything\s+(?:is\s+allowed|goes)|nothing\s+(?:is\s+)?(?:forbidden|off[\s-]limits|banned))/i
    ]
  },
  {
    // T1-2 / #62 (LLM03) — hallucinated / typosquatted dependency in an install command. The pattern
    // matches any install command; refine() classifies the package NAME offline (known-malicious,
    // typosquat near-miss of a popular package, or cross-ecosystem confusion) and only fires when
    // suspicious — so benign installs of real popular packages never flag. Content-free (name only).
    detectorId: "dep-typosquat",
    threatId: 62,
    stages: ["prompt", "output"],
    mode: "warn",
    hint: "Install of a hallucinated / typosquatted package (name is a near-miss of a popular package or a known-bad name).",
    patterns: [/\b(?:npm|pnpm|yarn|bun|pip3?|pipx|cargo)\s+(?:install|add|i)\b[^\n]{0,140}/i],
    refine: (m) => !!inspectInstall(m)
  }
];
