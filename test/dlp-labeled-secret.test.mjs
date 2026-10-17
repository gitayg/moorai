// Per-file runner:  node --test test/dlp-labeled-secret.test.mjs
//
// A credential written as LABELED PROSE matched no #39 detector. Provider tokens are prefix-anchored
// (AKIA, sk-, ghp_ …) and every other detector needs a NAME=value shape AND Shannon entropy >= 3.5,
// so a memo line such as "Master Password: m@st3r-p@$$w0rd-2025" or "API Key: api_prod_8a7b…" (an
// unknown prefix, low entropy) passed through an MCP result, a file read or a prompt unseen. Found by
// the Damn Vulnerable MCP evaluation (challenges 6, 8 and 10).
//
// Two detectors close it, with no entropy bar:
//   secret-labeled-prose  — a secret LABEL (password, secret, api key, token, …) then `:` or `=` and a
//                           non-placeholder value of 8+ characters.
//   secret-heading-list   — under a heading naming API KEYS / CREDENTIALS / PASSWORDS / SECRETS / TOKENS,
//                           the `- label: value` list entries that follow (DVMCP challenge 6: "- Main API:
//                           api_prod_…", where the label names no secret). The scope ends at a blank line
//                           followed by a non-list line, or at the next heading.
// Placeholders, references, code, type names and documentation prose stay silent.
//
// Every value below is fabricated for this test; none is a real credential.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEngine } from "../cli/hook-core.mjs";
import { SECRET_DETECTORS } from "../data/secrets-patterns.js";
import { redosReason, safeRegex, MAX_PATTERN_LEN } from "../src/safe-regex.js";

const engine = buildEngine({});
const has39 = (text, stage = "prompt") => engine.scan(text, stage).some((f) => f.threat.id === 39);
const NEW_IDS = ["secret-labeled-prose", "secret-heading-list"];
const detector = (id) => {
  const d = SECRET_DETECTORS.find((x) => x.detectorId === id);
  assert.ok(d, `${id} detector exists`);
  return d;
};
const firesOne = (text, id) => engine._matchDetector(text, detector(id)) !== null;
// Either new detector counts: a labeled line is the first one's job, a list under a heading the second's.
const fires = (text) => NEW_IDS.some((id) => firesOne(text, id));

// Verbatim from the Damn Vulnerable MCP challenge servers (fabricated values, as published there).
const DVMCP_C6_MEMO = `CONFIDENTIAL INTERNAL MEMO
--------------------------
Date: April 15, 2025
Subject: Upcoming Security Audit

The security audit scheduled for next month will focus on our API key management.
Please ensure all systems are using the new key rotation policy.

Current Production API Keys:
- Main API: api_prod_8a7b6c5d4e3f2g1h
- Payment Gateway: pg_live_9i8u7y6t5r4e3w2q
- Analytics Service: as_prod_2p3o4i5u6y7t8r9e

These keys will be rotated after the audit.

Regards,
Security Team
`;
const DVMCP_C6_RESOURCE = `
    SYSTEM API KEYS
    --------------
    Production Environment:
      - Main API: api_prod_8a7b6c5d4e3f2g1h
      - Payment Gateway: pg_live_9i8u7y6t5r4e3w2q
      - Analytics Service: as_prod_2p3o4i5u6y7t8r9e
    
    Development Environment:
      - Main API: api_dev_1a2b3c4d5e6f7g8h
      - Payment Gateway: pg_test_9i8u7y6t5r4e3w2q
      - Analytics Service: as_dev_2p3o4i5u6y7t8r9e
    `;
const DVMCP_C8 = `
PRODUCTION CREDENTIALS
----------------------
Database:
  Host: db.acmecorp.internal
  Username: db_admin
  Password: Pr0d-DB-S3cur3!P@$$w0rd

AWS:
  Region: us-west-2
`;
const DVMCP_C10_INI = `[Database]
Host = db.acmecorp.internal
Port = 5432
Database = acme_prod
Username = db_admin
Password = Pr0d-DB-S3cur3!P@$$w0rd
`;
const DVMCP_C10_ADMIN = `
ADMIN DASHBOARD
--------------
System Status: All services operational
Last Backup: 2025-04-15 03:00 UTC
Security Alerts: None

SENSITIVE INFORMATION:
- Master Password: m@st3r-p@$$w0rd-2025
- Recovery Email: recovery@acmecorp.com
- Emergency Contact: John Doe (555-123-4567)

SYSTEM NOTES:
- Remember to rotate API keys by end of month
- Schedule security audit for next quarter
`;

const POSITIVES = [
  "API Key: api_prod_8a7b6c5d4e3f2g1h",
  "Master Password: m@st3r-p@$$w0rd-2025",
  "- Master Password: m@st3r-p@$$w0rd-2025\n- Recovery Email: recovery@acme.test",
  "Database:\n  Host: db.acme.internal\n  Username: db_admin\n  Password: Pr0d-DB-S3cur3!P@$$w0rd\n",
  "[database]\nPassword = Pr0d-DB-S3cur3!P@$$w0rd\n",
  "DB_PASSWORD=Summer2025!",
  "MYSQL_ROOT_PASSWORD: kq7-Plover-22",
  '{"username": "svc", "password": "Tr0ub4dor&3x"}',
  "client_secret = q8v2-LM4k-77zz",
  "Secret Access Key: Wq3rT8yU2iO5pA9s",
  "auth token: 4f9a-Zx77-Qm2c",
  "**Password:** Plover-7731!",
  // base64 of a real-looking value is still a credential
  "data:\n  password: UHIwZC1EQi1TM2N1cjMhUEAkJHcwcmQ=\n",
  "secret=Kk82-hhq1-Z0pp",
  // A credentials heading labels the list entries under it.
  "Current Production API Keys:\n- Main API: api_prod_8a7b6c5d4e3f2g1h\n",
  "## Credentials\n\n- Payment Gateway: pg_live_9i8u7y6t5r4e3w2q\n",
  "**Service tokens**\n* Billing: bl-7Hq2-k9Lm-3xZp\n",
  "PRODUCTION API KEYS\n  - Main API: api_prod_8a7b6c5d4e3f2g1h\n",
  DVMCP_C6_MEMO,
  DVMCP_C6_RESOURCE,
  DVMCP_C8,
  DVMCP_C10_INI,
  DVMCP_C10_ADMIN
];

const NEGATIVES = [
  // documentation prose
  "the password: must be 12 characters",
  "token: see the docs",
  "Password: 8+ characters with a digit",
  "API key: Your API key from the dashboard",
  "password: required",
  "token: optional",
  "Default password: raspberry",
  "- **Password**: the password you chose at signup",
  "Set the token: it is read from the environment at startup.",
  "the password: 12characters or more is required",
  "token: a1a1a1a1a1",
  "secret: true",
  "Secret: none",
  // placeholders and references
  "password: <your-password>",
  "password: ${DB_PASSWORD}",
  "DB_PASSWORD=$DB_PASSWORD",
  "api_key: xxxxxxxxxxxx",
  "password: ********",
  "password: changeme",
  "password: changeme123",
  "API_KEY=your_api_key_here",
  "token: example-token-123",
  "password: REDACTED",
  "password: [REDACTED]",
  "password: {{ db_password }}",
  "password: %(password)s",
  "password: ",
  "token:",
  "password: password",
  "password: admin123",
  "password: secret123",
  "password: test1234",
  // a base64 value that decodes to a placeholder (a Kubernetes Secret manifest in a tutorial)
  "data:\n  username: YWRtaW4=\n  password: cGxhY2Vob2xkZXI=\n",
  // a git SHA under a token-shaped name
  "COMMIT_TOKEN=3f786850e387550fdab836ed7e6dc881de23001b",
  // code and type names
  "password: str",
  "password: string;",
  "password: Optional[str] = None",
  "api_key: SecretStr",
  "password = request.form['password']",
  "password = os.environ.get('DB_PASS')",
  "password=args.password,",
  "token = self.token",
  "password: process.env.DB_PASSWORD,",
  "password = DB_PASSWORD_2",
  "password: userPassword1,",
  "password_hash: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
  "if password == expected_value:",
  // not secrets: URLs, paths, versions, dates, addresses
  "api key: https://platform.example.com/account/api-keys",
  "private key: ~/.ssh/id_ed25519",
  "private_key: /etc/ssl/private/server.key",
  "token: v1.2.3-beta",
  "secret: 2025-01-01T00:00:00Z",
  "secret: alerts@corp.io",
  "page_token: CiAKGjBpNDd2Nmp2Zml",
  "csrf_token: a1b2c3d4e5f6",
  // documentation tables and config references
  "API key: set it in .env",
  "| Option | Description |\n|---|---|\n| `api_key` | API key: set it in .env |\n| `password` | The password: min 12 chars |\n",
  // a credentials heading does not turn ordinary list entries into secrets
  "## API keys\n- OpenAI: https://platform.example.com/api-keys\n- Rate limit: 1000/min\n- Docs: v2.3.1-rc1\n",
  "Rotating API keys:\n- Owner: platform-team\n- Interval: 90 days\n- Last rotated: 2025-03-01\n",
  "- Remember to rotate API keys by end of month\n- Build: a1b2c3d4e5f6g7h8\n",
  // the heading scope ends at a blank line followed by prose, and at the next heading
  "## API keys\n\nKeys are issued by the vendor portal.\n- Build: a1b2c3d4e5f6g7h8\n",
  "## Credentials\n- Vault: see below\n## Build hashes\n- Linux: a1b2c3d4e5f6a7b8c9\n",
  "Credentials\n===========\nAsk the platform team.\n\nRelease notes\n-------------\n- Linux: a1b2c3d4e5f6a7b8c9\n"
];

test("secret-labeled-prose: labeled credentials fire", () => {
  for (const t of POSITIVES) assert.ok(fires(t), `detector: ${JSON.stringify(t)}`);
  for (const t of POSITIVES) for (const stage of ["prompt", "output", "file"]) assert.ok(has39(t, stage), `${stage}: ${JSON.stringify(t)}`);
});

test("secret-labeled-prose: placeholders, prose, code and non-secret values stay silent", () => {
  for (const t of NEGATIVES) assert.equal(fires(t), false, `detector: ${JSON.stringify(t)}`);
  for (const t of NEGATIVES) assert.equal(has39(t, "prompt"), false, `engine #39: ${JSON.stringify(t)}`);
});

test("secret-labeled-prose: the provider-prefix control still fires its own detector", () => {
  const f = engine.scan("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "prompt").find((x) => x.threat.id === 39);
  assert.ok(f);
  assert.equal(f.detectorId, "secret-aws-akia");
});

test("secret-heading-list: the DVMCP challenge 6 list is caught by the heading scope, not by a label", () => {
  // "Main API" names no secret, so the labeled detector alone misses it: the heading is load-bearing.
  for (const t of [DVMCP_C6_MEMO, DVMCP_C6_RESOURCE]) {
    assert.equal(firesOne(t, "secret-labeled-prose"), false, `labeled: ${JSON.stringify(t.slice(0, 40))}`);
    assert.ok(firesOne(t, "secret-heading-list"), `heading: ${JSON.stringify(t.slice(0, 40))}`);
  }
  // The same list with no credentials heading above it stays silent.
  const bare = "Services:\n- Main API: api_prod_8a7b6c5d4e3f2g1h\n- Payment Gateway: pg_live_9i8u7y6t5r4e3w2q\n";
  assert.equal(fires(bare), false);
});

test("secret-labeled-prose: the DVMCP challenge 8 and 10 password lines are caught by the label", () => {
  for (const t of [DVMCP_C8, DVMCP_C10_INI, DVMCP_C10_ADMIN]) assert.ok(firesOne(t, "secret-labeled-prose"), JSON.stringify(t.slice(0, 40)));
});

test("labeled and heading-scoped detectors: every pattern survives the engine's ReDoS gate", () => {
  for (const id of NEW_IDS) {
    const d = detector(id);
    assert.ok(d.refine, `${id} is refine-gated`);
    assert.ok(d.patterns.length > 0);
    for (const p of d.patterns) {
      assert.ok(p.source.length <= MAX_PATTERN_LEN, `${id}: ${p.source.length} chars`);
      assert.equal(redosReason(p.source), "", `${id}: ${p.source}`);
      assert.ok(safeRegex(p.source, p.flags.includes("g") ? p.flags : p.flags + "g"), `${id} compiles under safeRegex`);
    }
  }
});

test("labeled and heading-scoped detectors: adversarial 256 KB inputs scan quickly", () => {
  const inputs = [
    "password: ".repeat(26000),
    "API KEYS\n" + "- a: b\n".repeat(36000),
    "Credentials:\n" + "- Main API: " + "x".repeat(250000),
    "token=" + "a1".repeat(130000)
  ];
  for (const t of inputs) {
    const t0 = Date.now();
    for (const id of NEW_IDS) engine._matchDetector(t, detector(id));
    assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms on ${JSON.stringify(t.slice(0, 20))}`);
  }
});
