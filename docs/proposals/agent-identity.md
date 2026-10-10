# Agent identity in MoorAI: design proposal

Status: proposal, nothing here is built. Baseline: agent v1.10.0 (`9fb0116`), console v0.80.0
(`89aa9b3`, `gitayg/curaiq-server`). Written 2026-10-09.

Line numbers below are from those commits (`git show HEAD:<file>`). The working tree is being edited,
so the numbers in a checkout may have moved.

## 1. Summary

On the identity / access / governance / runtime / accountability map, MoorAI is strongest at runtime
(per-call verdicts) and accountability (content-free alerts, the record chain). It is weakest at
identity and access. Today an alert says **which user or workload** (`actor`), **which container**
(`workload`, server mode only) and **which session** (`session`). It does not say **which agent**: no
product, no version, no instance, and nothing about delegation lineage leaves the device.

The proposal has three phases:

1. **Phase 1, on-device and content-free.** Each alert carries an `agentIdentity` record: agent
   kind, agent version, a keyed instance id, the keyed id of the parent agent, the root, the depth,
   and the delegation chain as keyed hashes. Each value also says where it came from and how much it
   can be trusted. Every value is read from fields the host already passes to its hook (shown per host
   in §5.3). Where the host gives no parent link, the record says the link was inferred or is unknown.
   It never makes one up.
2. **Phase 2, console.** An agent registry built the same way as the MCP approval registry: first
   seen, then pending, approved, denied or revoked. Per-agent policy rides in the signed policy, and a
   lineage view shows each session's delegation tree. On a laptop, identity may only **narrow** what an
   agent may do, never widen it, because every identity field there is stated by a process the user
   controls.
3. **Phase 3, standards.** In server mode, take a workload credential (a SPIFFE SVID or a WIMSE
   WIMSE Workload Identity Token with a proof token) and check it at the sidecar or the MCP gateway.
   Express delegation as OAuth token-exchange `act` chains under the actor profile. The target is
   `draft-ietf-wimse-aims-00`; §3.10 lists what the standards changed in this design.

The honest limit: on a developer laptop, MoorAI can **record** agent identity accurately for a host
that tells the truth. It cannot **prove** agent identity, because the hook, the agent and the install
token all belong to the same OS user. Only server mode with a separate sidecar and platform
attestation (Phase 3) gives an identity the agent cannot forge.

## 2. What exists today

### 2.1 Identity fields on alerts

| Field | Identifies | Computed | Where |
|---|---|---|---|
| `actor` | user@host on a laptop; `service@svc:<serviceId>` in server mode | `contentHash("user@host")` keyed from the install token | `cli/content-hash.mjs:116` (`actorHash`), `:71` (`deriveKey`); hook `cli/moorai-hook.mjs:447-448`; server mode `cli/server-mode.mjs:304` (`serviceWho`) |
| `user`, `device` | same pair, in clear on the wire | console replaces both with keyed pseudonyms on ingest | console `server/pseudonym.js:118` (`pseudonymiseEvent`) |
| `workload` | container id, pod / namespace / node, agent pid | `/proc/self/cgroup`, mountinfo, downward-API env | `cli/server-mode.mjs:390` (`workloadIdentity`); stamped in `post()`, `cli/moorai-hook.mjs:597-598`; server mode only |
| `session` | one host session | keyed hash of the host's raw session id, no label, so every surface gets the same value | hook `cli/moorai-hook.mjs:463`, `:1904`, stamped in `post()` `:599`; SDK `packages/agent-sdk/src/runtime.mjs:72`; gateway `mcp-gateway/report.mjs` (`Mcp-Session-Id`) |
| `surface` | which MoorAI surface sent it | literal | SDK runtime `packages/agent-sdk/src/runtime.mjs:74` (`agent-sdk`, `serve`, `model-proxy`, `inference-hook`) |

On the console, `server/siem-fields.js:15-27` (`AGENT_NAMES`, `agentNameOf`) fills an `agent_name`
column from `agentName`, `surface` or `agent`, using only the values `claude-code`, `codex`, `cursor`,
`gemini`, `copilot`, `agent-sdk`, `serve` and `gateway` (insert at `server/db.js:1058`).

**Gap 1: the hook never sends an agent kind.** The hook's `IDENTITY` (`cli/moorai-hook.mjs:448`) is
`{user, device, platform, tenant, actor}`, with no `agentName` and no `surface`. So the console's
`agent_name` is null for every alert from the Claude Code hook and from the Codex, Cursor, Gemini and
Copilot adapters. A Cursor alert looks the same as a Claude Code alert. The hook does know the host:
`cli/moorai-agent-hook.mjs:34` sets `MOORAI_HOOK_AGENT` to the adapter id. But only `beatHost()`
(`cli/moorai-hook.mjs:965-967`) reads it, for the daily posture heartbeat.

**Gap 2: version never rides on an alert.** `cli/agent-hooks/host-version.mjs` finds each host's
version from the environment (`AI_AGENT` for Claude Code, `CURSOR_VERSION` for Cursor, `:61-70`), from
the install path, or from `--version`. Its header says it is "never called on the hook's verdict
path", and the only thing that uses it is the daily posture beat.

### 2.2 Sub-agent handling

- **Spawn.** `cli/moorai-hook.mjs:2333-2350`. A `Task` or `Agent` PreToolUse posts threat #66
  "Sub-agent / A2A delegation" with `subagentType` **in clear** (`:2337`). It scans the delegated
  prompt and applies the entitlement envelope. It also logs a local handoff edge
  `{role:"handoff", parent: SESSION, to: contentHash(subagent_type)}` (`:2340`).
- **Child attribution.** `cli/moorai-hook.mjs:467-477` and `:1909-1914`. When the payload carries
  `agent_id` or `agent_type`, `ACTOR = contentHash(agent_type || agent_id)` and
  `SUBAGENT_LINEAGE = {parent: SESSION, role: "subagent"}`. Three limits follow:
  - The key is **`agent_type`, not `agent_id`**. That was deliberate, so the actor joins the handoff
    edge (which only knows the type) and gets enough events to learn a baseline. The cost is that two
    parallel `Explore` sub-agents in one session become one actor.
  - `parent` is always the **root session**, even for a nested sub-agent.
  - `ACTOR` and `SUBAGENT_LINEAGE` go only to the local `agent-events.jsonl`
    (`recordAgentEvent`, `cli/moorai-hook.mjs:668`, `cli/signals.mjs:149`) and into the nested `drift`
    object of the learned-drift alert (`:1253`). **`post()` adds only `workload` and `session`**
    (`:597-600`), so the console never receives lineage on ordinary alerts.
- **Ledger row.** `cli/moorai-hook.mjs:577` stores `a: localHash(agent_id)`, keyed with a
  device-local key and never sent.
- **"The parent's envelope applies to the child."** `reportEnvelope` (`cli/moorai-hook.mjs:1338-1341`)
  decides with `actor: IDENTITY.actor`, the user or workload. So the envelope is the
  **device's envelope**, applied the same way to the main agent and every sub-agent. No envelope
  belongs to one agent, and no envelope narrows for a child. JIT elevations match the same actor hash.
- **Adapters.** Each adapter turns its host's spawn into a Claude-shaped `Task`, keeping only the type
  name and the prompt:
  - Codex `spawn_agent` → `subagent_type: agent_type || task_name` (`cli/agent-hooks/codex.mjs:89-90`).
  - Cursor `subagentStart` → `subagent_type`, `task` (`cli/agent-hooks/cursor.mjs:92-93`).
  - Gemini `invoke_agent` → `agent_name` (`cli/agent-hooks/gemini.mjs:65`).
  - Copilot `task` → `agent_type` (`cli/agent-hooks/copilot.mjs:120`).
  - Each maps only the host's session key: Codex `session_id` (`codex.mjs:107`), Cursor
    `conversation_id` (`cursor.mjs:64`), Gemini `session_id` (`gemini.mjs:79`), Copilot `sessionId`
    (`copilot.mjs:148`).
  - The shim tags the child process with `MOORAI_HOOK_HOST=shim` only (`cli/agent-hooks/shim.mjs:15-20`).

  Any sub-agent id or parent id the host sends is dropped (§5.3).

### 2.3 Console patterns to reuse

- **MCP approval registry** (console `server/db.js:1720-1796`). One settings key per tenant
  (`mcpRegistry:<tenant>`), each entry keyed `scope:server`, with `state: pending|approved|denied`,
  `firstSeen`, `lastSeen`, `count`, `decidedAt`.
  - `recordMcpSeen` (`:1734`) creates the entry from alert ingest.
  - A changed `configHash` on an approved entry sets `drift` and moves it back to `pending` (the
    rug-pull rule).
  - `setMcpState` (`:1759`) is the admin transition; the route is `server/server.js:1215`, and each
    change writes a governance-log entry `mcp.state`.
  - `approvedMcpServers` (`:1793`) feeds `resolvePolicy` (`:693`): with `mcpGate` on, the approved set
    *is* the signed `mcpAllow`.
  - Tool reports from new reporters are rate-limited per tenant, because "any holder of the token can
    claim fresh ids" (`server/server.js` `/api/mcp/tools`).
- **Actor scope** (`server/db.js:1802-1804`, route `server/server.js:1263`). A managed or unmanaged
  label on an actor hash. New actors start unmanaged.
- **Workload profiles** (`cli/workload-profile.mjs`, CONTRACT C3). A declared baseline per
  `match.serviceId` or `match.repo`, carried in the signed policy or the root-owned system file. Its
  header already notes that `repo` "is a convenience scope, not an identity".

### 2.4 What the hash key means

The keyed hashes use a key derived from the **install token** (`cli/content-hash.mjs:65-72`).

- Install tokens are per *installation*, stored as one row each in the console's `installations`
  table (`server/db.js:142-148`), and are "shareable bearer links the admin re-copies"
  (`server/db.js:24-27`).
- So keyed ids correlate only between devices that share one installation token.
- Any holder of that token can post an alert carrying any `actor`, `session` or (proposed) agent id.
- On a laptop the token is in `~/.moorai/config.json`, which the user, and so the agent, can read.

### 2.5 What the gateway already sees

- **Authorization.** The MCP gateway passes the client's `Authorization` header upstream. It keeps a
  sha256 of it, only as a cool-down key (`mcp-gateway/server.mjs:126`, `mcp-gateway/cooldown.mjs:1-10`).
- **clientInfo.** It validates `initialize.params.clientInfo.{name,version}`
  (`mcp-gateway/validate.mjs:157-159`) but does not record it.

Both are natural places for Phase 3 checks.

## 3. Standards

Unless marked otherwise, each source below was fetched and read by the standards research for this
document on 2026-10-09. The two load-bearing IETF drafts (§3.2 and §3.1) were checked again against
datatracker afterwards. Datatracker URLs use the draft's canonical path, which always shows the
latest revision.

**Read across all of them, they agree on the same points:**

- an agent is a principal of its own, distinct from the user it acts for;
- delegation, not impersonation: user as `sub`, agent as actor;
- one stable identifier per agent, bound to a short-lived proof-of-possession credential;
- scope narrows at every delegation hop;
- revocation by signal (SSF / CAEP);
- tamper-evident audit logs that name the agent.

All of the specifications are drafts or proposals. None is final.

### 3.1 OpenID and OAuth agent identity

- **OpenID Foundation whitepaper, "Identity Management for Agentic AI".** AI Identity Management
  (AIIM) Community Group, October 2025. arXiv:2510.25819 (https://arxiv.org/abs/2510.25819); PDF at
  https://openid.net/wp-content/uploads/2025/10/Identity-Management-for-Agentic-AI.pdf. **A
  whitepaper, not a specification. The AIIM group writes no specs.**
  - Agents are first-class IAM entities. Use delegation, not impersonation: the token carries the user
    as `sub` and the agent as `act` or `azp`.
  - Recursive delegation must narrow scope at each hop: RFC 8693 token exchange when online,
    Biscuits or Macaroons when offline.
  - Credentials should carry both the principal's id and the agent instance's id, for audit.
  - Lifecycle through SCIM, with an experimental `AgenticIdentity` resource.
  - Revocation across a delegation chain is called "largely unsolved". Candidates: Shared Signals
    Framework (SSF), OpenID Provider Commands, IPSIE.
  - Four models: Enhanced Service Account (SPIFFE plus `agent_model` / `agent_provider` /
    `agent_version`), Delegated User Sub-Identity, Federated Trust, Sovereign DIDs.
- **OIDC-A 1.0** ("OpenID Connect for Agents"). arXiv:2509.25974 (https://arxiv.org/abs/2509.25974).
  **An individual proposal, not an OpenID Foundation document.**
  - Claims: `agent_type`, `agent_model`, `agent_version`, `agent_provider`, `agent_instance_id`,
    `delegator_sub`, `delegation_chain`, `delegation_purpose`, `delegation_constraints`,
    `agent_capabilities`, `agent_trust_level`, `agent_context_id`, `agent_attestation`.
- **`draft-sharif-openid-agent-identity-01`**, "OpenID Connect Agent Identity Claims for Autonomous AI
  Agents". **An individual IETF Internet-Draft, not an OpenID Foundation specification**; it says it
  is "not endorsed by the IETF". https://datatracker.ietf.org/doc/draft-sharif-openid-agent-identity/
  - Dates conflict: the header says 2026-08-26, datatracker says last updated 2026-08-27, and
    Appendix B dates revision 01 to March 2026.
  - Claims (Table 1):
    - Required: `agent_id` (stable) and `agent_owner`.
    - Optional: `agent_name`, `agent_trust_score`, `agent_trust_level` (L0 to L4),
      `agent_capabilities`, `agent_sanctions_status`, `agent_spend_limit`,
      `agent_attestation_method`, `agent_created_at`.
  - Relying parties authorize on `agent_id`.
  - **No delegation-chain claim.** The only link to a controlling party is the single
    `agent_owner`.
- **RFC 8693, OAuth 2.0 Token Exchange** (January 2020). https://www.rfc-editor.org/rfc/rfc8693
  - Distinguishes delegation from impersonation (§1.1).
  - `actor_token` and `may_act`.
  - Nested `act` claims form a chain; the outermost `act` is the current actor.
- **`draft-mcguinness-oauth-actor-profile-01`** (individual, 2026-10-09).
  https://datatracker.ietf.org/doc/draft-mcguinness-oauth-actor-profile/
  - Every `act` carries `iss`, and `(act.iss, act.sub)` is the canonical actor.
  - Optional `sub_profile: ai_agent`.
  - A maximum chain depth, and **no silent truncation**.
- **`draft-oauth-ai-agents-on-behalf-of-user-02`** (individual, **expired**): `requested_actor` and
  `actor_token` in the authorization request.

### 3.2 IETF WIMSE: agents as workloads

- **`draft-ietf-wimse-aims-00`**, "AI Identity Management System". WIMSE working group, 2026-09-15.
  It replaces `draft-klrc-aiagent-auth`. https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/
  Its normative points:
  - **Identifiers (§6).** Agents MUST be uniquely identified. Each agent MUST have exactly one WIMSE
    identifier, which MAY be a SPIFFE ID.
  - **Credentials (§7).** Agents MUST hold credentials that cryptographically bind them to that
    identifier; "an identifier alone is insufficient". Credentials SHOULD be short-lived and MUST
    expire. Static API keys are called an antipattern.
  - **§8.** "The LLM MUST NOT have access to an agent's credentials", or to the credentials it needs
    for tools.
  - **Delegation.** OAuth with the agent as `client_id` and the user as `sub`, minimum scopes, and
    Transaction Tokens.
    - Interactive confirmation MUST be bound to a verifiable authorization grant (CIBA).
    - Agents MUST NOT treat local UI confirmation alone as sufficient authorization.
  - **Revocation (§11).** Through SSF, CAEP and RISC. Cached decisions and tokens MUST NOT be used
    after revocation.
  - **Audit (§11).** Logs MUST be durable and tamper-evident. Minimum fields:
    - the authenticated agent identifier;
    - the delegated subject;
    - the resource or tool;
    - the action and the decision;
    - a timestamp and a correlation id;
    - the posture or risk state;
    - remediation and revocation events.
- **`draft-ietf-wimse-arch-08`** (2026-07-06), the architecture.
  https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/
- **`draft-ietf-wimse-workload-creds-02`** (2026-07-02).
  https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/
  - The Workload Identity Token (WIT) is a JWT with `typ` `wit+jwt` and a `cnf.jwk`.
  - Proof of possession is required.
  - It is sent in the `Workload-Identity-Token` header.
- **`draft-ietf-wimse-wpt-02`** (2026-08-27), the Workload Proof Token. It carries hashes binding it to
  the WIT (`wth`), to an access token (`tth`) and to other tokens (`oth`).
  https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/

### 3.3 SPIFFE / SPIRE

https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/

- **SPIFFE ID:** `spiffe://<trust-domain>/<path>`.
- **SVIDs:** X.509-SVID, JWT-SVID and WIT-SVID.
- **Attestation:** SPIRE issues SVIDs after node attestation and workload attestation, using selectors
  such as unix (uid, path), k8s (namespace, service account, pod labels) and docker.
- **Federation:** crossing trust domains needs explicit bundle exchange; it does not happen by itself.
- **Relevance:** AIMS lets the one WIMSE identifier be a SPIFFE ID, so SPIRE is the obvious issuer in
  server mode. The attestation selectors are facts the agent process cannot change.

### 3.4 NIST

- **AI Agent Standards Initiative.** NIST Center for AI Standards and Innovation (CAISI), announced
  2026-02-17. It has three pillars and no technical requirements. URL not recorded in the research
  hand-off.
- **NCCoE concept paper, "Accelerating the Adoption of Software and AI Agent Identity and
  Authorization"** (draft, February 2026), and its comment summary (2026-09-29, more than 600
  commenters). The comments converge on:
  - a stable identity anchor plus short-lived proof-of-possession credentials;
  - SSF / CAEP revocation;
  - scope narrowed per hop;
  - tamper-evident logs.
- **The first implementation use case is a DevSecOps / software-development agent**, which is
  MoorAI's market (§3.10).
- URLs for both were not recorded in the research hand-off.

### 3.5 CSA Agentic Trust Framework

- **Agentic Trust Framework (ATF) 0.9.1**, Public Review Draft, April 2026.
  https://github.com/massivescale-ai/agentic-trust-framework. Stewardship moving to the Cloud
  Security Alliance was announced as an agreement.
- **Identity requirements I-1 to I-5:**
  - I-1 Unique Identifier;
  - I-2 Credential Binding;
  - I-3 Ownership Chain;
  - I-4 Purpose Declaration;
  - I-5 Capability Manifest.
- "Every agent MUST have a unique, verifiable identity". IDs are per instance and bound to the
  agent's version and configuration.

### 3.6 ASD's ACSC, CISA and partners: "Careful Adoption of Agentic AI Services"

- **Published** 2026-05-01. ASD's ACSC led, with CISA, NSA, the Canadian Centre for Cyber Security,
  NCSC-NZ and NCSC-UK. It is not officially branded "Five Eyes".
  HTML: https://www.cyber.gc.ca/en/guidance/careful-adoption-agentic-ai
- **Identity recommendations:**
  - each agent is a distinct principal with its own cryptographic identity, using mTLS;
  - a **trusted agent registry, reconciled against the agents actually running, that denies
    unregistered agents and keys**;
  - delegation only with expiry and recorded grant chains;
  - just-in-time credentials;
  - unified audit logs that agents cannot write to;
  - human approval for high-impact actions.

### 3.7 Host hook references (fields used in §5.3)

| Host | Reference |
|---|---|
| Claude Code | https://code.claude.com/docs/en/hooks |
| Codex CLI | https://developers.openai.com/codex/hooks |
| Cursor | https://cursor.com/docs/hooks.md |
| Gemini CLI | The Gemini CLI hooks reference. The research hand-off gives its field list but not its URL; MoorAI's adapter header cites the 0.60.0 source. |
| GitHub Copilot | https://docs.github.com/en/copilot/reference/hooks-configuration |

### 3.8 OpenTelemetry GenAI semantic conventions

- Defines `gen_ai.agent.id`, `gen_ai.agent.name`, `gen_ai.agent.version`, `gen_ai.conversation.id`
  and `gen_ai.main_agent.*`, at **Development** stability.
- The conventions moved to the `semantic-conventions-genai` repository.
- **There is no parent-agent attribute.**
- https://opentelemetry.io/docs/specs/semconv/gen-ai/

### 3.9 SAF-MCP

- OpenSSF SIG, "Framework Model v2". https://github.com/secure-agentic-framework/saf-mcp
- **It has no technique for agent identity spoofing.** Nothing in it changes this design.
- The README does not support the claim that it was renamed from SAFE-MCP, so this document does not
  repeat it.

### 3.10 What the standards change in this design

Each change below is also marked "(standards change)" where it lands in §5 to §9.

1. **Phase 1: names.** Wire names stay MoorAI's camelCase, like every other alert field, but each
   field maps to OTel GenAI and OIDC-A (new mapping table in §5.1). The OTel mirror emits the
   `gen_ai.*` names. OTel has no parent attribute, so parent, depth and chain go out as
   `moorai.agent.*` attributes.
2. **Phase 1: the AIMS audit minimum.** AIMS §11's minimum audit record needs an agent identifier,
   which MoorAI alerts do not have today. Phase 1 adds one, but as a *stated* id, not the
   *authenticated* id AIMS asks for (§8.3). Today's alerts already carry the other fields: delegated
   subject (`actor`), tool, decision, timestamp, correlation id (`session`), risk.
3. **Phase 1: chain truncation.** The actor profile forbids silent truncation, so `chainTruncated`
   stays explicit. Phase 3 refuses an over-depth chain instead of trimming it.
4. **Phase 2: the registry's job.** The ACSC/CISA "trusted agent registry, reconciled against live
   agents, deny unregistered" is exactly the Phase 2 registry with `agentGate`. ATF I-1, I-3, I-4 and
   I-5 map onto instance id, owner (`actor`), and per-type purpose and capability manifest. So Phase 2
   adds two optional fields per type, `purpose` and a capability manifest (the per-type workload
   profile).
5. **Phase 2: revocation.** All the sources point to SSF / CAEP for revocation. Phase 2's revoke
   should also emit a CAEP event, so an IdP can revoke the agent's tokens. That is a new item.
6. **Phase 3: the target.** Target AIMS: one WIMSE id per agent (a SPIFFE ID), a WIT plus a WPT for
   proof of possession, and `act` chains per the actor profile (`iss` on each hop, a maximum depth).
   OIDC-A's and the sharif draft's agent claims are mapped, not adopted wholesale, because no single
   claim set has won.
7. **Threat model.** AIMS §8 ("the LLM MUST NOT have access to an agent's credentials") is not met on
   a laptop today: the agent can read the install token (§2.4). The placeholder-credentials feature
   in the model proxy and the MCP gateway (README "Placeholder credentials") already follows that
   rule for upstream API keys. The device-key idea in §7 point 4 is how MoorAI's own token could
   follow it too.
8. **Open question: "ask".** AIMS says local UI confirmation alone is not sufficient authorization.
   MoorAI's "ask" / justify verdict is exactly a local confirmation. This is a new open question
   (§9, Q8), not a design change.
9. **Opportunity: NCCoE.** The NCCoE's first implementation use case is a software-development
   agent. MoorAI could take part as a collaborator or reference implementation for the content-free
   audit and lineage layer. That is a business decision, recorded here only as a pointer.

## 4. Design principles

1. **Content-free, as now.** Ids are keyed hashes. A product name and version may travel in clear:
   the posture beat already sends both. No prompt, task description, agent definition text,
   transcript path or e-mail leaves the device. Cursor puts `user_email` on every hook payload, so the
   adapter must drop it.
2. **State the source, never guess.** Every value carries how it was obtained. A missing parent link
   is reported as `none` or `inferred`, never filled in. This follows the console's rule for
   `agent_name`: "never guessed from a tool name" (`server/siem-fields.js:13-14`).
3. **Identity narrows, never widens, unless it is attested.** This is the same one-way rule that server
   mode applies to environment variables (`cli/server-mode.mjs:39-46`). A self-stated identity may move
   an agent to *less* privilege (deny an unapproved type, apply a stricter profile). It may never grant
   more than the device or workload envelope. Only an identity checked against a credential the agent
   cannot mint (Phase 3) may widen.
4. **Reuse what exists.** Reuse the `session` value as the root instance id, the console's
   `agent_name` column for the kind, the MCP-registry state machine, and `workloadProfiles` for
   per-agent policy.

## 5. Phase 1: an agent identity record on every alert

### 5.1 Shape

```json
"agentName": "cursor",
"agentIdentity": {
  "v": 1,
  "kind": "cursor",
  "version": "2026.05.27-fe9a6e2",
  "versionSource": "payload",
  "role": "subagent",
  "instance": "h2:3f0c9a1d5e7b2468",
  "type": "h2:9b1e44c0a2d37f15",
  "root": "h2:a1b2c3d4e5f60718",
  "parent": "h2:a1b2c3d4e5f60718",
  "parentBinding": "exact",
  "depth": 1,
  "chain": ["h2:a1b2c3d4e5f60718"],
  "source": "host-payload"
}
```

| Field | Meaning | Value |
|---|---|---|
| `agentName` | The existing console field. Fills `agent_name` with **no console change**. | Same vocabulary as `AGENT_NAMES` |
| `kind` | Agent product | `claude-code`, `codex`, `cursor`, `gemini`, `copilot`, `agent-sdk`; `unknown` otherwise |
| `version` | Host version | `cleanVersion()` from `host-version.mjs` (digits and dots, short suffix, ≤ 40 chars); omitted when unknown |
| `versionSource` | Where the version came from | `payload`, `env`, `probe-cached` |
| `role` | Main agent or sub-agent | `main`, `subagent`; omitted when the host cannot tell (Codex, Gemini and Copilot tool calls, §5.3) |
| `instance` | This running agent | Main: equals `session` (the existing value, so session metrics still join). Sub-agent: `contentHash("agent-instance/v1|" + kind + "|" + session_id + "|" + subagent_id)` |
| `type` | Sub-agent type, or the `--agent` name | `contentHash("agent-type/v1|" + kind + "|" + type)`; built-in names may go in clear (§9, Q1) |
| `root` | Top-level agent of this tree | `session` |
| `parent` | Spawning agent's `instance` | Omitted for `role:"main"` |
| `parentBinding` | How sure the link is | `exact` (the host names the parent), `inferred` (one pending spawn matched, §5.4), `root-only` (the host shows the child belongs to the session, not which agent spawned it), `none` |
| `depth` | Root is 0 | Exact only when every link up the chain is `exact` or `inferred`; otherwise omitted |
| `chain` | Ancestor instances, root → parent | At most 8 keyed hashes; `chainTruncated: true` past that |
| `source` | Trust class of the whole record | `host-payload` (stated by the host process), `caller-claimed` (a body field on `moorai-serve`, `clientInfo` at the gateway), later `attested` (Phase 3) |

**Mapping to the standards (standards change, §3.10 item 1).** The wire names above stay as they are.
Each field maps to these names:

| MoorAI field | OTel GenAI (Development) | OIDC-A 1.0 claim | sharif-01 claim | Note |
|---|---|---|---|---|
| `kind` | `gen_ai.agent.name` | `agent_type` / `agent_provider` | `agent_name` | |
| `version` | `gen_ai.agent.version` | `agent_version` | none | |
| `instance` | `gen_ai.agent.id` | `agent_instance_id` | `agent_id` is *stable*, not per instance | |
| `root` / `session` | `gen_ai.conversation.id` | `agent_context_id` | none | |
| `parent`, `depth`, `chain` | none (OTel has no parent attribute) → `moorai.agent.parent` etc. | `delegation_chain` | none | RFC 8693 / actor profile: nested `act` |
| `actor` (existing) | none | `delegator_sub` | `agent_owner` | ATF I-3 ownership chain |
| `source:"attested"` (Phase 3) | none | `agent_attestation` | `agent_attestation_method` | |

The two drafts' "agent id" differ. sharif-01's `agent_id` is a stable identity for an agent, closer
to the Phase 2 registry key (kind plus type). OIDC-A's `agent_instance_id` is MoorAI's `instance`.
ATF asks for ids that are per instance *and* bound to version and configuration. MoorAI gets that
from `instance` together with `version` and the definition fingerprint (§6.1).

- When the device is unenrolled (`NO_KEY`), `instance`, `type`, `root`, `parent` and `chain` are left
  out, as `session` is today. `kind`, `version` and `role` still travel.
- The local rows (`agent-events.jsonl`, the session ledger) keep their device-local keys.

### 5.2 How the hook builds it

- **A new pure module, `cli/agent-identity.mjs`.** It takes the normalised hook input and returns the
  record. Nothing in it does I/O, so it is unit-testable like `cli/workload-profile.mjs`.
- **`cli/moorai-hook.mjs` `main()`.** Next to the `SESSION` assignment (`:1902-1914`), compute
  `AGENT_ID` once per invocation. `post()` (`:597`) stamps `agentName` and `agentIdentity` the same way
  it stamps `workload` and `session` today, so no emit site can forget it.
- **Kind.**
  - An unshimmed hook is `claude-code`, the same test as `beatHost()`.
  - A shimmed hook reads `MOORAI_HOOK_AGENT`, which `cli/moorai-agent-hook.mjs:34` already sets in the
    environment the shim inherits.
  - The Agent SDK uses `surface: "agent-sdk"`.
- **Version.**
  - A payload field when the host sends one (Cursor `cursor_version`).
  - Otherwise `versionFromEnv` (Claude Code `AI_AGENT`, Cursor `CURSOR_VERSION`): no I/O.
  - Otherwise a version file the posture-beat worker writes once a day
    (`<state>/host-version-<host>.json`). That costs one small read on the verdict path. It can be up
    to a day stale, and `versionSource:"probe-cached"` says so.
- **Adapters.** Each adapter passes the host's own identity fields through into the Claude-shaped
  payload under MoorAI-private names (`moorai_agent: {version, subagent_id, parent_id, parent_kind}`),
  so the core hook never has to know host-specific names. Each adapter drops `user_email`.

### 5.3 Where each value comes from, per host

**Sources.**

- **"Docs"** is the host's official hook reference (§3.7), read by the standards research on
  2026-10-09.
- **"Measured"** means read from a shipped binary installed on this machine:
  - Claude Code 2.1.295, the local native build. Its hook input schemas, with their `describe()`
    text, were pulled out with `strings`. MoorAI's tested version is 2.1.284.
  - cursor-agent 2026.05.27-fe9a6e2, MoorAI's tested version. Its payload-building code is in
    `index.js` and `3880.index.js`.
- **"Adapter"** means the citations already in MoorAI's adapter headers.
- Where docs and measurement agree, both are listed.

| | Claude Code | Codex CLI | Cursor | Gemini CLI | Copilot CLI |
|---|---|---|---|---|---|
| **Session key** | `session_id` (docs, measured) | `session_id`. Sub-agents use the **parent's** session id (docs; adapter `codex.mjs:24-25`). | `conversation_id` on all events, copied to `session_id` (docs, measured) | `session_id` (docs) | `sessionId` / `session_id` (docs) |
| **Version** | **None in stdin** (docs). Undocumented `AI_AGENT=claude-code_<v>_harness` in the hook env (measured 2.1.284, `host-version.mjs:61-65`). | None (docs) → probe-cached | `cursor_version` on every payload (docs, measured), plus `CURSOR_VERSION` in env (measured) | None (docs) → probe-cached | None (docs) → probe-cached |
| **Sub-agent id** | `agent_id`, present inside a sub-agent, **including PreToolUse and PostToolUse** (docs). Measured 2.1.295: "Use this field (not agent_type) to distinguish subagent calls". | `agent_id` on **SubagentStart / SubagentStop only** (docs) | `subagent_id` on `subagentStart` / `subagentStop` (docs, measured) | **None** (docs) | `agentId` on **subagentStop only** (docs) |
| **Sub-agent type** | `agent_type`, inside a sub-agent or on the main thread of an `--agent` session (docs, measured) | `spawn_agent` input `agent_type` / `task_name` (adapter) | `subagent_type` (docs, measured) | `invoke_agent` input `agent_name` (adapter) | `task` input `agent_type` (adapter) |
| **Parent id** | **None** (docs). `SubagentStart` has the child's `agent_id` but not the spawner's. A `PostToolUse` on `Agent` carries the caller's `agent_id` (absent = main thread) and `tool_response.agentId`, the child (measured). | **None** (docs) | `parent_conversation_id` + `tool_call_id` on `subagentStart` (docs, measured) | None (docs) | None (docs) |
| **Nesting** | Exists: 2.1.295 has a spawn-depth cap, `CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH` (measured, strings). No depth field. | Not stated | `is_parallel_worker` on spawn (measured); no depth field | Not stated | Not stated |
| **Model** | `model` on `SessionStart` only, optional (docs, measured) | `model` on **all events** (docs) | `model`, `model_id`, and `subagent_model` on spawn (docs, measured) | Only inside `llm_request.model` (docs) | None (docs) |
| **Must drop** | `transcript_path` | `transcript_path` if present | **`user_email` on every payload**, `transcript_path` | | |
| **Agent SDK** | Same hook input as Claude Code. The SDK passes `session_id` today (`packages/agent-sdk/src/index.mjs:60`) and would pass `agent_id` / `agent_type` too. Version = the SDK package's own version, read in process (not verified). | | | | |

**What this means for the record** (the parts that are new from the docs):

- **Codex.** A sub-agent shares its parent's `session_id`, and per the docs `agent_id` appears only
  on SubagentStart and SubagentStop, not on tool calls. So MoorAI **cannot tell a Codex sub-agent's
  tool call from its parent's**. A Codex tool call therefore carries **no `role`**: it might be the
  main agent's or a sub-agent's. It gets `parentBinding:"none"`, and the instance is the session.
  Writing `main` would be a guess, which principle 2 forbids. Codex sub-agents still show up through
  `spawn_agent` (the Task edge) and, if MoorAI registers them, SubagentStart / SubagentStop
  lifecycle events. Whether Codex will add `agent_id` to tool events is a request to make upstream.
- **Gemini CLI.** No sub-agent id anywhere. Same outcome as Codex, without even the lifecycle events.
- **Copilot CLI.** `agentId` only when a sub-agent stops. That allows an after-the-fact "this
  sub-agent existed" event; it does not attribute tool calls.
- **Cursor.** The only host that names the parent at spawn time.
- **Claude Code.** The only host that tags each tool call with the sub-agent. It needs the §5.4
  steps for the parent link.
- **Model** can go on the record for Codex (every event) and Cursor without extra cost. For Claude
  Code it needs a `SessionStart` registration (§9, Q4).

### 5.4 Parent links for Claude Code

The Claude Code payload never names a sub-agent's parent on the child's own calls. With nesting,
"spawned by the main thread" can no longer be assumed. The hook already registers PreToolUse and
PostToolUse for `Agent` and `Task` (`cli/moorai-hook.mjs:82`, `:128`, `:133`). That allows three steps:

1. **PreToolUse(`Agent`) in caller X** (X = `agent_id`, or main): write a pending-spawn row to a
   small state file, keyed by hashes only: `{session, caller: X, typeHash, toolUseIdHash, ts}`.
2. **Child Y's first event** (its first tool call, or `SubagentStart` if MoorAI registers it): if
   exactly one pending spawn in this session has a matching `typeHash`, bind Y → X with
   `parentBinding:"inferred"`.
   - With zero or several candidates, set `root-only`: Y belongs to this session, but which agent
     spawned it is unknown.
   - Parallel spawns of one type are the common case for `root-only`.
3. **PostToolUse(`Agent`) in X**: the response's `agentId` is Y. That gives an exact `X → Y` edge,
   and the hook posts it as a content-free "agent delegation edge" event. The console then marks the
   earlier inferred link exact or wrong.
   - For an async (`run_in_background`) spawn this arrives at launch (`status:"async_launched"`).
   - For a sync spawn it arrives only after the child ends. So the child's own alerts carry the
     inferred or root-only link, and the console fixes them up afterwards.

Registering `SubagentStart` costs one process start per sub-agent. It buys an earlier binding and a
first-seen lifecycle event. `SessionStart` would add `model` and `source` (startup, resume, fork).
Both are optional.

Cursor needs none of this: `subagentStart` names the parent conversation and the tool call. Whether a
Cursor sub-agent's *own* tool events carry its own `conversation_id` (= `subagent_id`?) was not
verified and must be measured.

### 5.5 Other surfaces

- **`moorai-serve`.** Takes optional `agent: {kind, version, instance, parent}` body fields, as it
  takes `session` today, and hashes the raw ids. It stamps `source:"caller-claimed"`.
- **MCP gateway.** Records `initialize.clientInfo.{name, version}` per `Mcp-Session-Id`, sanitised
  like `cleanVersion`, as `source:"caller-claimed"`. The 2026-07-28 transport has no session id, so it
  gets none.
- **Model proxy.** Nothing in Phase 1: a Messages request names no agent.
- **OTel mirror** (`cli/otel.mjs`). Maps to the GenAI semantic-convention agent attributes where they
  exist (§3.8).

### 5.6 Console side of Phase 1

- Add columns to `alerts` through `_migrate`: `agent_version`, `agent_instance`, `agent_type`,
  `agent_root`, `agent_parent`, `agent_parent_binding`, `agent_depth`, `agent_chain` (JSON). Reuse
  `agent_name` for the kind.
- Add a sanitizer, `server/agent-identity.js`:
  - hash-shaped values only (the same rule as `SESSION_RE`, `server/session-key.js:10`);
  - `kind` from the enum, `version` by the agent's `cleanVersion` regex, `depth` an integer from 0 to
    16, `chain` at most 8 entries;
  - anything else is stored as null, never rewritten.
- The keyed ids are not pseudonymised again.
- SIEM: bump `SIEM_SCHEMA_VERSION` to 4 and add the fields to `docs/SIEM_FIELDS.md`.
- Lineage export (`server/lineage-export.js`): add `agentKind`, `agentInstance` and `agentParent` to
  `LINEAGE_FIELDS`, its one choke point.

## 6. Phase 2: the console agent registry

### 6.1 What it registers

Instances are too many and too short-lived to approve. The registry holds **agent kinds** and
**agent types**:

- `kind:<kind>`: the product, e.g. `kind:codex`, with the versions seen and their counts.
- `type:<kind>:<typeHash>`: a sub-agent definition or `--agent` name, e.g. a project's
  `.claude/agents/reviewer.md`.
- Optionally `defn` on a type: a `fileFingerprint` (sha256, unkeyed, as drift uses,
  `cli/content-hash.mjs` `FP_PREFIX`) of the definition file. The hook can find it for project and
  user agents (`.claude/agents/<name>.md`); built-ins have none.

Each entry copies the MCP registry entry: `state`, `firstSeen`, `lastSeen`, `count`, `decidedAt`,
plus `revokedAt`, `revokeReason` and `versions: {<v>: count}`.

**Purpose and capabilities (standards change, §3.10 item 4).** Each entry also gets two optional
fields an admin fills in:

- `purpose`: a short declared purpose (ATF I-4);
- `capabilities`: the id of the per-type workload profile from §6.3, which serves as the capability
  manifest (ATF I-5).

With the instance id (I-1) and the owner (`actor`, I-3), that covers ATF I-1, I-3, I-4 and I-5 as
records. I-2, credential binding, waits for Phase 3.

This registry is the "trusted agent registry, reconciled against live agents, deny unregistered"
that ASD's ACSC, CISA and partners recommend (§3.6). The reconciliation is the registry's
`lastSeen` against live sightings. "Deny unregistered" is `agentGate` (§6.3).

### 6.2 Lifecycle

```
first seen (alert ingest) → pending → approved | denied
approved → revoked              (admin; not the same as denied: it was trusted and no longer is)
approved → pending              (drift: definition fingerprint changed, or a version outside an
                                 approved range, the agent analogue of the MCP rug-pull rule)
any → stale                     (no sightings for N days; display only)
```

- Every transition writes a governance-log entry `agent.state`, as `mcp.state` does.
- Creating entries from ingest is rate-limited per tenant for new reporters, as `/api/mcp/tools` is,
  because any install-token holder can invent types.

### 6.3 Policy

- **`agentGate`**, per policy, like `mcpGate`. When it is on, `resolvePolicy` puts
  `agentAllow: [{kind, versions?, types?: [typeHash]}]` into the signed body.
- The hook then:
  - denies a spawn (PreToolUse `Agent`/`Task`) whose `typeHash` is denied or revoked, or, with the
    gate on, not approved;
  - denies the tool calls of an instance whose type is denied or revoked;
  - uses the session-kill sentinel to end live instances of a revoked type.
- **Revocation latency** is the policy refresh interval. That interval was not measured for this
  document. AIMS §11 says cached decisions MUST NOT be used after revocation, which argues for a push
  channel rather than waiting for the refresh (§9, Q7).
- **Revocation signal out (standards change, §3.10 item 5).** A revoke also emits a Shared Signals /
  CAEP event to a configured receiver, so an IdP that issued the agent tokens can revoke them too.
  This follows AIMS §11, the OIDF whitepaper and the NCCoE comments. It is optional and off unless a
  receiver is configured.
- **Per-agent profiles.** Add `match.agentKind` and `match.agentType` to `workloadProfiles` (a CONTRACT
  C3 change), so an operator can declare that a `reviewer` sub-agent uses only Read and Grep. By §4.3,
  on a laptop a profile matched on agent identity can only **tighten**: the result is the intersection
  with the device envelope.
- **Per-agent envelope.** `decideEnvelope` gets the agent record next to the actor. A child's
  envelope is the parent's narrowed by the child's profile, so a delegated action can't exceed what
  its delegator may do.

### 6.4 Lineage view

A per-session tree, built from the alerts' `root`, `parent` and `chain` plus the exact edge events
(§5.4). Each node shows its kind, version and type state, and its alerts and verdicts. Links are
drawn solid when exact and dashed when inferred. A `root-only` child hangs under the root with a
"spawner unknown" mark.

Derived metrics extend the existing session metrics (`server/session-metrics.js`, v0.80.0):

- depth and fan-out per session;
- orphans (a child with no edge), already a local detector (`data/agent-detections.js`);
- per-type deny rate;
- adversarial instruction propagation measured along edges, not just within a session.

## 7. Phase 3: standards-based credentials and agent-to-agent trust

Phase 3 waits on the drafts in §3. It applies **only where a component outside the agent's control
can attest**: server mode with a sidecar, or a remote MCP server behind the gateway.

**Target (standards change, §3.10 item 6).** `draft-ietf-wimse-aims-00`:

- one WIMSE identifier per agent, which may be a SPIFFE ID;
- a short-lived credential bound to it by proof of possession, i.e. a WIT
  (`draft-ietf-wimse-workload-creds`) plus a WPT (`draft-ietf-wimse-wpt`);
- delegation as OAuth with the agent as `client_id` and the user as `sub`, with chains per
  `draft-mcguinness-oauth-actor-profile` (`iss` on every `act`, a maximum depth, no silent
  truncation).

Agent claims follow the §5.1 mapping. None of OIDC-A or the sharif draft is adopted wholesale.

1. **Workload credential, server mode.**
   - The agent's pod gets a SPIFFE SVID from SPIRE. Attestation is node attestation plus workload
     attestation from kernel and kubelet selectors, which the agent process cannot alter.
   - In the WIMSE drafts' terms, it holds a Workload Identity Token: a JWT, `typ: wit+jwt`, with a
     `cnf.jwk`, sent in the `Workload-Identity-Token` header and proven per request by a Workload
     Proof Token.
   - `moorai-serve` and the gateway read their own SVID through the Workload API, or from files that
     `spiffe-helper` writes. That avoids a gRPC dependency.
   - They verify the peer's credential on calls that carry one.
   - Alerts gain `agentIdentity.attested: {method: "x509-svid"|"jwt-svid"|"wit", trustDomain, id,
     verifiedBy}`. SPIFFE ids are infrastructure identifiers, like `pod`, so they are stored as-is.
     `source` becomes `attested` only for the fields the credential covers: the workload, not the
     sub-agent within it.
2. **Delegation chain as tokens.**
   - Where agents call tools with OAuth tokens, represent delegation with token exchange (RFC 8693):
     `sub` is the principal, and a nested `act` names each acting agent.
   - The gateway already sees `Authorization` (`mcp-gateway/server.mjs:126`). An opt-in verifier
     would check the signature against the tenant IdP's JWKS, the audience against the route, `act`
     depth against `maxDelegationDepth`, each hop's `(act.iss, act.sub)` against the registry, and
     the agent claims (§5.1 mapping).
   - An over-depth chain is refused, not trimmed (the actor profile's no-silent-truncation rule).
   - The verifier refuses an unapproved or revoked agent and records the verified chain with
     `source:"attested"`.
   - Proof of possession (a WPT, or DPoP) stops a replayed token. AIMS requires credentials bound to
     the identifier; a bearer token alone does not meet it.
3. **Agent-to-agent trust at the gateway or sidecar.** A request from agent A to tool or agent B is
   allowed when all three checks pass:
   - A's credential verifies;
   - A's kind and type are approved for route B;
   - the `act` chain stays inside policy depth, with no denied ancestor.

   This is the same "narrow on stated, widen only on attested" rule. Only here can an approval
   **widen** access, because the identity is proven.
4. **Laptop.** There is no attestation root for the agent. The best available is a device key
   (Secure Enclave or TPM) bound at enrollment by the desktop app, used to sign alerts. That proves
   **the device**, not the agent, and it would also fix the shared-bearer-token problem in §2.4. It
   is a separate proposal.
   - AIMS §8 says the LLM must not have access to the agent's credentials. MoorAI breaks the
     equivalent rule on a laptop: the agent can read the install token (standards change, §3.10
     item 7). A key that cannot be exported from the Secure Enclave or TPM would fix that.
   - The placeholder credentials in the model proxy and the MCP gateway (README "Placeholder
     credentials") already apply the rule to upstream API keys.
5. **Emitting claims.** MoorAI could map `agentIdentity` onto the draft claim names in §3 when it mints
   or forwards tokens. MoorAI is not an IdP, so it should consume and verify claims, not issue them,
   unless the sidecar becomes a token-exchange service. That would be a large scope change (§9, Q6).

## 8. Privacy and threat model

### 8.1 What stays content-free

- **In clear:** kind, version, role, depth and the binding class, plus the optional model name in
  server mode. These describe the product and the structure of the run, not its content. They match
  what the posture beat already sends.
- **Keyed hashes:** instance, root, parent, chain and type.
- **Never sent:** prompts, task descriptions, definition text, transcript paths, Cursor's
  `user_email`, raw session ids or raw agent ids.
- **Existing leak to fix:** threat #66 already sends `subagentType` in clear (`cli/moorai-hook.mjs:2337`).
  A user-defined name such as `acme-merger-review` is content. Phase 1 should hash it, keeping a
  built-in allow-list (`general-purpose`, `Explore`, `Plan` and so on) in clear (§9, Q1).
- **Linkability.** The console can rebuild a run's shape: how many agents, how deep, when. That is
  pseudonymous personal data about the user. Lineage fields share the alerts' retention and
  pseudonymisation; they need no new store.

### 8.2 Who can spoof what

| Setting | Attacker | Can forge | Cannot forge |
|---|---|---|---|
| Laptop | The agent itself (Bash as the user) or a malicious repo | Everything in §5. It can run `node moorai-hook.mjs` with any stdin, and it can read the install token in `~/.moorai/config.json`, so it can derive the hash key and post any actor, session, instance or parent. It can rename `.claude/agents/*.md` to claim an approved type, or run an unhooked agent and appear as nothing. | Nothing of the agent's identity is unforgeable. What it cannot do silently: break consistency. An orphan child, a version that disagrees with the posture beat, or a `kind` that disagrees with the adapter that ran are all detectable. |
| Server mode, hook only | The agent in the container | The same as a laptop for agent fields. If `MOORAI_INSTALL_TOKEN` is in the agent's environment, it can post as the workload. | `workload.containerId` (from `/proc`), and pod / namespace / node from the downward API. A settings-file override is refused (`cli/server-mode.mjs:14-46`). |
| Server mode, sidecar | The agent in its own container | What it puts in request bodies (`caller-claimed`) | What the sidecar observes itself (container id from shared mountinfo); in Phase 3, the SVID-attested workload |
| Console | Any install-token holder | New registry entries and fake lineage (rate-limited) | Approvals, which are admin-only and governance-logged |

### 8.3 Proven versus recorded

| Claim | Phase 1 laptop | Phase 1 server | Phase 3 server |
|---|---|---|---|
| Which user or workload | recorded | workload attributes partly platform-sourced | **proven** (SVID or WIT) |
| Which agent product and version | recorded (host-stated) | recorded | recorded. The credential names the workload, not the binary inside it, unless the image is attested. |
| Which sub-agent instance | recorded | recorded | recorded |
| Parent → child link | recorded, exact for Cursor and Claude Code async spawns; inferred otherwise | same | **proven** only where delegation uses `act` tokens the gateway verifies |
| Policy effect of identity | narrows only | narrows only | may widen on the attested fields |

## 9. Open questions

1. **Sub-agent type names: clear or hashed?** Hashing protects custom names but makes the registry UI
   show hashes. Options: hash with a built-in allow-list in clear, or let the console show names it
   learns from an admin.
2. **Key domain.** Keyed ids join only within one install token (§2.4). Cross-device or
   cross-installation lineage, such as a CI agent delegating to a sidecar on another install, will not
   join. A tenant-wide hashing key is a breaking change to every keyed value.
3. **Codex, Gemini and Copilot tool-call attribution** (§5.3). Per their docs, none of them puts a
   sub-agent id on tool calls:
   - Codex has `agent_id` only on SubagentStart / SubagentStop;
   - Copilot has `agentId` only on subagentStop;
   - Gemini has none.

   Until a host adds one, its sub-agents' tool calls cannot be told from the parent's. Should MoorAI
   ask Codex and Copilot upstream to add the field to tool events?
4. **Register `SubagentStart` and `SessionStart`?** One extra process start per sub-agent and per
   session, in exchange for earlier binding, `model`, and resume and fork tracking.
5. **Registry granularity.** Kind plus version range, or type plus definition fingerprint, or both?
   Version-range drift may be noisy on hosts that auto-update daily: Claude Code went from 2.1.284 to
   2.1.295 in about three days on this machine.
6. **Issue or only verify** tokens in Phase 3? §7 targets `draft-ietf-wimse-aims-00`, the only
   working-group draft on agents. It is a -00, and the claim drafts (OIDC-A, sharif-01) are
   individual and disagree on what "agent id" means. How much to build before AIMS reaches last
   call?
7. **Revocation latency.** Is the policy refresh interval acceptable for "revoke", or does revoke need
   a push channel? AIMS §11 says revoked authorization must be enforced "without undue delay", which
   points to push.
8. **Local "ask" versus AIMS** (standards change, §3.10 item 8). AIMS says agents MUST NOT treat local
   UI confirmation alone as sufficient authorization, and wants confirmation bound to a verifiable
   grant (CIBA). MoorAI's justify / "ask" verdict is a local confirmation in the host's UI. Should a
   server-mode or high-impact "ask" be routable to an out-of-band approver? (The backlog already has
   "just-in-time approval routing".)
9. **NCCoE.** Its first implementation use case is software-development agents (§3.4). Does MoorAI
   want to take part as a collaborator? That is a business decision, not a design one.

## 10. Cost estimates

Rough sizes: S is days, M is 1 to 2 weeks, L is 3 to 5 weeks, XL is more than 6 weeks, each for one
engineer including tests and docs.

| Phase | Size | Agent repo | Console repo |
|---|---|---|---|
| 1a: kind + version on every alert | S | `cli/moorai-hook.mjs` (`IDENTITY`/`post()`), `cli/agent-hooks/host-version.mjs` (cached version file), `cli/moorai-agent-hook.mjs`, `packages/agent-sdk/src/runtime.mjs` (already sends `surface`), tests | None: `agent_name` already exists. `agent_version` column + sanitizer. |
| 1b: instance, parent, chain | M | new `cli/agent-identity.mjs`; `cli/moorai-hook.mjs` (`main()` lineage, `post()`, pending-spawn store, edge event, optional `SubagentStart`); `cli/agent-hooks/{cursor,codex,gemini,copilot}.mjs` (pass ids, drop `user_email`); `cli/agent-hooks/shim.mjs`; `packages/agent-sdk/src/index.mjs`; `cli/moorai-serve.mjs`; `mcp-gateway/report.mjs` (`clientInfo`); `cli/otel.mjs`; hash `subagentType` on #66; README, `docs/CAPABILITY_SPEC.md`; conformance tests per adapter | `server/db.js` (columns), new `server/agent-identity.js`, `server/siem-fields.js` (schema 4), `server/lineage-export.js`, `docs/SIEM_FIELDS.md` |
| 2: registry, gate, profiles, lineage view | L | hook enforcement of `agentAllow` and the revoked state; `cli/workload-profile.mjs` (`match.agentKind`/`agentType`, a CONTRACT C3 change); envelope narrowing; definition fingerprint | `server/db.js` (registry with purpose and capabilities, `resolvePolicy`), `server/server.js` (routes), `server/policy-sign.js` (signed fields), dashboard views, `server/session-metrics.js`, an optional SSF/CAEP transmitter for revokes |
| 3: SVID / WIT / `act` verification | XL, gated on the drafts | new gateway verifier module (JWT/JWKS, `act`, proof of possession); SVID file reader for serve and gateway; `examples/serve/` SPIRE manifests | trust-bundle and JWKS configuration, registry ↔ claim mapping |

## 11. Not verified in this document

- **Hand-off details not re-checked.** The standards in §3 were fetched and read by the standards
  research, and two IETF drafts (`draft-ietf-wimse-aims-00`, `draft-sharif-openid-agent-identity-01`)
  were checked again against datatracker. The other revision numbers, dates and summaries are as the
  research handed them in.
- **Missing URLs.** None recorded for the NIST CAISI initiative, the NCCoE concept paper and its
  comment summary, or the Gemini CLI hooks page.
- **Dates conflict** in `draft-sharif-openid-agent-identity-01`: the header says 2026-08-26, Appendix B
  says March 2026.
- **SAF-MCP.** The claim that it was renamed from SAFE-MCP is not supported by its README, so this
  document does not make it.
- **Host fields from docs only:**
  - Codex, Gemini and Copilot fields in §5.3 come from their docs, not from a run or a binary;
  - whether Codex tool events really lack `agent_id` inside a sub-agent should be measured with a
    live run;
  - whether a Cursor sub-agent's own tool events carry its own `conversation_id`.
- **Claude Code fields** come from the docs and the 2.1.295 binary's schema strings, not from a live
  hook run. MoorAI's tested version is 2.1.284.
- **Agent SDK.** Its version source, and whether SDK hook input carries `agent_id` / `agent_type` the
  same way the CLI's does.
- **Revocation latency.** The console's policy refresh interval, which sets it, was not measured.
- **Cost estimates.** None are measured.
