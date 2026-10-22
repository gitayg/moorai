# Just-in-time approval routing (device side)

A policy can send selected held verdicts to a human approver group instead of letting them stand as a block or an
ask. The console stores the request, notifies the group and records the decision. The device never waits for it.

Code: `cli/approval-routing.mjs`, wired into `cli/moorai-hook.mjs` (Claude Code `PreToolUse`). Tests:
`test/approval-routing.test.mjs`, `test/approval-routing-hook.test.mjs`.

## Policy key

`approvalRouting` is a top-level key of the signed policy:

```json
{ "v": 1, "rules": [ { "id": "shell-review", "label": "Reverse shell needs a reviewer",
  "match": { "threatId": [54] }, "holds": ["block"], "group": "secops",
  "timeoutSec": 600, "onTimeout": "deny", "grant": "once", "grantTtlSec": 900 } ] }
```

- `match` keys: `threatId`, `mcpTool` (`server/tool`), `egressRuleId`, `reasonCode` (`EGRESS_RULE`,
  `OT_PROTOCOL_CLIENT`, `MCP_TOOL_ARGS`), `otOp`, `functionTool`. Every key a rule sets must match. Threat ids and
  egress rule ids must all be covered by the rule, so approving one threat never releases a second threat on the
  same call. The hook supplies no function name and no OT operation, and its only reason code is `EGRESS_RULE`, so a
  rule that needs `functionTool`, `otOp`, `OT_PROTOCOL_CLIENT` or `MCP_TOOL_ARGS` never matches in the hook.
- At most 64 rules. A malformed rule is dropped with a stderr warning that names the rule id (or its index), never a
  value. A dropped rule leaves the original verdict in force.
- An agent older than this one ignores the key: a block stays a block and an ask stays an ask.

## What the hook does

1. **Hold.** A `deny` (verdict `block`) or `ask` that matches a rule with that verdict in `holds` is answered at once
   with a deny: `Held for approval: <label> (request apr_…). Retry after it is approved.` A Claude Code ask is not
   shown locally.
2. **Request.** The device generates `apr_` + 26 Crockford base32 characters (128 random bits) and posts one
   `APPROVAL_REQUESTED` alert through the normal alert path (direct post, or the alert outbox when the console does
   not answer). The `approval` object carries the request id, rule id, surface `hook`, the held verdict, the action
   hash, and the request and expiry times. The action hash is the keyed per-tenant hash of the tool name and the
   key-sorted tool input. No command, path, URL or argument text is sent.
3. **Dedupe.** While a request for the same rule and action is pending, the same request id is reused and no new
   alert is sent. Pending requests are kept in `~/.moorai/approvals.json` (mode 0600, at most 256).
4. **Decision.** The policy fetch names the device's keyed actor (`actor=h2:…`, never a hostname or login), and the
   console adds that device's decided rows to the signed policy as `approvals`. Grants are read only from a policy
   whose ed25519 signature verifies under the anchor or the pinned key. An unsigned body, a body changed after
   signing, a body signed by another key, a grant written into the local policy cache, and a device that holds no
   key yet (first contact) give no grant.
5. **Use.** While an approve grant for the same rule and action hash is valid, the call is allowed. `grant: "once"`
   allows it one time: the request id is recorded as used and the next identical call raises a new request.
   `grant: "ttl"` allows it until `validUntil`. The first use posts `APPROVAL_USED`. A deny grant answers
   `Denied by approver (<label>, request apr_…)` while the console serves it.
6. **Expiry.** A pending request past its expiry with no decision is denied and `APPROVAL_EXPIRED` is posted once.
   The next identical call raises a new request, so a device sends at most one request per action per `timeoutSec`.

## What is held, and what is not

- Held: verdicts reached after the call was fully judged (detector findings and content rules), and the early stop
  of a named egress rule.
- An egress grant is honoured at the egress check only, and the call then goes through the remaining checks. A
  detector block on the same call still stands.
- Never held: fail-closed denies, policy tamper, containment, decoys, the circuit breaker and other behaviour
  signals, profile drift, session kills (a threat set to `kill`, or any block under `killOnCritical`), and calls on an
  unenrolled device (which is coached, not enforced).
- Controls applied after the hold in the same decision still apply to an approved call: capability-tag rules, the
  session-risk escalation and MXC containment wrapping.

## Limits

- **Latency.** The hook caches the verified policy for 60 seconds, so a decision reaches the device on the first
  call at least 60 seconds after the last fetch. There is no separate poll. Policy fetches by `moorai-guard` and the
  MCP guard do not name the actor, so a cache they wrote carries no approvals until the hook fetches again.
- **Replay of a once grant.** `approvals.json` is in the agent user's write scope, so a `once` grant can be replayed
  for the identical action until its `validUntil`. The signed `validUntil` is the bound.
- **Console down or old.** No grant arrives, so the call stays held, which is a deny. With a console that does not
  know approval routing the request is stored as a plain alert and expires on the device.
- **Surfaces.** This covers the Claude Code hook. The model proxy, MCP gateway and egress proxy do not hold verdicts
  for approval yet.
