# moorai-cloud-inventory: Amazon Bedrock

A read-only, content-free inventory of what an AWS account has defined on Amazon Bedrock: agents, their
aliases, action groups and knowledge-base associations, knowledge bases, guardrails, custom models,
provisioned throughput, application inference profiles and Bedrock AgentCore runtimes. Each resource
becomes one record with a keyed hash in place of its ARN, a few coarse attributes and on-device risk flags.
Nothing the customer wrote leaves the machine: no names, descriptions, instructions, prompt templates,
API or function schemas, Lambda or role ARNs, and no account id in clear.

It reads the account in one of two ways:

```sh
# (b) JSON the customer exported with the AWS CLI. This is the tested path.
moorai-cloud-inventory bedrock --from ./bedrock-export [--regions us-east-1,eu-west-1]

# (a) Shell out to the customer's own AWS CLI, with their own credentials. Only with --run.
moorai-cloud-inventory bedrock --run --regions us-east-1,eu-west-1 [--profile inventory-ro] [--export ./bedrock-export]

# The minimum IAM policy for --run
moorai-cloud-inventory bedrock --policy
```

Add `--out FILE` to write the inventory to a file instead of stdout, and `--post` to send it to the
console (`POST /api/cloud-inventory` with the device's install token). The device must be enrolled: the
install token is the key for the resource hashes, and without it the tool exits 2 instead of emitting
`h2:nokey` for every resource.

## Credentials and regions (`--run`)

The tool never reads, receives, stores or logs a credential. It runs `aws` (or `$MOORAI_AWS_CLI`) as a
child process that inherits the environment unchanged, so the AWS CLI resolves credentials through its own
chain and `AWS_PROFILE` works as it does in the customer's shell. `--profile NAME` is passed through as the
CLI's own `--profile`. Regions come from `--regions`; without it, from `AWS_REGION`, then
`AWS_DEFAULT_REGION` (the AWS CLI's precedence). Bedrock is regional, so name every region in use.

Every call passes `--region R --output json --no-cli-pager` and a `--query` projection that keeps only the
fields the inventory reads. With `--output json` the CLI applies the query once, after it has fetched every
page, so names and descriptions are dropped inside the AWS CLI process. AWS error text is never printed:
an `AccessDenied` message carries the caller's ARN, so a failed call is reported as
`not read: <region> <command>: <class>` (`access-denied`, `auth`, `unavailable`, `cli-unsupported`,
`throttled`, `timeout`, `missing`, `malformed`) and the rest of the inventory is still built. With no
usable CLI or credentials (`sts get-caller-identity` fails) it exits 3.

`--export DIR` saves the projected responses in the export layout, so a security team can review exactly
what was read and rebuild the inventory later with `--from DIR`. The projected responses hold resource
ARNs (an AgentCore runtime ARN contains the runtime's name); the inventory built from them does not.

## Minimum IAM policy

All List/Get, from the Service Authorization Reference (Amazon Bedrock, Amazon Bedrock AgentCore).
`sts:GetCallerIdentity` needs no permission.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "MoorAIBedrockInventoryReadOnly",
    "Effect": "Allow",
    "Action": [
      "bedrock:ListAgents", "bedrock:GetAgent", "bedrock:ListAgentAliases", "bedrock:ListAgentActionGroups",
      "bedrock:GetAgentActionGroup", "bedrock:ListAgentKnowledgeBases", "bedrock:ListKnowledgeBases",
      "bedrock:ListGuardrails", "bedrock:ListCustomModels", "bedrock:ListProvisionedModelThroughputs",
      "bedrock:ListInferenceProfiles", "bedrock-agentcore:ListAgentRuntimes"
    ],
    "Resource": "*"
  }]
}
```

`GetAgent` and `GetAgentActionGroup` are Read-level and return the agent's instruction and the action
group's API schema. They are needed because `foundationModel` and `parentActionSignature` (code
interpreter, user input, computer use) appear in no List response. The `--query` projection drops the
instruction and schema before the response reaches this tool. A policy without the two Get actions still
works; the affected attributes are then `null` and the calls are reported as `access-denied`.

## Export layout (`--from DIR`)

One file per AWS CLI call, the CLI's JSON output unchanged (projected or not):

| File | Command |
|---|---|
| `DIR/account.json` | `aws sts get-caller-identity` |
| `DIR/<region>/list-agents.json` | `aws bedrock-agent list-agents` |
| `DIR/<region>/get-agent/<agentId>.json` | `aws bedrock-agent get-agent --agent-id <agentId>` |
| `DIR/<region>/list-agent-aliases/<agentId>.json` | `aws bedrock-agent list-agent-aliases --agent-id <agentId>` |
| `DIR/<region>/list-agent-action-groups/<agentId>.json` | `aws bedrock-agent list-agent-action-groups --agent-id <agentId> --agent-version DRAFT` |
| `DIR/<region>/get-agent-action-group/<agentId>.<actionGroupId>.json` | `aws bedrock-agent get-agent-action-group --agent-id … --agent-version DRAFT --action-group-id …` |
| `DIR/<region>/list-agent-knowledge-bases/<agentId>.json` | `aws bedrock-agent list-agent-knowledge-bases --agent-id <agentId> --agent-version DRAFT` |
| `DIR/<region>/list-knowledge-bases.json` | `aws bedrock-agent list-knowledge-bases` |
| `DIR/<region>/list-guardrails.json` | `aws bedrock list-guardrails` |
| `DIR/<region>/list-custom-models.json` | `aws bedrock list-custom-models` |
| `DIR/<region>/list-provisioned-model-throughputs.json` | `aws bedrock list-provisioned-model-throughputs` |
| `DIR/<region>/list-inference-profiles.json` | `aws bedrock list-inference-profiles --type-equals APPLICATION` |
| `DIR/<region>/list-agent-runtimes.json` | `aws bedrock-agentcore-control list-agent-runtimes` |

A missing file is reported as `missing` for that region and command, not guessed. `account.json` is needed
unless an agent, guardrail, provisioned-throughput or runtime ARN in the export names the account.

## Records

```json
{ "platform": "bedrock", "region": "us-east-1", "kind": "agent", "id": "h2:3f9c0a1b2c3d4e5f",
  "status": "PREPARED", "updatedDay": "2026-09-14",
  "attrs": { "modelFamily": "anthropic.claude", "guardrailAttached": false, "guardrailVersion": null,
             "codeInterpreter": true, "computerUse": false, "userInput": true, "actionGroupCount": 3,
             "knowledgeBaseCount": 1, "aliasCount": 2, "memoryEnabled": true, "customerKey": false },
  "flags": ["agent-code-interpreter", "agent-kb-no-guardrail", "agent-no-guardrail"] }
```

- `id`: `h2:` + 16 hex, the tenant-keyed HMAC of the resource ARN (`cli/content-hash.mjs`, the same key
  as every other MoorAI fingerprint). Agents, aliases and knowledge bases have their ARN built from region,
  account and id (`arn:aws:bedrock:<region>:<account>:agent/<agentId>`, `agent-alias/<agentId>/<aliasId>`,
  `knowledge-base/<id>`); an action group, which has no ARN, uses `<agent ARN>/action-group/<id>`.
- `parent`: the agent's id, on aliases and action groups.
- `status`: the AWS status, from a closed list per kind (`cloud/bedrock/vocab.mjs`); anything else is `OTHER`.
- `updatedDay`: the UTC day of the resource's last update.
- `attrs`: per kind, below. `null` means not known (a call failed or the export lacks it).
- The inventory document adds `schema`, `platform`, `account` (keyed hash of the account id) and `regions`.

| Kind | Attributes | AWS fields |
|---|---|---|
| `agent` | `modelFamily`, `guardrailAttached`, `guardrailVersion` (`DRAFT`/`numbered`), `codeInterpreter`, `computerUse`, `userInput`, `actionGroupCount` (enabled), `knowledgeBaseCount` (enabled), `aliasCount`, `memoryEnabled`, `customerKey` | `Agent.foundationModel`, `guardrailConfiguration`, `memoryConfiguration.enabledMemoryTypes`, `customerEncryptionKeyArn` (presence); `AgentActionGroup.parentActionSignature`, `actionGroupState`; `AgentKnowledgeBaseSummary.knowledgeBaseState` |
| `alias` | `invocationState`, `routesTo` (`draft`/`version`), `provisionedThroughput`, `testAlias` | `AgentAliasSummary.aliasInvocationState`, `routingConfiguration`, `agentAliasId = TSTALIASID` |
| `action-group` | `signature` (`AMAZON.*`/`ANTHROPIC.*`/`custom`), `executor` (`lambda`/`return-control`/`none`) | `AgentActionGroup.parentActionSignature`, `actionGroupExecutor` (presence of `lambda`, `customControl`) |
| `knowledge-base` | `agentCount`, `unguardedAgentCount` | `ListAgentKnowledgeBases` across agents |
| `guardrail` | `version` (`DRAFT`/`numbered`), `crossRegion`, `agentCount` | `GuardrailSummary.version`, `crossRegionDetails`; agents' `guardrailConfiguration` |
| `custom-model` | `customizationType`, `baseModelFamily`, `shared`, `provisioned` | `CustomModelSummary.customizationType`, `baseModelArn`, `ownerAccountId` vs caller account; PT `modelArn` |
| `provisioned-throughput` | `modelUnits`, `commitment`, `modelKind` (`custom`/`foundation`), `modelFamily` | `ProvisionedModelSummary.modelUnits`, `commitmentDuration`, `modelArn`, `foundationModelArn` |
| `inference-profile` | `type` (`APPLICATION`), `modelCount`, `modelFamily` (or `mixed`), `multiRegion` | `InferenceProfileSummary.type`, `models[].modelArn` |
| `agentcore-runtime` | `version` | `AgentRuntime.agentRuntimeVersion` |

`modelFamily` is a coarse `provider.family` (`anthropic.claude`, `amazon.nova`, `meta.llama3`), or
`custom-model`, `application-inference-profile`, `provisioned-model`, `other`. The model id, version and
any ARN are not kept.

## Risk flags

Computed on the device from the record's own attributes, so the console can recompute them. An unknown
(`null`) attribute never raises or clears a flag.

| Flag | Severity | From |
|---|---|---|
| `agent-no-guardrail` | high | `guardrailConfiguration` absent on the agent (ListAgents / GetAgent) |
| `agent-computer-use` | high | an ENABLED action group with `parentActionSignature` `ANTHROPIC.Computer`, `ANTHROPIC.Bash` or `ANTHROPIC.TextEditor` |
| `agent-kb-no-guardrail` | high | a knowledge base associated `ENABLED` and no guardrail on the agent |
| `agent-code-interpreter` | medium | an ENABLED action group with `parentActionSignature = AMAZON.CodeInterpreter` |
| `kb-reachable-without-guardrail` | medium | (on the knowledge base) associated `ENABLED` with at least one agent without a guardrail |
| `custom-model-imported` | medium | `customizationType = IMPORTED` |
| `custom-model-shared` | medium | `ownerAccountId` is not the calling account |
| `agent-guardrail-draft` | low | `guardrailConfiguration.guardrailVersion = DRAFT` |
| `agent-custom-model` | low | `foundationModel` is a custom-model ARN |
| `custom-model-active` | info | `modelStatus = Active` |

## Limits of this slice

- Action groups and knowledge-base associations are read from each agent's `DRAFT` version. An alias that
  routes to a numbered version may run a different configuration; numbered versions are not read.
- Only APPLICATION inference profiles are listed; SYSTEM_DEFINED ones are Amazon Bedrock's own.
- A guardrail applied by application code (Converse / ApplyGuardrail) rather than attached to an agent is
  invisible here, so `agentCount: 0` does not mean a guardrail is unused.
- AgentCore: runtimes only (no gateways, memories or identities), and nothing about their code.
- Read-only inventory. No runtime enforcement on Bedrock (see docs/ROADMAP.md).
