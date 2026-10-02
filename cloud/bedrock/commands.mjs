// The read-only AWS CLI calls the Bedrock inventory makes — the single table that drives the `--run`
// collector, the export-directory layout read by `--from`, and the minimum IAM policy (`--policy`).
//
// Every call is a List*/Get* operation. IAM action names are from the Service Authorization Reference
// ("API operations defined by Amazon Bedrock" / "... Amazon Bedrock Agentcore"); response keys from the
// Bedrock API Reference Response Syntax blocks. `aws sts get-caller-identity` needs no IAM permission
// (STS API Reference: "No permissions are required to perform this operation.").
//
// `query` is a JMESPath projection passed to `--query`. With `--output json` the CLI "runs the query only
// once against the entire structure" after pagination (AWS CLI User Guide, Filtering output), so names,
// descriptions, instructions, prompt templates and schemas are dropped inside the AWS CLI process and
// never reach this one. The projection keeps the response's own top-level key, so a projected response
// and a full one exported by hand have the same shape. It is defence in depth: normalize.mjs reads only
// allow-listed fields either way. Where only presence matters (a KMS key ARN, a Lambda ARN) the projection
// reduces the field to a boolean (`!= \`null\``), so the ARN is not even held in memory here.
//
// Export layout (`--from DIR`, and what `--run --export DIR` writes):
//   DIR/account.json                                   aws sts get-caller-identity
//   DIR/<region>/<name>.json                           region-scoped list calls
//   DIR/<region>/<name>/<agentId>.json                 per-agent calls
//   DIR/<region>/get-agent-action-group/<agentId>.<actionGroupId>.json

// The agent version whose action groups and knowledge bases are read. DRAFT is the working copy every
// agent has; numbered versions behind aliases are not read in this slice (see cloud/README.md).
export const AGENT_VERSION = "DRAFT";

export const STS = {
  name: "account", service: "sts", op: "get-caller-identity", iam: null,
  query: "{Account: Account}"
};

export const COMMANDS = [
  { name: "list-agents", service: "bedrock-agent", op: "list-agents", scope: "region", listKey: "agentSummaries",
    iam: "bedrock:ListAgents",
    query: "{agentSummaries: agentSummaries[].{agentId: agentId, agentStatus: agentStatus, guardrailConfiguration: guardrailConfiguration, latestAgentVersion: latestAgentVersion, updatedAt: updatedAt}}" },
  { name: "get-agent", service: "bedrock-agent", op: "get-agent", scope: "agent", objKey: "agent",
    iam: "bedrock:GetAgent",
    args: (p) => ["--agent-id", p.agentId],
    query: "{agent: agent.{agentArn: agentArn, agentId: agentId, agentStatus: agentStatus, foundationModel: foundationModel, guardrailConfiguration: guardrailConfiguration, memoryConfiguration: {enabledMemoryTypes: memoryConfiguration.enabledMemoryTypes}, customerEncryptionKeyArn: customerEncryptionKeyArn != `null`, updatedAt: updatedAt}}" },
  { name: "list-agent-aliases", service: "bedrock-agent", op: "list-agent-aliases", scope: "agent", listKey: "agentAliasSummaries",
    iam: "bedrock:ListAgentAliases",
    args: (p) => ["--agent-id", p.agentId],
    query: "{agentAliasSummaries: agentAliasSummaries[].{agentAliasId: agentAliasId, agentAliasStatus: agentAliasStatus, aliasInvocationState: aliasInvocationState, routingConfiguration: routingConfiguration, updatedAt: updatedAt}}" },
  { name: "list-agent-action-groups", service: "bedrock-agent", op: "list-agent-action-groups", scope: "agent", listKey: "actionGroupSummaries",
    iam: "bedrock:ListAgentActionGroups",
    args: (p) => ["--agent-id", p.agentId, "--agent-version", AGENT_VERSION],
    query: "{actionGroupSummaries: actionGroupSummaries[].{actionGroupId: actionGroupId, actionGroupState: actionGroupState, updatedAt: updatedAt}}" },
  // ListAgentActionGroups' summary has no parentActionSignature, which is the only field that says
  // whether an action group is the code interpreter, user input or computer use — hence one Get each.
  { name: "get-agent-action-group", service: "bedrock-agent", op: "get-agent-action-group", scope: "action-group", objKey: "agentActionGroup",
    iam: "bedrock:GetAgentActionGroup",
    args: (p) => ["--agent-id", p.agentId, "--agent-version", AGENT_VERSION, "--action-group-id", p.actionGroupId],
    query: "{agentActionGroup: agentActionGroup.{actionGroupId: actionGroupId, actionGroupState: actionGroupState, parentActionSignature: parentActionSignature, actionGroupExecutor: {customControl: actionGroupExecutor.customControl, lambda: actionGroupExecutor.lambda != `null`}, updatedAt: updatedAt}}" },
  { name: "list-agent-knowledge-bases", service: "bedrock-agent", op: "list-agent-knowledge-bases", scope: "agent", listKey: "agentKnowledgeBaseSummaries",
    iam: "bedrock:ListAgentKnowledgeBases",
    args: (p) => ["--agent-id", p.agentId, "--agent-version", AGENT_VERSION],
    query: "{agentKnowledgeBaseSummaries: agentKnowledgeBaseSummaries[].{knowledgeBaseId: knowledgeBaseId, knowledgeBaseState: knowledgeBaseState, updatedAt: updatedAt}}" },
  { name: "list-knowledge-bases", service: "bedrock-agent", op: "list-knowledge-bases", scope: "region", listKey: "knowledgeBaseSummaries",
    iam: "bedrock:ListKnowledgeBases",
    query: "{knowledgeBaseSummaries: knowledgeBaseSummaries[].{knowledgeBaseId: knowledgeBaseId, status: status, updatedAt: updatedAt}}" },
  { name: "list-guardrails", service: "bedrock", op: "list-guardrails", scope: "region", listKey: "guardrails",
    iam: "bedrock:ListGuardrails",
    query: "{guardrails: guardrails[].{arn: arn, id: id, status: status, version: version, crossRegionDetails: crossRegionDetails, updatedAt: updatedAt}}" },
  { name: "list-custom-models", service: "bedrock", op: "list-custom-models", scope: "region", listKey: "modelSummaries",
    iam: "bedrock:ListCustomModels",
    query: "{modelSummaries: modelSummaries[].{modelArn: modelArn, baseModelArn: baseModelArn, baseModelName: baseModelName, customizationType: customizationType, modelStatus: modelStatus, ownerAccountId: ownerAccountId, creationTime: creationTime}}" },
  { name: "list-provisioned-model-throughputs", service: "bedrock", op: "list-provisioned-model-throughputs", scope: "region", listKey: "provisionedModelSummaries",
    iam: "bedrock:ListProvisionedModelThroughputs",
    query: "{provisionedModelSummaries: provisionedModelSummaries[].{provisionedModelArn: provisionedModelArn, modelArn: modelArn, foundationModelArn: foundationModelArn, modelUnits: modelUnits, commitmentDuration: commitmentDuration, status: status, lastModifiedTime: lastModifiedTime}}" },
  // APPLICATION only: SYSTEM_DEFINED profiles are defined by Amazon Bedrock, not by the customer.
  { name: "list-inference-profiles", service: "bedrock", op: "list-inference-profiles", scope: "region", listKey: "inferenceProfileSummaries",
    iam: "bedrock:ListInferenceProfiles",
    args: () => ["--type-equals", "APPLICATION"],
    query: "{inferenceProfileSummaries: inferenceProfileSummaries[].{inferenceProfileArn: inferenceProfileArn, models: models, status: status, type: type, updatedAt: updatedAt}}" },
  { name: "list-agent-runtimes", service: "bedrock-agentcore-control", op: "list-agent-runtimes", scope: "region", listKey: "agentRuntimes",
    iam: "bedrock-agentcore:ListAgentRuntimes",
    query: "{agentRuntimes: agentRuntimes[].{agentRuntimeArn: agentRuntimeArn, agentRuntimeVersion: agentRuntimeVersion, status: status, lastUpdatedAt: lastUpdatedAt}}" }
];

export const byName = Object.fromEntries(COMMANDS.map((c) => [c.name, c]));

// Every argument vector this tool can hand to `aws`. Read-only by construction: the op comes from the
// table above, never from input. `--no-cli-pager` keeps the CLI from opening `less` on a TTY.
export function cliArgs(cmd, { region, profile, params = {}, startingToken } = {}) {
  const a = [cmd.service, cmd.op, ...(cmd.args ? cmd.args(params) : []), "--region", region, "--output", "json", "--no-cli-pager"];
  if (cmd.query) a.push("--query", cmd.query);
  if (profile) a.push("--profile", profile);
  if (startingToken) a.push("--starting-token", startingToken);
  return a;
}

// Minimum IAM policy for `--run`. Resource "*": the List operations take no resource ARN (the
// Service Authorization Reference lists no resource type for ListAgents, ListKnowledgeBases,
// ListCustomModels, ListProvisionedModelThroughputs, ListInferenceProfiles, ListAgentRuntimes), and the
// agent-scoped ones are needed on every agent the inventory should see.
export function iamPolicy() {
  return {
    Version: "2012-10-17",
    Statement: [{
      Sid: "MoorAIBedrockInventoryReadOnly",
      Effect: "Allow",
      Action: COMMANDS.map((c) => c.iam),
      Resource: "*"
    }]
  };
}
