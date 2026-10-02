// Closed vocabularies copied from the Amazon Bedrock API Reference (fetched 2026-10-01). A value from
// the API that is not in its list is emitted as "OTHER" — never passed through — so a field AWS widens
// later, or a forged export, cannot carry text into a record.
//
//   AgentSummary.agentStatus            API_agent_AgentSummary.html
//   AgentAliasSummary.agentAliasStatus  API_agent_AgentAliasSummary.html
//   AgentAliasSummary.aliasInvocationState
//   AgentActionGroup.actionGroupState   API_agent_AgentActionGroup.html
//   AgentActionGroup.parentActionSignature
//   ActionGroupExecutor.customControl   API_agent_ActionGroupExecutor.html
//   AgentKnowledgeBaseSummary.knowledgeBaseState  API_agent_AgentKnowledgeBaseSummary.html
//   KnowledgeBaseSummary.status         API_agent_KnowledgeBaseSummary.html
//   GuardrailSummary.status             API_GuardrailSummary.html
//   CustomModelSummary.modelStatus / customizationType  API_CustomModelSummary.html
//   ProvisionedModelSummary.status      API_ListProvisionedModelThroughputs.html (statusEquals)
//   InferenceProfileSummary.status / type  API_InferenceProfileSummary.html
//   AgentRuntime.status                 bedrock-agentcore-control API_AgentRuntime.html

export const AGENT_STATUS = ["CREATING", "PREPARING", "PREPARED", "NOT_PREPARED", "DELETING", "FAILED", "VERSIONING", "UPDATING"];
export const ALIAS_STATUS = ["CREATING", "PREPARED", "FAILED", "UPDATING", "DELETING", "DISSOCIATED"];
export const ALIAS_INVOCATION = ["ACCEPT_INVOCATIONS", "REJECT_INVOCATIONS"];
export const ENABLED_STATE = ["ENABLED", "DISABLED"];
export const PARENT_SIGNATURES = ["AMAZON.UserInput", "AMAZON.CodeInterpreter", "ANTHROPIC.Computer", "ANTHROPIC.Bash", "ANTHROPIC.TextEditor"];
export const COMPUTER_USE_SIGNATURES = ["ANTHROPIC.Computer", "ANTHROPIC.Bash", "ANTHROPIC.TextEditor"];
export const KB_STATUS = ["CREATING", "ACTIVE", "DELETING", "UPDATING", "FAILED", "DELETE_UNSUCCESSFUL", "UPDATE_UNSUCCESSFUL"];
export const GUARDRAIL_STATUS = ["CREATING", "UPDATING", "VERSIONING", "READY", "FAILED", "DELETING"];
export const CUSTOM_MODEL_STATUS = ["Active", "Creating", "Failed"];
export const CUSTOMIZATION_TYPES = ["FINE_TUNING", "CONTINUED_PRE_TRAINING", "DISTILLATION", "REINFORCEMENT_FINE_TUNING", "IMPORTED"];
export const PT_STATUS = ["Creating", "InService", "Updating", "Failed"];
export const PROFILE_STATUS = ["ACTIVE"];
export const PROFILE_TYPES = ["SYSTEM_DEFINED", "APPLICATION"];
export const RUNTIME_STATUS = ["CREATING", "CREATE_FAILED", "UPDATING", "UPDATE_FAILED", "READY", "DELETING", "DELETE_FAILED"];

// The fixed id of an agent's built-in test alias (AgentAliasSummary.agentAliasId pattern
// `(\bTSTALIASID\b|[0-9a-zA-Z]+)`). An AWS constant, not customer text.
export const TEST_ALIAS_ID = "TSTALIASID";

export const KINDS = ["agent", "alias", "action-group", "knowledge-base", "guardrail", "custom-model",
  "provisioned-throughput", "inference-profile", "agentcore-runtime"];

export const oneOf = (list, v) => (typeof v === "string" && list.includes(v) ? v : v == null ? null : "OTHER");
