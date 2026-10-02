// Risk flags, computed on the device from a record's content-free attributes only — so the console, a
// SIEM or an auditor can recompute every flag from what was sent. An attribute that is unknown (null,
// because a call failed or the export lacked it) never raises a flag and never clears one.
//
// `source` names the AWS field each flag is derived from (Bedrock API Reference).

export const FLAGS = {
  "agent-no-guardrail": {
    kind: "agent", severity: "high",
    source: "bedrock-agent ListAgents AgentSummary.guardrailConfiguration / GetAgent Agent.guardrailConfiguration is absent",
    why: "Prompts and responses reach the model with no Bedrock Guardrail applied."
  },
  "agent-guardrail-draft": {
    kind: "agent", severity: "low",
    source: "Agent.guardrailConfiguration.guardrailVersion = DRAFT",
    why: "The agent follows the guardrail's working draft, which changes on every edit; a numbered version is fixed."
  },
  "agent-code-interpreter": {
    kind: "agent", severity: "medium",
    source: "GetAgentActionGroup AgentActionGroup.parentActionSignature = AMAZON.CodeInterpreter with actionGroupState = ENABLED",
    why: "The agent can write and run code in a sandbox, and its output feeds back into the conversation."
  },
  "agent-computer-use": {
    kind: "agent", severity: "high",
    source: "AgentActionGroup.parentActionSignature = ANTHROPIC.Computer | ANTHROPIC.Bash | ANTHROPIC.TextEditor with actionGroupState = ENABLED",
    why: "The agent can drive a desktop, a shell or a text editor."
  },
  "agent-kb-no-guardrail": {
    kind: "agent", severity: "high",
    source: "ListAgentKnowledgeBases AgentKnowledgeBaseSummary.knowledgeBaseState = ENABLED and no guardrailConfiguration on the agent",
    why: "Retrieved documents enter the model's context with no guardrail on the input or the answer (indirect prompt injection, data leakage)."
  },
  "agent-custom-model": {
    kind: "agent", severity: "low",
    source: "Agent.foundationModel is a custom-model ARN",
    why: "The agent runs on customer-trained weights; their provenance is the customer's to prove."
  },
  "kb-reachable-without-guardrail": {
    kind: "knowledge-base", severity: "medium",
    source: "KnowledgeBaseSummary.knowledgeBaseId associated ENABLED (ListAgentKnowledgeBases) with an agent that has no guardrailConfiguration",
    why: "At least one agent answers from this knowledge base with no guardrail."
  },
  "custom-model-active": {
    kind: "custom-model", severity: "info",
    source: "ListCustomModels CustomModelSummary.modelStatus = Active",
    why: "A customer-trained or imported model is ready for use."
  },
  "custom-model-imported": {
    kind: "custom-model", severity: "medium",
    source: "CustomModelSummary.customizationType = IMPORTED",
    why: "The weights were imported from outside Bedrock rather than trained in it."
  },
  "custom-model-shared": {
    kind: "custom-model", severity: "medium",
    source: "CustomModelSummary.ownerAccountId differs from the calling account (sts GetCallerIdentity Account)",
    why: "The model is owned by another AWS account and shared into this one."
  }
};

const RULES = {
  agent: {
    "agent-no-guardrail": (a) => a.guardrailAttached === false,
    "agent-guardrail-draft": (a) => a.guardrailVersion === "DRAFT",
    "agent-code-interpreter": (a) => a.codeInterpreter === true,
    "agent-computer-use": (a) => a.computerUse === true,
    "agent-kb-no-guardrail": (a) => a.guardrailAttached === false && Number.isInteger(a.knowledgeBaseCount) && a.knowledgeBaseCount > 0,
    "agent-custom-model": (a) => a.modelFamily === "custom-model"
  },
  "knowledge-base": {
    "kb-reachable-without-guardrail": (a) => Number.isInteger(a.unguardedAgentCount) && a.unguardedAgentCount > 0
  },
  "custom-model": {
    "custom-model-active": (_a, status) => status === "Active",
    "custom-model-imported": (a) => a.customizationType === "IMPORTED",
    "custom-model-shared": (a) => a.shared === true
  }
};

export function flagsFor(kind, attrs = {}, status = null) {
  const rules = RULES[kind] || {};
  return Object.keys(rules).filter((id) => rules[id](attrs, status)).sort();
}
