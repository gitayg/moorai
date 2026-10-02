// Bundle (raw AWS CLI JSON, from `--run` or an export directory) → content-free inventory records.
//
// The rule this file keeps: a value from AWS reaches a record only as (a) a keyed hash of an ARN,
// (b) a member of a closed vocabulary from vocab.mjs ("OTHER" otherwise), (c) a count, a boolean or a
// UTC day, or (d) a coarse model family from model-family.mjs. Names, descriptions, instructions, prompt
// templates, API/function schemas, Lambda ARNs, role ARNs and account ids are never read into a record.
// cloud/record-schema.mjs enforces the same rule on the output.
import * as V from "./vocab.mjs";
import { byName } from "./commands.mjs";
import { modelFamily } from "./model-family.mjs";
import { flagsFor } from "./risk.mjs";

const ID10 = /^[0-9a-zA-Z]{10}$/;
const ALIAS_ID = /^[0-9a-zA-Z]{10}$/;
const GUARDRAIL_ID = /^[a-z0-9]{1,64}$/;
const BEDROCK_ARN = /^arn:(aws[a-z-]*):bedrock(-agentcore)?:([a-z0-9-]*):(\d{12})?:[A-Za-z0-9._:/+_-]+$/;
const OWN_ARN = /^arn:aws[a-z-]*:bedrock(?:-agentcore)?:[a-z0-9-]+:(\d{12}):(?:agent|guardrail|knowledge-base|provisioned-model|runtime|application-inference-profile)\//;

const dayOf = (v) => {
  if (typeof v !== "string") return null;
  const ms = Date.parse(v);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString().slice(0, 10);
};
const int = (v) => (Number.isInteger(v) && v >= 0 && v < 1e6 ? v : null);
const KIND_ORDER = Object.fromEntries(V.KINDS.map((k, i) => [k, i]));

function findAccount(bundle) {
  for (const cmds of Object.values(bundle.regions)) {
    const arns = [
      ...Object.values(cmds["get-agent"] || {}).map((g) => g?.agent?.agentArn),
      ...(cmds["list-guardrails"]?.guardrails || []).map((g) => g?.arn),
      ...(cmds["list-provisioned-model-throughputs"]?.provisionedModelSummaries || []).map((p) => p?.provisionedModelArn),
      ...(cmds["list-agent-runtimes"]?.agentRuntimes || []).map((r) => r?.agentRuntimeArn)
    ];
    for (const a of arns) { const m = typeof a === "string" && OWN_ARN.exec(a); if (m) return m[1]; }
  }
  return null;
}

export function normalizeBedrock(bundle, hash) {
  const account = bundle.account || findAccount(bundle);
  if (!account) throw new Error("AWS account id unknown: add account.json (aws sts get-caller-identity) to the export");
  const records = [];
  const errors = [...(bundle.errors || [])];
  const seen = new Set(errors.map((e) => `${e.region}|${e.command}`));
  const note = (region, command, cls) => { const k = `${region}|${command}`; if (!seen.has(k)) { seen.add(k); errors.push({ region, command, class: cls }); } };

  for (const region of Object.keys(bundle.regions).sort()) {
    const R = bundle.regions[region];
    const arnOf = (rest) => `arn:aws:bedrock:${region}:${account}:${rest}`;
    const push = (kind, id, { parent = null, status = null, updatedDay = null, attrs }) =>
      records.push({ platform: "bedrock", region, kind, id: hash(id), ...(parent ? { parent: hash(parent) } : {}), status, updatedDay, attrs, flags: flagsFor(kind, attrs, status) });
    const list = (name) => {
      const v = R[name];
      if (v === undefined) { note(region, name, "missing"); return null; }
      const arr = v?.[byName[name].listKey];
      if (!Array.isArray(arr)) { note(region, name, "malformed"); return null; }
      return arr.filter((x) => x && typeof x === "object");
    };
    const perAgent = (name, agentId) => {
      const v = R[name]?.[agentId];
      if (v === undefined) { note(region, name, "missing"); return null; }
      const arr = v?.[byName[name].listKey];
      if (!Array.isArray(arr)) { note(region, name, "malformed"); return null; }
      return arr.filter((x) => x && typeof x === "object");
    };
    const guardrailArn = (ident) => (typeof ident === "string" && BEDROCK_ARN.test(ident) ? ident : GUARDRAIL_ID.test(String(ident)) ? arnOf(`guardrail/${ident}`) : null);

    // ---- agents, with their aliases, action groups and knowledge-base associations ----
    const guardrailUse = new Map();
    const kbAgents = new Map();
    for (const s of list("list-agents") || []) {
      if (!ID10.test(String(s.agentId))) { note(region, "list-agents", "malformed"); continue; }
      const agentId = s.agentId;
      const agentArn = arnOf(`agent/${agentId}`);
      const got = R["get-agent"]?.[agentId];
      if (got === undefined) note(region, "get-agent", "missing");
      const d = got?.agent && typeof got.agent === "object" ? got.agent : null;

      const gc = (d ? d.guardrailConfiguration : s.guardrailConfiguration) || null;
      const guardrailAttached = Boolean(gc && gc.guardrailIdentifier);
      if (guardrailAttached) { const g = guardrailArn(gc.guardrailIdentifier); if (g) guardrailUse.set(g, (guardrailUse.get(g) || 0) + 1); }

      const ags = perAgent("list-agent-action-groups", agentId);
      let enabled = 0, unknown = 0;
      const sig = new Set();
      for (const a of ags || []) {
        if (!ID10.test(String(a.actionGroupId))) { note(region, "list-agent-action-groups", "malformed"); continue; }
        const g = R["get-agent-action-group"]?.[`${agentId}.${a.actionGroupId}`];
        if (g === undefined) note(region, "get-agent-action-group", "missing");
        const dg = g?.agentActionGroup && typeof g.agentActionGroup === "object" ? g.agentActionGroup : null;
        const state = dg?.actionGroupState ?? a.actionGroupState;
        const exec = dg?.actionGroupExecutor || {};
        const signature = dg ? (dg.parentActionSignature ? V.oneOf(V.PARENT_SIGNATURES, dg.parentActionSignature) : "custom") : null;
        const executor = dg ? (exec.lambda ? "lambda" : exec.customControl === "RETURN_CONTROL" ? "return-control" : exec.customControl ? "OTHER" : "none") : null;
        if (state === "ENABLED") { enabled++; if (dg) sig.add(signature); else unknown++; }
        push("action-group", `${agentArn}/action-group/${a.actionGroupId}`, {
          parent: agentArn, status: V.oneOf(V.ENABLED_STATE, state), updatedDay: dayOf(dg?.updatedAt ?? a.updatedAt), attrs: { signature, executor }
        });
      }
      const has = (pred) => (!ags ? null : [...sig].some(pred) ? true : unknown ? null : false);

      const kbs = perAgent("list-agent-knowledge-bases", agentId);
      let kbEnabled = 0;
      for (const k of kbs || []) {
        if (k.knowledgeBaseState !== "ENABLED" || !ID10.test(String(k.knowledgeBaseId))) continue;
        kbEnabled++;
        const e = kbAgents.get(k.knowledgeBaseId) || { agents: 0, unguarded: 0 };
        e.agents++; if (!guardrailAttached) e.unguarded++;
        kbAgents.set(k.knowledgeBaseId, e);
      }

      const aliases = perAgent("list-agent-aliases", agentId);
      for (const al of aliases || []) {
        if (!ALIAS_ID.test(String(al.agentAliasId))) { note(region, "list-agent-aliases", "malformed"); continue; }
        const rc = Array.isArray(al.routingConfiguration) ? al.routingConfiguration : [];
        const v = rc[0]?.agentVersion;
        push("alias", arnOf(`agent-alias/${agentId}/${al.agentAliasId}`), {
          parent: agentArn, status: V.oneOf(V.ALIAS_STATUS, al.agentAliasStatus), updatedDay: dayOf(al.updatedAt),
          attrs: {
            invocationState: V.oneOf(V.ALIAS_INVOCATION, al.aliasInvocationState),
            routesTo: v === "DRAFT" ? "draft" : v ? "version" : null,
            provisionedThroughput: rc.some((x) => x && x.provisionedThroughput),
            testAlias: al.agentAliasId === V.TEST_ALIAS_ID
          }
        });
      }

      push("agent", agentArn, {
        status: V.oneOf(V.AGENT_STATUS, s.agentStatus), updatedDay: dayOf(s.updatedAt),
        attrs: {
          modelFamily: d ? modelFamily(d.foundationModel) : null,
          guardrailAttached,
          guardrailVersion: !gc ? null : gc.guardrailVersion === "DRAFT" ? "DRAFT" : gc.guardrailVersion ? "numbered" : null,
          codeInterpreter: has((x) => x === "AMAZON.CodeInterpreter"),
          computerUse: has((x) => V.COMPUTER_USE_SIGNATURES.includes(x)),
          userInput: has((x) => x === "AMAZON.UserInput"),
          actionGroupCount: ags ? enabled : null,
          knowledgeBaseCount: kbs ? kbEnabled : null,
          aliasCount: aliases ? aliases.length : null,
          memoryEnabled: d ? Array.isArray(d.memoryConfiguration?.enabledMemoryTypes) && d.memoryConfiguration.enabledMemoryTypes.length > 0 : null,
          customerKey: d ? Boolean(d.customerEncryptionKeyArn) : null
        }
      });
    }

    // ---- knowledge bases ----
    for (const k of list("list-knowledge-bases") || []) {
      if (!ID10.test(String(k.knowledgeBaseId))) { note(region, "list-knowledge-bases", "malformed"); continue; }
      const use = kbAgents.get(k.knowledgeBaseId) || { agents: 0, unguarded: 0 };
      push("knowledge-base", arnOf(`knowledge-base/${k.knowledgeBaseId}`), {
        status: V.oneOf(V.KB_STATUS, k.status), updatedDay: dayOf(k.updatedAt), attrs: { agentCount: use.agents, unguardedAgentCount: use.unguarded }
      });
    }

    // ---- guardrails ----
    for (const g of list("list-guardrails") || []) {
      const id = BEDROCK_ARN.test(String(g.arn)) ? g.arn : guardrailArn(g.id);
      if (!id) { note(region, "list-guardrails", "malformed"); continue; }
      push("guardrail", id, {
        status: V.oneOf(V.GUARDRAIL_STATUS, g.status), updatedDay: dayOf(g.updatedAt),
        attrs: {
          version: g.version === "DRAFT" ? "DRAFT" : g.version ? "numbered" : null,
          crossRegion: Boolean(g.crossRegionDetails && (g.crossRegionDetails.guardrailProfileId || g.crossRegionDetails.guardrailProfileArn)),
          agentCount: guardrailUse.get(id) || 0
        }
      });
    }

    // ---- provisioned throughput (read before custom models: it says which custom models are provisioned) ----
    const pts = list("list-provisioned-model-throughputs");
    const provisioned = new Set((pts || []).map((p) => p.modelArn).filter((a) => typeof a === "string"));
    for (const p of pts || []) {
      if (!BEDROCK_ARN.test(String(p.provisionedModelArn))) { note(region, "list-provisioned-model-throughputs", "malformed"); continue; }
      const m = typeof p.modelArn === "string" ? p.modelArn : "";
      push("provisioned-throughput", p.provisionedModelArn, {
        status: V.oneOf(V.PT_STATUS, p.status), updatedDay: dayOf(p.lastModifiedTime),
        attrs: {
          modelUnits: int(p.modelUnits), commitment: Boolean(p.commitmentDuration),
          modelKind: !m ? null : m.includes(":custom-model/") ? "custom" : m.includes(":foundation-model/") ? "foundation" : "other",
          modelFamily: modelFamily(p.foundationModelArn)
        }
      });
    }

    // ---- custom models ----
    for (const m of list("list-custom-models") || []) {
      if (!BEDROCK_ARN.test(String(m.modelArn))) { note(region, "list-custom-models", "malformed"); continue; }
      push("custom-model", m.modelArn, {
        status: V.oneOf(V.CUSTOM_MODEL_STATUS, m.modelStatus), updatedDay: dayOf(m.creationTime),
        attrs: {
          customizationType: V.oneOf(V.CUSTOMIZATION_TYPES, m.customizationType),
          baseModelFamily: modelFamily(m.baseModelArn),
          shared: /^\d{12}$/.test(String(m.ownerAccountId)) ? m.ownerAccountId !== account : null,
          provisioned: pts ? provisioned.has(m.modelArn) : null
        }
      });
    }

    // ---- application inference profiles (SYSTEM_DEFINED ones are AWS's, not the customer's) ----
    for (const p of list("list-inference-profiles") || []) {
      if (p.type !== "APPLICATION") continue;
      if (!BEDROCK_ARN.test(String(p.inferenceProfileArn))) { note(region, "list-inference-profiles", "malformed"); continue; }
      const models = (Array.isArray(p.models) ? p.models : []).map((x) => x?.modelArn).filter((a) => typeof a === "string");
      const fams = [...new Set(models.map(modelFamily))];
      const regions = new Set(models.map((a) => BEDROCK_ARN.exec(a)?.[3]).filter(Boolean));
      push("inference-profile", p.inferenceProfileArn, {
        status: V.oneOf(V.PROFILE_STATUS, p.status), updatedDay: dayOf(p.updatedAt),
        attrs: { type: "APPLICATION", modelCount: models.length, modelFamily: fams.length === 1 ? fams[0] : fams.length ? "mixed" : null, multiRegion: regions.size > 1 }
      });
    }

    // ---- Bedrock AgentCore runtimes ----
    for (const r of list("list-agent-runtimes") || []) {
      if (!BEDROCK_ARN.test(String(r.agentRuntimeArn))) { note(region, "list-agent-runtimes", "malformed"); continue; }
      push("agentcore-runtime", r.agentRuntimeArn, {
        status: V.oneOf(V.RUNTIME_STATUS, r.status), updatedDay: dayOf(r.lastUpdatedAt),
        attrs: { version: /^[1-9][0-9]{0,4}$/.test(String(r.agentRuntimeVersion)) ? Number(r.agentRuntimeVersion) : null }
      });
    }
  }

  records.sort((a, b) => (a.region < b.region ? -1 : a.region > b.region ? 1 : 0) || KIND_ORDER[a.kind] - KIND_ORDER[b.kind] || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  errors.sort((a, b) => `${a.region}|${a.command}`.localeCompare(`${b.region}|${b.command}`));
  return { account, records, errors };
}
