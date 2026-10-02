// The last gate before an inventory leaves the normaliser: every record is checked against a closed
// schema — exact key sets, closed vocabularies, keyed-hash ids, integers, booleans and dates. Nothing
// shaped like free text can pass, so a future edit that copies a name, a description or an ARN into a
// record fails here (and in test/cloud-inventory.test.mjs) instead of shipping.
//
// Problems are reported by PATH only, never by value: the value is the thing that must not be printed.
import * as V from "./bedrock/vocab.mjs";
import { FLAGS } from "./bedrock/risk.mjs";

const HASH = /^h2:[0-9a-f]{16}$/;
const REGION = /^[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d{1,2}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const FAMILY = /^[a-z0-9-]{1,32}\.[a-z0-9]{1,32}$/;
const OPAQUE_FAMILIES = ["custom-model", "application-inference-profile", "provisioned-model", "other", "mixed"];

const bool = (v) => v === null || typeof v === "boolean";
const int = (v) => v === null || (Number.isInteger(v) && v >= 0 && v < 1e6);
const fam = (v) => v === null || (typeof v === "string" && (FAMILY.test(v) || OPAQUE_FAMILIES.includes(v)));
const oneOf = (list) => (v) => v === null || list.includes(v) || v === "OTHER";

const ATTRS = {
  agent: { modelFamily: fam, guardrailAttached: bool, guardrailVersion: oneOf(["DRAFT", "numbered"]), codeInterpreter: bool, computerUse: bool,
    userInput: bool, actionGroupCount: int, knowledgeBaseCount: int, aliasCount: int, memoryEnabled: bool, customerKey: bool },
  alias: { invocationState: oneOf(V.ALIAS_INVOCATION), routesTo: oneOf(["draft", "version"]), provisionedThroughput: bool, testAlias: bool },
  "action-group": { signature: oneOf([...V.PARENT_SIGNATURES, "custom"]), executor: oneOf(["lambda", "return-control", "none"]) },
  "knowledge-base": { agentCount: int, unguardedAgentCount: int },
  guardrail: { version: oneOf(["DRAFT", "numbered"]), crossRegion: bool, agentCount: int },
  "custom-model": { customizationType: oneOf(V.CUSTOMIZATION_TYPES), baseModelFamily: fam, shared: bool, provisioned: bool },
  "provisioned-throughput": { modelUnits: int, commitment: bool, modelKind: oneOf(["custom", "foundation", "other"]), modelFamily: fam },
  "inference-profile": { type: oneOf(V.PROFILE_TYPES), modelCount: int, modelFamily: fam, multiRegion: bool },
  "agentcore-runtime": { version: int }
};

const STATUS = {
  agent: V.AGENT_STATUS, alias: V.ALIAS_STATUS, "action-group": V.ENABLED_STATE, "knowledge-base": V.KB_STATUS, guardrail: V.GUARDRAIL_STATUS,
  "custom-model": V.CUSTOM_MODEL_STATUS, "provisioned-throughput": V.PT_STATUS, "inference-profile": V.PROFILE_STATUS, "agentcore-runtime": V.RUNTIME_STATUS
};

const TOP = {
  platform: (v) => v === "bedrock",
  region: (v) => typeof v === "string" && REGION.test(v),
  kind: (v) => V.KINDS.includes(v),
  id: (v) => typeof v === "string" && HASH.test(v),
  parent: (v) => v === null || (typeof v === "string" && HASH.test(v)),
  status: null, attrs: null, flags: null,
  updatedDay: (v) => v === null || (typeof v === "string" && DAY.test(v))
};

export function recordProblems(r) {
  if (!r || typeof r !== "object" || Array.isArray(r)) return ["record"];
  const p = [];
  for (const k of Object.keys(r)) if (!(k in TOP)) p.push(k);
  for (const [k, ok] of Object.entries(TOP)) if (ok && !ok(r[k] === undefined ? null : r[k])) p.push(k);
  for (const k of ["platform", "region", "kind", "id"]) if (r[k] == null && !p.includes(k)) p.push(k);
  const spec = ATTRS[r.kind];
  if (!spec) return p;
  if (!oneOf(STATUS[r.kind])(r.status === undefined ? null : r.status)) p.push("status");
  const a = r.attrs;
  if (!a || typeof a !== "object" || Array.isArray(a)) p.push("attrs");
  else {
    for (const k of Object.keys(a)) if (!(k in spec)) p.push(`attrs.${k}`);
    for (const [k, ok] of Object.entries(spec)) if (!(k in a) || !ok(a[k])) p.push(`attrs.${k}`);
  }
  if (!Array.isArray(r.flags) || r.flags.some((f) => !FLAGS[f] || FLAGS[f].kind !== r.kind)) p.push("flags");
  return p;
}

export function assertContentFree(records) {
  const bad = [];
  records.forEach((r, i) => { const p = recordProblems(r); if (p.length) bad.push(`record ${i} (${V.KINDS.includes(r?.kind) ? r.kind : "?"}): ${p.join(", ")}`); });
  if (bad.length) throw new Error(`inventory refused, fields outside the content-free schema: ${bad.join("; ")}`);
  return records;
}
