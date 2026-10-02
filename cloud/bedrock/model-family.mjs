// A model reference reduced to a coarse, AWS-public family id: "anthropic.claude", "amazon.nova",
// "meta.llama3". Never the reference itself — an ARN carries the account id, a custom model's ARN carries
// the customer's model id, and the version suffix adds nothing to an inventory.
//
// Inputs seen in Bedrock: a model id ("anthropic.claude-3-5-sonnet-20240620-v1:0"), a cross-region
// inference profile id ("us.anthropic.claude-..."), or an ARN of a foundation model, an inference profile,
// an application inference profile, a custom model or a provisioned model (Agent.foundationModel,
// InferenceProfileModel.modelArn, ProvisionedModelSummary.modelArn, CustomModelSummary.baseModelArn).

const GEO = /^(us|eu|apac|us-gov|global|jp|au|ca)\./;
const FAMILY = /^[a-z0-9-]{1,32}\.[a-z0-9]{1,32}$/;
const ARN = /^arn:aws[a-z-]*:bedrock:[a-z0-9-]*:[0-9]*:([a-z-]+)\/(.+)$/;
const OPAQUE = { "custom-model": "custom-model", "application-inference-profile": "application-inference-profile", "provisioned-model": "provisioned-model" };

function fromId(id) {
  const m = /^([a-z0-9-]+)\.([a-z]+[0-9]*)/.exec(String(id).replace(GEO, ""));
  if (!m) return "other";
  const fam = `${m[1]}.${m[2]}`;
  return FAMILY.test(fam) ? fam : "other";
}

export function modelFamily(ref) {
  if (typeof ref !== "string" || !ref) return null;
  const a = ARN.exec(ref);
  if (a) {
    const [, type, rest] = a;
    if (OPAQUE[type]) return OPAQUE[type];
    if (type === "foundation-model" || type === "inference-profile") return fromId(rest);
    return "other";
  }
  if (ref.startsWith("arn:")) return "other";
  return fromId(ref);
}
