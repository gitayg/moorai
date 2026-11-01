// Canonical JSON: the one serializer behind every signed digest that crosses the device boundary — the signed
// policy (cli/hook-core.mjs policyDigest, byte-identical to the console's canonicalJson), the approval actionHash
// (cli/approval-routing.mjs) and the approval receipt (cli/approval-receipts.mjs, docs/approval-receipts.md §2).
//
//   * Object keys sorted recursively, by Array.prototype.sort's default order (UTF-16 code units; for ASCII keys
//     the same as byte order).
//   * No insignificant whitespace: "," and ":" with nothing around them.
//   * Strings and numbers exactly as JSON.stringify writes them (UTF-8 output, "\"" "\\" and control characters
//     escaped, \b \f \n \r \t short forms, others \u00xx lowercase, "/" and non-ASCII not escaped; numbers in
//     ECMAScript Number::toString form: integers as digits, -0 as 0, non-integers in shortest round-trip form,
//     1e21 and above or below 1e-6 in exponent form such as 1e+21, NaN and Infinity as null).
//   * undefined, at the top or as an object value, is written as null (JSON input never holds it).
export function canonicalJson(v) {
  if (v === undefined) return "null";
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
}
