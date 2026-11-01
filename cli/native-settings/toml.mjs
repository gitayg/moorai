// Minimal deterministic TOML writer for the files MoorAI generates (Codex requirements.toml, Gemini CLI
// policy files). Strings are JSON-quoted: a JSON string literal with \" \\ \n \t \uXXXX escapes is also a
// valid TOML basic string. Keys are bare when TOML allows it, quoted otherwise.

const BARE = /^[A-Za-z0-9_-]+$/;
export const tomlKey = (k) => (BARE.test(k) ? k : JSON.stringify(k));
export function tomlValue(v) {
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "boolean" || typeof v === "number") return String(v);
  if (Array.isArray(v)) return `[${v.map(tomlValue).join(", ")}]`;
  if (v && typeof v === "object") {
    const e = Object.entries(v);
    return e.length ? `{ ${e.map(([k, x]) => `${tomlKey(k)} = ${tomlValue(x)}`).join(", ")} }` : "{}";
  }
  throw new TypeError("unsupported TOML value");
}
// [["a", "b"], { k: v }] -> "[a.b]\nk = v\n"; an empty object still writes the header (an empty table).
export const tomlTable = (path, kv) => `[${path.map(tomlKey).join(".")}]\n${Object.entries(kv).map(([k, v]) => `${tomlKey(k)} = ${tomlValue(v)}\n`).join("")}`;
export const tomlArrayTable = (name, kv) => `[[${tomlKey(name)}]]\n${Object.entries(kv).map(([k, v]) => `${tomlKey(k)} = ${tomlValue(v)}\n`).join("")}`;
