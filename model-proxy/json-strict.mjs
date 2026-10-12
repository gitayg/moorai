// Duplicate object keys in JSON text. JSON.parse keeps the LAST value of a repeated key; other parsers keep
// the first (simdjson's find_field, used by fast JSON clients) or throw (serde derive, Gson maps, .NET
// dictionaries). So `{"command":"ls","command":"rm -rf ~"}` is checked as one command and may run as the
// other: an argument string or a body with a repeated key cannot be checked for what the client will read.
// Keys are compared after JSON unescaping ("command" and "command" are the same key).
//
// `text` must already be valid JSON (callers run JSON.parse first); one pass, O(length).
export function hasDuplicateKeys(text) {
  const s = String(text);
  const stack = [];
  let expectKey = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) {
      let j = i + 1;
      for (;;) {
        j = s.indexOf('"', j);
        if (j < 0) return false;
        let k = j - 1, n = 0;
        while (k > i && s.charCodeAt(k) === 0x5c) { n++; k--; }
        if (n % 2 === 0) break;
        j++;
      }
      const top = stack[stack.length - 1];
      if (top && expectKey) {
        const raw = s.slice(i + 1, j);
        const key = raw.includes("\\") ? JSON.parse(s.slice(i, j + 1)) : raw;
        if (top.has(key)) return true;
        top.add(key);
        expectKey = false;
      }
      i = j;
    } else if (c === 0x7b) { stack.push(new Set()); expectKey = true; }
    else if (c === 0x5b) { stack.push(null); expectKey = false; }
    else if (c === 0x7d || c === 0x5d) { stack.pop(); expectKey = false; }
    else if (c === 0x2c) expectKey = Boolean(stack[stack.length - 1]);
  }
  return false;
}

export const DUPLICATE_KEY_REASON = "tool call arguments repeat a key, so a client may read a different value than the one checked";

// JSON.parse of a tool call's argument string, plus whether it repeats a key.
export function parseArgs(text) {
  let value = null;
  try { value = JSON.parse(text); } catch { return { value: null, dup: false }; }
  return { value, dup: value !== null && typeof value === "object" && hasDuplicateKeys(text) };
}
