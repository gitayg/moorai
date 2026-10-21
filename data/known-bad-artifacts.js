// Known-bad artifact digests: full SHA-256 values a public advisory published for a malicious package, its
// files or its second-stage payloads. Matched exactly (never by prefix) against a downloaded registry
// artifact and against every extracted file; a match is pkg-known-malicious (block). Content-free: only the
// digest is compared. Add a value only when the advisory prints all 64 hex characters.

export const KNOWN_BAD_SHA256 = new Map([
  // Public research write-up (October 2026): PyPI iflow-mcp_cmpxchg16-reddit-mcp 0.1.0, an MCP server that
  // fetches an image and runs Python hidden in it (remote code fetch-and-execute).
  ["5e77fa2a506e1ce6f0726faa502a5bdd0fccd598bd835c7cd6b69963de550198", "iflow-mcp_cmpxchg16-reddit-mcp 0.1.0 wheel"],
  ["163293b10474b29f53e568c6c070de287b057ad1acf89fa755d224262af39478", "iflow-mcp_cmpxchg16-reddit-mcp 0.1.0 source archive"],
  ["0012b35b2dc2213c720c92476aa2abca4c6a08052ed4d20692a6c0b970ba847e", "reddit_mcp/server.py (wheel, source archive and upstream)"],
  ["970659f5132d021aaf2ff12dfcf1b098a3a956c5c4dbc608da229b40d94a8453", "reddit.png stego image (retrieved 2026-10-15)"],
  ["7568ca4fd110561020373fbfeb0fa6a36aaf241a59cd5e621a275199e64aa520", "script decoded from the image"]
]);

export function isKnownBadSha256(hex, set = KNOWN_BAD_SHA256) {
  return typeof hex === "string" && hex.length === 64 && set.has(hex.toLowerCase());
}
