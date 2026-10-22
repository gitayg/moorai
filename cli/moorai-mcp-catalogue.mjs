#!/usr/bin/env node
// moorai-mcp-catalogue — verify a signed MoorAI MCP catalogue file, or report the state of the copy this
// device caches (~/.moorai/mcp-catalogue.json). Output is JSON and content-free: a status, counts, the
// sequence number and the signing key id.
//
//   moorai-mcp-catalogue verify <file> [--pubkey <base64 SPKI DER>]   exit 0 = signature ok, 1 = not
//   moorai-mcp-catalogue status                                        the cached copy, re-verified
//
// Trust keys: --pubkey, MOORAI_CATALOGUE_PUBKEY, /etc/moorai/catalogue.pub and the built-in list.
import { readFileSync } from "node:fs";
import { verifyCatalogue, catalogueTrustKeys, readCatalogue } from "./mcp-catalogue.mjs";

function summary(status, cat, keyId) {
  const entries = cat && Array.isArray(cat.entries) ? cat.entries : [];
  return {
    status,
    ...(cat ? { seq: cat.seq, issuedAt: cat.issuedAt, expiresAt: cat.expiresAt || null, entries: entries.length, doNotInstall: entries.filter((e) => e && e.status === "do-not-install").length } : {}),
    ...(keyId ? { keyId } : {})
  };
}

const [cmd, ...rest] = process.argv.slice(2);
const flag = (n) => { const i = rest.indexOf(n); return i >= 0 ? rest[i + 1] : undefined; };
const out = (o, code) => { process.stdout.write(JSON.stringify(o, null, 2) + "\n"); process.exit(code); };

if (cmd === "verify" && rest[0]) {
  let cat = null;
  try { cat = JSON.parse(readFileSync(rest[0], "utf8")); } catch { out({ status: "unreadable" }, 1); }
  const pk = flag("--pubkey");
  const v = verifyCatalogue(cat, { keys: catalogueTrustKeys({ policyKeys: pk ? [pk] : [] }) });
  out(summary(v.status, v.trusted ? cat : null, v.keyId), v.trusted ? 0 : 1);
} else if (cmd === "status") {
  const r = readCatalogue({});
  out(summary(r.status, r.catalogue, r.keyId), 0);
} else {
  process.stdout.write("usage: moorai-mcp-catalogue verify <file> [--pubkey <base64 SPKI DER>] | status\n");
  process.exit(cmd === "--help" || cmd === "-h" ? 0 : 2);
}
