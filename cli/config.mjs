import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// Resolves the agent's management binding: the provision file dropped by the unique
// installer (~/.moorai/config.json), with env overrides and a localhost fallback.
export function loadConfig() {
  const fallback = {
    serverUrl: process.env.MoorAI_SERVER || "http://localhost:8787",
    tenant: process.env.MoorAI_TENANT || "unprovisioned"
  };
  // The Rust host writes ~/.moorai/config.json; pre-rebrand installs used ~/.curaiq and older ones
  // ~/.raiseme. Prefer newest, fall back through the legacy dirs, then to env/localhost.
  for (const dir of [".moorai", ".curaiq", ".raiseme"]) {
    try {
      const c = JSON.parse(readFileSync(join(homedir(), dir, "config.json"), "utf8"));
      return { serverUrl: c.serverUrl || fallback.serverUrl, tenant: c.tenant || fallback.tenant, installToken: c.installToken || "" };
    } catch { /* try next */ }
  }
  return fallback;
}
