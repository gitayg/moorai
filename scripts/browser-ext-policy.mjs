#!/usr/bin/env node
// Render the Chrome / Edge force-install and managed-settings policy files for MoorAI Browser Guard.
//
//   node scripts/browser-ext-policy.mjs --id <32-letter extension id> --out <dir>
//        [--server-url https://console.example.com] [--install-token <token>] [--mode coach|block]
//        [--lock] [--no-report] [--update-url <update manifest URL>] [--index 1]
//
// The extension id comes from the store listing once the owner has published it (or from a self-hosted
// build). --update-url replaces the store update URL for a self-hosted build; off-store force-install
// works only on domain-joined Windows and MDM-managed macOS.
//
// Writes into --out:
//   chrome-macos.mobileconfig, edge-macos.mobileconfig   MDM profile (Jamf, Intune macOS custom profile)
//   chrome-windows.reg, edge-windows.reg                 registry policy (GPO preferences, scripts)
//   chrome-linux-policy.json                             /etc/opt/chrome/policies/managed/
//   moorai-browser-guard.admx, en-US/moorai-browser-guard.adml   GPO / Intune imported ADMX (managed settings)
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TPL = join(ROOT, "browser-ext", "policy");
export const STORE_UPDATE_URL = { chrome: "https://clients2.google.com/service/update2/crx", edge: "https://edge.microsoft.com/extensionwebstorebase/v1/crx" };
const BROWSERS = {
  chrome: { name: "Google Chrome", domain: "com.google.Chrome", reg: "Google\\Chrome" },
  edge: { name: "Microsoft Edge", domain: "com.microsoft.Edge", reg: "Microsoft\\Edge" }
};

function die(m) { process.stderr.write(`browser-ext-policy: ${m}\n`); process.exit(2); }
const argv = process.argv.slice(2);
const arg = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };

const xml = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const regStr = (s) => String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
function uuid(seed) {
  const h = createHash("sha256").update(seed).digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`.toUpperCase();
}
const fill = (tpl, vars) => tpl.replace(/__([A-Z_]+)__/g, (m, k) => (k in vars ? vars[k] : m));

const id = arg("--id");
if (!id || !/^[a-p]{32}$/.test(id)) die("--id must be the 32-letter (a-p) extension id");
const out = arg("--out");
if (!out) die("--out is required");
const mode = arg("--mode");
if (mode !== undefined && !["coach", "block"].includes(mode)) die("--mode must be coach or block");
const serverUrl = arg("--server-url");
if (serverUrl !== undefined) { try { new URL(serverUrl); } catch { die("--server-url is not a URL"); } }
const index = arg("--index") || "1";
if (!/^[1-9][0-9]{0,3}$/.test(index)) die("--index must be a positive integer");
const updateUrl = arg("--update-url");

// Managed settings, in managed-schema.json order; only what was asked for.
const managed = {};
if (serverUrl !== undefined) managed.serverUrl = serverUrl;
const token = arg("--install-token");
if (token !== undefined) managed.installToken = token;
if (mode !== undefined) managed.mode = mode;
managed.reportEnabled = !argv.includes("--no-report");
if (argv.includes("--lock")) managed.lockSettings = true;

const plistBlock = Object.entries(managed).map(([k, v]) => `                <key>${k}</key>\n                ${typeof v === "boolean" ? `<${v}/>` : `<string>${xml(v)}</string>`}`).join("\n");
const regBlock = Object.entries(managed).map(([k, v]) => (typeof v === "boolean" ? `"${k}"=dword:0000000${v ? 1 : 0}` : `"${k}"="${regStr(v)}"`)).join("\r\n");

mkdirSync(join(out, "en-US"), { recursive: true });
const mac = readFileSync(join(TPL, "macos.mobileconfig.tmpl"), "utf8");
const reg = readFileSync(join(TPL, "windows.reg.tmpl"), "utf8");
for (const [key, b] of Object.entries(BROWSERS)) {
  const vars = { EXTENSION_ID: id, UPDATE_URL: xml(updateUrl || STORE_UPDATE_URL[key]), BROWSER: key, BROWSER_NAME: b.name, BROWSER_DOMAIN: b.domain, MANAGED_PLIST: plistBlock, UUID_PAYLOAD: uuid(`${id}:${key}:payload`), UUID_PROFILE: uuid(`${id}:${key}:profile`) };
  writeFileSync(join(out, `${key}-macos.mobileconfig`), fill(mac, vars));
  const rvars = { EXTENSION_ID: id, UPDATE_URL: regStr(updateUrl || STORE_UPDATE_URL[key]), BROWSER_NAME: b.name, REG_VENDOR: b.reg, INDEX: index, MANAGED_REG: regBlock };
  writeFileSync(join(out, `${key}-windows.reg`), fill(reg, rvars).replace(/\r?\n/g, "\r\n"));
}
writeFileSync(join(out, "chrome-linux-policy.json"), JSON.stringify({ ExtensionInstallForcelist: [`${id};${updateUrl || STORE_UPDATE_URL.chrome}`], "3rdparty": { extensions: { [id]: managed } } }, null, 2) + "\n");
writeFileSync(join(out, "moorai-browser-guard.admx"), fill(readFileSync(join(TPL, "moorai-browser-guard.admx.tmpl"), "utf8"), { EXTENSION_ID: id }));
writeFileSync(join(out, "en-US", "moorai-browser-guard.adml"), fill(readFileSync(join(TPL, "moorai-browser-guard.adml.tmpl"), "utf8"), { EXTENSION_ID: id }));
process.stdout.write(`wrote policy files for ${id} to ${out}\n`);
