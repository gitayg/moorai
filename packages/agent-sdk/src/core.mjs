// The one place this package reaches the MoorAI engine. Everything the SDK decides goes through the
// repo's own decision functions (cli/hook-core.mjs and the two helpers the hook composes with it), so
// a detector or policy change lands here with no copy to keep in step.
//
// WHERE THE ENGINE COMES FROM. Two layouts, the same relative tree in both:
//   vendored  packages/agent-sdk/moorai/{cli,data,src,mcp-proxy}/…  written by scripts/vendor.mjs
//             before `npm pack` (prepack). This is what a published tarball carries: an npm install
//             of @moorai/agent-sdk has no repository around it.
//   in-repo   ../../../cli/… — the package directory inside the MoorAI repository. Development and
//             the repo's tests use this, so they exercise the live engine rather than a stale copy.
// The repository wins when this file sits inside it (a moorai package.json three levels up), so a vendored
// copy left behind by `npm pack` can never shadow the live engine in development. Anywhere else — an
// npm install — the vendored copy is the only one there is. Both are dependency-free ES modules.
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const VENDORED = join(HERE, "..", "moorai");
const REPO = join(HERE, "..", "..", "..");
const inRepo = (() => { try { return existsSync(join(REPO, "cli", "hook-core.mjs")) && JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")).name === "moorai"; } catch { return false; } })();
if (!inRepo && !existsSync(join(VENDORED, "cli", "hook-core.mjs"))) throw new Error("@moorai/agent-sdk: the MoorAI engine is missing (run `npm run vendor` in the package before packing it)");
export const ENGINE_ROOT = inRepo ? REPO : VENDORED;
export const ENGINE_LAYOUT = inRepo ? "in-repo" : "vendored";

const load = (rel) => import(pathToFileURL(join(ENGINE_ROOT, rel)).href);
export const hookCore = await load("cli/hook-core.mjs");
export const serverModeLib = await load("cli/server-mode.mjs");
export const mcpFileArgs = await load("cli/mcp-file-args.mjs");
export const secretEgress = await load("cli/secret-egress.mjs");
export const contentHashLib = await load("cli/content-hash.mjs");
export const inboundLib = await load("cli/inbound.mjs");
export const indexScanLib = await load("cli/index-scan.mjs");
export const provenance = await load("cli/provenance.mjs");
export const captureTiers = await load("data/capture-tiers.js");
export const modelEndpoints = await load("data/model-endpoints.js");
export const outboundUpload = await load("data/outbound-upload.js");
export const offlineDefault = await load("data/offline-default.js");
export const toolTagsLib = await load("cli/tool-tags.mjs");
export const exceptionsLib = await load("cli/exceptions.mjs");
