#!/usr/bin/env node
// moorai-cloud-inventory — read-only, content-free inventory of what a customer has defined on a cloud
// AI platform. First platform: Amazon Bedrock (Agents, aliases, action groups, knowledge bases,
// guardrails, custom models, provisioned throughput, application inference profiles, AgentCore runtimes).
//
//   moorai-cloud-inventory bedrock --from DIR [--regions r1,r2] [--out FILE] [--post]
//   moorai-cloud-inventory bedrock --run [--regions r1,r2] [--profile NAME] [--export DIR] [--out FILE] [--post]
//   moorai-cloud-inventory bedrock --policy
//
// --from reads AWS CLI JSON the customer exported (layout in cloud/bedrock/commands.mjs).
// --run   shells out to the customer's own `aws` CLI with their own credentials/profile. Never implied.
// --policy prints the minimum IAM policy for --run.
// Exit: 0 ok · 2 usage / not enrolled · 3 AWS could not be read at all (no CLI, no credentials).
// See cloud/README.md.
import { writeFileSync } from "node:fs";
import { deriveKey } from "../cli/content-hash.mjs";
import { loadConfig } from "../cli/config.mjs";
import { readExport, writeExport, REGION_RE } from "./bedrock/read-export.mjs";
import { collectViaCli, FatalCollectError } from "./bedrock/collect-cli.mjs";
import { iamPolicy } from "./bedrock/commands.mjs";
import { buildInventory, postBody } from "./inventory.mjs";
import { postInventory } from "./post.mjs";
import { exitWhenDrained } from "../cli/exit-drain.mjs";

const USAGE = "usage: moorai-cloud-inventory bedrock (--from DIR | --run [--profile NAME] [--export DIR] | --policy) [--regions r1,r2] [--out FILE] [--post]";
const fail = (code, msg) => { process.stderr.write(`moorai-cloud-inventory: ${msg}\n`); return code; };
const die = (code, msg) => process.exit(fail(code, msg));

function parse(argv) {
  const o = { flags: new Set() };
  const val = new Set(["--from", "--regions", "--profile", "--export", "--out"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (val.has(a)) { if (argv[i + 1] === undefined) die(2, `${a} needs a value\n${USAGE}`); o[a.slice(2)] = argv[++i]; }
    else if (["--run", "--post", "--policy", "--help", "-h"].includes(a)) o.flags.add(a);
    else if (!o.platform && !a.startsWith("-")) o.platform = a;
    else die(2, `unknown argument ${JSON.stringify(a)}\n${USAGE}`);
  }
  return o;
}

async function main() {
  const o = parse(process.argv.slice(2));
  if (o.flags.has("--help") || o.flags.has("-h")) { process.stdout.write(USAGE + "\n"); return 0; }
  if (o.platform !== "bedrock") die(2, `only "bedrock" is supported\n${USAGE}`);
  if (o.flags.has("--policy")) { process.stdout.write(JSON.stringify(iamPolicy(), null, 2) + "\n"); return 0; }
  const run = o.flags.has("--run");
  if (run === Boolean(o.from)) die(2, `pass exactly one of --from DIR or --run\n${USAGE}`);
  if (o.export && !run) die(2, "--export only applies to --run");

  let regions = o.regions ? o.regions.split(",").map((s) => s.trim()).filter(Boolean) : null;
  if (run && !regions) {
    const env = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION;
    regions = env ? [env] : null;
    if (!regions) die(2, "no region: pass --regions r1,r2 or set AWS_REGION / AWS_DEFAULT_REGION");
  }
  if (regions && regions.some((r) => !REGION_RE.test(r))) die(2, "--regions takes AWS region names, e.g. us-east-1,eu-west-1");

  const config = loadConfig();
  const key = deriveKey(config.installToken);
  if (!key) die(2, "not enrolled: no install token in ~/.moorai/config.json — enroll this device first; resource ids are keyed to your tenant");

  let bundle;
  if (run) {
    try {
      bundle = await collectViaCli({ regions, profile: o.profile });
    } catch (e) {
      if (e instanceof FatalCollectError) die(3, `could not read AWS (${e.cls}); check that the AWS CLI is installed and \`aws sts get-caller-identity\` works for this profile`);
      throw e;
    }
    if (o.export) writeExport(bundle, o.export);
  } else {
    bundle = readExport(o.from, { regions });
  }

  let built;
  try { built = buildInventory(bundle, { key }); } catch (e) { die(2, e.message); }
  const { inventory, errors, summary } = built;
  const text = JSON.stringify(inventory, null, 2) + "\n";
  if (o.out) writeFileSync(o.out, text); else process.stdout.write(text);

  const flags = Object.entries(summary.flags).map(([f, n]) => `${f}=${n}`).join(" ") || "none";
  process.stderr.write(`bedrock: ${summary.records} records in ${summary.regions} region(s); flags: ${flags}\n`);
  for (const e of errors) process.stderr.write(`  not read: ${e.region ?? "-"} ${e.command}: ${e.class}\n`);

  if (o.flags.has("--post")) {
    // Past this fetch a failure returns its code rather than calling die(): process.exit() right after
    // fetch() aborts the process on Windows (0xC0000409) — see cli/exit-drain.mjs.
    let r;
    try { r = await postInventory(postBody(inventory), { serverUrl: config.serverUrl, installToken: config.installToken }); }
    catch (e) { return fail(1, `could not reach the console (${e.name})`); }
    if (r.status < 200 || r.status >= 300) return fail(1, `console refused the inventory (HTTP ${r.status})`);
    process.stderr.write(`posted ${inventory.records.length} records to the console\n`);
  }
  return 0;
}

main().then((c) => exitWhenDrained(c), (e) => exitWhenDrained(fail(1, e.message)));
