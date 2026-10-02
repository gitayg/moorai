// `--run`: build the bundle by shelling out to the customer's own AWS CLI.
//
// Credentials: this process never reads, receives or passes one. The CLI resolves them itself from its
// normal chain; the child inherits this process's environment unchanged, so AWS_PROFILE, AWS_REGION and
// friends behave exactly as they do in the customer's shell (AWS CLI User Guide, environment variables:
// AWS_PROFILE "overrides the behavior of using the profile named [default]"; `--profile` overrides it).
//
// What reaches this process: only the `--query` projection from commands.mjs. What reaches the terminal:
// command names, regions and an error class. AWS error text is classified and dropped, never printed —
// an AccessDenied message carries the caller's ARN and account id.
import { execFile } from "node:child_process";
import { COMMANDS, STS, byName, cliArgs } from "./commands.mjs";
import { emptyBundle, ACCOUNT_RE } from "./read-export.mjs";

const ID10 = /^[0-9a-zA-Z]{10}$/;
const MAX_PAGES = 100;

export class FatalCollectError extends Error {
  constructor(cls) { super(`aws ${cls}`); this.cls = cls; }
}

export function classify(err, stderr = "") {
  if (err && err.code === "ENOENT") return "cli-not-found";
  if (err && (err.killed || err.signal === "SIGTERM")) return "timeout";
  const s = String(stderr);
  if (/AccessDenied|not authorized|UnauthorizedOperation/i.test(s)) return "access-denied";
  if (/ExpiredToken|InvalidClientTokenId|UnrecognizedClient|Unable to locate credentials|SignatureDoesNotMatch|security token included in the request is invalid|The config profile .* could not be found/i.test(s)) return "auth";
  if (/Could not connect|EndpointConnectionError|Unknown endpoint|Could not resolve/i.test(s)) return "unavailable";
  if (/Invalid choice|argument operation|argument command/i.test(s)) return "cli-unsupported";
  if (/ResourceNotFound/i.test(s)) return "not-found";
  if (/Throttl|TooManyRequests/i.test(s)) return "throttled";
  return "error";
}

function execAws(bin, args, { env, timeoutMs }) {
  return new Promise((resolve) => {
    execFile(bin, args, { env, timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
      if (err) return resolve({ ok: false, cls: classify(err, stderr) });
      try { resolve({ ok: true, json: JSON.parse(stdout) }); } catch { resolve({ ok: false, cls: "malformed" }); }
    });
  });
}

// One command, all pages. The CLI paginates these operations itself (each reference page: "is a
// paginated operation. Multiple API calls may be issued in order to retrieve the entire data set");
// a `NextToken` only appears in its output when it stopped early, and is followed with --starting-token.
async function runCommand(cmd, ctx, region, params) {
  let token, merged;
  for (let page = 0; page < MAX_PAGES; page++) {
    const r = await execAws(ctx.bin, cliArgs(cmd, { region, profile: ctx.profile, params, startingToken: token }), ctx);
    if (!r.ok) return r;
    const out = r.json && typeof r.json === "object" ? r.json : {};
    if (!merged) merged = { ...out };
    else if (cmd.listKey && Array.isArray(out[cmd.listKey])) merged[cmd.listKey] = [...(merged[cmd.listKey] || []), ...out[cmd.listKey]];
    token = typeof out.NextToken === "string" && out.NextToken ? out.NextToken : undefined;
    delete merged.NextToken;
    if (!token) return { ok: true, json: merged };
  }
  return { ok: false, cls: "too-many-pages" };
}

async function pool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) await fn(items[i++]); }));
}

export async function collectViaCli({ regions, profile, bin = process.env.MOORAI_AWS_CLI || "aws", env = process.env, timeoutMs = 60000, concurrency = 4, onProgress = () => {} } = {}) {
  const ctx = { bin, profile, env, timeoutMs };
  const b = emptyBundle();
  const fail = (region, command, cls) => b.errors.push({ region, command, class: cls });

  const who = await execAws(bin, [STS.service, STS.op, "--region", regions[0], "--output", "json", "--no-cli-pager", "--query", STS.query, ...(profile ? ["--profile", profile] : [])], ctx);
  if (!who.ok) throw new FatalCollectError(who.cls);
  if (!ACCOUNT_RE.test(String(who.json?.Account))) throw new FatalCollectError("malformed");
  b.account = String(who.json.Account);

  for (const region of regions) {
    const R = (b.regions[region] = {});
    const one = async (cmd, params, store) => {
      const r = await runCommand(cmd, ctx, region, params);
      onProgress(region, cmd.name);
      if (!r.ok) { fail(region, cmd.name, r.cls); if (r.cls === "cli-not-found") throw new FatalCollectError(r.cls); return null; }
      store(r.json);
      return r.json;
    };
    for (const cmd of COMMANDS.filter((c) => c.scope === "region")) await one(cmd, {}, (j) => (R[cmd.name] = j));

    const agents = (R["list-agents"]?.agentSummaries || []).map((s) => s?.agentId).filter((id) => ID10.test(String(id)));
    for (const name of ["get-agent", "list-agent-aliases", "list-agent-action-groups", "list-agent-knowledge-bases"]) if (agents.length) R[name] = {};
    await pool(agents, concurrency, async (agentId) => {
      for (const name of ["get-agent", "list-agent-aliases", "list-agent-knowledge-bases"]) await one(byName[name], { agentId }, (j) => (R[name][agentId] = j));
      const ags = await one(byName["list-agent-action-groups"], { agentId }, (j) => (R["list-agent-action-groups"][agentId] = j));
      for (const ag of (ags?.actionGroupSummaries || []).map((a) => a?.actionGroupId).filter((id) => ID10.test(String(id)))) {
        R["get-agent-action-group"] ||= {};
        await one(byName["get-agent-action-group"], { agentId, actionGroupId: ag }, (j) => (R["get-agent-action-group"][`${agentId}.${ag}`] = j));
      }
    });
  }
  return b;
}
