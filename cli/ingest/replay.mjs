// Replays one recorded hook input through the live hook's decision functions (cli/hook-core.mjs,
// cli/inbound.mjs, cli/prompt-scan.mjs). The per-tool composition — which function runs on which text,
// at which stage, with which ctx — follows cli/moorai-hook.mjs main(), handlePostToolUse() and
// handlePrompt() branch by branch. That composition is glue, not detection: every verdict comes from
// the imported functions, so a detector or policy change reaches the replay with no edit here.
// test/ingest-parity.test.mjs runs the real hook process on the same inputs and asserts the same
// decision, which is what catches the glue drifting from the hook.
//
// Not replayed, because each needs state or I/O from the moment of the call rather than the record:
// files a command reads (read from disk now, they could differ), file metadata (#72), MCP file
// arguments, local secret-value egress (#65, needs today's secrets), MCP reputation (network),
// fetch-then-exec across calls, deletion volume, circuit breaker, learned drift, session escalation,
// intent alignment and model escalation.
import os from "node:os";
import {
  buildEngine, decideText, decideCredFileRead, decideAgentStateWrite, decideEndpoints, decideEnvelope,
  extractReadPaths, embeddedScripts, mcpGateway, mcpFloor, threatActionFor, fileScanText, isEnvTemplate,
  PS_OUTBOUND_UPLOAD
} from "../hook-core.mjs";
import { decideInbound, surfaceOf, inboundText } from "../inbound.mjs";
import { promptScanPlan, promptBlockers } from "../prompt-scan.mjs";
import { OUTBOUND_UPLOAD } from "../../data/outbound-upload.js";
import { extractHosts } from "../../data/model-endpoints.js";
import { shellMemoryWrites } from "../../data/poisoning-tells.js";
import { CAPS } from "../../mcp-proxy/tool-scan.mjs";
import { actorHash } from "../content-hash.mjs";

const RANK = { allow: 1, ask: 2, deny: 3 };
const FILE_CAP = 262144; // the hook's readFileCapped: only the first 256 KiB of a file is scanned
const SHELL_TOOLS = new Set(["Bash", "PowerShell"]);
const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);
const TOOL_ALIASES = { Shell: "Bash" };
const POST_TOOLS = new Set(["WebFetch", "WebSearch", "Bash", "PowerShell", "Agent", "Task"]);

// The hook's policy when none is loaded on a fail-open device (cli/moorai-hook.mjs NO_POLICY_BASELINE,
// not exported there because importing that module runs the hook).
export const NO_POLICY_BASELINE = { captureTier: "content-free", builtinDefault: true };

function writeText(tool, ti) {
  if (tool === "Write") return typeof ti.content === "string" ? ti.content : "";
  if (tool === "Edit") return typeof ti.new_string === "string" ? ti.new_string : "";
  if (tool === "NotebookEdit") return typeof ti.new_source === "string" ? ti.new_source : "";
  if (tool === "MultiEdit") return (Array.isArray(ti.edits) ? ti.edits : []).map((e) => (e && typeof e.new_string === "string" ? e.new_string : "")).join("\n");
  return "";
}

// One verdict under construction: decision, findings tagged with the stage the hook reports them at.
function verdict() { return { decision: "allow", findings: [], maskIds: [] }; }
function merge(v, d, stage) {
  for (const f of d.findings || []) v.findings.push({ ...f, stage });
  for (const id of d.maskIds || []) if (!v.maskIds.includes(id)) v.maskIds.push(id);
  if (RANK[d.decision] > RANK[v.decision]) v.decision = d.decision;
}
function raise(v, decision) { if (RANK[decision] > RANK[v.decision]) v.decision = decision; }
function synthetic(v, threatId, category, riskLevel, stage, decision) {
  v.findings.push({ threatId, category, riskLevel, match: "", detectorId: "", stage });
  if (decision) raise(v, decision);
}
// A finding whose action is "mask" did not raise the decision; the host would have rewritten the span.
function settle(v) { if (v.decision === "allow" && v.maskIds.length) v.decision = "mask"; return v; }

export function createReplayer(policy, { actor = actorHash(os.userInfo().username, os.hostname()) } = {}) {
  const engine = buildEngine(policy);

  const endpoints = (v, text, stage = "egress") => {
    const ep = decideEndpoints(policy, text);
    if (ep.decision === "deny") synthetic(v, 63, "Unapproved model endpoint", "High", stage, "deny");
  };
  const envelope = (v, ctx, stage) => {
    const mode = policy?.entitlementMode || "off";
    if (mode === "off") return;
    const d = decideEnvelope(policy, { ...ctx, actor });
    if (d.inScope) return;
    synthetic(v, 64, "Agent entitlement drift", "High", stage, mode === "block" ? "deny" : null);
  };

  // PreToolUse. `mask`: the host could rewrite this input (Claude Code yes; the Codex shim no).
  function pre(input, { mask, readText } = {}) {
    const tool = TOOL_ALIASES[input.tool_name] || input.tool_name || "";
    const ti = input.tool_input && typeof input.tool_input === "object" ? input.tool_input : {};
    const canMask = mask && !TOOL_ALIASES[input.tool_name];
    const v = verdict();
    if (tool === "Read") {
      const text = fileScanText(Buffer.from(String(readText || "")).subarray(0, FILE_CAP));
      merge(v, decideText(engine, policy, text, "file", { ctx: { template: isEnvTemplate(ti.file_path) } }), "file");
      merge(v, decideCredFileRead(engine, policy, ti.file_path), "file");
      envelope(v, { tool: "Read", paths: [ti.file_path] }, "file");
      return { tool, ...settle(v) };
    }
    if (SHELL_TOOLS.has(tool)) {
      const ps = tool === "PowerShell";
      const cmd = typeof ti.command === "string" ? ti.command : "";
      const scripts = embeddedScripts(cmd, ps ? { shell: "powershell" } : undefined);
      const shellText = [cmd, ...scripts].join("\n");
      const uploading = OUTBOUND_UPLOAD.some((r) => r.test(shellText)) || (ps && PS_OUTBOUND_UPLOAD.some((r) => r.test(shellText)));
      const cmdEgress = uploading || extractHosts(cmd).length > 0;
      const readPaths = extractReadPaths(cmd, { ...(ps ? { shell: "powershell" } : {}), env: process.env, home: os.homedir(), insensitive: process.platform === "win32" });
      if (ps) for (const p of readPaths) merge(v, decideCredFileRead(engine, policy, p), "file");
      merge(v, decideText(engine, policy, cmd, "prompt", { ctx: { egress: cmdEgress }, mask: canMask }), "file");
      for (const w of shellMemoryWrites(shellText)) merge(v, decideText(engine, policy, w.text, "output", { ctx: { targetPath: w.path }, only: [22] }), "file");
      for (const s of scripts) merge(v, decideText(engine, policy, s, "prompt", { ctx: { egress: cmdEgress } }), "file");
      endpoints(v, cmd);
      envelope(v, { tool: "Bash", paths: readPaths }, "file");
      return { tool, ...settle(v) };
    }
    if (WRITE_TOOLS.has(tool)) {
      const path = ti.file_path || ti.notebook_path || "";
      const text = writeText(tool, ti);
      merge(v, decideText(engine, policy, text, "output", { ctx: { targetPath: path }, mask: canMask }), "output");
      merge(v, decideAgentStateWrite(engine, policy, path), "output");
      endpoints(v, text);
      envelope(v, { tool, paths: [path] }, "file");
      return { tool, ...settle(v) };
    }
    if (tool === "WebFetch") {
      const url = typeof ti.url === "string" ? ti.url : "";
      const prompt = typeof ti.prompt === "string" ? ti.prompt : "";
      merge(v, decideText(engine, policy, `${url}\n${prompt}`, "prompt", { ctx: { egress: true }, mask: canMask }), "egress");
      endpoints(v, url);
      envelope(v, { tool: "WebFetch" }, "egress");
      return { tool, ...settle(v) };
    }
    if (tool.startsWith("mcp__")) {
      const server = tool.split("__")[1] || "";
      const args = JSON.stringify(ti);
      const g = mcpGateway(engine, policy, { tool, server, args, mask: canMask });
      if (g.gate === "server") { synthetic(v, 0, "MCP: unapproved server", "High", "mcp", "deny"); return { tool, ...v }; }
      if (g.gate === "args") { synthetic(v, 0, "MCP: denied tool argument", "High", "mcp", "deny"); return { tool, ...v }; }
      envelope(v, { tool, mcpServer: server }, "egress");
      if (v.decision === "deny") return { tool, ...v };
      endpoints(v, args);
      if (v.decision === "deny") return { tool, ...v };
      merge(v, g, "egress");
      v.decision = mcpFloor(policy, v.decision);
      return { tool, ...settle(v) };
    }
    if (tool === "Task" || tool === "Agent") {
      const act = threatActionFor(policy, 66);
      const block = act === "block" || act === "kill";
      synthetic(v, 66, "Sub-agent / A2A delegation", "Medium", "behavior", block ? "deny" : null);
      merge(v, decideText(engine, policy, typeof ti.prompt === "string" ? ti.prompt : "", "prompt", { mask: canMask }), "egress");
      envelope(v, { tool: "Task" }, "behavior");
      return { tool, ...settle(v) };
    }
    return { tool, unsupported: true, ...v };
  }

  // PostToolUse: the result the agent ingested. Only for a call that ran (not denied) and succeeded,
  // and only on the surfaces the hook registers PostToolUse for.
  function post(tool, response, { mask } = {}) {
    if (!(POST_TOOLS.has(tool) || tool.startsWith("mcp__")) || response == null) return null;
    if (SHELL_TOOLS.has(tool) && typeof response === "object" && response.isImage === true) return null;
    let value = response;
    if ((tool === "Agent" || tool === "Task") && typeof response === "object" && !Array.isArray(response)) {
      if (response.status === "async_launched") return null;
      if (response.content != null) value = response.content;
    }
    const text = inboundText(value);
    if (!text) return null;
    const v = verdict();
    merge(v, decideInbound(engine, policy, text, { surface: surfaceOf(tool), stage: "output", mask: !!mask }), "output");
    return settle(v);
  }

  function prompt(input, { server = false } = {}) {
    const plan = promptScanPlan(policy, input, { server });
    if (!plan.scan) return { scanned: false, decision: "allow", findings: [] };
    let text = input.prompt;
    if (text.length > CAPS.maxResultBytes) text = text.slice(0, CAPS.maxResultBytes);
    const d = decideText(engine, policy, text, "file", { ctx: { inbound: true } });
    const blockers = plan.action === "block" ? promptBlockers(d.findings, (id) => threatActionFor(policy, id)) : [];
    return { scanned: true, decision: blockers.length ? "deny" : "allow", findings: d.findings.map((f) => ({ ...f, stage: "prompt" })) };
  }

  return { engine, pre, post, prompt };
}
