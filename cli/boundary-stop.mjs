// Trust boundary changed without a threat-model update (#85): the hook's glue. At PreToolUse it records,
// on the call's local ledger row, which boundary signals the call raised (`tb`) and whether it wrote a
// threat-model file (`tm`, with `tmk`: keyed hashes of the files, so Stop can find them again without a path
// on the row). At Stop / SubagentStop it reads the rows in scope and decides.
//
// Which calls count, as for the #84 disclosure check (cli/oversight-disclosure.mjs): one the hook allowed, an
// ask the host then reported running, and an ask on a tool the host never reports back on (Write / Edit /
// MultiEdit). A denied call, and a Bash ask with no outcome by Stop, did not run. A threat-model write counts
// only when it is established: allowed, or asked and then reported run (an ask on Write / Edit, whose outcome
// the host never reports, does not clear the check). And it counts only for a threat-model file of THIS
// repository: at Stop the written files' keys (realpath-based, cli/oversight-surfaces.mjs realOf) must match a
// threat-model file the walk finds under repoRoot(cwd) (regular files only, symlinks not followed), so a decoy
// outside the repository, another repository's model or an in-repo symlink to a file elsewhere clears nothing.
//
// A write clears the check only when it is a real update (cli/boundary-update.mjs): to a model that existed when
// the turn began or a policy-declared path, with a change beyond comments and whitespace; a model created in the
// turn only when the policy's threatclPath validates it; with a threatclPath set, only on "pass". The Stop row
// records why a write did not clear (tmr: "created" | "not-substantive" | "validation").
//
// The Stop decision: a boundary change in scope, the repository has a threat model (or the policy sets
// reportWithoutModel), and no threat-model update in scope -> one content-free alert carrying the signal kinds
// and a count (threatModel "created" when the turn's only model writes created new files). threatModel.require "block-stop" on Claude Code also answers decision "block" once per scope,
// never when stop_hook_active is set. threatPolicy[85] "disabled" turns it off.
import { askTrackable } from "./ask-outcome.mjs";
import { beforeAfter } from "./oversight-signals.mjs";
import { BOUNDARY_SIGNALS, boundaryEditSignals } from "./boundary-signals.mjs";
import { boundaryCommandSignals } from "./boundary-shell.mjs";
import { threatModelPolicy, threatModelWrite, threatModelCommand, repoRoot, findThreatModels, whichThreatcl, validateThreatModels, isThreatModelText } from "./boundary-model.mjs";
import { readFileSync, statSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { keyOf, digestOfText, beforeValue, assessModelWrites } from "./boundary-update.mjs";

export const BOUNDARY_THREAT = 85;
export const BOUNDARY_CATEGORY = "Trust boundary changed without a threat-model update";
export const BOUNDARY_INVALID_CATEGORY = "Threat model failed validation";
export const BOUNDARY_BLOCK_REASON = "MoorAI: this turn changed a trust boundary (a new dependency, outbound host, credential path or HTTP route) and did not update the project's threat model. Before you stop, update the threat model to cover the change, or tell the user plainly why it does not need one.";
const READ_MAX = 1_048_576;
const quiet = () => {};
const disabled = (policy) => { const a = policy && policy.threatPolicy ? policy.threatPolicy[BOUNDARY_THREAT] : undefined; return a === "disabled"; };

// Row fields for a Write / Edit / MultiEdit (NotebookEdit is not judged).
export function boundaryWriteFields(tool, ti, path, cwd, policy) {
  try {
    if (!path || disabled(policy) || !["Write", "Edit", "MultiEdit"].includes(tool)) return {};
    const base = typeof cwd === "string" && cwd ? cwd : process.cwd();
    const abs = isAbsolute(path) ? path : resolve(base, path);
    let file = null, exists = false;
    try { const st = statSync(abs); exists = true; if (st.isFile() && st.size <= READ_MAX) file = readFileSync(abs, "utf8"); } catch { file = null; }
    const { before, after } = beforeAfter({ tool, input: ti, file });
    const tm = threatModelPolicy(policy, quiet);
    if (threatModelWrite({ path: abs, before, after, cwd: base, tm })) { const k = keyOf(abs); return { tm: 1, tmk: [k], tmb: { [k]: !exists ? 0 : file === null ? "" : digestOfText(file, abs) } }; }
    if (/\.hcl$/i.test(abs) && isThreatModelText(after)) return {};
    const tb = boundaryEditSignals({ path: abs, before, after, cwd: base });
    return tb.length ? { tb } : {};
  } catch { return {}; }
}

// Row fields for a shell command.
export function boundaryCommandFields(command, cwd, policy, { ps = false } = {}) {
  try {
    if (typeof command !== "string" || disabled(policy)) return {};
    const out = {};
    const files = threatModelCommand(command, { cwd, tm: threatModelPolicy(policy, quiet), ps });
    if (files.length) { const f8 = files.slice(0, 8); out.tm = 1; out.tmk = f8.map(keyOf); out.tmb = Object.fromEntries(f8.map((f) => [keyOf(f), beforeValue(f)])); }
    const tb = boundaryCommandSignals(command, { cwd, ps });
    if (tb.length) out.tb = tb;
    return out;
  } catch { return {}; }
}

// rows: the session ledger rows in scope, oldest first.
export function boundaryChanges(rows) {
  const list = Array.isArray(rows) ? rows : [];
  const kinds = new Set(), keys = new Set(), before = {};
  let count = 0, delegated = false, modelTouched = false;
  list.forEach((r, i) => {
    if (!r || r.ev !== "pre") return;
    const ran = (x) => x.u && list.slice(i + 1).some((y) => y && (y.ev === "post" || y.ev === "fail") && y.u === x.u);
    if (r.tm && (r.decision === "allow" || (r.decision === "ask" && ran(r)))) {
      modelTouched = true;
      for (const k of Array.isArray(r.tmk) ? r.tmk : r.tmk ? [r.tmk] : []) {
        keys.add(k);
        if (!Object.prototype.hasOwnProperty.call(before, k) && r.tmb && Object.prototype.hasOwnProperty.call(r.tmb, k)) before[k] = r.tmb[k];
      }
    }
    if (!Array.isArray(r.tb) || !r.tb.length) return;
    let counted = r.decision === "allow";
    if (!counted && r.decision === "ask") counted = !askTrackable(r.tool) || ran(r);
    if (!counted) return;
    count++;
    for (const s of r.tb) if (BOUNDARY_SIGNALS.includes(s)) kinds.add(s);
    if (r.a) delegated = true;
  });
  return { kinds: BOUNDARY_SIGNALS.filter((s) => kinds.has(s)), count, delegated, modelTouched, modelKeys: [...keys], before };
}

// The Stop / SubagentStop decision. rows: in scope (a sub-agent: its own; the main agent: the whole turn,
// its sub-agents' included). scope: the rows the "already flagged in this scope" check reads. turnStart: the
// turn's UserPromptSubmit row (its tms snapshot), or null. platform: for tests only.
// → { flagged, kinds, count, threatModel, delegated, block, validation, row }
export function boundaryAtStop({ rows, scope, cwd, policy, sub = false, coach = false, host = "", stopHookActive = false, threatclTimeoutMs = 3000, turnStart = null, platform = process.platform } = {}) {
  const none = { flagged: false, kinds: [], count: 0, threatModel: "unknown", delegated: false, block: false, validation: null, row: {} };
  try {
    if (disabled(policy)) return none;
    const tm = threatModelPolicy(policy, quiet);
    const c = boundaryChanges(rows);
    const row = {};
    let validation = null, found = null;
    const root = () => found || (found = findThreatModels(repoRoot(cwd), tm));
    // The written threat-model files that are this repository's own.
    const want = new Set(c.modelKeys);
    const written = c.modelTouched ? root().files.filter((f) => want.has(keyOf(f))) : [];
    let modelUpdated = false, created = false;
    if (written.length) {
      const w = whichThreatcl({ cwd, tm, platform });
      const result = w.bin ? validateThreatModels(written, { bin: w.bin, timeoutMs: threatclTimeoutMs }) : w.reason;
      validation = { result, files: w.bin && result !== "untrusted-input" ? written.length : 0 };
      row.tmv = validation.result;
      // Validation is configured when a threatclPath is set and may run here ("unset" / "unsupported": not).
      const configured = result !== "unset" && result !== "unsupported";
      const a = assessModelWrites(written, { turnStart, before: c.before, tm, root: repoRoot(cwd) });
      const update = a.some((x) => (x.existed || x.declared) && x.substantive);
      const newModel = a.some((x) => !x.existed && !x.declared);
      modelUpdated = configured ? result === "pass" && (update || newModel) : update;
      if (!modelUpdated) {
        created = newModel;
        row.tmr = configured && result !== "pass" ? "validation" : newModel && !update ? "created" : "not-substantive";
      }
    }
    if (!c.count || modelUpdated) return { ...none, kinds: c.kinds, count: c.count, delegated: c.delegated, validation, row: { ...row, tbFlag: false } };
    const present = root().files.length > 0;
    const flagged = present || tm.reportWithoutModel;
    const already = (Array.isArray(scope) ? scope : []).some((r) => r && (r.ev === "stop" || r.ev === "substop") && r.tbFlag);
    const fresh = flagged && !already;
    const block = fresh && present && !coach && tm.require === "block-stop" && stopHookActive !== true && host === "claude-code";
    row.tbFlag = flagged;
    if (block) row.tbBlock = true;
    return { flagged: fresh, kinds: c.kinds, count: c.count, threatModel: created ? "created" : present ? "present" : "absent", delegated: c.delegated || sub, block, validation, row };
  } catch { return none; }
}
