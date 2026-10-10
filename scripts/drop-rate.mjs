#!/usr/bin/env node
// PRE-SCREEN DROP RATE. For every attack, on every surface it can arrive through: was it (a) caught by a
// deterministic rule, (b) missed by the rules but ELIGIBLE for the semantic / on-device-model path, or
// (c) missed and DROPPED before any model could see it — and for (c), which gate dropped it.
//
// The question comes from a published two-stage design (regex pre-screen -> LLM judge) whose pre-screen
// decided what reached the judge and so capped detection at 34%. The lesson is to measure what the cheap
// stage DROPS, not only what the later stage catches. Eligibility is a code-path question: NO model and
// NO network is called here. Whether a model would then flag an eligible text is a separate measurement.
//
//   node scripts/drop-rate.mjs                                   # tune data, every corpus, text report
//   node scripts/drop-rate.mjs --corpus heldout-v2 --file test/redteam/heldout-v2-tune.json
//   node scripts/drop-rate.mjs --corpus inbound --split tune
//   node scripts/drop-rate.mjs --json
//   node scripts/drop-rate.mjs --misses                          # list dropped tune ids + reason
//   (orchestrator only) --file <locked file> | --split locked  --i-am-scoring-the-locked-split
//
// Postures: "default" = no org policy (escalation OFF, data/semantic-escalation.js SEMANTIC_DEFAULT);
// "opted-in" = { modelEscalation: true, semanticEscalation: "local" }, the policy the --semantic scorers use.
// Content-free: ids, families, axes, surfaces, reasons, counts. Never sample text.
import { fileURLToPath } from "node:url";
import { classify, tally, detectGateStages, SURFACES } from "./drop-rate-classify.mjs";
import { heldoutV2, redteamHarness, inbound, UNLOCK_FLAG, isLockedHeldoutFile } from "./drop-rate-corpora.mjs";
import { makeEngine, observeText, observeInboundHook, observeInboundGateway, observeInboundSdk, observeInboundLabelled, SURFACES_BY_STAGE, BASE_POLICY } from "./drop-rate-observe.mjs";

export const POSTURES = Object.freeze({
  "default": BASE_POLICY,
  "opted-in": Object.freeze({ ...BASE_POLICY, modelEscalation: true, semanticEscalation: "local" })
});

export function parseArgs(argv) {
  const val = (f) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : undefined);
  return {
    corpora: (val("--corpus") || "heldout-v2,inbound,redteam").split(",").filter(Boolean),
    file: val("--file") || "test/redteam/heldout-v2-tune.json",
    split: val("--split") || "tune",
    unlocked: argv.includes(UNLOCK_FLAG),
    json: argv.includes("--json"),
    misses: argv.includes("--misses")
  };
}

// One sample -> [{ surface, obs }] for every surface it can arrive through.
async function observations(engine, s) {
  if (s.corpus.startsWith("inbound:")) {
    const out = [
      { surface: "hook:PostToolUse", obs: observeInboundHook(engine, s) },
      { surface: "sdk", obs: await observeInboundSdk(engine, s) },
      { surface: "mcp-gateway", obs: observeInboundGateway(engine, s) }
    ];
    const lab = observeInboundLabelled(engine, s);
    if (lab) out.push({ surface: `labelled:${lab.surface}`, real: lab.surface, obs: lab.obs });
    return out;
  }
  return (SURFACES_BY_STAGE[s.stage] || SURFACES_BY_STAGE.prompt).map((surface) => ({ surface, obs: observeText(engine, s, surface) }));
}

const PRODUCTION = (surface) => surface !== "harness" && !surface.startsWith("labelled:");

export async function run(o) {
  const engine = makeEngine();
  const detectGate = detectGateStages(engine, ["prompt", "file", "index", "output"]);
  const samples = [];
  for (const c of o.corpora) {
    if (c === "heldout-v2") samples.push(...heldoutV2(o.file, { unlocked: o.unlocked }));
    else if (c === "inbound") samples.push(...inbound(o.split, { unlocked: o.unlocked }));
    else if (c === "redteam") samples.push(...redteamHarness());
    else throw new Error(`unknown corpus ${c}`);
  }
  const rows = [];
  for (const s of samples) {
    for (const { surface, real, obs } of await observations(engine, s)) {
      for (const [posture, policy] of Object.entries(POSTURES)) {
        const v = classify(obs, real || surface, policy, { detectGate });
        rows.push({ corpus: s.corpus, id: s.id, family: s.family, axis: s.axis, surface, posture, reported: obs.reported, ...v });
      }
    }
  }
  // Per attack: does ANY shipped surface catch it or route it to the model? (harness + labelled excluded)
  const reach = new Map();
  for (const r of rows) {
    if (!PRODUCTION(r.surface)) continue;
    const k = `${r.posture}|${r.corpus}|${r.id}`;
    const e = reach.get(k) || { posture: r.posture, corpus: r.corpus, id: r.id, family: r.family, axis: r.axis, caught: false, eligible: false };
    if (r.bucket === "caught") e.caught = true;
    if (r.bucket === "eligible") e.eligible = true;
    reach.set(k, e);
  }
  const global = [...reach.values()].map((e) => ({ ...e, bucket: e.caught ? "caught" : e.eligible ? "eligible" : "dropped", reason: e.caught || e.eligible ? undefined : "no-surface-routes-it" }));
  return { detectGate, rows, global, inputs: { corpora: o.corpora, file: o.corpora.includes("heldout-v2") ? o.file : undefined, split: o.corpora.includes("inbound") ? o.split : undefined } };
}

export function summarise(res) {
  const out = {};
  const corpora = [...new Set(res.rows.map((r) => r.corpus))];
  // The inbound sub-corpora are also pooled, the population scripts/score-inbound.mjs scores as one.
  if (corpora.some((c) => c.startsWith("inbound:"))) corpora.push("inbound:ALL");
  const inC = (c) => (r) => r.corpus === c || (c === "inbound:ALL" && r.corpus.startsWith("inbound:"));
  for (const c of corpora) {
    out[c] = {};
    for (const p of Object.keys(POSTURES)) {
      const rs = res.rows.filter((r) => inC(c)(r) && r.posture === p);
      const g = res.global.filter((r) => inC(c)(r) && r.posture === p);
      out[c][p] = {
        bySurface: tally(rs, (r) => r.surface),
        // dropped AND no alert-level finding reported on that surface: the attack is silent there
        silentBySurface: Object.fromEntries([...new Set(rs.map((r) => r.surface))].map((x) => [x, rs.filter((r) => r.surface === x && r.bucket === "dropped" && (!r.reported || r.reason === "surface-not-scanned")).length])),
        routesBySurface: Object.fromEntries([...new Set(rs.map((r) => r.surface))].map((x) => [x, rs.filter((r) => r.surface === x && r.bucket === "eligible").reduce((m, r) => ({ ...m, [r.route]: (m[r.route] || 0) + 1 }), {})])),
        anySurface: tally(g, () => "any")["ALL"],
        byFamily: Object.fromEntries([...new Set(rs.map((r) => r.surface))].map((s) => [s, tally(rs.filter((r) => r.surface === s), (r) => r.family)])),
        byAxis: Object.fromEntries([...new Set(rs.map((r) => r.surface))].map((s) => [s, tally(rs.filter((r) => r.surface === s), (r) => r.axis)])),
        anyByFamily: tally(g, (r) => r.family),
        anyByAxis: tally(g, (r) => r.axis)
      };
    }
  }
  return out;
}

const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : "-");
const reasons = (e) => Object.entries(e.reasons).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", ") || "-";
const line = (label, e, w = 34) => `    ${label.padEnd(w)} ${String(e.n).padStart(4)} ${String(e.caught).padStart(6)} ${String(e.eligible).padStart(8)} ${String(e.dropped).padStart(7)} ${pct(e.dropped, e.n).padStart(7)}  ${reasons(e)}`;
const head = (label, w = 34) => `    ${label.padEnd(w)} ${"n".padStart(4)} ${"caught".padStart(6)} ${"eligible".padStart(8)} ${"dropped".padStart(7)} ${"drop%".padStart(7)}  drop reasons`;

// Family / axis tables are printed for the harness and one production surface per corpus; --json has all.
const GROUP_SURFACES = (c) => (c.startsWith("inbound:") ? ["hook:PostToolUse", "labelled:hook:Read", "labelled:hook:index"] : ["harness", "guard:claude-p"]);

export function toText(res, sum) {
  let t = `MoorAI pre-screen drop rate · ${JSON.stringify(res.inputs)} · detect gate ${JSON.stringify(res.detectGate)}\n`;
  t += `(a) caught = the corpus scorer's own "detected"; (b) eligible = would be handed to the on-device model; (c) dropped = neither. No model was called.\n`;
  for (const [c, byP] of Object.entries(sum)) {
    for (const [p, s] of Object.entries(byP)) {
      t += `\n== ${c} · posture ${p}\n${head("surface")}\n`;
      for (const [surf, e] of Object.entries(s.bySurface)) if (surf !== "ALL") t += line(surf, e) + `  | silent ${s.silentBySurface[surf]}${Object.keys(s.routesBySurface[surf]).length ? ` | routes ${JSON.stringify(s.routesBySurface[surf])}` : ""}\n`;
      t += line("ANY shipped surface (per attack)", s.anySurface) + "\n";
      if (p !== "opted-in") continue;
      for (const gs of GROUP_SURFACES(c)) {
        if (!s.byFamily[gs]) continue;
        t += `  by family · ${gs}\n${head("family")}\n`;
        for (const [k, e] of Object.entries(s.byFamily[gs])) if (k !== "ALL") t += line(k, e) + "\n";
        if (Object.keys(s.byAxis[gs]).some((k) => k !== "-" && k !== "ALL")) {
          t += `  by axis · ${gs}\n${head("axis")}\n`;
          for (const [k, e] of Object.entries(s.byAxis[gs])) if (k !== "ALL") t += line(k, e) + "\n";
        }
      }
    }
  }
  return t;
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  if (o.corpora.includes("heldout-v2") && isLockedHeldoutFile(o.file) && !o.unlocked) { console.error(`${o.file} holds locked samples; pass ${UNLOCK_FLAG} (orchestrator only)`); process.exit(2); }
  if (o.corpora.includes("inbound") && o.split !== "tune" && !o.unlocked) { console.error(`--split ${o.split} includes locked samples; pass ${UNLOCK_FLAG} (orchestrator only)`); process.exit(2); }
  const res = await run(o);
  const sum = summarise(res);
  if (o.json) { process.stdout.write(JSON.stringify({ inputs: res.inputs, detectGate: res.detectGate, surfaces: Object.fromEntries(Object.entries(SURFACES).map(([k, v]) => [k, v.ref])), summary: sum }, null, 2) + "\n"); return; }
  let t = toText(res, sum);
  // Ids are printed for tune data only, never for a locked run.
  if (o.misses && !o.unlocked) {
    t += `\nDropped on EVERY shipped surface (opted-in posture):\n`;
    for (const g of res.global.filter((r) => r.posture === "opted-in" && r.bucket === "dropped")) t += `  ${g.corpus}:${g.id} [${g.family}/${g.axis}]\n`;
  }
  process.stdout.write(t);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch((e) => { console.error(e); process.exit(1); });
