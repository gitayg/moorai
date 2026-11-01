// The benign cost of the default #39 result mask (cli/inbound.mjs CRED_RESULT_DECISION, cli/result-mask.mjs): on
// the inbound evaluation population (scripts/inbound-corpus.mjs, tune split only) and optionally real third-party
// files from node_modules trees, how many results would have a span masked, and how many would fail the mask (on
// the hook that is the decision-"block" reason next to the result), per path:
//   hook     stage "output", the web / door rules by the sample's door (the PostToolUse scan)
//   gateway  stage "file", the door rules (the HTTP gateway and the stdio guard)
// In process, the same functions those surfaces call. Content-free output: counts, corpus names and sample ids.
//
//   node scripts/score-result-mask.mjs [--real <dir-with-node_modules>]... [--json] [--ids]
import { buildEngine } from "../cli/hook-core.mjs";
import { maskResult } from "../cli/result-mask.mjs";
import { repoSamples, realSamples } from "./inbound-corpus.mjs";

const argv = process.argv.slice(2);
const real = argv.flatMap((a, i) => (a === "--real" && argv[i + 1] ? [argv[i + 1]] : []));
const POLICY = { captureTier: "content-free", builtinDefault: true };
const engine = buildEngine(POLICY);
const hash = (s) => "h2:" + Buffer.from(String(s)).toString("hex").slice(0, 16);
const PATHS = { hook: (s) => ({ stage: "output", surface: s.door === "web" ? "web" : "door" }), gateway: () => ({ stage: "file", surface: "door" }) };

const samples = [...repoSamples(), ...realSamples(real)].filter((s) => s.split === "tune" || s.corpus === "real");
const out = {};
for (const [path, opts] of Object.entries(PATHS)) {
  const t = { benign: 0, masked: 0, failed: 0, attacks: 0, attacksMasked: 0, byCorpus: {}, ids: [] };
  for (const s of samples) {
    const r = maskResult(engine, POLICY, s.text, { ...opts(s), hash });
    const c = (t.byCorpus[s.corpus] ??= { benign: 0, masked: 0, failed: 0 });
    if (s.kind === "attack") { t.attacks++; if (r) t.attacksMasked++; continue; }
    t.benign++; c.benign++;
    if (!r) continue;
    if (r.failed) { t.failed++; c.failed++; } else { t.masked++; c.masked++; }
    t.ids.push(`${s.corpus}:${s.id}${r.failed ? " (failed)" : ""}`);
  }
  out[path] = t;
}
if (argv.includes("--json")) process.stdout.write(JSON.stringify(out, null, 2) + "\n");
else for (const [path, t] of Object.entries(out)) {
  console.log(`${path}: benign results masked ${t.masked} / ${t.benign}, mask failed ${t.failed} / ${t.benign}; attacks with a masked span ${t.attacksMasked} / ${t.attacks}`);
  for (const [c, v] of Object.entries(t.byCorpus)) if (v.benign) console.log(`  ${c.padEnd(10)} masked ${v.masked} / ${v.benign}, failed ${v.failed}`);
  if (argv.includes("--ids")) for (const id of t.ids) console.log(`    ${id}`);
}
