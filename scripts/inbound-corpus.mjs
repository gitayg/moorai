// The INBOUND evaluation population and its fixed tune / locked split, shared by scripts/score-inbound.mjs
// and test/inbound-split.test.mjs.
//
// Inbound content is text that arrives INTO the agent: a fetched page, a tool or MCP result, a ticket, a
// document, a memory file read at session start. Every repository corpus that carries such text is
// gathered here, each sample tagged attack (it carries an instruction aimed at the agent, or a live
// payload) or benign:
//   vector2-indirect-content   every attack and benign sample (all of them are third-party content)
//   vector3-supply-chain       the file / index / output samples (the tool-stage ones are tools/list
//                              metadata, scored by scripts/score-tool-stage-e2e.mjs instead)
//   vector5-memory-crossagent  "text" samples, and the CONSUME step of "steps" samples (the session and
//                              events harnesses carry no inbound text)
//   atlas-2026-09              the non-prompt samples, and the file-metadata values (`metadata`)
//   benign-web-content         all 311 pages; the `shouldDetect: true` pages are live payloads, so attacks
//   benign-corpus-v2           all 610 prompts, scored a second time as if a tool had returned them
//                              (a stress set: its hard negatives are shaped like attacks)
// plus, optionally, real third-party files from node_modules trees named on the command line
// (README.md / package.json / the main file of each package), always benign.
//
// THE SPLIT. Fixed before any detector output on these corpora was read: 60% tune, 40% locked, by
// sha256(SEED:corpus:id). Two corpora already carry a locked half of their own and keep it rather than
// being re-split, so no sample that was locked before is tunable now: benign-web-content (`split`
// tune/test) and atlas-2026-09 (`split` tune/test) map tune -> tune and test -> locked. The manifest hash
// (splitHash) is over the sorted (corpus, id, split) triples; test/inbound-split.test.mjs pins it.
// Only the tune half's errors may be read while iterating; the locked half is scored once.
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const SEED = "moorai-inbound-2026-10-06";
export const TUNE_SHARE = 0.6;
const rd = (p) => JSON.parse(readFileSync(join(ROOT, p), "utf8"));

export function hashSplit(corpus, id) {
  const h = createHash("sha256").update(`${SEED}:${corpus}:${id}`).digest();
  return h.readUInt32BE(0) / 2 ** 32 < TUNE_SHARE ? "tune" : "locked";
}

// The threat each ATLAS family's own detector reports; an attack counts as detected when that threat or
// an injection threat (#3, #40, #50, #60) is raised. T0129-meta is instruction text, so injection only.
const ATLAS_EXPECT = { "T0131-links": 68, "T0133-recon": 69, "T0134-cloak": 70, "obf-css": 50, "render-exfil": 71 };
const WEB_CHANNELS = new Set(["web-page", "search-snippets"]);
const doorOf = (channel, tool) => (tool === "WebFetch" || tool === "WebSearch" || WEB_CHANNELS.has(channel) ? "web" : "door");

export function repoSamples() {
  const out = [];
  const push = (corpus, s, kind, text, extra = {}) => {
    if (typeof text !== "string" || !text.trim()) return;
    const expect = typeof s.expectThreat === "number" ? s.expectThreat : ATLAS_EXPECT[s.family];
    out.push({ corpus, id: s.id, kind, text, door: doorOf(s.channel, s.tool), channel: s.channel || s.family || s.category || "", split: hashSplit(corpus, s.id), ...(expect ? { expect } : {}), ...extra });
  };
  const v2 = rd("test/redteam/vector2-indirect-content.json");
  for (const s of v2.attacks) push("vector2", s, "attack", s.text);
  for (const s of v2.benign) push("vector2", s, "benign", s.text);
  const v3 = rd("test/redteam/vector3-supply-chain.json");
  for (const s of v3.attacks) if (s.stage !== "tool") push("vector3", s, "attack", s.text);
  for (const s of v3.benign) if (s.stage !== "tool") push("vector3", s, "benign", s.text);
  const v5 = rd("test/redteam/vector5-memory-crossagent.json");
  const v5text = (s) => {
    if (s.harness === "text") return s.text;
    if (s.harness === "steps" && Array.isArray(s.steps) && s.steps.length) return s.steps[(s.consumeStep || s.steps.length) - 1]?.text;
    return null;
  };
  for (const s of v5.attacks) push("vector5", s, "attack", v5text(s));
  for (const s of v5.benign) push("vector5", s, "benign", v5text(s));
  const at = rd("test/redteam/atlas-2026-09.json");
  for (const s of [...at.samples, ...(at.metadata || [])]) if (s.stage !== "prompt") push("atlas", s, s.shouldDetect ? "attack" : "benign", s.text, { split: s.split === "test" ? "locked" : "tune" });
  const web = rd("test/redteam/benign-web-content.json");
  for (const s of web.samples) push("web", s, s.shouldDetect ? "attack" : "benign", s.text, { split: s.split === "test" ? "locked" : "tune", hardNegative: !!s.hard_negative });
  const bv2 = rd("test/redteam/benign-corpus-v2.json");
  for (const s of bv2.benign) push("benign-v2", { ...s, channel: s.category }, "benign", s.text, { door: "door" });
  return out;
}

// Real third-party files: for each package directly under <tree>/node_modules (and each scope's
// packages), its README.md, package.json and main file, first 64 KB each. Benign by construction.
export function realSamples(trees = []) {
  const out = [];
  for (const tree of trees) {
    const nm = join(tree, "node_modules");
    if (!existsSync(nm)) continue;
    const pkgs = [];
    for (const n of readdirSync(nm).sort()) {
      if (n.startsWith(".")) continue;
      if (n.startsWith("@")) { for (const m of readdirSync(join(nm, n)).sort()) pkgs.push(join(nm, n, m)); }
      else pkgs.push(join(nm, n));
    }
    for (const p of pkgs) {
      let main = "index.js";
      try { const pj = JSON.parse(readFileSync(join(p, "package.json"), "utf8")); if (typeof pj.main === "string") main = pj.main; } catch { /* no package.json */ }
      for (const f of ["README.md", "package.json", main]) {
        const fp = join(p, f);
        try {
          if (!statSync(fp).isFile()) continue;
          const text = readFileSync(fp).subarray(0, 65536).toString("utf8");
          const id = relative(dirname(tree), fp);
          out.push({ corpus: "real", id, kind: "benign", text, door: "door", channel: f === "README.md" ? "readme" : f === "package.json" ? "package-json" : "source", split: hashSplit("real", id) });
        } catch { /* missing file */ }
      }
    }
  }
  return out;
}

export function splitHash(samples) {
  const rows = samples.map((s) => `${s.corpus}\t${s.id}\t${s.split}`).sort();
  return createHash("sha256").update(rows.join("\n")).digest("hex");
}
