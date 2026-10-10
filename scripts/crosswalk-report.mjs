#!/usr/bin/env node
// Coverage per external framework, from the crosswalks in data/crosswalks/.
//
//   node scripts/crosswalk-report.mjs              # covered / partial / not covered / not applicable per framework
//   node scripts/crosswalk-report.mjs --json       # the same numbers as JSON
//   node scripts/crosswalk-report.mjs --markdown   # the tables docs/CROSSWALKS.md carries
//
// Each crosswalk maps every id in a pinned copy of the framework's official list to one status. The
// file format, the evidence rules and the sources are in docs/CROSSWALKS.md; test/crosswalks.test.mjs
// checks them.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

export const CROSSWALK_FILES = [
  "data/crosswalks/saf-mcp.json",
  "data/crosswalks/careful-adoption-of-agentic-ai-services.json",
  "data/crosswalks/agentic-trust-framework.json"
];
export const STATUSES = ["covered", "partial", "not-covered", "not-applicable"];
const LABEL = { covered: "Covered", partial: "Partial", "not-covered": "Not covered", "not-applicable": "Not applicable" };

export function loadCrosswalks(root = ROOT) {
  return CROSSWALK_FILES.map((f) => ({ file: f, ...JSON.parse(readFileSync(join(root, f), "utf8")) }));
}

export function loadComponents(root = ROOT) {
  return JSON.parse(readFileSync(join(root, "data/crosswalks/components.json"), "utf8")).components;
}

export function crosswalkCounts(cw) {
  const counts = Object.fromEntries(STATUSES.map((s) => [s, 0]));
  for (const e of cw.entries) counts[e.status] += 1;
  const total = cw.catalog.length;
  const applicable = total - counts["not-applicable"];
  return { key: cw.framework.key, name: cw.framework.shortName, total, ...counts, applicable };
}

export function report(cws = loadCrosswalks()) {
  return cws.map(crosswalkCounts);
}

function pct(n, d) {
  return d ? `${Math.round((n / d) * 100)}%` : "-";
}

export function summaryMarkdown(rows = report()) {
  const out = [
    "| Framework | Items | Covered | Partial | Not covered | Not applicable | Covered or partial, of applicable |",
    "|---|--:|--:|--:|--:|--:|--:|"
  ];
  for (const r of rows) {
    out.push(`| ${r.name} | ${r.total} | ${r.covered} | ${r.partial} | ${r["not-covered"]} | ${r["not-applicable"]} | ${r.covered + r.partial} of ${r.applicable} (${pct(r.covered + r.partial, r.applicable)}) |`);
  }
  return out.join("\n");
}

function cell(s) {
  return String(s ?? "").replace(/\|/g, "\\|");
}

export function detailMarkdown(cw, components = loadComponents()) {
  const titles = new Map(cw.catalog.map((c) => [c.id, c.title || c.text]));
  const out = ["| Id | Title | Status | MoorAI threats | Evidence | Limit or reason |", "|---|---|---|---|---|---|"];
  for (const e of cw.entries) {
    const threats = e.threats.length ? e.threats.map((t) => `#${t}`).join(", ") : "";
    const ev = e.evidence.map((k) => components[k]?.name || k).join("; ");
    const why = e.status === "partial" ? e.limit : e.status === "covered" ? "" : `${e.naKind ? `(${e.naKind}) ` : ""}${e.reason || ""}`;
    out.push(`| ${e.id} | ${cell(titles.get(e.id))} | ${LABEL[e.status]} | ${threats} | ${cell(ev)} | ${cell(why)} |`);
  }
  return out.join("\n");
}

export function rejectedMarkdown(cw, components = loadComponents()) {
  if (!cw.rejected?.length) return "None.";
  const out = ["| Id | Credit considered | Why it was rejected |", "|---|---|---|"];
  for (const r of cw.rejected) {
    const what = [r.credit.threat ? `#${r.credit.threat}` : "", r.credit.component ? components[r.credit.component]?.name || r.credit.component : ""].filter(Boolean).join(", ");
    out.push(`| ${r.id} | ${cell(what)} | ${cell(r.reason)} |`);
  }
  return out.join("\n");
}

function main(argv) {
  const cws = loadCrosswalks();
  const rows = report(cws);
  if (argv.includes("--json")) {
    process.stdout.write(JSON.stringify(rows, null, 2) + "\n");
    return;
  }
  if (argv.includes("--markdown")) {
    const components = loadComponents();
    const parts = [summaryMarkdown(rows)];
    for (const cw of cws) {
      parts.push(`### ${cw.framework.shortName}\n\n${detailMarkdown(cw, components)}\n\nRejected credits:\n\n${rejectedMarkdown(cw, components)}`);
    }
    process.stdout.write(parts.join("\n\n") + "\n");
    return;
  }
  const w = Math.max(...rows.map((r) => r.name.length));
  console.log(`${"Framework".padEnd(w)}  Items  Covered  Partial  Not covered  Not applicable`);
  for (const r of rows) {
    console.log(`${r.name.padEnd(w)}  ${String(r.total).padStart(5)}  ${String(r.covered).padStart(7)}  ${String(r.partial).padStart(7)}  ${String(r["not-covered"]).padStart(11)}  ${String(r["not-applicable"]).padStart(14)}`);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main(process.argv.slice(2));
