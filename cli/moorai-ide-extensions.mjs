#!/usr/bin/env node
// moorai-ide-extensions — scan the IDE extensions installed on this machine (VS Code, Insiders, VSCodium,
// Cursor, Windsurf, Kiro, VS Code Server, JetBrains plugins) for published malicious ids, typosquats,
// invisible-Unicode code and side-loaded installs. Report-only: exit 0 whatever it finds. Content-free
// output (editor, id, version, AI flag, codes, risk, advisory ids). Nothing leaves the machine.
//
//   moorai-ide-extensions [--format json|md] [--flagged]
import { scanIdeExtensions } from "./ide-extensions.mjs";

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) {
  process.stdout.write("usage: moorai-ide-extensions [--format json|md] [--flagged]\n");
  process.exit(0);
}
const fmt = argv.includes("--format") ? argv[argv.indexOf("--format") + 1] : "json";
const r = scanIdeExtensions();
if (argv.includes("--flagged")) r.extensions = r.extensions.filter((x) => x.codes.length);
if (fmt === "md") {
  const rows = r.extensions.map((x) => `| ${x.editor} | ${x.id} | ${x.version || "—"} | ${x.ai ? "yes" : "no"} | ${x.codes.join(", ") || "—"}${x.advisories ? ` (${x.advisories.join(", ")})` : ""} | ${x.risk} |`);
  process.stdout.write(`# IDE extension scan\n\n${r.scanned} scanned, ${r.flagged} flagged, ${r.ai} AI${r.truncated ? " (partial: a read bound was hit)" : ""}. Report-only.\n\n| Editor | Extension | Version | AI | Findings | Risk |\n|---|---|---|---|---|---|\n${rows.join("\n") || "| — | — | — | — | — | — |"}\n`);
} else {
  process.stdout.write(JSON.stringify(r, null, 2) + "\n");
}
