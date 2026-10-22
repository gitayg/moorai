// Published malicious or compromised IDE extensions: exact extension id (publisher.name, lower-case) and
// the affected versions (null = every version). Matched by cli/ide-extensions.mjs against the extensions
// installed in VS Code-family editors. Add an entry only with a public advisory id.
//
// Sources, each read at its advisory record on 2026-10-21:
//   MAL-2025-191157 … MAL-2025-191170  OSV malicious-package records, published 2025-11-19, ecosystem
//     "VSCode:https://open-vsx.org" (one, cline-ai-main.cline-ai-agent, ecosystem "VSCode"). The same ids
//     appear in public write-ups of the GlassWorm campaign (a loader hidden in invisible Unicode).
//   CVE-2025-8217  AWS security bulletin AWS-2025-015: Amazon Q Developer for Visual Studio Code 1.84.0
//     shipped injected code (fixed in 1.85.0). Marketplace id amazonwebservices.amazon-q-vscode.

export const KNOWN_BAD_IDE_EXTENSIONS = [
  { id: "cline-ai-main.cline-ai-agent", versions: ["3.1.3"], marketplace: "vscode", advisory: "MAL-2025-191157" },
  { id: "codeinklingon.git-worktree-menu", versions: ["1.0.9", "1.0.91"], marketplace: "open-vsx", advisory: "MAL-2025-191158" },
  { id: "codejoy.codejoy-vscode-extension", versions: ["1.8.3", "1.8.4"], marketplace: "open-vsx", advisory: "MAL-2025-191159" },
  { id: "ellacrity.recoil", versions: ["0.7.4"], marketplace: "open-vsx", advisory: "MAL-2025-191160" },
  { id: "ginfuru.better-nunjucks", versions: ["0.3.2"], marketplace: "open-vsx", advisory: "MAL-2025-191161" },
  { id: "grrrck.positron-plus-1-e", versions: ["0.0.71"], marketplace: "open-vsx", advisory: "MAL-2025-191162" },
  { id: "jeronimoekerdt.color-picker-universal", versions: ["2.8.91"], marketplace: "open-vsx", advisory: "MAL-2025-191163" },
  { id: "jscearcy.rust-doc-viewer", versions: ["4.2.1"], marketplace: "open-vsx", advisory: "MAL-2025-191164" },
  { id: "kleinesfilmroellchen.serenity-dsl-syntaxhighlight", versions: ["0.3.2"], marketplace: "open-vsx", advisory: "MAL-2025-191165" },
  { id: "l-igh-t.vscode-theme-seti-folder", versions: ["1.2.3"], marketplace: "open-vsx", advisory: "MAL-2025-191166" },
  { id: "sirilmp.dark-theme-sm", versions: ["3.11.4"], marketplace: "open-vsx", advisory: "MAL-2025-191167" },
  { id: "sissel.shopify-liquid", versions: ["4.0.1"], marketplace: "open-vsx", advisory: "MAL-2025-191168" },
  { id: "srcery-colors.srcery-colors", versions: ["0.3.9"], marketplace: "open-vsx", advisory: "MAL-2025-191169" },
  { id: "tretinv3.forts-api-extention", versions: ["0.3.1"], marketplace: "open-vsx", advisory: "MAL-2025-191170" },
  { id: "amazonwebservices.amazon-q-vscode", versions: ["1.84.0"], marketplace: "vscode", advisory: "CVE-2025-8217" }
];

// → [{ advisory }] for an installed id + version (both compared lower-case / exactly).
export function knownBadExtension(id, version, list = KNOWN_BAD_IDE_EXTENSIONS) {
  const k = String(id || "").toLowerCase();
  return list.filter((e) => e.id === k && (e.versions === null || e.versions.includes(String(version))));
}
