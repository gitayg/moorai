// No MDM PowerShell script may name a parameter after a read-only automatic variable.
//
// Install-MoorAI.ps1 declared `param([string] $Home)` on Write-EnrollConfig and Register-Hooks. $HOME is
// a read-only automatic variable, and PSScriptAnalyzer's AvoidAssignmentToAutomaticVariable rule lists it
// with the note "Attempting to assign to any of those read-only variable would result in an error at
// runtime" (Rules/AvoidAssignmentToAutomaticVariable.cs, _readOnlyAutomaticVariables). A function whose
// parameter binding throws never writes the enroll config or registers the hooks, so an Intune install
// would leave the device unprotected. The list below is that rule's, including the PowerShell 6+ set.
//
//   node --test test/mdm-powershell-params.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const READ_ONLY = ["?", "true", "false", "Host", "PSCulture", "Error", "ExecutionContext", "Home", "PID", "PSEdition",
  "PSHome", "PSUICulture", "PSVersionTable", "ShellId", "IsCoreCLR", "IsLinux", "IsMacOS", "IsWindows"];
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const BAD = new RegExp(`^\\$(${READ_ONLY.map(esc).join("|")})$`, "i");

function ps1Files(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...ps1Files(p));
    else if (/\.ps1$/i.test(name)) out.push(p);
  }
  return out;
}

// Every `param( … )` block, balanced over nested parentheses such as [Parameter(Mandatory)].
function paramBlocks(src) {
  const blocks = [];
  const re = /\bparam\s*\(/gi;
  let m;
  while ((m = re.exec(src))) {
    let depth = 1, i = re.lastIndex;
    while (i < src.length && depth) { if (src[i] === "(") depth++; else if (src[i] === ")") depth--; i++; }
    blocks.push({ text: src.slice(re.lastIndex, i - 1), line: src.slice(0, m.index).split("\n").length });
  }
  return blocks;
}

test("the scan finds the MDM PowerShell scripts and their param blocks", () => {
  const files = ps1Files(join(ROOT, "packaging"));
  assert.ok(files.some((f) => f.endsWith("Install-MoorAI.ps1")), "Install-MoorAI.ps1 not found");
  assert.ok(files.flatMap((f) => paramBlocks(readFileSync(f, "utf8"))).length >= 2, "expected param blocks to scan");
});

test("no param block names a read-only automatic variable", () => {
  const hits = [];
  for (const f of ps1Files(join(ROOT, "packaging"))) {
    for (const b of paramBlocks(readFileSync(f, "utf8"))) {
      // A declared name is a $variable NOT on the right of `=`; `[switch] $DryRun = $false` declares $DryRun.
      for (const m of b.text.matchAll(/(=\s*)?\$([A-Za-z_?][\w]*)/g)) {
        if (!m[1] && BAD.test(`$${m[2]}`)) hits.push(`${relative(ROOT, f)}:${b.line} declares $${m[2]}`);
      }
    }
  }
  assert.deepEqual(hits, []);
});
