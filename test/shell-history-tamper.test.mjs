// Clear Command History (MITRE ATT&CK T1070.003) and Prevent Command History Logging (T1690) through an
// AI coding agent's shell (data/shell-history-tamper.js, detector shell-history-tamper on threat #73).
//
// THE GAP. agent-history-tamper (#73) watched the agent's own transcript stores, but the SHELL's record
// of what the agent ran — ~/.bash_history, ~/.zsh_history, PSReadLine, and the logging switches that stop
// it being written — fired nothing (ATT&CK v20 gap analysis, probe: `history -c` "-- none --").
//
//   node --test --import ./test/hermetic-env.mjs test/shell-history-tamper.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { DETECTOR_MODULE, scan, credit, assertLinear, runHook, withHome } from "./detector-gap-kit.mjs";
import { SHELL_HISTORY_TAMPER } from "../data/shell-history-tamper.js";

const { DETECTORS } = DETECTOR_MODULE;
const DET = "shell-history-tamper#73";

const POSITIVES = [
  "history -c",
  "history -c; history -w",
  "Clear-History",
  "set +o history",
  "unset HISTFILE",
  "unset HISTFILE HISTSIZE",
  "export HISTFILE=/dev/null",
  "HISTFILE=/dev/null bash",
  "export HISTFILE=",
  "HISTSIZE=0",
  "HISTFILESIZE=0",
  "SAVEHIST=0",
  "Set-PSReadLineOption -HistorySaveStyle SaveNothing",
  "Remove-Item (Get-PSReadLineOption).HistorySavePath -Force",
  "rm ~/.bash_history",
  "rm -f ~/.zsh_history",
  "shred -u ~/.bash_history",
  "truncate -s 0 ~/.bash_history",
  "rm \"$HOME/.local/share/fish/fish_history\"",
  "rm -f ~/.config/powershell/ConsoleHost_history.txt",
  "cat /dev/null > ~/.bash_history",
  "> ~/.bash_history",
  ": > ~/.zsh_history",
  "echo -n > ~/.bash_history",
  "printf '' > ~/.zsh_history"
];

const NEGATIVES = [
  "history",
  "history 20",
  "history | grep ssh",
  "cat ~/.bash_history",
  "grep -i token ~/.zsh_history",
  "tail -n 50 ~/.bash_history",
  "cp ~/.bash_history ~/backup/history.txt",
  "wc -l ~/.bash_history",
  "Get-History",
  "Get-PSReadLineOption",
  "echo $HISTFILE",
  "set -o history",
  "export HISTSIZE=10000",
  "HISTSIZE=50000",
  "HISTFILESIZE=20000",
  "export HISTFILE=~/.bash_history",
  "HISTFILE=/data/project/.bash_history bash",
  "Set-PSReadLineOption -HistorySaveStyle SaveIncrementally",
  "less ~/.zsh_history",
  "diff ~/.bash_history ~/.bash_history.bak"
];

for (const cmd of POSITIVES) {
  test(`T1070.003 positive: ${DET} fires on ${JSON.stringify(cmd)}`, () => {
    assert.ok(scan(cmd).includes(DET), `missed; findings: [${scan(cmd).join(",")}]`);
  });
}
for (const cmd of NEGATIVES) {
  test(`T1070.003 negative: ${DET} stays silent on ${JSON.stringify(cmd)}`, () => {
    assert.ok(!scan(cmd).includes(DET), `false positive; findings: [${scan(cmd).join(",")}]`);
  });
}

test("wiring: a shell-history-tamper detector on threat 73 holds the pattern list by reference", () => {
  const d = DETECTORS.find((x) => x.detectorId === "shell-history-tamper");
  assert.ok(d && d.threatId === 73);
  assert.equal(d.patterns, SHELL_HISTORY_TAMPER);
});

test("ATT&CK: #73 credits T1070.003 and T1690 as partial", () => {
  assert.equal(credit(73, "T1070.003")?.coverage, "partial");
  assert.equal(credit(73, "T1690")?.coverage, "partial");
});

test("pattern cost: 60KB adversarial inputs scan in linear time, pattern by pattern", () => {
  assertLinear(SHELL_HISTORY_TAMPER, [
    ["", "history -c ", 5500],
    ["", "Clear-History ", 4300],
    ["", "unset HISTFILE ", 4000],
    ["", "HISTFILE=/dev/null ", 3200],
    ["", "HISTSIZE=0 ", 6000],
    ["", "Set-PSReadLineOption -HistorySaveStyle x ", 1500],
    ["", "Remove-Item HistorySavePath ", 2100],
    ["", "rm .bash_history ", 3500],
    ["", "> .bash_history ", 3700],
    ["", "echo -n > .bash_history ", 2500]
  ]);
});

test("hook e2e: clearing shell history asks before it runs (no policy: #73 is justify); reading it is allowed", () => {
  withHome((home) => {
    assert.equal(runHook(home, "Bash", { command: "history -c; rm -f ~/.bash_history" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "unset HISTFILE" }), "ask");
    assert.equal(runHook(home, "PowerShell", { command: "Set-PSReadLineOption -HistorySaveStyle SaveNothing" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "tail -n 50 ~/.bash_history" }), "allow");
    assert.equal(runHook(home, "Bash", { command: "export HISTSIZE=10000" }), "allow");
  });
});
