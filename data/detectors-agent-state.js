// Detectors for attacks on the agent's own state and instructions: chat-history / memory tampering
// (MITRE ATLAS AML.T0092) and self-replicating prompts (AML.T0061). Spread into DETECTORS.
import { agentStateTamperHit } from "./agent-state-paths.js";
import { selfReplicationHit } from "./self-replication.js";
import { SHELL_HISTORY_TAMPER } from "./shell-history-tamper.js";

export const AGENT_STATE_DETECTORS = [
  {
    // T1070.003 / T1690 — the agent clears, deletes or disables its SHELL command history
    // (data/shell-history-tamper.js). A second detector on threat #73, like agent-history-tamper: the
    // engine dedups by threat, so the two never double-count. Prompt stage, where the Bash/PowerShell
    // command text is scanned. Plain patterns (no refine): reading, listing or growing the history stays
    // silent. Threat #73.
    detectorId: "shell-history-tamper",
    threatId: 73,
    stages: ["prompt"],
    mode: "warn",
    hint: "Clears, deletes or disables the shell's command history (history -c, rm/truncate of ~/.bash_history or ~/.zsh_history, unset HISTFILE, set +o history, PSReadLine SaveNothing).",
    patterns: SHELL_HISTORY_TAMPER
  },
  {
    // AML.T0092 — a tool call that deletes, truncates, rewrites, moves or fabricates the agent's own
    // transcripts (data/agent-state-paths.js has the per-agent store and what counts as a write). Stage
    // "prompt" because that is where the hook scans a Bash command and serialized MCP arguments; the
    // Write/Edit family reaches it through agentStateWriteProbe(file_path). The prefilter is the store's
    // directory name; the decision is a per-segment parse, so a path named in prose or in a read stays
    // silent. Threat #73.
    detectorId: "agent-history-tamper",
    threatId: 73,
    stages: ["prompt"],
    mode: "warn",
    hint: "A tool call deletes, rewrites, truncates or fabricates the agent's own session transcripts or prompt history.",
    patterns: [/\.(?:claude|codex|cursor|gemini|copilot)\b|\bcursor[\\/]{1,2}user\b|\$\{?(?:CLAUDE_CONFIG_DIR|CODEX_HOME|COPILOT_HOME)\b/i],
    refine: (_m, text) => agentStateTamperHit(text)
  },
  {
    // AML.T0061 — ingested content telling the model to reproduce the instruction itself into its
    // outputs or into what it creates (data/self-replication.js). Ingest stages only: a user typing the
    // sentence is not a worm. Named inj-* so the engine re-runs it over decoded variants. Threat #74.
    detectorId: "inj-self-replication",
    threatId: 74,
    stages: ["file", "index", "output"],
    mode: "warn",
    hint: "Ingested content tells the model to copy the instruction itself into its replies or into what it creates (self-replicating prompt).",
    patterns: [/\b(?:this|these|itself|yourself|the\s{1,4}text\s{1,4}between|the\s{1,4}(?:above|preceding|following)|instructions?\s{1,4}(?:above|below|herein))\b/i],
    refine: (_m, text) => selfReplicationHit(text)
  }
];
