// AI model downloads (#76 Unsafe AI model loading, ATLAS AML.T0011.000 Unsafe AI Artifacts): an agent's
// command that fetches model weights (ollama pull, huggingface-cli / hf download, git lfs pull, a git
// clone from the Hugging Face hub, curl / wget of a .pt .bin .ckpt .pkl .gguf .safetensors .onnx .h5
// .keras file). Report-only: #76 resolves to "notify" unless a policy raises it. The finding is the
// hand-off to the static model scanner: the hook queues the download target and a detached worker scans
// the files once the download settles (cli/model-scan-queue.mjs). Nothing is scanned on PreToolUse.
//
// It YIELDS to model-unsafe-load, the older detector on the same threat: the engine keeps one finding per
// threat, so this fires only where model-unsafe-load is silent and never relabels a load finding.
// data/model-download.js.
import { modelDownloadHit } from "./model-download.js";
import { unsafeModelLoadHit } from "./model-load.js";

export const MODEL_DOWNLOAD_DETECTORS = [
  {
    detectorId: "model-download",
    threatId: 76,
    stages: ["prompt"],
    mode: "notify",
    hint: "Downloads AI model weights; MoorAI scans the downloaded files statically in the background.",
    patterns: [/\b(?:ollama|huggingface-cli|hf|lfs|curl|wget|clone)\b/i],
    // Only a Bash command (ctx.shell "sh", as the hook, the replayer and the Agent SDK label one): the same
    // words in a prompt or a document are a mention, not a download.
    refine: (_m, text, ctx) => !!ctx && ctx.shell === "sh" && !unsafeModelLoadHit(text) && modelDownloadHit(text)
  }
];
