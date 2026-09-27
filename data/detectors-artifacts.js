// Detectors for output-component manipulation (AML.T0067 / AML.T0077) and AI model artifacts:
// unsafe model loading (AML.T0011.000) and model/dataset collection (AML.T0035). Spread into DETECTORS.
//
// out-link-deceptive -> #75, model-unsafe-load -> #76, model-artifact-collection -> #77.
// egress-rendered-extended (#71) and obf-invisible-output (#50) extend threats that already exist.
//
// Every refine-gated prefilter below is cheap and broad on purpose and must compile under the ReDoS
// guard (test/detector-patterns-compile.test.mjs): the engine silently skips a pattern it rejects.
import { renderedExfilExtHit } from "./render-exfil-ext.js";
import { deceptiveLinkHit } from "./output-links.js";
import { unsafeModelLoadHit } from "./model-load.js";
import { modelCollectionHit } from "./model-collection.js";
import { renderedExfilHit } from "./render-exfil.js";
import { visuallyHiddenInstruction } from "./visual-hiding.js";

// The engine keeps ONE finding per threat and the last "warn" detector to match wins it, so a detector
// appended here that shares a threat with an older one would silently take over that finding — its id
// and hint — whenever both match. The two that extend an existing threat therefore YIELD: they fire only
// where the older detector for the same threat and stage is silent, so they add coverage and never
// relabel it. The other three own their threats and share with no older detector.
// obf-invisible-instructions' three patterns, restated: tag block, ANSI/OSC escape, variation selectors.
const OLDER_INVISIBLE_OUTPUT = [/[\u{E0000}-\u{E007F}]/u, /\x1b[\[\]P^_]/, /[\u{E0100}-\u{E01EF}]/u];

export const ARTIFACT_DETECTORS = [
  {
    // AML.T0077 / #71 (LLM02) — the rendering channels egress-rendered-image does not read: data in a
    // URL PATH segment, hex- or base64-encoded text, a secret-named parameter (the ATLAS example
    // `?secrets="private data"`), reference-style markdown images, <iframe>/<embed>/<object>/<video>/
    // srcset/CSS url(), and one value split across many rendered requests. Shape tests in
    // data/render-exfil-ext.js; hosts are never listed. Output only, like its sibling.
    detectorId: "egress-rendered-extended",
    threatId: 71,
    stages: ["output"],
    mode: "warn",
    hint: "Content the client renders on its own (image, embed, reference-style image, CSS) carries data in its URL path or parameters.",
    patterns: [
      /!\[[^\]\n]{0,200}\]/,
      /<(?:img|iframe|frame|embed|object|video|audio|source|track|input|link)\b/i,
      /url\(\s{0,4}["']?https?:\/\//i
    ],
    refine: (_m, text) => !renderedExfilHit(text) && renderedExfilExtHit(text)
  },
  {
    // AML.T0067 / #75 (LLM05) — a link that displays one destination and goes to another:
    // URL-shaped link text whose href is a lookalike, a brand-embedding host, an IP or punycode host,
    // the displayed path on a foreign host, or an unrelated non-redirector host; a URL whose userinfo is
    // a domain (https://github.com@mirror.example/); zero-width or bidi overrides inside a URL. Same-
    // brand, wrapper (archive, safelinks) and shortener hrefs are silent. data/output-links.js.
    detectorId: "out-link-deceptive",
    threatId: 75,
    stages: ["output"],
    mode: "warn",
    hint: "A link shows one address and opens another (lookalike, disguised or spoofed destination).",
    patterns: [
      /\]\(\s{0,4}<?https?:\/\//i,
      /<a\b[^>]{0,400}?\bhref\s{0,4}=\s{0,4}["']https?:\/\//i,
      /\bhttps?:\/\/[^\s\/?#@"'<>]{1,200}@/i
    ],
    refine: (_m, text) => deceptiveLinkHit(text)
  },
  {
    // #50 (LLM08) — the zero-width runs and bidi overrides idx-invisible-text screens at the prompt
    // stage, on the OUTPUT stage it never reaches (fetched pages, tool results, written files).
    // obf-invisible-instructions already covers the tag block and variation selectors on output; this
    // adds only the two code-point families it lacks. Same FP scoping as idx-invisible-text: a RUN of
    // >= 2 zero-widths (an emoji ZWJ sequence has one between scalars) and only the two OVERRIDES —
    // the RLM/LRM marks, embeddings and isolates Hebrew and Arabic text uses are not matched.
    detectorId: "obf-invisible-output",
    threatId: 50,
    stages: ["output"],
    mode: "warn",
    hint: "Zero-width run or direction-override characters in fetched or generated content hide text from the reader.",
    patterns: [
      /[\u200B-\u200D\u2060\uFEFF]{2,}/,
      /[\u202D\u202E]/
    ],
    refine: (_m, text) => !OLDER_INVISIBLE_OUTPUT.some((r) => r.test(text)) && !visuallyHiddenInstruction(text)
  },
  {
    // AML.T0011.000 / #76 (LLM03) — a model file deserialized in a way that runs its code:
    // torch.load(weights_only=False, or bare on an untrusted source), pickle/joblib/dill/cloudpickle/
    // read_pickle of a URL / download / temp path, np.load(allow_pickle=True), load_model(safe_mode=
    // False), trust_remote_code=True / --trust-remote-code. Judged per call on its own arguments and
    // only in code position, so prose and inline-code mentions stay silent. data/model-load.js.
    detectorId: "model-unsafe-load",
    threatId: 76,
    stages: ["prompt", "output"],
    mode: "warn",
    hint: "Loads a model file in a way that can run code from it (pickle-based load, weights_only=False, trust_remote_code).",
    patterns: [
      /\b(?:torch\.load|c?[Pp]ickle\.loads?|_pickle\.loads?|joblib\.load|dill\.loads?|cloudpickle\.loads?|read_pickle|allow_pickle|load_model|trust[-_]remote[-_]code)\b/
    ],
    refine: (_m, text) => unsafeModelLoadHit(text)
  },
  {
    // AML.T0035 / #77 (LLM02) — model weights or datasets packaged or sent off the device:
    // a hub upload (huggingface-cli/hf upload, ollama push, git push to hf.co, HfApi upload from
    // python -c), an artifact path in the source position of an outbound command or piped into one,
    // or an archive/copy of artifacts into a temp dir. Downloads, pulls, cache listings and inference
    // stay silent. Reuses OUTBOUND_UPLOAD. data/model-collection.js.
    detectorId: "model-artifact-collection",
    threatId: 77,
    stages: ["prompt"],
    mode: "warn",
    hint: "Packages or uploads AI model weights or datasets (possible model theft / artifact exfiltration).",
    patterns: [
      /safetensors|\.gguf|\.ggml|\.onnx|\.ckpt|\.pth?\b|\.h5\b|\.keras\b|\.tflite|\.mlmodel|\.mlpackage|\.pkl\b|\.joblib|huggingface|\.ollama|lmstudio|lm-studio|models--|ollama\s{1,4}push|\bhf\s{1,4}upload|upload_(?:file|folder|large_folder)|push_to_hub|create_commit/i
    ],
    refine: (_m, text) => modelCollectionHit(text)
  }
];
