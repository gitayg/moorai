#!/usr/bin/env node
// moorai-model-scan <path|dir> [--json] [--allow <sha256>]… [--policy file.json] [--max-files N] [--max-gib N]
//
// Static model-file scan (cli/model-scan.mjs): pickle / PyTorch, Keras (.keras, .h5), TensorFlow
// SavedModel, ONNX, GGUF and SafeTensors files are inspected WITHOUT being loaded or executed. One
// verdict per file: unsafe, suspicious, clean, allowed (sha256 on the allow-list) or unscanned.
// A directory is walked recursively (symlinked directories are not followed) up to --max-files files
// (default 2000) and --max-gib GiB of candidates (default 256).
//
// --allow adds a known-good sha256; --policy reads modelScan.allowHashes from a local policy JSON.
// Runs entirely on this machine: no network, nothing posted.
// Exit 0 when no file is unsafe or suspicious, 1 when one is, 2 on a usage error or a missing path.
import { run } from "./model-scan-cli.mjs";

process.exitCode = run();
