// Bounded JSONL line reader for agent transcripts. A transcript on a real machine can be a gigabyte
// with single lines of hundreds of megabytes (a pasted image, a large file read), so nothing here ever
// holds more than one line of at most `maxLineBytes` in memory, and every byte read is charged against
// a shared budget. readline cannot do this: it buffers an over-long line in full.
//
// Yields { line: string } for each complete line, { oversize: true } once per line longer than
// maxLineBytes (its bytes are skipped, not buffered), and, when the file or the shared budget cut the
// read mid-line, a final { partial: true }. The caller checks its deadline between yields.
import { createReadStream } from "node:fs";
import zlib from "node:zlib";

export const ZSTD_SUPPORTED = typeof zlib.createZstdDecompress === "function";

// budget: { bytesLeft } shared across files. Returns via `state` whether this file was cut short.
export async function* boundedLines(path, { maxFileBytes, maxLineBytes, budget, state = {} }) {
  const raw = createReadStream(path, { highWaterMark: 64 * 1024 });
  const stream = path.endsWith(".zst") ? raw.pipe(zlib.createZstdDecompress()) : raw;
  let fileBytes = 0;
  let parts = [], pendingLen = 0, discarding = false;
  state.cutByFile = false;
  state.cutByBudget = false;
  try {
    for await (let chunk of stream) {
      const room = Math.min(maxFileBytes - fileBytes, budget.bytesLeft);
      if (room <= 0) { if (fileBytes >= maxFileBytes) state.cutByFile = true; else state.cutByBudget = true; break; }
      let cut = false;
      if (chunk.length > room) { chunk = chunk.subarray(0, room); cut = true; }
      fileBytes += chunk.length;
      budget.bytesLeft -= chunk.length;
      let start = 0;
      for (let nl = chunk.indexOf(10, start); nl !== -1; nl = chunk.indexOf(10, start)) {
        const piece = chunk.subarray(start, nl);
        start = nl + 1;
        if (discarding) { discarding = false; parts = []; pendingLen = 0; continue; }
        if (pendingLen + piece.length > maxLineBytes) { parts = []; pendingLen = 0; yield { oversize: true }; continue; }
        const line = pendingLen ? Buffer.concat([...parts, piece]).toString("utf8") : piece.toString("utf8");
        parts = []; pendingLen = 0;
        yield { line };
      }
      const rest = chunk.subarray(start);
      if (rest.length && !discarding) {
        if (pendingLen + rest.length > maxLineBytes) { parts = []; pendingLen = 0; discarding = true; yield { oversize: true }; }
        else { parts.push(Buffer.from(rest)); pendingLen += rest.length; }
      }
      if (cut) { if (fileBytes >= maxFileBytes) state.cutByFile = true; else state.cutByBudget = true; break; }
    }
  } finally {
    stream.destroy();
    if (stream !== raw) raw.destroy();
  }
  state.bytes = fileBytes;
  if (pendingLen && !discarding) {
    if (state.cutByFile || state.cutByBudget) yield { partial: true };
    else yield { line: Buffer.concat(parts).toString("utf8") }; // last line with no trailing newline
  }
}
