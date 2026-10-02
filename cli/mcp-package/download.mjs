// Streamed artifact download. The response body goes straight to a temp file and is hashed AS IT
// STREAMS, so the registry's sha512/sha256 is still verified end-to-end without the artifact ever being
// buffered — a 33 MB tarball costs one chunk of memory, not 33 MB (plus a copy in the extractor).
//
// PRIVACY CONTRACT is registry.mjs's, unchanged: redirects refused, no request body, no header beyond
// the (absent) accept, and the URL is the pinned registry/codeload URL the caller resolved.
//
// The partial file is removed on any failure — a cap breach, an integrity failure, or an aborted body.

import { createHash } from "node:crypto";
import { createWriteStream, rmSync } from "node:fs";
import { pipeline } from "node:stream/promises";
import { RegistryError } from "./registry.mjs";

async function* bodyChunks(res) {
  if (res.body && typeof res.body.getReader === "function") {
    const reader = res.body.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        yield Buffer.from(value);
      }
    } finally {
      try { await reader.cancel(); } catch {}
    }
    return;
  }
  if (res.body && typeof res.body[Symbol.asyncIterator] === "function") {
    for await (const c of res.body) yield Buffer.from(c);
    return;
  }
  yield Buffer.from(await res.arrayBuffer());
}

// → {bytes, digest} — digest is base64 for sha512, hex otherwise, null when no algorithm was asked for.
export async function downloadToFile(fetchImpl, url, dest, { cap, algorithm = null } = {}) {
  let res;
  try {
    res = await fetchImpl(url, { redirect: "error", headers: {} });
  } catch { throw new RegistryError("network-error"); }
  if (!res || !res.ok) throw new RegistryError(`http-${res ? res.status : 0}`);
  const len = Number(res.headers && res.headers.get && res.headers.get("content-length"));
  if (len > cap) throw new RegistryError("too-large");

  const h = algorithm && algorithm !== "none" ? createHash(algorithm) : null;
  let bytes = 0;
  const out = createWriteStream(dest, { flags: "wx", mode: 0o600 });
  // `pipeline` owns backpressure and teardown: when the source throws (cap breached, body aborted) it
  // destroys the file stream and propagates, instead of leaving a half-written file and a late write.
  try {
    await pipeline(
      (async function* () {
        for await (const chunk of bodyChunks(res)) {
          bytes += chunk.length;
          if (bytes > cap) throw new RegistryError("too-large");
          if (h) h.update(chunk);
          yield chunk;
        }
      })(),
      out
    );
  } catch (e) {
    // pipeline() rejects as soon as the source throws, WITHOUT waiting for the file stream's async
    // open. A cap breach in the first chunks therefore lands before the file exists: an immediate
    // rmSync removes nothing, and the open then creates the partial file behind it (measured: 195 of
    // 200 breaches left the file; under load the late open also races the caller's recursive rmSync
    // of the work dir into ENOTEMPTY). Wait until the stream has closed before removing the file.
    if (!out.closed) await new Promise((r) => out.once("close", r));
    try { rmSync(dest, { force: true }); } catch {}
    throw e instanceof RegistryError ? e : new RegistryError("write-error");
  }
  return { bytes, digest: h ? (algorithm === "sha512" ? h.digest("base64") : h.digest("hex")) : null };
}
