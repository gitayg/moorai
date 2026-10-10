// A fetch that cannot hang: aborted when no response headers arrive within timeoutMs, and again when the
// body then goes quiet for timeoutMs (an idle timer, re-armed by touch() on every chunk), so a large but
// moving download is never cut off while a stalled one is. Timeouts surface as RegistryError("timeout").
import { RegistryError } from "./registry-error.mjs";

export const REQUEST_TIMEOUT_MS = 30000;

// → { res, touch(), done() }. The caller reads the body, calling touch() per chunk and done() at the end.
export async function timedFetch(fetchImpl, url, init, timeoutMs = REQUEST_TIMEOUT_MS) {
  const ac = new AbortController();
  let timedOut = false, t = null;
  const arm = () => { clearTimeout(t); t = setTimeout(() => { timedOut = true; ac.abort(new RegistryError("timeout")); }, timeoutMs); };
  const done = () => clearTimeout(t);
  arm();
  let res;
  try {
    res = await fetchImpl(url, { ...init, signal: ac.signal });
  } catch {
    done();
    throw new RegistryError(timedOut ? "timeout" : "network-error");
  }
  arm();
  return { res, touch: arm, done, timedOut: () => timedOut };
}
