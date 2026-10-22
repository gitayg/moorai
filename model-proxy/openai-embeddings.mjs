// OpenAI embeddings (POST …/embeddings). The request's `input` is text sent to the provider to be turned
// into vectors: a string, a list of strings, or token ids (a list of integers, or a list of such lists),
// per the official SDK (openai-node src/resources/embeddings.ts, EmbeddingCreateParams.input: "Input text
// to embed, encoded as a string or array of tokens"). Strings are scanned as prompt content (the same DLP
// a chat prompt gets); token ids are not text and are not scanned. The response carries vectors only: no
// tool call, nothing held. Errors take the Chat Completions shape (openai.mjs).
export { errorBody, streamError, replaceResponse } from "./openai.mjs";
export const NAME = "openai";
const MAX_INPUTS = 2048; // the API's own per-request input count limit

export function outboundItems(body) {
  const input = body && typeof body === "object" ? body.input : null;
  const list = typeof input === "string" ? [input] : Array.isArray(input) ? input.slice(0, MAX_INPUTS) : [];
  return list.filter((t) => typeof t === "string" && t).map((text) => ({ kind: "prompt", stage: "prompt", ctx: {}, text }));
}

export function responseToolCalls() { return []; }

// Embeddings do not stream; a stream answered anyway is passed through, never held.
export function createStream() {
  return { onEvent: async (ev) => ({ out: [ev.raw] }), onEnd: async () => ({ out: [] }), holding: false };
}
export const createReplaceStream = createStream;
