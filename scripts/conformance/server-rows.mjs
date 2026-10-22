// AI Servers conformance rows that are recorded, not run: the official provider SDKs and the amd64 server
// image. The tier installs and pulls nothing, so each row says whether the thing is present here. A
// present SDK is still not run (no driver for it yet), and says so.
import { spawnSync } from "node:child_process";

export const PROVIDER_SDKS = [
  { id: "sdk-openai-node", label: "OpenAI SDK for Node", js: "openai" },
  { id: "sdk-anthropic-node", label: "Anthropic SDK for Node", js: "@anthropic-ai/sdk" },
  { id: "sdk-google-genai-node", label: "Google Gen AI SDK for Node", js: "@google/genai" },
  { id: "sdk-ollama-node", label: "Ollama client for Node", js: "ollama" },
  { id: "sdk-openai-python", label: "OpenAI SDK for Python", py: "openai" },
  { id: "sdk-anthropic-python", label: "Anthropic SDK for Python", py: "anthropic" },
  { id: "sdk-google-genai-python", label: "Google Gen AI SDK for Python", py: "google.genai" },
  { id: "sdk-ollama-python", label: "Ollama client for Python", py: "ollama" }
];

export function jsInstalled(name) { try { import.meta.resolve(name); return true; } catch { return false; } }
export function pyInstalled(mod) {
  const r = spawnSync("python3", ["-I", "-c", `import ${mod}`], { encoding: "utf8", timeout: 20000 });
  return r.status === 0;
}

export function sdkTargets({ js = jsInstalled, py = pyInstalled } = {}) {
  return PROVIDER_SDKS.map((s) => {
    const present = s.js ? js(s.js) : py(s.py);
    return { kind: "sdk", id: s.id, label: s.label, ran: false, model: "none", reason: present ? "no-live-tier" : "sdk-not-installed", cases: [] };
  });
}

// The published sidecar image (docker/server/Dockerfile, ghcr.io/gitayg/moorai-server) for linux/amd64.
export function imageTarget() {
  const base = { kind: "image", id: "server-image-amd64", label: "MoorAI server image for linux/amd64", ran: false, model: "none", cases: [] };
  const ls = spawnSync("docker", ["image", "ls", "--format", "{{.Repository}}:{{.Tag}}"], { encoding: "utf8", timeout: 20000 });
  if (ls.status !== 0) return { ...base, reason: "image-not-present" };
  const tags = ls.stdout.split("\n").map((s) => s.trim()).filter((t) => /moorai-server/.test(t));
  if (!tags.length) return { ...base, reason: "image-not-present" };
  const ins = spawnSync("docker", ["image", "inspect", ...tags, "--format", "{{.Architecture}}"], { encoding: "utf8", timeout: 20000 });
  const amd64 = ins.status === 0 && ins.stdout.split("\n").some((a) => a.trim() === "amd64");
  return { ...base, reason: amd64 ? "no-live-tier" : "image-not-present" };
}
