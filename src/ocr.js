// #23 — image text extraction, device-first. Every path here goes through the native host command
// (src-tauri/src/ocr.rs); there is no HTTP in this module by design. The MoorAI console is never in
// the image path — the old /api/ocr BYO-vision-key round trip is gone, so the raw image no longer
// leaves the device to reach us.
//
// Three states, and the UI must name whichever one applies before the user pastes:
//   native   — the OS's own engine (macOS Vision, Windows OCR). Nothing leaves the device.
//   provider — no OS engine here, but this device already holds a provider key. Disclosed egress,
//              device → provider directly, and only on an explicit opt-in from the caller.
//   skipped  — neither. The feature is skipped; it never silently degrades into egress.

const SKIPPED = { native: false, engine: null, providerFallback: false };

function invoker() {
  return window.__TAURI__?.core?.invoke || null;
}

export function engineLabel(engine) {
  if (engine === "macos-vision") return "macOS Vision";
  if (engine === "windows-ocr") return "Windows OCR";
  if (engine === "linux-tesseract") return "Tesseract (Linux)";
  return "your AI provider";
}

// What this device can do. Cheap and offline — never throws, so a browser-only preview of the app
// degrades to "skipped" instead of erroring.
export async function ocrCapability() {
  const invoke = invoker();
  if (!invoke) return SKIPPED;
  try {
    return await invoke("ocr_capability");
  } catch {
    return SKIPPED;
  }
}

// Decide which of the three states applies, and the sentence the user is shown for it. Pure, so the
// ordering guarantee — provider is reachable ONLY when there is no native engine — is testable
// without a webview. `mode` is what the caller acts on; `hint` is what it displays.
export function decideImageInspection(cap, { sizeBytes = 0, maxBytes = 4 * 1024 * 1024, policyDisabled = false } = {}) {
  if (sizeBytes > maxBytes) {
    return { mode: "skip", hint: "Image too large to inspect (over 4MB). Upload event logged." };
  }
  if (policyDisabled) {
    return { mode: "skip", hint: "Image inspection is turned off in your policy. Upload event logged." };
  }
  if (cap?.native) {
    return { mode: "native", hint: `Extracting text on-device (${engineLabel(cap.engine)}) to scan for secrets & PII…` };
  }
  if (cap?.providerFallback) {
    return {
      mode: "provider",
      hint: "No on-device text recognition on this platform — the image will be sent to your AI provider using the token already on this device, not to MoorAI."
    };
  }
  return {
    mode: "skip",
    hint: "No on-device text recognition on this platform and no AI provider key on this device — image content is not inspected. Upload event logged."
  };
}

// Returns { text, engine, leftDevice }. `allowProvider` is ignored by the host whenever a native
// engine exists, so passing it can never route an image off a device that could have read it locally.
export async function ocrImage(base64, mime, allowProvider = false) {
  const invoke = invoker();
  if (!invoke) throw new Error("native host unavailable");
  return await invoke("ocr_image", { image: base64, mime: mime || "image/png", allowProvider });
}
