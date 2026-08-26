// #23 — image inspection. A pasted screenshot is text as far as policy is concerned, so we recover
// the text and run it through the SAME PII/secret detectors as any pasted file. The ordering is the
// whole point:
//
//   1. the OS's own text-recognition engine (macOS Vision, Windows OCR) — on device, zero bundle,
//      zero egress. Always preferred; never asks.
//   2. only where the OS ships no engine, the caller may opt into the provider the developer's
//      agent already talks to, using the key already on this device (see ocr_provider.rs). Never
//      the default, never silent — the frontend discloses it and logs a content-free alert.
//   3. no engine and no key → the feature is skipped. It never degrades into hidden egress.
use base64::Engine as _;

// Matches the frontend's paste/drop limit. Large enough for a full-screen screenshot.
const MAX_IMAGE_BYTES: usize = 4 * 1024 * 1024;

#[cfg(target_os = "macos")]
fn native_engine() -> Option<&'static str> {
    crate::ocr_vision::engine()
}
#[cfg(windows)]
fn native_engine() -> Option<&'static str> {
    crate::ocr_winocr::engine()
}
#[cfg(target_os = "linux")]
fn native_engine() -> Option<&'static str> {
    crate::ocr_tesseract::engine()
}
#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
fn native_engine() -> Option<&'static str> {
    None
}

#[cfg(target_os = "macos")]
fn native_recognize(bytes: &[u8]) -> Result<String, String> {
    crate::ocr_vision::recognize(bytes)
}
#[cfg(windows)]
fn native_recognize(bytes: &[u8]) -> Result<String, String> {
    crate::ocr_winocr::recognize(bytes)
}
#[cfg(target_os = "linux")]
fn native_recognize(bytes: &[u8]) -> Result<String, String> {
    crate::ocr_tesseract::recognize(bytes)
}
#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
fn native_recognize(_bytes: &[u8]) -> Result<String, String> {
    Err("no on-device text recognition on this platform".into())
}

// What this device can do, decided BEFORE the user pastes so the UI can tell them the truth up
// front. Cheap and offline: a capability probe on the OS engine plus a key-presence check.
#[tauri::command]
pub fn ocr_capability() -> serde_json::Value {
    let engine = native_engine();
    serde_json::json!({
        "native": engine.is_some(),
        "engine": engine,
        "providerFallback": crate::ocr_provider::has_device_key(),
        "maxBytes": MAX_IMAGE_BYTES
    })
}

// Extract text from a base64 image. `allow_provider` is the frontend's explicit, disclosed opt-in
// to leaving the device; it is ignored whenever a native engine exists, so the on-device path can
// never be talked out of by the caller.
#[tauri::command]
pub fn ocr_image(image: String, mime: String, allow_provider: bool) -> Result<serde_json::Value, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(image.as_bytes())
        .map_err(|_| "image is not valid base64".to_string())?;
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err("image too large to inspect".into());
    }
    if let Some(engine) = native_engine() {
        return Ok(serde_json::json!({
            "text": native_recognize(&bytes)?,
            "engine": engine,
            "leftDevice": false
        }));
    }
    if !allow_provider {
        return Err("no on-device text recognition on this platform".into());
    }
    Ok(serde_json::json!({
        "text": crate::ocr_provider::recognize(&image, &mime)?,
        "engine": "provider",
        "leftDevice": true
    }))
}
