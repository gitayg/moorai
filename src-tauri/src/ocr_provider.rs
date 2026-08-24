// Provider fallback for platforms whose OS ships no text-recognition engine. Deliberately mirrors
// data/device-inference.mjs: the credential is the one ALREADY on this device — the same provider
// the developer's coding agent talks to — so no NEW third party is introduced, and the call goes
// device → provider DIRECTLY. The MoorAI console is not in the path and never sees the image.
//
// Key resolution matches deviceKey() in device-inference.mjs (env, then the admin key file), plus
// the token the user already saved in MoorAI for the agent itself. A Claude Code *subscription*
// OAuth token (sk-ant-oat…) is deliberately excluded — it is scoped to that client and the Messages
// API may reject it.
use std::time::Duration;

const API_URL: &str = "https://api.anthropic.com/v1/messages";
const DEFAULT_MODEL: &str = "claude-haiku-4-5";
const PROMPT: &str = "Transcribe every character of text visible in this image, verbatim, in reading order. Reply with ONLY the transcribed text — no commentary, no markdown, no description. If the image contains no text, reply with nothing.";

fn key_file() -> String {
    std::env::var("MOORAI_PROVIDER_KEY_FILE")
        .unwrap_or_else(|_| format!("{}/provider-key", crate::platform::config_dir()))
}

pub fn device_key() -> Option<String> {
    if let Ok(k) = std::env::var("ANTHROPIC_API_KEY") {
        let k = k.trim().to_string();
        if !k.is_empty() {
            return Some(k);
        }
    }
    if let Ok(k) = std::fs::read_to_string(key_file()) {
        let k = k.trim().to_string();
        if !k.is_empty() {
            return Some(k);
        }
    }
    crate::read_config()
        .get("agentToken")
        .and_then(|v| v.as_str())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty() && !t.starts_with("sk-ant-oat"))
}

// True when a usable provider key exists on this device. Cheap; no network.
pub fn has_device_key() -> bool {
    device_key().is_some()
}

// The Messages API accepts only these four image media types; anything else is sent as PNG.
fn media_type(mime: &str) -> &'static str {
    match mime.split(';').next().unwrap_or("").trim() {
        "image/jpeg" | "image/jpg" => "image/jpeg",
        "image/gif" => "image/gif",
        "image/webp" => "image/webp",
        _ => "image/png",
    }
}

pub fn recognize(image_b64: &str, mime: &str) -> Result<String, String> {
    let key = device_key().ok_or("no provider key on this device")?;
    let model = std::env::var("MOORAI_PROVIDER_VISION_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.into());
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 2048,
        "messages": [{
            "role": "user",
            "content": [
                { "type": "image", "source": { "type": "base64", "media_type": media_type(mime), "data": image_b64 } },
                { "type": "text", "text": PROMPT }
            ]
        }]
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(API_URL)
        .header("content-type", "application/json")
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .json(&body)
        .send()
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("provider {}", resp.status().as_u16()));
    }
    let parsed: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    let text = parsed
        .get("content")
        .and_then(|v| v.as_array())
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    Ok(text)
}
