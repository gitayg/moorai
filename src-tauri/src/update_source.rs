// Where the auto-updater looks, decided at runtime rather than compiled in.
//
// The updater is built per check with tauri-plugin-updater 2.10.1's
// `UpdaterExt::updater_builder()` (lib.rs:71 of the plugin), which clones the plugin config —
// including `pubkey` from tauri.conf.json — and then `UpdaterBuilder::endpoints(Vec<Url>)`
// (updater.rs:197) replaces only the endpoint list. `Update::download` verifies every artifact with
// `verify_signature(&buffer, &self.signature, &self.config.pubkey)` (updater.rs:712), so a
// self-hosted console can serve only builds signed with MoorAI's key. Nothing here touches the key.
//
//   off       a managed setting (macOS managed preference DisableUpdates in the run.glick.moorai
//             domain), or "updates": "off" in ~/.moorai/config.json. No updater is built and no
//             request is made.
//   console   the device is provisioned to a console that is not a MoorAI cloud origin:
//             <console>/api/update only. The MoorAI cloud is never asked.
//   cloud     anything else (unprovisioned consumer installs, or devices on the MoorAI cloud): the
//             endpoints tauri.conf.json lists, as before.
use serde_json::Value;

pub const CLOUD_ORIGINS: [&str; 2] = ["https://app.moorai.dev", "https://moorai.glick.run"];
pub const CLOUD_ENDPOINTS: [&str; 2] = ["https://app.moorai.dev/api/update", "https://moorai.glick.run/api/update"];
pub const MANAGED_DOMAIN: &str = "run.glick.moorai";
pub const MANAGED_KEY: &str = "DisableUpdates";

#[derive(Debug, PartialEq)]
pub enum Plan {
    Off(String),
    Endpoints(Vec<String>),
}

// "updates": "off" (or false) in config.json.
pub fn config_off(cfg: &Value) -> bool {
    match cfg.get("updates") {
        Some(Value::String(s)) => s.trim().eq_ignore_ascii_case("off"),
        Some(Value::Bool(b)) => !b,
        _ => false,
    }
}

pub fn plan(console: Option<&str>, cfg: &Value, managed_off: bool) -> Plan {
    if managed_off {
        return Plan::Off(format!("turned off by the managed setting {MANAGED_KEY} ({MANAGED_DOMAIN})"));
    }
    if config_off(cfg) {
        return Plan::Off("turned off in ~/.moorai/config.json (\"updates\": \"off\")".into());
    }
    match console {
        Some(o) if !CLOUD_ORIGINS.contains(&o) => Plan::Endpoints(vec![format!("{o}/api/update")]),
        _ => Plan::Endpoints(CLOUD_ENDPOINTS.iter().map(|s| s.to_string()).collect()),
    }
}

// The console this device is provisioned to: the origin recorded host-side at enrolment
// (console_binding.rs), else config.json's serverUrl as a bare origin. The agent-writable serverUrl
// is acceptable here, unlike for credentials, because the update carries no secret and the artifact
// must still verify against MoorAI's key.
pub fn provisioned_console(dir: &str, cfg: &Value) -> Option<String> {
    crate::console_binding::resolve(dir, cfg).origin.or_else(|| {
        cfg.get("serverUrl").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty())
            .and_then(|s| crate::console_binding::normalize_origin(s).ok())
    })
}

// A managed boolean read with plutil, which reads the profile file locally (no network).
pub fn plist_bool(path: &str, key: &str) -> Option<bool> {
    if !std::path::Path::new(path).exists() { return None; }
    let out = std::process::Command::new("/usr/bin/plutil").args(["-extract", key, "raw", "-o", "-", path]).output().ok()?;
    if !out.status.success() { return None; }
    match String::from_utf8_lossy(&out.stdout).trim() {
        "true" | "1" | "YES" => Some(true),
        "false" | "0" | "NO" => Some(false),
        _ => None,
    }
}

// MDM: a configuration profile's Forced settings for the run.glick.moorai domain land in
// /Library/Managed Preferences (system) and /Library/Managed Preferences/<user> (per user). Both are
// root-owned, so an agent running as the user cannot flip them. Other platforms have no managed
// setting yet; config.json is their switch.
pub fn managed_disable_updates() -> bool {
    if !cfg!(target_os = "macos") { return false; }
    let user = crate::platform::username();
    [format!("/Library/Managed Preferences/{user}/{MANAGED_DOMAIN}.plist"), format!("/Library/Managed Preferences/{MANAGED_DOMAIN}.plist")]
        .iter()
        .find_map(|p| plist_bool(p, MANAGED_KEY))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scratch(tag: &str) -> String {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let d = std::env::temp_dir().join(format!("moorai-update-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    #[test]
    fn a_self_hosted_console_is_the_only_update_endpoint() {
        assert_eq!(plan(Some("https://moorai.acme.internal"), &json!({}), false), Plan::Endpoints(vec!["https://moorai.acme.internal/api/update".into()]));
        assert_eq!(plan(Some("https://h.example:8443"), &json!({}), false), Plan::Endpoints(vec!["https://h.example:8443/api/update".into()]));
    }

    #[test]
    fn unprovisioned_and_cloud_devices_keep_the_cloud_endpoints() {
        let cloud = Plan::Endpoints(CLOUD_ENDPOINTS.iter().map(|s| s.to_string()).collect());
        assert_eq!(plan(None, &json!({}), false), cloud);
        assert_eq!(plan(Some("https://app.moorai.dev"), &json!({}), false), cloud);
        assert_eq!(plan(Some("https://moorai.glick.run"), &json!({}), false), cloud);
    }

    #[test]
    fn updates_off_wins_over_every_endpoint() {
        for console in [None, Some("https://moorai.acme.internal"), Some("https://app.moorai.dev")] {
            assert!(matches!(plan(console, &json!({ "updates": "off" }), false), Plan::Off(_)), "{console:?}");
            assert!(matches!(plan(console, &json!({ "updates": false }), false), Plan::Off(_)), "{console:?}");
            assert!(matches!(plan(console, &json!({ "updates": "on" }), true), Plan::Off(_)), "managed off beats config on: {console:?}");
        }
        assert!(matches!(plan(None, &json!({ "updates": "on" }), false), Plan::Endpoints(_)));
        assert!(matches!(plan(None, &json!({ "updates": true }), false), Plan::Endpoints(_)));
    }

    #[test]
    fn the_cloud_endpoints_match_tauri_conf_and_the_pubkey_is_the_shipped_one() {
        let conf: Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let eps: Vec<&str> = conf["plugins"]["updater"]["endpoints"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(eps, CLOUD_ENDPOINTS.to_vec());
        assert_eq!(conf["plugins"]["updater"]["pubkey"].as_str().unwrap().trim(), include_str!("../updater-pubkey.txt").trim());
        assert!(!conf["plugins"]["updater"]["dangerousInsecureTransportProtocol"].as_bool().unwrap_or(false), "release builds must refuse http update endpoints");
    }

    #[test]
    fn the_provisioned_console_prefers_the_host_record_then_config() {
        let dir = scratch("prov");
        assert_eq!(provisioned_console(&dir, &json!({})), None);
        assert_eq!(provisioned_console(&dir, &json!({ "serverUrl": "https://moorai.acme.internal/x" })).as_deref(), Some("https://moorai.acme.internal"));
        assert_eq!(provisioned_console(&dir, &json!({ "serverUrl": "http://plain.example" })), None, "an unusable serverUrl is not an update source");
        crate::console_binding::write_binding(&dir, "https://bound.example", "enrolment").unwrap();
        assert_eq!(provisioned_console(&dir, &json!({ "serverUrl": "https://moorai.acme.internal", "installToken": "t" })).as_deref(), Some("https://bound.example"));
    }

    #[test]
    fn a_managed_plist_turns_updates_off() {
        if !cfg!(target_os = "macos") { return; }
        let dir = scratch("plist");
        let p = format!("{dir}/{MANAGED_DOMAIN}.plist");
        let write = |v: &str| std::fs::write(&p, format!(r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>{v}</dict></plist>"#)).unwrap();
        write("<key>DisableUpdates</key><true/>");
        assert_eq!(plist_bool(&p, MANAGED_KEY), Some(true));
        write("<key>DisableUpdates</key><false/>");
        assert_eq!(plist_bool(&p, MANAGED_KEY), Some(false));
        write("<key>ServerURL</key><string>https://x</string>");
        assert_eq!(plist_bool(&p, MANAGED_KEY), None);
        assert_eq!(plist_bool(&format!("{dir}/missing.plist"), MANAGED_KEY), None);
    }
}
