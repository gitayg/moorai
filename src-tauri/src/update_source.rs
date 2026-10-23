// Where the auto-updater looks, decided at runtime rather than compiled in.
//
// The updater is built per check with tauri-plugin-updater 2.10.1's
// `UpdaterExt::updater_builder()` (lib.rs:71 of the plugin), which clones the plugin config —
// including `pubkey` from tauri.conf.json — and then `UpdaterBuilder::endpoints(Vec<Url>)`
// (updater.rs:197) replaces only the endpoint list. `Update::download` verifies every artifact with
// `verify_signature(&buffer, &self.signature, &self.config.pubkey)` (updater.rs:712), so a
// self-hosted console can serve only builds signed with MoorAI's key. Nothing here touches the key.
//
// ~/.moorai/config.json is writable by the agent MoorAI guards, so it has no say here: a planted
// "updates": "off" would keep the device on an old build, and a planted serverUrl could name an update
// server that answers 204 forever. Only administrator sources (admin_config.rs) and the console the host
// recorded at enrolment (console_binding.rs) count.
//
//   off       an administrator turned updates off: the macOS managed preference DisableUpdates in the
//             run.glick.moorai domain, or "updates": "off" in the machine file (/etc/moorai/config.json,
//             %ProgramData%\MoorAI\config.json) when only an administrator can write it. No updater is
//             built and no request is made.
//   console   the device's console is not a MoorAI cloud origin: <console>/api/update only. The console is
//             the administrator-provisioned one (managed ServerURL, machine-file serverUrl), else the one
//             the host recorded at enrolment. The MoorAI cloud is never asked.
//   cloud     anything else (unprovisioned consumer installs, or devices on the MoorAI cloud): the
//             endpoints tauri.conf.json lists, as before.
use serde_json::Value;

pub const CLOUD_ORIGINS: [&str; 2] = ["https://app.moorai.dev", "https://moorai.glick.run"];
pub const CLOUD_ENDPOINTS: [&str; 2] = ["https://app.moorai.dev/api/update", "https://moorai.glick.run/api/update"];

#[derive(Debug, PartialEq)]
pub enum Plan {
    Off(String),
    Endpoints(Vec<String>),
}

pub fn plan(console: Option<&str>, admin_off: Option<&str>) -> Plan {
    if let Some(why) = admin_off {
        return Plan::Off(why.to_string());
    }
    match console {
        Some(o) if !CLOUD_ORIGINS.contains(&o) => Plan::Endpoints(vec![format!("{o}/api/update")]),
        _ => Plan::Endpoints(CLOUD_ENDPOINTS.iter().map(|s| s.to_string()).collect()),
    }
}

// The console updates come from: the administrator-provisioned one, else the one recorded host-side at
// enrolment. config.json's serverUrl is read only by console_binding::resolve's one-time migration for
// installs enrolled before the record existed, exactly as for credentialed calls.
pub fn update_console(dir: &str, _cfg: &Value, admin_console: Option<&str>) -> Option<String> {
    // Only a console an administrator provisioned or the user enrolled to is an update source; one recorded
    // by first-use migration came from an agent-writable config.json.
    admin_console.map(String::from).or_else(|| crate::console_binding::enrolled_console(dir))
}

// check_and_install_update's decision.
pub fn choose(dir: &str, cfg: &Value, admin: &crate::admin_config::Admin) -> Plan {
    plan(update_console(dir, cfg, admin.console.as_deref()).as_deref(), admin.updates_off.as_deref())
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

    // ~/.moorai/config.json is writable by the agent MoorAI guards. The update decision as lib.rs's
    // check_and_install_update makes it, for a device with no admin setting.
    fn decide(dir: &str, cfg: &Value) -> Plan { choose(dir, cfg, &crate::admin_config::Admin::default()) }

    #[test]
    fn a_planted_config_neither_turns_updates_off_nor_moves_the_update_endpoint() {
        let cloud = Plan::Endpoints(CLOUD_ENDPOINTS.iter().map(|s| s.to_string()).collect());
        // no recorded console: what an agent writes to keep the device on its current build
        let none = scratch("planted-none");
        assert_eq!(decide(&none, &json!({ "updates": "off" })), cloud, "a planted updates:off stopped updates");
        assert_eq!(decide(&none, &json!({ "updates": false })), cloud, "a planted updates:false stopped updates");
        assert_eq!(decide(&none, &json!({ "serverUrl": "https://updates.evil.test" })), cloud, "a planted serverUrl chose the update endpoint");
        // enrolled to a self-hosted console: the planted values move nothing either
        let bound = scratch("planted-bound");
        crate::console_binding::write_binding(&bound, "https://moorai.acme.internal", "enrolment").unwrap();
        let acme = Plan::Endpoints(vec!["https://moorai.acme.internal/api/update".into()]);
        assert_eq!(decide(&bound, &json!({ "serverUrl": "https://updates.evil.test", "installToken": "t", "updates": "off" })), acme);
    }

    #[test]
    fn a_self_hosted_console_is_the_only_update_endpoint() {
        assert_eq!(plan(Some("https://moorai.acme.internal"), None), Plan::Endpoints(vec!["https://moorai.acme.internal/api/update".into()]));
        assert_eq!(plan(Some("https://h.example:8443"), None), Plan::Endpoints(vec!["https://h.example:8443/api/update".into()]));
    }

    #[test]
    fn unprovisioned_and_cloud_devices_keep_the_cloud_endpoints() {
        let cloud = Plan::Endpoints(CLOUD_ENDPOINTS.iter().map(|s| s.to_string()).collect());
        assert_eq!(plan(None, None), cloud);
        assert_eq!(plan(Some("https://app.moorai.dev"), None), cloud);
        assert_eq!(plan(Some("https://moorai.glick.run"), None), cloud);
    }

    #[test]
    fn an_admin_updates_off_wins_over_every_endpoint() {
        let off = crate::admin_config::Admin { console: None, updates_off: Some("turned off by the managed setting DisableUpdates (run.glick.moorai)".into()), ..Default::default() };
        for dir in [scratch("off-none"), { let d = scratch("off-bound"); crate::console_binding::write_binding(&d, "https://moorai.acme.internal", "enrolment").unwrap(); d }] {
            assert!(matches!(choose(&dir, &json!({ "updates": "on", "installToken": "t" }), &off), Plan::Off(_)), "{dir}");
        }
        let admin_file = crate::admin_config::from_sources(None, None, &json!({ "updates": "off" }), "/etc/moorai/config.json");
        assert!(matches!(choose(&scratch("off-file"), &json!({}), &admin_file), Plan::Off(_)));
    }

    #[test]
    fn an_admin_provisioned_or_enrolled_self_hosted_console_is_the_update_source() {
        let acme = Plan::Endpoints(vec!["https://moorai.acme.internal/api/update".into()]);
        // MDM: managed ServerURL / machine-file serverUrl, before any enrolment
        let mdm = crate::admin_config::from_sources(Some("https://moorai.acme.internal".into()), None, &Value::Null, "/etc/moorai/config.json");
        assert_eq!(choose(&scratch("mdm"), &json!({}), &mdm), acme);
        // enrolled in the app (console_binding.rs records the enrolment)
        let bound = scratch("enrolled");
        crate::console_binding::write_binding(&bound, "https://moorai.acme.internal", "enrolment").unwrap();
        assert_eq!(choose(&bound, &json!({ "installToken": "t" }), &crate::admin_config::Admin::default()), acme);
        // a console recorded by first-use migration came from a config.json the agent can write, so it is
        // not an update source: a planted one could answer "no update" forever and freeze the device
        let migrated = scratch("migrated");
        let cloud = Plan::Endpoints(CLOUD_ENDPOINTS.iter().map(|s| s.to_string()).collect());
        assert_eq!(choose(&migrated, &json!({ "serverUrl": "https://updates.evil.test", "installToken": "t" }), &crate::admin_config::Admin::default()), cloud);
        // the admin's console wins over a recorded one
        assert_eq!(choose(&bound, &json!({}), &crate::admin_config::Admin { console: Some("https://moorai.corp.example".into()), updates_off: None, ..Default::default() }), Plan::Endpoints(vec!["https://moorai.corp.example/api/update".into()]));
    }

    // The updater GETs each endpoint as given, substituting only {{target}}/{{arch}}/{{current_version}}/
    // {{bundle_type}} (tauri-plugin-updater 2.10.1 updater.rs check()). No endpoint carries a query or a
    // template, so an update check names no user, device, tenant or token, enrolled or not.
    #[test]
    fn an_update_check_url_carries_no_identifier() {
        let bound = scratch("ids");
        crate::console_binding::write_binding(&bound, "https://moorai.acme.internal", "enrolment").unwrap();
        for p in [plan(None, None), choose(&bound, &json!({ "installToken": "t", "tenant": "acme" }), &crate::admin_config::Admin::default())] {
            let Plan::Endpoints(eps) = p else { panic!("updates off") };
            for e in eps {
                let u = url::Url::parse(&e).unwrap();
                assert!(u.query().is_none() && !e.contains("{{") && !e.contains("%7B"), "{e}");
                assert!(u.path() == "/api/update", "{e}");
            }
        }
    }

    #[test]
    fn the_cloud_endpoints_match_tauri_conf_and_the_pubkey_is_the_shipped_one() {
        let conf: Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let eps: Vec<&str> = conf["plugins"]["updater"]["endpoints"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(eps, CLOUD_ENDPOINTS.to_vec());
        assert_eq!(conf["plugins"]["updater"]["pubkey"].as_str().unwrap().trim(), include_str!("../updater-pubkey.txt").trim());
        assert!(!conf["plugins"]["updater"]["dangerousInsecureTransportProtocol"].as_bool().unwrap_or(false), "release builds must refuse http update endpoints");
    }
}
