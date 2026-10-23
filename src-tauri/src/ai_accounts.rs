// Which account each agent CLI is signed into, as the device report carries it (lib.rs device_accounts).
//
// The Claude account's email never leaves the device: it is sent as the keyed h2: pseudonym the agent uses
// everywhere else (content_hash.rs: HMAC-SHA-256 under a key derived from the install token, lower-cased
// first so one address is one pseudonym), and an email inside the organization name (a personal Claude
// organization is "<email>'s Organization") is replaced by the same pseudonym. The rest of the
// organization name is sent as is: a company name is what shows a work account. The email's domain is classed
// on the device (domain_class) so the console can flag a personal account without receiving the domain.
use serde_json::{json, Value};

fn email_pseudonym(key: Option<&[u8; 32]>, email: &str) -> String {
    crate::content_hash::hash_with_key(key, &email.trim().to_lowercase())
}

// The email's domain against the corporate domains of the policy this device was served, decided here because
// only the pseudonym leaves: "corporate", "personal", or "unknown" (no domains to judge by, or no domain). Exact,
// case-insensitive match, a leading "@" ignored, as the console compares.
pub fn domain_class(email: &str, corporate: &[String]) -> &'static str {
    let e = email.trim().to_lowercase();
    let Some(at) = e.rfind('@').filter(|&i| i > 0 && i + 1 < e.len()) else { return "unknown" };
    let corp: Vec<String> = corporate.iter().map(|d| d.trim().trim_start_matches('@').to_lowercase()).filter(|d| !d.is_empty()).collect();
    if corp.is_empty() { return "unknown"; }
    if corp.iter().any(|d| *d == e[at + 1..]) { "corporate" } else { "personal" }
}

// Claude Code's ~/.claude.json oauthAccount → { agent, account, domainClass, org }, or None without an email.
pub fn claude_account(acc: &Value, key: Option<&[u8; 32]>, corporate: &[String]) -> Option<Value> {
    let email = acc.get("emailAddress").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty())?;
    let org = acc.get("organizationName").and_then(|v| v.as_str()).map(|o| {
        let re = regex::Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").expect("email pattern");
        re.replace_all(o, |c: &regex::Captures| email_pseudonym(key, &c[0])).into_owned()
    });
    Some(json!({ "agent": "claude", "account": email_pseudonym(key, email), "domainClass": domain_class(email, corporate), "org": org }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    // HOME pointed at a scratch dir holding `claude` as ~/.claude.json and `config` as ~/.moorai/config.json.
    fn accounts_with(claude: serde_json::Value, config: serde_json::Value) -> serde_json::Value { accounts_with_domains(claude, config, None) }
    fn accounts_with_domains(claude: serde_json::Value, config: serde_json::Value, corp: Option<Vec<String>>) -> serde_json::Value {
        let _g = crate::console_binding::TEST_HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let home = std::env::temp_dir().join(format!("moorai-accounts-{}-{n}", std::process::id())).to_string_lossy().into_owned();
        let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let saved = std::env::var(var).ok();
        std::env::set_var(var, &home);
        std::fs::create_dir_all(format!("{home}/.moorai")).unwrap();
        std::fs::write(format!("{home}/.claude.json"), claude.to_string()).unwrap();
        std::fs::write(format!("{home}/.moorai/config.json"), config.to_string()).unwrap();
        let out = crate::device_accounts(corp);
        match saved { Some(v) => std::env::set_var(var, v), None => std::env::remove_var(var) }
        let _ = std::fs::remove_dir_all(&home);
        out
    }

    // The Claude account's email leaves the device only as the keyed h2: pseudonym the agent uses
    // everywhere else (content_hash.rs), so the console never receives it.
    #[test]
    fn the_claude_email_leaves_the_device_only_as_a_keyed_pseudonym() {
        let claude = json!({ "oauthAccount": { "emailAddress": "Jane.Doe@Example.com", "organizationName": "Acme Inc" } });
        let out = accounts_with(claude, json!({ "tenant": "acme", "installToken": "tok-SECRET-INSTALL" }));
        let key = crate::content_hash::derive_key("tok-SECRET-INSTALL");
        let a = out["accounts"].as_array().unwrap().iter().find(|a| a["agent"] == "claude").cloned().unwrap();
        assert_eq!(a["account"], json!(crate::content_hash::hash_with_key(key.as_ref(), "jane.doe@example.com")), "{out}");
        assert_eq!(a["org"], "Acme Inc", "a company name is kept: {out}");
        assert!(!out.to_string().to_lowercase().contains("jane.doe"), "the email left the device: {out}");
        assert!(!out.to_string().contains('@'), "{out}");
    }

    // A personal Claude organization is named "<email>'s Organization": the email inside it is replaced
    // by the same pseudonym, and the rest of the name is kept.
    #[test]
    fn an_email_inside_the_org_name_is_replaced_by_the_same_pseudonym() {
        let claude = json!({ "oauthAccount": { "emailAddress": "jane@gmail.com", "organizationName": "jane@gmail.com's Organization" } });
        let out = accounts_with(claude, json!({ "tenant": "acme", "installToken": "tok-SECRET-INSTALL" }));
        let h = crate::content_hash::hash_with_key(crate::content_hash::derive_key("tok-SECRET-INSTALL").as_ref(), "jane@gmail.com");
        let a = out["accounts"].as_array().unwrap().iter().find(|a| a["agent"] == "claude").cloned().unwrap();
        assert_eq!(a["account"], json!(h));
        assert_eq!(a["org"], json!(format!("{h}'s Organization")), "{out}");
        assert!(!out.to_string().contains("gmail"), "{out}");
    }

    // The domain is classed on the device, before the email is hashed, against the corporate domains of the
    // policy this device was served: corporate, personal, or unknown (no domains to judge by, or no domain).
    // No domain string leaves the device.
    #[test]
    fn the_email_domain_is_classed_on_the_device_and_no_domain_is_sent() {
        let cfg = json!({ "tenant": "acme", "installToken": "tok-SECRET-INSTALL" });
        let class = |email: &str, corp: Option<Vec<&str>>| {
            let out = accounts_with_domains(json!({ "oauthAccount": { "emailAddress": email } }), cfg.clone(), corp.map(|v| v.into_iter().map(String::from).collect()));
            let a = out["accounts"].as_array().unwrap().iter().find(|a| a["agent"] == "claude").cloned().unwrap();
            assert!(a.get("domain").is_none(), "{out}");
            assert!(!out.to_string().to_lowercase().contains("gmail") && !out.to_string().to_lowercase().contains("acme.com"), "{out}");
            a["domainClass"].as_str().unwrap_or("<none>").to_string()
        };
        assert_eq!(class("Jane@Acme.com", Some(vec!["acme.com", "acme.io"])), "corporate");
        assert_eq!(class("jane@acme.io", Some(vec!["@ACME.IO"])), "corporate", "case and a leading @ do not matter");
        assert_eq!(class("jane@gmail.com", Some(vec!["acme.com"])), "personal");
        assert_eq!(class("jane@mail.acme.com", Some(vec!["acme.com"])), "personal", "exact domain, as the console compares");
        assert_eq!(class("jane@gmail.com", Some(vec![])), "unknown", "no corporate domains: nothing to judge by");
        assert_eq!(class("jane@gmail.com", None), "unknown");
        assert_eq!(class("not-an-email", Some(vec!["acme.com"])), "unknown");
    }

    // Unenrolled there is no key, and no report is posted (src/api.js reportDevice); the email still never
    // appears, as the NO_KEY sentinel.
    #[test]
    fn unenrolled_the_account_is_the_no_key_sentinel() {
        let out = accounts_with(json!({ "oauthAccount": { "emailAddress": "jane@example.com" } }), json!({}));
        let a = out["accounts"].as_array().unwrap().iter().find(|a| a["agent"] == "claude").cloned().unwrap();
        assert_eq!(a["account"], json!(crate::content_hash::NO_KEY), "{out}");
    }
}
