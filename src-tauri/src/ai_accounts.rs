// Which account each agent CLI is signed into, as the device report carries it (lib.rs device_accounts).
//
// The Claude account's email never leaves the device: it is sent as the keyed h2: pseudonym the agent uses
// everywhere else (content_hash.rs: HMAC-SHA-256 under a key derived from the install token, lower-cased
// first so one address is one pseudonym), and an email inside the organization name (a personal Claude
// organization is "<email>'s Organization") is replaced by the same pseudonym. The rest of the
// organization name is sent as is: a company name is what shows a work account.
use serde_json::{json, Value};

fn email_pseudonym(key: Option<&[u8; 32]>, email: &str) -> String {
    crate::content_hash::hash_with_key(key, &email.trim().to_lowercase())
}

// Claude Code's ~/.claude.json oauthAccount → { agent, account, org }, or None without an email.
pub fn claude_account(acc: &Value, key: Option<&[u8; 32]>) -> Option<Value> {
    let email = acc.get("emailAddress").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty())?;
    let org = acc.get("organizationName").and_then(|v| v.as_str()).map(|o| {
        let re = regex::Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").expect("email pattern");
        re.replace_all(o, |c: &regex::Captures| email_pseudonym(key, &c[0])).into_owned()
    });
    Some(json!({ "agent": "claude", "account": email_pseudonym(key, email), "org": org }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    // HOME pointed at a scratch dir holding `claude` as ~/.claude.json and `config` as ~/.moorai/config.json.
    fn accounts_with(claude: serde_json::Value, config: serde_json::Value) -> serde_json::Value {
        let _g = crate::console_binding::TEST_HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let home = std::env::temp_dir().join(format!("moorai-accounts-{}-{n}", std::process::id())).to_string_lossy().into_owned();
        let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let saved = std::env::var(var).ok();
        std::env::set_var(var, &home);
        std::fs::create_dir_all(format!("{home}/.moorai")).unwrap();
        std::fs::write(format!("{home}/.claude.json"), claude.to_string()).unwrap();
        std::fs::write(format!("{home}/.moorai/config.json"), config.to_string()).unwrap();
        let out = crate::device_accounts();
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

    // Unenrolled there is no key, and no report is posted (src/api.js reportDevice); the email still never
    // appears, as the NO_KEY sentinel.
    #[test]
    fn unenrolled_the_account_is_the_no_key_sentinel() {
        let out = accounts_with(json!({ "oauthAccount": { "emailAddress": "jane@example.com" } }), json!({}));
        let a = out["accounts"].as_array().unwrap().iter().find(|a| a["agent"] == "claude").cloned().unwrap();
        assert_eq!(a["account"], json!(crate::content_hash::NO_KEY), "{out}");
    }
}
