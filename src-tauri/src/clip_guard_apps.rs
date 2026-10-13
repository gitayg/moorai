// Which apps count as AI apps for the clipboard guard, and the words the user sees.
//
// The built-in list is the shadow-AI catalog the inventory already uses (data/ai-catalog.json, also read
// by platform.rs and cli/moorai-aibom.mjs): its macOS bundle ids ("macBundle") and the file names of its
// Windows executables ("win"), lowercased. The signed policy can add ids (clipboardGuard.aiApps) and
// approve ids (clipboardGuard.approvedApps); approval is decided in clip_guard.rs.
use std::collections::{HashMap, HashSet};

pub struct AppList { names: HashMap<String, String>, extra: HashSet<String> }

fn catalog() -> serde_json::Value {
    serde_json::from_str(include_str!("../../data/ai-catalog.json")).unwrap_or_else(|_| serde_json::json!({ "apps": [] }))
}

// The id the frontmost-app provider reports for a Windows executable path: its file name, lowercased.
pub fn exe_id(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_ascii_lowercase()
}

impl AppList {
    pub fn builtin(extra: HashSet<String>) -> AppList {
        let mut names = HashMap::new();
        for a in catalog().get("apps").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
            let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let ids = a.get("macBundle").and_then(|v| v.as_array()).cloned().unwrap_or_default().into_iter()
                .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                .chain(a.get("win").and_then(|v| v.as_array()).cloned().unwrap_or_default().into_iter().filter_map(|v| v.as_str().map(exe_id)));
            for id in ids { names.entry(id).or_insert_with(|| name.clone()); }
        }
        AppList { names, extra }
    }
}

impl crate::clip_guard::AiApps for AppList {
    fn is_ai(&self, app: &str) -> bool { self.names.contains_key(app) || self.extra.contains(app) }
    fn display_name(&self, app: &str) -> String {
        self.names.get(app).filter(|n| !n.is_empty()).cloned().unwrap_or_else(|| app.to_string())
    }
}

// Plain words for a detector id (data/detectors.js and data/secrets-patterns.js ids).
pub fn detector_label(id: &str) -> &'static str {
    match id {
        "secret-aws-akia" => "an AWS access key",
        "secret-aws-secret" => "an AWS secret key",
        "secret-github" => "a GitHub token",
        "secret-gitlab" => "a GitLab token",
        "secret-slack" => "a Slack token",
        "secret-stripe" => "a Stripe key",
        "secret-google-api" | "secret-gcp-sa" => "a Google Cloud credential",
        "secret-openai-anthropic" => "an AI provider API key",
        "secret-npm" | "secret-pypi" => "a package-registry token",
        "secret-sendgrid" | "secret-twilio" => "an API key",
        "secret-azure" => "an Azure credential",
        "secret-db-conn" => "a database password",
        "dlp-private-key" => "a private key",
        "dlp-jwt" => "an access token",
        "dlp-email" => "an email address",
        "dlp-phone" => "a phone number",
        "dlp-national-id" => "a national ID number",
        "dlp-payment-card" => "a payment card number",
        "dlp-iban" => "a bank account number",
        "dlp-ip-markers" => "text marked confidential",
        s if s.starts_with("secret-") => "a password or secret",
        _ => "sensitive data",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clip_guard::AiApps;

    #[test]
    fn the_catalog_supplies_mac_bundles_and_windows_exes() {
        let l = AppList::builtin(HashSet::new());
        for id in ["com.openai.chat", "com.openai.codex", "com.microsoft.copilot-mac", "com.anthropic.claudefordesktop", "com.todesktop.230313mzl4w4u92", "ai.perplexity.mac", "com.microsoft.copilot", "chatgpt.exe", "claude.exe", "cursor.exe", "copilot.exe", "perplexity.exe"] {
            assert!(l.is_ai(id), "{id}");
        }
        assert!(!l.is_ai("com.apple.textedit") && !l.is_ai("notepad.exe"));
        assert_eq!(l.display_name("com.openai.chat"), "ChatGPT");
        assert_eq!(l.display_name("x.y"), "x.y");
        assert_eq!(exe_id(r"C:\Users\a\AppData\Local\Programs\Claude\Claude.exe"), "claude.exe");
        assert!(AppList::builtin(["com.apple.textedit".to_string()].into()).is_ai("com.apple.textedit"));
    }
}
