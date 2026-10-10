// MoorAI policy + an agent's workspace -> a Microsoft Execution Containers (MXC) launch request (the
// JSON wxc-exec.exe reads). Launch-time mirror of cli/mxc-policy.mjs: same tables, same rules, same
// output. Both replay test/fixtures/mxc/policy-cases.json, so a change to one without the other fails
// `cargo test` or `node --test`. Pure (string paths, injected existence check), so it compiles and is
// tested on every OS even though only the Windows host launches with it.
//
// Contract: microsoft/mxc @ 7cd00d1, schemas/stable/mxc-config.schema.1.0.0.json.
#![cfg_attr(not(windows), allow(dead_code))]

// egressRules -> MXC and Seatbelt network rules. Declared here so lib.rs needs no new line.
#[path = "mxc_egress.rs"]
pub mod egress;

use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const MXC_SCHEMA_VERSION: &str = "1.0.0";
pub const DEFAULT_MODEL_PROXY_PORT: u16 = 8791;
pub const AGENT_TMP: &str = "{HOME}\\.moorai\\agent-tmp";
// cli/mxc-policy.mjs NODE_PRESERVE_SYMLINKS: Node's main-module realpathSync lstat()s every ancestor and
// gets EPERM on C:\ in BaseContainer; granting enumeration on the ancestors cascades to the profile.
pub const NODE_PRESERVE_SYMLINKS: &[&str] = &["--preserve-symlinks", "--preserve-symlinks-main"];

pub const AGENT_STATE_CLAUDE: &[&str] = &["{HOME}\\.claude", "{HOME}\\.claude.json"];
pub const AGENT_STATE_CODEX: &[&str] = &["{HOME}\\.codex"];
pub const AGENT_STATE_COPILOT: &[&str] = &["{HOME}\\.copilot"];

pub const AGENT_RO_CLAUDE: &[&str] = &["{HOME}\\.local\\share\\claude"];
pub const AGENT_RO_CODEX: &[&str] = &[];
pub const AGENT_RO_COPILOT: &[&str] = &[];

pub const MOORAI_STATE: &[&str] = &["{HOME}\\.moorai", "{APPDATA}\\MoorAI", "{LOCALAPPDATA}\\MoorAI"];

pub const TOOLCHAIN_RO: &[&str] = &[
    "{PROGRAMFILES}\\nodejs",
    "{PROGRAMFILES}\\Git",
    "{PROGRAMFILES}\\PowerShell\\7",
    "{HOME}\\.gitconfig",
    "{PROGRAMDATA}\\MoorAI",
];

pub struct PathClass {
    pub id: &'static str,
    pub risk: &'static str,
    pub deny: bool,
    pub paths: &'static [&'static str],
}

// Most specific first; see cli/mxc-policy.mjs PATH_CLASSES for the rationale of each row.
pub const PATH_CLASSES: &[PathClass] = &[
    PathClass { id: "moorai-host", risk: "High", deny: true, paths: &["{LOCALAPPDATA}\\MoorAI Host"] },
    PathClass { id: "startup-folder", risk: "High", deny: true, paths: &["{APPDATA}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "{PROGRAMDATA}\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"] },
    PathClass { id: "scheduled-tasks", risk: "High", deny: true, paths: &["{SYSTEMROOT}\\System32\\Tasks", "{SYSTEMROOT}\\Tasks"] },
    PathClass { id: "shell-profile", risk: "High", deny: true, paths: &["{HOME}\\Documents\\WindowsPowerShell", "{HOME}\\Documents\\PowerShell", "{HOME}\\.bashrc", "{HOME}\\.bash_profile", "{HOME}\\.profile"] },
    PathClass { id: "credential-store", risk: "High", deny: true, paths: &["{APPDATA}\\Microsoft\\Credentials", "{LOCALAPPDATA}\\Microsoft\\Credentials", "{APPDATA}\\Microsoft\\Protect", "{APPDATA}\\Microsoft\\Crypto", "{LOCALAPPDATA}\\Microsoft\\Vault", "{PROGRAMDATA}\\Microsoft\\Vault"] },
    PathClass { id: "ssh-keys", risk: "High", deny: true, paths: &["{HOME}\\.ssh"] },
    PathClass { id: "cloud-credentials", risk: "High", deny: true, paths: &["{HOME}\\.aws", "{HOME}\\.azure", "{HOME}\\.kube", "{HOME}\\.docker", "{APPDATA}\\gcloud", "{HOME}\\.config\\gcloud"] },
    PathClass { id: "package-credentials", risk: "High", deny: true, paths: &["{HOME}\\.npmrc", "{HOME}\\.pypirc", "{HOME}\\.netrc", "{HOME}\\_netrc", "{HOME}\\.git-credentials", "{HOME}\\.config\\gh", "{APPDATA}\\GitHub CLI"] },
    PathClass { id: "browser-profile", risk: "High", deny: true, paths: &["{LOCALAPPDATA}\\Google\\Chrome\\User Data", "{LOCALAPPDATA}\\Microsoft\\Edge\\User Data", "{LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\User Data", "{APPDATA}\\Mozilla\\Firefox\\Profiles"] },
    PathClass { id: "moorai-state", risk: "Medium", deny: false, paths: &["{HOME}\\.moorai", "{APPDATA}\\MoorAI", "{LOCALAPPDATA}\\MoorAI", "{PROGRAMDATA}\\MoorAI"] },
    PathClass { id: "agent-state", risk: "Low", deny: false, paths: &["{HOME}\\.claude", "{HOME}\\.claude.json", "{HOME}\\.codex", "{HOME}\\.copilot"] },
    PathClass { id: "workspace", risk: "Low", deny: false, paths: &["{WORKSPACE}"] },
    PathClass { id: "system", risk: "Medium", deny: false, paths: &["{SYSTEMROOT}", "{PROGRAMFILES}", "{PROGRAMFILES86}", "{PROGRAMDATA}"] },
    PathClass { id: "user-profile", risk: "Medium", deny: false, paths: &["{HOME}"] },
];

pub fn agent_state(agent: &str) -> Option<&'static [&'static str]> {
    match agent {
        "claude" => Some(AGENT_STATE_CLAUDE),
        "codex" => Some(AGENT_STATE_CODEX),
        "copilot" => Some(AGENT_STATE_COPILOT),
        _ => None,
    }
}

fn agent_ro(agent: &str) -> &'static [&'static str] {
    match agent {
        "claude" => AGENT_RO_CLAUDE,
        "codex" => AGENT_RO_CODEX,
        _ => AGENT_RO_COPILOT,
    }
}

// ---- Windows path helpers (string-only) ----

fn is_drive_only(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

pub fn win_norm(p: &str) -> String {
    let s = p.trim().replace('/', "\\");
    let unc = s.starts_with("\\\\");
    let mut out = String::with_capacity(s.len() + 1);
    let mut prev = false;
    for c in s.chars() {
        if c == '\\' {
            if prev {
                continue;
            }
            prev = true;
        } else {
            prev = false;
        }
        out.push(c);
    }
    if unc {
        out.insert(0, '\\');
    }
    if is_drive_only(&out) {
        out.push('\\');
    }
    if out.chars().count() > 3 && out.ends_with('\\') {
        while out.ends_with('\\') {
            out.pop();
        }
    }
    out
}

fn key(p: &str) -> String {
    win_norm(p).to_lowercase()
}

// `\\server\share` followed by optional `\rest`; returns (has_share, has_more)
fn unc_parts(s: &str) -> Option<(bool, bool)> {
    let rest = s.strip_prefix("\\\\")?;
    let mut it = rest.split('\\');
    let server = it.next().unwrap_or("");
    let share = it.next();
    if server.is_empty() {
        return None;
    }
    match share {
        Some(sh) if !sh.is_empty() => Some((true, it.next().is_some())),
        _ => None,
    }
}

pub fn is_absolute_win(p: &str) -> bool {
    let s = win_norm(p);
    let b = s.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
        return true;
    }
    matches!(unc_parts(&s), Some((true, _)))
}

pub fn is_volume_root(p: &str) -> bool {
    let s = win_norm(p);
    let b = s.as_bytes();
    if b.len() == 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
        return true;
    }
    matches!(unc_parts(&s), Some((true, false)))
}

pub fn is_under(child: &str, parent: &str) -> bool {
    let c = key(child);
    let p = key(parent);
    if c.is_empty() || p.is_empty() {
        return false;
    }
    if c == p {
        return true;
    }
    let prefix = if p.ends_with('\\') { p } else { format!("{p}\\") };
    c.starts_with(&prefix)
}

pub fn win_dirname(p: &str) -> String {
    let s = win_norm(p);
    match s.rfind('\\') {
        None => String::new(),
        Some(i) => {
            let d = &s[..i];
            if is_drive_only(d) {
                format!("{d}\\")
            } else {
                d.to_string()
            }
        }
    }
}

fn env_get(env: &BTreeMap<String, String>, name: &str) -> String {
    env.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

// The host's NODE_OPTIONS with NODE_PRESERVE_SYMLINKS appended where missing (cli/mxc-policy.mjs nodeOptions).
pub fn node_options(env: &BTreeMap<String, String>) -> String {
    let ws = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c' | '\x0b');
    let raw = env_get(env, "NODE_OPTIONS");
    let own = raw.trim_matches(ws);
    let have: Vec<&str> = own.split(ws).collect();
    let mut parts: Vec<&str> = vec![own];
    parts.extend(NODE_PRESERVE_SYMLINKS.iter().copied().filter(|f| !have.contains(f)));
    parts.into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join(" ")
}

#[derive(Default, Clone)]
pub struct Tokens {
    pub home: String,
    pub appdata: String,
    pub localappdata: String,
    pub programdata: String,
    pub programfiles: String,
    pub programfiles86: String,
    pub systemroot: String,
    pub workspace: String,
}

pub fn tokens(env: &BTreeMap<String, String>, workspace: &str) -> Tokens {
    let abs = |v: &str| if is_absolute_win(v) { win_norm(v) } else { String::new() };
    let home = abs(&win_norm(&env_get(env, "USERPROFILE")));
    let or_home = |v: String, suffix: &str| {
        if !v.is_empty() {
            v
        } else if !home.is_empty() {
            format!("{home}{suffix}")
        } else {
            String::new()
        }
    };
    Tokens {
        appdata: or_home(abs(&env_get(env, "APPDATA")), "\\AppData\\Roaming"),
        localappdata: or_home(abs(&env_get(env, "LOCALAPPDATA")), "\\AppData\\Local"),
        programdata: abs(&env_get(env, "ProgramData")),
        programfiles: abs(&env_get(env, "ProgramFiles")),
        programfiles86: abs(&env_get(env, "ProgramFiles(x86)")),
        systemroot: abs(&env_get(env, "SystemRoot")),
        workspace: abs(workspace),
        home,
    }
}

fn token_value<'a>(t: &'a Tokens, name: &str) -> Option<&'a str> {
    let v = match name {
        "HOME" => &t.home,
        "APPDATA" => &t.appdata,
        "LOCALAPPDATA" => &t.localappdata,
        "PROGRAMDATA" => &t.programdata,
        "PROGRAMFILES" => &t.programfiles,
        "PROGRAMFILES86" => &t.programfiles86,
        "SYSTEMROOT" => &t.systemroot,
        "WORKSPACE" => &t.workspace,
        _ => return None,
    };
    if v.is_empty() {
        None
    } else {
        Some(v.as_str())
    }
}

pub fn expand(template: &str, t: &Tokens) -> String {
    let mut out = String::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) if after[..close].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) && close > 0 => {
                match token_value(t, &after[..close]) {
                    Some(v) => out.push_str(v),
                    None => return String::new(),
                }
                rest = &after[close + 1..];
            }
            _ => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    win_norm(&out)
}

pub fn classify_path(path: &str, t: &Tokens) -> &'static str {
    if !is_absolute_win(path) {
        return "other";
    }
    for c in PATH_CLASSES {
        for tpl in c.paths {
            let p = expand(tpl, t);
            if !p.is_empty() && is_under(path, &p) {
                return c.id;
            }
        }
    }
    "other"
}

fn all_digits(s: &str, min: usize, max: usize) -> bool {
    !s.is_empty() && s.len() >= min && s.len() <= max && s.bytes().all(|b| b.is_ascii_digit())
}

pub fn is_numeric_cidr(s: &str) -> bool {
    let v = s.trim();
    let Some((addr, prefix)) = v.rsplit_once('/') else { return false };
    let parts: Vec<&str> = addr.split('.').collect();
    let v4_shape = !addr.contains('/') && parts.len() == 4 && parts.iter().all(|o| all_digits(o, 1, 3)) && all_digits(prefix, 1, 2);
    if v4_shape {
        return parts.iter().all(|o| o.parse::<u32>().map(|n| n <= 255).unwrap_or(false)) && prefix.parse::<u32>().map(|n| n <= 32).unwrap_or(false);
    }
    let v6_shape = addr.contains(':') && addr.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.') && all_digits(prefix, 1, 3);
    v6_shape && prefix.parse::<u32>().map(|n| n <= 128).unwrap_or(false)
}

fn dedupe(list: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = vec![];
    for p in list {
        if p.is_empty() {
            continue;
        }
        if seen.insert(key(&p)) {
            out.push(p);
        }
    }
    out
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase", default)]
pub struct PolicyInput {
    pub agent: String,
    pub workspace: String,
    pub env: BTreeMap<String, String>,
    pub agent_bin: String,
    pub node_dir: String,
    pub hook_roots: Vec<String>,
    pub model_proxy_port: Option<i64>,
    pub egress_allow: Vec<String>,
    // MoorAI's egress rule set (cli/egress-rules.mjs shape), mapped by egress::mxc_egress.
    pub egress_rules: Option<Value>,
    pub egress_default: Option<Value>,
    pub extra_ca_certs: String,
    pub command_line: String,
    pub denials_output_path: String,
    pub capture_denials: bool,
    pub fs_deny_supported: bool,
    pub host_app_dir: String,
}

fn fail(code: &str, reason: &str) -> Value {
    json!({ "ok": false, "reasonCode": code, "reason": reason })
}

const SUPPORTED: &str = "claude, codex, copilot";

// Returns { ok:true, policy, ensureDirs, egressUnexpressed? } or { ok:false, reasonCode, reason } — the exact object
// cli/mxc-policy.mjs buildMxcPolicy returns for the same input.
pub fn build_policy(i: &PolicyInput, exists: &dyn Fn(&str) -> bool) -> Value {
    let agent = i.agent.as_str();
    let Some(state) = agent_state(agent) else {
        return fail("unsupported-agent", &format!("agent must be one of {SUPPORTED}"));
    };
    let t = tokens(&i.env, &i.workspace);
    if t.home.is_empty() {
        return fail("no-profile", "USERPROFILE is not an absolute path");
    }
    if i.workspace.trim().is_empty() {
        return fail("workspace-unset", "no agent workspace is configured; MXC grants one project directory, never the whole profile");
    }
    if t.workspace.is_empty() {
        return fail("workspace-not-absolute", "the agent workspace must be an absolute Windows path");
    }
    let ws = t.workspace.clone();
    if is_volume_root(&ws) {
        return fail("workspace-volume-root", "a volume root cannot be the workspace (BaseContainer grants on a root do not cascade; docs/schema.md)");
    }
    if is_under(&t.home, &ws) {
        return fail("workspace-is-profile", "the workspace contains the user profile; pick a project directory");
    }
    for sys in [&t.systemroot, &t.programfiles, &t.programfiles86, &t.programdata] {
        if !sys.is_empty() && is_under(&ws, sys) {
            return fail("workspace-in-system", "the workspace is inside a system directory");
        }
    }
    for c in PATH_CLASSES.iter().filter(|c| c.deny) {
        for tpl in c.paths {
            let p = expand(tpl, &t);
            if !p.is_empty() && is_under(&ws, &p) {
                return fail("workspace-in-protected", &format!("the workspace is inside a protected location ({})", c.id));
            }
        }
    }
    for c in PATH_CLASSES.iter().filter(|c| c.deny) {
        for tpl in c.paths {
            let p = expand(tpl, &t);
            if !p.is_empty() && is_under(&p, &ws) {
                return fail("workspace-contains-protected", &format!("the workspace contains a protected location ({})", c.id));
            }
        }
    }
    let app_dir = if is_absolute_win(&i.host_app_dir) { win_norm(&i.host_app_dir) } else { String::new() };
    let touches_app = |g: &str| !app_dir.is_empty() && (is_under(g, &app_dir) || is_under(&app_dir, g));
    if touches_app(&ws) {
        return fail("workspace-overlaps-host-app", "the workspace overlaps the MoorAI desktop host's install directory");
    }
    if !exists(&ws) {
        return fail("workspace-missing", "the workspace directory does not exist");
    }
    let command_line = i.command_line.trim().to_string();
    if command_line.is_empty() {
        return fail("no-command", "no agent command line");
    }
    let port = i.model_proxy_port.unwrap_or(DEFAULT_MODEL_PROXY_PORT as i64);
    if !(1..=65535).contains(&port) {
        return fail("bad-proxy-port", "modelProxyPort must be 1-65535");
    }
    let egress_allow: Vec<String> = i.egress_allow.iter().map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect();
    if egress_allow.iter().any(|c| !is_numeric_cidr(c)) {
        return fail("egress-not-numeric", "egress allow entries must be numeric CIDRs; MXC rules cannot name hosts (networking.md, 1.1 Out of GA scope)");
    }

    let agent_tmp = expand(AGENT_TMP, &t);
    let mut ens: Vec<String> = MOORAI_STATE.iter().map(|x| expand(x, &t)).collect();
    ens.push(agent_tmp.clone());
    ens.push(expand(state[0], &t));
    let ensure_dirs = dedupe(ens);
    let ensured = |p: &str| ensure_dirs.iter().any(|d| key(d) == key(p));
    let present = |p: &str| !p.is_empty() && (ensured(p) || exists(p));

    let mut rw_c = vec![ws.clone()];
    rw_c.extend(state.iter().map(|x| expand(x, &t)));
    rw_c.extend(MOORAI_STATE.iter().map(|x| expand(x, &t)));
    let rw: Vec<String> = dedupe(rw_c).into_iter().filter(|p| key(p) == key(&ws) || (present(p) && !touches_app(p))).collect();

    let norm_abs = |p: &str| if is_absolute_win(p) { win_norm(p) } else { String::new() };
    let ca_files = dedupe(vec![
        norm_abs(&i.extra_ca_certs),
        norm_abs(&env_get(&i.env, "NODE_EXTRA_CA_CERTS")),
        norm_abs(&env_get(&i.env, "SSL_CERT_FILE")),
    ]);
    let agent_bin_dir = if is_absolute_win(&i.agent_bin) { win_dirname(&i.agent_bin) } else { String::new() };
    let mut ro_c = vec![agent_bin_dir];
    ro_c.extend(agent_ro(agent).iter().map(|x| expand(x, &t)));
    ro_c.push(norm_abs(&i.node_dir));
    ro_c.extend(TOOLCHAIN_RO.iter().map(|x| expand(x, &t)));
    ro_c.extend(i.hook_roots.iter().map(|p| norm_abs(p)));
    ro_c.extend(ca_files);
    let ro_candidates = dedupe(ro_c);
    let deny_class_paths: Vec<String> = PATH_CLASSES
        .iter()
        .filter(|c| c.deny)
        .flat_map(|c| c.paths.iter().map(|x| expand(x, &t)))
        .filter(|p| !p.is_empty())
        .collect();
    let in_denied = |p: &str| deny_class_paths.iter().any(|d| is_under(p, d));
    let profiles_parent = win_dirname(&t.home);
    let broad: Vec<&str> = [t.home.as_str(), t.appdata.as_str(), t.localappdata.as_str(), profiles_parent.as_str()].into_iter().filter(|b| !b.is_empty()).collect();
    let too_broad = |p: &str| broad.iter().any(|b| is_under(b, p));
    let ro: Vec<String> = ro_candidates
        .into_iter()
        .filter(|p| present(p) && !is_volume_root(p) && !too_broad(p) && !touches_app(p) && !rw.iter().any(|g| is_under(p, g)) && !in_denied(p))
        .collect();

    let grants: Vec<&String> = rw.iter().chain(ro.iter()).collect();
    let overlapping = |d: &str| grants.iter().any(|g| is_under(d, g));
    let denied = dedupe(
        deny_class_paths
            .iter()
            .chain(std::iter::once(&app_dir))
            .filter(|d| !d.is_empty() && exists(d) && (i.fs_deny_supported || overlapping(d)))
            .cloned()
            .collect(),
    );

    let mut env = vec![format!("TEMP={agent_tmp}"), format!("TMP={agent_tmp}"), format!("NODE_OPTIONS={}", node_options(&i.env))];
    if agent == "claude" {
        env.push(format!("ANTHROPIC_BASE_URL=http://127.0.0.1:{port}/anthropic"));
        env.push("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1".into());
        env.push("DISABLE_AUTOUPDATER=1".into());
    } else if agent == "codex" {
        env.push(format!("OPENAI_BASE_URL=http://127.0.0.1:{port}/openai"));
    }
    env.push("GIT_CONFIG_COUNT=1".into());
    env.push("GIT_CONFIG_KEY_0=safe.directory".into());
    env.push(format!("GIT_CONFIG_VALUE_0={}", ws.replace('\\', "/")));
    if is_absolute_win(&i.extra_ca_certs) {
        env.push(format!("NODE_EXTRA_CA_CERTS={}", win_norm(&i.extra_ca_certs)));
    }

    // egress.default stays "deny" whatever egressDefault says; egressRules only add numeric allows and
    // denies (cli/sandbox-policy.mjs mxcNetwork).
    let mut network = json!({
        "egress": { "default": "deny" },
        "ingress": { "default": "deny", "hostLoopback": "allow" }
    });
    let has_rules = i.egress_rules.as_ref().is_some_and(|v| !v.is_null()) || i.egress_default.as_ref().is_some_and(|v| !v.is_null());
    let eg = has_rules.then(|| egress::mxc_egress(i.egress_rules.as_ref(), i.egress_default.as_ref()));
    let mut allow: Vec<Value> = vec![];
    if !egress_allow.is_empty() {
        let to: Vec<Value> = egress_allow.iter().map(|c| json!({ "cidr": c })).collect();
        allow.push(json!({ "to": to, "ports": [{ "protocol": "tcp", "port": 443 }] }));
    }
    if let Some(e) = &eg {
        allow.extend(e.allow.iter().cloned());
    }
    if !allow.is_empty() {
        network["egress"]["allow"] = json!(allow);
    }
    if let Some(e) = eg.as_ref().filter(|e| !e.deny.is_empty()) {
        network["egress"]["deny"] = json!(e.deny);
    }

    let mut pc = json!({
        "leastPrivilege": false,
        "ui": { "isolation": "desktop", "desktopSystemControl": false, "systemSettings": "none", "ime": false }
    });
    if i.capture_denials && !i.denials_output_path.trim().is_empty() {
        pc["captureDenials"] = json!({ "mode": "block", "outputPath": win_norm(&i.denials_output_path) });
    }

    let policy = json!({
        "version": MXC_SCHEMA_VERSION,
        "containment": "processcontainer",
        "process": { "commandLine": command_line, "cwd": ws, "env": env, "inheritDefaultEnv": true },
        "filesystem": { "readwritePaths": rw, "readonlyPaths": ro, "deniedPaths": denied },
        "fallback": { "allowDaclMutation": false },
        "network": network,
        "ui": { "disable": false, "clipboard": "none", "injection": false },
        "processContainer": pc
    });
    let mut out = json!({ "ok": true, "policy": policy, "ensureDirs": ensure_dirs });
    if let Some(e) = eg.filter(|e| !e.unexpressed.is_empty()) {
        out["egressUnexpressed"] = json!(e.unexpressed);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // The shared golden cases. cli/mxc-policy.mjs replays the same file in test/mxc-policy.test.mjs.
    const CASES: &str = include_str!("../../test/fixtures/mxc/policy-cases.json");

    fn exists_from(case: &Value) -> impl Fn(&str) -> bool {
        let list: Vec<String> = case["existing"].as_array().cloned().unwrap_or_default().iter().filter_map(|v| v.as_str().map(|s| s.to_lowercase())).collect();
        let all = case["existing"].as_str() == Some("*");
        move |p: &str| all || list.iter().any(|e| win_norm(e).to_lowercase() == win_norm(p).to_lowercase())
    }

    #[test]
    fn golden_policy_cases_match_the_node_reference() {
        let cases: Vec<Value> = serde_json::from_str(CASES).expect("policy-cases.json parses");
        assert!(cases.len() >= 8, "fixture lost its cases");
        for case in &cases {
            let input: PolicyInput = serde_json::from_value(case["input"].clone()).expect("input deserializes");
            let got = build_policy(&input, &exists_from(case));
            assert_eq!(got, case["expected"], "case {}", case["name"]);
        }
    }

    #[test]
    fn path_helpers() {
        assert_eq!(win_norm("c:/Users//dev/"), "c:\\Users\\dev");
        assert_eq!(win_norm("C:"), "C:\\");
        assert_eq!(win_norm("\\\\srv\\share\\x\\"), "\\\\srv\\share\\x");
        assert!(is_volume_root("D:\\") && is_volume_root("\\\\srv\\share") && !is_volume_root("D:\\x"));
        assert!(is_under("C:\\Users\\Dev\\.SSH\\id", "c:\\users\\dev\\.ssh"));
        assert!(!is_under("C:\\Users\\dev\\.sshx", "C:\\Users\\dev\\.ssh"));
        assert_eq!(win_dirname("C:\\x.exe"), "C:\\");
        assert!(is_numeric_cidr("140.82.112.0/20") && is_numeric_cidr("2606:50c0::/32"));
        assert!(!is_numeric_cidr("api.anthropic.com/32") && !is_numeric_cidr("1.2.3.4/33") && !is_numeric_cidr("300.1.1.1/8"));
    }
}
