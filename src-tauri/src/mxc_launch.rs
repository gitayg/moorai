// Opt-in Windows launch of an agent inside Microsoft Execution Containers (MXC) through wxc-exec.exe.
//
// portable_pty 0.8 cannot add PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT to its ConPTY spawn (its
// attribute list holds one entry), so MoorAI does not create the contained process itself: the PTY
// runs `wxc-exec.exe`, and wxc-exec creates the contained child — the same shape as `sandbox-exec`
// on macOS and as microsoft/mxc PR #1400's Node `spawnWithPty` for ProcessContainer.
//
// wxc-exec flags used, all from microsoft/mxc @ 7cd00d1 docs:
//   --config <file>    docs/logging-access-denied.md ("wxc-exec --audit --config <config>"),
//                      docs/development/guides/diagnostics.md ("wxc-exec.exe --config capture-config.json")
//   --log-file <file>  docs/development/architecture/telemetry.md ("wxc-exec.exe --log-file .\mxc-audit.log
//                      .\config.json"); content-free audit records, "No config values, no filesystem paths,
//                      no command lines" (docs/telemetry.md)
//   --probe            docs/development/plans/backend-support-probe-api.md (shells out to `wxc-exec --probe`
//                      and parses its JSON `tier`); output shape = mxc_sdk::v1::ProbeOutput
//                      (docs/api-reference/rust/v1/types.md)
// There is no `--policy` flag. The command goes in `process.commandLine` inside the config rather than
// after `--`: docs/schema.md says wxc-exec "inserts or replaces process.commandLine" from the `--` tail,
// but how it joins and quotes that argv is in src/tools/wxc/src/main.rs, which is not in the sources read.
// Building the command line here keeps the quoting under test.
//
// Everything that touches the OS goes through the `Host` trait so detection and planning are unit-tested
// on any platform with a mock; `WinHost` is the real implementation.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::mxc::{build_policy, PolicyInput};
use serde_json::Value;
use std::collections::BTreeMap;

pub const WXC_EXEC: &str = "wxc-exec.exe";
pub const REQUIRED_TIER: &str = "base-container";

// microsoft/mxc @ 7cd00d1 docs/backends/process-container/os-version-support.md, "Process Isolation".
pub const PROCESS_ISOLATION_FLOORS: &[(u32, u32)] = &[(26100, 9278), (26200, 9278), (26300, 9550), (28000, 2804)];

#[derive(Debug, PartialEq)]
pub enum BuildVerdict {
    Supported,
    TooOld(String),
    // a build the table does not list (Insider/Canary); the probe decides
    Unlisted,
}

pub fn build_verdict(build: u32, ubr: u32) -> BuildVerdict {
    if let Some((_, floor)) = PROCESS_ISOLATION_FLOORS.iter().find(|(b, _)| *b == build) {
        return if ubr >= *floor {
            BuildVerdict::Supported
        } else {
            BuildVerdict::TooOld(format!("Windows build {build}.{ubr} is below {build}.{floor}, the first with MXC process isolation"))
        };
    }
    if build < PROCESS_ISOLATION_FLOORS[0].0 {
        return BuildVerdict::TooOld(format!("Windows build {build} predates MXC (needs 26100.9278 / 26200.9278 or later)"));
    }
    BuildVerdict::Unlisted
}

// "10.0.26100.9278" (the `ver` banner tail platform::os_version returns) -> (26100, 9278)
pub fn parse_os_build(v: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = v.trim().trim_end_matches(']').split('.').collect();
    if parts.len() < 4 {
        return None;
    }
    Some((parts[2].trim().parse().ok()?, parts[3].trim().parse().ok()?))
}

// ---- command line (MSVC / CommandLineToArgvW rules) ----

pub fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.chars().any(|c| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '"')) {
        return a.to_string();
    }
    let mut out = String::from("\"");
    let mut bs = 0usize;
    for c in a.chars() {
        match c {
            '\\' => bs += 1,
            '"' => {
                out.push_str(&"\\".repeat(bs * 2 + 1));
                out.push('"');
                bs = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(bs));
                bs = 0;
                out.push(c);
            }
        }
    }
    out.push_str(&"\\".repeat(bs * 2));
    out.push('"');
    out
}

pub fn command_line(argv: &[String]) -> String {
    argv.iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" ")
}

const CMD_META: &[char] = &['&', '|', '<', '>', '^', '%', '!'];

// The contained process's command line. A .cmd/.bat npm shim cannot be CreateProcess'd directly, so
// it runs under `cmd.exe /d /s /c "<line>"` (/s strips exactly the outer quotes). cmd re-parses that
// line, so a shim path or argument carrying cmd metacharacters is refused rather than escaped.
pub fn agent_command_line(bin: &str, args: &[String], system_root: &str) -> Result<String, String> {
    let mut argv = vec![bin.to_string()];
    argv.extend(args.iter().cloned());
    let lower = bin.to_ascii_lowercase();
    if lower.ends_with(".cmd") || lower.ends_with(".bat") {
        if argv.iter().any(|a| a.contains(CMD_META) || a.contains('"')) {
            return Err("the agent's .cmd shim path or arguments contain cmd.exe metacharacters".into());
        }
        let cmd = if system_root.is_empty() { "cmd.exe".to_string() } else { format!("{system_root}\\System32\\cmd.exe") };
        return Ok(format!("{} /d /s /c \"{}\"", quote_arg(&cmd), command_line(&argv)));
    }
    Ok(command_line(&argv))
}

// argv for portable_pty: wxc-exec.exe --log-file <log> --config <policy>
pub fn wxc_spawn_args(policy_path: &str, log_file: &str) -> Vec<String> {
    vec!["--log-file".into(), log_file.into(), "--config".into(), policy_path.into()]
}

pub fn wxc_probe_args(policy_path: &str) -> Vec<String> {
    vec!["--probe".into(), "--config".into(), policy_path.into()]
}

// ---- probe ----

#[derive(Debug, Default, PartialEq)]
pub struct Probe {
    pub tier: Option<String>,
    pub error: Option<String>,
    pub deny_paths: bool,
    pub native_capture: bool,
    pub host_loopback_allow: bool,
    pub warnings: usize,
}

// ProbeOutput { tier, needsDaclAugmentation, warnings, probes: ProbeFacts, error } — camelCase on the
// wire (networking.md names `probes.baseContainerSupportsIdentitylessLoopbackProxy`). Tolerates text
// around the JSON object.
pub fn parse_probe(out: &str) -> Option<Probe> {
    let start = out.find('{')?;
    let end = out.rfind('}')?;
    if end <= start {
        return None;
    }
    let v: Value = serde_json::from_str(&out[start..=end]).ok()?;
    let b = |k: &str| v.get("probes").and_then(|p| p.get(k)).and_then(|x| x.as_bool()).unwrap_or(false);
    Some(Probe {
        tier: v.get("tier").and_then(|x| x.as_str()).map(String::from),
        error: v.get("error").and_then(|x| x.as_str()).map(String::from),
        deny_paths: b("baseContainerSupportsDenyPaths"),
        native_capture: b("nativeCaptureAvailable"),
        host_loopback_allow: b("baseContainerSupportsIngressHostLoopbackAllow"),
        warnings: v.get("warnings").and_then(|w| w.as_array()).map(|a| a.len()).unwrap_or(0),
    })
}

// ---- hook roots ----

// MoorAI's hook runs inside the container, so the package it runs from must be readable. Finds every
// absolute `...\cli\moorai-hook.mjs` / `...\cli\moorai-agent-hook.mjs` in an agent's hook config text
// (JSON or TOML; JSON's doubled backslashes are folded first) and returns the package roots.
pub fn hook_roots_from_text(text: &str) -> Vec<String> {
    let s = text.replace("\\\\", "\\").replace('/', "\\");
    let lower = s.to_ascii_lowercase();
    let mut out: Vec<String> = vec![];
    for needle in ["\\cli\\moorai-hook.mjs", "\\cli\\moorai-agent-hook.mjs"] {
        let mut from = 0;
        while let Some(rel) = lower[from..].find(needle) {
            let end = from + rel;
            from = end + needle.len();
            let head = &s[..end];
            let bytes = head.as_bytes();
            let mut root = None;
            let mut k = end;
            while k >= 2 {
                k -= 1;
                if bytes[k] == b'\\' && bytes[k - 1] == b':' && k >= 2 && bytes[k - 2].is_ascii_alphabetic() {
                    let d = k - 2;
                    if d == 0 || matches!(bytes[d - 1], b'"' | b'\'' | b' ' | b'=' | b'\t' | b'\n') {
                        root = Some(head[d..].to_string());
                        break;
                    }
                }
                if matches!(bytes[k], b'"' | b'\'' | b'\n') {
                    break;
                }
            }
            if let Some(r) = root {
                let r = crate::mxc::win_norm(&r);
                if !out.iter().any(|x| x.eq_ignore_ascii_case(&r)) {
                    out.push(r);
                }
            }
        }
    }
    out
}

// ---- trust boundary ----
//
// Nothing the host reads to BUILD a launch may come from inside a read-write grant, or a contained agent
// would choose the policy of its own next launch. ~/.moorai/config.json is inside one (the hook's
// state leg), so MXC settings live in a host-only file outside every grant (PATH_CLASSES
// "moorai-host", which build_policy refuses to grant and denies explicitly where it can).

pub const HOST_SETTINGS_FILE: &str = "{LOCALAPPDATA}\\MoorAI Host\\mxc.json";

#[derive(Debug, Default, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MxcSettings {
    pub enabled: bool,
    pub workspace: String,
    pub wxc_exec: String,
    pub egress_allow: Vec<String>,
    // MoorAI's egress rule set for the container's network policy (crate::mxc::egress). Host-only, like
    // the rest of this file; the same JSON an operator puts in the console policy or machine-wide config.
    pub egress_rules: Option<Value>,
    pub egress_default: Option<Value>,
    pub extra_ca_certs: String,
    pub model_proxy_port: Option<u16>,
    pub keep_runs: bool,
    pub hook_roots: Vec<String>,
    // Console binding for the HOST's post-exit denial alerts. Host-only on purpose: config.json is
    // agent-writable, and a rewritten serverUrl would make the host send its install token elsewhere.
    pub console_url: String,
    pub install_token: String,
    pub tenant: String,
    // What happens when MXC is enabled but cannot be set up. Only FALLBACK_JOB_OBJECT launches the agent
    // without MXC; anything else, including unset, refuses the launch (decide_launch).
    pub fallback: String,
}

pub const FALLBACK_JOB_OBJECT: &str = "job-object";

// A missing or unreadable file is "MXC off", never an error that changes how the agent launches.
pub fn parse_settings(text: Option<&str>) -> MxcSettings {
    text.and_then(|t| serde_json::from_str(t).ok()).unwrap_or_default()
}

fn env_val(env: &BTreeMap<String, String>, k: &str) -> String {
    env.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| crate::mxc::win_norm(v)).unwrap_or_default()
}

// wxc-exec runs OUTSIDE the container with the user's full rights, so only two places qualify:
// Program Files (admin-writable only), or the desktop host's own install directory (build_policy never
// grants anything overlapping it). Anywhere else under the profile — PATH entries, env overrides,
// the agent's state dirs — is refused even if it exists. The signature check comes on top.
pub fn wxc_location_allowed(path: &str, app_dir: &str, env: &BTreeMap<String, String>) -> bool {
    use crate::mxc::{is_absolute_win, is_under, win_norm};
    let p = win_norm(path);
    if !is_absolute_win(&p) || !p.to_ascii_lowercase().ends_with("\\wxc-exec.exe") || p.contains("..") {
        return false;
    }
    let pf: Vec<String> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"].iter().map(|k| env_val(env, k)).filter(|v| is_absolute_win(v)).collect();
    if pf.iter().any(|d| is_under(&p, d)) {
        return true;
    }
    let app = win_norm(app_dir);
    is_absolute_win(&app) && is_under(&p, &app)
}

// `Get-AuthenticodeSignature` output reduced to "<Status>|<Subject>"; Microsoft-signed only.
pub fn signature_ok(out: &str) -> bool {
    let line = out.lines().map(str::trim).find(|l| l.contains('|')).unwrap_or("");
    let (status, subject) = line.split_once('|').unwrap_or(("", ""));
    status.eq_ignore_ascii_case("Valid") && subject.split(',').any(|f| f.trim() == "O=Microsoft Corporation")
}

// A hook root is granted read-only only if it is really a MoorAI package (cli\moorai-hook.mjs or
// cli\moorai-agent-hook.mjs plus a package.json named "moorai") and is not a broad profile root. Roots
// are discovered from agent-writable hook configs, so this check is what stops a contained agent
// from widening its next launch; build_policy also drops profile-wide roots as a last line.
pub fn valid_hook_root(host: &dyn Host, root: &str, env: &BTreeMap<String, String>) -> bool {
    use crate::mxc::{is_absolute_win, is_under, win_dirname, win_norm};
    let r = win_norm(root);
    if !is_absolute_win(&r) || crate::mxc::is_volume_root(&r) {
        return false;
    }
    let home = env_val(env, "USERPROFILE");
    let mut broad = vec![home.clone(), env_val(env, "APPDATA"), env_val(env, "LOCALAPPDATA"), win_dirname(&home)];
    if !home.is_empty() {
        broad.push(format!("{home}\\AppData"));
    }
    if broad.iter().filter(|b| !b.is_empty()).any(|b| is_under(b, &r)) {
        return false;
    }
    let has_hook = host.exists(&format!("{r}\\cli\\moorai-hook.mjs")) || host.exists(&format!("{r}\\cli\\moorai-agent-hook.mjs"));
    let named = host
        .read_file(&format!("{r}\\package.json"))
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .map(|v| v.get("name").and_then(|n| n.as_str()) == Some("moorai"))
        .unwrap_or(false);
    has_hook && named
}

// The only URL the host posts denial alerts to: https, a host, no credentials, and rebuilt from the
// parsed origin so a path/query in the setting cannot steer it. Paired with redirects off in after_exit.
pub fn alert_endpoint(console_url: &str) -> Option<String> {
    let u = url::Url::parse(console_url.trim()).ok()?;
    if u.scheme() != "https" || !u.username().is_empty() || u.password().is_some() {
        return None;
    }
    let host = u.host_str().filter(|h| !h.is_empty())?;
    let origin = match u.port() {
        Some(p) => format!("https://{host}:{p}"),
        None => format!("https://{host}"),
    };
    let endpoint = format!("{origin}/api/alerts");
    // belt and braces: the endpoint we built must still name the configured host
    (url::Url::parse(&endpoint).ok()?.host_str() == Some(host)).then_some(endpoint)
}

// (endpoint, install token, tenant) — from host-only settings or nothing at all.
pub fn session_console(settings: &MxcSettings) -> Option<(String, String, String)> {
    let token = settings.install_token.trim();
    if token.is_empty() {
        return None;
    }
    Some((alert_endpoint(&settings.console_url)?, token.to_string(), settings.tenant.trim().to_string()))
}

// ---- planning ----

// What is at a path the host is about to create as a directory, without following a final link.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DirState {
    Missing,
    Dir,
    NotDir,
    // a symlink, junction or any other reparse point
    Reparse,
    Unreadable,
}

pub trait Host {
    fn os_build(&self) -> Option<(u32, u32)>;
    fn exists(&self, path: &str) -> bool;
    // every place wxc-exec.exe might be, in preference order; plan_launch applies the trust rules
    fn wxc_candidates(&self) -> Vec<String>;
    fn microsoft_signed(&self, path: &str) -> bool;
    fn read_file(&self, path: &str) -> Option<String>;
    fn app_dir(&self) -> String;
    fn proxy_healthy(&self, port: u16) -> bool;
    fn create_dir_all(&self, path: &str) -> Result<(), String>;
    fn dir_state(&self, path: &str) -> DirState;
    fn write_file(&self, path: &str, text: &str) -> Result<(), String>;
    // stdout + stderr of `wxc-exec <args>`
    fn run(&self, exe: &str, args: &[String]) -> Result<String, String>;
}

pub struct LaunchRequest {
    pub agent: String,
    pub agent_bin: String,
    pub agent_args: Vec<String>,
    pub workspace: String,
    pub env: BTreeMap<String, String>,
    pub node_dir: String,
    pub hook_roots: Vec<String>,
    pub model_proxy_port: u16,
    pub egress_allow: Vec<String>,
    pub extra_ca_certs: String,
    pub run_dir: String,
}

#[derive(Debug, PartialEq)]
pub struct LaunchPlan {
    pub wxc_exec: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub env: Vec<(String, String)>,
    pub policy_path: String,
    pub capture_denials: bool,
    pub notes: Vec<String>,
    // the policy's ensureDirs, checked again by recheck_dirs right before wxc-exec is spawned
    pub ensure_dirs: Vec<String>,
}

fn sys_root(env: &BTreeMap<String, String>) -> String {
    env.iter().find(|(k, _)| k.eq_ignore_ascii_case("SystemRoot")).map(|(_, v)| v.clone()).unwrap_or_default()
}

// The ensureDirs sit inside read-write grants, so a contained agent could have put a file, a symlink or a
// junction where one goes. Each must be a plain directory before and after the host creates it.
fn ensure_dir(host: &dyn Host, d: &str) -> Result<(), String> {
    let why = |s: DirState| match s {
        DirState::Dir | DirState::Missing => None,
        DirState::NotDir => Some("exists but is not a directory"),
        DirState::Reparse => Some("is a symbolic link, junction or other reparse point"),
        DirState::Unreadable => Some("could not be inspected"),
    };
    let refuse = |w: &str| Err(format!("{d} {w}; the contained agent can write there, so it is not used for the container (remove it and relaunch)"));
    if let Some(w) = why(host.dir_state(d)) {
        return refuse(w);
    }
    host.create_dir_all(d)?;
    match host.dir_state(d) {
        DirState::Dir => Ok(()),
        s => refuse(why(s).unwrap_or("was not created")),
    }
}

// Every reason MoorAI will NOT launch inside MXC ends up as Err(reason); decide_launch then refuses the
// launch, or keeps today's Job Object launch when the host-only settings allow it.
pub fn plan_launch(host: &dyn Host, req: &LaunchRequest) -> Result<LaunchPlan, String> {
    match host.os_build() {
        None => return Err("could not read the Windows build number".into()),
        Some((b, u)) => {
            if let BuildVerdict::TooOld(r) = build_verdict(b, u) {
                return Err(r);
            }
        }
    }
    let app_dir = crate::mxc::win_norm(&host.app_dir());
    if !crate::mxc::is_absolute_win(&app_dir) {
        return Err("could not determine MoorAI's own install directory, so it cannot be kept out of the container's grants".into());
    }
    let candidates: Vec<String> = host.wxc_candidates().into_iter().filter(|c| host.exists(c)).collect();
    if candidates.is_empty() {
        return Err("wxc-exec.exe not found (install the MXC runtime under Program Files or next to MoorAI, or set wxcExec in %LOCALAPPDATA%\\MoorAI Host\\mxc.json)".into());
    }
    let placed: Vec<&String> = candidates.iter().filter(|c| wxc_location_allowed(c, &app_dir, &req.env)).collect();
    if placed.is_empty() {
        return Err("wxc-exec.exe was found only outside Program Files and the MoorAI install directory; it runs with full user rights, so it is not trusted there".into());
    }
    let wxc = placed.into_iter().find(|c| host.microsoft_signed(c)).cloned().ok_or("wxc-exec.exe is not Authenticode-signed by Microsoft Corporation")?;
    let uses_proxy = matches!(req.agent.as_str(), "claude" | "codex");
    if !uses_proxy && req.egress_allow.is_empty() {
        return Err(format!("{} has no loopback API route; MXC egress needs numeric CIDRs in egressAllow (%LOCALAPPDATA%\\MoorAI Host\\mxc.json)", req.agent));
    }
    if uses_proxy && !host.proxy_healthy(req.model_proxy_port) {
        return Err(format!("moorai-model-proxy is not answering on 127.0.0.1:{}; the contained agent would have no route to its API", req.model_proxy_port));
    }
    let cmd = agent_command_line(&req.agent_bin, &req.agent_args, &sys_root(&req.env))?;
    let run_dir = crate::mxc::win_norm(&req.run_dir);
    let policy_path = format!("{run_dir}\\policy.json");
    let log_file = format!("{run_dir}\\audit.log");
    let mut input = PolicyInput {
        agent: req.agent.clone(),
        workspace: req.workspace.clone(),
        env: req.env.clone(),
        agent_bin: req.agent_bin.clone(),
        node_dir: req.node_dir.clone(),
        hook_roots: req.hook_roots.iter().filter(|r| valid_hook_root(host, r, &req.env)).cloned().collect(),
        model_proxy_port: Some(req.model_proxy_port as i64),
        egress_allow: req.egress_allow.clone(),
        egress_rules: None,
        egress_default: None,
        extra_ca_certs: req.extra_ca_certs.clone(),
        command_line: cmd,
        denials_output_path: format!("{run_dir}\\denials.json"),
        capture_denials: true,
        fs_deny_supported: true,
        host_app_dir: app_dir.clone(),
    };
    // egressRules/egressDefault come from the same host-only mxc.json the caller read (LaunchRequest is
    // built in lib.rs and does not carry them), so the contained agent cannot choose its next network policy.
    let settings = parse_settings(host.read_file(&crate::mxc::expand(HOST_SETTINGS_FILE, &crate::mxc::tokens(&req.env, ""))).as_deref());
    input.egress_rules = settings.egress_rules;
    input.egress_default = settings.egress_default;
    host.create_dir_all(&run_dir)?;
    let mut notes = vec![];
    // A per-user install can sit in %LOCALAPPDATA%\\MoorAI, the hook's breadcrumb leg. build_policy
    // drops any grant overlapping the install dir; say so, because the hook loses that state leg.
    let t = crate::mxc::tokens(&req.env, &req.workspace);
    let mut rw_templates: Vec<&str> = crate::mxc::MOORAI_STATE.to_vec();
    rw_templates.extend(crate::mxc::agent_state(&req.agent).unwrap_or(&[]).iter().copied());
    for tpl in rw_templates {
        let g = crate::mxc::expand(tpl, &t);
        if !g.is_empty() && (crate::mxc::is_under(&g, &app_dir) || crate::mxc::is_under(&app_dir, &g)) {
            notes.push(format!("{tpl} overlaps the MoorAI install directory and is not granted"));
        }
    }
    // At most two rounds: the first probe can only REMOVE features (explicit denies, capture).
    for round in 0..2 {
        let plan = build_policy(&input, &|p| host.exists(p));
        if plan["ok"] != Value::Bool(true) {
            return Err(format!("MXC policy refused: {}", plan["reason"].as_str().unwrap_or("unknown")));
        }
        for d in plan["ensureDirs"].as_array().into_iter().flatten().filter_map(|d| d.as_str()) {
            ensure_dir(host, d)?;
        }
        let unexpressed = plan["egressUnexpressed"].as_array().map(|a| a.len()).unwrap_or(0);
        if round == 0 && unexpressed > 0 {
            notes.push(format!("{unexpressed} egressRules entries are not fully expressed in the MXC network policy; MoorAI's own check still applies to them (node cli/sandbox-policy.mjs --target mxc lists them)"));
        }
        let text = serde_json::to_string_pretty(&plan["policy"]).map_err(|e| e.to_string())?;
        host.write_file(&policy_path, &text)?;
        let out = host.run(&wxc, &wxc_probe_args(&policy_path))?;
        let probe = parse_probe(&out).ok_or("wxc-exec --probe returned no JSON")?;
        if let Some(e) = probe.error {
            return Err(format!("wxc-exec --probe: {e}"));
        }
        let tier = probe.tier.clone().unwrap_or_default();
        let denied_any = plan["policy"]["filesystem"]["deniedPaths"].as_array().map(|a| !a.is_empty()).unwrap_or(false);
        let mut changed = false;
        if input.fs_deny_supported && !probe.deny_paths {
            input.fs_deny_supported = false;
            changed = true;
            notes.push("native FS deny unavailable: only deny carve-outs under a grant are kept".into());
        } else if denied_any && !probe.deny_paths {
            return Err("the policy needs explicit deniedPaths but this host cannot enforce them without DACL mutation".into());
        }
        if input.capture_denials && !probe.native_capture {
            input.capture_denials = false;
            changed = true;
            notes.push("native denial capture unavailable: no denial alerts for this session".into());
        }
        if changed && round == 0 {
            continue;
        }
        if tier != REQUIRED_TIER {
            return Err(format!("MXC would run this on the '{}' tier; MoorAI launches only into {REQUIRED_TIER}", if tier.is_empty() { "unknown" } else { &tier }));
        }
        if !probe.host_loopback_allow {
            return Err("this host cannot allow host loopback for a direct-egress container, so the agent could not reach moorai-model-proxy".into());
        }
        let env = plan["policy"]["process"]["env"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| e.as_str()?.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
            .collect();
        return Ok(LaunchPlan {
            wxc_exec: wxc,
            args: wxc_spawn_args(&policy_path, &log_file),
            cwd: plan["policy"]["process"]["cwd"].as_str().unwrap_or_default().to_string(),
            env,
            policy_path,
            capture_denials: input.capture_denials,
            notes,
            ensure_dirs: plan["ensureDirs"].as_array().into_iter().flatten().filter_map(|d| d.as_str().map(String::from)).collect(),
        });
    }
    Err("wxc-exec --probe did not settle on a policy".into())
}

// The ensureDirs again, immediately before wxc-exec is spawned: plan_launch checked them, then probed,
// so a contained process could have swapped one for a junction since. Each must still be a plain
// directory. With no contained session left running (stop_prior_session) nothing inside a grant
// should be able to change them; this catches one that survived anyway.
pub fn recheck_dirs(host: &dyn Host, plan: &LaunchPlan) -> Result<(), String> {
    for d in &plan.ensure_dirs {
        let s = host.dir_state(d);
        if s != DirState::Dir {
            return Err(format!("{d} changed after it was checked ({s:?}); the contained agent can write there, so wxc-exec was not started (relaunch)"));
        }
    }
    Ok(())
}

// The session a new MXC launch replaces (lib.rs: its PTY child and its Job Object). The ensureDirs sit
// inside read-write grants, so a contained agent still running from it could swap a directory for a
// junction between plan_launch's checks and wxc-exec's spawn.
pub trait PriorSession {
    // anything of it still alive: the PTY child, or a process in its Job Object
    fn running(&self) -> bool;
    // kill the PTY child and terminate its Job Object
    fn stop(&mut self);
    // Some(why) when running() is true only because nothing proves the session gone
    fn unproven(&self) -> Option<String> {
        None
    }
}

// What MoorAI holds about the previous session, as running() reads it (lib.rs TermPrior).
#[derive(Clone, Copy, Debug)]
pub struct PriorState {
    // it was launched through wxc-exec (MXC-contained)
    pub was_contained: bool,
    // None: no Job Object handle for it; Some(None): the job's process count could not be read
    pub job: Option<Option<u32>>,
    // its PTY child has not exited
    pub child_live: bool,
}

// Whether the previous session may still be running. Fails closed: a contained session counts as
// running unless its Job Object says it is empty (wxc-exec, the PTY child, can exit while the contained
// agent lives on), and so does any job whose count cannot be read.
pub fn prior_running(s: PriorState) -> bool {
    if s.child_live {
        return true;
    }
    match s.job {
        Some(Some(n)) => n > 0,
        Some(None) => true,
        None => s.was_contained,
    }
}

// Why prior_running said "running" without anything seen running: Some when nothing could be checked.
pub fn prior_unproven(s: PriorState) -> Option<&'static str> {
    if s.child_live {
        return None;
    }
    match s.job {
        Some(None) => Some("its Job Object could not be queried"),
        None if s.was_contained => Some("it has no Job Object MoorAI can check (the job could not be created or the process not assigned to it)"),
        _ => None,
    }
}

// Before planning a new MXC launch: stop the previous session and wait, up to `tries` pauses, for it
// to be gone. Err = refuse the launch; it is never planned next to a live contained agent.
pub fn stop_prior_session(prior: &mut dyn PriorSession, tries: u32, pause: &dyn Fn()) -> Result<(), String> {
    if !prior.running() {
        return Ok(());
    }
    prior.stop();
    for _ in 0..tries {
        if !prior.running() {
            return Ok(());
        }
        pause();
    }
    if prior.running() {
        if let Some(why) = prior.unproven() {
            return Err(format!("the previous MXC-contained session cannot be confirmed stopped: {why}; MXC is not set up next to a contained agent that may still be running (end it, then restart MoorAI)"));
        }
        return Err("the previous agent session is still running and did not stop; MXC is not set up next to it (close it and relaunch)".into());
    }
    Ok(())
}

// What term_open does with a plan when MXC is enabled in the host-only settings.
#[derive(Debug, PartialEq)]
pub enum LaunchDecision {
    Contained(LaunchPlan),
    // launch without MXC (Job Object), printing the reason
    Fallback(String),
    // do not launch the agent at all, printing the reason
    Refuse(String),
}

// Fail-closed: some reasons a plan fails are under the contained agent's control (a file planted where
// an ensured dir goes), so a failure only downgrades to the Job Object when the host-only settings say so.
pub fn decide_launch(settings: &MxcSettings, planned: Result<LaunchPlan, String>) -> LaunchDecision {
    match planned {
        Ok(p) => LaunchDecision::Contained(p),
        Err(r) if settings.fallback == FALLBACK_JOB_OBJECT => LaunchDecision::Fallback(r),
        Err(r) => LaunchDecision::Refuse(r),
    }
}

// denials.<run-id>.json in the run dir, never its .verbose.json sibling (logging-access-denied.md:
// "MXC inserts a unique per-run identifier ... into the file stem").
pub fn is_denials_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("denials.") && n.ends_with(".json") && !n.ends_with(".verbose.json") && n.len() > "denials..json".len()
}

// RFC 3339 UTC timestamp (the `ts` other alerts carry) without a date crate. Days-to-civil from
// Howard Hinnant's chrono-compatible algorithm.
pub fn iso_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

// What the host keeps for one contained session, so the post-exit step can read its denials.
pub struct MxcSession {
    pub plan: LaunchPlan,
    pub run_dir: String,
    // console binding from host-only settings (session_console), never from ~/.moorai/config.json
    pub alert_endpoint: Option<String>,
    pub install_token: String,
    pub tenant: String,
    pub agent: String,
    pub workspace: String,
    pub env: BTreeMap<String, String>,
    pub keep_run: bool,
}

// ---- the real Windows host ----

#[cfg(windows)]
pub struct WinHost {
    pub wxc_override: Option<String>,
}

#[cfg(windows)]
impl Host for WinHost {
    fn os_build(&self) -> Option<(u32, u32)> {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        let k = winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion").ok();
        if let Some(k) = k {
            let build: Option<u32> = k.get_value::<String, _>("CurrentBuildNumber").ok().and_then(|s| s.parse().ok());
            let ubr: Option<u32> = k.get_value::<u32, _>("UBR").ok();
            if let (Some(b), Some(u)) = (build, ubr) {
                return Some((b, u));
            }
        }
        parse_os_build(&crate::platform::os_version())
    }
    fn exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }
    fn wxc_candidates(&self) -> Vec<String> {
        let mut c = vec![];
        if let Some(p) = &self.wxc_override {
            c.push(p.clone());
        }
        let app = self.app_dir();
        if !app.is_empty() {
            c.push(format!("{app}\\{WXC_EXEC}"));
        }
        if let Some(p) = crate::platform::which("wxc-exec") {
            c.push(p);
        }
        c
    }
    fn microsoft_signed(&self, path: &str) -> bool {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        if path.contains('\'') {
            return false;
        }
        let ps = format!("$s = Get-AuthenticodeSignature -LiteralPath '{path}'; \"$($s.Status)|$($s.SignerCertificate.Subject)\"");
        std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|o| signature_ok(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or(false)
    }
    fn read_file(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }
    fn app_dir(&self) -> String {
        std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.to_string_lossy().to_string())).unwrap_or_default()
    }
    fn proxy_healthy(&self, port: u16) -> bool {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(1500))
            .build()
            .ok()
            .and_then(|c| c.get(format!("http://127.0.0.1:{port}/healthz")).send().ok())
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
    fn create_dir_all(&self, path: &str) -> Result<(), String> {
        std::fs::create_dir_all(path).map_err(|e| format!("{path}: {e}"))
    }
    fn dir_state(&self, path: &str) -> DirState {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => DirState::Missing,
            Err(_) => DirState::Unreadable,
            Ok(m) if m.file_type().is_symlink() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => DirState::Reparse,
            Ok(m) if m.is_dir() => DirState::Dir,
            Ok(_) => DirState::NotDir,
        }
    }
    fn write_file(&self, path: &str, text: &str) -> Result<(), String> {
        crate::private_file::write_private(path, text).map_err(|e| format!("{path}: {e}"))
    }
    fn run(&self, exe: &str, args: &[String]) -> Result<String, String> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let o = std::process::Command::new(exe).args(args).creation_flags(CREATE_NO_WINDOW).output().map_err(|e| e.to_string())?;
        Ok(format!("{}\n{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
    }
}

// After the contained session exits: read and DELETE the denial files (they hold full paths), turn
// them into content-free alerts, post them through /api/alerts when enrolled. Returns a one-line,
// path-free summary for the terminal.
#[cfg(windows)]
pub fn after_exit(s: &MxcSession) -> Option<String> {
    let (run_dir, agent, env, workspace, keep_run) = (s.run_dir.as_str(), s.agent.as_str(), &s.env, s.workspace.as_str(), s.keep_run);
    let mut alerts: Vec<Value> = vec![];
    let identity = serde_json::json!({
        "user": crate::platform::username(),
        "device": crate::platform::hostname(),
        "platform": std::env::consts::OS,
        "tenant": if s.tenant.is_empty() { "unprovisioned" } else { s.tenant.as_str() },
    });
    let ts = iso_utc(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
    if let Ok(rd) = std::fs::read_dir(run_dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let lower = name.to_ascii_lowercase();
            if is_denials_file(&name) {
                if let Ok(text) = std::fs::read_to_string(e.path()) {
                    if let Ok(p) = crate::mxc_denials::parse_denials(&text, env, workspace) {
                        alerts.extend(crate::mxc_denials::denial_alerts(&p, agent, &ts, &identity));
                    }
                }
                let _ = std::fs::remove_file(e.path());
            } else if lower.starts_with("denials.") && lower.ends_with(".verbose.json") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    if !keep_run {
        let _ = std::fs::remove_dir_all(run_dir);
    }
    if alerts.is_empty() {
        return None;
    }
    // s.alert_endpoint came from session_console (host-only settings, https, origin only); redirects
    // are off so the console cannot bounce the install token somewhere else either.
    if let (Some(endpoint), false) = (&s.alert_endpoint, s.install_token.trim().is_empty()) {
        if let Ok(client) = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(4))
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            for a in &alerts {
                let _ = client.post(endpoint).header("X-Install-Token", s.install_token.trim()).json(a).send();
            }
        }
    }
    let total: u64 = alerts.iter().filter_map(|a| a["count"].as_u64()).sum();
    let classes: Vec<String> = alerts.iter().filter_map(|a| a["reasonCode"].as_str().map(String::from)).take(6).collect();
    Some(format!("MXC blocked {total} access(es): {}", classes.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Mock {
        build: Option<(u32, u32)>,
        wxc: Vec<String>,
        signed: bool,
        app: String,
        files: Vec<(String, String)>,
        proxy: bool,
        // paths that are not plain directories; anything else that exists() is one
        dir_states: Vec<(String, DirState)>,
        probes: RefCell<Vec<String>>,
        writes: RefCell<Vec<(String, String)>>,
        runs: RefCell<Vec<Vec<String>>>,
    }

    fn probe_json(tier: &str, deny: bool, capture: bool, loopback: bool) -> String {
        format!(
            r#"{{"tier":"{tier}","needsDaclAugmentation":false,"warnings":[],"probes":{{"baseContainerApiPresent":true,"nativeCaptureAvailable":{capture},"guardedCaptureAvailable":false,"bfscfgPresent":false,"bfsCompiledIn":false,"baseContainerSupportsDenyPaths":{deny},"baseContainerSupportsEnumeratePaths":true,"baseContainerSupportsIngressHostLoopbackAllow":{loopback},"baseContainerSupportsIdentitylessLoopbackProxy":true,"isolationSessionAvailable":false,"hyperlightAvailable":false}},"error":null}}"#
        )
    }

    impl Mock {
        fn ok() -> Self {
            Mock {
                build: Some((26100, 9278)),
                wxc: vec!["C:\\Program Files\\Microsoft MXC\\wxc-exec.exe".into()],
                signed: true,
                app: "C:\\Program Files\\MoorAI".into(),
                files: vec![("C:\\tools\\moorai\\package.json".into(), r#"{"name":"moorai","version":"1.5.0"}"#.into())],
                proxy: true,
                dir_states: vec![],
                probes: RefCell::new(vec![probe_json("base-container", true, true, true)]),
                writes: RefCell::new(vec![]),
                runs: RefCell::new(vec![]),
            }
        }
    }

    impl Host for Mock {
        fn os_build(&self) -> Option<(u32, u32)> {
            self.build
        }
        fn exists(&self, p: &str) -> bool {
            !p.to_ascii_lowercase().contains("missing")
        }
        fn wxc_candidates(&self) -> Vec<String> {
            self.wxc.clone()
        }
        fn microsoft_signed(&self, _p: &str) -> bool {
            self.signed
        }
        fn read_file(&self, p: &str) -> Option<String> {
            self.files.iter().find(|(k, _)| k.eq_ignore_ascii_case(p)).map(|(_, v)| v.clone())
        }
        fn app_dir(&self) -> String {
            self.app.clone()
        }
        fn proxy_healthy(&self, _port: u16) -> bool {
            self.proxy
        }
        fn create_dir_all(&self, p: &str) -> Result<(), String> {
            // as std::fs::create_dir_all: a file in the way fails, a link to a directory succeeds
            match self.dir_states.iter().find(|(k, _)| k.eq_ignore_ascii_case(p)) {
                Some((_, DirState::NotDir)) => Err(format!("{p}: Cannot create a file when that file already exists. (os error 183)")),
                _ => Ok(()),
            }
        }
        fn dir_state(&self, p: &str) -> DirState {
            match self.dir_states.iter().find(|(k, _)| k.eq_ignore_ascii_case(p)) {
                Some((_, s)) => *s,
                None if self.exists(p) => DirState::Dir,
                None => DirState::Missing,
            }
        }
        fn write_file(&self, p: &str, t: &str) -> Result<(), String> {
            self.writes.borrow_mut().push((p.into(), t.into()));
            Ok(())
        }
        fn run(&self, _exe: &str, args: &[String]) -> Result<String, String> {
            self.runs.borrow_mut().push(args.to_vec());
            let mut p = self.probes.borrow_mut();
            Ok(if p.len() > 1 { p.remove(0) } else { p[0].clone() })
        }
    }

    fn req(agent: &str) -> LaunchRequest {
        let env: BTreeMap<String, String> = [
            ("USERPROFILE", "C:\\Users\\dev"),
            ("SystemRoot", "C:\\Windows"),
            ("ProgramFiles", "C:\\Program Files"),
            ("ProgramData", "C:\\ProgramData"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        LaunchRequest {
            agent: agent.into(),
            agent_bin: "C:\\Users\\dev\\.local\\bin\\claude.exe".into(),
            agent_args: vec!["--continue".into()],
            workspace: "C:\\src\\proj".into(),
            env,
            node_dir: "C:\\Program Files\\nodejs".into(),
            hook_roots: vec![],
            model_proxy_port: 8791,
            egress_allow: vec![],
            extra_ca_certs: String::new(),
            run_dir: "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\mxc-runs\\r1".into(),
        }
    }

    #[test]
    fn build_floors_follow_the_os_version_table() {
        assert_eq!(build_verdict(26100, 9278), BuildVerdict::Supported);
        assert_eq!(build_verdict(26200, 9300), BuildVerdict::Supported);
        assert!(matches!(build_verdict(26100, 9277), BuildVerdict::TooOld(_)));
        assert!(matches!(build_verdict(26300, 9549), BuildVerdict::TooOld(_)));
        assert_eq!(build_verdict(28000, 2804), BuildVerdict::Supported);
        assert!(matches!(build_verdict(22631, 9999), BuildVerdict::TooOld(_)));
        assert_eq!(build_verdict(26657, 1002), BuildVerdict::Unlisted);
        assert_eq!(parse_os_build("10.0.26100.9278"), Some((26100, 9278)));
        assert_eq!(parse_os_build("10.0.26200.9301]"), Some((26200, 9301)));
        assert_eq!(parse_os_build("garbage"), None);
    }

    #[test]
    fn command_line_quoting_round_trips_msvc_rules() {
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("C:\\Program Files\\x"), "\"C:\\Program Files\\x\"");
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_arg("C:\\dir with space\\"), "\"C:\\dir with space\\\\\"");
        assert_eq!(
            agent_command_line("C:\\Users\\dev\\.local\\bin\\claude.exe", &["--continue".into()], "C:\\Windows").unwrap(),
            "C:\\Users\\dev\\.local\\bin\\claude.exe --continue"
        );
        assert_eq!(
            agent_command_line("C:\\Users\\a b\\AppData\\Roaming\\npm\\claude.cmd", &[], "C:\\Windows").unwrap(),
            "C:\\Windows\\System32\\cmd.exe /d /s /c \"\"C:\\Users\\a b\\AppData\\Roaming\\npm\\claude.cmd\"\""
        );
        assert!(agent_command_line("C:\\x&calc\\claude.cmd", &[], "C:\\Windows").is_err());
    }

    #[test]
    fn spawn_args_are_the_documented_wxc_exec_flags() {
        assert_eq!(wxc_spawn_args("C:\\r\\policy.json", "C:\\r\\audit.log"), vec!["--log-file", "C:\\r\\audit.log", "--config", "C:\\r\\policy.json"]);
        assert_eq!(wxc_probe_args("C:\\r\\policy.json"), vec!["--probe", "--config", "C:\\r\\policy.json"]);
    }

    #[test]
    fn probe_output_parses_the_documented_fields() {
        let p = parse_probe(&format!("note\n{}\n", probe_json("base-container", true, false, true))).unwrap();
        assert_eq!(p.tier.as_deref(), Some("base-container"));
        assert!(p.deny_paths && !p.native_capture && p.host_loopback_allow && p.error.is_none());
        assert!(parse_probe("no json here").is_none());
    }

    #[test]
    fn happy_path_launches_wxc_exec_with_the_written_policy() {
        let m = Mock::ok();
        let plan = plan_launch(&m, &req("claude")).expect("plan");
        assert_eq!(plan.wxc_exec, "C:\\Program Files\\Microsoft MXC\\wxc-exec.exe");
        let rd = "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\mxc-runs\\r1";
        assert_eq!(plan.args, vec!["--log-file".to_string(), format!("{rd}\\audit.log"), "--config".into(), format!("{rd}\\policy.json")]);
        assert_eq!(plan.cwd, "C:\\src\\proj");
        assert!(plan.capture_denials);
        assert!(plan.env.contains(&("ANTHROPIC_BASE_URL".into(), "http://127.0.0.1:8791/anthropic".into())));
        let (path, text) = m.writes.borrow().last().cloned().unwrap();
        assert_eq!(path, format!("{rd}\\policy.json"));
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["process"]["commandLine"], "C:\\Users\\dev\\.local\\bin\\claude.exe --continue");
        assert_eq!(v["fallback"]["allowDaclMutation"], false);
        assert_eq!(m.runs.borrow()[0], vec!["--probe".to_string(), "--config".into(), format!("{rd}\\policy.json")]);
        assert!(v["network"]["egress"].get("deny").is_none(), "no egressRules in mxc.json: no deny rules");
    }

    // egressRules in the host-only mxc.json reach the written policy; what MXC cannot carry is a note.
    #[test]
    fn egress_rules_from_host_settings_reach_the_policy() {
        let mut m = Mock::ok();
        m.files.push((
            "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\mxc.json".into(),
            r#"{"enabled":true,"egressRules":[{"host":"203.0.113.4","action":"block"},{"host":"api.github.com","action":"allow"}],"egressDefault":"block"}"#.into(),
        ));
        let plan = plan_launch(&m, &req("claude")).expect("plan");
        let (_, text) = m.writes.borrow().last().cloned().unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["network"]["egress"]["default"], "deny");
        assert_eq!(v["network"]["egress"]["deny"], serde_json::json!([{ "to": [{ "cidr": "203.0.113.4/32" }] }]));
        assert_eq!(plan.notes.iter().filter(|n| n.contains("egressRules entries are not fully expressed")).count(), 1);
    }

    #[test]
    fn every_missing_capability_falls_back_with_a_reason() {
        let mut m = Mock::ok();
        m.build = Some((26100, 9000));
        assert!(plan_launch(&m, &req("claude")).unwrap_err().contains("26100.9278"));
        let mut m = Mock::ok();
        m.build = None;
        assert!(plan_launch(&m, &req("claude")).is_err());
        let mut m = Mock::ok();
        m.wxc = vec![];
        assert!(plan_launch(&m, &req("claude")).unwrap_err().contains("wxc-exec.exe not found"));
        let mut m = Mock::ok();
        m.proxy = false;
        assert!(plan_launch(&m, &req("claude")).unwrap_err().contains("moorai-model-proxy"));
        let m = Mock::ok();
        assert!(plan_launch(&m, &req("copilot")).unwrap_err().contains("egressAllow"));
        let m = Mock::ok();
        *m.probes.borrow_mut() = vec![probe_json("appcontainer-dacl", true, true, true)];
        assert!(plan_launch(&m, &req("claude")).unwrap_err().contains("appcontainer-dacl"));
        let m = Mock::ok();
        *m.probes.borrow_mut() = vec![probe_json("base-container", true, true, false)];
        assert!(plan_launch(&m, &req("claude")).unwrap_err().contains("host loopback"));
        let m = Mock::ok();
        *m.probes.borrow_mut() = vec![r#"{"tier":null,"warnings":[],"probes":{},"error":"backend_unavailable"}"#.into()];
        assert!(plan_launch(&m, &req("claude")).unwrap_err().contains("backend_unavailable"));
        let mut r = req("claude");
        r.workspace = "C:\\Users\\dev".into();
        assert!(plan_launch(&Mock::ok(), &r).unwrap_err().contains("contains the user profile"));
    }

    #[test]
    fn a_host_without_native_capture_or_fs_deny_reprobes_with_those_features_dropped() {
        let m = Mock::ok();
        *m.probes.borrow_mut() = vec![probe_json("base-container", false, false, true), probe_json("base-container", false, false, true)];
        let plan = plan_launch(&m, &req("claude")).expect("plan");
        assert!(!plan.capture_denials);
        assert_eq!(plan.notes.len(), 2);
        assert_eq!(m.runs.borrow().len(), 2, "re-probed once");
        let v: Value = serde_json::from_str(&m.writes.borrow().last().unwrap().1).unwrap();
        assert!(v["processContainer"].get("captureDenials").is_none());
        assert_eq!(v["filesystem"]["deniedPaths"], serde_json::json!([]));
    }

    #[test]
    fn hook_roots_come_from_the_agents_hook_config() {
        let settings = r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"node \"C:\\Users\\dev\\AppData\\Roaming\\npm\\node_modules\\moorai\\cli\\moorai-hook.mjs\""}]}]}}"#;
        assert_eq!(hook_roots_from_text(settings), vec!["C:\\Users\\dev\\AppData\\Roaming\\npm\\node_modules\\moorai".to_string()]);
        let codex = r#"command = "C:\\Program Files\\nodejs\\node.exe D:\\GAI Apps\\RAISEME\\cli\\moorai-agent-hook.mjs --agent codex""#;
        assert_eq!(hook_roots_from_text(codex), vec!["D:\\GAI Apps\\RAISEME".to_string()]);
        assert!(hook_roots_from_text(r#"node "${CLAUDE_PLUGIN_ROOT}/cli/moorai-hook.mjs""#).is_empty());
    }

    #[test]
    fn wxc_exec_must_live_in_program_files_or_the_app_dir_and_be_microsoft_signed() {
        let env = req("claude").env;
        let app = "C:\\Users\\dev\\AppData\\Local\\MoorAI";
        assert!(wxc_location_allowed("C:\\Program Files\\Microsoft MXC\\wxc-exec.exe", app, &env));
        assert!(wxc_location_allowed("c:/users/dev/appdata/local/moorai/WXC-EXEC.EXE", app, &env));
        assert!(!wxc_location_allowed("C:\\Users\\dev\\.moorai\\wxc-exec.exe", app, &env), "agent-writable state dir");
        assert!(!wxc_location_allowed("C:\\src\\proj\\wxc-exec.exe", app, &env), "workspace");
        assert!(!wxc_location_allowed("C:\\Program Files\\..\\Users\\dev\\wxc-exec.exe", app, &env));
        assert!(!wxc_location_allowed("C:\\Program Files\\MXC\\evil.exe", app, &env));
        assert!(!wxc_location_allowed("wxc-exec.exe", app, &env));

        let mut m = Mock::ok();
        m.wxc = vec!["C:\\Users\\dev\\.claude\\wxc-exec.exe".into()];
        assert!(plan_launch(&m, &req("claude")).unwrap_err().contains("not trusted"));
        // an untrusted override is skipped in favour of a trusted install further down the list
        let mut m = Mock::ok();
        m.wxc = vec!["C:\\Users\\dev\\.claude\\wxc-exec.exe".into(), "C:\\Program Files\\Microsoft MXC\\wxc-exec.exe".into()];
        assert_eq!(plan_launch(&m, &req("claude")).unwrap().wxc_exec, "C:\\Program Files\\Microsoft MXC\\wxc-exec.exe");
        let mut m = Mock::ok();
        m.signed = false;
        assert!(plan_launch(&m, &req("claude")).unwrap_err().contains("signed by Microsoft"));

        assert!(signature_ok("Valid|CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US\r\n"));
        assert!(!signature_ok("NotSigned|"));
        assert!(!signature_ok("Valid|CN=Evil, O=Microsoft Corporation Fake, C=US"));
        assert!(!signature_ok("HashMismatch|CN=Microsoft Corporation, O=Microsoft Corporation"));
    }

    #[test]
    fn the_host_install_dir_is_never_granted_and_must_be_known() {
        let mut m = Mock::ok();
        m.app = String::new();
        assert!(plan_launch(&m, &req("claude")).unwrap_err().contains("install directory"));

        // per-user install in the hook's breadcrumb leg: that grant is dropped, noted, and the dir denied
        let mut m = Mock::ok();
        m.app = "C:\\Users\\dev\\AppData\\Local\\MoorAI".into();
        m.wxc = vec!["C:\\Users\\dev\\AppData\\Local\\MoorAI\\wxc-exec.exe".into()];
        let mut r = req("claude");
        r.env.insert("LOCALAPPDATA".into(), "C:\\Users\\dev\\AppData\\Local".into());
        let plan = plan_launch(&m, &r).expect("plan");
        assert!(plan.notes.iter().any(|n| n.contains("{LOCALAPPDATA}\\MoorAI overlaps")), "{:?}", plan.notes);
        let v: Value = serde_json::from_str(&m.writes.borrow().last().unwrap().1).unwrap();
        let fs = &v["filesystem"];
        for g in fs["readwritePaths"].as_array().unwrap().iter().chain(fs["readonlyPaths"].as_array().unwrap()) {
            let g = g.as_str().unwrap();
            assert!(!crate::mxc::is_under(g, &m.app) && !crate::mxc::is_under(&m.app, g), "grant {g} overlaps the install dir");
        }
        assert!(fs["deniedPaths"].as_array().unwrap().iter().any(|d| d == "C:\\Users\\dev\\AppData\\Local\\MoorAI"));

        let mut m = Mock::ok();
        m.app = "C:\\src\\proj\\moorai-build".into();
        assert!(plan_launch(&m, &req("claude")).unwrap_err().contains("install directory"));
    }

    #[test]
    fn hook_roots_are_granted_only_when_they_are_a_real_moorai_package_and_not_a_profile_root() {
        let m = Mock::ok();
        let env = req("claude").env;
        assert!(valid_hook_root(&m, "C:\\tools\\moorai", &env));
        assert!(!valid_hook_root(&m, "C:\\tools\\other", &env), "no package.json named moorai");
        let mut m2 = Mock::ok();
        m2.files.push(("C:\\Users\\dev\\package.json".into(), r#"{"name":"moorai"}"#.into()));
        m2.files.push(("C:\\Users\\package.json".into(), r#"{"name":"moorai"}"#.into()));
        for broad in ["C:\\Users\\dev", "C:\\Users", "C:\\Users\\dev\\AppData", "C:\\"] {
            assert!(!valid_hook_root(&m2, broad, &env), "{broad} is too broad");
        }
        let mut m3 = Mock::ok();
        m3.files.push(("C:\\x\\missing\\package.json".into(), r#"{"name":"moorai"}"#.into()));
        assert!(!valid_hook_root(&m3, "C:\\x\\missing", &env), "no cli\\moorai-hook.mjs");

        let mut r = req("claude");
        r.hook_roots = vec!["C:\\tools\\moorai".into(), "C:\\tools\\other".into(), "C:\\Users\\dev".into()];
        let m = Mock::ok();
        plan_launch(&m, &r).expect("plan");
        let v: Value = serde_json::from_str(&m.writes.borrow().last().unwrap().1).unwrap();
        let ro: Vec<&str> = v["filesystem"]["readonlyPaths"].as_array().unwrap().iter().filter_map(|x| x.as_str()).collect();
        assert!(ro.contains(&"C:\\tools\\moorai") && !ro.contains(&"C:\\tools\\other") && !ro.contains(&"C:\\Users\\dev"), "{ro:?}");
    }

    #[test]
    fn launch_settings_come_from_the_host_only_file_and_default_off() {
        assert_eq!(parse_settings(None), MxcSettings::default());
        assert!(!parse_settings(Some("{not json")).enabled);
        let s = parse_settings(Some(r#"{"enabled":true,"workspace":"C:\\src\\proj","egressAllow":["140.82.112.0/20"],"modelProxyPort":9000}"#));
        assert!(s.enabled && s.workspace == "C:\\src\\proj" && s.model_proxy_port == Some(9000) && s.egress_allow.len() == 1);
        // the host-only dir is a protected class: never granted, and a workspace inside or around it is refused
        let t = crate::mxc::Tokens { localappdata: "C:\\Users\\dev\\AppData\\Local".into(), ..Default::default() };
        assert_eq!(crate::mxc::classify_path(&crate::mxc::expand(HOST_SETTINGS_FILE, &t), &t), "moorai-host");
        let mut r = req("claude");
        r.env.insert("LOCALAPPDATA".into(), "C:\\Users\\dev\\AppData\\Local".into());
        r.workspace = "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\ws".into();
        assert!(plan_launch(&Mock::ok(), &r).unwrap_err().contains("protected"));
    }

    #[test]
    fn host_alerts_go_only_to_the_https_console_named_in_host_only_settings() {
        assert_eq!(alert_endpoint("https://app.moorai.dev").as_deref(), Some("https://app.moorai.dev/api/alerts"));
        assert_eq!(alert_endpoint("https://app.moorai.dev/some/path?x=1#f").as_deref(), Some("https://app.moorai.dev/api/alerts"));
        assert_eq!(alert_endpoint("https://console.example:8443/").as_deref(), Some("https://console.example:8443/api/alerts"));
        for bad in ["http://app.moorai.dev", "file:///C:/x", "https://user:pw@app.moorai.dev", "https://", "app.moorai.dev", "", "ftp://app.moorai.dev"] {
            assert_eq!(alert_endpoint(bad), None, "{bad} must not be a post target");
        }
        let s = parse_settings(Some(r#"{"enabled":true,"consoleUrl":"https://app.moorai.dev","installToken":"tok","tenant":"acme"}"#));
        assert_eq!(session_console(&s), Some(("https://app.moorai.dev/api/alerts".into(), "tok".into(), "acme".into())));
        // no host-only binding -> the host posts nothing (it never falls back to ~/.moorai/config.json)
        assert_eq!(session_console(&parse_settings(Some(r#"{"enabled":true}"#))), None);
        assert_eq!(session_console(&parse_settings(Some(r#"{"consoleUrl":"https://app.moorai.dev","installToken":"  "}"#))), None);
    }

    const AGENT_TMP_DIR: &str = "C:\\Users\\dev\\.moorai\\agent-tmp";

    #[test]
    fn mxc_on_and_a_failed_plan_refuses_the_launch_unless_host_settings_allow_the_job_object() {
        let on = parse_settings(Some(r#"{"enabled":true}"#));
        assert_eq!(on.fallback, "");
        assert_eq!(decide_launch(&on, Err("no wxc-exec".into())), LaunchDecision::Refuse("no wxc-exec".into()));
        for other in ["", "none", "JOB-OBJECT", " job-object", "jobobject", "true"] {
            let s = MxcSettings { enabled: true, fallback: other.into(), ..Default::default() };
            assert!(matches!(decide_launch(&s, Err("x".into())), LaunchDecision::Refuse(_)), "fallback {other:?} must not allow an unisolated launch");
        }
        let allow = parse_settings(Some(r#"{"enabled":true,"fallback":"job-object"}"#));
        assert_eq!(decide_launch(&allow, Err("no wxc-exec".into())), LaunchDecision::Fallback("no wxc-exec".into()));
        let m = Mock::ok();
        assert!(matches!(decide_launch(&on, plan_launch(&m, &req("claude"))), LaunchDecision::Contained(_)));
    }

    #[test]
    fn an_agent_planted_file_at_agent_tmp_refuses_the_launch_instead_of_dropping_isolation() {
        // ~/.moorai is read-write inside the container, so the agent can put a FILE where agent-tmp goes
        let mut m = Mock::ok();
        m.dir_states = vec![(AGENT_TMP_DIR.into(), DirState::NotDir)];
        let err = plan_launch(&m, &req("claude")).unwrap_err();
        assert!(err.contains("agent-tmp") && err.contains("not a directory"), "{err}");
        assert!(m.runs.borrow().is_empty(), "wxc-exec was probed on a policy whose TEMP is not a directory");
        let on = parse_settings(Some(r#"{"enabled":true}"#));
        assert!(matches!(decide_launch(&on, plan_launch(&m, &req("claude"))), LaunchDecision::Refuse(_)));
    }

    #[test]
    fn an_ensured_dir_that_is_a_link_or_reparse_point_refuses_the_launch() {
        // create_dir_all succeeds on a junction to a directory, so only the reparse check catches it
        for (path, state) in [
            (AGENT_TMP_DIR, DirState::Reparse),
            ("C:\\Users\\dev\\.moorai", DirState::Reparse),
            ("C:\\Users\\dev\\.claude", DirState::Reparse),
            (AGENT_TMP_DIR, DirState::Unreadable),
        ] {
            let mut m = Mock::ok();
            m.dir_states = vec![(path.into(), state)];
            let err = plan_launch(&m, &req("claude")).expect_err(&format!("{path} as {state:?} was accepted"));
            let why = if state == DirState::Reparse { "reparse point" } else { "could not be inspected" };
            assert!(err.contains(path) && err.contains(why), "{err}");
            assert!(m.runs.borrow().is_empty() && m.writes.borrow().is_empty(), "{path} as {state:?}: a policy was written or probed");
        }
        // plain directories, or missing ones the host creates, still plan
        let mut m = Mock::ok();
        m.dir_states = vec![(AGENT_TMP_DIR.into(), DirState::Dir)];
        plan_launch(&m, &req("claude")).expect("plan");
    }

    #[test]
    fn an_ensured_dir_swapped_between_plan_and_spawn_refuses_the_spawn() {
        let mut m = Mock::ok();
        let plan = plan_launch(&m, &req("claude")).expect("plan");
        assert!(plan.ensure_dirs.iter().any(|d| d == AGENT_TMP_DIR), "{:?}", plan.ensure_dirs);
        recheck_dirs(&m, &plan).expect("nothing changed since the plan");
        // a contained agent still running from the last session turns a checked dir into a junction,
        // removes it, or puts a file there after plan_launch looked
        for state in [DirState::Reparse, DirState::NotDir, DirState::Missing, DirState::Unreadable] {
            for path in [AGENT_TMP_DIR, "C:\\Users\\dev\\.moorai", "C:\\Users\\dev\\.claude"] {
                m.dir_states = vec![(path.into(), state)];
                let err = recheck_dirs(&m, &plan).expect_err(&format!("{path} became {state:?} after the plan and wxc-exec would still be spawned"));
                assert!(err.contains(path), "{err}");
            }
        }
    }

    struct Prior {
        alive: std::cell::Cell<u32>,
        stops: u32,
        // running() reports true this many more times after stop()
        dies_after: Option<u32>,
    }

    impl PriorSession for Prior {
        fn running(&self) -> bool {
            self.alive.get() > 0
        }
        fn stop(&mut self) {
            self.stops += 1;
            if let Some(n) = self.dies_after {
                self.alive.set(n);
            }
        }
    }

    #[test]
    fn a_new_mxc_launch_stops_the_previous_session_first_and_refuses_if_it_will_not_stop() {
        let pauses = std::cell::Cell::new(0u32);
        let pause = || pauses.set(pauses.get() + 1);
        // nothing running: no stop, no wait
        let mut p = Prior { alive: 0.into(), stops: 0, dies_after: None };
        stop_prior_session(&mut p, 5, &pause).expect("nothing to stop");
        assert_eq!((p.stops, pauses.get()), (0, 0));
        // running, then gone after the stop: the launch goes ahead only once it has exited
        let mut p = Prior { alive: 1.into(), stops: 0, dies_after: Some(0) };
        stop_prior_session(&mut p, 5, &pause).expect("stopped");
        assert_eq!(p.stops, 1);
        // still running a few polls after the stop: waited for, then fine
        struct Slow(std::cell::Cell<u32>);
        impl PriorSession for Slow {
            fn running(&self) -> bool {
                let n = self.0.get();
                self.0.set(n.saturating_sub(1));
                n > 0
            }
            fn stop(&mut self) {}
        }
        pauses.set(0);
        stop_prior_session(&mut Slow(3.into()), 5, &pause).expect("exited within the wait");
        assert!(pauses.get() >= 2, "did not wait for the previous session to exit");
        // never stops: the launch is refused rather than planned next to a live contained agent
        pauses.set(0);
        let mut p = Prior { alive: 1.into(), stops: 0, dies_after: None };
        let err = stop_prior_session(&mut p, 5, &pause).expect_err("planned while the previous session was still running");
        assert!(err.contains("still running"), "{err}");
        assert_eq!((p.stops, pauses.get()), (1, 5));
    }

    #[test]
    fn a_contained_prior_session_that_cannot_be_checked_counts_as_running() {
        let st = |was_contained, job, child_live| PriorState { was_contained, job, child_live };
        // a contained session with no Job Object to ask, its PTY child gone: wxc-exec exited, the
        // contained agent may not have; nothing proves it gone
        assert!(prior_running(st(true, None, false)), "a contained session with no job handle was taken as stopped");
        // its job's process count could not be read
        assert!(prior_running(st(true, Some(None), false)));
        // proven gone: the job reports no process and the child exited
        assert!(!prior_running(st(true, Some(Some(0)), false)));
        assert!(prior_running(st(true, Some(Some(2)), false)));
        assert!(prior_running(st(true, Some(Some(0)), true)), "the PTY child is still live");
        // an uncontained session (or none at all) has no job to prove anything with: its child decides
        assert!(!prior_running(st(false, None, false)));
        assert!(prior_running(st(false, None, true)));
        assert!(prior_running(st(false, Some(None), false)));
        // said why only when nothing could be checked
        assert!(prior_unproven(st(true, None, false)).is_some());
        assert!(prior_unproven(st(true, Some(None), false)).is_some());
        assert!(prior_unproven(st(true, Some(Some(2)), false)).is_none());
        assert!(prior_unproven(st(true, None, true)).is_none());

        // through stop_prior_session: stopped, waited for, then refused with the reason
        struct Unchecked(u32);
        impl PriorSession for Unchecked {
            fn running(&self) -> bool {
                prior_running(PriorState { was_contained: true, job: None, child_live: false })
            }
            fn stop(&mut self) {
                self.0 += 1;
            }
            fn unproven(&self) -> Option<String> {
                prior_unproven(PriorState { was_contained: true, job: None, child_live: false }).map(String::from)
            }
        }
        let pauses = std::cell::Cell::new(0u32);
        let mut p = Unchecked(0);
        let err = stop_prior_session(&mut p, 5, &|| pauses.set(pauses.get() + 1)).expect_err("launched next to a contained session nothing proved gone");
        assert!(err.contains("cannot be confirmed stopped") && err.contains("no Job Object"), "{err}");
        assert_eq!((p.0, pauses.get()), (1, 5), "refused only after the stop and the wait");
    }

    #[test]
    fn iso_timestamps() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(1_791_400_000), "2026-10-07T19:06:40Z");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn only_denials_json_files_are_read() {
        assert!(is_denials_file("denials.4321_0123456789abcdef.json"));
        assert!(!is_denials_file("denials.4321_0123456789abcdef.verbose.json"));
        assert!(!is_denials_file("policy.json") && !is_denials_file("denials..json"));
    }
}
