mod ai_keys;
mod ai_runtime;
mod console_binding;
mod content_hash;
mod listen_sockets;
mod local_ai;
mod local_ai_windows;
mod local_model_names;
mod mxc;
mod mxc_denials;
mod mxc_launch;
mod ocr;
mod ocr_provider;
#[cfg(target_os = "macos")]
mod ocr_vision;
#[cfg(windows)]
mod ocr_winocr;
#[cfg(target_os = "linux")]
mod ocr_tesseract;
mod platform;
mod private_file;
#[cfg(windows)]
mod winsec;

use std::fs::{create_dir_all, OpenOptions};
use std::io::{Read, Write};
use std::sync::Mutex;
use portable_pty::{native_pty_system, ChildKiller, MasterPty, PtySize};
use tauri::{Emitter, Manager};
use tauri_plugin_updater::UpdaterExt;

// Holds the live claude PTY so input/resize can reach it. claude runs directly on this device —
// no server, no streaming.
#[derive(Default)]
struct Term {
    writer: Mutex<Option<Box<dyn Write + Send>>>,
    master: Mutex<Option<Box<dyn MasterPty + Send>>>,
    // Windows opt-in isolation: raw Job Object handle for the live agent process. Held so its
    // kill-on-close limit stays active for the session's lifetime; replaced/closed on next launch.
    // Unused on non-Windows targets, where isolation goes through the Seatbelt profile instead.
    #[allow(dead_code)]
    job: Mutex<Option<isize>>,
    // Windows: whether the live (or last) session was launched through wxc-exec (MXC-contained). Such a
    // session with no job to check is never taken as stopped (mxc_launch::prior_running).
    #[allow(dead_code)]
    contained: Mutex<bool>,
    // #3 — a killer for the live agent process so a "kill" verdict (from the guard's PreToolUse hook,
    // delivered out-of-band via the kill-session sentinel) can terminate the whole session, not just
    // deny one call. Replaced on each launch; taken when a kill fires so it can't double-kill.
    killer: Mutex<Option<Box<dyn ChildKiller + Send + Sync>>>,
    // true while the live session's PTY child has not exited (its wait thread clears it). Read before an
    // MXC launch, which must not be planned while the previous session is still running.
    live: Mutex<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>>,
}

// The previous session, as an MXC launch sees it (mxc_launch::stop_prior_session).
#[cfg(windows)]
struct TermPrior<'a>(&'a Term);

#[cfg(windows)]
impl TermPrior<'_> {
    fn state(&self) -> mxc_launch::PriorState {
        mxc_launch::PriorState {
            was_contained: *self.0.contained.lock().unwrap(),
            job: self.0.job.lock().unwrap().map(winsec::job_active_processes),
            child_live: self.0.live.lock().unwrap().as_ref().map(|l| l.load(std::sync::atomic::Ordering::SeqCst)).unwrap_or(false),
        }
    }
}

#[cfg(windows)]
impl mxc_launch::PriorSession for TermPrior<'_> {
    fn running(&self) -> bool {
        mxc_launch::prior_running(self.state())
    }
    fn unproven(&self) -> Option<String> {
        mxc_launch::prior_unproven(self.state()).map(String::from)
    }
    fn stop(&mut self) {
        if let Some(mut k) = self.0.killer.lock().unwrap().take() { let _ = k.kill(); }
        if let Some(j) = *self.0.job.lock().unwrap() { winsec::terminate_job(j); }
    }
}

#[tauri::command]
fn term_open(app: tauri::AppHandle, state: tauri::State<Term>, cols: u16, rows: u16, tool: Option<String>) -> Result<(), String> {
    // Which agent CLI to launch — constrained to the ones MoorAI supports.
    let tool = match tool.as_deref() {
        Some("codex") => "codex",
        Some("copilot") => "copilot",
        _ => "claude",
    };
    // #3 — host-side policy enforcement. The MoorAI app itself refuses to launch an agent the
    // admin hasn't allowed, so the picker's restriction is real at the launch boundary (not just
    // UI a devtools user could invoke around). Claude is the always-available baseline; codex/
    // copilot require an allow confirmed with the server. This can't stop a user running the CLI
    // entirely outside MoorAI — that's inherent to their own machine — it's governance, not a sandbox.
    if tool != "claude" {
        let decision = tool_allowed(tool);
        // A refused or ignored console binding is shown, not swallowed (console_binding.rs).
        if let Some(w) = &decision.warning { let _ = app.emit("term-data", format!("\x1b[33m[MoorAI] {w}\x1b[0m\r\n")); }
        if !decision.allowed {
            let _ = app.emit("term-data", format!("\x1b[31m[MoorAI] {tool} is not permitted by your organization's policy.\x1b[0m\r\n"));
            return Err(format!("{tool} not permitted by policy"));
        }
    }
    let pair = native_pty_system()
        .openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
        .map_err(|e| e.to_string())?;

    let _ = app.emit("term-data", format!("\x1b[2m[MoorAI] launching {tool}…\x1b[0m\r\n"));

    let bin = find_tool(tool).ok_or(format!("{tool} CLI not found"))?;
    let cfg = read_config();
    // Opt-in Windows containment through Microsoft Execution Containers (mxc_launch.rs). Default off;
    // turning it on also turns on the Job Object launch, which is what runs when MXC is unavailable.
    // Its settings are read from the host-only %LOCALAPPDATA%\MoorAI Host\mxc.json, NOT config.json:
    // ~/.moorai is writable from inside the container, and the agent must not choose its next launch.
    #[cfg(windows)]
    let mxc_settings = mxc_host_settings();
    #[cfg(windows)]
    let want_mxc = mxc_settings.enabled;
    #[cfg(not(windows))]
    let want_mxc = false;
    // Experimental opt-in host isolation: launch the agent inside a sandbox when enabled in config.
    let isolate = want_mxc || cfg.get("isolateAgent").and_then(|v| v.as_bool()).unwrap_or(false);
    // Claude resumes the previous conversation across app restarts (only once a first session exists,
    // so a fresh install doesn't `--continue` into nothing). Codex/Copilot start a fresh session.
    let mut agent_args: Vec<String> = vec![];
    if tool == "claude" && cfg.get("hadSession").and_then(|v| v.as_bool()).unwrap_or(false) { agent_args.push("--continue".into()); }
    // The ensureDirs are checked in mxc_prepare and the agent can write to them, so the previous session
    // (possibly a contained agent) is stopped, and seen to be gone, before anything is planned.
    #[cfg(windows)]
    if want_mxc {
        if let Err(reason) = mxc_launch::stop_prior_session(&mut TermPrior(&state), 50, &|| std::thread::sleep(std::time::Duration::from_millis(100))) {
            let _ = app.emit("term-data", format!("\x1b[31m[MoorAI] {tool} was not launched: {reason}.\x1b[0m\r\n"));
            return Err(reason);
        }
    }
    #[cfg(windows)]
    let mxc_session = if want_mxc { mxc_prepare(&app, &mxc_settings, tool, &bin, &agent_args)? } else { None };
    #[cfg(not(windows))]
    let mxc_session: Option<mxc_launch::MxcSession> = { let _ = want_mxc; None };
    let mut cmd = match &mxc_session {
        Some(s) => {
            // The PTY runs wxc-exec; wxc-exec creates the contained agent (command line is in the policy).
            let mut c = portable_pty::CommandBuilder::new(&s.plan.wxc_exec);
            for a in &s.plan.args { c.arg(a); }
            c
        }
        None => {
            let mut c = platform::agent_command(&bin, isolate);
            for a in &agent_args { c.arg(a); }
            c
        }
    };
    // Inherit the full environment (HOME, etc.) so the agent finds its config; augment PATH.
    for (k, v) in std::env::vars() { cmd.env(k, v); }
    let home = platform::home_dir();
    match &mxc_session {
        Some(s) => cmd.cwd(&s.plan.cwd),
        None => cmd.cwd(if home.is_empty() { ".".into() } else { home }),
    }
    cmd.env("TERM", "xterm-256color");
    cmd.env("PATH", platform::augmented_path());
    // The policy's own env block (TEMP, model-proxy base URL, git safe.directory) is also set on
    // wxc-exec, so the container gets it whether MXC layers it or inherits the launcher's environment.
    if let Some(s) = &mxc_session { for (k, v) in &s.plan.env { cmd.env(k, v); } }
    // Per-agent auth: each CLI uses its own login; we only inject a token the user explicitly saved.
    match tool {
        "claude" => {
            if let Some(tok) = cfg.get("agentToken").and_then(|v| v.as_str()) {
                if tok.starts_with("sk-ant-oat") { cmd.env("CLAUDE_CODE_OAUTH_TOKEN", tok); }
                else if !tok.is_empty() { cmd.env("ANTHROPIC_API_KEY", tok); }
            }
        }
        "codex" => {
            if let Some(tok) = cfg.get("openaiToken").and_then(|v| v.as_str()) {
                if !tok.is_empty() { cmd.env("OPENAI_API_KEY", tok); }
            }
        }
        "copilot" => {
            if let Some(tok) = cfg.get("githubToken").and_then(|v| v.as_str()) {
                if !tok.is_empty() { cmd.env("GH_TOKEN", tok); cmd.env("GITHUB_TOKEN", tok); }
            }
        }
        _ => {}
    }

    // Re-check the ensureDirs immediately before wxc-exec starts (mxc_launch::recheck_dirs). A change
    // since the plan refuses the launch; it is never downgraded to the Job Object.
    #[cfg(windows)]
    if let Some(s) = &mxc_session {
        if let Err(reason) = mxc_launch::recheck_dirs(&mxc_launch::WinHost { wxc_override: None }, &s.plan) {
            let _ = app.emit("term-data", format!("\x1b[31m[MoorAI] {tool} was not launched: {reason}.\x1b[0m\r\n"));
            if !s.keep_run { let _ = std::fs::remove_dir_all(&s.run_dir); }
            return Err(reason);
        }
    }
    let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    set_config_bool("hadSession", true);
    drop(pair.slave);
    // Windows opt-in host isolation: place the agent in a kill-on-close Job Object so a closed or
    // killed session leaves no orphaned agent processes. Close any prior session's job first. macOS
    // isolation is handled up front by wrapping the command in a Seatbelt sandbox (see platform.rs).
    #[cfg(windows)]
    {
        if let Some(old) = state.job.lock().unwrap().take() { winsec::close_job(old); }
        *state.contained.lock().unwrap() = mxc_session.is_some();
        if isolate {
            let job = if mxc_session.is_some() { winsec::create_mxc_job() } else { winsec::create_agent_job() };
            if let (Some(pid), Some(job)) = (child.process_id(), job) {
                // Kept only when the process is in it: an empty job would report a contained session gone.
                if winsec::assign_process(job, pid) { *state.job.lock().unwrap() = Some(job); } else { winsec::close_job(job); }
            } else if let Some(job) = job {
                winsec::close_job(job);
            }
        }
    }
    let mut child = child;
    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    *state.writer.lock().unwrap() = Some(pair.master.take_writer().map_err(|e| e.to_string())?);
    *state.master.lock().unwrap() = Some(pair.master);

    let app2 = app.clone();
    #[cfg(windows)]
    let app3 = app.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => { let _ = app2.emit("term-data", String::from_utf8_lossy(&buf[..n]).to_string()); }
            }
        }
        let _ = app.emit("term-exit", ());
    });
    // #3 — hold a killer for the new session so a "kill" verdict can terminate it out-of-band.
    *state.killer.lock().unwrap() = Some(child.clone_killer());
    let live = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    *state.live.lock().unwrap() = Some(live.clone());
    std::thread::spawn(move || {
        let _ = child.wait();
        live.store(false, std::sync::atomic::Ordering::SeqCst);
        // MXC writes its denial report only after the contained process exits (logging-access-denied.md).
        #[cfg(windows)]
        if let Some(s) = mxc_session {
            if s.plan.capture_denials {
                if let Some(line) = mxc_launch::after_exit(&s) {
                    let _ = app3.emit("term-data", format!("\x1b[33m[MoorAI] {line}\x1b[0m\r\n"));
                }
            } else if !s.keep_run {
                let _ = std::fs::remove_dir_all(&s.run_dir);
            }
        }
        #[cfg(not(windows))]
        let _ = mxc_session;
    });
    Ok(())
}

// Build and probe the MXC launch for this session (Windows only). Ok(None) = launch the usual way, only
// when mxc.json sets "fallback": "job-object"; otherwise a failed plan is Err and the agent is not
// launched. Either way the reason is printed in the terminal.
#[cfg(windows)]
fn mxc_host_settings() -> mxc_launch::MxcSettings {
    let env: std::collections::BTreeMap<String, String> = std::env::vars().collect();
    let path = mxc::expand(mxc_launch::HOST_SETTINGS_FILE, &mxc::tokens(&env, ""));
    mxc_launch::parse_settings(std::fs::read_to_string(path).ok().as_deref())
}

#[cfg(windows)]
fn mxc_prepare(app: &tauri::AppHandle, settings: &mxc_launch::MxcSettings, tool: &str, bin: &str, agent_args: &[String]) -> Result<Option<mxc_launch::MxcSession>, String> {
    use std::collections::BTreeMap;
    let env: BTreeMap<String, String> = std::env::vars().collect();
    let home = platform::home_dir();
    let local = std::env::var("LOCALAPPDATA").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| format!("{home}\\AppData\\Local"));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    // Host-only: outside every grant in the policy, so the contained agent cannot plant a denials file.
    let run_dir = format!("{local}\\MoorAI Host\\mxc-runs\\{now}-{}", std::process::id());
    let mut hook_texts: Vec<String> = vec![];
    let codex_home = std::env::var("CODEX_HOME").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| format!("{home}\\.codex"));
    let copilot_home = std::env::var("COPILOT_HOME").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| format!("{home}\\.copilot"));
    for f in [format!("{home}\\.claude\\settings.json"), format!("{codex_home}\\hooks.json"), format!("{codex_home}\\config.toml")] {
        if let Ok(t) = std::fs::read_to_string(&f) { hook_texts.push(t); }
    }
    if let Ok(rd) = std::fs::read_dir(format!("{copilot_home}\\hooks")) {
        for e in rd.flatten() { if let Ok(t) = std::fs::read_to_string(e.path()) { hook_texts.push(t); } }
    }
    // Discovered from agent-writable hook configs, so plan_launch only grants a root that passes
    // valid_hook_root (a real moorai package, not a profile root). Host-only roots come first.
    let mut hook_roots: Vec<String> = settings.hook_roots.clone();
    for t in &hook_texts { for r in mxc_launch::hook_roots_from_text(t) { if !hook_roots.iter().any(|x: &String| x.eq_ignore_ascii_case(&r)) { hook_roots.push(r); } } }
    let req = mxc_launch::LaunchRequest {
        agent: tool.to_string(),
        agent_bin: bin.to_string(),
        agent_args: agent_args.to_vec(),
        workspace: settings.workspace.clone(),
        env: env.clone(),
        node_dir: platform::which("node").map(|p| mxc::win_dirname(&p)).unwrap_or_default(),
        hook_roots,
        model_proxy_port: settings.model_proxy_port.filter(|p| *p > 0).unwrap_or(mxc::DEFAULT_MODEL_PROXY_PORT),
        egress_allow: settings.egress_allow.clone(),
        extra_ca_certs: settings.extra_ca_certs.clone(),
        run_dir: run_dir.clone(),
    };
    let host = mxc_launch::WinHost { wxc_override: Some(settings.wxc_exec.clone()).filter(|p| !p.is_empty()) };
    match mxc_launch::decide_launch(settings, mxc_launch::plan_launch(&host, &req)) {
        mxc_launch::LaunchDecision::Contained(plan) => {
            let _ = app.emit("term-data", format!("\x1b[2m[MoorAI] {tool} runs inside Microsoft Execution Containers (BaseContainer).\x1b[0m\r\n"));
            for n in &plan.notes { let _ = app.emit("term-data", format!("\x1b[2m[MoorAI] MXC: {n}\x1b[0m\r\n")); }
            // Console binding for the host's denial alerts: host-only settings or none. config.json is
            // agent-writable, so its serverUrl/installToken are never used for this post.
            let (alert_endpoint, install_token, tenant) = match mxc_launch::session_console(settings) {
                Some((e, t, n)) => (Some(e), t, n),
                None => (None, String::new(), String::new()),
            };
            Ok(Some(mxc_launch::MxcSession { plan, run_dir, alert_endpoint, install_token, tenant, agent: tool.to_string(), workspace: req.workspace, env, keep_run: settings.keep_runs }))
        }
        mxc_launch::LaunchDecision::Fallback(reason) => {
            let _ = app.emit("term-data", format!("\x1b[33m[MoorAI] MXC isolation not used: {reason}. Launching with the Job Object instead (\"fallback\": \"job-object\" in %LOCALAPPDATA%\\MoorAI Host\\mxc.json).\x1b[0m\r\n"));
            if !settings.keep_runs { let _ = std::fs::remove_dir_all(&run_dir); }
            Ok(None)
        }
        mxc_launch::LaunchDecision::Refuse(reason) => {
            let _ = app.emit("term-data", format!("\x1b[31m[MoorAI] {tool} was not launched: MXC isolation is on in %LOCALAPPDATA%\\MoorAI Host\\mxc.json but could not be set up: {reason}. Fix the cause, or set \"fallback\": \"job-object\" in that file to launch without MXC.\x1b[0m\r\n"));
            if !settings.keep_runs { let _ = std::fs::remove_dir_all(&run_dir); }
            Err(format!("MXC isolation could not be set up: {reason}"))
        }
    }
}

// #3 — terminate the live agent PTY on a policy "kill" verdict. Callable directly by the frontend, and
// invoked by the kill-session watcher (see run()). Governance: it only kills MoorAI's own child.
#[tauri::command]
fn term_kill(app: tauri::AppHandle, state: tauri::State<Term>) -> bool {
    let killed = { let mut k = state.killer.lock().unwrap(); if let Some(mut kill) = k.take() { let _ = kill.kill(); true } else { false } };
    if killed {
        let _ = app.emit("term-data", "\r\n\x1b[31m[MoorAI] session terminated by policy (kill verdict) — nothing further was run.\x1b[0m\r\n");
        let _ = app.emit("term-exit", ());
    }
    killed
}

#[tauri::command]
fn term_input(state: tauri::State<Term>, data: String) -> Result<(), String> {
    if let Some(w) = state.writer.lock().unwrap().as_mut() {
        w.write_all(data.as_bytes()).map_err(|e| e.to_string())?;
        let _ = w.flush();
    }
    Ok(())
}

#[tauri::command]
fn term_resize(state: tauri::State<Term>, cols: u16, rows: u16) -> Result<(), String> {
    if let Some(m) = state.master.lock().unwrap().as_ref() {
        m.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 }).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// Native, on-device audit sink — appends a redacted entry to a JSONL file in the app
// data dir. The host owns this file; it persists beyond the webview's localStorage.
#[tauri::command]
fn native_log(app: tauri::AppHandle, entry: serde_json::Value) -> Result<(), String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("audit.jsonl"))
        .map_err(|e| e.to_string())?;
    writeln!(f, "{}", entry).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// Resolve an agent CLI binary (GUI/minimal-PATH safe). Each tool has an env override
// (MoorAI_CLAUDE / MoorAI_CODEX / MoorAI_COPILOT) plus the usual per-platform install locations.
fn find_tool(tool: &str) -> Option<String> { platform::find_tool(tool) }

fn find_claude() -> Option<String> { find_tool("claude") }

// #3 — is this agent permitted for our tenant/device? Asks the console recorded host-side at
// enrolment (console_binding.rs — never config.json's serverUrl, which the agent can rewrite), falling
// back to the frontend-cached allow-list on a network error, else deny. Unprovisioned installs are
// not restricted.
fn tool_allowed(tool: &str) -> console_binding::Decision {
    console_binding::policy_allows(&read_config(), &console_binding::host_dir(), tool, &platform::username(), &platform::hostname(), &console_binding::real_fetch)
}

// Writes the provision config (serverUrl + tenant) to ~/.moorai/config.json — used when the
// user enrolls by pasting an installation token in the app.
#[tauri::command]
fn save_provision(config: serde_json::Value) -> Result<(), String> {
    // An enrolment (the provision carries an install token) records its console host-side first; an
    // unsafe serverUrl refuses the enrolment before anything is written.
    console_binding::record_enrolment(&console_binding::host_dir(), &config)?;
    let dir = platform::config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // Merge into the existing config so enrolling doesn't clobber agent auth / other keys.
    let mut cfg = read_config();
    if !cfg.is_object() { cfg = serde_json::json!({}); }
    if let (Some(o), Some(n)) = (cfg.as_object_mut(), config.as_object()) {
        for (k, v) in n { o.insert(k.clone(), v.clone()); }
    }
    private_file::write_private(platform::config_path(), &serde_json::to_string_pretty(&cfg).unwrap())
        .map_err(|e| e.to_string())?;
    Ok(())
}

// Opens a system terminal running the claude CLI so the user can complete the OAuth login.
#[tauri::command]
fn open_login_terminal() -> Result<(), String> {
    let bin = find_claude().unwrap_or_else(|| "claude".into());
    platform::launch_login_terminal(&bin)
}

// Relaunch the app — used by idle-restart to pick up the latest installed build and resume the
// session. Re-running boot also re-checks for updates.
#[tauri::command]
fn restart_app(app: tauri::AppHandle) { app.restart(); }

// About-dialog metadata, including the live code signature read from the running bundle.
#[tauri::command]
fn about_info() -> serde_json::Value {
    // Whether the running binary carries a valid vendor signature (Developer ID on macOS,
    // Authenticode on Windows). We surface only a boolean, never the identity / Team ID.
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        // Bundle identifier. Kept in lockstep with tauri.conf.json's `identifier`. The CuraIQ→MoorAI
        // flip (run.glick.curaiq → run.glick.moorai) makes the OS treat this as a NEW app, so it ships
        // only with a validated transitional bridge release (see packaging/mdm/README.md "Identifier
        // migration"). Per-user config is home-based (~/.moorai, cli/state-dirs.mjs), NOT bundle-scoped,
        // so it survives the flip untouched.
        "identifier": "run.glick.moorai",
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "signed": platform::is_signed()
    })
}

// Silent auto-update: ask the update server if a newer build exists; if so, download it,
// verify its signature, and install it in place. Returns true when an update was installed
// (the caller then relaunches via restart_app). The replaced bundle is not quarantined, so the
// next launch skips Gatekeeper even while we're adhoc-signed.
#[tauri::command]
async fn check_and_install_update(app: tauri::AppHandle) -> Result<bool, String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    match updater.check().await.map_err(|e| e.to_string())? {
        Some(update) => {
            update.download_and_install(|_chunk, _total| {}, || {}).await.map_err(|e| e.to_string())?;
            Ok(true)
        }
        None => Ok(false),
    }
}

// Merge a boolean flag into ~/.moorai/config.json without clobbering other keys.
fn set_config_bool(key: &str, val: bool) {
    let mut cfg = read_config();
    if !cfg.is_object() { cfg = serde_json::json!({}); }
    if let Some(o) = cfg.as_object_mut() { o.insert(key.to_string(), serde_json::Value::Bool(val)); }
    let _ = std::fs::create_dir_all(platform::config_dir());
    let _ = private_file::write_private(platform::config_path(), &serde_json::to_string_pretty(&cfg).unwrap_or_default());
}

// Opens a URL in the system browser (keeps it out of the app's webview).
#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    // Only http(s) — never hand `open` a file:// path, app bundle, or custom scheme.
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("blocked non-http URL".into());
    }
    let opener = if cfg!(target_os = "macos") { "open" } else if cfg!(target_os = "windows") { "explorer" } else { "xdg-open" };
    std::process::Command::new(opener).arg(url).spawn().map_err(|e| e.to_string())?;
    Ok(())
}

// Inventories other AI tools installed on the device + the OS, to report to the MoorAI server.
#[tauri::command]
fn device_ai_tools() -> serde_json::Value { platform::ai_tools() }

// Minimal `key = "value"` (TOML) / `key: value` (YAML) scan — tolerant, no crate. `sep` is '=' or ':'.
fn cfg_val(txt: &str, key: &str, sep: char) -> Option<String> {
    for line in txt.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix(key) {
            if let Some(v) = rest.trim_start().strip_prefix(sep) {
                let v = v.trim().trim_matches('"').trim_matches('\'').trim().to_string();
                if !v.is_empty() { return Some(v); }
            }
        }
    }
    None
}

// #7 — AI asset inventory: which models/providers each agent is configured for, plus local models on
// disk. Config metadata only (default-model strings; local-model directory NAMES) — never token/auth
// files. Feeds the console's per-device + fleet AI-asset catalog. Also AI-provider keys AT REST
// (provider + location class + keyed hash only), RUNNING local model / localhost MCP servers (process
// names + ports + loopback-vs-network only), INSTALLED local runtimes (class + version only) and, on
// Windows, the Windows AI platform and the ODR agent connectors (names + booleans only) — the Rust
// mirrors of cli/aibom-keys.mjs, cli/aibom-runtime.mjs and cli/local-ai-*.mjs. `async` so the OS
// probes (5 s each, PowerShell 10 s, run in parallel) stay off the main thread.
#[tauri::command(async)]
fn device_ai_assets() -> serde_json::Value {
    let home = platform::home_dir();
    let mut providers: Vec<serde_json::Value> = vec![];
    // Claude Code — ~/.claude/settings.json { model }
    if let Ok(txt) = std::fs::read_to_string(format!("{home}/.claude/settings.json")) {
        if let Ok(j) = serde_json::from_str::<serde_json::Value>(&txt) {
            let model = j.get("model").and_then(|v| v.as_str()).map(|s| s.to_string());
            providers.push(serde_json::json!({ "provider": "Anthropic", "agent": "claude", "model": model, "source": "settings.json" }));
        }
    }
    // Codex — ~/.codex/config.toml (model, model_provider)
    if let Ok(txt) = std::fs::read_to_string(format!("{home}/.codex/config.toml")) {
        let prov = cfg_val(&txt, "model_provider", '=').unwrap_or_else(|| "OpenAI".into());
        providers.push(serde_json::json!({ "provider": prov, "agent": "codex", "model": cfg_val(&txt, "model", '='), "source": "config.toml" }));
    }
    // Aider — ~/.aider.conf.yml (model:)
    if let Ok(txt) = std::fs::read_to_string(format!("{home}/.aider.conf.yml")) {
        providers.push(serde_json::json!({ "provider": "Aider", "agent": "aider", "model": cfg_val(&txt, "model", ':'), "source": "aider.conf.yml" }));
    }
    // Local models — Ollama + LM Studio directory names only (no file contents).
    let mut local: Vec<serde_json::Value> = vec![];
    if let Ok(rd) = std::fs::read_dir(format!("{home}/.ollama/models/manifests/registry.ollama.ai/library")) {
        for e in rd.flatten() { if let Some(n) = e.file_name().to_str() { local.push(serde_json::json!({ "runtime": "ollama", "name": n })); } }
    }
    for lmdir in [format!("{home}/.lmstudio/models"), format!("{home}/.cache/lm-studio/models")] {
        if let Ok(rd) = std::fs::read_dir(&lmdir) {
            for e in rd.flatten() { if e.path().is_dir() { if let Some(n) = e.file_name().to_str() { local.push(serde_json::json!({ "runtime": "lmstudio", "name": n })); } } }
        }
    }
    // Local models whose NAME says their safety training was removed (counts only; local_model_names.rs).
    // Its own 2 s deadline, on a thread beside the 5 s local-AI probes, so it adds no wait.
    let safety_home = home.clone();
    let model_safety = std::thread::spawn(move || local_model_names::collect(&safety_home));
    let key = content_hash::tenant_key();
    let keys = ai_keys::scan_keys_at_rest(&home, &|v| content_hash::hash_with_key(key.as_ref(), v));
    let ai = ai_runtime::collect(&home);
    let model_safety = model_safety.join().ok();
    let mut summary = serde_json::json!({
        "runningLocalRuntimes": ai.runtimes.len(),
        "networkLocalRuntimes": ai.runtimes.iter().filter(|r| r.listening.as_deref() == Some("network")).count(),
        "installedLocalRuntimes": ai.installed.len(),
        "localModelsSafetyRemovedByName": model_safety.as_ref().map_or(0, |m| m.count),
    });
    let mut out = serde_json::json!({ "providers": providers, "localModels": local, "apiKeysAtRest": keys, "localRuntimes": ai.runtimes, "localRuntimesInstalled": ai.installed, "localMcpListeners": ai.mcp, "runtimeProbe": ai.runtime_probe });
    // Windows only, and only when the probe produced something: an absent block means "not probed or
    // not available" (odr.exe ships from build 26220.7262), never "nothing there".
    if let Some(w) = ai.windows_ai { out["windowsAi"] = w; }
    if let Some(c) = ai.agent_connectors { summary["agentConnectors"] = c["count"].clone(); out["agentConnectors"] = c; }
    if let Some(m) = model_safety { out["localModelSafety"] = serde_json::json!(m); }
    out["summary"] = summary;
    out
}

// Inventories the MCP servers each coding agent has configured (the agent "posture/config" layer).
// Reads well-known config files and reports only server names + scope + transport — never contents.
// #16 — heuristic "tool-poisoning" risk for an MCP server's launch config. We can't read the
// server's tool descriptions without connecting, so we flag the highest-signal proxy: a launch
// command that fetches and executes remote code, or runs an inline shell. Never inspects contents.
fn mcp_risk(cfg: &serde_json::Value) -> Option<&'static str> {
    let mut parts = String::new();
    if let Some(c) = cfg.get("command").and_then(|v| v.as_str()) { parts.push_str(c); parts.push(' '); }
    if let Some(args) = cfg.get("args").and_then(|v| v.as_array()) {
        for a in args { if let Some(s) = a.as_str() { parts.push_str(s); parts.push(' '); } }
    }
    let p = parts.to_lowercase();
    let fetch = p.contains("curl") || p.contains("wget");
    let pipe_sh = p.contains("| sh") || p.contains("|sh") || p.contains("| bash") || p.contains("|bash");
    if fetch && pipe_sh { return Some("launch command fetches and pipes a remote script to a shell"); }
    if p.contains("bash -c") || p.contains("sh -c") || p.contains("eval ") { return Some("launch command runs an inline shell"); }
    None
}

// #8 — heuristic capability scope for an MCP server from its launch config: network, filesystem,
// credential access. Advisory (like mcp_risk). Reads command/args and env var KEYS only — never env
// values, honoring the no-credential-vault rule. The server scores level/reasons centrally.
fn mcp_caps(cfg: &serde_json::Value) -> serde_json::Value {
    let mut parts = String::new();
    if let Some(c) = cfg.get("command").and_then(|v| v.as_str()) { parts.push_str(c); parts.push(' '); }
    if let Some(args) = cfg.get("args").and_then(|v| v.as_array()) {
        for a in args { if let Some(s) = a.as_str() { parts.push_str(s); parts.push(' '); } }
    }
    let p = parts.to_lowercase();
    let remote = cfg.get("url").is_some()
        || cfg.get("type").and_then(|v| v.as_str()) == Some("sse")
        || cfg.get("transport").and_then(|v| v.as_str()) == Some("sse");
    let net = remote || ["fetch", "brave-search", "puppeteer", "playwright", "firecrawl", "http"].iter().any(|k| p.contains(k));
    let fs = p.contains("filesystem") || p.contains("server-files") || p.contains(" files ");
    let mut cred = ["github", "gitlab", "slack", "aws", "gdrive", "google-drive", "notion", "stripe", "jira"].iter().any(|k| p.contains(k));
    if let Some(env) = cfg.get("env").and_then(|v| v.as_object()) {
        for k in env.keys() {
            let ku = k.to_uppercase();
            if ["TOKEN", "KEY", "SECRET", "PASSWORD", "CREDENTIAL"].iter().any(|s| ku.contains(s)) { cred = true; break; }
        }
    }
    serde_json::json!({ "net": net, "fs": fs, "cred": cred })
}

fn mcp_collect(map: &serde_json::Map<String, serde_json::Value>, scope: &str, out: &mut Vec<serde_json::Value>, seen: &mut std::collections::HashSet<String>) {
    for (name, cfg) in map {
        if name.is_empty() || !seen.insert(format!("{scope}:{name}")) { continue; }
        let remote = cfg.get("url").is_some()
            || cfg.get("type").and_then(|v| v.as_str()) == Some("sse")
            || cfg.get("transport").and_then(|v| v.as_str()) == Some("sse");
        let mut entry = serde_json::json!({ "name": name, "scope": scope, "transport": if remote { "remote" } else { "stdio" }, "caps": mcp_caps(cfg) });
        if let Some(reason) = mcp_risk(cfg) { entry["risk"] = serde_json::Value::String(reason.into()); }
        out.push(entry);
    }
}

#[tauri::command]
fn device_mcp() -> serde_json::Value {
    let home = platform::home_dir();
    let mut servers: Vec<serde_json::Value> = vec![];
    let mut seen = std::collections::HashSet::new();
    // Claude Code — ~/.claude.json (global + per-project mcpServers)
    if let Ok(txt) = std::fs::read_to_string(format!("{home}/.claude.json")) {
        if let Ok(j) = serde_json::from_str::<serde_json::Value>(&txt) {
            if let Some(m) = j.get("mcpServers").and_then(|v| v.as_object()) { mcp_collect(m, "claude", &mut servers, &mut seen); }
            if let Some(projs) = j.get("projects").and_then(|v| v.as_object()) {
                for (_, pv) in projs {
                    if let Some(m) = pv.get("mcpServers").and_then(|v| v.as_object()) { mcp_collect(m, "claude", &mut servers, &mut seen); }
                }
            }
        }
    }
    // Cursor — ~/.cursor/mcp.json
    if let Ok(txt) = std::fs::read_to_string(format!("{home}/.cursor/mcp.json")) {
        if let Ok(j) = serde_json::from_str::<serde_json::Value>(&txt) {
            if let Some(m) = j.get("mcpServers").and_then(|v| v.as_object()) { mcp_collect(m, "cursor", &mut servers, &mut seen); }
        }
    }
    serde_json::json!({ "servers": servers })
}

// Which account each agent CLI is logged in as — the account NAME only (email / username), never
// the token. Lets the console report the list of accounts used with AI agents (e.g. to spot
// personal accounts). Reads only identity fields from well-known configs; tokens are never touched.
#[tauri::command]
fn device_accounts() -> serde_json::Value {
    let home = platform::home_dir();
    let mut accounts: Vec<serde_json::Value> = vec![];

    // Claude Code — ~/.claude.json → oauthAccount.emailAddress (+ organizationName). Not the token.
    if let Ok(txt) = std::fs::read_to_string(format!("{home}/.claude.json")) {
        if let Ok(j) = serde_json::from_str::<serde_json::Value>(&txt) {
            if let Some(acc) = j.get("oauthAccount") {
                if let Some(email) = acc.get("emailAddress").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                    let org = acc.get("organizationName").and_then(|v| v.as_str());
                    accounts.push(serde_json::json!({ "agent": "claude", "account": email, "org": org }));
                }
            }
        }
    }
    // GitHub Copilot — ~/.config/gh/hosts.yml → the authenticated `user:` (username, not a token).
    if let Ok(txt) = std::fs::read_to_string(format!("{home}/.config/gh/hosts.yml")) {
        for line in txt.lines() {
            if let Some(u) = line.trim().strip_prefix("user:") {
                let name = u.trim();
                if !name.is_empty() { accounts.push(serde_json::json!({ "agent": "copilot", "account": name })); break; }
            }
        }
    }
    // Codex (OpenAI) — presence only. The account lives inside a token we deliberately do not parse.
    if std::path::Path::new(&format!("{home}/.codex/auth.json")).exists() {
        accounts.push(serde_json::json!({ "agent": "codex", "account": serde_json::Value::Null }));
    }

    serde_json::json!({ "accounts": accounts })
}

// #5 — local sensitive-file awareness. Given a directory (e.g. the agent's working dir), lists
// sensitive FILE NAMES present — secrets, private keys, credential files — so the user can be
// warned before an agent reads or transmits them. Names only; file contents are never read. Shallow.
#[tauri::command]
fn dir_sensitive(path: String) -> serde_json::Value {
    let dir = if path.trim().is_empty() { platform::home_dir() } else { path };
    let sensitive = |name: &str| -> bool {
        let n = name.to_lowercase();
        n == ".env" || n.starts_with(".env.")
            || n.ends_with(".pem") || n.ends_with(".key") || n.ends_with(".pfx") || n.ends_with(".p12")
            || n == "id_rsa" || n == "id_ed25519" || n == "id_dsa" || n == "id_ecdsa"
            || n == "credentials" || n == "credentials.json" || n == ".netrc" || n == ".npmrc" || n == ".pypirc"
            || n == "service-account.json" || n.ends_with("-key.json")
            || n == ".git-credentials" || n == "secrets.yaml" || n == "secrets.yml"
    };
    let mut found: Vec<String> = vec![];
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            if found.len() >= 50 { break; }
            let name = e.file_name().to_string_lossy().to_string();
            if sensitive(&name) { found.push(name); }
        }
    }
    serde_json::json!({ "dir": dir, "sensitive": found })
}

// Inventories installed browsers and their extensions (name, id, broad-access flag).
#[tauri::command]
fn device_browsers() -> serde_json::Value { platform::browsers() }

// Shadow-AI signal (Feature 2) — catalog-matched AI desktop apps + AI browser/editor extensions.
// Content-free; rides the existing /api/device-report sink.
#[tauri::command]
fn device_ai_shadow() -> serde_json::Value { platform::ai_shadow() }

// Checks for pending OS software/security updates (posture signal). Can be slow — call async.
#[tauri::command]
fn os_patch_status() -> serde_json::Value { platform::patch_status() }

// Coverage integrity — when each agent host was last used, from that host's own session logs: the
// newest mtime, rounded down to the hour. The Rust mirror of cli/agent-posture.mjs lastActive(), same
// directories and the same bounded walk (only the 8 newest entries per level are opened). Timestamps
// only — never a path, a file name or a byte of a log. src/api.js posts it on its own to
// /api/agent-posture, so the console sees agent use even when every MoorAI hook is switched off.
fn newest_mtime(dir: &std::path::Path, depth: u32) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let mut ents: Vec<(std::path::PathBuf, bool, u64)> = rd
        .flatten()
        .take(2000)
        .filter_map(|e| {
            let md = e.metadata().ok()?;
            let m = md.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
            Some((e.path(), md.is_dir(), m))
        })
        .collect();
    ents.sort_by(|a, b| b.2.cmp(&a.2));
    let mut best = 0;
    for (p, is_dir, m) in ents.into_iter().take(8) {
        let v = if is_dir { if depth > 1 { newest_mtime(&p, depth - 1) } else { 0 } } else { m };
        if v > best { best = v; }
    }
    best
}
#[tauri::command(async)]
fn device_agent_activity() -> serde_json::Value {
    let home = platform::home_dir();
    let env_or = |k: &str, d: String| std::env::var(k).ok().filter(|s| !s.is_empty()).unwrap_or(d);
    let codex = env_or("CODEX_HOME", format!("{home}/.codex"));
    let copilot = env_or("COPILOT_HOME", format!("{home}/.copilot"));
    let hosts = [
        ("claude-code", format!("{home}/.claude/projects"), 2),
        ("codex", format!("{codex}/sessions"), 4),
        ("gemini", format!("{home}/.gemini/tmp"), 3),
        ("cursor", format!("{home}/.cursor/chats"), 3),
        ("copilot", format!("{copilot}/session-state"), 2),
    ];
    let mut out = vec![];
    for (host, dir, depth) in hosts {
        let m = newest_mtime(std::path::Path::new(&dir), depth);
        if m > 0 { out.push(serde_json::json!({ "host": host, "lastActiveEpoch": m - m % 3600 })); }
    }
    serde_json::json!({ "activity": out })
}

// Native security posture — AV health, firewall state, disk encryption (Windows-native).
#[tauri::command]
fn device_posture() -> serde_json::Value { platform::security_posture() }

pub(crate) fn read_config() -> serde_json::Value {
    std::fs::read_to_string(platform::config_read_path("config.json"))
        .ok()
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or_else(|| serde_json::json!({}))
}

// Persists the agent auth (method + token) to the local config.
#[tauri::command]
fn set_agent_auth(method: String, token: String) -> Result<(), String> {
    std::fs::create_dir_all(platform::config_dir()).map_err(|e| e.to_string())?;
    let mut cfg = read_config();
    if !cfg.is_object() { cfg = serde_json::json!({}); }
    cfg["authMethod"] = serde_json::Value::String(method);
    cfg["agentToken"] = serde_json::Value::String(token);
    private_file::write_private(platform::config_path(), &serde_json::to_string_pretty(&cfg).unwrap())
        .map_err(|e| e.to_string())?;
    Ok(())
}

// Native OS identity for the security dashboard — metadata only, no content.
#[tauri::command]
fn identity() -> serde_json::Value {
    let user = platform::username();
    let device = platform::hostname();
    let cfg = read_config();
    let tenant = cfg.get("tenant").and_then(|t| t.as_str()).unwrap_or("unprovisioned").to_string();
    let install_token = cfg.get("installToken").and_then(|t| t.as_str()).unwrap_or("").to_string();
    // The only origin the renderer may send the install token to (null = none), and why not, if so.
    let console = console_binding::resolve(&console_binding::host_dir(), &cfg);
    serde_json::json!({ "user": user, "device": device, "platform": std::env::consts::OS, "tenant": tenant, "installToken": install_token, "appVersion": env!("CARGO_PKG_VERSION"), "console": console.origin, "consoleWarning": console.warning })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(Term::default())
        // #3 — kill-session watcher. The guard's PreToolUse hook runs out-of-process, so a "kill"
        // verdict is delivered as a small content-free sentinel file (~/.moorai/kill-session). Poll for
        // it and terminate the live agent PTY when it appears — detect-and-prevent for the interactive
        // session. A stale sentinel (older than 60s, e.g. left by a prior run) is consumed but ignored.
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let sentinel = format!("{}/kill-session", platform::config_dir());
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(600));
                    let txt = match std::fs::read_to_string(&sentinel) { Ok(t) => t, Err(_) => continue };
                    let _ = std::fs::remove_file(&sentinel); // consume the sentinel either way
                    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i128).unwrap_or(0);
                    let fresh = serde_json::from_str::<serde_json::Value>(&txt).ok()
                        .and_then(|j| j.get("ts").and_then(|v| v.as_i64()))
                        .map(|ts| now_ms - ts as i128 <= 60_000).unwrap_or(false);
                    if !fresh { continue; }
                    if let Some(state) = handle.try_state::<Term>() {
                        let killed = { let mut k = state.killer.lock().unwrap(); if let Some(mut kill) = k.take() { let _ = kill.kill(); true } else { false } };
                        if killed {
                            let _ = handle.emit("term-data", "\r\n\x1b[31m[MoorAI] session terminated by policy (kill verdict) — nothing further was run.\x1b[0m\r\n");
                            let _ = handle.emit("term-exit", ());
                        }
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![native_log, app_version, identity, save_provision, set_agent_auth, open_url, open_login_terminal, restart_app, check_and_install_update, about_info, term_open, term_input, term_resize, term_kill, device_ai_tools, device_ai_assets, device_mcp, os_patch_status, device_browsers, device_ai_shadow, device_posture, device_accounts, device_agent_activity, dir_sensitive, ocr::ocr_capability, ocr::ocr_image])
        .run(tauri::generate_context!())
        .expect("error while running MoorAI");
}
