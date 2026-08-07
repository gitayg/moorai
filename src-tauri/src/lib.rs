mod platform;
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
    // #3 — a killer for the live agent process so a "kill" verdict (from the guard's PreToolUse hook,
    // delivered out-of-band via the kill-session sentinel) can terminate the whole session, not just
    // deny one call. Replaced on each launch; taken when a kill fires so it can't double-kill.
    killer: Mutex<Option<Box<dyn ChildKiller + Send + Sync>>>,
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
    if tool != "claude" && !tool_allowed(tool) {
        let _ = app.emit("term-data", format!("\x1b[31m[MoorAI] {tool} is not permitted by your organization's policy.\x1b[0m\r\n"));
        return Err(format!("{tool} not permitted by policy"));
    }
    let pair = native_pty_system()
        .openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
        .map_err(|e| e.to_string())?;

    let _ = app.emit("term-data", format!("\x1b[2m[MoorAI] launching {tool}…\x1b[0m\r\n"));

    let bin = find_tool(tool).ok_or(format!("{tool} CLI not found"))?;
    // Experimental opt-in host isolation: launch the agent inside a sandbox when enabled in config.
    let isolate = read_config().get("isolateAgent").and_then(|v| v.as_bool()).unwrap_or(false);
    let mut cmd = platform::agent_command(&bin, isolate);
    // Claude resumes the previous conversation across app restarts (only once a first session exists,
    // so a fresh install doesn't `--continue` into nothing). Codex/Copilot start a fresh session.
    if tool == "claude" && read_config().get("hadSession").and_then(|v| v.as_bool()).unwrap_or(false) { cmd.arg("--continue"); }
    // Inherit the full environment (HOME, etc.) so the agent finds its config; augment PATH.
    for (k, v) in std::env::vars() { cmd.env(k, v); }
    let home = platform::home_dir();
    cmd.cwd(if home.is_empty() { ".".into() } else { home });
    cmd.env("TERM", "xterm-256color");
    cmd.env("PATH", platform::augmented_path());
    // Per-agent auth: each CLI uses its own login; we only inject a token the user explicitly saved.
    let cfg = read_config();
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

    let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    set_config_bool("hadSession", true);
    drop(pair.slave);
    // Windows opt-in host isolation: place the agent in a kill-on-close Job Object so a closed or
    // killed session leaves no orphaned agent processes. Close any prior session's job first. macOS
    // isolation is handled up front by wrapping the command in a Seatbelt sandbox (see platform.rs).
    #[cfg(windows)]
    {
        if let Some(old) = state.job.lock().unwrap().take() { winsec::close_job(old); }
        if isolate {
            if let (Some(pid), Some(job)) = (child.process_id(), winsec::create_agent_job()) {
                winsec::assign_process(job, pid);
                *state.job.lock().unwrap() = Some(job);
            }
        }
    }
    let mut child = child;
    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    *state.writer.lock().unwrap() = Some(pair.master.take_writer().map_err(|e| e.to_string())?);
    *state.master.lock().unwrap() = Some(pair.master);

    let app2 = app.clone();
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
    std::thread::spawn(move || { let _ = child.wait(); });
    Ok(())
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

// #3 — is this agent permitted for our tenant/device? Asks the server (authoritative), falling
// back to the frontend-cached allow-list on a network error, else deny. Unprovisioned installs
// (no server binding) are not restricted.
fn tool_allowed(tool: &str) -> bool {
    let cfg = read_config();
    let server = cfg.get("serverUrl").and_then(|v| v.as_str()).unwrap_or("");
    let token = cfg.get("installToken").and_then(|v| v.as_str()).unwrap_or("");
    if server.is_empty() || token.is_empty() { return true; }
    // Offline fallback: the allow-list the frontend persists to config on each policy poll.
    let cached = cfg.get("allowedTools").and_then(|v| v.as_array())
        .map(|a| a.iter().any(|x| x.as_str() == Some(tool)));
    let user = platform::username();
    let device = platform::hostname();
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .build() { Ok(c) => c, Err(_) => return cached.unwrap_or(false) };
    let resp = client
        .get(format!("{server}/api/policy"))
        .query(&[("user", user.as_str()), ("device", device.as_str())])
        .header("X-Install-Token", token)
        .send()
        .and_then(|r| r.json::<serde_json::Value>());
    match resp {
        Ok(j) => j.get("allowedTools").and_then(|v| v.as_array())
            .map(|a| a.iter().any(|x| x.as_str() == Some(tool)))
            .unwrap_or(true), // policy without an allow-list → not restricted
        Err(_) => cached.unwrap_or(false), // network/parse failure → last-known, else deny
    }
}

// Writes the provision config (serverUrl + tenant) to ~/.curaiq/config.json — used when the
// user enrolls by pasting an installation token in the app.
#[tauri::command]
fn save_provision(config: serde_json::Value) -> Result<(), String> {
    let dir = platform::config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // Merge into the existing config so enrolling doesn't clobber agent auth / other keys.
    let mut cfg = read_config();
    if !cfg.is_object() { cfg = serde_json::json!({}); }
    if let (Some(o), Some(n)) = (cfg.as_object_mut(), config.as_object()) {
        for (k, v) in n { o.insert(k.clone(), v.clone()); }
    }
    std::fs::write(platform::config_path(), serde_json::to_string_pretty(&cfg).unwrap())
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
        "identifier": "run.glick.curaiq",
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

// Merge a boolean flag into ~/.curaiq/config.json without clobbering other keys.
fn set_config_bool(key: &str, val: bool) {
    let mut cfg = read_config();
    if !cfg.is_object() { cfg = serde_json::json!({}); }
    if let Some(o) = cfg.as_object_mut() { o.insert(key.to_string(), serde_json::Value::Bool(val)); }
    let _ = std::fs::create_dir_all(platform::config_dir());
    let _ = std::fs::write(platform::config_path(), serde_json::to_string_pretty(&cfg).unwrap_or_default());
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
// files. Feeds the console's per-device + fleet AI-asset catalog.
#[tauri::command]
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
    serde_json::json!({ "providers": providers, "localModels": local })
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

// Checks for pending OS software/security updates (posture signal). Can be slow — call async.
#[tauri::command]
fn os_patch_status() -> serde_json::Value { platform::patch_status() }

// Native security posture — AV health, firewall state, disk encryption (Windows-native).
#[tauri::command]
fn device_posture() -> serde_json::Value { platform::security_posture() }

fn read_config() -> serde_json::Value {
    std::fs::read_to_string(platform::config_path())
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
    std::fs::write(platform::config_path(), serde_json::to_string_pretty(&cfg).unwrap())
        .map_err(|e| e.to_string())?;
    Ok(())
}

// Fallback agent path: the local claude CLI (uses its own OAuth login). MoorAI has already
// pre-flight reviewed the prompt on the JS side.
#[tauri::command]
fn run_agent(prompt: String) -> Result<String, String> {
    let bin = find_claude().ok_or("claude CLI not found — paste an OAuth token or API key in setup")?;
    // On Windows the resolved binary may be a .cmd/.bat shim, which CreateProcess can't run directly.
    let out = {
        #[cfg(windows)]
        {
            let lower = bin.to_ascii_lowercase();
            if lower.ends_with(".cmd") || lower.ends_with(".bat") {
                std::process::Command::new("cmd.exe").args(["/c", &bin, "-p"]).arg(&prompt).output()
            } else {
                std::process::Command::new(&bin).arg("-p").arg(&prompt).output()
            }
        }
        #[cfg(not(windows))]
        {
            std::process::Command::new(&bin).arg("-p").arg(&prompt).output()
        }
    }
    .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!("{}{}", String::from_utf8_lossy(&out.stderr), String::from_utf8_lossy(&out.stdout)).trim().to_string())
    }
}

// Native OS identity for the security dashboard — metadata only, no content.
#[tauri::command]
fn identity() -> serde_json::Value {
    let user = platform::username();
    let device = platform::hostname();
    let cfg = read_config();
    let tenant = cfg.get("tenant").and_then(|t| t.as_str()).unwrap_or("unprovisioned").to_string();
    let install_token = cfg.get("installToken").and_then(|t| t.as_str()).unwrap_or("").to_string();
    serde_json::json!({ "user": user, "device": device, "platform": std::env::consts::OS, "tenant": tenant, "installToken": install_token, "appVersion": env!("CARGO_PKG_VERSION") })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(Term::default())
        // #3 — kill-session watcher. The guard's PreToolUse hook runs out-of-process, so a "kill"
        // verdict is delivered as a small content-free sentinel file (~/.curaiq/kill-session). Poll for
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
        .invoke_handler(tauri::generate_handler![native_log, app_version, identity, run_agent, save_provision, set_agent_auth, open_url, open_login_terminal, restart_app, check_and_install_update, about_info, term_open, term_input, term_resize, term_kill, device_ai_tools, device_ai_assets, device_mcp, os_patch_status, device_browsers, device_posture, device_accounts, dir_sensitive])
        .run(tauri::generate_context!())
        .expect("error while running MoorAI");
}
