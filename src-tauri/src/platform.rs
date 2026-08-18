// Platform shims. Everything that differs between macOS and Windows lives here so lib.rs stays
// platform-neutral. Each function has a `#[cfg]`-gated body per OS; the signatures are identical.
use portable_pty::CommandBuilder;
use std::path::Path;

// --- paths & identity ---

// The user's home directory: $HOME on Unix, %USERPROFILE% on Windows. Forward slashes work in
// std::fs paths on Windows, so callers can keep using `format!("{home}/.curaiq")` unchanged.
pub fn home_dir() -> String {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").unwrap_or_default()
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME").unwrap_or_default()
    }
}

pub fn config_dir() -> String {
    format!("{}/.curaiq", home_dir())
}

pub fn config_path() -> String {
    format!("{}/config.json", config_dir())
}

// Login name: USER/LOGNAME on Unix, USERNAME on Windows.
pub fn username() -> String {
    std::env::var("USER")
        .ok()
        .or_else(|| std::env::var("USERNAME").ok())
        .or_else(|| std::env::var("LOGNAME").ok())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

// Device name. Windows exposes it as COMPUTERNAME (no subprocess); Unix uses the `hostname` command.
pub fn hostname() -> String {
    #[cfg(windows)]
    {
        if let Ok(h) = std::env::var("COMPUTERNAME") {
            if !h.is_empty() {
                return h;
            }
        }
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

// OS product version: `sw_vers -productVersion` on macOS, the `ver` banner on Windows.
pub fn os_version() -> String {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_default()
    }
    #[cfg(windows)]
    {
        std::process::Command::new("cmd")
            .args(["/c", "ver"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .and_then(|s| s.rsplit("Version ").next().map(|v| v.trim_end_matches(']').trim().to_string()))
            .filter(|s| !s.is_empty())
            .unwrap_or_default()
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        String::new()
    }
}

// --- code signature (about dialog) ---

// Whether the running binary carries a valid vendor signature. macOS: a Developer ID authority in
// codesign. Windows: an Authenticode signature reporting Valid. We surface only the boolean.
pub fn is_signed() -> bool {
    #[cfg(target_os = "macos")]
    {
        if let Ok(exe) = std::env::current_exe() {
            // exe = .../MoorAI.app/Contents/MacOS/curaiq → the .app bundle is 3 levels up.
            if let Some(bundle) = exe.ancestors().nth(3) {
                if let Ok(out) = std::process::Command::new("codesign").arg("-dvv").arg(bundle).output() {
                    for line in String::from_utf8_lossy(&out.stderr).lines() {
                        if let Some(a) = line.strip_prefix("Authority=") {
                            if a.contains("Developer ID") {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
    #[cfg(windows)]
    {
        if let Ok(exe) = std::env::current_exe() {
            let ps = format!(
                "(Get-AuthenticodeSignature -LiteralPath '{}').Status",
                exe.display()
            );
            if let Ok(out) = std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
                .output()
            {
                return String::from_utf8_lossy(&out.stdout).trim().eq_ignore_ascii_case("Valid");
            }
        }
        false
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        false
    }
}

// --- agent CLI resolution & launch ---

fn env_override_key(tool: &str) -> &'static str {
    match tool {
        "codex" => "MoorAI_CODEX",
        "copilot" => "MoorAI_COPILOT",
        _ => "MoorAI_CLAUDE",
    }
}

fn tool_candidates(tool: &str, home: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        // npm global installs land as .cmd shims in %APPDATA%\npm; native installers vary.
        vec![
            format!("{home}/.local/bin/{tool}.exe"),
            format!("{home}/.local/bin/{tool}.cmd"),
            format!("{appdata}/npm/{tool}.cmd"),
            format!("{appdata}/npm/{tool}.exe"),
            format!("{home}/.{tool}/bin/{tool}.exe"),
            format!("{local}/Programs/{tool}/{tool}.exe"),
        ]
    }
    #[cfg(not(windows))]
    {
        match tool {
            "codex" => vec![
                format!("{home}/.local/bin/codex"),
                format!("{home}/.codex/bin/codex"),
                "/opt/homebrew/bin/codex".into(),
                "/usr/local/bin/codex".into(),
            ],
            "copilot" => vec![
                format!("{home}/.local/bin/copilot"),
                format!("{home}/.npm-global/bin/copilot"),
                "/opt/homebrew/bin/copilot".into(),
                "/usr/local/bin/copilot".into(),
            ],
            _ => vec![
                format!("{home}/.local/bin/claude"),
                format!("{home}/.claude/local/claude"),
                "/opt/homebrew/bin/claude".into(),
                "/usr/local/bin/claude".into(),
            ],
        }
    }
}

// Resolve an agent CLI (GUI/minimal-PATH safe): env override, then known install locations, then a
// PATH scan honoring platform executable extensions.
pub fn find_tool(tool: &str) -> Option<String> {
    let home = home_dir();
    if let Ok(p) = std::env::var(env_override_key(tool)) {
        if Path::new(&p).exists() {
            return Some(p);
        }
    }
    tool_candidates(tool, &home)
        .into_iter()
        .find(|p| Path::new(p).exists())
        .or_else(|| which(tool))
}

// Minimal `which`: scan PATH, applying PATHEXT on Windows so `claude` resolves to claude.cmd/.exe.
pub fn which(tool: &str) -> Option<String> {
    let path = std::env::var("PATH").unwrap_or_default();
    let sep = if cfg!(windows) { ';' } else { ':' };
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT".into())
            .split(';')
            .map(|s| s.trim().to_lowercase())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in path.split(sep) {
        if dir.is_empty() {
            continue;
        }
        for ext in &exts {
            let cand = format!("{dir}/{tool}{ext}");
            if Path::new(&cand).exists() {
                return Some(cand);
            }
        }
    }
    None
}

// Host-based isolation (experimental, opt-in). On macOS, write a conservative Seatbelt profile that
// lets the agent operate normally in the user's home working area but blocks writes to system, app,
// and boot locations — so a compromised or tricked agent can't modify the OS, install persistence,
// or tamper with other apps. Network and normal file work stay available. Returns the profile path.
#[cfg(target_os = "macos")]
fn sandbox_profile_path() -> Option<String> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir).ok()?;
    let path = format!("{dir}/agent-sandbox.sb");
    let profile = "(version 1)\n\
;; MoorAI agent isolation (experimental) — governance sandbox. Allow normal operation; deny writes\n\
;; to system / app / boot locations so the agent cannot modify the OS or install persistence.\n\
(allow default)\n\
(deny file-write*\n\
  (subpath \"/System\")\n\
  (subpath \"/usr/bin\")\n\
  (subpath \"/usr/sbin\")\n\
  (subpath \"/bin\")\n\
  (subpath \"/sbin\")\n\
  (subpath \"/Library\")\n\
  (subpath \"/Applications\")\n\
  (subpath \"/etc\")\n\
  (subpath \"/private/etc\"))\n";
    std::fs::write(&path, profile).ok()?;
    Some(path)
}

// Build the launch command for an agent binary. When `isolate` is set, the process is launched
// inside a host sandbox (macOS Seatbelt via sandbox-exec; Windows restricted token is a follow-up).
// On Windows, .cmd/.bat shims can't be executed directly by CreateProcess, so wrap them in `cmd /c`.
pub fn agent_command(bin: &str, isolate: bool) -> CommandBuilder {
    #[cfg(target_os = "macos")]
    if isolate {
        if let Some(profile) = sandbox_profile_path() {
            // sandbox-exec runs `bin` (plus any args term_open appends) under the profile.
            let mut c = CommandBuilder::new("sandbox-exec");
            c.arg("-f");
            c.arg(profile);
            c.arg(bin);
            return c;
        }
    }
    #[cfg(windows)]
    {
        let _ = isolate; // Windows host isolation (restricted token / AppContainer) — follow-up.
        let lower = bin.to_ascii_lowercase();
        if lower.ends_with(".cmd") || lower.ends_with(".bat") {
            let mut c = CommandBuilder::new("cmd.exe");
            c.arg("/c");
            c.arg(bin);
            return c;
        }
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = isolate;
    }
    CommandBuilder::new(bin)
}

// PATH with the likely agent-install dirs prepended, so a launched CLI can find sibling tools.
pub fn augmented_path() -> String {
    let path = std::env::var("PATH").unwrap_or_default();
    #[cfg(windows)]
    {
        let home = home_dir();
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        format!("{home}\\.local\\bin;{appdata}\\npm;{path}")
    }
    #[cfg(not(windows))]
    {
        format!("/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:{path}")
    }
}

// Open an interactive terminal running the given CLI so the user can complete an OAuth login.
pub fn launch_login_terminal(bin: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        std::process::Command::new("cmd")
            .args(["/c", "start", "", bin])
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let script = format!(
            "tell application \"Terminal\"\nactivate\ndo script \"{}\"\nend tell",
            bin
        );
        std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

// --- device inventory ---

// Shared shadow-AI catalog (data/ai-catalog.json), embedded at compile time so BOTH this Rust host
// and the JS CLI AIBOM (cli/moorai-aibom.mjs) agree on "what counts as AI" from one source of truth.
// Rust can't import JS, so the catalog is JSON read via include_str! + serde_json. Content-free:
// only app-path presence, extension NAME keywords, and known extension IDs drive the match.
fn ai_catalog() -> &'static serde_json::Value {
    use std::sync::OnceLock;
    static CATALOG: OnceLock<serde_json::Value> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("../../data/ai-catalog.json"))
            .unwrap_or_else(|_| serde_json::json!({ "apps": [], "extensions": [] }))
    })
}

// Match a browser/editor extension against the catalog by known store id (exact, case-insensitive)
// or by display-name keyword (plain lowercase substring — kept substring, not regex, so this and the
// JS side match byte-for-byte). Returns the catalog entry id when it's a known AI extension.
// NOTE: "extension dir/name present" ≠ enabled — this is presence, not activity. Acceptable for
// content-free discovery; only the name/id ever leaves the device, never storage or page content.
fn ai_ext_match(name: &str, id: &str) -> Option<String> {
    let name_l = name.to_lowercase();
    let exts = ai_catalog().get("extensions")?.as_array()?;
    for e in exts {
        let entry_id = e.get("id").and_then(|v| v.as_str());
        if let Some(ids) = e.get("ids").and_then(|v| v.as_array()) {
            if ids.iter().any(|x| x.as_str().map(|s| s.eq_ignore_ascii_case(id)).unwrap_or(false)) {
                return entry_id.map(|s| s.to_string());
            }
        }
        if let Some(kws) = e.get("keywords").and_then(|v| v.as_array()) {
            if kws.iter().any(|k| k.as_str().map(|s| name_l.contains(s)).unwrap_or(false)) {
                return entry_id.map(|s| s.to_string());
            }
        }
    }
    None
}

// Start-menu shortcut probe (Windows): the .lnk may sit directly in Programs\ or one folder deep
// (e.g. Programs\ChatGPT\ChatGPT.lnk). Presence-only.
#[cfg(windows)]
fn start_menu_has(dir: &str, leaf: &str) -> bool {
    if Path::new(&format!("{dir}/{leaf}")).exists() {
        return true;
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.path().is_dir() && e.path().join(leaf).exists() {
                return true;
            }
        }
    }
    false
}

// Catalog-driven installed AI desktop apps (display names). Presence-only (path existence).
// macOS: /Applications + ~/Applications (per-user installs). Windows: %LOCALAPPDATA%,
// %PROGRAMFILES%, %PROGRAMFILES(X86)% for the exe, plus Start-Menu .lnk shortcuts.
fn installed_ai_apps() -> Vec<String> {
    let apps = match ai_catalog().get("apps").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return vec![],
    };
    let strs = |a: &serde_json::Value, key: &str| -> Vec<String> {
        a.get(key)
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default()
    };

    #[cfg(target_os = "macos")]
    let roots: Vec<String> = vec!["/Applications".to_string(), format!("{}/Applications", home_dir())];

    #[cfg(windows)]
    let (roots, start_menus): (Vec<String>, Vec<String>) = {
        let var = |k: &str| std::env::var(k).unwrap_or_default();
        let roots: Vec<String> = [var("LOCALAPPDATA"), var("ProgramFiles"), var("ProgramFiles(x86)")]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect();
        let start_menus: Vec<String> = [var("APPDATA"), var("ProgramData")]
            .into_iter()
            .filter(|s| !s.is_empty())
            .map(|s| format!("{s}/Microsoft/Windows/Start Menu/Programs"))
            .collect();
        (roots, start_menus)
    };

    #[cfg(not(any(target_os = "macos", windows)))]
    let _ = &strs; // no platform paths on other OSes

    #[cfg(not(any(target_os = "macos", windows)))]
    return vec![];

    #[cfg(any(target_os = "macos", windows))]
    apps.iter()
        .filter_map(|a| {
            let name = a.get("name")?.as_str()?;
            #[cfg(target_os = "macos")]
            let hit = strs(a, "mac")
                .iter()
                .any(|leaf| roots.iter().any(|r| Path::new(&format!("{r}/{leaf}")).exists()));
            #[cfg(windows)]
            let hit = strs(a, "win")
                .iter()
                .any(|frag| roots.iter().any(|r| Path::new(&format!("{r}/{frag}")).exists()))
                || strs(a, "winLnk")
                    .iter()
                    .any(|lnk| start_menus.iter().any(|sm| start_menu_has(sm, lnk)));
            if hit { Some(name.to_string()) } else { None }
        })
        .collect()
}

// Installed AI apps + CLI tools, plus OS + version. Metadata only, never content.
pub fn ai_tools() -> serde_json::Value {
    let home = home_dir();

    let mut tools: Vec<String> = installed_ai_apps();

    // CLI AI tools — resolved through the same finder used to launch them.
    for (label, name) in [("claude CLI", "claude"), ("codex CLI", "codex"), ("copilot CLI", "copilot")] {
        if find_tool(name).is_some() {
            tools.push(label.to_string());
        }
    }
    // ollama / aider on common paths (no launcher for these).
    #[cfg(not(windows))]
    {
        let extra: [(&str, [String; 3]); 2] = [
            ("ollama CLI", [format!("{home}/.ollama"), "/opt/homebrew/bin/ollama".into(), "/usr/local/bin/ollama".into()]),
            ("aider", [format!("{home}/.local/bin/aider"), "/opt/homebrew/bin/aider".into(), "/usr/local/bin/aider".into()]),
        ];
        for (name, paths) in &extra {
            if paths.iter().any(|p| Path::new(p).exists()) {
                tools.push(name.to_string());
            }
        }
    }
    #[cfg(windows)]
    {
        let _ = &home;
        if which("ollama").is_some() {
            tools.push("ollama CLI".into());
        }
        if which("aider").is_some() {
            tools.push("aider".into());
        }
    }

    serde_json::json!({ "os": std::env::consts::OS, "osVersion": os_version(), "tools": tools })
}

// Chromium profile dirs under a browser's User Data root (each holds an Extensions/ dir).
fn chromium_profiles(base: &str) -> Vec<std::path::PathBuf> {
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(base) {
        for e in rd.flatten() {
            let p = e.path();
            if p.join("Extensions").is_dir() {
                out.push(p);
            }
        }
    }
    out
}

fn resolve_ext_name(ver: &Path, m: &serde_json::Value, id: &str) -> String {
    let name = m.get("name").and_then(|v| v.as_str()).unwrap_or(id);
    if !name.starts_with("__MSG_") {
        return name.to_string();
    }
    let key = name.trim_start_matches("__MSG_").trim_end_matches("__");
    let locale = m.get("default_locale").and_then(|v| v.as_str()).unwrap_or("en");
    for loc in [locale, "en", "en_US"] {
        if let Ok(t) = std::fs::read_to_string(ver.join(format!("_locales/{loc}/messages.json"))) {
            if let Ok(j) = serde_json::from_str::<serde_json::Value>(&t) {
                if let Some(o) = j.as_object() {
                    if let Some(v) = o.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v) {
                        if let Some(msg) = v.get("message").and_then(|x| x.as_str()) {
                            return msg.to_string();
                        }
                    }
                }
            }
        }
    }
    id.to_string()
}

fn ext_broad(m: &serde_json::Value) -> bool {
    let broad = ["<all_urls>", "*://*/*", "http://*/*", "https://*/*", "tabs", "webRequest", "webRequestBlocking", "cookies", "clipboardRead", "history", "debugger"];
    let has = |key: &str| {
        m.get(key)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().any(|p| broad.contains(&p.as_str().unwrap_or(""))))
            .unwrap_or(false)
    };
    has("host_permissions") || has("permissions")
}

// Chromium-family browsers and their User Data roots, per platform.
fn chromium_bases() -> Vec<(&'static str, String)> {
    let home = home_dir();
    #[cfg(target_os = "macos")]
    {
        let sup = format!("{home}/Library/Application Support");
        vec![
            ("Google Chrome", format!("{sup}/Google/Chrome")),
            ("Microsoft Edge", format!("{sup}/Microsoft Edge")),
            ("Brave", format!("{sup}/BraveSoftware/Brave-Browser")),
            ("Arc", format!("{sup}/Arc/User Data")),
            ("Vivaldi", format!("{sup}/Vivaldi")),
            ("Opera", format!("{sup}/com.operasoftware.Opera")),
        ]
    }
    #[cfg(windows)]
    {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        let _ = &home;
        vec![
            ("Google Chrome", format!("{local}/Google/Chrome/User Data")),
            ("Microsoft Edge", format!("{local}/Microsoft/Edge/User Data")),
            ("Brave", format!("{local}/BraveSoftware/Brave-Browser/User Data")),
            ("Vivaldi", format!("{local}/Vivaldi/User Data")),
            ("Opera", format!("{appdata}/Opera Software/Opera Stable")),
        ]
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = &home;
        vec![]
    }
}

fn firefox_profiles_dir() -> String {
    let home = home_dir();
    #[cfg(target_os = "macos")]
    {
        format!("{home}/Library/Application Support/Firefox/Profiles")
    }
    #[cfg(windows)]
    {
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        let _ = &home;
        format!("{appdata}/Mozilla/Firefox/Profiles")
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        format!("{home}/.mozilla/firefox")
    }
}

// Installed browsers and their extensions (name, id, broad-access flag). A browser is reported when
// its profile/User-Data dir exists. Safari is macOS-only (App Extensions via pluginkit).
pub fn browsers() -> serde_json::Value {
    let mut result = vec![];

    for (name, base) in chromium_bases() {
        if !Path::new(&base).exists() {
            continue;
        }
        let mut exts = vec![];
        let mut seen = std::collections::HashSet::new();
        for profile in chromium_profiles(&base) {
            if let Ok(rd) = std::fs::read_dir(profile.join("Extensions")) {
                for id_entry in rd.flatten() {
                    if exts.len() >= 100 {
                        break;
                    }
                    let id = id_entry.file_name().to_string_lossy().to_string();
                    if id.starts_with('.') || id == "Temp" || !seen.insert(id.clone()) {
                        continue;
                    }
                    let ver = std::fs::read_dir(id_entry.path())
                        .ok()
                        .and_then(|r| r.flatten().map(|e| e.path()).find(|p| p.is_dir()));
                    if let Some(ver) = ver {
                        if let Ok(t) = std::fs::read_to_string(ver.join("manifest.json")) {
                            if let Ok(m) = serde_json::from_str::<serde_json::Value>(&t) {
                                let nm = resolve_ext_name(&ver, &m, &id);
                                let aim = ai_ext_match(&nm, &id);
                                exts.push(serde_json::json!({ "name": nm, "id": id, "broad": ext_broad(&m), "ai": aim.is_some(), "aiId": aim }));
                            }
                        }
                    }
                }
            }
        }
        result.push(serde_json::json!({ "browser": name, "extensions": exts }));
    }

    // Firefox — same extensions.json format on every platform.
    let ff = firefox_profiles_dir();
    if Path::new(&ff).exists() {
        let mut exts = vec![];
        if let Ok(rd) = std::fs::read_dir(&ff) {
            for p in rd.flatten() {
                if let Ok(t) = std::fs::read_to_string(p.path().join("extensions.json")) {
                    if let Ok(j) = serde_json::from_str::<serde_json::Value>(&t) {
                        if let Some(addons) = j.get("addons").and_then(|a| a.as_array()) {
                            for a in addons {
                                if a.get("type").and_then(|t| t.as_str()) != Some("extension") {
                                    continue;
                                }
                                if a.get("location").and_then(|l| l.as_str()) != Some("app-profile") {
                                    continue;
                                }
                                let id = a.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let nm = a.pointer("/defaultLocale/name").and_then(|v| v.as_str()).unwrap_or(&id).to_string();
                                let aim = ai_ext_match(&nm, &id);
                                exts.push(serde_json::json!({ "name": nm, "id": id, "broad": false, "ai": aim.is_some(), "aiId": aim }));
                            }
                        }
                    }
                }
            }
        }
        if !exts.is_empty() || result.iter().all(|b| b["browser"] != "Firefox") {
            result.push(serde_json::json!({ "browser": "Firefox", "extensions": exts }));
        }
    }

    // Safari — Apple App Extensions registered with the system (macOS only).
    #[cfg(target_os = "macos")]
    {
        if Path::new("/Applications/Safari.app").exists() {
            let mut exts = vec![];
            let mut seen = std::collections::HashSet::new();
            for proto in ["com.apple.Safari.web-extension", "com.apple.Safari.extension", "com.apple.Safari.content-blocker"] {
                if let Ok(out) = std::process::Command::new("pluginkit").args(["-m", "-A", "-v", "-p", proto]).output() {
                    for line in String::from_utf8_lossy(&out.stdout).lines() {
                        if exts.len() >= 100 {
                            break;
                        }
                        let id = line.split_whitespace().find(|t| t.contains('.')).unwrap_or("").split('(').next().unwrap_or("").to_string();
                        if id.is_empty() || id.starts_with("com.apple.") || !seen.insert(id.clone()) {
                            continue;
                        }
                        let name = id.rsplit('.').next().unwrap_or(&id).to_string();
                        let aim = ai_ext_match(&name, &id);
                        exts.push(serde_json::json!({ "name": name, "id": id, "broad": false, "ai": aim.is_some(), "aiId": aim }));
                    }
                }
            }
            result.push(serde_json::json!({ "browser": "Safari", "extensions": exts }));
        }
    }

    serde_json::json!(result)
}

// Distinct shadow-AI signal (Feature 2): the catalog-matched AI desktop apps + the AI-classified
// browser/editor extensions, as clean arrays. Reuses the same content-free collectors and the same
// /api/device-report sink — no new endpoint, no new data leaving the device (names/ids/flags only).
pub fn ai_shadow() -> serde_json::Value {
    let apps = installed_ai_apps();
    let mut extensions = vec![];
    if let Some(browser_list) = browsers().as_array() {
        for b in browser_list {
            let browser = b.get("browser").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if let Some(exts) = b.get("extensions").and_then(|v| v.as_array()) {
                for e in exts {
                    if e.get("ai").and_then(|v| v.as_bool()).unwrap_or(false) {
                        extensions.push(serde_json::json!({
                            "browser": browser,
                            "name": e.get("name").cloned().unwrap_or(serde_json::Value::Null),
                            "id": e.get("id").cloned().unwrap_or(serde_json::Value::Null),
                            "aiId": e.get("aiId").cloned().unwrap_or(serde_json::Value::Null),
                            "broad": e.get("broad").cloned().unwrap_or(serde_json::Value::Bool(false)),
                        }));
                    }
                }
            }
        }
    }
    serde_json::json!({ "apps": apps, "extensions": extensions })
}

// Pending OS security/software updates (posture signal). macOS: `softwareupdate -l`. Windows: the
// Microsoft.Update COM searcher via PowerShell. Both can be slow — callers invoke this async.
pub fn patch_status() -> serde_json::Value {
    #[cfg(target_os = "macos")]
    {
        match std::process::Command::new("softwareupdate").arg("-l").output() {
            Ok(o) => {
                let s = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
                if s.contains("No new software available") {
                    return serde_json::json!({ "upToDate": true, "count": 0, "titles": [] });
                }
                let titles: Vec<String> = s
                    .lines()
                    .filter(|l| l.trim_start().starts_with("Title:"))
                    .map(|l| l.trim().trim_start_matches("Title:").trim().trim_end_matches(',').to_string())
                    .collect();
                let labels = s.lines().filter(|l| l.trim_start().starts_with("* Label:")).count();
                let count = if titles.is_empty() { labels } else { titles.len() };
                serde_json::json!({ "upToDate": count == 0, "count": count, "titles": titles })
            }
            Err(e) => serde_json::json!({ "upToDate": null, "count": 0, "error": e.to_string() }),
        }
    }
    #[cfg(windows)]
    {
        crate::winsec::patch_status()
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        serde_json::json!({ "upToDate": null, "count": 0 })
    }
}

// Native security-posture bundle (AV / firewall / disk encryption). Windows-native via windows-rs;
// empty elsewhere for now (a macOS equivalent — Defender/socketfilterfw/fdesetup — can follow).
pub fn security_posture() -> serde_json::Value {
    #[cfg(windows)]
    {
        crate::winsec::security_posture()
    }
    #[cfg(not(windows))]
    {
        serde_json::json!({})
    }
}
