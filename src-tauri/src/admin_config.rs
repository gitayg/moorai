// Settings only an administrator can make. ~/.moorai/config.json (and the localStorage of the webview) is
// writable by the agent MoorAI guards, so nothing read from it may decide where the app's console or its
// updates come from, or whether updates run at all. These sources may:
//
//   macOS    the managed preferences of the run.glick.moorai domain, as an MDM configuration profile
//            installs them: /Library/Managed Preferences/<user>/run.glick.moorai.plist, then
//            /Library/Managed Preferences/run.glick.moorai.plist, and then the machine file. <user> is
//            the login name of the process's uid from the user database (getpwuid_r), never USER,
//            LOGNAME or HOME, which whoever launched the app sets; a name that could leave the directory
//            (a separator, "..", NUL) drops the per-user path;
//   macOS, Linux  the machine file /etc/moorai/config.json;
//   Windows  the machine file <ProgramData>\MoorAI\config.json, read only when its ACL lets nobody but
//            Administrators, SYSTEM or TrustedInstaller write it (the evaluation of cli/hook-core.mjs
//            icaclsPermissive, over the output of <SystemRoot>\System32\icacls.exe). ProgramData and
//            SystemRoot come from HKLM (admin-written), not the environment, which the user sets; the file
//            is held open without write or delete sharing from the ACL check to the read, so the file read
//            is the file checked, and a reparse point (symlink or junction) at the file is refused.
//
// On macOS and Linux every file is read the same way (read_owned_under): its directory, canonicalised,
// must lie under the source's root (/Library/Managed Preferences, /etc/moorai); that directory and every
// one above it must be owned by root and not group- or world-writable; the file is opened with
// O_NOFOLLOW (a symlink is refused) and its owner (root) and mode (not group- or world-writable) are
// checked on the open descriptor, which is then the one read, so nothing can be swapped in between.
// A plist is handed to /usr/bin/plutil on stdin, not by path.
//
//   key                     managed preference   machine file
//   provisioned console     ServerURL            "serverUrl"
//   updates off             DisableUpdates true  "updates": "off" (or false)
//
// A file that fails the ownership or ACL check, or cannot be checked, is ignored, as if absent.
// Known gap, shared with cli/hook-core.mjs: icacls does not print the file's owner, so on Windows a file an
// ordinary user created and then stripped to an administrator-only DACL still passes. Creating it needs
// write access to %ProgramData%\MoorAI, which the MDM install script should take away (packaging/mdm).
use serde_json::Value;

pub const MANAGED_DOMAIN: &str = "run.glick.moorai";
pub const MANAGED_SERVER_KEY: &str = "ServerURL";
pub const MANAGED_DISABLE_UPDATES_KEY: &str = "DisableUpdates";

#[derive(Debug, Default, PartialEq, Clone)]
pub struct Admin {
    // The console an administrator provisioned, as a bare origin (console_binding::normalize_origin).
    pub console: Option<String>,
    // Why an administrator turned updates off, when one did.
    pub updates_off: Option<String>,
}

pub fn machine_config_path() -> String {
    if cfg!(windows) {
        format!("{}\\MoorAI\\config.json", windows_dirs().1)
    } else {
        "/etc/moorai/config.json".into()
    }
}

// (SystemRoot, ProgramData) as HKLM records them. The environment variables of the same names are the
// user's to set (and the agent's, for any app it starts), so they would let a user-made directory pass as
// the machine's.
#[cfg(windows)]
fn windows_dirs() -> (String, String) {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    let drive_path = |s: &str| s.len() > 2 && s.as_bytes()[0].is_ascii_alphabetic() && &s[1..3] == ":\\";
    let root = hklm.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion").ok()
        .and_then(|k| k.get_value::<String, _>("SystemRoot").ok())
        .filter(|s| drive_path(s))
        .unwrap_or_else(|| "C:\\Windows".into());
    // REG_EXPAND_SZ "%SystemDrive%\ProgramData"; %SystemDrive% is expanded from SystemRoot above, not from
    // the environment.
    let pd = hklm.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList").ok()
        .and_then(|k| k.get_value::<String, _>("ProgramData").ok())
        .map(|s| s.replace("%SystemDrive%", &root[..2]).replace("%SYSTEMDRIVE%", &root[..2]))
        .filter(|s| drive_path(s) && !s.contains('%'))
        .unwrap_or_else(|| format!("{}\\ProgramData", &root[..2]));
    (root, pd)
}
#[cfg(not(windows))]
fn windows_dirs() -> (String, String) { ("C:\\Windows".into(), "C:\\ProgramData".into()) }

// "updates": "off" (or false).
pub fn updates_off_value(v: Option<&Value>) -> bool {
    match v {
        Some(Value::String(s)) => s.trim().eq_ignore_ascii_case("off"),
        Some(Value::Bool(b)) => !b,
        _ => false,
    }
}

// The admin settings, from what each source said. `machine` is the parsed machine file (Null if absent or
// untrusted). A managed value wins; an unusable console URL counts as unset.
pub fn from_sources(managed_server: Option<String>, managed_disable: Option<bool>, machine: &Value, machine_path: &str) -> Admin {
    let usable = |s: &str| crate::console_binding::normalize_origin(s).ok();
    let console = managed_server.as_deref().and_then(usable)
        .or_else(|| machine.get("serverUrl").and_then(|v| v.as_str()).and_then(usable));
    let updates_off = if managed_disable == Some(true) {
        Some(format!("turned off by the managed setting {MANAGED_DISABLE_UPDATES_KEY} ({MANAGED_DOMAIN})"))
    } else if updates_off_value(machine.get("updates")) {
        Some(format!("turned off in {machine_path} (\"updates\": \"off\")"))
    } else {
        None
    };
    Admin { console, updates_off }
}

pub fn admin() -> Admin {
    let path = machine_config_path();
    let machine = read_admin_owned(&path).and_then(|t| serde_json::from_str::<Value>(&t).ok()).unwrap_or(Value::Null);
    let (server, disable) = managed();
    from_sources(server, disable, &machine, &path)
}

// ---- macOS managed preferences ----

pub const MANAGED_ROOT: &str = "/Library/Managed Preferences";

// A managed value: /usr/bin/plutil reads the plist from stdin (the bytes read_owned_under returned), never
// from a path that could be swapped after the checks. Local only (no network).
pub fn plist_raw(plist: &[u8], key: &str) -> Option<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("/usr/bin/plutil").args(["-extract", key, "raw", "-o", "-", "-"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let wrote = child.stdin.take().map(|mut i| i.write_all(plist).is_ok()).unwrap_or(false);
    let out = child.wait_with_output().ok()?;
    if !wrote || !out.status.success() { return None; }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn plist_bool(plist: &[u8], key: &str) -> Option<bool> {
    match plist_raw(plist, key)?.as_str() {
        "true" | "1" | "YES" => Some(true),
        "false" | "0" | "NO" => Some(false),
        _ => None,
    }
}

// The login name of this process's real uid, from the user database. Never USER, LOGNAME or HOME: the
// launcher of the process sets those.
#[cfg(unix)]
pub fn os_username() -> Option<String> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(libc::getuid(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found) };
    if rc != 0 || found.is_null() || pwd.pw_name.is_null() { return None; }
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }.to_string_lossy().into_owned();
    Some(name).filter(|n| !n.is_empty())
}

// A name that can only be one directory directly under MANAGED_ROOT.
pub fn safe_path_component(name: &str) -> bool {
    !name.is_empty() && !name.contains("..") && !name.contains(['/', '\\', '\0'])
}

// The per-user plist (only for a name that stays one component), then the machine-wide one.
pub fn managed_paths(user: Option<&str>) -> Vec<std::path::PathBuf> {
    let root = std::path::Path::new(MANAGED_ROOT);
    let file = format!("{MANAGED_DOMAIN}.plist");
    let mut paths = Vec::new();
    if let Some(u) = user.filter(|u| safe_path_component(u)) { paths.push(root.join(u).join(&file)); }
    paths.push(root.join(&file));
    paths
}

// (ServerURL, DisableUpdates) from the first of `paths` that says each, reading only files that pass
// read_owned_under(root, owner).
#[cfg(unix)]
pub fn managed_from(paths: &[std::path::PathBuf], root: &std::path::Path, owner: u32) -> (Option<String>, Option<bool>) {
    let plists: Vec<Vec<u8>> = paths.iter().filter_map(|p| read_owned_under(p, root, owner)).collect();
    let server = plists.iter().find_map(|b| plist_raw(b, MANAGED_SERVER_KEY).filter(|s| !s.is_empty()));
    let disable = plists.iter().find_map(|b| plist_bool(b, MANAGED_DISABLE_UPDATES_KEY));
    (server, disable)
}

#[cfg(target_os = "macos")]
fn managed() -> (Option<String>, Option<bool>) {
    managed_from(&managed_paths(os_username().as_deref()), std::path::Path::new(MANAGED_ROOT), 0)
}
#[cfg(not(target_os = "macos"))]
fn managed() -> (Option<String>, Option<bool>) { (None, None) }

// ---- reading a file only root can have written (macOS, Linux) ----

// The file's bytes when only root (or `owner`: production passes 0; tests pass their own uid so the
// checks can be exercised without root) can have written it, else None:
//   - its directory, canonicalised, lies under `root` (canonicalised), so ".." and a symlinked directory
//     cannot lead elsewhere;
//   - that directory and every directory above it is owned by root (or `owner`) and not group- or
//     world-writable, so nobody else can rename the file away or put another in its place;
//   - the file is opened with O_NOFOLLOW (a symlink is refused) and O_NONBLOCK (a FIFO cannot hang the
//     app), and the open descriptor's metadata says a regular file owned by root (or `owner`) and not
//     group- or world-writable; that descriptor is what is read, so the file read is the file checked.
#[cfg(unix)]
pub fn read_owned_under(path: &std::path::Path, root: &std::path::Path, owner: u32) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let trusted = |md: &std::fs::Metadata| (md.uid() == 0 || md.uid() == owner) && md.mode() & 0o022 == 0;
    let root = root.canonicalize().ok()?;
    let name = path.file_name()?;
    let dir = path.parent()?.canonicalize().ok()?;
    if !dir.starts_with(&root) { return None; }
    for d in dir.ancestors() {
        let md = std::fs::symlink_metadata(d).ok()?;
        if !md.is_dir() || !trusted(&md) { return None; }
    }
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(dir.join(name)).ok()?;
    let md = f.metadata().ok()?;
    if !md.is_file() || !trusted(&md) { return None; }
    let mut bytes = Vec::new();
    f.take(1 << 20).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

// ---- the machine file ----

// The file's text when only an administrator can have written it, else None.
#[cfg(unix)]
pub fn read_admin_owned(path: &str) -> Option<String> {
    let p = std::path::Path::new(path);
    String::from_utf8(read_owned_under(p, p.parent()?, 0)?).ok()
}

#[cfg(windows)]
pub fn read_admin_owned(path: &str) -> Option<String> {
    use std::io::Read;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::process::CommandExt;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // Held open with read sharing only from before the ACL check until the read: nobody can write,
    // rename or delete the file in between, so icacls judges the file that is read. A reparse point at
    // the file (symlink, junction) is opened as itself and refused.
    let f = std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path).ok()?;
    let md = f.metadata().ok()?;
    if !md.is_file() || md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 { return None; }
    // A fixed path from HKLM, not PATH or %SystemRoot%: both are the user's to change.
    let root = windows_dirs().0;
    let out = std::process::Command::new(format!("{root}\\System32\\icacls.exe")).arg(path).creation_flags(CREATE_NO_WINDOW).output().ok()?;
    if !out.status.success() || icacls_permissive(&String::from_utf8_lossy(&out.stdout), path) { return None; }
    let mut text = String::new();
    f.take(1 << 20).read_to_string(&mut text).ok()?;
    Some(text)
}

// ---- icacls evaluation (cli/hook-core.mjs parseIcacls / icaclsPermissive) ----

#[cfg(any(windows, test))]
const ICACLS_FLAGS: [&str; 5] = ["OI", "CI", "IO", "NP", "I"];
#[cfg(any(windows, test))]
const ICACLS_WRITE: [&str; 12] = ["F", "M", "W", "WD", "AD", "WA", "WEA", "D", "DE", "DC", "WDAC", "WO"];
// An allow-list: anyone else with write access makes the file user-writable. CREATOR OWNER is absent on
// purpose; its standard ACE is inherit-only and so does not apply to the file itself.
#[cfg(any(windows, test))]
const ICACLS_PRIVILEGED: [&str; 7] = ["SYSTEM", "LOCAL SYSTEM", "ADMINISTRATORS", "ADMINISTRATOR", "TRUSTEDINSTALLER", "DOMAIN ADMINS", "ENTERPRISE ADMINS"];

#[cfg(any(windows, test))]
fn acl_principal(name: &str) -> String {
    let s = name.trim();
    s.rsplit('\\').next().unwrap_or(s).trim().to_ascii_uppercase()
}

// True when the ACL lets someone who is not an administrator write the file, or has no entry we can read
// (the guarantee could not be established, so it is not claimed).
#[cfg(any(windows, test))]
pub fn icacls_permissive(output: &str, path: &str) -> bool {
    let ace = regex::Regex::new(r"^\s*(.+?):((?:\([^()]*\))+)\s*$").expect("static regex");
    let group = regex::Regex::new(r"\(([^()]*)\)").expect("static regex");
    let mut entries = 0;
    for raw in output.lines() {
        let t = raw.trim();
        if t.is_empty() { continue; }
        let lt = t.to_ascii_lowercase();
        if lt.starts_with("successfully processed") || lt.starts_with("failed processing") { continue; }
        let line = if !path.is_empty() && raw.starts_with(path) { &raw[path.len()..] } else { raw };
        let Some(m) = ace.captures(line) else { continue };
        entries += 1;
        let mut inherit_only = false;
        let mut writes = false;
        for g in group.captures_iter(&m[2]) {
            let u = g[1].trim().to_ascii_uppercase();
            if ICACLS_FLAGS.contains(&u.as_str()) { if u == "IO" { inherit_only = true; } continue; }
            if u.split(',').any(|r| ICACLS_WRITE.contains(&r.trim())) { writes = true; }
        }
        if inherit_only || !writes { continue; }
        if !ICACLS_PRIVILEGED.contains(&acl_principal(&m[1]).as_str()) { return true; }
    }
    entries == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scratch(tag: &str) -> String {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let d = std::env::temp_dir().join(format!("moorai-admin-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    #[test]
    fn the_admin_console_comes_from_the_managed_preference_then_the_machine_file() {
        let p = "/etc/moorai/config.json";
        assert_eq!(from_sources(Some("https://moorai.acme.internal/x".into()), None, &json!({ "serverUrl": "https://other.example" }), p).console.as_deref(), Some("https://moorai.acme.internal"));
        assert_eq!(from_sources(None, None, &json!({ "serverUrl": "https://moorai.acme.internal:8443/" }), p).console.as_deref(), Some("https://moorai.acme.internal:8443"));
        assert_eq!(from_sources(Some("REPLACE_WITH_SERVER_URL".into()), None, &json!({ "serverUrl": "https://moorai.acme.internal" }), p).console.as_deref(), Some("https://moorai.acme.internal"), "an unusable managed value falls through");
        assert_eq!(from_sources(None, None, &json!({ "serverUrl": "http://plain.example" }), p).console, None, "plain http is not a console");
        assert_eq!(from_sources(None, None, &Value::Null, p), Admin::default());
    }

    #[test]
    fn updates_are_off_only_when_an_admin_source_says_so() {
        let p = "/etc/moorai/config.json";
        assert!(from_sources(None, Some(true), &Value::Null, p).updates_off.unwrap().contains(MANAGED_DISABLE_UPDATES_KEY));
        assert!(from_sources(None, None, &json!({ "updates": "off" }), p).updates_off.unwrap().contains(p));
        assert!(from_sources(None, None, &json!({ "updates": false }), p).updates_off.is_some());
        assert!(from_sources(None, Some(true), &json!({ "updates": "on" }), p).updates_off.is_some(), "a managed true beats the file");
        assert_eq!(from_sources(None, Some(false), &json!({ "updates": "on" }), p).updates_off, None);
        assert_eq!(from_sources(None, None, &json!({ "updates": true }), p).updates_off, None);
    }

    #[cfg(unix)]
    #[test]
    fn a_machine_file_the_user_owns_is_ignored() {
        let dir = scratch("own");
        let f = format!("{dir}/config.json");
        std::fs::write(&f, r#"{"updates":"off","serverUrl":"https://updates.evil.test"}"#).unwrap();
        assert_eq!(read_admin_owned(&f), None, "a user-owned file is the agent's to write");
        assert_eq!(read_admin_owned(&format!("{dir}/missing.json")), None);
        // a file root owns and nobody else may write is read (macOS and Linux both ship /etc/hosts that way)
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata("/etc/hosts").unwrap();
        if md.uid() == 0 && md.mode() & 0o022 == 0 { assert!(read_admin_owned("/etc/hosts").is_some()); }
    }

    #[test]
    fn a_managed_plist_is_read_for_both_keys() {
        if !cfg!(target_os = "macos") { return; }
        let on = plist_doc("<key>DisableUpdates</key><true/><key>ServerURL</key><string>https://moorai.acme.internal</string>");
        assert_eq!(plist_bool(on.as_bytes(), MANAGED_DISABLE_UPDATES_KEY), Some(true));
        assert_eq!(plist_raw(on.as_bytes(), MANAGED_SERVER_KEY).as_deref(), Some("https://moorai.acme.internal"));
        let off = plist_doc("<key>DisableUpdates</key><false/>");
        assert_eq!(plist_bool(off.as_bytes(), MANAGED_DISABLE_UPDATES_KEY), Some(false));
        assert_eq!(plist_raw(off.as_bytes(), MANAGED_SERVER_KEY), None);
        assert_eq!(plist_bool(b"not a plist", MANAGED_DISABLE_UPDATES_KEY), None);
    }

    #[test]
    fn the_per_user_managed_path_is_built_only_from_a_single_path_component() {
        let machine = std::path::PathBuf::from(format!("{MANAGED_ROOT}/{MANAGED_DOMAIN}.plist"));
        assert_eq!(managed_paths(Some("itay.glick")), vec![std::path::PathBuf::from(format!("{MANAGED_ROOT}/itay.glick/{MANAGED_DOMAIN}.plist")), machine.clone()]);
        for bad in ["..", "../../tmp/x", "a/b", "/tmp", "a\\b", "x\0y", "", "a..b"] {
            assert_eq!(managed_paths(Some(bad)), vec![machine.clone()], "{bad:?} must not name a per-user path");
        }
        assert_eq!(managed_paths(None), vec![machine]);
    }

    #[cfg(unix)]
    #[test]
    fn the_user_name_comes_from_the_user_database_not_the_environment() {
        let _g = crate::console_binding::TEST_HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let id = std::process::Command::new("/usr/bin/id").arg("-un").output().unwrap();
        let expected = String::from_utf8_lossy(&id.stdout).trim().to_string();
        let saved: Vec<(&str, Option<String>)> = ["USER", "LOGNAME", "HOME"].iter().map(|k| (*k, std::env::var(k).ok())).collect();
        for (k, _) in &saved { std::env::set_var(k, "../../tmp/evil"); }
        let got = os_username();
        for (k, v) in &saved { match v { Some(v) => std::env::set_var(k, v), None => std::env::remove_var(k) } }
        assert_eq!(got.as_deref(), Some(expected.as_str()));
    }

    // read_owned_under, exercised without root: `owner` stands in for root, so a scratch tree owned by the
    // test's uid plays the part of /Library/Managed Preferences. Production passes 0.
    #[cfg(unix)]
    fn me() -> u32 { unsafe { libc::getuid() } }
    #[cfg(unix)]
    fn mode(p: &str, m: u32) { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap(); }

    #[cfg(unix)]
    #[test]
    fn a_trusted_file_under_its_root_is_read() {
        let base = scratch("ok");
        let root = format!("{base}/root");
        std::fs::create_dir_all(format!("{root}/u")).unwrap();
        mode(&base, 0o755); mode(&root, 0o755); mode(&format!("{root}/u"), 0o755);
        let f = format!("{root}/u/{MANAGED_DOMAIN}.plist");
        std::fs::write(&f, "x").unwrap();
        mode(&f, 0o644);
        assert_eq!(read_owned_under(std::path::Path::new(&f), std::path::Path::new(&root), me()).as_deref(), Some(&b"x"[..]));
    }

    // The production checks (owner 0) accept a profile MDM really installed, when this machine has one.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_real_mdm_installed_managed_plist_passes_the_production_checks() {
        let Ok(rd) = std::fs::read_dir(MANAGED_ROOT) else { eprintln!("skipped: no {MANAGED_ROOT}"); return };
        let Some(real) = rd.filter_map(|e| e.ok()).map(|e| e.path()).find(|p| p.extension().is_some_and(|x| x == "plist") && p.is_file()) else { eprintln!("skipped: no managed plist installed"); return };
        assert!(read_owned_under(&real, std::path::Path::new(MANAGED_ROOT), 0).is_some(), "{} was refused", real.display());
    }

    #[cfg(unix)]
    #[test]
    fn a_file_the_user_owns_is_not_root_owned() {
        let base = scratch("userowned");
        let f = format!("{base}/{MANAGED_DOMAIN}.plist");
        std::fs::write(&f, "x").unwrap();
        assert_eq!(read_owned_under(std::path::Path::new(&f), std::path::Path::new(&base), 0), None, "owner 0: a file this uid made is not an administrator's");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_file_is_refused_even_to_a_root_owned_target() {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata("/etc/hosts").unwrap();
        if md.uid() != 0 || md.mode() & 0o022 != 0 { eprintln!("skipped: /etc/hosts is not root-only"); return; }
        let base = scratch("symlink");
        mode(&base, 0o755);
        let f = format!("{base}/{MANAGED_DOMAIN}.plist");
        std::os::unix::fs::symlink("/etc/hosts", &f).unwrap();
        assert_eq!(read_owned_under(std::path::Path::new(&f), std::path::Path::new(&base), me()), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_resolves_outside_its_root_is_refused() {
        let base = scratch("escape");
        let (root, out) = (format!("{base}/root"), format!("{base}/outside"));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        for d in [&base, &root, &out] { mode(d, 0o755); }
        let f = format!("{out}/{MANAGED_DOMAIN}.plist");
        std::fs::write(&f, "x").unwrap();
        mode(&f, 0o644);
        let dotdot = format!("{root}/../outside/{MANAGED_DOMAIN}.plist");
        assert_eq!(read_owned_under(std::path::Path::new(&dotdot), std::path::Path::new(&root), me()), None, "..");
        std::os::unix::fs::symlink(&out, format!("{root}/u")).unwrap();
        let via_link = format!("{root}/u/{MANAGED_DOMAIN}.plist");
        assert_eq!(read_owned_under(std::path::Path::new(&via_link), std::path::Path::new(&root), me()), None, "a symlinked directory");
    }

    #[cfg(unix)]
    #[test]
    fn a_writable_file_or_directory_is_refused() {
        let base = scratch("writable");
        let root = format!("{base}/root");
        std::fs::create_dir_all(&root).unwrap();
        mode(&base, 0o755); mode(&root, 0o755);
        let f = format!("{root}/{MANAGED_DOMAIN}.plist");
        std::fs::write(&f, "x").unwrap();
        let read = || read_owned_under(std::path::Path::new(&f), std::path::Path::new(&root), me());
        mode(&f, 0o644);
        assert!(read().is_some());
        mode(&f, 0o664);
        assert_eq!(read(), None, "group-writable file");
        mode(&f, 0o646);
        assert_eq!(read(), None, "world-writable file");
        mode(&f, 0o644);
        mode(&root, 0o777);
        assert_eq!(read(), None, "world-writable directory: the file can be replaced");
        mode(&root, 0o755);
        mode(&base, 0o775);
        assert_eq!(read(), None, "group-writable ancestor");
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let base = scratch("fifo");
        mode(&base, 0o755);
        let f = format!("{base}/{MANAGED_DOMAIN}.plist");
        let c = std::ffi::CString::new(f.clone()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        assert_eq!(read_owned_under(std::path::Path::new(&f), std::path::Path::new(&base), me()), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_per_user_managed_plist_wins_and_the_machine_one_fills_in() {
        if !cfg!(target_os = "macos") { return; }
        let base = scratch("both");
        let root = format!("{base}/root");
        std::fs::create_dir_all(format!("{root}/u")).unwrap();
        for d in [&base, &root, &format!("{root}/u")] { mode(d, 0o755); }
        let (user, machine) = (format!("{root}/u/{MANAGED_DOMAIN}.plist"), format!("{root}/{MANAGED_DOMAIN}.plist"));
        std::fs::write(&user, plist_doc("<key>ServerURL</key><string>https://moorai.acme.internal</string>")).unwrap();
        std::fs::write(&machine, plist_doc("<key>ServerURL</key><string>https://moorai.other.internal</string><key>DisableUpdates</key><true/>")).unwrap();
        mode(&user, 0o644); mode(&machine, 0o644);
        let paths = [std::path::PathBuf::from(&user), std::path::PathBuf::from(&machine)];
        assert_eq!(managed_from(&paths, std::path::Path::new(&root), me()), (Some("https://moorai.acme.internal".into()), Some(true)));
        assert_eq!(managed_from(&paths, std::path::Path::new(&root), 0), (None, None), "owner 0: user-owned plists are ignored");
    }

    fn plist_doc(v: &str) -> String {
        format!(r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>{v}</dict></plist>"#)
    }

    // USER and LOGNAME are set by whoever launched the app, and the agent can launch it. A name with
    // "../" in it walked the managed-preference path out of /Library/Managed Preferences into a
    // directory the agent writes, and its plist was read as an administrator's.
    #[test]
    fn a_user_name_from_the_environment_cannot_walk_the_managed_path_out_of_managed_preferences() {
        if !cfg!(target_os = "macos") || !std::path::Path::new("/Library/Managed Preferences").is_dir() { eprintln!("skipped: no /Library/Managed Preferences"); return; }
        let _g = crate::console_binding::TEST_HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = scratch("traverse");
        std::fs::write(format!("{dir}/{MANAGED_DOMAIN}.plist"), plist_doc("<key>ServerURL</key><string>https://collector.evil.test</string><key>DisableUpdates</key><true/>")).unwrap();
        let evil = format!("../..{dir}");
        let saved: Vec<(&str, Option<String>)> = ["USER", "LOGNAME"].iter().map(|k| (*k, std::env::var(k).ok())).collect();
        for (k, _) in &saved { std::env::set_var(k, &evil); }
        let got = admin();
        for (k, v) in &saved { match v { Some(v) => std::env::set_var(k, v), None => std::env::remove_var(k) } }
        assert_eq!(got.console, None, "a plist the agent planted in {dir} provisioned the console");
        assert_eq!(got.updates_off, None, "a plist the agent planted in {dir} turned updates off");
    }

    // Captures in the shape test/windows-acl.test.mjs pins (real Windows 11 output, DESKTOP-JOL2MB8).
    const P: &str = "C:\\ProgramData\\MoorAI\\config.json";
    fn acl(lines: &[&str]) -> String {
        let pad = " ".repeat(P.len() + 1);
        let mut s = format!("{P} {}\r\n", lines[0]);
        for l in &lines[1..] { s.push_str(&format!("{pad}{l}\r\n")); }
        s.push_str("Successfully processed 1 files; Failed processing 0 files\r\n");
        s
    }

    #[test]
    fn icacls_admin_only_is_trusted_and_anything_user_writable_is_not() {
        assert!(!icacls_permissive(&acl(&["NT AUTHORITY\\SYSTEM:(I)(F)", "BUILTIN\\Administrators:(I)(F)", "BUILTIN\\Users:(I)(RX)"]), P));
        assert!(icacls_permissive(&acl(&["DESKTOP-JOL2MB8\\itay:(I)(F)", "NT AUTHORITY\\SYSTEM:(I)(F)", "BUILTIN\\Administrators:(I)(F)", "BUILTIN\\Users:(I)(RX)"]), P), "the ProgramData CREATOR OWNER case");
        for (who, right) in [("BUILTIN\\Users", "F"), ("BUILTIN\\Users", "M"), ("BUILTIN\\Users", "W"), ("Everyone", "F"), ("NT AUTHORITY\\Authenticated Users", "M"), ("NT AUTHORITY\\INTERACTIVE", "W")] {
            let line = format!("{who}:({right})");
            assert!(icacls_permissive(&acl(&[&line, "NT AUTHORITY\\SYSTEM:(I)(F)", "BUILTIN\\Administrators:(I)(F)"]), P), "{line}");
        }
        assert!(icacls_permissive(&acl(&["BUILTIN\\Users:(I)(RX,W)", "NT AUTHORITY\\SYSTEM:(I)(F)"]), P), "a specific write right in a list");
        assert!(icacls_permissive(&acl(&["BUILTIN\\Users:(WDAC)", "NT AUTHORITY\\SYSTEM:(I)(F)"]), P), "WRITE_DAC is write");
        assert!(!icacls_permissive(&acl(&["CREATOR OWNER:(OI)(CI)(IO)(F)", "NT AUTHORITY\\SYSTEM:(I)(F)", "BUILTIN\\Administrators:(I)(F)"]), P), "inherit-only ACEs govern children");
        assert!(icacls_permissive("", P), "no entries: not established, so not trusted");
        assert!(icacls_permissive("Successfully processed 0 files; Failed processing 1 files\r\n", P));
    }
}
