//! Admin inputs (contract §4.1, §10): the machine config and the root-only secret. The helper reads
//! both ONLY from the admin locations of crate::state::Paths, through the ownership checks
//! admin_config.rs implements (`read_owned_under`, ported here; Windows: HKLM + icacls, platform agent).
//! No user-scope file, no environment variable and no command-line flag can supply or override any of
//! these values.

use serde::{Deserialize, Deserializer, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HelperMode {
    /// The hook must reach the helper; when it cannot, it enforces with the posture ratchet and
    /// stamps `helperUnreachable` / `helperOutdated` (contract §10.3).
    Required,
    /// Use the helper when it answers, else behave exactly as before the helper existed. The default
    /// when the field is absent and for any unknown value (§10.1).
    #[default]
    Optional,
    /// Never connect (diagnostics / rollback).
    Off,
}

impl<'de> Deserialize<'de> for HelperMode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        Ok(match v.as_str() {
            Some("required") => HelperMode::Required,
            Some("off") => HelperMode::Off,
            _ => HelperMode::Optional,
        })
    }
}

/// /etc/moorai/config.json or <ProgramData>\MoorAI\config.json (root/admin-owned, world-readable).
/// Existing fields (serverUrl, tenant) keep their phase 1 meaning; the helper fields are new (§10.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MachineConfig {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub server_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tenant: Option<String>,
    #[serde(default)]
    pub helper: HelperMode,
    /// Semver; a helper whose hello.helperVersion is lower counts as outdated for the hook.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub helper_min_version: Option<String>,
}

/// /etc/moorai/secret.json (root 0600 on macOS and Linux) or <ProgramData>\MoorAI\secret.json
/// (SYSTEM + Administrators only). Delivered by MDM (§4.1, §13.1 decision 4).
#[derive(Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub install_token: Option<String>,
    /// One-time MDM enrolment secret for /api/devices/register; the helper removes it from the file
    /// after a successful bound registration.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub enroll_secret: Option<String>,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret { .. }")
    }
}

/// The resolved binding the helper uses for every console call.
#[derive(Debug, Clone, PartialEq)]
pub struct Binding {
    /// Normalised origin (console_binding::normalize_origin semantics).
    pub origin: String,
    pub tenant: String,
    pub secret: Secret,
}

#[derive(Debug)]
pub enum ConfigError {
    Missing(&'static str),
    NotAdminOwned(String),
    Parse(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Missing(w) => write!(f, "missing {w}"),
            ConfigError::NotAdminOwned(w) => write!(f, "not administrator-owned: {w}"),
            ConfigError::Parse(w) => write!(f, "unparseable: {w}"),
        }
    }
}

/// Port of src-tauri console_binding::normalize_origin: `scheme://host[:port]`, lower-case host, no
/// credentials; https only, except plain http for localhost / 127.0.0.1 / [::1]. Any path is dropped.
pub fn normalize_origin(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    let (scheme, rest) = t.split_once("://").ok_or_else(|| format!("\"{t}\" is not a URL"))?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return Err("the console URL carries credentials".into());
    }
    let (host, port) = if let Some(after) = authority.strip_prefix('[') {
        let (h, tail) = after.split_once(']').ok_or("the console URL has a bad IPv6 host")?;
        (format!("[{}]", h.to_ascii_lowercase()), tail.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_ascii_lowercase(), Some(p)),
            None => (authority.to_ascii_lowercase(), None),
        }
    };
    let host_ok = !host.is_empty()
        && (host.starts_with('[') && host[1..host.len() - 1].chars().all(|c| c.is_ascii_hexdigit() || c == ':')
            || host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'));
    if !host_ok {
        return Err("the console URL has no usable host".into());
    }
    let port = match port {
        None => None,
        Some(p) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => {
            let n: u32 = p.parse().map_err(|_| "bad port")?;
            if n == 0 || n > 65535 {
                return Err("bad port".into());
            }
            let default = (scheme == "https" && n == 443) || (scheme == "http" && n == 80);
            (!default).then_some(n)
        }
        Some(_) => return Err("bad port".into()),
    };
    let local = matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]");
    match scheme.as_str() {
        "https" => {}
        "http" if local => {}
        "http" => return Err(format!("http://{host} is not https (plain http is allowed only for localhost)")),
        s => return Err(format!("{s}: is not an https URL")),
    }
    Ok(match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
}

/// The file's bytes when only root (or `owner`: production passes 0, an injected test tree its own
/// uid) can have written it, else None. Port of admin_config.rs `read_owned_under`: the directory,
/// canonicalised, lies under `root`; it and every directory above it is owned by root/`owner` and not
/// group- or world-writable; the file is opened O_NOFOLLOW | O_NONBLOCK and the open descriptor must be
/// a regular file owned by root/`owner`, not group- or world-writable.
#[cfg(unix)]
pub fn read_owned_under(path: &Path, root: &Path, owner: u32) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let trusted = |md: &std::fs::Metadata| (md.uid() == 0 || md.uid() == owner) && md.mode() & 0o022 == 0;
    let root = root.canonicalize().ok()?;
    let name = path.file_name()?;
    let dir = path.parent()?.canonicalize().ok()?;
    if !dir.starts_with(&root) {
        return None;
    }
    // Every directory from the file's up to the trust root (`/` for the system paths, so the whole
    // chain; the injected root in a test tree).
    for d in dir.ancestors() {
        let md = std::fs::symlink_metadata(d).ok()?;
        if !md.is_dir() || !trusted(&md) {
            return None;
        }
        if d == root {
            break;
        }
    }
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(dir.join(name)).ok()?;
    let md = f.metadata().ok()?;
    if !md.is_file() || !trusted(&md) {
        return None;
    }
    let mut bytes = Vec::new();
    f.take(1 << 20).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

#[cfg(windows)]
pub fn read_owned_under(path: &Path, _root: &Path, _owner: u32) -> Option<Vec<u8>> {
    // The HKLM ProgramData + icacls check is the Windows platform agent's (contract §4.1). Until it
    // lands, nothing is trusted on Windows: the safe direction.
    let _ = path;
    None
}

/// The secret file additionally must not be readable by group or other (§4.1: 0600).
#[cfg(unix)]
fn secret_mode_ok(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).map(|m| m.mode() & 0o077 == 0).unwrap_or(false)
}

#[cfg(windows)]
fn secret_mode_ok(_path: &Path) -> bool {
    true
}

pub fn load_machine_config(paths: &crate::state::Paths) -> Result<MachineConfig, ConfigError> {
    let bytes = read_owned_under(&paths.machine_config, &paths.trust_root, paths.admin_owner())
        .ok_or_else(|| ConfigError::NotAdminOwned(paths.machine_config.display().to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| ConfigError::Parse(format!("machine config: {e}")))
}

pub fn load_secret(paths: &crate::state::Paths) -> Result<Secret, ConfigError> {
    if !paths.secret.exists() {
        return Err(ConfigError::Missing("secret.json"));
    }
    let bytes = read_owned_under(&paths.secret, &paths.trust_root, paths.admin_owner())
        .ok_or_else(|| ConfigError::NotAdminOwned(paths.secret.display().to_string()))?;
    if !secret_mode_ok(&paths.secret) {
        return Err(ConfigError::NotAdminOwned(format!("{} is readable by group or other", paths.secret.display())));
    }
    serde_json::from_slice(&bytes).map_err(|_| ConfigError::Parse("secret.json".into()))
}

/// Resolve the binding: origin and tenant from the machine config, the install token from the secret.
pub fn load_binding(paths: &crate::state::Paths) -> Result<Binding, ConfigError> {
    let mc = load_machine_config(paths)?;
    let server = mc.server_url.as_deref().filter(|s| !s.trim().is_empty()).ok_or(ConfigError::Missing("serverUrl"))?;
    let origin = normalize_origin(server).map_err(ConfigError::Parse)?;
    let tenant = mc.tenant.filter(|t| !t.is_empty()).ok_or(ConfigError::Missing("tenant"))?;
    let secret = load_secret(paths)?;
    if secret.install_token.as_deref().unwrap_or("").is_empty() {
        return Err(ConfigError::Missing("installToken"));
    }
    Ok(Binding { origin, tenant, secret })
}

/// After a successful bound registration (§4.1): rewrite secret.json without `enrollSecret`, same
/// owner (the helper is root, so its write is root-owned) and mode 0600.
pub fn remove_enroll_secret(paths: &crate::state::Paths) -> Result<(), ConfigError> {
    let mut s = load_secret(paths)?;
    if s.enroll_secret.is_none() {
        return Ok(());
    }
    s.enroll_secret = None;
    let bytes = serde_json::to_vec(&s).map_err(|e| ConfigError::Parse(e.to_string()))?;
    crate::state::write_atomic(&paths.secret, &bytes).map_err(|e| ConfigError::NotAdminOwned(e.to_string()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::state::Paths;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn origins_normalise_like_console_binding() {
        assert_eq!(normalize_origin(" HTTPS://Console.Example.com/x/y ").unwrap(), "https://console.example.com");
        assert_eq!(normalize_origin("https://c.example:8443").unwrap(), "https://c.example:8443");
        assert_eq!(normalize_origin("https://c.example:443/").unwrap(), "https://c.example");
        assert_eq!(normalize_origin("http://127.0.0.1:5000").unwrap(), "http://127.0.0.1:5000");
        assert_eq!(normalize_origin("http://[::1]:5000").unwrap(), "http://[::1]:5000");
        for bad in ["http://evil.example", "ftp://x", "https://u:p@x.example", "https://", "x.example", "https://a b", "https://x:99999"] {
            assert!(normalize_origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn unknown_helper_mode_is_optional() {
        let m: MachineConfig = serde_json::from_str(r#"{"helper":"maybe"}"#).unwrap();
        assert_eq!(m.helper, HelperMode::Optional);
        let m: MachineConfig = serde_json::from_str(r#"{"helper":"off","helperMinVersion":"0.2.0"}"#).unwrap();
        assert_eq!((m.helper, m.helper_min_version.as_deref()), (HelperMode::Off, Some("0.2.0")));
    }

    fn tree() -> Paths {
        let root = crate::state::test_root("cfg");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        for d in [&root, &root.join("etc")] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Paths::under(&root)
    }

    fn put(p: &Path, s: &str, mode: u32) {
        std::fs::write(p, s).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn binding_comes_from_admin_owned_files_only() {
        let p = tree();
        put(&p.machine_config, r#"{"serverUrl":"https://Console.example","tenant":"acme"}"#, 0o644);
        put(&p.secret, r#"{"installToken":"tok","enrollSecret":"mes_00"}"#, 0o600);
        let b = load_binding(&p).unwrap();
        assert_eq!((b.origin.as_str(), b.tenant.as_str()), ("https://console.example", "acme"));
        assert_eq!(b.secret.install_token.as_deref(), Some("tok"));
        assert!(!format!("{b:?}").contains("tok"), "the secret never prints");

        std::fs::set_permissions(&p.secret, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(load_binding(&p), Err(ConfigError::NotAdminOwned(_))), "a secret others can read");
        std::fs::set_permissions(&p.secret, std::fs::Permissions::from_mode(0o600)).unwrap();

        std::fs::set_permissions(&p.machine_config, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(load_binding(&p), Err(ConfigError::NotAdminOwned(_))), "a world-writable config");
        std::fs::set_permissions(&p.machine_config, std::fs::Permissions::from_mode(0o644)).unwrap();

        std::fs::set_permissions(p.machine_config.parent().unwrap(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(load_binding(&p).is_err(), "a writable admin dir");
        std::fs::set_permissions(p.machine_config.parent().unwrap(), std::fs::Permissions::from_mode(0o755)).unwrap();

        let real = p.machine_config.with_file_name("real.json");
        std::fs::rename(&p.machine_config, &real).unwrap();
        std::os::unix::fs::symlink(&real, &p.machine_config).unwrap();
        assert!(load_binding(&p).is_err(), "a symlinked config");
    }

    #[test]
    fn plain_http_to_a_remote_console_is_refused() {
        let p = tree();
        put(&p.machine_config, r#"{"serverUrl":"http://console.example","tenant":"acme"}"#, 0o644);
        put(&p.secret, r#"{"installToken":"tok"}"#, 0o600);
        assert!(matches!(load_binding(&p), Err(ConfigError::Parse(_))));
    }

    #[test]
    fn the_enrol_secret_is_removed_and_the_mode_kept() {
        use std::os::unix::fs::MetadataExt;
        let p = tree();
        put(&p.secret, r#"{"installToken":"tok","enrollSecret":"mes_00"}"#, 0o600);
        remove_enroll_secret(&p).unwrap();
        let s = load_secret(&p).unwrap();
        assert_eq!((s.install_token.as_deref(), s.enroll_secret.as_deref()), (Some("tok"), None));
        assert_eq!(std::fs::metadata(&p.secret).unwrap().mode() & 0o777, 0o600);
    }
}
