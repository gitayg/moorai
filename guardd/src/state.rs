//! Helper state layout (contract §4). Every path is a compile-time constant per OS. The only other
//! way to build a `Paths` is `Paths::under`, which exists only in test builds and with the
//! `test-injection` feature, and which `Helper::new` refuses when the process runs as root/SYSTEM.
//!
//! Directory and file checks (§4.2): the state dir is created 0700 and the run dir 0755; an existing
//! one must be a real directory (no symlink) owned by the helper's uid and not group- or
//! world-writable, and every ancestor up to the trust root must be owned by root (or, in an injected
//! test tree, by the test uid) and not writable by anyone else. State files are written by temp file +
//! fsync + rename + fsync(dir), mode 0600, and read back only when they are regular files owned by the
//! helper's uid with no group/other access.

use serde::{de::DeserializeOwned, Serialize};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// Admin machine config (read-only to the helper).
    pub machine_config: PathBuf,
    /// Admin root-only secret (install token / enrol secret).
    pub secret: PathBuf,
    /// Admin policy trust anchor (optional, phase 1 file).
    pub policy_pub: PathBuf,
    /// Admin policy high-water mark (optional, phase 1 file).
    pub policy_hwm_admin: PathBuf,
    /// Helper-private state directory (0700 / SYSTEM only).
    pub state_dir: PathBuf,
    /// World-readable, admin-writable directory holding the socket (Unix) and device.pub.
    pub run_dir: PathBuf,
    /// IPC endpoint: socket path on Unix, pipe name on Windows.
    pub endpoint: String,
    /// Whether these are the compiled-in system paths.
    pub system: bool,
    /// Ownership walks stop here: `/` for system paths, the injected root for a test tree.
    pub trust_root: PathBuf,
}

/// File names inside state_dir (contract §4.2). All 0600 (Unix) / inherited protected ACL (Windows),
/// written by write-temp + fsync + rename.
pub mod files {
    pub const DEVICE_KEY: &str = "device.key";
    /// A rotation in progress: the new seed, kept until the console accepted it (§5.2 `rotated`).
    pub const DEVICE_KEY_NEXT: &str = "device.key.next";
    pub const REGISTRATION: &str = "registration.json";
    pub const BINDING_SNAPSHOT: &str = "binding.json";
    pub const POLICY_CACHE: &str = "policy-cache.json";
    pub const POLICY_LKG: &str = "policy-lkg.json";
    pub const POLICY_PIN: &str = "policy-pin.json";
    pub const POLICY_HWM: &str = "policy-hwm.json";
    pub const POSTURE: &str = "posture";
    pub const BACKOFF: &str = "backoff.json";
    pub const ALERTS_DIR: &str = "alerts";
    pub const CHAIN: &str = "chain.json";
    pub const BEAT: &str = "beat.json";
    pub const COUNTERS: &str = "counters.json";
    pub const QUARANTINE: &str = "quarantine.json";
    pub const COMMANDS: &str = "commands.json";
    /// In run_dir, world-readable: the device public key the hook verifies hello proofs against.
    pub const DEVICE_PUB: &str = "device.pub";
}

#[cfg(target_os = "macos")]
fn system_paths() -> Paths {
    Paths {
        machine_config: "/etc/moorai/config.json".into(),
        secret: "/etc/moorai/secret.json".into(),
        policy_pub: "/etc/moorai/policy.pub".into(),
        policy_hwm_admin: "/etc/moorai/policy-hwm.json".into(),
        state_dir: "/Library/Application Support/MoorAI/state".into(),
        run_dir: "/private/var/run/moorai".into(),
        endpoint: "/private/var/run/moorai/hook.sock".into(),
        system: true,
        trust_root: "/".into(),
    }
}

#[cfg(target_os = "linux")]
fn system_paths() -> Paths {
    Paths {
        machine_config: "/etc/moorai/config.json".into(),
        secret: "/etc/moorai/secret.json".into(),
        policy_pub: "/etc/moorai/policy.pub".into(),
        policy_hwm_admin: "/etc/moorai/policy-hwm.json".into(),
        state_dir: "/var/lib/moorai".into(),
        run_dir: "/run/moorai".into(),
        endpoint: "/run/moorai/hook.sock".into(),
        system: true,
        trust_root: "/".into(),
    }
}

/// Windows: <ProgramData> comes from HKLM ProfileList (admin_config.rs windows_dirs), never from
/// %ProgramData%. The pipe name is fixed.
#[cfg(windows)]
fn system_paths() -> Paths {
    let pd = crate::platform::program_data_from_hklm();
    let base = PathBuf::from(pd).join("MoorAI");
    Paths {
        machine_config: base.join("config.json"),
        secret: base.join("secret.json"),
        policy_pub: base.join("policy.pub"),
        policy_hwm_admin: base.join("policy-hwm.json"),
        state_dir: base.join("state"),
        run_dir: base.join("run"),
        endpoint: r"\\.\pipe\MoorAI.Hook".into(),
        system: true,
        trust_root: base,
    }
}

impl Paths {
    pub fn system() -> Paths {
        system_paths()
    }

    /// Test-only: every path under `root`. Never compiled into a packaging build.
    #[cfg(any(test, feature = "test-injection"))]
    pub fn under(root: &Path) -> Paths {
        let run = root.join("run");
        #[cfg(unix)]
        let endpoint = run.join("hook.sock").to_string_lossy().into_owned();
        #[cfg(windows)]
        let endpoint = format!(r"\\.\pipe\MoorAI.Hook.test.{}", std::process::id());
        Paths {
            machine_config: root.join("etc/config.json"),
            secret: root.join("etc/secret.json"),
            policy_pub: root.join("etc/policy.pub"),
            policy_hwm_admin: root.join("etc/policy-hwm.json"),
            state_dir: root.join("state"),
            run_dir: run,
            endpoint,
            system: false,
            trust_root: root.to_path_buf(),
        }
    }

    pub fn state_file(&self, name: &str) -> PathBuf {
        self.state_dir.join(name)
    }

    pub fn device_pub(&self) -> PathBuf {
        self.run_dir.join(files::DEVICE_PUB)
    }

    /// The uid that may own admin inputs and the trees above them besides root: root itself for system
    /// paths, the test process's uid for an injected tree.
    pub fn admin_owner(&self) -> u32 {
        if self.system {
            0
        } else {
            current_uid()
        }
    }
}

#[cfg(unix)]
pub fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(windows)]
pub fn current_uid() -> u32 {
    0
}

fn err(kind: io::ErrorKind, msg: String) -> io::Error {
    io::Error::new(kind, msg)
}

/// Whether a directory's metadata is acceptable as an ancestor of helper state: owned by root or
/// `owner`, not world-writable, and not group-writable unless the group is a system group (gid 0, or
/// macOS gid 1 `daemon`, which owns /private/var/run root:daemon 0775 on every Mac).
#[cfg(unix)]
pub fn trusted_dir_meta(md: &std::fs::Metadata, owner: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let system_group = md.gid() == 0 || (cfg!(target_os = "macos") && md.gid() == 1);
    (md.uid() == 0 || md.uid() == owner) && md.mode() & 0o002 == 0 && (md.mode() & 0o020 == 0 || system_group)
}

/// Walk `dir`'s ancestors (exclusive of `dir`) up to and including `trust_root`; each must be a real
/// directory satisfying `trusted_dir_meta`. `dir` must lie under `trust_root`.
#[cfg(unix)]
pub fn check_ancestors(dir: &Path, trust_root: &Path, owner: u32) -> io::Result<()> {
    if !dir.starts_with(trust_root) {
        return Err(err(io::ErrorKind::PermissionDenied, format!("{} is outside its trust root", dir.display())));
    }
    let mut cur = dir.parent();
    while let Some(d) = cur {
        let md = std::fs::symlink_metadata(d)?;
        if md.file_type().is_symlink() || !md.is_dir() || !trusted_dir_meta(&md, owner) {
            return Err(err(io::ErrorKind::PermissionDenied, format!("{} is not an administrator-only directory", d.display())));
        }
        if d == trust_root {
            break;
        }
        cur = d.parent();
    }
    Ok(())
}

/// Create `dir` with `mode` if missing, else verify it: a real directory owned by this uid, not
/// group- or world-writable; extra read bits are removed so the mode ends as `mode`.
#[cfg(unix)]
pub fn ensure_dir(dir: &Path, mode: u32, trust_root: &Path, owner: u32) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    check_ancestors(dir, trust_root, owner)?;
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(mode).create(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))?;
            fsync_dir(dir.parent().unwrap_or(Path::new("/")))?;
        }
        Err(e) => return Err(e),
        Ok(md) => {
            if md.file_type().is_symlink() || !md.is_dir() {
                return Err(err(io::ErrorKind::PermissionDenied, format!("{} is not a directory", dir.display())));
            }
            if md.uid() != current_uid() {
                return Err(err(io::ErrorKind::PermissionDenied, format!("{} is owned by uid {}", dir.display(), md.uid())));
            }
            if md.mode() & 0o022 != 0 {
                return Err(err(io::ErrorKind::PermissionDenied, format!("{} is group- or world-writable", dir.display())));
            }
            if md.mode() & 0o777 != mode {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))?;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn ensure_dir(dir: &Path, _mode: u32, _trust_root: &Path, _owner: u32) -> io::Result<()> {
    // The protected DACL is the Windows platform agent's (contract §4.2); core only creates the dir.
    std::fs::create_dir_all(dir)
}

/// fsync(2). Deliberately not `File::sync_all`, which on macOS is F_FULLFSYNC (a full drive-cache
/// flush, 10–30 ms each): four of those put `submit` over its budget. fsync(2) is what the contract
/// names; power-loss durability beyond it is out of scope (reported as a deviation).
#[cfg(unix)]
pub fn fsync(f: &std::fs::File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: fsync on an open descriptor we own.
    if unsafe { libc::fsync(f.as_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
pub fn fsync(f: &std::fs::File) -> io::Result<()> {
    f.sync_all()
}

#[cfg(unix)]
fn fsync_dir(dir: &Path) -> io::Result<()> {
    fsync(&std::fs::File::open(dir)?)
}

#[cfg(windows)]
fn fsync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Atomic write, mode 0600: temp file in the same dir, fsync file, rename, fsync dir.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic_mode(path, bytes, 0o600)
}

pub fn write_atomic_mode(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| err(io::ErrorKind::InvalidInput, "no parent dir".into()))?;
    let name = path.file_name().ok_or_else(|| err(io::ErrorKind::InvalidInput, "no file name".into()))?;
    let tmp = dir.join(format!(".{}.tmp-{}", name.to_string_lossy(), crate::clock::random_hex(6)));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    let _ = mode;
    let res = (|| {
        let mut f = opts.open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        f.write_all(bytes)?;
        fsync(&f)?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        fsync_dir(dir)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Read a helper-private file: None when absent; an error when it exists but is not a regular file
/// owned by this uid with no group/other access (O_NOFOLLOW: a symlink is refused).
pub fn read_private(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let md = f.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !md.is_file() || md.uid() != current_uid() || md.mode() & 0o077 != 0 {
            return Err(err(io::ErrorKind::PermissionDenied, format!("{} is not a private helper file", path.display())));
        }
    }
    #[cfg(windows)]
    if !md.is_file() {
        return Err(err(io::ErrorKind::PermissionDenied, format!("{} is not a file", path.display())));
    }
    let mut out = Vec::new();
    f.take(64 << 20).read_to_end(&mut out)?;
    Ok(Some(out))
}

/// A JSON state file: None when absent, an error when unreadable or unparseable (never silently
/// replaced: the callers decide).
pub fn load_json<T: DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    match read_private(path)? {
        None => Ok(None),
        Some(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| err(io::ErrorKind::InvalidData, format!("{}: {e}", path.display()))),
    }
}

pub fn save_json<T: Serialize>(path: &Path, v: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(v).map_err(|e| err(io::ErrorKind::InvalidData, e.to_string()))?;
    write_atomic(path, &bytes)
}

/// Test-only scratch root: `<temp>/mgt-<uid>/` (created 0700 by and for this uid,
/// refused if it is a symlink or someone else's), then a fresh 0755 subdirectory for one test. The
/// subdirectory is the injected trust root (`Paths::under`), so the production ownership walks stop
/// there and never depend on how /tmp is shared.
#[cfg(all(unix, any(test, feature = "test-injection")))]
pub fn test_root(tag: &str) -> PathBuf {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let parent = std::env::temp_dir().join(format!("mgt-{}", current_uid()));
    match std::fs::DirBuilder::new().mode(0o700).create(&parent) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => panic!("test root {}: {e}", parent.display()),
    }
    let md = std::fs::symlink_metadata(&parent).expect("test root");
    assert!(md.is_dir() && !md.file_type().is_symlink() && md.uid() == current_uid(), "{} is not this uid's directory", parent.display());
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).expect("chmod test root");
    // Short names: the injected socket path (<root>/run/hook.sock) must fit sun_path (104 on macOS).
    let short: String = tag.chars().filter(|c| c.is_ascii_alphanumeric()).take(6).collect();
    let d = parent.join(format!("{short}{}", crate::clock::random_hex(4)));
    std::fs::DirBuilder::new().mode(0o755).create(&d).expect("test dir");
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).expect("chmod test dir");
    d
}

/// Create (or verify) the state dir 0700 and the run dir 0755 with the ownership checks above.
pub fn prepare_dirs(paths: &Paths) -> io::Result<()> {
    let owner = paths.admin_owner();
    ensure_dir(&paths.state_dir, 0o700, &paths.trust_root, owner)?;
    ensure_dir(&paths.state_dir.join(files::ALERTS_DIR), 0o700, &paths.trust_root, owner)?;
    ensure_dir(&paths.run_dir, 0o755, &paths.trust_root, owner)?;
    Ok(())
}

/// Everything the helper holds in memory, persisted under state_dir. One instance behind the helper's
/// mutex; network I/O is never done while it is locked.
pub struct HelperState {
    pub paths: Paths,
    pub key: std::sync::Arc<crate::keys::DeviceKey>,
    pub device_id: String,
    /// Hostname as the hook reports `device`.
    pub device: String,
    pub binding: Option<crate::config::Binding>,
    /// Why there is no binding (content-free, for the log).
    pub binding_error: Option<String>,
    pub registration: Option<crate::console::Registration>,
    pub needs_register: bool,
    pub policy: crate::policy::PolicyStore,
    pub alerts: crate::alerts::AlertQueue,
    pub beat: crate::beat::BeatState,
    pub counters: crate::beat::Counters,
    pub observer: crate::observe::Observer,
    pub quarantines: crate::quarantine::Quarantines,
    pub commands: crate::push::CommandsState,
    pub kills: Vec<crate::push::KillEntry>,
    pub started_at_ms: u64,
    pub hook_version: Option<String>,
    pub app_version: Option<String>,
}

/// `state/binding.json`: the binding last used, for change detection only (§4.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BindingSnapshot {
    pub origin: String,
    pub tenant: String,
}

#[derive(Debug)]
pub enum OpenError {
    Io(io::Error),
    /// device.key exists but is unusable; never replaced silently (§4.2).
    Key(crate::keys::KeyError),
}

impl HelperState {
    /// Create/verify dirs and modes, load or create the device key, publish device.pub, resolve the
    /// binding and load every state file.
    pub fn open(paths: Paths, sys: &dyn crate::platform::SystemInfo, now_ms: u64) -> Result<HelperState, OpenError> {
        prepare_dirs(&paths).map_err(OpenError::Io)?;
        let key = crate::keys::DeviceKey::load_or_create(&paths.state_dir).map_err(OpenError::Key)?;
        crate::keys::write_device_pub(&paths.run_dir, &key).map_err(OpenError::Io)?;
        let device_id = crate::keys::device_id_of_machine_id(&sys.machine_id().map_err(OpenError::Io)?);
        let (binding, binding_error) = match crate::config::load_binding(&paths) {
            Ok(b) => (Some(b), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let tenant = binding.as_ref().map(|b| b.tenant.clone());
        let mut policy = crate::policy::PolicyStore::open(&paths, tenant.as_deref());
        let snap_path = paths.state_file(files::BINDING_SNAPSHOT);
        let previous: Option<BindingSnapshot> = load_json(&snap_path).unwrap_or(None);
        let mut registration: Option<crate::console::Registration> = load_json(&paths.state_file(files::REGISTRATION)).unwrap_or(None);
        if let Some(b) = &binding {
            let snap = BindingSnapshot { origin: b.origin.clone(), tenant: b.tenant.clone() };
            if previous.as_ref().is_some_and(|p| p.tenant != snap.tenant) {
                eprintln!("moorai-guardd: the administrator changed the tenant; dropping the old tenant's pin, mark and cached policy");
                policy.reset_for_tenant_change().map_err(OpenError::Io)?;
            }
            if previous.as_ref() != Some(&snap) {
                save_json(&snap_path, &snap).map_err(OpenError::Io)?;
            }
        }
        let tenant_s = tenant.clone().unwrap_or_default();
        let alerts = crate::alerts::AlertQueue::open(&paths.state_dir.join(files::ALERTS_DIR), &paths.state_file(files::CHAIN), &tenant_s).map_err(OpenError::Io)?;
        let beat = load_json(&paths.state_file(files::BEAT)).map_err(OpenError::Io)?.unwrap_or_default();
        let counters = load_json(&paths.state_file(files::COUNTERS)).map_err(OpenError::Io)?.unwrap_or_default();
        let quarantines = crate::quarantine::Quarantines::open(&paths.state_file(files::QUARANTINE)).map_err(OpenError::Io)?;
        let commands: crate::push::CommandsState = load_json(&paths.state_file(files::COMMANDS)).map_err(OpenError::Io)?.unwrap_or_default();
        let pending = crate::keys::pending_rotation(&paths.state_dir).map_err(OpenError::Key)?.is_some();
        if registration.as_ref().is_some_and(|r| binding.as_ref().is_some_and(|b| r.tenant != b.tenant && !r.tenant.is_empty())) {
            registration = None;
        }
        let needs_register = pending
            || match (&registration, &binding) {
                (Some(r), Some(b)) => r.key_id != key.key_id() || r.device_id != device_id || r.origin != b.origin,
                (None, Some(_)) => true,
                (_, None) => false,
            };
        Ok(HelperState {
            device: sys.hostname(),
            paths,
            key: std::sync::Arc::new(key),
            device_id,
            binding,
            binding_error,
            registration,
            needs_register,
            policy,
            alerts,
            beat,
            counters,
            observer: crate::observe::Observer::new(now_ms),
            quarantines,
            commands,
            kills: Vec::new(),
            started_at_ms: now_ms,
            hook_version: None,
            app_version: None,
        })
    }

    /// The last cmdSeq applied: the higher of commands.json and quarantine.json (§8.5).
    pub fn last_cmd_seq(&self) -> u64 {
        self.commands.last_cmd_seq.max(self.quarantines.file.last_cmd_seq)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    pub fn tmp_root(tag: &str) -> PathBuf {
        super::test_root(&format!("state-{tag}"))
    }

    #[test]
    fn dirs_are_created_with_the_contract_modes() {
        let root = tmp_root("modes");
        let p = Paths::under(&root);
        prepare_dirs(&p).unwrap();
        assert_eq!(std::fs::metadata(&p.state_dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(p.state_dir.join("alerts")).unwrap().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&p.run_dir).unwrap().mode() & 0o777, 0o755);
    }

    #[test]
    fn a_writable_or_symlinked_state_dir_is_refused() {
        let root = tmp_root("refuse");
        let p = Paths::under(&root);
        std::fs::create_dir(&p.state_dir).unwrap();
        std::fs::set_permissions(&p.state_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(prepare_dirs(&p).is_err(), "world-writable state dir");
        std::fs::remove_dir(&p.state_dir).unwrap();
        let elsewhere = tmp_root("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, &p.state_dir).unwrap();
        assert!(prepare_dirs(&p).is_err(), "symlinked state dir");
    }

    #[test]
    fn a_writable_ancestor_is_refused() {
        let root = tmp_root("anc");
        let p = Paths::under(&root);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(prepare_dirs(&p).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(prepare_dirs(&p).is_ok());
    }

    #[test]
    fn a_readable_state_dir_is_tightened_to_0700() {
        let root = tmp_root("tighten");
        let p = Paths::under(&root);
        std::fs::create_dir(&p.state_dir).unwrap();
        std::fs::set_permissions(&p.state_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        prepare_dirs(&p).unwrap();
        assert_eq!(std::fs::metadata(&p.state_dir).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn atomic_writes_are_0600_and_leave_no_temp_files() {
        let root = tmp_root("atomic");
        let f = root.join("x.json");
        write_atomic(&f, b"one").unwrap();
        write_atomic(&f, b"two").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"two");
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o777, 0o600);
        let names: Vec<_> = std::fs::read_dir(&root).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }

    #[test]
    fn private_reads_refuse_shared_or_symlinked_files() {
        let root = tmp_root("private");
        let f = root.join("s.json");
        write_atomic(&f, b"{}").unwrap();
        assert_eq!(read_private(&f).unwrap().as_deref(), Some(&b"{}"[..]));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&f).is_err(), "group/other readable");
        let l = root.join("l.json");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&f, &l).unwrap();
        assert!(read_private(&l).is_err(), "symlink");
        assert_eq!(read_private(&root.join("absent")).unwrap(), None);
    }
}
