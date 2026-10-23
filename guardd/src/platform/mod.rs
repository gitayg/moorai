//! Per-OS mechanics behind cfg (contract §12 ownership: each subdirectory belongs to that OS's
//! platform/packaging agent). Every OS module exposes the same items:
//!   `Platform` implementing observe::ProcessSource + quarantine::QuarantineBackend + SystemInfo.

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::Platform;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::Platform;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::{program_data_from_hklm, Platform};

/// Boot and clock facts the beat carries (contract §6.4).
pub trait SystemInfo {
    fn boot_id(&self) -> std::io::Result<String>;
    /// Seconds awake since boot, excluding sleep.
    fn awake_sec(&self) -> std::io::Result<u64>;
    /// Seconds since boot, including sleep.
    fn uptime_sec(&self) -> std::io::Result<u64>;
    /// Raw OS machine id fed to keys::device_id_of_machine_id (never sent as is).
    fn machine_id(&self) -> std::io::Result<String>;
    fn hostname(&self) -> String;
    /// The login name of `uid` (the IPC peer's kernel-reported uid), as the peer's hook reads its own:
    /// Node's os.userInfo().username is libuv uv_os_get_passwd = getpwuid_r(geteuid()).pw_name. None when
    /// the uid has no passwd entry; the helper then derives no actor for that peer (policy::derive_actor).
    fn login_name(&self, uid: u32) -> Option<String>;
}

/// getpwuid_r(uid).pw_name, the lookup behind Node's os.userInfo().username. None when there is no entry
/// or the name is not UTF-8.
#[cfg(unix)]
pub fn passwd_name(uid: u32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    loop {
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: pw, buf and out outlive the call; buf.len() is the buffer's real size.
        let rc = unsafe { libc::getpwuid_r(uid as libc::uid_t, &mut pw, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), &mut out) };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || out.is_null() || pw.pw_name.is_null() {
            return None;
        }
        // SAFETY: pw_name points into buf, NUL-terminated by getpwuid_r.
        let name = unsafe { std::ffi::CStr::from_ptr(pw.pw_name) };
        return name.to_str().ok().filter(|n| !n.is_empty()).map(str::to_string);
    }
}

#[cfg(all(test, unix))]
mod tests {
    #[test]
    fn passwd_name_resolves_real_uids_and_nothing_else() {
        assert_eq!(super::passwd_name(0).as_deref(), Some("root"));
        assert!(super::passwd_name(crate::state::current_uid()).is_some_and(|n| !n.is_empty()));
        assert_eq!(super::passwd_name(3_999_999_999), None, "no passwd entry");
    }
}
