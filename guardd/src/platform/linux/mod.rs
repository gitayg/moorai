//! linux platform mechanics. Owned by the linux platform/packaging agent (contract §12).
//! Process source: /proc/<pid>/{stat,status,exe,cmdline}.

pub mod quarantine;

use crate::observe::{ProcInfo, ProcessSource};
use crate::platform::SystemInfo;

pub struct Platform {
    _private: (),
}

impl Platform {
    pub fn new() -> Self {
        Platform { _private: () }
    }
}

impl Default for Platform {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessSource for Platform {
    fn list(&self) -> std::io::Result<Vec<ProcInfo>> {
        todo!("/proc/<pid>/{{stat,status,exe,cmdline}}")
    }

    fn get(&self, _pid: u32) -> std::io::Result<Option<ProcInfo>> {
        todo!("/proc/<pid>/{{stat,status,exe,cmdline}}")
    }
}

impl SystemInfo for Platform {
    fn boot_id(&self) -> std::io::Result<String> {
        todo!("/proc/sys/kernel/random/boot_id")
    }

    fn awake_sec(&self) -> std::io::Result<u64> {
        todo!("clock_gettime(CLOCK_MONOTONIC)")
    }

    fn uptime_sec(&self) -> std::io::Result<u64> {
        todo!("clock_gettime(CLOCK_BOOTTIME)")
    }

    fn machine_id(&self) -> std::io::Result<String> {
        todo!("/etc/machine-id")
    }

    fn hostname(&self) -> String {
        crate::platform::gethostname()
    }

    fn login_name(&self, uid: u32) -> Option<String> {
        crate::platform::passwd_name(uid)
    }
}

#[cfg(test)]
mod tests {
    use crate::platform::SystemInfo;

    #[test]
    fn hostname_is_gethostname_and_does_not_panic() {
        // helper::peer_actor calls hostname() for every actor-scoped policy request; it must not panic.
        let h = super::Platform::new().hostname();
        let want = std::process::Command::new("uname").arg("-n").output().expect("uname -n");
        assert_eq!(h, String::from_utf8_lossy(&want.stdout).trim_end_matches('\n'));
        assert!(!h.is_empty());
    }
}
