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
        todo!("gethostname / GetComputerNameExW(ComputerNameDnsHostname), same value the hook sends as device")
    }
}
