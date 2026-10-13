//! macos platform mechanics. Owned by the macos platform/packaging agent (contract §12).
//! Process source: sysctl KERN_PROC_ALL + proc_pidpath + KERN_PROCARGS2.

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
        todo!("sysctl KERN_PROC_ALL + proc_pidpath + KERN_PROCARGS2")
    }

    fn get(&self, _pid: u32) -> std::io::Result<Option<ProcInfo>> {
        todo!("sysctl KERN_PROC_ALL + proc_pidpath + KERN_PROCARGS2")
    }
}

impl SystemInfo for Platform {
    fn boot_id(&self) -> std::io::Result<String> {
        todo!("kern.bootsessionuuid")
    }

    fn awake_sec(&self) -> std::io::Result<u64> {
        todo!("clock_gettime(CLOCK_UPTIME_RAW)")
    }

    fn uptime_sec(&self) -> std::io::Result<u64> {
        todo!("now - kern.boottime")
    }

    fn machine_id(&self) -> std::io::Result<String> {
        todo!("IOPlatformUUID (IOKit) or sysctl kern.uuid")
    }

    fn hostname(&self) -> String {
        todo!("gethostname / GetComputerNameExW(ComputerNameDnsHostname), same value the hook sends as device")
    }
}
