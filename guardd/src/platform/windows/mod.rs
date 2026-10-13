//! windows platform mechanics. Owned by the windows platform/packaging agent (contract §12).
//! Process source: CreateToolhelp32Snapshot + QueryFullProcessImageNameW + GetProcessTimes; parent link valid only if parent creation < child creation.

pub mod quarantine;
pub mod pipe;

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
        todo!("CreateToolhelp32Snapshot + QueryFullProcessImageNameW + GetProcessTimes; parent link valid only if parent creation < child creation")
    }

    fn get(&self, _pid: u32) -> std::io::Result<Option<ProcInfo>> {
        todo!("CreateToolhelp32Snapshot + QueryFullProcessImageNameW + GetProcessTimes; parent link valid only if parent creation < child creation")
    }
}

impl SystemInfo for Platform {
    fn boot_id(&self) -> std::io::Result<String> {
        todo!("GUID derived from the boot time (GetTickCount64 vs system time, rounded) - contract §6.4")
    }

    fn awake_sec(&self) -> std::io::Result<u64> {
        todo!("QueryUnbiasedInterruptTime")
    }

    fn uptime_sec(&self) -> std::io::Result<u64> {
        todo!("GetTickCount64")
    }

    fn machine_id(&self) -> std::io::Result<String> {
        todo!("HKLM\\SOFTWARE\\Microsoft\\Cryptography MachineGuid")
    }

    fn hostname(&self) -> String {
        todo!("gethostname / GetComputerNameExW(ComputerNameDnsHostname), same value the hook sends as device")
    }
}

/// <ProgramData> from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList "ProgramData",
/// expanded against HKLM SystemDrive; never %ProgramData% (same rule as admin_config.rs windows_dirs).
pub fn program_data_from_hklm() -> String {
    todo!("contract §4.3")
}
