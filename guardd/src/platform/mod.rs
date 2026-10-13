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
}
