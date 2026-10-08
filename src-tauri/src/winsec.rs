// Native Windows security-posture inventory via the windows-rs stack — WMI (SecurityCenter2 for
// registered AV + firewall products, and BitLocker volume encryption) plus the registry (firewall
// per-profile state, reboot-pending flags, last-update time, installed hotfixes). Compiled only on
// Windows. Every query is self-contained and degrades to a null/empty value on any error, so a
// missing WMI class, a locked-down namespace, or a non-elevated context never fails the whole call.
use serde::Deserialize;
use winreg::enums::*;
use winreg::RegKey;
use wmi::{COMLibrary, WMIConnection};

// --- WMI row shapes ---

// SecurityCenter2 exposes AV/firewall products with camelCase property names.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AntiVirusProduct {
    display_name: String,
    product_state: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FirewallProduct {
    display_name: String,
    product_state: u32,
}

// Win32_* classes use PascalCase property names. The `wmi` crate derives the queried class from the
// struct name, so the container `rename` must be the exact WMI class name.
#[derive(Deserialize)]
#[serde(rename = "Win32_EncryptableVolume", rename_all = "PascalCase")]
struct EncryptableVolume {
    drive_letter: Option<String>,
    protection_status: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_QuickFixEngineering", rename_all = "PascalCase")]
struct QuickFix {
    #[allow(dead_code)]
    hot_fix_id: Option<String>,
    installed_on: Option<String>,
}

// Decode a SecurityCenter2 productState DWORD → (real-time protection enabled, definitions current).
// Byte layout: [provider][scanner][outdated]; scanner 0x10/0x11 = on, outdated 0x00 = up to date.
fn av_flags(state: u32) -> (bool, bool) {
    let scanner = (state >> 8) & 0xff;
    let outdated = state & 0xff;
    (scanner == 0x10 || scanner == 0x11, outdated == 0x00)
}

fn query_av() -> Vec<serde_json::Value> {
    let mut out = vec![];
    if let Ok(com) = COMLibrary::new() {
        if let Ok(con) = WMIConnection::with_namespace_path("ROOT\\SecurityCenter2", com) {
            if let Ok(list) = con.query::<AntiVirusProduct>() {
                for p in list {
                    let (enabled, up_to_date) = av_flags(p.product_state);
                    out.push(serde_json::json!({
                        "name": p.display_name,
                        "enabled": enabled,
                        "upToDate": up_to_date,
                        "state": format!("0x{:06x}", p.product_state)
                    }));
                }
            }
        }
    }
    out
}

// Third-party firewall products registered with Security Center (the built-in Defender firewall is
// reported separately via the registry profile state below).
fn firewall_products() -> Vec<serde_json::Value> {
    let mut out = vec![];
    if let Ok(com) = COMLibrary::new() {
        if let Ok(con) = WMIConnection::with_namespace_path("ROOT\\SecurityCenter2", com) {
            if let Ok(list) = con.query::<FirewallProduct>() {
                for p in list {
                    let (enabled, _) = av_flags(p.product_state);
                    out.push(serde_json::json!({ "name": p.display_name, "enabled": enabled }));
                }
            }
        }
    }
    out
}

// Windows Defender firewall enablement per profile, straight from the registry (no elevation, no scan).
fn firewall_state() -> serde_json::Value {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let read = |profile: &str| -> Option<bool> {
        let path = format!(
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}"
        );
        hklm.open_subkey(path)
            .ok()
            .and_then(|k| k.get_value::<u32, _>("EnableFirewall").ok())
            .map(|v| v == 1)
    };
    serde_json::json!({
        "domain": read("DomainProfile"),
        "private": read("StandardProfile"),
        "public": read("PublicProfile"),
        "products": firewall_products()
    })
}

// BitLocker protection status per volume (0 = off, 1 = on). The namespace requires elevation to
// query; without it we report status "unavailable" rather than failing.
fn bitlocker() -> serde_json::Value {
    let com = match COMLibrary::new() {
        Ok(c) => c,
        Err(_) => return serde_json::json!({ "status": "unknown" }),
    };
    match WMIConnection::with_namespace_path("ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption", com) {
        Ok(con) => match con.query::<EncryptableVolume>() {
            Ok(vols) => {
                let arr: Vec<serde_json::Value> = vols
                    .into_iter()
                    .map(|v| {
                        serde_json::json!({
                            "drive": v.drive_letter.unwrap_or_default(),
                            "protected": v.protection_status.map(|s| s == 1)
                        })
                    })
                    .collect();
                serde_json::json!({ "volumes": arr })
            }
            Err(_) => serde_json::json!({ "status": "unavailable (needs admin)" }),
        },
        Err(_) => serde_json::json!({ "status": "unknown" }),
    }
}

// The security-posture bundle reported to the MoorAI server (metadata only, no content).
pub fn security_posture() -> serde_json::Value {
    serde_json::json!({
        "antivirus": query_av(),
        "firewall": firewall_state(),
        "bitlocker": bitlocker()
    })
}

// Installed hotfixes (count + a recent id) via WMI QFE — cheap posture signal, no online scan.
fn query_qfe() -> (usize, String) {
    if let Ok(com) = COMLibrary::new() {
        if let Ok(con) = WMIConnection::with_namespace_path("ROOT\\CIMV2", com) {
            if let Ok(list) = con.query::<QuickFix>() {
                let count = list.len();
                let latest = list
                    .iter()
                    .filter_map(|q| q.installed_on.clone())
                    .last()
                    .unwrap_or_default();
                return (count, latest);
            }
        }
    }
    (0, String::new())
}

// Patch posture without an online Windows Update scan: reboot-pending flags + last-successful-update
// time from the registry, plus installed-hotfix stats. `upToDate` stays null — enumerating *pending*
// updates needs the online COM UpdateSearcher, which we deliberately avoid here (slow, can hang).
pub fn patch_status() -> serde_json::Value {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key_exists = |p: &str| hklm.open_subkey(p).is_ok();
    let reboot_pending = key_exists(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    ) || key_exists(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
    ) || hklm
        .open_subkey(r"SYSTEM\CurrentControlSet\Control\Session Manager")
        .ok()
        .and_then(|k| k.get_raw_value("PendingFileRenameOperations").ok())
        .is_some();

    let last_update = hklm
        .open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install")
        .ok()
        .and_then(|k| k.get_value::<String, _>("LastSuccessTime").ok())
        .unwrap_or_default();

    let (hotfix_count, latest_hotfix) = query_qfe();

    serde_json::json!({
        "upToDate": serde_json::Value::Null,
        "count": 0,
        "titles": [],
        "rebootPending": reboot_pending,
        "lastUpdate": last_update,
        "hotfixCount": hotfix_count,
        "latestHotfix": latest_hotfix
    })
}

// --- Opt-in host isolation: Job Objects ---
//
// Places the spawned agent process in a Windows Job Object configured with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. When the host drops the job handle (app exit, or the next
// session replacing it), every process in the job is terminated — so a killed/closed session can
// never leave an orphaned agent (or its child tool processes) running unsupervised. This is the
// first, safest isolation increment; tighter AppContainer filesystem/network limits layer on top of
// the same job later. All functions degrade to a no-op on any error so isolation failure never
// blocks launching the agent.

/// Create a Job Object with kill-on-close semantics. Returns the raw handle as `isize`, or `None`.
/// Far above any legitimate build (parallel compilers, test runners, npm) but still a hard ceiling
/// on a runaway or malicious fork bomb, which spawns thousands.
const AGENT_ACTIVE_PROCESS_LIMIT: u32 = 256;

pub fn create_agent_job() -> Option<isize> {
    create_job(false)
}

/// The job for an agent launched through wxc-exec (mxc_launch.rs). UI limits of every job in a
/// nesting chain apply together, so this job must not re-impose the two limits the MXC policy relaxes
/// for PowerShell — UILIMIT_HANDLES and UILIMIT_GLOBALATOMS (microsoft/mxc
/// tests/playground/playground-limitations.md, "PowerShell in BaseContainer": DLL_INIT_FAILED under
/// 0x03FF). Clipboard and the rest stay denied here as well as in the container's own `ui` policy.
pub fn create_mxc_job() -> Option<isize> {
    create_job(true)
}

fn create_job(relax_desktop_handles: bool) -> Option<isize> {
    use windows::core::PCWSTR;
    use windows::Win32::System::JobObjects::{
        CreateJobObjectW, SetInformationJobObject, JobObjectBasicUIRestrictions,
        JobObjectExtendedLimitInformation, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
        JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
        JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
        JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    };
    unsafe {
        let job = CreateJobObjectW(None, PCWSTR::null()).ok()?;

        // Note the flags deliberately NOT set: JOB_OBJECT_LIMIT_BREAKAWAY_OK and
        // SILENT_BREAKAWAY. Without them a child calling CreateProcess with
        // CREATE_BREAKAWAY_FROM_JOB fails, so the agent cannot spawn a helper outside the job to
        // survive session close or escape these limits.
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit = AGENT_ACTIVE_PROCESS_LIMIT;
        let _ = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const core::ffi::c_void,
            core::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );

        // Clipboard denial is the load-bearing one: the user's clipboard routinely holds passwords
        // and tokens, and an agent that can read it has a silent exfil channel that never touches
        // the filesystem or a prompt we scan. The rest deny the job a route to the wider desktop
        // session. Safe for a console agent, which uses pipes rather than USER handles.
        let mut flags = JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_EXITWINDOWS
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
        if !relax_desktop_handles {
            flags = flags | JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_GLOBALATOMS;
        }
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS { UIRestrictionsClass: flags };
        let _ = SetInformationJobObject(
            job,
            JobObjectBasicUIRestrictions,
            &ui as *const _ as *const core::ffi::c_void,
            core::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        );

        Some(job.0 as isize)
    }
}

/// Assign a running process (by PID) to the job. Returns whether assignment succeeded.
pub fn assign_process(job: isize, pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::JobObjects::AssignProcessToJobObject;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};
    unsafe {
        let hproc = match OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let ok =
            AssignProcessToJobObject(HANDLE(job as *mut core::ffi::c_void), hproc).is_ok();
        let _ = CloseHandle(hproc);
        ok
    }
}

/// Terminate every process in the job now, keeping the handle open (job_active_processes still works).
pub fn terminate_job(job: isize) {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::TerminateJobObject;
    unsafe {
        let _ = TerminateJobObject(HANDLE(job as *mut core::ffi::c_void), 1);
    }
}

/// How many processes are still in the job; None if the job cannot be queried.
pub fn job_active_processes(job: isize) -> Option<u32> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{
        JobObjectBasicAccountingInformation, QueryInformationJobObject,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    };
    let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    unsafe {
        QueryInformationJobObject(
            Some(HANDLE(job as *mut core::ffi::c_void)),
            JobObjectBasicAccountingInformation,
            &mut info as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            None,
        )
        .ok()?;
    }
    Some(info.ActiveProcesses)
}

/// Close a job handle. With kill-on-close set, this terminates every process still in the job.
pub fn close_job(job: isize) {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    unsafe {
        let _ = CloseHandle(HANDLE(job as *mut core::ffi::c_void));
    }
}
