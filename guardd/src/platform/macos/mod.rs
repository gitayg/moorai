//! macos platform mechanics. Owned by the macos platform/packaging agent (contract §12).
//! Process source: proc_listallpids + proc_pidinfo(PROC_PIDTBSDINFO) + proc_pidpath + KERN_PROCARGS2.

pub mod quarantine;
mod sys;
#[cfg(test)]
mod tests;

use crate::observe::{ProcInfo, ProcessSource};
use crate::platform::SystemInfo;
use std::io;

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
    fn list(&self) -> io::Result<Vec<ProcInfo>> {
        // A process that vanishes or cannot be read between enumeration and lookup is skipped.
        Ok(sys::all_pids()?.into_iter().filter_map(|pid| self.get(pid).ok().flatten()).collect())
    }

    fn get(&self, pid: u32) -> io::Result<Option<ProcInfo>> {
        let Some(info) = sys::bsdinfo(pid)? else { return Ok(None) };
        let Some(image) = sys::pidpath(pid) else { return Ok(None) };
        Ok(Some(ProcInfo {
            pid,
            ppid: info.pbi_ppid,
            // Effective uid: the IPC peer's uid comes from LOCAL_PEERCRED (xucred cr_uid, the effective
            // uid), and the quarantine target rule compares the two, so both must be the same kind.
            uid: info.pbi_uid,
            start_ms: sys::start_ms(&info),
            image,
            script: sys::argv1(pid),
        }))
    }
}

impl SystemInfo for Platform {
    fn boot_id(&self) -> io::Result<String> {
        sys::sysctl_string(c"kern.bootsessionuuid")
    }

    fn awake_sec(&self) -> io::Result<u64> {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        if unsafe { libc::clock_gettime(libc::CLOCK_UPTIME_RAW, &mut ts) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ts.tv_sec as u64)
    }

    fn uptime_sec(&self) -> io::Result<u64> {
        let boot = sys::boottime()?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(io::Error::other)?;
        Ok(now.as_secs().saturating_sub(boot.tv_sec as u64))
    }

    fn machine_id(&self) -> io::Result<String> {
        // gethostuuid(2) returns the IOPlatformUUID; formatted as ioreg prints it (upper-case 8-4-4-4-12).
        let mut id = [0u8; 16];
        let timeout = libc::timespec { tv_sec: 5, tv_nsec: 0 };
        if unsafe { libc::gethostuuid(id.as_mut_ptr(), &timeout) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let h: String = id.iter().map(|b| format!("{b:02X}")).collect();
        Ok(format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]))
    }

    fn hostname(&self) -> String {
        // gethostname(2), the call behind Node's os.hostname() (libuv uv_os_gethostname).
        let mut buf = [0u8; 256];
        if unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) } != 0 {
            return String::new();
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }
}
