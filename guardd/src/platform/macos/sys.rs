//! Thin libc wrappers for the macos platform layer. Every item used is in libc 0.2.186.

use std::ffi::CStr;
use std::io;

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// proc_pidinfo(PROC_PIDTBSDINFO). None when the process is gone (ESRCH) or not readable by us (EPERM).
pub fn bsdinfo(pid: u32) -> io::Result<Option<libc::proc_bsdinfo>> {
    let Ok(pid) = libc::c_int::try_from(pid) else { return Ok(None) };
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, &mut info as *mut _ as *mut libc::c_void, size) };
    if n == size {
        return Ok(Some(info));
    }
    match errno() {
        libc::ESRCH | libc::EPERM | 0 => Ok(None),
        e => Err(io::Error::from_raw_os_error(e)),
    }
}

pub fn start_ms(info: &libc::proc_bsdinfo) -> u64 {
    info.pbi_start_tvsec * 1000 + info.pbi_start_tvusec / 1000
}

/// proc_pidpath: the full executable path, None if unreadable.
pub fn pidpath(pid: u32) -> Option<String> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

/// Every pid on the system (proc_listallpids returns a count of pids, not bytes).
pub fn all_pids() -> io::Result<Vec<u32>> {
    let mut cap = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if cap < 0 {
        return Err(io::Error::last_os_error());
    }
    loop {
        cap += 64;
        let mut buf = vec![0 as libc::c_int; cap as usize];
        let bytes = (buf.len() * std::mem::size_of::<libc::c_int>()) as libc::c_int;
        let n = unsafe { libc::proc_listallpids(buf.as_mut_ptr() as *mut libc::c_void, bytes) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n < cap {
            buf.truncate(n as usize);
            return Ok(buf.into_iter().filter(|&p| p >= 0).map(|p| p as u32).collect());
        }
        cap *= 2;
    }
}

fn sysctl_raw(mib: &mut [libc::c_int], buf: &mut [u8]) -> io::Result<usize> {
    let mut len = buf.len();
    let rc = unsafe { libc::sysctl(mib.as_mut_ptr(), mib.len() as libc::c_uint, buf.as_mut_ptr() as *mut libc::c_void, &mut len, std::ptr::null_mut(), 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(len)
}

fn sysctl_name(name: &CStr) -> io::Result<Vec<u8>> {
    let mut len = 0usize;
    if unsafe { libc::sysctlbyname(name.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u8; len];
    if unsafe { libc::sysctlbyname(name.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, &mut len, std::ptr::null_mut(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(len);
    Ok(buf)
}

pub fn sysctl_string(name: &CStr) -> io::Result<String> {
    let buf = sysctl_name(name)?;
    let s = CStr::from_bytes_until_nul(&buf).map(|c| c.to_bytes()).unwrap_or(&buf);
    String::from_utf8(s.to_vec()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn boottime() -> io::Result<libc::timeval> {
    let buf = sysctl_name(c"kern.boottime")?;
    if buf.len() < std::mem::size_of::<libc::timeval>() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "kern.boottime too short"));
    }
    Ok(unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const libc::timeval) })
}

fn argmax() -> usize {
    let mut v: libc::c_int = 0;
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let mut len = std::mem::size_of::<libc::c_int>();
    let rc = unsafe { libc::sysctl(mib.as_mut_ptr(), 2, &mut v as *mut _ as *mut libc::c_void, &mut len, std::ptr::null_mut(), 0) };
    if rc == 0 && v > 0 {
        v as usize
    } else {
        1024 * 1024
    }
}

/// argv[1] from KERN_PROCARGS2: i32 argc, the exec path NUL-terminated, NUL padding, then argv strings.
/// None when unreadable (another user's process when unprivileged, a zombie, a vanished pid) or argc < 2.
pub fn argv1(pid: u32) -> Option<String> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let mut buf = vec![0u8; argmax()];
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let len = sysctl_raw(&mut mib, &mut buf).ok()?;
    parse_argv1(&buf[..len])
}

pub fn parse_argv1(buf: &[u8]) -> Option<String> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    if argc < 2 {
        return None;
    }
    let rest = &buf[4..];
    let exec_end = rest.iter().position(|&b| b == 0)?;
    let mut i = exec_end;
    while rest.get(i) == Some(&0) {
        i += 1;
    }
    let mut args = rest[i..].split(|&b| b == 0);
    args.next()?;
    let a1 = args.next()?;
    String::from_utf8(a1.to_vec()).ok()
}
