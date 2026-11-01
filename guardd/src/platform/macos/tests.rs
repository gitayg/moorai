use super::Platform;
use crate::observe::{ProcInfo, ProcessSource};
use crate::platform::SystemInfo;
use crate::quarantine::{PidRef, QuarantineBackend};
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Test oracle for the run state, read straight from the kernel (not through the code under test).
fn pbi_status(pid: u32) -> Option<u32> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let n = unsafe { libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDTBSDINFO, 0, &mut info as *mut _ as *mut libc::c_void, size) };
    (n == size).then_some(info.pbi_status)
}

fn wait_status(pid: u32, want_stopped: bool) -> Option<u32> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let s = pbi_status(pid);
        if (s == Some(libc::SSTOP)) == want_stopped || Instant::now() > deadline {
            return s;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_sleep() -> Reap {
    Reap(Command::new("/bin/sleep").arg("30").spawn().expect("spawn sleep"))
}

fn get_live(p: &Platform, pid: u32) -> ProcInfo {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(i) = p.get(pid).expect("get") {
            if i.image != std::env::current_exe().unwrap().canonicalize().unwrap().to_string_lossy() {
                return i;
            }
        }
        assert!(Instant::now() < deadline, "child {pid} never became readable");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn sh(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd).args(args).output().expect("run");
    assert!(out.status.success(), "{cmd} failed");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn list_contains_self() {
    let p = Platform::new();
    let me = std::process::id();
    let all = p.list().expect("list");
    let e = all.iter().find(|i| i.pid == me).expect("own pid in list");
    let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
    assert_eq!(e.image, exe.to_string_lossy());
    assert_eq!(e.uid, unsafe { libc::geteuid() });
    assert_eq!(e.ppid, unsafe { libc::getppid() } as u32);
    let now = now_ms();
    assert!(e.start_ms <= now && now - e.start_ms < 3600 * 1000, "start_ms {} now {}", e.start_ms, now);
    assert!(all.len() > 10, "only {} processes listed", all.len());
}

#[test]
fn get_matches_list_and_absent_is_none() {
    let p = Platform::new();
    let me = std::process::id();
    let listed = p.list().unwrap().into_iter().find(|i| i.pid == me).unwrap();
    assert_eq!(p.get(me).unwrap(), Some(listed));
    assert_eq!(p.get(999_999).unwrap(), None);
    assert_eq!(p.get(u32::MAX).unwrap(), None);
}

#[test]
fn script_is_argv1() {
    let dir = std::env::temp_dir().join(format!("guardd-macos-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("agent-script.sh");
    std::fs::write(&script, "sleep 30\nexit 0\n").unwrap();
    let script = script.canonicalize().unwrap().to_string_lossy().into_owned();
    let child = Reap(Command::new("/bin/sh").arg(&script).spawn().unwrap());
    let p = Platform::new();
    let pid = child.0.id();
    let deadline = Instant::now() + Duration::from_secs(2);
    let got = loop {
        let s = p.get(pid).unwrap().and_then(|i| i.script);
        if s.as_deref() == Some(script.as_str()) || Instant::now() > deadline {
            break s;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(got.as_deref(), Some(script.as_str()));
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn suspend_then_resume() {
    let child = spawn_sleep();
    let pid = child.0.id();
    let p = Platform::new();
    let info = get_live(&p, pid);
    assert_eq!(info.image, "/bin/sleep");
    p.suspend(std::slice::from_ref(&info)).expect("suspend");
    // No polling here: suspend must only return once the stop is confirmed.
    assert_eq!(pbi_status(pid), Some(libc::SSTOP));
    p.suspend(std::slice::from_ref(&info)).expect("suspend is idempotent");
    p.resume(&[PidRef::from(&info)]).expect("resume");
    let s = wait_status(pid, false);
    assert!(s.is_some() && s != Some(libc::SSTOP), "still stopped after resume: {s:?}");
}

#[test]
fn wrong_start_time_is_not_signalled() {
    let child = spawn_sleep();
    let pid = child.0.id();
    let p = Platform::new();
    let info = get_live(&p, pid);
    let stale = ProcInfo { start_ms: info.start_ms - 1, ..info.clone() };
    p.suspend(std::slice::from_ref(&stale)).expect("a reused pid counts as gone");
    std::thread::sleep(Duration::from_millis(50));
    assert_ne!(pbi_status(pid), Some(libc::SSTOP), "suspend signalled a pid whose start time differs");

    p.suspend(std::slice::from_ref(&info)).expect("suspend");
    assert_eq!(pbi_status(pid), Some(libc::SSTOP));
    p.resume(&[PidRef { pid, start_ms: info.start_ms + 1 }]).expect("a reused pid counts as gone");
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(pbi_status(pid), Some(libc::SSTOP), "resume continued a pid whose start time differs");
    p.resume(&[PidRef::from(&info)]).expect("resume");
    assert_ne!(wait_status(pid, false), Some(libc::SSTOP));
}

#[test]
fn exited_process_counts_as_done() {
    let mut child = Command::new("/usr/bin/true").spawn().unwrap();
    let p = Platform::new();
    let pid = child.id();
    let info = ProcInfo { pid, ppid: std::process::id(), uid: 0, start_ms: now_ms(), image: "/usr/bin/true".into(), script: None };
    child.wait().unwrap();
    p.suspend(std::slice::from_ref(&info)).expect("exited counts as done");
    p.resume(&[PidRef::from(&info)]).expect("exited is skipped");
}

#[test]
fn boot_and_clocks() {
    let p = Platform::new();
    let a = p.boot_id().unwrap();
    assert!(!a.is_empty());
    assert_eq!(a, p.boot_id().unwrap());
    let awake = p.awake_sec().unwrap();
    let up = p.uptime_sec().unwrap();
    // now - kern.boottime runs on the adjusted wall clock while CLOCK_UPTIME_RAW runs on the raw timebase;
    // measured on this Mac with no sleep since boot: uptime_raw=30960 monotonic_raw=30960
    // now-boottime=30950.662, so awake can exceed uptime by a few seconds. Bound the drift instead.
    assert!(awake > 0 && awake <= up + 60, "awake {awake} uptime {up}");
    let sysctl = sh("/usr/sbin/sysctl", &["-n", "kern.bootsessionuuid"]);
    assert_eq!(a, sysctl.trim());
}

#[test]
fn machine_id_is_ioplatformuuid() {
    let out = sh("/usr/sbin/ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]);
    let line = out.lines().find(|l| l.contains("\"IOPlatformUUID\"")).expect("IOPlatformUUID line");
    let want = line.rsplit('"').nth(1).unwrap();
    assert_eq!(want.len(), 36);
    assert_eq!(Platform::new().machine_id().unwrap(), want);
}

#[test]
fn hostname_matches_bin_hostname() {
    assert_eq!(Platform::new().hostname(), sh("/bin/hostname", &[]).trim_end_matches('\n'));
}

/// A process that accepts SIGSTOP but never reaches SSTOP: suspend must report it, not return Ok.
struct NeverStops;
impl super::quarantine::Ops for NeverStops {
    fn state(&self, _pid: u32) -> std::io::Result<Option<(u64, u32)>> {
        Ok(Some((1000, 2)))
    }
    fn kill(&self, _pid: u32, _sig: libc::c_int) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn suspend_fails_when_stop_is_not_confirmed() {
    let info = ProcInfo { pid: 4242, ppid: 1, uid: 501, start_ms: 1000, image: "/bin/x".into(), script: None };
    let r = super::quarantine::suspend_with(&NeverStops, std::slice::from_ref(&info));
    assert!(matches!(r, Err(crate::quarantine::BackendError::Os(ref m)) if m.contains("4242")), "{r:?}");
}

#[test]
fn procargs2_layout() {
    let mut b = 3i32.to_ne_bytes().to_vec();
    b.extend_from_slice(b"/bin/bash\0\0\0\0sh\0/tmp/s.sh\0x\0PATH=/bin\0");
    assert_eq!(super::sys::parse_argv1(&b).as_deref(), Some("/tmp/s.sh"));
    let mut one = 1i32.to_ne_bytes().to_vec();
    one.extend_from_slice(b"/bin/sleep\0\0sleep\0HOME=/x\0");
    assert_eq!(super::sys::parse_argv1(&one), None);
    assert_eq!(super::sys::parse_argv1(&[1, 0]), None);
}
