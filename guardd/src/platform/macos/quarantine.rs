//! macos quarantine mechanics (contract §8.4). Owned by the macos platform agent; the decision and
//! target rule are core (crate::quarantine).
//!
//! Residual race: macOS has no pidfd, so between the start-time check and kill(2) a pid could exit and
//! be reused. The window is one syscall wide; the start-time check closes everything wider.

use super::{sys, Platform};
use crate::ipc::NetBlockState;
use crate::observe::ProcInfo;
use crate::quarantine::{BackendError, Entry, PidRef, QuarantineBackend};
use std::io;
use std::time::{Duration, Instant};

/// How long suspend waits for every SIGSTOP to take effect.
const STOP_CONFIRM: Duration = Duration::from_millis(50);
/// <sys/proc.h> SZOMB (libc 0.2.186 exports SSTOP but not SZOMB).
const SZOMB: u32 = 5;

/// Kernel facts suspend/resume need, behind a seam so the confirmation loop is testable.
pub(super) trait Ops {
    /// (start_ms, pbi_status), None when the process is gone or unreadable.
    fn state(&self, pid: u32) -> io::Result<Option<(u64, u32)>>;
    fn kill(&self, pid: u32, sig: libc::c_int) -> io::Result<()>;
}

pub(super) struct Os;

impl Ops for Os {
    fn state(&self, pid: u32) -> io::Result<Option<(u64, u32)>> {
        Ok(sys::bsdinfo(pid)?.map(|i| (sys::start_ms(&i), i.pbi_status)))
    }

    fn kill(&self, pid: u32, sig: libc::c_int) -> io::Result<()> {
        let pid = libc::pid_t::try_from(pid).map_err(|_| io::Error::from_raw_os_error(libc::ESRCH))?;
        if unsafe { libc::kill(pid, sig) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn is_gone(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ESRCH)
}

/// Signal `sig` to every (pid, start_ms) that is still the same process; returns the pids signalled.
fn signal_matching(ops: &dyn Ops, refs: &[(u32, u64)], sig: libc::c_int, errs: &mut Vec<String>) -> Vec<(u32, u64)> {
    let mut sent = Vec::new();
    for &(pid, start) in refs {
        match ops.state(pid) {
            Ok(Some((s, _))) if s == start => match ops.kill(pid, sig) {
                Ok(()) => sent.push((pid, start)),
                Err(e) if is_gone(&e) => {}
                Err(e) => errs.push(format!("kill({pid}): {e}")),
            },
            Ok(_) => {}
            Err(e) => errs.push(format!("proc_pidinfo({pid}): {e}")),
        }
    }
    sent
}

pub(super) fn suspend_with(ops: &dyn Ops, tree: &[ProcInfo]) -> Result<(), BackendError> {
    let refs: Vec<(u32, u64)> = tree.iter().map(|p| (p.pid, p.start_ms)).collect();
    let mut errs = Vec::new();
    let mut pending = signal_matching(ops, &refs, libc::SIGSTOP, &mut errs);
    let deadline = Instant::now() + STOP_CONFIRM;
    loop {
        // Done: stopped (SSTOP), exited (gone or zombie), or the pid now belongs to another process.
        pending.retain(|&(pid, start)| match ops.state(pid) {
            Ok(Some((s, st))) => s == start && st != libc::SSTOP && st != SZOMB,
            Ok(None) => false,
            Err(_) => true,
        });
        if pending.is_empty() || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    errs.extend(pending.iter().map(|(pid, _)| format!("pid {pid} not stopped within {} ms", STOP_CONFIRM.as_millis())));
    if errs.is_empty() {
        Ok(())
    } else {
        Err(BackendError::Os(errs.join("; ")))
    }
}

pub(super) fn resume_with(ops: &dyn Ops, pids: &[PidRef]) -> Result<(), BackendError> {
    let refs: Vec<(u32, u64)> = pids.iter().map(|p| (p.pid, p.start_ms)).collect();
    let mut errs = Vec::new();
    signal_matching(ops, &refs, libc::SIGCONT, &mut errs);
    if errs.is_empty() {
        Ok(())
    } else {
        Err(BackendError::Os(errs.join("; ")))
    }
}

impl QuarantineBackend for Platform {
    fn suspend(&self, tree: &[ProcInfo]) -> Result<(), BackendError> {
        suspend_with(&Os, tree)
    }

    fn resume(&self, pids: &[PidRef]) -> Result<(), BackendError> {
        resume_with(&Os, pids)
    }

    fn net_block(&self, _entry: &Entry) -> Result<NetBlockState, BackendError> {
        // Contract §13.1 decision 8: the Network Extension content filter is not built and pf is not
        // used, so the processes stay suspended and the entry records networkBlock "unavailable".
        Ok(NetBlockState::Unsupported)
    }

    fn net_unblock(&self, _entry: &Entry) -> Result<(), BackendError> {
        Ok(())
    }
}
