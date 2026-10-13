//! macos quarantine mechanics (contract §8.4). Owned by the macos platform agent; the decision and
//! target rule are core (crate::quarantine).

use super::Platform;
use crate::ipc::NetBlockState;
use crate::observe::ProcInfo;
use crate::quarantine::{BackendError, Entry, PidRef, QuarantineBackend};

impl QuarantineBackend for Platform {
    fn suspend(&self, _tree: &[ProcInfo]) -> Result<(), BackendError> {
        todo!("kill(pid, SIGSTOP) top-down, confirm via proc_pidinfo pbi_status == SSTOP")
    }

    fn resume(&self, _pids: &[PidRef]) -> Result<(), BackendError> {
        todo!("kill(pid, SIGCONT) when start time matches")
    }

    fn net_block(&self, _entry: &Entry) -> Result<NetBlockState, BackendError> {
        todo!("pf anchor moorai/quarantine blocking by uid is too coarse; Network Extension content filter keyed on audit token (decision pending, contract §13)")
    }

    fn net_unblock(&self, _entry: &Entry) -> Result<(), BackendError> {
        todo!("remove the anchor rules / filter entry")
    }
}
