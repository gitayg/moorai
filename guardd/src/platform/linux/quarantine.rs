//! linux quarantine mechanics (contract §8.4). Owned by the linux platform agent; the decision and
//! target rule are core (crate::quarantine).

use super::Platform;
use crate::ipc::NetBlockState;
use crate::observe::ProcInfo;
use crate::quarantine::{BackendError, Entry, PidRef, QuarantineBackend};

impl QuarantineBackend for Platform {
    fn suspend(&self, _tree: &[ProcInfo]) -> Result<(), BackendError> {
        todo!("cgroup v2 cgroup.freeze=1 when the target's cgroup holds only the tree, else kill(pid, SIGSTOP) top-down; confirm state T in /proc/<pid>/stat or cgroup.events frozen 1")
    }

    fn resume(&self, _pids: &[PidRef]) -> Result<(), BackendError> {
        todo!("cgroup.freeze=0 / kill(pid, SIGCONT) when start time matches")
    }

    fn net_block(&self, _entry: &Entry) -> Result<NetBlockState, BackendError> {
        todo!("nftables table inet moorai_quarantine, rule 'socket cgroupv2 level N <path> drop' per quarantined cgroup (needs a per-tree cgroup; else meta skuid is too coarse, contract §13)")
    }

    fn net_unblock(&self, _entry: &Entry) -> Result<(), BackendError> {
        todo!("delete the rule")
    }
}
