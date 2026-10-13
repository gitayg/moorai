//! windows quarantine mechanics (contract §8.4). Owned by the windows platform agent; the decision and
//! target rule are core (crate::quarantine).

use super::Platform;
use crate::ipc::NetBlockState;
use crate::observe::ProcInfo;
use crate::quarantine::{BackendError, Entry, PidRef, QuarantineBackend};

impl QuarantineBackend for Platform {
    fn suspend(&self, _tree: &[ProcInfo]) -> Result<(), BackendError> {
        todo!("NtSuspendProcess per process top-down (or a job object with JOB_OBJECT freeze where supported); confirm all threads suspended")
    }

    fn resume(&self, _pids: &[PidRef]) -> Result<(), BackendError> {
        todo!("NtResumeProcess when creation time matches")
    }

    fn net_block(&self, _entry: &Entry) -> Result<NetBlockState, BackendError> {
        todo!("WFP filter at FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6 + RECV_ACCEPT, condition FWPM_CONDITION_ALE_APP_ID of each image (coarse: blocks every process of that image), MXC profile switched to deny-all where in use")
    }

    fn net_unblock(&self, _entry: &Entry) -> Result<(), BackendError> {
        todo!("delete the filters by their persisted ids")
    }
}
