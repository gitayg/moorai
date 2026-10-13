//! Named-pipe transport (contract §3.1, §3.6). Owned by the Windows platform agent.
//! Server: CreateNamedPipeW(r"\\.\pipe\MoorAI.Hook", PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
//! | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, ...) with the DACL
//! D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU) (no FILE_CREATE_PIPE_INSTANCE for AU).
//! Peer: GetNamedPipeClientProcessId -> OpenProcess -> OpenProcessToken -> TokenUser SID, TokenElevation.

use crate::transport::Listener;

pub fn bind(_paths: &crate::state::Paths) -> std::io::Result<Box<dyn Listener>> {
    todo!("contract §3.1 Windows")
}
