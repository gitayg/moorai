//! IPC transport (contract §3.1, §3.6). Unix sockets (macOS + Linux) live here and are owned by the
//! core; the Windows named pipe lives in crate::platform::windows::pipe and is owned by the Windows
//! platform agent. Both hand the server loop a `Conn` plus the kernel-reported `PeerCred`.

#[cfg(unix)]
pub mod unix;

use std::io::{Read, Write};

/// Who is on the other end, from the kernel: LOCAL_PEERCRED + LOCAL_PEERPID (macOS), SO_PEERCRED
/// (Linux), GetNamedPipeClientProcessId + the client's process token (Windows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCred {
    pub pid: u32,
    /// Unix uid; on Windows a stable per-SID number assigned by the platform module.
    pub uid: u32,
    /// Windows only: the caller token's user SID string ("S-1-5-21-...").
    pub sid: Option<String>,
    /// uid 0 (Unix) or SYSTEM / elevated Administrators token (Windows).
    pub admin: bool,
}

pub trait Conn: Read + Write + Send {
    fn peer(&self) -> &PeerCred;
    fn set_timeouts(&mut self, read_ms: u64, write_ms: u64) -> std::io::Result<()>;
}

pub trait Listener: Send {
    /// Blocks for the next connection; a connection whose peer cannot be read is dropped here and
    /// never reaches the server loop.
    fn accept(&self) -> std::io::Result<Box<dyn Conn>>;

    /// Wait at most `ms` for a connection (None on timeout), so the server loop can notice shutdown.
    /// The default blocks like `accept`; the Unix listener implements a real timeout.
    fn accept_timeout(&self, _ms: u64) -> std::io::Result<Option<Box<dyn Conn>>> {
        self.accept().map(Some)
    }
}

/// An in-memory connection for tests: a fixed peer and a scripted byte stream in, captured bytes out.
#[cfg(any(test, feature = "test-injection"))]
pub struct MemConn {
    pub peer: PeerCred,
    pub input: std::io::Cursor<Vec<u8>>,
    pub output: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

#[cfg(any(test, feature = "test-injection"))]
impl Read for MemConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}

#[cfg(any(test, feature = "test-injection"))]
impl Write for MemConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(any(test, feature = "test-injection"))]
impl Conn for MemConn {
    fn peer(&self) -> &PeerCred {
        &self.peer
    }
    fn set_timeouts(&mut self, _r: u64, _w: u64) -> std::io::Result<()> {
        Ok(())
    }
}

/// Bind the endpoint for `paths` on this OS (socket in run_dir mode 0666 inside a root-owned 0755
/// directory; or the pipe with FILE_FLAG_FIRST_PIPE_INSTANCE and the contract DACL).
pub fn bind(paths: &crate::state::Paths) -> std::io::Result<Box<dyn Listener>> {
    #[cfg(unix)]
    {
        unix::bind(paths)
    }
    #[cfg(windows)]
    {
        crate::platform::windows::pipe::bind(paths)
    }
}
