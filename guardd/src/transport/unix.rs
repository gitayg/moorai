//! Unix-socket transport for macOS and Linux (contract §3.1). On Linux under systemd the listening
//! socket is inherited from moorai-guardd.socket (LISTEN_FDS, fd 3) instead of being bound here;
//! that is the only environment variable the helper reads, and only to locate an fd systemd passed.

use super::{Conn, Listener, PeerCred};
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::io::FromRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

pub struct UnixListenerT {
    inner: UnixListener,
}

pub struct UnixConn {
    stream: UnixStream,
    peer: PeerCred,
}

impl Read for UnixConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for UnixConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn dur(ms: u64) -> Option<Duration> {
    Some(Duration::from_millis(ms.max(1)))
}

impl Conn for UnixConn {
    fn peer(&self) -> &PeerCred {
        &self.peer
    }
    fn set_timeouts(&mut self, read_ms: u64, write_ms: u64) -> io::Result<()> {
        self.stream.set_read_timeout(dur(read_ms))?;
        self.stream.set_write_timeout(dur(write_ms))
    }
}

impl UnixListenerT {
    fn wrap(&self, stream: UnixStream) -> Option<Box<dyn Conn>> {
        // A connection whose peer cannot be read is closed before any frame is read (§3.6).
        match peer_cred(stream.as_raw_fd()) {
            Ok(peer) => {
                let _ = stream.set_nonblocking(false);
                Some(Box::new(UnixConn { stream, peer }))
            }
            Err(e) => {
                eprintln!("moorai-guardd: dropping a connection whose peer credentials are unreadable: {e}");
                None
            }
        }
    }
}

impl Listener for UnixListenerT {
    fn accept(&self) -> io::Result<Box<dyn Conn>> {
        loop {
            let (stream, _) = self.inner.accept()?;
            if let Some(c) = self.wrap(stream) {
                return Ok(c);
            }
        }
    }

    fn accept_timeout(&self, ms: u64) -> io::Result<Option<Box<dyn Conn>>> {
        let mut pfd = libc::pollfd { fd: self.inner.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd for the duration of the call.
        let n = unsafe { libc::poll(&mut pfd, 1, ms.min(i32::MAX as u64) as i32) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted { Ok(None) } else { Err(e) };
        }
        if n == 0 {
            return Ok(None);
        }
        self.inner.set_nonblocking(true)?;
        let r = self.inner.accept();
        self.inner.set_nonblocking(false)?;
        match r {
            Ok((stream, _)) => Ok(self.wrap(stream)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// systemd socket activation (Linux, system paths only): fd 3 when LISTEN_PID is this process and
/// LISTEN_FDS >= 1, and it is a listening AF_UNIX stream socket.
#[cfg(target_os = "linux")]
fn inherited() -> Option<UnixListener> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    let fds: u32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if pid != std::process::id() || fds < 1 {
        return None;
    }
    let fd: RawFd = 3;
    let mut ty: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt on an fd number with a correctly sized out-parameter.
    let ok = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE, &mut ty as *mut _ as *mut libc::c_void, &mut len) } == 0;
    if !ok || ty != libc::SOCK_STREAM {
        return None;
    }
    // SAFETY: systemd handed us fd 3 as a listening socket; we take ownership of it once.
    let l = unsafe { UnixListener::from_raw_fd(fd) };
    l.local_addr().ok()?;
    Some(l)
}

#[cfg(not(target_os = "linux"))]
fn inherited() -> Option<UnixListener> {
    None
}

/// Bind `paths.endpoint`: create run_dir 0755 owned by the helper's uid if missing (refuse if it
/// exists with another owner or group/world-writable), unlink a stale socket (only a socket: any
/// other file there is refused), bind, chmod 0666.
pub fn bind(paths: &crate::state::Paths) -> io::Result<Box<dyn Listener>> {
    if paths.system {
        if let Some(l) = inherited() {
            return Ok(Box::new(UnixListenerT { inner: l }));
        }
    }
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    crate::state::ensure_dir(&paths.run_dir, 0o755, &paths.trust_root, paths.admin_owner())?;
    let ep = std::path::Path::new(&paths.endpoint);
    if ep.parent() != Some(paths.run_dir.as_path()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "the endpoint is not in the run dir"));
    }
    match std::fs::symlink_metadata(ep) {
        Ok(md) if md.file_type().is_socket() => std::fs::remove_file(ep)?,
        Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, "a non-socket file holds the endpoint path")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let l = UnixListener::bind(ep)?;
    std::fs::set_permissions(ep, std::fs::Permissions::from_mode(0o666))?;
    Ok(Box::new(UnixListenerT { inner: l }))
}

/// Kernel peer credentials of a connected socket.
#[cfg(target_os = "macos")]
pub fn peer_cred(fd: RawFd) -> io::Result<PeerCred> {
    // SAFETY: zeroed xucred is a valid out-parameter; sizes are passed exactly.
    let mut cred: libc::xucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_LOCAL, libc::LOCAL_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if cred.cr_version != libc::XUCRED_VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected xucred version"));
    }
    let mut pid: libc::pid_t = 0;
    let mut plen = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_LOCAL, libc::LOCAL_PEERPID, &mut pid as *mut _ as *mut libc::c_void, &mut plen) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if pid <= 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no peer pid"));
    }
    Ok(PeerCred { pid: pid as u32, uid: cred.cr_uid, sid: None, admin: cred.cr_uid == 0 })
}

#[cfg(target_os = "linux")]
pub fn peer_cred(fd: RawFd) -> io::Result<PeerCred> {
    // SAFETY: zeroed ucred is a valid out-parameter; sizes are passed exactly.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if cred.pid <= 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no peer pid"));
    }
    Ok(PeerCred { pid: cred.pid as u32, uid: cred.uid, sid: None, admin: cred.uid == 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_credentials_are_the_kernels() {
        let (a, _b) = UnixStream::pair().unwrap();
        let p = peer_cred(a.as_raw_fd()).unwrap();
        assert_eq!(p.pid, std::process::id());
        assert_eq!(p.uid, crate::state::current_uid());
        assert_eq!(p.admin, p.uid == 0);
    }
}
