//! The helper's IPC server loop (contract §3.1–§3.3): framing and limits, envelope checks and
//! versioning, `hello` first, server-side deadlines, the connection cap. Dispatch is behind `Handler`
//! so the loop is testable with an in-memory connection and a fake handler.

use super::{frame, ErrorCode, ErrorResp, RequestFrame, Response, ResponseFrame, MAX_FRAME, OPS, PROTO_VERSION, SERVER_FRAME_DEADLINE_MS, SERVER_IDLE_MS, SERVER_MAX_CONNECTIONS};
use crate::canonical::parse_canonical;
use crate::transport::{Conn, Listener, PeerCred};
use serde_json::Value;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Write timeout for a reply: a peer that does not read cannot pin a server thread.
pub const SERVER_WRITE_MS: u64 = 1000;

/// Per-connection state the ops see.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ConnCtx {
    pub hello_done: bool,
    pub client: Option<String>,
}

/// Work to run after the reply is written (the quarantine network step, §8.4 steps 5–6).
pub type AfterReply = Box<dyn FnOnce() + Send>;

pub trait Handler: Send + Sync {
    fn handle(&self, ctx: &mut ConnCtx, peer: &PeerCred, req: RequestFrame) -> (ResponseFrame, Option<AfterReply>);
}

pub fn error_frame(id: u32, code: ErrorCode, message: &str, req_op: Option<&str>) -> ResponseFrame {
    ResponseFrame { v: PROTO_VERSION, id, body: Response::Error(ErrorResp { code, message: message.into(), req_op: req_op.map(str::to_string) }) }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    Frame(Vec<u8>),
    /// EOF before the first byte of a frame: the client is done.
    Closed,
    /// No frame for SERVER_IDLE_MS, or a frame slower than SERVER_FRAME_DEADLINE_MS: close silently.
    TimedOut,
    Empty,
    TooLarge,
}

fn read_full(conn: &mut dyn Conn, buf: &mut [u8], deadline: Instant) -> io::Result<bool> {
    let mut got = 0;
    while got < buf.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        conn.set_timeouts(left.as_millis() as u64, SERVER_WRITE_MS)?;
        match conn.read(&mut buf[got..]) {
            Ok(0) => return Ok(false),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Err(io::ErrorKind::TimedOut.into()),
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Read one frame: the first byte within SERVER_IDLE_MS, the rest of the frame within
/// SERVER_FRAME_DEADLINE_MS of it; the length is checked before the body is buffered.
pub fn read_frame(conn: &mut dyn Conn, idle_ms: u64, frame_ms: u64) -> ReadOutcome {
    let mut first = [0u8; 1];
    match read_full(conn, &mut first, Instant::now() + Duration::from_millis(idle_ms)) {
        Ok(true) => {}
        Ok(false) => return ReadOutcome::Closed,
        Err(_) => return ReadOutcome::TimedOut,
    }
    let deadline = Instant::now() + Duration::from_millis(frame_ms);
    let mut rest = [0u8; 3];
    match read_full(conn, &mut rest, deadline) {
        Ok(true) => {}
        _ => return ReadOutcome::TimedOut,
    }
    let n = u32::from_be_bytes([first[0], rest[0], rest[1], rest[2]]) as usize;
    if n == 0 {
        return ReadOutcome::Empty;
    }
    if n > MAX_FRAME {
        return ReadOutcome::TooLarge;
    }
    let mut body = vec![0u8; n];
    match read_full(conn, &mut body, deadline) {
        Ok(true) => ReadOutcome::Frame(body),
        _ => ReadOutcome::TimedOut,
    }
}

fn write_frame(conn: &mut dyn Conn, f: &ResponseFrame) -> io::Result<()> {
    let bytes = frame::encode(f).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
    conn.set_timeouts(SERVER_IDLE_MS, SERVER_WRITE_MS)?;
    conn.write_all(&bytes)?;
    conn.flush()
}

enum Envelope {
    Ok(RequestFrame),
    /// Answer with this error; `close` = drop the connection after it.
    Err(ResponseFrame, bool),
}

fn envelope(payload: &[u8], ctx: &ConnCtx) -> Envelope {
    let v = match parse_canonical(payload) {
        Ok(Value::Object(m)) => m,
        _ => return Envelope::Err(error_frame(0, ErrorCode::BadFrame, "not a canonical JSON object", None), true),
    };
    let id = match v.get("id").and_then(Value::as_u64) {
        Some(i) if (1..=u32::MAX as u64).contains(&i) => i as u32,
        _ => return Envelope::Err(error_frame(0, ErrorCode::BadRequest, "id must be a u32 >= 1", None), true),
    };
    let op = v.get("op").and_then(Value::as_str).map(str::to_string);
    match v.get("v").and_then(Value::as_u64) {
        Some(x) if x == PROTO_VERSION as u64 => {}
        _ => return Envelope::Err(error_frame(id, ErrorCode::UnsupportedVersion, "protocol version not served", op.as_deref()), false),
    }
    let Some(op) = op.filter(|o| OPS.contains(&o.as_str())) else {
        return Envelope::Err(error_frame(id, ErrorCode::UnknownOp, "unknown op", None), false);
    };
    if !ctx.hello_done && op != "hello" {
        return Envelope::Err(error_frame(id, ErrorCode::BadRequest, "hello first", Some(&op)), true);
    }
    match serde_json::from_value::<RequestFrame>(Value::Object(v)) {
        Ok(f) => Envelope::Ok(f),
        Err(_) => Envelope::Err(error_frame(id, ErrorCode::BadRequest, "malformed request fields", Some(&op)), false),
    }
}

/// Serve one connection until the client closes, a deadline passes, or a framing error.
pub fn serve_conn(mut conn: Box<dyn Conn>, handler: &dyn Handler) {
    serve_conn_with(conn.as_mut(), handler, SERVER_IDLE_MS, SERVER_FRAME_DEADLINE_MS)
}

pub fn serve_conn_with(conn: &mut dyn Conn, handler: &dyn Handler, idle_ms: u64, frame_ms: u64) {
    let peer = conn.peer().clone();
    let mut ctx = ConnCtx::default();
    loop {
        let payload = match read_frame(conn, idle_ms, frame_ms) {
            ReadOutcome::Frame(p) => p,
            ReadOutcome::Closed | ReadOutcome::TimedOut => return,
            ReadOutcome::Empty => {
                let _ = write_frame(conn, &error_frame(0, ErrorCode::BadFrame, "empty frame", None));
                return;
            }
            ReadOutcome::TooLarge => {
                let _ = write_frame(conn, &error_frame(0, ErrorCode::FrameTooLarge, "frame exceeds MAX_FRAME", None));
                return;
            }
        };
        match envelope(&payload, &ctx) {
            Envelope::Err(f, close) => {
                if write_frame(conn, &f).is_err() || close {
                    return;
                }
            }
            Envelope::Ok(req) => {
                let (resp, after) = handler.handle(&mut ctx, &peer, req);
                let ok = write_frame(conn, &resp).is_ok();
                if let Some(a) = after {
                    a();
                }
                if !ok {
                    return;
                }
            }
        }
    }
}

/// Accept loop: one thread per connection, at most SERVER_MAX_CONNECTIONS at once (`busy` beyond),
/// until `stop` is set.
pub fn serve(listener: &dyn Listener, handler: Arc<dyn Handler>, stop: &AtomicBool) -> io::Result<()> {
    serve_with_cap(listener, handler, stop, SERVER_MAX_CONNECTIONS)
}

pub fn serve_with_cap(listener: &dyn Listener, handler: Arc<dyn Handler>, stop: &AtomicBool, cap: usize) -> io::Result<()> {
    let active = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::SeqCst) {
        let Some(mut conn) = listener.accept_timeout(250)? else { continue };
        if active.fetch_add(1, Ordering::SeqCst) >= cap {
            active.fetch_sub(1, Ordering::SeqCst);
            let _ = write_frame(conn.as_mut(), &error_frame(0, ErrorCode::Busy, "too many connections", None));
            continue;
        }
        let h = handler.clone();
        let a = active.clone();
        std::thread::spawn(move || {
            serve_conn(conn, h.as_ref());
            a.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{CallResp, Request};
    use super::*;
    use crate::transport::MemConn;
    use serde_json::json;

    struct Echo;
    impl Handler for Echo {
        fn handle(&self, ctx: &mut ConnCtx, _p: &PeerCred, req: RequestFrame) -> (ResponseFrame, Option<AfterReply>) {
            if matches!(req.body, Request::Hello(_)) {
                ctx.hello_done = true;
            }
            (ResponseFrame { v: 1, id: req.id, body: Response::Call(CallResp {}) }, None)
        }
    }

    fn frame_of(v: serde_json::Value) -> Vec<u8> {
        frame::encode_value(&v).unwrap()
    }

    fn hello(id: u32) -> Vec<u8> {
        frame_of(json!({"v":1,"id":id,"op":"hello","proto":[1],"client":"moorai-hook","clientVersion":"1.13.6","nonce":"00112233445566778899aabbccddeeff"}))
    }

    fn run(input: Vec<u8>) -> Vec<serde_json::Value> {
        let out = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut c = MemConn { peer: PeerCred { pid: 1, uid: 501, sid: None, admin: false }, input: std::io::Cursor::new(input), output: out.clone() };
        serve_conn_with(&mut c, &Echo, 200, 100);
        let bytes = out.lock().unwrap().clone();
        let mut d = frame::Decoder::new();
        d.push(&bytes);
        let mut v = vec![];
        while let Some(x) = d.next_value().unwrap() {
            v.push(x);
        }
        v
    }

    fn code(v: &serde_json::Value) -> (&str, u64) {
        (v["code"].as_str().unwrap_or(""), v["id"].as_u64().unwrap())
    }

    #[test]
    fn several_requests_on_one_connection_are_answered_in_order() {
        let mut input = hello(1);
        input.extend(frame_of(json!({"v":1,"id":2,"op":"call","event":"PreToolUse","host":"claude-code","sessionHash":"a1b2c3d4e5f60718"})));
        let out = run(input);
        assert_eq!(out.iter().map(|v| v["id"].as_u64().unwrap()).collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn hello_must_come_first() {
        let out = run(frame_of(json!({"v":1,"id":3,"op":"kill"})));
        assert_eq!(code(&out[0]), ("bad_request", 3));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn framing_errors_answer_and_close() {
        let mut input = vec![0, 0, 0, 0];
        input.extend(hello(1));
        let out = run(input);
        assert_eq!((code(&out[0]), out.len()), (("bad_frame", 0), 1), "empty frame closes");

        let out = run((2 * 1024 * 1024u32).to_be_bytes().to_vec());
        assert_eq!(code(&out[0]), ("frame_too_large", 0));

        let p = br#"{"v":1, "id":1}"#;
        let mut input = (p.len() as u32).to_be_bytes().to_vec();
        input.extend_from_slice(p);
        input.extend(hello(2));
        let out = run(input);
        assert_eq!((code(&out[0]), out.len()), (("bad_frame", 0), 1), "non-canonical closes");

        let p = b"[1]";
        let mut input = (p.len() as u32).to_be_bytes().to_vec();
        input.extend_from_slice(p);
        assert_eq!(code(&run(input)[0]), ("bad_frame", 0), "non-object");

        let p = b"\xef\xbb\xbf{}";
        let mut input = (p.len() as u32).to_be_bytes().to_vec();
        input.extend_from_slice(p);
        assert_eq!(code(&run(input)[0]), ("bad_frame", 0), "BOM");
    }

    #[test]
    fn version_and_op_errors_keep_the_connection() {
        let mut input = hello(1);
        input.extend(frame_of(json!({"v":2,"id":2,"op":"kill"})));
        input.extend(frame_of(json!({"v":1,"id":3,"op":"reboot"})));
        input.extend(frame_of(json!({"v":1,"id":4,"op":"call","event":7})));
        input.extend(frame_of(json!({"v":1,"id":5,"op":"kill","unknownField":true})));
        let out = run(input);
        assert_eq!(code(&out[1]), ("unsupported_version", 2));
        assert_eq!(code(&out[2]), ("unknown_op", 3));
        assert_eq!(code(&out[3]), ("bad_request", 4));
        assert_eq!(out[4]["id"], 5, "unknown fields are ignored");
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn a_missing_id_is_bad_request_with_id_zero() {
        let mut input = hello(1);
        input.extend(frame_of(json!({"v":1,"op":"kill"})));
        let out = run(input);
        assert_eq!(code(&out[1]), ("bad_request", 0));
    }

    #[test]
    fn a_truncated_frame_times_out_without_an_answer() {
        let mut input = hello(1);
        let h = hello(2);
        input.extend_from_slice(&h[..h.len() - 3]);
        let out = run(input);
        assert_eq!(out.len(), 1);
    }
}
