//! Framing (contract §3.2): a 4-byte big-endian unsigned length N, 1 <= N <= MAX_FRAME, then N bytes
//! of canonical JSON (one object). A receiver that sees N == 0, N > MAX_FRAME, non-canonical bytes or
//! a non-object answers `bad_frame` / `frame_too_large` (when it can) and closes the connection.

use super::MAX_FRAME;
use crate::canonical::{canonical_json, parse_canonical, CanonError};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    Empty,
    TooLarge(usize),
    NotObject,
    Canon(CanonError),
    Shape(String),
}

impl From<CanonError> for FrameError {
    fn from(e: CanonError) -> Self {
        FrameError::Canon(e)
    }
}

/// Encode any serialisable message as one frame.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, FrameError> {
    let v = serde_json::to_value(msg).map_err(|e| FrameError::Shape(e.to_string()))?;
    encode_value(&v)
}

pub fn encode_value(v: &Value) -> Result<Vec<u8>, FrameError> {
    if !v.is_object() {
        return Err(FrameError::NotObject);
    }
    let payload = canonical_json(v)?.into_bytes();
    if payload.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Incremental decoder: feed bytes as they arrive, take complete frames out.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Next complete frame's payload as a JSON object, `Ok(None)` when more bytes are needed. The
    /// length is checked before the body is buffered, so a hostile length never allocates.
    pub fn next_value(&mut self) -> Result<Option<Value>, FrameError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if n == 0 {
            return Err(FrameError::Empty);
        }
        if n > MAX_FRAME {
            return Err(FrameError::TooLarge(n));
        }
        if self.buf.len() < 4 + n {
            return Ok(None);
        }
        let payload: Vec<u8> = self.buf.drain(..4 + n).skip(4).collect();
        let v = parse_canonical(&payload)?;
        if !v.is_object() {
            return Err(FrameError::NotObject);
        }
        Ok(Some(v))
    }

    pub fn next<T: DeserializeOwned>(&mut self) -> Result<Option<T>, FrameError> {
        match self.next_value()? {
            None => Ok(None),
            Some(v) => serde_json::from_value(v).map(Some).map_err(|e| FrameError::Shape(e.to_string())),
        }
    }
}
