//! Canonical JSON (contract §3.3): byte-identical to `canonicalJson` in cli/hook-core.mjs and
//! RAISEME-server/server/policy-sign.js, restricted to the wire value set. Keys are sorted by UTF-16
//! code units (what JavaScript's `Array.prototype.sort` does), strings are escaped exactly as
//! `JSON.stringify` escapes them, and the only numbers allowed are integers in ±(2^53-1).

use serde_json::Value;
use std::fmt;

pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonError {
    /// A float, or an integer outside ±(2^53-1).
    NotWireNumber(String),
    /// Bytes that are not UTF-8 JSON.
    Parse(String),
    /// Parsed, but the bytes are not their own canonical form.
    NotCanonical,
}

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonError::NotWireNumber(n) => write!(f, "not a wire integer: {n}"),
            CanonError::Parse(e) => write!(f, "not JSON: {e}"),
            CanonError::NotCanonical => write!(f, "not canonical JSON"),
        }
    }
}

impl std::error::Error for CanonError {}

pub fn canonical_json(v: &Value) -> Result<String, CanonError> {
    let mut out = String::new();
    write_value(v, &mut out)?;
    Ok(out)
}

fn write_value(v: &Value, out: &mut String) -> Result<(), CanonError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let ok = match (n.as_i64(), n.as_u64()) {
                (Some(i), _) => (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&i),
                (None, Some(u)) => u <= MAX_SAFE_INTEGER as u64,
                _ => false,
            };
            if !ok {
                return Err(CanonError::NotWireNumber(n.to_string()));
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(x, out)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(&m[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// `JSON.stringify` string escaping: `"` `\\` and U+0000..U+001F only; \b \t \n \f \r by name, the
/// rest as lowercase \u00xx. Nothing else (not `/`, not U+007F, not U+2028) is escaped.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Parse `bytes` and require that they are exactly their own canonical form (contract §3.3: every
/// receiver of a frame or a signed body enforces this, which removes duplicate keys, big numbers,
/// whitespace and escape variants as a source of disagreement between parsers).
pub fn parse_canonical(bytes: &[u8]) -> Result<Value, CanonError> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| CanonError::Parse(e.to_string()))?;
    if canonical_json(&v)?.as_bytes() != bytes {
        return Err(CanonError::NotCanonical);
    }
    Ok(v)
}

/// `canonicalJson` of cli/hook-core.mjs over ANY JSON value, floats included: what the policy digest
/// (`policyDigest`, sha256 over the policy minus `policySig`) hashes. Numbers are printed as JavaScript
/// prints them after `JSON.parse` (every number is an IEEE double; ECMAScript Number::toString), keys are
/// sorted by UTF-16 code unit, strings escaped as `JSON.stringify`. Wire frames never use this: they use
/// the strict `canonical_json`.
pub fn js_canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_js(v, &mut out);
    out
}

fn write_js(v: &Value, out: &mut String) {
    match v {
        Value::Number(n) => {
            let f = match (n.as_i64(), n.as_u64(), n.as_f64()) {
                (Some(i), _, _) => i as f64,
                (None, Some(u), _) => u as f64,
                (_, _, Some(f)) => f,
                _ => f64::NAN,
            };
            out.push_str(&js_number(f));
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_js(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_js(&m[*k], out);
            }
            out.push('}');
        }
        Value::String(s) => write_string(s, out),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Null => out.push_str("null"),
    }
}

/// ECMAScript Number::toString(10) for a finite double (JSON.stringify prints non-finite as null).
pub fn js_number(f: f64) -> String {
    if !f.is_finite() {
        return "null".into();
    }
    if f == 0.0 {
        return "0".into();
    }
    let e = format!("{:e}", f.abs());
    let (mant, exp) = e.split_once('e').expect("LowerExp has an exponent");
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i64;
    let n = exp.parse::<i64>().expect("exponent") + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let rest = if k > 1 { format!(".{}", &digits[1..]) } else { String::new() };
        let x = n - 1;
        format!("{}{rest}e{}{}", &digits[..1], if x >= 0 { "+" } else { "-" }, x.abs())
    };
    if f < 0.0 {
        format!("-{body}")
    } else {
        body
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_by_utf16_not_utf8() {
        // U+1F600 is D83D DE00 in UTF-16 (sorts before U+E000) but F0.. in UTF-8 (sorts after).
        let v = json!({"\u{e000}": 2, "\u{1f600}": 1});
        assert_eq!(canonical_json(&v).unwrap(), "{\"\u{1f600}\":1,\"\u{e000}\":2}");
    }

    #[test]
    fn refuses_floats_and_unsafe_integers() {
        assert!(canonical_json(&json!(1.5)).is_err());
        assert!(canonical_json(&json!(9_007_199_254_740_992u64)).is_err());
        assert_eq!(canonical_json(&json!(-9_007_199_254_740_991i64)).unwrap(), "-9007199254740991");
    }

    #[test]
    fn non_canonical_bytes_are_refused() {
        assert!(parse_canonical(br#"{"a":1}"#).is_ok());
        assert_eq!(parse_canonical(br#"{"a": 1}"#), Err(CanonError::NotCanonical));
        assert_eq!(parse_canonical(br#"{"b":1,"a":2}"#), Err(CanonError::NotCanonical));
        assert_eq!(parse_canonical(br#"{"a":1,"a":1}"#), Err(CanonError::NotCanonical));
        assert_eq!(parse_canonical(b"{\"a\":\"\\u0041\"}"), Err(CanonError::NotCanonical), "escaped A");
    }

    #[test]
    fn js_numbers_print_as_javascript_prints_them() {
        for (f, js) in [
            (1.0, "1"), (0.1, "0.1"), (-0.0, "0"), (1.5e-7, "1.5e-7"), (1e21, "1e+21"), (1e20, "100000000000000000000"),
            (123.456, "123.456"), (0.000001, "0.000001"), (0.0000001, "1e-7"), (-2.5e-10, "-2.5e-10"),
            (9007199254740993.0, "9007199254740992"), (1.7976931348623157e308, "1.7976931348623157e+308"),
        ] {
            assert_eq!(js_number(f), js, "{f:e}");
        }
    }

    #[test]
    fn js_canonical_takes_floats_and_big_integers() {
        let v: Value = serde_json::from_str(r#"{"b":[1.50,2e3,18446744073709551615],"a":{"y":null,"x":"\u00e9"}}"#).unwrap();
        assert_eq!(js_canonical_json(&v), "{\"a\":{\"x\":\"\u{e9}\",\"y\":null},\"b\":[1.5,2000,18446744073709552000]}");
    }
}
