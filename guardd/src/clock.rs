//! Time and randomness helpers shared by the core modules: wall-clock milliseconds, the contract's
//! timestamp form (§2: `YYYY-MM-DDTHH:MM:SS.sssZ`, what `Date#toISOString` emits) and a strict parser
//! for it, and uniform random draws from the OS CSPRNG for back-off jitter.

use ring::rand::{SecureRandom, SystemRandom};

/// Milliseconds since the Unix epoch from the system clock (0 if the clock is before 1970).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `Date#toISOString` of epoch milliseconds (years 0..=9999).
pub fn iso_ms(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600_000,
        (rem / 60_000) % 60,
        (rem / 1000) % 60,
        rem % 1000
    )
}

/// Parse an ISO 8601 date-time: `YYYY-MM-DDTHH:MM:SS`, an optional fraction (milliseconds kept,
/// further digits truncated), then `Z` or `±HH:MM`. Anything else is None: the callers treat an
/// unreadable timestamp as "no comparison possible", the JS hook's semantics for `iatOrder`.
pub fn parse_iso_ms(s: &str) -> Option<i64> {
    let b = s.trim().as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = b.get(r)?;
        if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d, h, mi, se) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || d < 1 || d > 31 || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    let mut i = 19;
    let mut frac_ms = 0i64;
    if b[i] == b'.' {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None;
        }
        let digits = &b[start..i.min(start + 3)];
        let mut v = 0i64;
        for (k, c) in digits.iter().enumerate() {
            v += ((c - b'0') as i64) * [100, 10, 1][k];
        }
        frac_ms = v;
    }
    let offset_min = match b.get(i..)? {
        [b'Z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let oh = std::str::from_utf8(&[*h1, *h2]).ok()?.parse::<i64>().ok()?;
            let om = std::str::from_utf8(&[*m1, *m2]).ok()?.parse::<i64>().ok()?;
            if oh > 23 || om > 59 {
                return None;
            }
            let o = oh * 60 + om;
            if *sign == b'+' {
                o
            } else {
                -o
            }
        }
        _ => return None,
    };
    let (cy, cm, cd) = civil_from_days(days_from_civil(y, mo, d));
    if (cy, cm, cd) != (y, mo, d) {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    Some(days * 86_400_000 + h * 3_600_000 + mi * 60_000 + se * 1000 + frac_ms - offset_min * 60_000)
}

/// A uniform draw in [0, 1) from the OS CSPRNG.
pub fn rand01() -> f64 {
    let mut b = [0u8; 8];
    SystemRandom::new().fill(&mut b).expect("system RNG");
    (u64::from_be_bytes(b) >> 11) as f64 / (1u64 << 53) as f64
}

/// `n` random bytes from the OS CSPRNG, lowercase hex.
pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    SystemRandom::new().fill(&mut b).expect("system RNG");
    crate::canonical::hex(&b)
}

/// Full-jitter exponential back-off: random(0, min(cap, base * 2^attempt)).
pub fn full_jitter_ms(base_ms: u64, cap_ms: u64, attempt: u32, r01: f64) -> u64 {
    let ceiling = cap_ms.min(base_ms.saturating_mul(1u64 << attempt.min(20)));
    (ceiling as f64 * r01) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_round_trips_and_matches_to_iso_string() {
        assert_eq!(iso_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_ms(1_791_797_399_120), "2026-10-12T09:29:59.120Z");
        assert_eq!(parse_iso_ms("2026-10-12T09:29:59.120Z"), Some(1_791_797_399_120));
        assert_eq!(parse_iso_ms("2026-10-12T11:29:59.120+02:00"), Some(1_791_797_399_120));
        assert_eq!(parse_iso_ms("2026-10-12T09:29:59Z"), Some(1_791_797_399_000));
        assert_eq!(parse_iso_ms("2024-02-29T00:00:00.000Z").map(iso_ms).as_deref(), Some("2024-02-29T00:00:00.000Z"));
    }

    #[test]
    fn junk_timestamps_do_not_parse() {
        for s in ["", "yesterday", "2026-13-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-10-12 09:29:59Z", "2026-10-12T09:29:59.Z", "2026-10-12T09:29:59"] {
            assert_eq!(parse_iso_ms(s), None, "{s}");
        }
    }

    #[test]
    fn jitter_is_bounded() {
        assert_eq!(full_jitter_ms(5_000, 300_000, 0, 0.5), 2_500);
        assert_eq!(full_jitter_ms(5_000, 300_000, 30, 0.999_999), 299_999);
        let r = rand01();
        assert!((0.0..1.0).contains(&r));
    }
}
