// The clipboard guard's policy iat high-water mark helpers: the hook's rule (cli/hook-core.mjs
// isPolicyRollback / maxIat / parsePolicyHwm, F-202), so an older but validly signed policy cannot be
// replayed to roll the guard back. A policy whose iat is STRICTLY older than a mark is behind it; an equal
// iat is the same policy re-fetched. Unparseable or absent on either side means no comparison is possible.
// Which marks may refuse (only those user-writable state cannot raise) is decided in clip_guard_policy.rs.
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mark {
    pub tenant: String,
    pub iat: String,
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

// ISO 8601 `YYYY-MM-DDTHH:MM:SS[.fff…](Z|±HH:MM)` → epoch ms; anything else None. The console signs
// `Date#toISOString()`; the same strict reading as guardd's clock::parse_iso_ms.
pub fn iat_order(s: &str) -> Option<i64> {
    let b = s.trim().as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = b.get(r)?;
        if part.is_empty() || !part.iter().all(u8::is_ascii_digit) { return None; }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' { return None; }
    let (y, mo, d, h, mi, se) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 59 { return None; }
    let mut i = 19;
    let mut frac = 0i64;
    if b[i] == b'.' {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() { i += 1; }
        if i == start { return None; }
        for (k, c) in b[start..i.min(start + 3)].iter().enumerate() { frac += ((c - b'0') as i64) * [100, 10, 1][k]; }
    }
    let offset_min = match b.get(i..)? {
        [b'Z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let oh = std::str::from_utf8(&[*h1, *h2]).ok()?.parse::<i64>().ok()?;
            let om = std::str::from_utf8(&[*m1, *m2]).ok()?.parse::<i64>().ok()?;
            if oh > 23 || om > 59 { return None; }
            if *sign == b'+' { oh * 60 + om } else { -(oh * 60 + om) }
        }
        _ => return None,
    };
    // 2026-02-30 and the like are not dates
    let (ny, nm) = if mo == 12 { (y + 1, 1) } else { (y, mo + 1) };
    if d > days_from_civil(ny, nm, 1) - days_from_civil(y, mo, 1) { return None; }
    let days = days_from_civil(y, mo, d);
    Some(days * 86_400_000 + h * 3_600_000 + mi * 60_000 + se * 1000 + frac - offset_min * 60_000)
}

pub fn is_rollback(iat: &str, mark: Option<&str>) -> bool {
    matches!((iat_order(iat), mark.and_then(iat_order)), (Some(a), Some(b)) if a < b)
}

// The later of two marks; an unparseable side loses.
pub fn max_iat(a: Option<&str>, b: Option<&str>) -> Option<String> {
    match (a.filter(|x| iat_order(x).is_some()), b.filter(|x| iat_order(x).is_some())) {
        (Some(x), Some(y)) => Some(if iat_order(y) > iat_order(x) { y } else { x }.to_string()),
        (Some(x), None) | (None, Some(x)) => Some(x.to_string()),
        (None, None) => None,
    }
}

// The hook's pin copies → the highest `iat` among the copies for this tenant. The caller uses it only when
// pin_keys accepted the pin as a whole.
pub fn pin_mark(pins: &[Option<String>], tenant: &str) -> Option<String> {
    let mut mark = None;
    for text in pins.iter().flatten() {
        let Ok(p) = serde_json::from_str::<Value>(text) else { continue };
        if p.get("v").and_then(|v| v.as_u64()) != Some(1) || p.get("tenant").and_then(|t| t.as_str()) != Some(tenant) { continue; }
        mark = max_iat(mark.as_deref(), p.get("iat").and_then(|i| i.as_str()));
    }
    mark
}

// parsePolicyHwm: the root-owned mark's format (the pin's shape minus the keys). A wrong version or
// another tenant's mark reads as no mark, never an error.
pub fn parse_root_hwm(text: &str, tenant: &str) -> Option<String> {
    let j: Value = serde_json::from_str(text).ok()?;
    if j.get("v").and_then(|v| v.as_f64()) != Some(1.0) { return None; }
    if !tenant.is_empty() && j.get("tenant").and_then(|t| t.as_str()).unwrap_or("") != tenant { return None; }
    j.get("iat").and_then(|i| i.as_str()).filter(|i| iat_order(i).is_some()).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iat_reads_like_the_hook_and_guardd() {
        assert_eq!(iat_order("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(iat_order("2026-10-12T10:00:00.000Z"), Some(1_791_799_200_000), "Date.parse in Node gives this");
        assert_eq!(iat_order("2026-10-12T12:00:00+02:00"), Some(1_791_799_200_000));
        for bad in ["", "1760000000000", "2026-02-30T00:00:00Z", "2026-10-12", "2026-10-12T10:00:00", "2026-10-12T10:00:00.Z"] {
            assert_eq!(iat_order(bad), None, "{bad}");
        }
    }

    #[test]
    fn strictly_older_is_a_rollback_and_unreadable_is_not() {
        let (a, b) = ("2026-10-01T00:00:00.000Z", "2026-10-02T00:00:00.000Z");
        assert!(is_rollback(a, Some(b)));
        assert!(!is_rollback(b, Some(b)) && !is_rollback(b, Some(a)) && !is_rollback(a, None));
        assert!(!is_rollback("1760000000000", Some(b)) && !is_rollback(a, Some("junk")));
        assert_eq!(max_iat(Some(a), Some(b)).as_deref(), Some(b));
        assert_eq!(max_iat(Some("junk"), Some(a)).as_deref(), Some(a));
        assert_eq!(max_iat(None, None), None);
    }

    #[test]
    fn marks_come_only_from_this_tenants_records() {
        let b = "2026-10-02T00:00:00.000Z";
        let pin = |t: &str, iat: &str| Some(serde_json::json!({ "v": 1, "tenant": t, "keys": [], "iat": iat }).to_string());
        assert_eq!(pin_mark(&[pin("acme", "2026-10-01T00:00:00.000Z"), pin("acme", b)], "acme").as_deref(), Some(b));
        assert_eq!(pin_mark(&[pin("evil", b), Some("{junk".into()), None], "acme"), None);
        assert_eq!(parse_root_hwm(&serde_json::json!({ "v": 1, "tenant": "acme", "iat": b }).to_string(), "acme").as_deref(), Some(b));
        assert_eq!(parse_root_hwm(&serde_json::json!({ "v": 1, "tenant": "evil", "iat": b }).to_string(), "acme"), None);
        assert_eq!(parse_root_hwm(&serde_json::json!({ "v": 2, "tenant": "acme", "iat": b }).to_string(), "acme"), None);
        assert_eq!(parse_root_hwm("not json", "acme"), None);
    }
}
