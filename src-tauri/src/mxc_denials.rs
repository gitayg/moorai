// MXC captureDenials output -> content-free MoorAI alerts. Launch-time mirror of cli/mxc-denials.mjs;
// both replay test/fixtures/mxc/denial-cases.json. Reads only the documented fields of
// microsoft/mxc @ 7cd00d1 docs/logging-access-denied.md "Output file the caller consumes":
// denials[].{resource, resourceType, accessType} and summary.deniedResourcesTruncated. A `resource`
// never leaves this module — files become a path class, capabilities a well-known name or
// "custom-sid", other types are reported by type alone.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::mxc::{classify_path, tokens, PATH_CLASSES};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const MXC_DENIAL_CATEGORY: &str = "MXC: access denied";
pub const RESOURCE_TYPES: &[&str] = &["file", "ui", "network", "capability", "other"];
pub const ACCESS_TYPES: &[&str] = &["read", "write", "execute", "unknown"];
pub const MAX_DENIAL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_GROUPS: usize = 32;

#[derive(Clone, Debug, PartialEq)]
pub struct Group {
    pub reason_code: String,
    pub resource_type: String,
    pub access_type: String,
    pub path_class: Option<String>,
    pub capability: Option<String>,
    pub risk_level: &'static str,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Parsed {
    pub groups: Vec<Group>,
    pub dropped_groups: usize,
    pub total: u64,
    pub truncated: bool,
}

fn is_capability_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 64 && b[0].is_ascii_alphabetic() && b.iter().all(|c| c.is_ascii_alphanumeric())
}

fn rank(r: &str) -> u8 {
    match r {
        "High" => 2,
        "Medium" => 1,
        _ => 0,
    }
}

fn risk_for(resource_type: &str, class: Option<&str>) -> &'static str {
    match resource_type {
        "file" => class.and_then(|c| PATH_CLASSES.iter().find(|p| p.id == c)).map(|p| p.risk).unwrap_or("Low"),
        "network" | "capability" => "Medium",
        _ => "Low",
    }
}

// ctx: the env and workspace the policy was built from, so path classes line up with the grants.
pub fn parse_denials(text: &str, env: &BTreeMap<String, String>, workspace: &str) -> Result<Parsed, &'static str> {
    if text.len() > MAX_DENIAL_BYTES {
        return Err("too-large");
    }
    let doc: Value = serde_json::from_str(text).map_err(|_| "malformed")?;
    let denials = doc.get("denials").and_then(|d| d.as_array()).ok_or("malformed")?;
    let t = tokens(env, workspace);
    let mut groups: Vec<Group> = vec![];
    let mut total = 0u64;
    for d in denials {
        if !(d.is_object() || d.is_array()) {
            continue;
        }
        total += 1;
        let field = |k: &str| d.get(k).and_then(|v| v.as_str());
        let resource_type = field("resourceType").filter(|v| RESOURCE_TYPES.contains(v)).unwrap_or("other").to_string();
        let access_type = field("accessType").filter(|v| ACCESS_TYPES.contains(v)).unwrap_or("unknown").to_string();
        let mut path_class = None;
        let mut capability = None;
        let label = match resource_type.as_str() {
            "file" => {
                let c = classify_path(field("resource").unwrap_or(""), &t).to_string();
                path_class = Some(c.clone());
                // "other" is also a resourceType (registry and the like); an unclassified file must not join its group
                if c == "other" { "file-other".to_string() } else { c }
            }
            "capability" => {
                let c = field("resource").filter(|r| is_capability_name(r)).unwrap_or("custom-sid").to_string();
                capability = Some(c.clone());
                format!("capability-{c}")
            }
            other => other.to_string(),
        };
        let reason_code = format!("{label}-{access_type}");
        if let Some(g) = groups.iter_mut().find(|g| g.reason_code == reason_code) {
            g.count += 1;
            continue;
        }
        groups.push(Group {
            risk_level: risk_for(&resource_type, path_class.as_deref()),
            reason_code,
            resource_type,
            access_type,
            path_class,
            capability,
            count: 1,
        });
    }
    groups.sort_by(|a, b| rank(b.risk_level).cmp(&rank(a.risk_level)).then(b.count.cmp(&a.count)).then(a.reason_code.cmp(&b.reason_code)));
    let dropped = groups.len().saturating_sub(MAX_GROUPS);
    groups.truncate(MAX_GROUPS);
    let truncated = doc.get("summary").and_then(|s| s.get("deniedResourcesTruncated")).and_then(|v| v.as_bool()) == Some(true);
    Ok(Parsed { groups, dropped_groups: dropped, total, truncated })
}

// One alert per group: the content-free /api/alerts envelope cli/moorai-agentwatch.mjs posts.
pub fn denial_alerts(parsed: &Parsed, agent: &str, ts: &str, identity: &Value) -> Vec<Value> {
    parsed
        .groups
        .iter()
        .map(|g| {
            let mut a = identity.as_object().cloned().unwrap_or_default();
            let mut set = |k: &str, v: Value| {
                a.insert(k.to_string(), v);
            };
            set("threatId", json!(0));
            set("category", json!(MXC_DENIAL_CATEGORY));
            set("riskLevel", json!(g.risk_level));
            set("stage", json!("containment"));
            set("tool", json!(format!("mxc:{agent}")));
            set("ts", json!(ts));
            set("contentHash", json!(format!("mxc:{}", g.reason_code)));
            set("reasonCode", json!(g.reason_code));
            set("resourceType", json!(g.resource_type));
            set("accessType", json!(g.access_type));
            set("count", json!(g.count));
            set("truncated", json!(parsed.truncated || parsed.dropped_groups > 0));
            set("source", json!("mxc-capture-denials"));
            if let Some(c) = &g.path_class {
                set("pathClass", json!(c));
            }
            if let Some(c) = &g.capability {
                set("capability", json!(c));
            }
            Value::Object(a)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CASES: &str = include_str!("../../test/fixtures/mxc/denial-cases.json");

    #[test]
    fn golden_denial_cases_match_the_node_reference() {
        let cases: Vec<Value> = serde_json::from_str(CASES).expect("denial-cases.json parses");
        assert!(cases.len() >= 4, "fixture lost its cases");
        for case in &cases {
            let env: BTreeMap<String, String> = serde_json::from_value(case["env"].clone()).unwrap_or_default();
            let ws = case["workspace"].as_str().unwrap_or("");
            let text = match &case["text"] {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let got = match parse_denials(&text, &env, ws) {
                Err(e) => json!({ "ok": false, "error": e }),
                Ok(p) => json!({ "ok": true, "alerts": denial_alerts(&p, case["agent"].as_str().unwrap_or(""), case["ts"].as_str().unwrap_or(""), &case["identity"]) }),
            };
            assert_eq!(got, case["expected"], "case {}", case["name"]);
        }
    }

    #[test]
    fn no_alert_carries_a_path_or_a_pid() {
        let env: BTreeMap<String, String> = [("USERPROFILE".to_string(), "C:\\Users\\dev".to_string())].into_iter().collect();
        let text = r#"{"denials":[{"resource":"C:\\Users\\dev\\.ssh\\id_ed25519","resourceType":"file","accessType":"read","pid":4242,"filetime":"132847890123456789"}],"summary":{"totalDenials":1}}"#;
        let p = parse_denials(text, &env, "C:\\src\\proj").unwrap();
        let s = serde_json::to_string(&denial_alerts(&p, "claude", "t", &json!({}))).unwrap();
        assert!(!s.contains("id_ed25519") && !s.contains(".ssh") && !s.contains("4242") && !s.contains("1328478901"), "leaked: {s}");
        assert!(s.contains("\"pathClass\":\"ssh-keys\""), "{s}");
    }
}
