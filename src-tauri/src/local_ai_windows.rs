// Windows AI platform inventory and the Windows On-device Agent Registry (ODR) — the Rust mirror of
// cli/local-ai-windows.mjs (read that file for the Microsoft sources behind every package family, the
// NPU class, the GPU floors and both documented `odr.exe list` shapes). Windows only at runtime; the
// parsers are pure and tested everywhere against test/fixtures/local-ai/{windows-ai,odr-list}.json,
// which the JS tests replay too. Fail-open: a probe that cannot run, times out or prints something
// unusable yields None and the block is left out of the report.
#![cfg_attr(not(windows), allow(dead_code))]
use crate::ai_runtime::Runner;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashSet};
use std::sync::OnceLock;
use std::time::Duration;

// Joined with "; " — the same script as the JS WIN_AI_PS (pinned by test/aibom-rust-parity.test.mjs).
pub const WIN_AI_PS: &[&str] = &[
    r"$ErrorActionPreference='SilentlyContinue'",
    r"$re='^(Microsoft\.WindowsAppRuntime\.|MicrosoftCorporationII\.WinAppRuntime\.|Microsoft\.WinAppRuntime\.DDLM\.|MicrosoftCorporationII\.WinML\.|Microsoft\.WinML\.|Microsoft\.AionInstructPreview\.)'",
    r"$p=@(Get-AppxPackage | Where-Object { $_.Name -match $re } | ForEach-Object { @{n=[string]$_.Name;v=[string]$_.Version} })",
    r"$g=@(Get-CimInstance -ClassName Win32_VideoController | ForEach-Object { @{n=[string]$_.Name;m=[string]$_.AdapterCompatibility} })",
    r"$a=@(Get-PnpDevice -Class ComputeAccelerator -PresentOnly | ForEach-Object { @{n=[string]$_.FriendlyName;m=[string]$_.Manufacturer} })",
    r"ConvertTo-Json -Compress -Depth 4 -InputObject @{p=$p;g=$g;a=$a}",
];
pub const WIN_AI_TIMEOUT: Duration = Duration::from_secs(10);
pub const ODR_TIMEOUT: Duration = Duration::from_secs(5);
pub const ODR_EXE: &str = "odr.exe";
pub const ODR_ARGS: &[&str] = &["list"];
const ODR_MAX_ITEMS: usize = 100;

fn re(cell: &'static OnceLock<Regex>, src: &str) -> &'static Regex { cell.get_or_init(|| Regex::new(src).unwrap()) }

pub fn vendor_of(name: &str, maker: &str) -> &'static str {
    static V: OnceLock<Regex> = OnceLock::new();
    static N: OnceLock<Regex> = OnceLock::new();
    static A: OnceLock<Regex> = OnceLock::new();
    static I: OnceLock<Regex> = OnceLock::new();
    static Q: OnceLock<Regex> = OnceLock::new();
    let s = format!("{name} {maker}");
    if re(&V, r"(?i)microsoft basic|remote display|hyper-v|vmware|virtualbox|parallels|citrix|indirect display").is_match(&s) { return "virtual"; }
    if re(&N, r"(?i)nvidia").is_match(&s) { return "nvidia"; }
    if re(&A, r"(?i)\bamd\b|advanced micro devices|radeon").is_match(&s) { return "amd"; }
    if re(&I, r"(?i)intel").is_match(&s) { return "intel"; }
    if re(&Q, r"(?i)qualcomm|snapdragon|adreno|hexagon").is_match(&s) { return "qualcomm"; }
    "other"
}

// → nvidia-rtx30plus | nvidia-other | amd-rdna3plus | amd-other | intel-arc | intel-other | qualcomm | virtual | other
pub fn gpu_tier(name: &str, maker: &str) -> &'static str {
    static NV: OnceLock<Regex> = OnceLock::new();
    static NVPRO: OnceLock<Regex> = OnceLock::new();
    static RX: OnceLock<Regex> = OnceLock::new();
    static IGPU: OnceLock<Regex> = OnceLock::new();
    static ARC: OnceLock<Regex> = OnceLock::new();
    match vendor_of(name, maker) {
        "nvidia" => {
            let gen = re(&NV, r"(?i)RTX\s*(\d{2})\d{2}\b").captures(name).and_then(|m| m[1].parse::<u32>().ok());
            if gen.is_some_and(|g| g >= 30) || re(&NVPRO, r"(?i)RTX\s*(A\d{3,4}|PRO|\d{4}\s*Ada)").is_match(name) { "nvidia-rtx30plus" } else { "nvidia-other" }
        }
        "amd" => {
            let gen = re(&RX, r"(?i)\bRX\s*(\d)\d{3}\b").captures(name).and_then(|m| m[1].parse::<u32>().ok());
            if gen.is_some_and(|g| g >= 7) || re(&IGPU, r"(?i)Radeon\s*(7[4-9]0M|8[0-9]0M)\b").is_match(name) { "amd-rdna3plus" } else { "amd-other" }
        }
        "intel" => if re(&ARC, r"(?i)\bArc\b").is_match(name) { "intel-arc" } else { "intel-other" },
        v => v,
    }
}

fn as_arr(v: Option<&Value>) -> Vec<&Value> {
    match v {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(o @ Value::Object(_)) => vec![o],
        _ => vec![],
    }
}
fn s<'a>(v: &'a Value, k: &str) -> &'a str { v.get(k).and_then(|x| x.as_str()).unwrap_or("") }

// PowerShell JSON → the content-free platform record, or None when the probe produced nothing usable.
pub fn parse_windows_ai(text: &str) -> Option<Value> {
    static NAME: OnceLock<Regex> = OnceLock::new();
    static VER: OnceLock<Regex> = OnceLock::new();
    static SDK: OnceLock<Regex> = OnceLock::new();
    static ML: OnceLock<Regex> = OnceLock::new();
    static AION: OnceLock<Regex> = OnceLock::new();
    static EPS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    let j: Value = serde_json::from_str(text.trim()).ok()?;
    if !j.is_object() { return None; }
    let name_re = re(&NAME, r"^[A-Za-z0-9.-]{1,128}$");
    let ver_re = re(&VER, r"^\d+(\.\d+){0,3}$");
    let groups: [(&Regex, &str); 3] = [
        (re(&SDK, r"(?i)^(Microsoft\.WindowsAppRuntime\.|MicrosoftCorporationII\.WinAppRuntime\.|Microsoft\.WinAppRuntime\.DDLM\.)"), "appSdkRuntime"),
        (re(&ML, r"(?i)^(MicrosoftCorporationII\.WinML\.|Microsoft\.WinML\.)"), "windowsMlEps"),
        (re(&AION, r"(?i)^Microsoft\.AionInstructPreview\."), "aionPreview"),
    ];
    let eps = EPS.get_or_init(|| [(r"(?i)QNN", "QNN"), (r"(?i)OpenVINO", "OpenVINO"), (r"(?i)VitisAI|AMD\.NPU", "VitisAI"), (r"(?i)MIGraphX|AMD\.GPU", "MIGraphX"), (r"(?i)NVIDIA|TensorRT|TRT", "NvTensorRtRtx"), (r"(?i)WebGPU", "WebGPU")]
        .into_iter().map(|(r, n)| (Regex::new(r).unwrap(), n)).collect());
    let mut out = json!({ "appSdkRuntime": [], "windowsMlEps": [], "aionPreview": [] });
    let mut seen = HashSet::new();
    for p in as_arr(j.get("p")) {
        let name = s(p, "n");
        let version = p.get("v").and_then(|v| v.as_str()).filter(|v| ver_re.is_match(v));
        if !name_re.is_match(name) || !seen.insert(format!("{name}|{}", version.unwrap_or("null"))) { continue; }
        let Some((_, group)) = groups.iter().find(|(r, _)| r.is_match(name)) else { continue };
        let mut row = json!({ "name": name, "version": version });
        if *group == "windowsMlEps" { row["ep"] = json!(eps.iter().find(|(r, _)| r.is_match(name)).map(|(_, n)| *n).unwrap_or("unknown")); }
        out[*group].as_array_mut().unwrap().push(row);
    }
    let npus: Vec<&str> = as_arr(j.get("a")).iter().map(|d| vendor_of(s(d, "n"), s(d, "m"))).collect();
    let gpus: Vec<(&str, &str)> = as_arr(j.get("g")).iter().map(|d| (vendor_of(s(d, "n"), s(d, "m")), gpu_tier(s(d, "n"), s(d, "m")))).filter(|(v, _)| *v != "virtual").collect();
    let vendors: BTreeSet<&str> = npus.iter().copied().collect();
    out["npu"] = json!({ "present": !npus.is_empty(), "count": npus.len(), "vendors": vendors });
    out["gpus"] = json!(gpus.iter().map(|(v, t)| json!({ "vendor": v, "tier": t })).collect::<Vec<_>>());
    out["localInference"] = json!({ "npu": !npus.is_empty(), "suitedGpu": gpus.iter().any(|(_, t)| matches!(*t, "nvidia-rtx30plus" | "amd-rdna3plus" | "intel-arc")) });
    Some(out)
}

pub fn windows_ai_platform(runner: Runner) -> Option<Value> {
    let script = WIN_AI_PS.join("; ");
    parse_windows_ai(&runner("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script], WIN_AI_TIMEOUT)?)
}

// A connector NAME only: control characters stripped, capped, refused when it looks like a path or URL.
pub fn odr_name(v: Option<&Value>) -> Option<String> {
    static PATHISH: OnceLock<Regex> = OnceLock::new();
    let raw = v?.as_str()?;
    let cleaned: String = raw.chars().filter(|c| !matches!(*c as u32, 0..=0x1f | 0x7f)).collect();
    let t: String = cleaned.trim().chars().take(128).collect();
    // JS slices UTF-16 units; for the names ODR carries (ASCII ids) chars and units agree.
    if t.is_empty() || re(&PATHISH, r"\\|://|^[A-Za-z]:|^[/~]").is_match(&t) { return None; }
    Some(t)
}

pub fn parse_odr_list(text: &str) -> Option<Value> {
    static PFN: OnceLock<Regex> = OnceLock::new();
    static MSIX: OnceLock<Regex> = OnceLock::new();
    let j: Value = serde_json::from_str(text.trim()).ok()?;
    let list = match &j {
        Value::Array(a) => a,
        Value::Object(o) => match o.get("structuredContent").and_then(|sc| sc.get("servers")).and_then(|v| v.as_array()) {
            Some(a) if o.get("structuredContent").is_some_and(|v| v.is_object()) => a,
            _ => o.get("servers").and_then(|v| v.as_array())?,
        },
        _ => return None,
    };
    let pfn = re(&PFN, r"^[A-Za-z0-9.-]{3,50}_[0-9a-hjkmnp-tv-z]{13}$");
    let msix = re(&MSIX, r"(?i)^(msix|appx)$");
    let entries: Vec<&Value> = list.iter().filter(|e| e.is_object()).collect();
    let empty = json!({});
    let items: Vec<Value> = entries.iter().take(ODR_MAX_ITEMS).map(|e| {
        let srv = e.get("server").filter(|v| v.is_object()).unwrap_or(&empty);
        let man = e.get("manifest").filter(|v| v.is_object()).unwrap_or(&empty);
        let name = odr_name(srv.get("name")).or_else(|| odr_name(man.get("name"))).or_else(|| odr_name(e.get("name")));
        let first_arr = |k: &str| [srv.get(k), e.get(k)].into_iter().flatten().find_map(|v| v.as_array()).cloned().unwrap_or_default();
        let remote = !first_arr("remotes").is_empty();
        let packaged = first_arr("packages").iter().any(|p| p.is_object()
            && (p.get("registryType").and_then(|v| v.as_str()).is_some_and(|t| msix.is_match(t))
                || p.get("identifier").and_then(|v| v.as_str()).is_some_and(|i| pfn.is_match(i))));
        json!({ "name": name, "packaged": packaged, "contained": packaged && !remote })
    }).collect();
    Some(json!({ "count": entries.len(), "items": items }))
}

pub fn odr_agent_connectors(runner: Runner) -> Option<Value> {
    parse_odr_list(&runner(ODR_EXE, ODR_ARGS, ODR_TIMEOUT)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const WIN_FX: &str = include_str!("../../test/fixtures/local-ai/windows-ai.json");
    const ODR_FX: &str = include_str!("../../test/fixtures/local-ai/odr-list.json");

    fn leaks(fx: &Value, out: &str) {
        for l in fx["leaks"].as_array().unwrap() { assert!(!out.contains(l.as_str().unwrap()), "{l} leaked: {out}"); }
    }

    #[test]
    fn windows_ai_cases_match_the_shared_fixture() {
        let fx: Value = serde_json::from_str(WIN_FX).unwrap();
        for c in fx["cases"].as_array().unwrap() {
            let got = parse_windows_ai(c["stdout"].as_str().unwrap()).unwrap_or(Value::Null);
            assert_eq!(got, c["expect"], "{}", c["name"]);
            leaks(&fx, &got.to_string());
        }
        for t in fx["tiers"].as_array().unwrap() {
            assert_eq!(gpu_tier(t[0].as_str().unwrap(), t[1].as_str().unwrap()), t[2].as_str().unwrap(), "{}", t[0]);
        }
    }

    #[test]
    fn odr_cases_match_the_shared_fixture_and_stay_content_free() {
        let fx: Value = serde_json::from_str(ODR_FX).unwrap();
        for c in fx["cases"].as_array().unwrap() {
            let got = parse_odr_list(c["stdout"].as_str().unwrap()).unwrap_or(Value::Null);
            assert_eq!(got, c["expect"], "{}", c["name"]);
            leaks(&fx, &got.to_string());
        }
    }

    #[test]
    fn odr_list_is_capped_but_counted() {
        let many: Vec<Value> = (0..105).map(|i| json!({ "server": { "name": format!("s{i}") } })).collect();
        let got = parse_odr_list(&serde_json::to_string(&many).unwrap()).unwrap();
        assert_eq!((got["count"].as_u64(), got["items"].as_array().unwrap().len()), (Some(105), 100));
    }

    #[test]
    fn probes_run_once_with_their_budgets_and_fail_open() {
        let calls = RefCell::new(vec![]);
        let r = |cmd: &str, args: &[&str], t: Duration| { calls.borrow_mut().push((cmd.to_string(), args.iter().map(|a| a.to_string()).collect::<Vec<_>>(), t)); None };
        assert_eq!(windows_ai_platform(&r), None);
        assert_eq!(odr_agent_connectors(&r), None);
        let c = calls.borrow();
        assert_eq!(c[0].0, "powershell");
        assert_eq!(c[0].1[..3], ["-NoProfile", "-NonInteractive", "-Command"]);
        assert_eq!(c[0].2, Duration::from_secs(10));
        assert_eq!((c[1].0.as_str(), c[1].1.clone(), c[1].2), ("odr.exe", vec!["list".to_string()], Duration::from_secs(5)));
        let script = WIN_AI_PS.join("; ");
        assert!(!Regex::new(r"(?i)-AllUsers|RunAs|Start-Process|Set-|Remove-|Invoke-WebRequest").unwrap().is_match(&script), "read-only, current user, no elevation");
        let junk = |_: &str, _: &[&str], _: Duration| Some("WARNING: not json".to_string());
        assert_eq!(windows_ai_platform(&junk), None);
        assert_eq!(odr_agent_connectors(&junk), None);
    }
}
