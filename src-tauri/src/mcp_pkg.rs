// `pkg` on each MCP server in the device report: the Rust mirror of cli/mcp-package/pkg-report.mjs (and
// of the parts of cli/mcp-package/resolve.mjs it uses). Lets the console show single-maintainer,
// unpinned, package version and package-scan data.
//
//   pkg = { eco: "npm"|"pypi"|"docker"|"local"|"other", name, version, pinned, maintainers, maintainersOrg,
//           scan: { verdict: "clean"|"warn"|"block", findings: [code] } | null }
//
// Content-free: the launch command, its arguments and env are parsed here and dropped; only a registry
// package name and the version spec as configured leave. A local package is eco "local" with no name; a
// docker image on a non-public registry keeps no name or tag; a URL, git or remote launch is "other".
// The maintainer count and scan verdict are read from ~/.moorai/mcp-pkg.json, which the Node side's
// reputation path writes (7-day TTL per value). Everything, including what is read from that
// user-writable file, is validated and bounded before it is sent. Parity with Node:
// test/fixtures/mcp-pkg-cases.json and test/fixtures/mcp-pkg-cache.json are asserted by both test suites.

use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::sync::OnceLock;

pub const PKG_CACHE_FILE: &str = "mcp-pkg.json";
const TTL_MS: f64 = 7.0 * 24.0 * 3600.0 * 1000.0;
const FUTURE_SKEW_MS: f64 = 24.0 * 3600.0 * 1000.0;
const MAX_NAME: usize = 214;
const MAX_VERSION: usize = 64;
const MAX_FINDINGS: usize = 32;
const MAX_MAINTAINERS: f64 = 1000.0;
const PUBLIC_REGISTRIES: &[&str] = &["docker.io", "index.docker.io", "registry-1.docker.io", "ghcr.io", "quay.io", "gcr.io", "mcr.microsoft.com", "public.ecr.aws", "registry.gitlab.com", "registry.k8s.io"];

macro_rules! re {
    ($name:ident, $pat:expr) => {
        fn $name() -> &'static Regex {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new($pat).unwrap())
        }
    };
}
re!(re_split, r#""((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+)"#);
re!(re_unescape, r"\\(.)");
re!(re_path_like, r"^(/|\.\.?[/\\]|~[/\\]|[a-zA-Z]:[/\\]|file:)");
re!(re_npm_scheme, r"(?i)^(git\+|git:|https?:|github:|gitlab:|bitbucket:|npm:)");
re!(re_npm_name, r"(?i)^(@[a-z0-9][A-Za-z0-9_.~-]*/)?[a-z0-9][A-Za-z0-9_.~-]*$");
re!(re_py_scheme, r"(?i)^(git\+|https?:)");
re!(re_py_archive, r"(?i)\.(whl|tar\.gz|zip)$");
re!(re_py_spec, r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(?:(==|@)\s*([A-Za-z0-9.!+_-]+)|[<>=!~].*)?$");
re!(re_py_rest, r"(?s)^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?\s*(.*)$");
re!(re_py_name, r"^[A-Za-z0-9][A-Za-z0-9._-]*$");
re!(re_py_exact, r"^[A-Za-z0-9.!+_-]+$");
re!(re_docker_name, r"^[a-z0-9]+(?:[._-]+[a-z0-9]+)*(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?$");
// The console's rule: no whitespace, backslash or "://", no leading "/", "." or "~" (see pkg-report.mjs).
re!(re_version, r"^[0-9A-Za-z.+_~^<>=!*|,-]+$");
re!(re_exact_semver, r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$");
re!(re_threat, r"^threat-\d{1,4}$");
re!(re_python, r"^python(\d(\.\d+)?)?$");
re!(re_guard, r"moorai-mcp-guard\.mjs$");
re!(re_unparsed_remote, r"(?i)^(git\+|git:|github:|gitlab:|bitbucket:|npm:)");
re!(re_local_archive, r"(?i)\.(tgz|tar\.gz|whl|zip)$");
re!(re_win_ext, r"(?i)\.(exe|cmd|bat)$");

fn vocab() -> &'static BTreeSet<String> {
    static V: OnceLock<BTreeSet<String>> = OnceLock::new();
    V.get_or_init(|| {
        let j: Value = serde_json::from_str(include_str!("../../data/mcp-pkg-findings.json")).unwrap_or(Value::Null);
        j.get("codes").and_then(|c| c.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
    })
}

// ---- resolve.mjs subset ------------------------------------------------------------------------------

fn split_command(s: &str) -> Vec<String> {
    re_split().captures_iter(s).map(|c| {
        if let Some(m) = c.get(1) { re_unescape().replace_all(m.as_str(), "$1").into_owned() }
        else if let Some(m) = c.get(2) { m.as_str().to_string() }
        else { c.get(3).map(|m| m.as_str().to_string()).unwrap_or_default() }
    }).collect()
}

fn base(cmd: &str) -> String {
    let s = cmd.replace('\\', "/");
    let last = s.rsplit('/').next().unwrap_or("");
    re_win_ext().replace(last, "").to_lowercase()
}

fn is_path_like(s: &str) -> bool { re_path_like().is_match(s) }

fn parse_npm_spec(spec: &str) -> Option<(String, Option<String>)> {
    let s = spec.trim();
    if s.is_empty() || is_path_like(s) || re_npm_scheme().is_match(s) || s.ends_with(".tgz") { return None; }
    let (name, version) = match s.rfind('@') {
        Some(at) if at > 0 => (&s[..at], { let v = &s[at + 1..]; if v.is_empty() { None } else { Some(v.to_string()) } }),
        _ => (s, None),
    };
    if !re_npm_name().is_match(name) || name.chars().count() > MAX_NAME { return None; }
    Some((name.to_string(), version))
}

fn parse_pypi_name(spec: &str) -> Option<String> {
    let s = spec.trim();
    if s.is_empty() || is_path_like(s) || re_py_scheme().is_match(s) || re_py_archive().is_match(s) { return None; }
    re_py_spec().captures(s).map(|c| c[1].to_string())
}

struct NpmRunner { value_flags: &'static [&'static str], pkg_flags: &'static [&'static str] }
fn npm_runner(name: &str) -> NpmRunner {
    match name {
        "npx" => NpmRunner { value_flags: &["--registry", "--cache", "--userconfig", "-c", "--call"], pkg_flags: &["-p", "--package"] },
        "bunx" => NpmRunner { value_flags: &["--registry"], pkg_flags: &["-p", "--package"] },
        "pnpm dlx" => NpmRunner { value_flags: &["--registry", "--reporter"], pkg_flags: &["--package"] },
        "yarn dlx" => NpmRunner { value_flags: &[], pkg_flags: &["-p", "--package"] },
        "npm exec" => NpmRunner { value_flags: &["--registry", "-c", "--call", "-w", "--workspace"], pkg_flags: &["--package"] },
        _ => NpmRunner { value_flags: &[], pkg_flags: &["--package"] }, // pnpx
    }
}
const PY_VALUE_FLAGS: &[&str] = &["--python", "-p", "--with", "--with-requirements", "--with-editable", "--index-url", "-i", "--index",
    "--extra-index-url", "--default-index", "--find-links", "-f", "--constraints", "-c", "--overrides", "--directory",
    "--python-preference", "--cache-dir", "--config-file", "--pip-args", "--env-file", "--index-strategy", "--keyring-provider"];
const DOCKER_VALUE_FLAGS: &[&str] = &["-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "--network", "--net", "-p",
    "--publish", "-w", "--workdir", "--entrypoint", "-u", "--user", "--platform", "--pull", "-l", "--label", "--cap-add",
    "--cap-drop", "-m", "--memory", "--cpus", "--add-host", "--dns", "-h", "--hostname", "--security-opt", "--tmpfs",
    "--ulimit", "--device", "--gpus", "--runtime", "--restart", "--log-driver", "--log-opt", "--ipc", "--pid", "--shm-size"];

fn npm_token(args: &[String], runner: &str) -> Option<String> {
    let r = npm_runner(runner);
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" { return args.get(i + 1).filter(|s| !s.is_empty()).cloned(); }
        let eq = a.find('=').filter(|&e| e > 0);
        let flag = eq.map(|e| &a[..e]).unwrap_or(a);
        if r.pkg_flags.contains(&flag) { return Some(eq.map(|e| a[e + 1..].to_string()).unwrap_or_else(|| args.get(i + 1).cloned().unwrap_or_default())); }
        if a.starts_with('-') { if eq.is_none() && r.value_flags.contains(&a.as_str()) { i += 1; } i += 1; continue; }
        return Some(a.clone());
    }
    None
}

fn pypi_token(args: &[String]) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let eq = a.find('=').filter(|&e| e > 0);
        let flag = if a.starts_with('-') { eq.map(|e| &a[..e]).unwrap_or(a) } else { a.as_str() };
        if flag == "--from" || flag == "--spec" { return Some(eq.map(|e| a[e + 1..].to_string()).unwrap_or_else(|| args.get(i + 1).cloned().unwrap_or_default())); }
        if a == "--" { return args.get(i + 1).filter(|s| !s.is_empty()).cloned(); }
        if a.starts_with('-') { if eq.is_none() && PY_VALUE_FLAGS.contains(&a.as_str()) { i += 1; } i += 1; continue; }
        return Some(a.clone());
    }
    None
}

fn docker_image(args: &[String]) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with('-') { if !a.contains('=') && DOCKER_VALUE_FLAGS.contains(&a.as_str()) { i += 1; } i += 1; continue; }
        return Some(a.clone());
    }
    None
}

fn first_non_flag(args: &[String]) -> Option<&String> { args.iter().find(|a| !a.starts_with('-')) }

enum Launch { Npm(String, Option<String>), Pypi(String), PypiInferred, Docker(String), Local, Unknown }

fn npm_from(args: &[String], runner: &str) -> (Launch, Option<String>) {
    let spec = npm_token(args, runner);
    let r = spec.as_deref().filter(|s| !s.is_empty()).and_then(parse_npm_spec).map(|(n, v)| Launch::Npm(n, v)).unwrap_or(Launch::Unknown);
    (r, spec)
}
fn pypi_from(args: &[String]) -> (Launch, Option<String>) {
    let spec = pypi_token(args);
    let r = spec.as_deref().filter(|s| !s.is_empty()).and_then(parse_pypi_name).map(Launch::Pypi).unwrap_or(Launch::Unknown);
    (r, spec)
}

fn launch_spec(argv_in: &[String]) -> (Launch, Option<String>) {
    let mut argv: Vec<String> = argv_in.to_vec();
    let b0 = base(argv.first().map(String::as_str).unwrap_or(""));
    if b0 == "cmd" && argv.get(1).map(|s| s.eq_ignore_ascii_case("/c")).unwrap_or(false) { argv = argv[2..].to_vec(); }
    else if (b0 == "sh" || b0 == "bash" || b0 == "zsh") && argv.get(1).map(String::as_str) == Some("-c") && argv.get(2).map(|s| !s.is_empty()).unwrap_or(false) { argv = split_command(&argv[2]); }
    if argv.is_empty() { return (Launch::Unknown, None); }
    let cmd = base(&argv[0]);
    let rest = &argv[1..];
    let r0 = rest.first().map(String::as_str);
    match cmd.as_str() {
        "npx" | "bunx" | "pnpx" => return npm_from(rest, &cmd),
        "pnpm" | "yarn" if r0 == Some("dlx") => return npm_from(&rest[1..], &format!("{cmd} dlx")),
        "npm" if r0 == Some("exec") || r0 == Some("x") => return npm_from(&rest[1..], "npm exec"),
        "bun" if r0 == Some("x") => return npm_from(&rest[1..], "bunx"),
        "uvx" => return pypi_from(rest),
        "uv" if r0 == Some("tool") && rest.get(1).map(String::as_str) == Some("run") => return pypi_from(&rest[2..]),
        "pipx" if r0 == Some("run") => return pypi_from(&rest[1..]),
        _ => {}
    }
    if re_python().is_match(&cmd) || cmd == "py" {
        if let Some(mi) = rest.iter().position(|a| a == "-m") {
            if let Some(m) = rest.get(mi + 1).filter(|s| !s.is_empty()) {
                return (if m.to_lowercase().contains("mcp") { Launch::PypiInferred } else { Launch::Unknown }, None);
            }
        }
        return (if first_non_flag(rest).is_some() { Launch::Local } else { Launch::Unknown }, None);
    }
    if cmd == "docker" || cmd == "podman" {
        let img = rest.iter().position(|a| a == "run").and_then(|ri| docker_image(&rest[ri + 1..]));
        return (img.map(Launch::Docker).unwrap_or(Launch::Unknown), None);
    }
    if ["node", "deno", "bun", "tsx", "ts-node"].contains(&cmd.as_str()) {
        let p = if r0 == Some("run") { first_non_flag(&rest[1..]) } else { first_non_flag(rest) };
        return (if p.is_some() { Launch::Local } else { Launch::Unknown }, None);
    }
    if cmd == "uv" && r0 == Some("run") { return (Launch::Local, None); }
    if is_path_like(&argv[0]) { return (Launch::Local, None); }
    (Launch::Unknown, None)
}

fn unwrap_guard(argv: Vec<String>) -> Vec<String> {
    let Some(i) = argv.iter().position(|a| re_guard().is_match(a)) else { return argv };
    match argv.iter().skip(i).position(|a| a == "--") { Some(off) => argv[i + off + 1..].to_vec(), None => argv }
}

// ---- pkg-report.mjs mirror ---------------------------------------------------------------------------

fn decl_argv(cfg: &Value) -> Option<Vec<String>> {
    let cmd = cfg.get("command").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty())?;
    let args: Vec<String> = cfg.get("args").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    if cfg.get("args").is_none() && cmd.trim().chars().any(char::is_whitespace) { return Some(split_command(cmd)); }
    let mut v = vec![cmd.to_string()];
    v.extend(args);
    Some(v)
}

fn pypi_version_spec(token: &str) -> (Option<String>, bool) {
    let t = token.trim();
    let rest = re_py_rest().captures(t).and_then(|c| c.get(1)).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
    if rest.is_empty() { return (None, false); }
    let op = if rest.starts_with("===") { 3 } else if rest.starts_with("==") { 2 } else if rest.starts_with('@') { 1 } else { 0 };
    if op == 0 { return (Some(rest), false); }
    let v = rest[op..].trim().to_string();
    if v.is_empty() { return (None, false); }
    let pinned = v != "latest" && re_py_exact().is_match(&v);
    (Some(v), pinned)
}

fn docker_pkg(image: &str) -> Value {
    let mut s = image.trim().to_string();
    let mut digest: Option<String> = None;
    if let Some(at) = s.find('@') { digest = Some(s[at + 1..].to_string()); s.truncate(at); }
    let mut tag: Option<String> = None;
    let slash = s.rfind('/');
    if let Some(colon) = s.rfind(':') { if slash.map(|sl| colon > sl).unwrap_or(true) { tag = Some(s[colon + 1..].to_string()); s.truncate(colon); } }
    let first = s.split('/').next().unwrap_or("").to_string();
    let host = s.contains('/') && (first.contains('.') || first.contains(':') || first == "localhost");
    let public = !host || PUBLIC_REGISTRIES.contains(&first.to_lowercase().as_str());
    let pinned = digest.as_deref().map(|d| d.len() == 71 && d.starts_with("sha256:") && d[7..].chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))).unwrap_or(false);
    if !public { return json!({ "eco": "docker", "name": null, "version": null, "pinned": pinned }); }
    let repo = s.to_lowercase();
    if pinned {
        let name = format!("{repo}{}@{}", tag.map(|t| format!(":{t}")).unwrap_or_default(), digest.unwrap_or_default());
        return json!({ "eco": "docker", "name": name, "version": null, "pinned": true });
    }
    json!({ "eco": "docker", "name": repo, "version": tag, "pinned": false })
}

fn unparsed_eco(spec: Option<&str>) -> &'static str {
    let t = spec.unwrap_or("").trim();
    if t.is_empty() { return "other"; }
    if t.get(..5).map(|p| p.eq_ignore_ascii_case("file:")).unwrap_or(false) { return "local"; }
    if t.contains("://") || re_unparsed_remote().is_match(t) { return "other"; }
    if is_path_like(t) || re_local_archive().is_match(t) { return "local"; }
    "other"
}

fn clean_name(eco: &str, v: &Value) -> Value {
    let Some(s) = v.as_str() else { return Value::Null };
    let ok = s.chars().count() <= MAX_NAME && match eco { "npm" => re_npm_name().is_match(s), "pypi" => re_py_name().is_match(s), "docker" => re_docker_name().is_match(s), _ => false };
    if ok { Value::String(s.to_string()) } else { Value::Null }
}
fn clean_version(v: &Value) -> Value {
    match v.as_str() { Some(s) if !s.is_empty() && s.chars().count() <= MAX_VERSION && re_version().is_match(s) && !s.starts_with(['/', '.', '~']) => Value::String(s.to_string()), _ => Value::Null }
}
fn clean_count(v: &Value) -> Value {
    match v.as_f64() { Some(f) if v.is_number() && f.is_finite() && f.fract() == 0.0 && f >= 1.0 => json!(f.min(MAX_MAINTAINERS) as i64), _ => Value::Null }
}
fn clean_scan(s: &Value) -> Value {
    let Some(verdict) = s.get("verdict").and_then(|v| v.as_str()).filter(|v| ["clean", "warn", "block"].contains(v)) else { return Value::Null };
    let set: BTreeSet<String> = s.get("findings").and_then(|f| f.as_array()).map(|a| a.iter().filter_map(|x| x.as_str())
        .filter(|c| vocab().contains(*c) || re_threat().is_match(c)).map(str::to_string).collect()).unwrap_or_default();
    json!({ "verdict": verdict, "findings": set.into_iter().take(MAX_FINDINGS).collect::<Vec<_>>() })
}

// Any value → the contract's pkg, every field validated.
pub fn clamp(p: &Value) -> Value {
    let eco = match p.get("eco").and_then(|v| v.as_str()) { Some(e @ ("npm" | "pypi" | "docker" | "local" | "other")) => e, _ => "other" };
    let reg = matches!(eco, "npm" | "pypi" | "docker");
    let meta = matches!(eco, "npm" | "pypi");
    let null = Value::Null;
    let g = |k: &str| p.get(k).unwrap_or(&null);
    json!({
        "eco": eco,
        "name": if reg { clean_name(eco, g("name")) } else { Value::Null },
        "version": if reg { clean_version(g("version")) } else { Value::Null },
        "pinned": if reg && g("pinned").is_boolean() { g("pinned").clone() } else { Value::Null },
        "maintainers": if meta { clean_count(g("maintainers")) } else { Value::Null },
        "maintainersOrg": if meta && g("maintainersOrg").is_boolean() { g("maintainersOrg").clone() } else { Value::Null },
        "scan": if meta { clean_scan(g("scan")) } else { Value::Null },
    })
}

// An MCP server config entry → pkg (maintainers and scan null). The config is never copied out.
pub fn derive(cfg: &Value) -> Value {
    if cfg.get("url").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false) { return clamp(&json!({ "eco": "other" })); }
    let Some(argv) = decl_argv(cfg) else { return clamp(&json!({ "eco": "other" })) };
    let (launch, spec) = launch_spec(&unwrap_guard(argv));
    match launch {
        Launch::Npm(name, version) => {
            let pinned = version.as_deref().map(|v| re_exact_semver().is_match(v)).unwrap_or(false);
            clamp(&json!({ "eco": "npm", "name": name, "version": version, "pinned": pinned }))
        }
        Launch::Pypi(name) => {
            let (version, pinned) = pypi_version_spec(spec.as_deref().unwrap_or(""));
            clamp(&json!({ "eco": "pypi", "name": name, "version": version, "pinned": pinned }))
        }
        Launch::Docker(img) => clamp(&docker_pkg(&img)),
        Launch::Local => clamp(&json!({ "eco": "local" })),
        Launch::PypiInferred => clamp(&json!({ "eco": "other" })),
        Launch::Unknown => clamp(&json!({ "eco": unparsed_eco(spec.as_deref()) })),
    }
}

fn pkg_key(pkg: &Value) -> Option<String> {
    let eco = pkg.get("eco").and_then(|v| v.as_str()).filter(|e| *e == "npm" || *e == "pypi")?;
    let name = pkg.get("name").and_then(|v| v.as_str()).filter(|s| !s.is_empty())?;
    let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("");
    Some(format!("{eco}:{}@{version}", name.to_lowercase()))
}

// ~/.moorai/mcp-pkg.json, or an empty cache when absent or not the expected shape.
pub fn read_cache(home: &str) -> Value {
    let empty = json!({ "v": 1, "entries": {} });
    let Ok(txt) = std::fs::read_to_string(std::path::Path::new(home).join(".moorai").join(PKG_CACHE_FILE)) else { return empty };
    match serde_json::from_str::<Value>(&txt) {
        Ok(c) if c.get("v").and_then(|v| v.as_i64()) == Some(1) && c.get("entries").map(|e| e.is_object()).unwrap_or(false) => c,
        _ => empty,
    }
}

fn fresh(x: Option<&Value>, now: f64) -> bool {
    let Some(at) = x.filter(|x| x.is_object()).and_then(|x| x.get("at")).and_then(|a| a.as_f64()) else { return false };
    at.is_finite() && now - at <= TTL_MS && at - now <= FUTURE_SKEW_MS
}

// pkg + the cache → pkg with the fresh maintainer count and scan verdict, clamped again.
pub fn with_meta(pkg: Value, cache: &Value, now_ms: f64) -> Value {
    let Some(key) = pkg_key(&pkg) else { return pkg };
    let Some(e) = cache.get("entries").and_then(|m| m.get(&key)).filter(|e| e.is_object()) else { return pkg };
    let mut out: Map<String, Value> = pkg.as_object().cloned().unwrap_or_default();
    let m = e.get("m").filter(|m| fresh(Some(m), now_ms) && !clean_count(m.get("count").unwrap_or(&Value::Null)).is_null());
    if let Some(m) = m {
        out.insert("maintainers".into(), m.get("count").cloned().unwrap_or(Value::Null));
        out.insert("maintainersOrg".into(), Value::Bool(m.get("org").and_then(|o| o.as_bool()) == Some(true)));
    }
    if fresh(e.get("s"), now_ms) {
        let s = clean_scan(e.get("s").unwrap_or(&Value::Null));
        if !s.is_null() { out.insert("scan".into(), s); }
    }
    clamp(&Value::Object(out))
}

pub fn now_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0)
}

// The device report's entry point: one server's pkg.
pub fn pkg_for(cfg: &Value, cache: &Value, now_ms: f64) -> Value { with_meta(derive(cfg), cache, now_ms) }

#[cfg(test)]
mod tests {
    use super::*;

    const CASES: &str = include_str!("../../test/fixtures/mcp-pkg-cases.json");
    const CACHE: &str = include_str!("../../test/fixtures/mcp-pkg-cache.json");

    #[test]
    fn shared_fixture_matches_node() {
        let fx: Value = serde_json::from_str(CASES).unwrap();
        let cases = fx["cases"].as_array().unwrap();
        assert!(cases.len() >= 40);
        for c in cases {
            let p = derive(&c["decl"]);
            for k in ["eco", "name", "version", "pinned"] { assert_eq!(p[k], c["pkg"][k], "{} {k}: {p}", c["id"]); }
            for k in ["maintainers", "maintainersOrg", "scan"] { assert!(p[k].is_null(), "{} {k}", c["id"]); }
            assert_eq!(p.as_object().unwrap().len(), 7);
        }
    }

    #[test]
    fn shared_cache_fixture_matches_node() {
        let fx: Value = serde_json::from_str(CACHE).unwrap();
        let now = fx["now"].as_f64().unwrap();
        for c in fx["cases"].as_array().unwrap() {
            let p = pkg_for(&c["decl"], &fx["cache"], now);
            for k in ["maintainers", "maintainersOrg", "scan"] { assert_eq!(p[k], c[k], "{} {k}: {p}", c["id"]); }
        }
    }

    #[test]
    fn clamps_every_field() {
        let good = json!({ "eco": "npm", "name": "srv", "version": "1.0.0", "pinned": true, "maintainers": 2, "maintainersOrg": false, "scan": { "verdict": "clean", "findings": [] } });
        assert_eq!(clamp(&good), good);
        let with = |k: &str, v: Value| { let mut g = good.clone(); g[k] = v; clamp(&g) };
        assert_eq!(with("eco", json!("rubygems"))["eco"], "other");
        assert!(with("eco", json!("rubygems"))["name"].is_null());
        assert!(with("name", json!("a".repeat(215)))["name"].is_null());
        assert_eq!(with("name", json!("a".repeat(214)))["name"], json!("a".repeat(214)));
        assert!(with("name", json!("/Users/alice/x"))["name"].is_null());
        assert!(with("version", json!("1".repeat(65)))["version"].is_null());
        assert!(with("version", json!("git+https://x"))["version"].is_null());
        assert_eq!(with("maintainers", json!(50000))["maintainers"], 1000);
        assert_eq!(with("maintainers", json!(3.0))["maintainers"], 3);
        for bad in [json!(-1), json!(0), json!(1.5), json!("3"), Value::Null, json!({})] { assert!(with("maintainers", bad.clone())["maintainers"].is_null(), "{bad}"); }
        let codes: Vec<Value> = vocab().iter().map(|c| json!(c)).chain([json!("threat-60"), json!("rm -rf /"), json!("/Users/alice")]).collect();
        let many = with("scan", json!({ "verdict": "warn", "findings": codes }));
        assert_eq!(many["scan"]["findings"].as_array().unwrap().len(), 32);
        assert!(with("scan", json!({ "verdict": "evil", "findings": [] }))["scan"].is_null());
        let loc = clamp(&json!({ "eco": "local", "name": "secret-dir", "version": "1.0.0", "pinned": true, "maintainers": 3, "maintainersOrg": true, "scan": { "verdict": "clean", "findings": [] } }));
        assert_eq!(loc, json!({ "eco": "local", "name": null, "version": null, "pinned": null, "maintainers": null, "maintainersOrg": null, "scan": null }));
    }

    #[test]
    fn vocabulary_is_loaded() {
        assert!(vocab().contains("single-maintainer") && vocab().contains("pkg-remote-code") && vocab().len() >= 30);
    }

    #[test]
    fn content_free() {
        let cfg = json!({ "command": "/usr/local/bin/npx", "args": ["-y", "--registry", "https://registry.internal.corp/npm", "@acme/weather-mcp@2.1.0", "--token", "SECRET-ARG-9Z", "/Users/alice/clients/merger"], "env": { "ACME_API_KEY": "sk-live-ENVVALUE-3" } });
        let p = derive(&cfg);
        assert_eq!(p["name"], "@acme/weather-mcp");
        assert_eq!(p["pinned"], true);
        let s = p.to_string();
        for leak in ["npx", "/usr/local", "internal.corp", "SECRET-ARG-9Z", "/Users", "ACME_API_KEY", "sk-live", "--token"] { assert!(!s.contains(leak), "leaked {leak}: {s}"); }
    }

    #[test]
    fn reads_the_cache_file_from_home() {
        let dir = std::env::temp_dir().join(format!("moorai-rs-pkg-{}-{}", std::process::id(), now_ms() as u64));
        std::fs::create_dir_all(dir.join(".moorai")).unwrap();
        let home = dir.to_string_lossy().to_string();
        assert_eq!(read_cache(&home), json!({ "v": 1, "entries": {} }), "absent → empty");
        std::fs::write(dir.join(".moorai").join(PKG_CACHE_FILE), "not json").unwrap();
        assert_eq!(read_cache(&home), json!({ "v": 1, "entries": {} }), "unreadable → empty");
        let fx: Value = serde_json::from_str(CACHE).unwrap();
        std::fs::write(dir.join(".moorai").join(PKG_CACHE_FILE), fx["cache"].to_string()).unwrap();
        let p = pkg_for(&json!({ "command": "npx", "args": ["-y", "@scope/srv@1.4.2"] }), &read_cache(&home), fx["now"].as_f64().unwrap());
        assert_eq!(p["maintainers"], 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
