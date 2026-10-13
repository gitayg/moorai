//! The packaged entry point (contract §10.2): no arguments but `--build-info`, and the system paths
//! refuse an unprivileged process before touching any state.
#![cfg(unix)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_moorai-guardd");

#[test]
fn build_info_reports_whether_test_injection_was_compiled_in() {
    let out = Command::new(BIN).arg("--build-info").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(s.trim(), format!("moorai-guardd {} test-injection={}", env!("CARGO_PKG_VERSION"), cfg!(feature = "test-injection")));
}

#[test]
fn any_other_argument_is_refused() {
    let out = Command::new(BIN).args(["--root", "/tmp/x"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn an_unprivileged_run_refuses_the_system_paths() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let out = Command::new(BIN).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Unprivileged"), "{}", String::from_utf8_lossy(&out.stderr));
}
