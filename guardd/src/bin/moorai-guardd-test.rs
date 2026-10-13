//! Unprivileged test daemon (contract §11.2): the real helper over `Paths::under(<root>)`. Built only
//! with `--features test-injection`; refuses to run as root/SYSTEM (Helper::new).
//!
//!   cargo run --features test-injection --bin moorai-guardd-test -- --root <dir>

use moorai_guardd::helper::Helper;
use moorai_guardd::state::Paths;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = match args.as_slice() {
        [flag, dir] if flag == "--root" => std::path::PathBuf::from(dir),
        _ => {
            eprintln!("usage: moorai-guardd-test --root <dir>");
            std::process::exit(2);
        }
    };
    match Helper::new(Paths::under(&root)).and_then(|h| h.run()) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("moorai-guardd-test: {e:?}");
            std::process::exit(1);
        }
    }
}
