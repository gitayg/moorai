//! moorai-guardd entry point. Takes NO arguments and reads NO environment that could change a path,
//! an origin or a key (contract §10.2); the only accepted argument is `--build-info`, which prints
//! the version and whether the test-injection feature was compiled in (CI asserts it was not).

use moorai_guardd::helper::Helper;
use moorai_guardd::state::Paths;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 1 && args[0] == "--build-info" {
        println!(
            "moorai-guardd {} test-injection={}",
            moorai_guardd::HELPER_VERSION,
            cfg!(feature = "test-injection")
        );
        return;
    }
    if !args.is_empty() {
        eprintln!("moorai-guardd takes no arguments");
        std::process::exit(2);
    }
    match Helper::new(Paths::system()).and_then(|h| h.run()) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("moorai-guardd: {e:?}");
            std::process::exit(1);
        }
    }
}
