#[test]
fn args_command_modules_have_one_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let args = std::fs::read_to_string(root.join("src/args.rs")).expect("args.rs readable");

    for (module, reexports, owned) in [
        (
            "scan_system",
            &[
                "pub use scan_system::{",
                "parse_space_bytes",
                "ScanSystemArgs",
            ][..],
            "pub struct ScanSystemArgs",
        ),
        (
            "watch",
            &["pub use watch::WatchArgs;"][..],
            "pub struct WatchArgs",
        ),
        (
            "calibrate",
            &["pub use calibrate::CalibrateArgs;"][..],
            "pub struct CalibrateArgs",
        ),
        (
            "diff",
            &["pub use diff::DiffArgs;"][..],
            "pub struct DiffArgs",
        ),
        (
            "explain",
            &["pub use explain::ExplainArgs;"][..],
            "pub struct ExplainArgs",
        ),
    ] {
        let module_path = root.join(format!("src/args/{module}.rs"));
        let module_src = std::fs::read_to_string(&module_path)
            .unwrap_or_else(|error| panic!("{} readable: {error}", module_path.display()));

        assert!(
            args.contains(&format!("mod {module};"))
                && reexports.iter().all(|reexport| args.contains(reexport)),
            "args.rs must declare and re-export `{module}` through {reexports:?}"
        );
        assert!(
            module_src.contains(owned),
            "args/{module}.rs must own `{owned}`"
        );
        assert!(
            !args.contains(owned),
            "args.rs must not re-own `{owned}` after the command module split"
        );
    }
}
