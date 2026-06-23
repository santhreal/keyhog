#[test]
fn args_daemon_surface_has_one_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let args = std::fs::read_to_string(root.join("src/args.rs")).expect("args.rs readable");
    let daemon =
        std::fs::read_to_string(root.join("src/args/daemon.rs")).expect("daemon.rs readable");

    assert!(
        args.contains("mod daemon;")
            && args.contains("pub use daemon::{DaemonAction, DaemonArgs};"),
        "args.rs must re-export daemon command args from the daemon module"
    );

    for owned in ["pub struct DaemonArgs", "pub enum DaemonAction"] {
        assert!(daemon.contains(owned), "args/daemon.rs must own `{owned}`");
        assert!(
            !args.contains(owned),
            "args.rs must not re-own `{owned}` after the daemon split"
        );
    }
}
