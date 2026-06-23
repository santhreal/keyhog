#[test]
fn args_config_surface_has_one_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let args = std::fs::read_to_string(root.join("src/args.rs")).expect("args.rs readable");
    let config =
        std::fs::read_to_string(root.join("src/args/config.rs")).expect("config.rs readable");

    assert!(
        args.contains("mod config;") && args.contains("pub use config::ConfigArgs;"),
        "args.rs must re-export config command args from the config module"
    );

    assert!(
        config.contains("pub struct ConfigArgs"),
        "args/config.rs must own `ConfigArgs`"
    );
    assert!(
        !args.contains("pub struct ConfigArgs"),
        "args.rs must not re-own `ConfigArgs` after the config split"
    );
}
