#[test]
fn args_hook_surface_has_one_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let args = std::fs::read_to_string(root.join("src/args.rs")).expect("args.rs readable");
    let hook = std::fs::read_to_string(root.join("src/args/hook.rs")).expect("hook.rs readable");

    assert!(
        args.contains("mod hook;") && args.contains("pub use hook::HookCommand;"),
        "args.rs must re-export hook command args from the hook module"
    );
    assert!(
        hook.contains("pub enum HookCommand"),
        "args/hook.rs must own `HookCommand`"
    );
    assert!(
        !args.contains("pub enum HookCommand"),
        "args.rs must not re-own `HookCommand` after the hook split"
    );
}
