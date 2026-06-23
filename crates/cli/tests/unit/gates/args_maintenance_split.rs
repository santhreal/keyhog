#[test]
fn args_maintenance_surfaces_have_one_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let args = std::fs::read_to_string(root.join("src/args.rs")).expect("args.rs readable");
    let maintenance = std::fs::read_to_string(root.join("src/args/maintenance.rs"))
        .expect("args/maintenance.rs readable");

    assert!(
        args.contains("mod maintenance;")
            && args.contains(
                "pub use maintenance::{\n    BackendArgs, CompletionArgs, DoctorArgs, RepairArgs, UninstallArgs, UpdateArgs,"
            ),
        "args.rs must re-export maintenance command args from the maintenance module"
    );

    for owned in [
        "pub struct CompletionArgs",
        "pub struct BackendArgs",
        "pub struct DoctorArgs",
        "pub struct UpdateArgs",
        "pub struct RepairArgs",
        "pub struct UninstallArgs",
    ] {
        assert!(
            maintenance.contains(owned),
            "args/maintenance.rs must own `{owned}`"
        );
        assert!(
            !args.contains(owned),
            "args.rs must not re-own `{owned}` after the maintenance split"
        );
    }
}
