#[test]
fn scan_system_uses_shared_scan_runtime_boundary() {
    let scan_system = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/scan_system.rs"
    ))
    .expect("scan_system source readable");
    let orchestrator = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/mod.rs"
    ))
    .expect("orchestrator source readable");

    for required in [
        "struct DefaultScanRuntime",
        "fn compile_default_scan_runtime(",
        "fn scan_chunk(&self, chunk: &Chunk)",
        "self.router.choose(None, std::slice::from_ref(chunk))",
        "self.scanner.scan_with_backend(chunk, backend)",
    ] {
        assert!(
            orchestrator.contains(required),
            "orchestrator must own default scan runtime detail `{required}`"
        );
    }

    for required in [
        "use crate::orchestrator::{DefaultScanRuntime, compile_default_scan_runtime};",
        "let scan_runtime = compile_default_scan_runtime(",
        "scan_runtime.warm();",
        "scan_runtime.scan_chunk(&chunk)?",
        "fn scan_source_chunks(",
        "\"filesystem\"",
        "\"git-history\"",
    ] {
        assert!(
            scan_system.contains(required),
            "scan_system must delegate through shared scan runtime `{required}`"
        );
    }

    for forbidden in [
        "cached_autoroute_router_for_default_config(",
        "router.choose(",
        "scan_with_backend(&chunk, backend)",
    ] {
        assert!(
            !scan_system.contains(forbidden),
            "scan_system must not re-own default runtime routing detail `{forbidden}`"
        );
    }

    let scan_mount = scan_system
        .split("fn scan_mount(")
        .nth(1)
        .and_then(|tail| tail.split("fn scan_git_history(").next())
        .expect("scan_mount body extractable");
    let scan_git_history = scan_system
        .split("fn scan_git_history(")
        .nth(1)
        .and_then(|tail| tail.split("#[cfg(not(feature = \"git\"))]").next())
        .expect("scan_git_history body extractable");
    for body in [scan_mount, scan_git_history] {
        assert!(
            !body.contains(".chunks()"),
            "scan_mount/scan_git_history must delegate chunk iteration to scan_source_chunks"
        );
        assert!(
            !body.contains("record_skipped_chunk()"),
            "scan_mount/scan_git_history must not duplicate skipped-chunk accounting"
        );
    }
}
