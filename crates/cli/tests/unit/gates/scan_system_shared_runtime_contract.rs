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
}
