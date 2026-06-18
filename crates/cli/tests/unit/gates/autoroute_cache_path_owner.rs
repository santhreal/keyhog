#[test]
fn autoroute_cache_path_resolution_has_one_fail_closed_owner() {
    let backend = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch/backend.rs"
    ))
    .expect("backend router source readable");
    let cache_path = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/autoroute_cache_path.rs"
    ))
    .expect("autoroute cache path source readable");
    let orchestrator_config = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator_config.rs"
    ))
    .expect("orchestrator config source readable");

    assert!(
        !backend.contains("mod cache_path;")
            && backend.contains("autoroute_cache_path: Result<Option<PathBuf>, String>"),
        "backend router must receive the resolved autoroute cache path instead of owning path parsing"
    );
    assert!(
        !backend.contains("std::env::var(\"KEYHOG_AUTOROUTE_CACHE\")")
            && !backend.contains("std::env::var_os(\"KEYHOG_AUTOROUTE_CACHE\")")
            && !backend.contains("autoroute_cache_path_for"),
        "backend router must not parse legacy autoroute cache env directly"
    );
    assert!(
        cache_path.contains("Result<Option<PathBuf>, String>")
            && cache_path.contains("--autoroute-cache <PATH|off>")
            && cache_path.contains("[system].autoroute_cache")
            && cache_path.contains("must be an absolute file path")
            && cache_path.contains("platform cache directory"),
        "autoroute cache path owner must fail closed for relative paths and missing defaults"
    );
    assert!(
        !cache_path.contains("using the default autoroute cache path")
            && !cache_path.contains("unwrap_or")
            && !cache_path.contains(".ok()"),
        "autoroute cache path owner must not silently default or mask parse errors"
    );
    assert!(
        orchestrator_config.contains("crate::autoroute_cache_path::resolve_autoroute_cache_path")
            && backend.contains("Some(error)")
            && backend.contains("self.persist_cache_path()?"),
        "router must preserve cache path errors and refuse calibration before non-durable probes"
    );
}
