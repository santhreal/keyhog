use keyhog_scanner::hw_probe::{parse_backend_str, ScanBackend};

#[test]
fn forced_backend_gpu_env() {
    // Pure string→backend mapping assertion. This must NOT mutate the global
    // `KEYHOG_BACKEND` env var: a global set to a GPU value races with every
    // concurrent scan in the parallel `all_tests` pool, and gpu_forced reacts to
    // a forced-but-unavailable GPU by exiting the whole process (harness abort).
    // `parse_backend_str` is the single source of truth the env path delegates to.
    assert_eq!(parse_backend_str("gpu"), Some(ScanBackend::Gpu));
    assert_eq!(parse_backend_str("gpu-zero-copy"), Some(ScanBackend::Gpu));
    assert_eq!(parse_backend_str("literal-set"), Some(ScanBackend::Gpu));
}
