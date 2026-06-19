use keyhog_scanner::hw_probe::testing::{parse_backend_str, ScanBackend};

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

    // MegaScan arm. BOTH `mega-scan` and `megascan` are advertised `--backend`
    // values (clap `PossibleValuesParser` in `args/scan.rs`); the no-hyphen form
    // was previously unrecognized here, so `--backend megascan` silently fell
    // through to auto-routing. The canonical parser must accept every advertised
    // spelling (coherence — the gpu-init policy and the routing both delegate
    // here, so a dropped alias split the CLI flag's two effects).
    assert_eq!(parse_backend_str("mega-scan"), Some(ScanBackend::MegaScan));
    assert_eq!(parse_backend_str("megascan"), Some(ScanBackend::MegaScan));
    assert_eq!(
        parse_backend_str("gpu-mega-scan"),
        Some(ScanBackend::MegaScan)
    );
    assert_eq!(parse_backend_str("regex-nfa"), Some(ScanBackend::MegaScan));
    assert_eq!(
        parse_backend_str("rule-pipeline"),
        Some(ScanBackend::MegaScan)
    );

    // SIMD/CPU arms and the case-insensitive contract.
    assert_eq!(parse_backend_str("simd"), Some(ScanBackend::SimdCpu));
    assert_eq!(parse_backend_str("simd-regex"), Some(ScanBackend::SimdCpu));
    assert_eq!(parse_backend_str("hyperscan"), Some(ScanBackend::SimdCpu));
    assert_eq!(parse_backend_str("cpu"), Some(ScanBackend::CpuFallback));
    assert_eq!(
        parse_backend_str("cpu-fallback"),
        Some(ScanBackend::CpuFallback)
    );
    assert_eq!(parse_backend_str("scalar"), Some(ScanBackend::CpuFallback));
    assert_eq!(parse_backend_str("MegaScan"), Some(ScanBackend::MegaScan));

    // Unknown strings (and `auto`, which means "defer to the router") are not
    // backends this parser names.
    assert_eq!(parse_backend_str("auto"), None);
    assert_eq!(parse_backend_str("garbage-value"), None);
}
