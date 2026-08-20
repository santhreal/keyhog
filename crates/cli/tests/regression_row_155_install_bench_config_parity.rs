//! WHY THIS TEST EXISTS:
//! Row 155 / Installation and benchmark harness configuration parity:
//! Crate feature definitions (`crates/cli/Cargo.toml`, `crates/scanner/Cargo.toml`),
//! benchmark harness defaults (`benchmarks/bench/scanners/keyhog.py`, `benchmarks/cross_device.sh`),
//! and user documentation (`README.md`, `docs/src/install.md`, `benchmarks/README.md`)
//! must maintain strict parity.
//!
//! 1. Default CLI install must be pure-Rust portable CPU (`default = ["portable"]`),
//!    ensuring zero-system-dependency installation out of the box on clean Rust hosts.
//! 2. Benchmark suite default configuration (`simd-nocache-nodaemon-full`) requires
//!    the Hyperscan / Vectorscan SIMD regex engine, and the harness fails loudly
//!    without silent fallbacks when candidate binaries lack required SIMD acceleration.
//! 3. Installation documentation explicitly reflects both `--features portable` and
//!    `--features portable,simd` commands.
//! 4. Missing SIMD backend initialization fails closed with honest error messages.

use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("navigate from crates/cli to workspace root")
        .to_path_buf()
}

#[test]
fn manifest_default_features_and_bench_simd_parity() {
    let root = workspace_root();

    // 1. crates/cli/Cargo.toml default features must be ["portable"]
    let cli_cargo =
        fs::read_to_string(root.join("crates/cli/Cargo.toml")).expect("read crates/cli/Cargo.toml");
    assert!(
        cli_cargo.contains(r#"default = ["portable"]"#),
        "crates/cli/Cargo.toml default must be portable pure-Rust: default = [\"portable\"]"
    );
    assert!(
        cli_cargo.contains(r#"gpu = ["keyhog-scanner/gpu"]"#),
        "crates/cli/Cargo.toml must wire gpu feature to keyhog-scanner/gpu"
    );
    assert!(
        cli_cargo.contains(r#"simd = ["keyhog-scanner/simd"]"#),
        "crates/cli/Cargo.toml must wire simd feature to keyhog-scanner/simd"
    );

    // 2. crates/scanner/Cargo.toml feature declarations
    let scanner_cargo = fs::read_to_string(root.join("crates/scanner/Cargo.toml"))
        .expect("read crates/scanner/Cargo.toml");
    assert!(
        scanner_cargo.contains(r#"simd = ["dep:hyperscan"]"#)
            || scanner_cargo.contains(r#"simd = ["hyperscan"]"#),
        "crates/scanner/Cargo.toml must declare simd feature linking to hyperscan"
    );
    assert!(
        scanner_cargo.contains(r#"ci-lean ="#) && scanner_cargo.contains(r#""simd""#),
        "crates/scanner/Cargo.toml ci-lean feature must include simd"
    );
}

#[test]
fn benchmark_harness_and_scripts_declare_simd_parity() {
    let root = workspace_root();

    // 1. benchmarks/bench/scanners/keyhog.py
    let keyhog_py = fs::read_to_string(root.join("benchmarks/bench/scanners/keyhog.py"))
        .expect("read benchmarks/bench/scanners/keyhog.py");
    assert!(
        keyhog_py.contains("simd-nocache-nodaemon-full"),
        "keyhog.py must declare simd-nocache-nodaemon-full as primary variant"
    );
    assert!(
        keyhog_py.contains("--features simd"),
        "keyhog.py must reference --features simd for building benchmark candidates"
    );
    assert!(
        keyhog_py.contains("resolve_keyhog_binary"),
        "keyhog.py must use resolve_keyhog_binary for binary resolution"
    );

    // 2. benchmarks/cross_device.sh
    let cross_device = fs::read_to_string(root.join("benchmarks/cross_device.sh"))
        .expect("read benchmarks/cross_device.sh");
    assert!(
        cross_device.contains("KH_FEAT=\"--no-default-features --features portable\""),
        "cross_device.sh must specify portable for Darwin"
    );
    assert!(
        cross_device.contains("KH_FEAT=\"--features simd\""),
        "cross_device.sh must default Linux remote installations to --features simd"
    );
}

#[test]
fn documentation_reflects_portable_and_simd_install_commands() {
    let root = workspace_root();

    // 1. README.md
    let readme = fs::read_to_string(root.join("README.md")).expect("read README.md");
    assert!(
        readme.contains(
            "cargo install --locked keyhog --no-default-features --features portable,simd"
        ),
        "README.md must document SIMD installation command"
    );
    assert!(
        readme.contains(
            "cargo install --locked keyhog --no-default-features --features portable,gpu"
        ),
        "README.md must document GPU installation command"
    );

    // 2. benchmarks/README.md
    let bench_readme =
        fs::read_to_string(root.join("benchmarks/README.md")).expect("read benchmarks/README.md");
    assert!(
        bench_readme.contains("cargo build --release -p keyhog --features simd"),
        "benchmarks/README.md must document cargo build --release -p keyhog --features simd"
    );
    assert!(
        bench_readme.contains("/mnt/FlareTraining/santh-archive/cargo-target"),
        "benchmarks/README.md must document archive target directory resolution"
    );
}

#[test]
fn runtime_simd_parity_contract() {
    use keyhog_scanner::CompiledScanner;

    // Compile a minimal real non-empty DetectorSpec from embedded specs
    let detectors = keyhog_core::embedded_detector_specs()
        .iter()
        .take(1)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        !detectors.is_empty(),
        "embedded detector specs must be non-empty"
    );

    let scanner = CompiledScanner::compile(detectors).expect("compile scanner with detector spec");

    // Verify fail-closed behavior vs availability
    if scanner.simd_backend_available() {
        let init_result = scanner.initialize_simd_backend();
        assert!(
            init_result.is_ok(),
            "SIMD backend initialization must succeed when simd_backend_available() is true"
        );
    } else {
        let init_result = scanner.initialize_simd_backend();
        assert!(
            init_result.is_err(),
            "SIMD backend initialization must fail closed when not available"
        );
        let err_msg = init_result.unwrap_err();
        assert!(
            err_msg.contains("this scanner build has no Hyperscan/SIMD backend")
                || err_msg.contains("the detector corpus produced no Hyperscan phase-one plan"),
            "unexpected error message on missing SIMD backend: {err_msg}"
        );
    }
}
