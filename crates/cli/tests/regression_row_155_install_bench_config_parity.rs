//! WHY THIS TEST EXISTS:
//! Row 155 / Installation and benchmark harness configuration parity:
//! Crate feature definitions (`crates/cli/Cargo.toml`, `crates/scanner/Cargo.toml`),
//! benchmark harness defaults (`benchmarks/bench/scanners/keyhog.py`, `benchmarks/cross_device.sh`),
//! and user documentation (`README.md`, `docs/src/install.md`, `benchmarks/README.md`)
//! must maintain strict parity.
//!
//! Specifically:
//! 1. Default CLI install must be pure-Rust `portable` (no native C/C++ or driver prerequisites).
//! 2. Accelerator features (`simd`, `gpu`) are explicit opt-ins in the CLI.
//! 3. The benchmark runner default configuration (`simd-nocache-nodaemon-full`) requires `simd`
//!    and must be coherently documented across install instructions, build scripts, and harness files.
//! 4. Non-SIMD builds must fail closed on explicit `--backend simd` rather than silently degrading.
//!
//! WHAT IT DOES NOT CATCH:
//! Physical host hardware differences or uninstalled system library linkage at link time.

use std::collections::BTreeMap;
use std::path::Path;
use toml::Value;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
}

fn load_features_from_manifest(manifest_path: &Path) -> BTreeMap<String, Vec<String>> {
    let content = std::fs::read_to_string(manifest_path)
        .unwrap_or_else(|e| panic!("Failed to read {manifest_path:?}: {e}"));
    let parsed: Value = toml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse TOML {manifest_path:?}: {e}"));

    let mut result = BTreeMap::new();
    if let Some(features_table) = parsed.get("features").and_then(|f| f.as_table()) {
        for (name, values) in features_table {
            let deps = values
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            result.insert(name.clone(), deps);
        }
    }
    result
}

#[test]
fn cli_default_is_portable_and_excludes_native_simd_gpu_prerequisites() {
    let root = repo_root();
    let cli_manifest = root.join("crates/cli/Cargo.toml");
    let features = load_features_from_manifest(&cli_manifest);

    let default = features
        .get("default")
        .expect("CLI Cargo.toml must declare default feature");
    assert_eq!(
        default,
        &vec!["portable".to_string()],
        "CLI default feature must be exactly ['portable'] so `cargo install keyhog` works on clean Rust hosts"
    );

    let portable = features
        .get("portable")
        .expect("CLI Cargo.toml must declare portable feature");
    assert!(
        !portable.contains(&"simd".to_string())
            && !portable.contains(&"keyhog-scanner/simd".to_string()),
        "portable feature must not pull simd/Hyperscan dependency"
    );
    assert!(
        !portable.contains(&"gpu".to_string())
            && !portable.contains(&"keyhog-scanner/gpu".to_string()),
        "portable feature must not pull gpu dependency"
    );

    let simd = features
        .get("simd")
        .expect("CLI Cargo.toml must declare simd feature");
    assert_eq!(
        simd,
        &vec!["keyhog-scanner/simd".to_string()],
        "simd feature must wire keyhog-scanner/simd"
    );

    let gpu = features
        .get("gpu")
        .expect("CLI Cargo.toml must declare gpu feature");
    assert_eq!(
        gpu,
        &vec!["keyhog-scanner/gpu".to_string()],
        "gpu feature must wire keyhog-scanner/gpu"
    );
}

#[test]
fn scanner_manifest_declares_engine_features_coherently() {
    let root = repo_root();
    let scanner_manifest = root.join("crates/scanner/Cargo.toml");
    let features = load_features_from_manifest(&scanner_manifest);

    assert!(
        features.contains_key("simd"),
        "scanner must declare simd feature"
    );
    assert!(
        features.contains_key("gpu"),
        "scanner must declare gpu feature"
    );
    assert!(
        features.contains_key("ci-lean"),
        "scanner must declare ci-lean feature"
    );

    let ci_lean = features.get("ci-lean").expect("ci-lean feature");
    assert!(
        ci_lean.contains(&"simd".to_string()),
        "ci-lean must include simd"
    );
    assert!(
        !ci_lean.contains(&"gpu".to_string()),
        "ci-lean must omit gpu"
    );
}

#[test]
fn benchmark_harness_and_scripts_declare_simd_parity() {
    let root = repo_root();
    let keyhog_py = std::fs::read_to_string(root.join("benchmarks/bench/scanners/keyhog.py"))
        .expect("read keyhog.py");
    let cross_device = std::fs::read_to_string(root.join("benchmarks/cross_device.sh"))
        .expect("read cross_device.sh");
    let makefile =
        std::fs::read_to_string(root.join("benchmarks/Makefile")).expect("read Makefile");
    let bench_readme = std::fs::read_to_string(root.join("benchmarks/README.md"))
        .expect("read benchmarks/README.md");

    // keyhog.py default variant uses simd and documents the feature requirement
    assert!(
        keyhog_py.contains("backend=\"simd\""),
        "keyhog.py benchmark adapter default config must use backend='simd'"
    );
    assert!(
        keyhog_py.contains("--features simd"),
        "keyhog.py must document --features simd requirement for SIMD benchmark execution"
    );

    // cross_device.sh sets --features simd on Linux
    assert!(
        cross_device.contains("KH_FEAT=\"--features simd\""),
        "cross_device.sh must specify --features simd for Linux SIMD parity"
    );
    assert!(
        cross_device.contains("Darwin*) KH_FEAT=\"--no-default-features --features portable\""),
        "cross_device.sh must specify portable for Darwin"
    );

    // Makefile builds ci-lean which contains simd
    assert!(
        makefile.contains("--features ci-lean"),
        "benchmarks Makefile must build keyhog candidate with ci-lean (which includes simd)"
    );

    // benchmarks/README.md documents candidate build commands without silent PATH fallback
    assert!(
        bench_readme.contains("cargo build --release -p keyhog --features simd"),
        "benchmarks/README.md must document cargo build with --features simd"
    );
    assert!(
        bench_readme.contains("fails loudly when no candidate exists"),
        "benchmarks/README.md must document loud failure without silent PATH fallback"
    );
}

#[test]
fn documentation_reflects_portable_and_simd_install_commands() {
    let root = repo_root();
    let readme = std::fs::read_to_string(root.join("README.md")).expect("read README.md");
    let install_doc = std::fs::read_to_string(root.join("docs/src/install.md"))
        .expect("read docs/src/install.md");

    // README documents default portable install
    assert!(
        readme.contains("cargo install --locked keyhog")
            || readme.contains("cargo install keyhog --locked"),
        "README.md must document default cargo install keyhog"
    );

    // README documents GPU and SIMD feature installs
    assert!(
        readme.contains(
            "cargo install --locked keyhog --no-default-features --features portable,gpu"
        ),
        "README.md must document GPU feature installation"
    );
    assert!(
        readme.contains(
            "cargo install --locked keyhog --no-default-features --features portable,simd"
        ),
        "README.md must document SIMD feature installation"
    );

    // install.md documents the full profile table
    assert!(
        install_doc.contains("General installation with SIMD peer"),
        "install.md must document SIMD installation profile"
    );
    assert!(
        install_doc.contains("General installation with GPU peers"),
        "install.md must document GPU installation profile"
    );
    assert!(
        install_doc.contains(
            "cargo install --locked keyhog --no-default-features --features portable,simd"
        ),
        "install.md must document portable,simd command"
    );
}

#[test]
fn missing_simd_feature_fails_closed_on_explicit_simd_request() {
    // Verify scanner contract: if compiled without feature = "simd", initialize_simd_backend fails closed
    #[cfg(not(feature = "simd"))]
    {
        use keyhog_scanner::CompiledScanner;
        let scanner = CompiledScanner::compile(Vec::new()).expect("compile empty scanner");
        assert!(
            !scanner.simd_backend_available(),
            "Scanner without simd feature must report simd backend unavailable"
        );
        let result = scanner.initialize_simd_backend();
        assert!(
            result.is_err(),
            "Scanner without simd feature must fail initialization of SIMD backend"
        );
        assert_eq!(
            result.err(),
            Some("this scanner build has no Hyperscan/SIMD backend".to_string())
        );
    }
}
