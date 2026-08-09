//! KH-GAP-074: fuzz targets are not invoked by any CI workflow.

use super::support::repo_root;

#[test]
fn ci_workflows_invoke_fuzz_targets_or_cargo_fuzz() {
    let workflows_dir = repo_root().join(".github/workflows");
    let mut combined = String::new();
    for entry in std::fs::read_dir(&workflows_dir).expect("list workflows") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("yml") {
            combined.push_str(&std::fs::read_to_string(&path).expect("read workflow"));
        }
    }

    let wired = combined.contains("cargo fuzz")
        || combined.contains("fuzz/")
        || combined.contains("scanner_target")
        || combined.contains("decode_target");

    assert!(
        wired,
        "no .github/workflows/*.yml references cargo-fuzz or fuzz/ targets. \
         fuzz corpus never runs in CI (KH-GAP-074)"
    );
}

/// Locks out rolling compiler changes that can fail fuzz CI before libFuzzer
/// executes an input, leaving the sanitizer gate reproducible across commits.
#[test]
fn fuzz_smoke_pins_the_rust_toolchain() {
    let workflow = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml"))
        .expect("read CI workflow");

    assert!(
        workflow.contains("rustup toolchain install nightly-2026-08-07")
            && workflow.contains("cargo +nightly-2026-08-07 fuzz run decode_target")
            && workflow.contains("cargo +nightly-2026-08-07 fuzz run scanner_target")
            && !workflow.contains("cargo +nightly fuzz run")
            && !workflow.lines().any(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("rustup toolchain install nightly")
                    && !trimmed.starts_with("rustup toolchain install nightly-")
            }),
        "fuzz smoke must use its verified pinned nightly, not a rolling compiler that can change \
         sanitizer behavior between otherwise identical commits"
    );
}

/// Hyperscan's FFI scratch state currently ICEs rustc under cargo-fuzz ASan
/// instrumentation, so the smoke must retain Rust CPU coverage without `simd`.
#[test]
fn fuzz_smoke_excludes_asan_incompatible_hyperscan() {
    let manifest =
        std::fs::read_to_string(repo_root().join("fuzz/Cargo.toml")).expect("read fuzz manifest");
    let scanner_dependency = manifest
        .split("[dependencies.keyhog-scanner]")
        .nth(1)
        .and_then(|tail| tail.split("[[").next())
        .expect("keyhog-scanner fuzz dependency");

    assert!(
        scanner_dependency.contains("\"simdsieve\"") && !scanner_dependency.contains("\"simd\""),
        "scanner fuzz dependency must exercise the Rust SIMD sieve without compiling Hyperscan's \
         ASan-incompatible scratch wrapper"
    );
}
