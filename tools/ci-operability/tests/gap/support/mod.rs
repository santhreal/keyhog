//! Shared helpers for CI operability gap oracles.

use std::path::PathBuf;

pub mod spec_waiver;

/// Repository root — two levels up from this crate's manifest.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// Read a named workflow from `.github/workflows/`, panicking with context on failure.
pub fn read_workflow(name: &str) -> String {
    std::fs::read_to_string(repo_root().join(".github/workflows").join(name))
        .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// SPEC waiver for the santh-ci migration of `.github/workflows/ci.yml`.
pub const CI_YML_WAIVER: &str = "tools/ci-operability/spec_waivers/ci_yml_santh_ci_migration.toml";
/// SPEC waiver for the cargo-rdme README contract.
pub const CARGO_RDME_WAIVER: &str =
    "tools/ci-operability/spec_waivers/cargo_rdme_readme_contract.toml";

/// The 14 strict contract-multiplier runner binaries gated by CI.
pub const STRICT_RUNNERS: [&str; 14] = [
    "contracts_runner",
    "adversarial_explosion_runner",
    "encoding_explosion_runner",
    "path_shape_runner",
    "noise_injection_runner",
    "unicode_confusable_runner",
    "whitespace_normalization_runner",
    "line_length_runner",
    "entropy_edge_runner",
    "compound_encoding_runner",
    "multi_secret_runner",
    "comment_embed_runner",
    "companion_contracts_runner",
    "cve_replay_runner",
];
