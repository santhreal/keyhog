//! WHY THIS TEST EXISTS:
//! Row 17 / Lockfile exclusion parity contract:
//! Every major ecosystem lockfile (npm, yarn, pnpm, cargo, go, bundler, poetry, pipenv,
//! uv, pdm, composer, nix, mix, pub, cocoapods, conan) must be registered in
//! `rules/default_excludes.toml` so hash-rich lockfiles do not flood scans with false positives.
//!
//! WHAT IT DOES NOT CATCH:
//! Custom proprietary in-house lockfile formats.

use std::collections::BTreeSet;
use std::path::Path;
use toml::Value;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
}

#[test]
fn default_excludes_contains_all_major_ecosystem_lockfiles() {
    let root = repo_root();
    let excludes_path = root.join("rules/default_excludes.toml");
    assert!(
        excludes_path.exists(),
        "rules/default_excludes.toml must exist"
    );

    let content =
        std::fs::read_to_string(&excludes_path).expect("read rules/default_excludes.toml");
    let parsed: Value = toml::from_str(&content).expect("parse rules/default_excludes.toml");

    let filenames_array = parsed
        .get("default_excludes")
        .and_then(|t| t.get("filenames"))
        .and_then(|v| v.as_array())
        .expect("default_excludes.filenames array must exist");

    let filenames: BTreeSet<String> = filenames_array
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    let expected_lockfiles = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "cargo.lock",
        "go.sum",
        "gemfile.lock",
        "poetry.lock",
        "pipfile.lock",
        "uv.lock",
        "pdm.lock",
        "composer.lock",
        "flake.lock",
        "mix.lock",
        "pubspec.lock",
        "podfile.lock",
        "conan.lock",
    ];

    for lockfile in expected_lockfiles {
        assert!(
            filenames.contains(lockfile),
            "rules/default_excludes.toml must contain ecosystem lockfile '{lockfile}'"
        );
    }
}
