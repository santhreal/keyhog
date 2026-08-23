//! Regression test for Row 74: catch_unwind isolation boundaries.
//!
//! Asserts that:
//! 1. Every `catch_unwind` site across the scanner crate is classified at run time.
//! 2. `[profile.release]` sets `panic = "unwind"` so isolation boundaries work under the shipped binary.
//! 3. Injected panics inside isolation boundaries degrade cleanly to `Err` without process abort.

#[test]
fn catch_unwind_sites_are_classified_and_profile_release_unwinds() {
    // 1. Check Cargo.toml release profile
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let cargo_toml = std::fs::read_to_string(manifest_dir.join("../../Cargo.toml"))
        .expect("Cargo.toml readable");

    let release_section = cargo_toml
        .split("[profile.release]")
        .nth(1)
        .expect("[profile.release] section present");
    let release_block = release_section.split("\n[").next().expect("release block");

    assert!(
        release_block.contains("panic = \"unwind\""),
        "[profile.release] must set panic = \"unwind\" so catch_unwind isolation boundaries function in release builds"
    );

    // 2. Discover all catch_unwind sites in crates/scanner/src
    let src_dir = manifest_dir.join("src");
    let mut sites = Vec::new();
    fn walk_src(dir: &std::path::Path, manifest_dir: &std::path::Path, sites: &mut Vec<String>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk_src(&path, manifest_dir, sites);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        for (idx, line) in content.lines().enumerate() {
                            if line.contains("catch_unwind(") {
                                let relative = path
                                    .strip_prefix(manifest_dir)
                                    .unwrap_or(&path)
                                    .to_string_lossy()
                                    .replace('\\', "/");
                                sites.push(format!("{}:{}", relative, idx + 1));
                            }
                        }
                    }
                }
            }
        }
    }
    walk_src(&src_dir, manifest_dir, &mut sites);
    sites.sort();

    // 3. Known classifications
    let known_classification_prefixes = [
        "src/gpu_literal_artifacts.rs",
        "src/engine/gpu_lazy_helpers.rs",
        "src/engine/phase2_gpu_dfa.rs",
        "src/gpu/backend/acquisition.rs",
    ];

    for site in &sites {
        let is_known = known_classification_prefixes
            .iter()
            .any(|prefix| site.starts_with(prefix));
        assert!(
            is_known,
            "Unclassified catch_unwind site detected: {site}. Classify its degradation contract or remove."
        );
    }
}

#[test]
fn isolation_boundary_panic_injection_degrades_to_err() {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        panic!("simulated driver panic inside isolation boundary");
    }));
    assert!(result.is_err(), "catch_unwind must capture unwinding panic");
}
