//! LR2-A8 harness integration: gap/mod.rs matches disk

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[test]
fn gap_mod_covers_every_gap_rs_except_mod() {
    let gap_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gap");
    let mod_src = std::fs::read_to_string(gap_dir.join("mod.rs")).expect("mod.rs");
    for entry in std::fs::read_dir(&gap_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_str().unwrap();
        if stem == "mod" {
            continue;
        }
        assert!(
            mod_src.contains(&format!("pub mod {stem};")),
            "gap/mod.rs missing {stem}"
        );
    }
}

fn manifest_test_paths(manifest: &str) -> BTreeSet<String> {
    manifest
        .lines()
        .map(str::trim)
        .filter_map(|line| {
            let (_, value) = line.split_once("path")?;
            let (_, value) = value.split_once('=')?;
            let value = value.trim();
            let value = value.strip_prefix('"')?;
            let (path, _) = value.split_once('"')?;
            Some(path.replace('\\', "/"))
        })
        .collect()
}

fn path_attrs_from_top_level_tests(tests_dir: &Path) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for entry in std::fs::read_dir(tests_dir).expect("tests dir readable") {
        let path = entry.expect("test dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} readable: {error}", path.display()));
        for line in src.lines().map(str::trim) {
            let Some(rest) = line.strip_prefix("#[path = \"") else {
                continue;
            };
            let Some((path_attr, _)) = rest.split_once('"') else {
                continue;
            };
            paths.insert(format!("tests/{}", path_attr.replace('\\', "/")));
        }
    }
    paths
}

fn gap_rs_files(gap_dir: &Path) -> BTreeSet<String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = BTreeSet::new();
    for entry in std::fs::read_dir(gap_dir).expect("gap dir readable") {
        let path = entry.expect("gap dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        if path.file_name().and_then(|s| s.to_str()) == Some("mod.rs") {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or_else(|error| panic!("{} under manifest dir: {error}", path.display()))
            .to_string_lossy()
            .replace('\\', "/");
        files.insert(rel);
    }
    files
}

#[test]
fn no_new_unreachable_gap_rs_files() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let tests_dir = root.join("tests");
    let gap_dir = tests_dir.join("gap");
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("scanner Cargo.toml");
    let mut executable = manifest_test_paths(&manifest);
    executable.extend(path_attrs_from_top_level_tests(&tests_dir));

    let allowed_unreachable: BTreeSet<&'static str> = [
        "tests/gap/adversarial_bulk_lacks_per_detector_hostile_twins.rs",
        "tests/gap/analyze_keyword_only_must_assert.rs",
        "tests/gap/backend_worst_case_parity_sample_only.rs",
        "tests/gap/checksum_github.rs",
        "tests/gap/checksum_gitlab_npm_slack_stripe.rs",
        "tests/gap/compiler_inline_tests_in_src.rs",
        "tests/gap/compiler_prefix_inline_tests_in_src.rs",
        "tests/gap/confidence_calibration_uncalibrated_passthrough.rs",
        "tests/gap/confidence_floor_policy.rs",
        "tests/gap/confidence_penalties_inline_tests_in_src.rs",
        "tests/gap/context_false_positive_inline_tests_in_src.rs",
        "tests/gap/context_inference_cfg_test_string_breaks_gate.rs",
        "tests/gap/context_sequential_placeholder_strips_prefix.rs",
        "tests/gap/context_tokio_async_fn_test_body_is_test_code.rs",
        "tests/gap/cross_platform_cfg_gates_absent.rs",
        "tests/gap/decode_pipeline_exceeds_modularity_cap.rs",
        "tests/gap/detector_precision_decoys.rs",
        "tests/gap/detector_recall_prefixes.rs",
        "tests/gap/engine_backend_parity.rs",
        "tests/gap/entropy_keyword_only_requires_keyword_line.rs",
        "tests/gap/entropy_keywords_inline_tests_in_src.rs",
        "tests/gap/file_gate_matrix_scanner_adversarial_unmarked.rs",
        "tests/gap/file_gate_matrix_scanner_missing_submodule_rows.rs",
        "tests/gap/inline_gate.rs",
        "tests/gap/multiline_reassembly.rs",
        "tests/gap/no_suppress_test_fixtures_clears_generic_fallback_haircut.rs",
        "tests/gap/pipeline_exceeds_modularity_cap.rs",
        "tests/gap/pipeline_hot_path_allocs.rs",
        "tests/gap/r5_adversarial_expansion_total_floor_155.rs",
        "tests/gap/r5_adversarial_one_test_per_file.rs",
        "tests/gap/r5_checksum_invalid_drops_named_service_match.rs",
        "tests/gap/r5_chunk_boundary_subdir_wired.rs",
        "tests/gap/r5_concat_subdir_wired.rs",
        "tests/gap/r5_homoglyph_subdir_wired.rs",
        "tests/gap/r5_per_detector_near_miss_runner_present.rs",
        "tests/gap/r5_reverse_subdir_wired.rs",
        "tests/gap/scan_filters_grouped.rs",
        "tests/gap/suppression_postprocess_exceeds_modularity_cap.rs",
        "tests/gap/suppression_shape_gate_pipeline_twins_incomplete.rs",
        "tests/gap/unicode_homoglyph_matrix.rs",
    ]
    .into_iter()
    .collect();

    let unreachable: BTreeSet<String> = gap_rs_files(&gap_dir)
        .into_iter()
        .filter(|path| !executable.contains(path))
        .collect();
    let unexpected: Vec<_> = unreachable
        .iter()
        .filter(|path| !allowed_unreachable.contains(path.as_str()))
        .cloned()
        .collect();
    assert!(
        unexpected.is_empty(),
        "new tests/gap/*.rs files must be executable via Cargo.toml [[test]] or a top-level #[path] target; unexpected unreachable files: {unexpected:#?}"
    );
}

#[test]
fn decode_pipeline_layers_gap_has_cargo_target() {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("scanner Cargo.toml");
    assert!(
        manifest.contains("name = \"gap_decode_pipeline_layers\"")
            && manifest.contains("path = \"tests/gap/decode_pipeline_layers.rs\""),
        "decode_pipeline_layers gap suite must be executable as a Cargo test target"
    );
}
