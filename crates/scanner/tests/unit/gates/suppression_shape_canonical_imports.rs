//! Gate: shape and path suppression predicates use their owner modules.

use super::support::*;

#[test]
fn shape_predicates_do_not_route_through_pipeline_or_suppression_root() {
    let mut files = Vec::new();
    collect_rs_files(&scanner_src(), &mut files);
    let mut offenders = Vec::new();

    for path in files {
        let rel = path
            .strip_prefix(scanner_src())
            .expect("scanner src path")
            .to_string_lossy()
            .replace('\\', "/");
        if rel.starts_with("suppression/") || rel == "pipeline/mod.rs" {
            continue;
        }
        let code = uncommented_code(&read(&path));
        for forbidden in [
            "crate::pipeline::looks_like_",
            "crate::pipeline::contains_uuid_v4_substring",
        ] {
            if code.contains(forbidden) {
                offenders.push(format!("{rel} contains {forbidden}"));
            }
        }
        if code.contains("crate::suppression::looks_like_")
            || code.contains("crate::suppression::contains_uuid_v4_substring")
        {
            offenders.push(format!(
                "{rel} imports shape predicates through suppression root"
            ));
        }
    }

    let pipeline = read(&scanner_src().join("pipeline/mod.rs"));
    for forbidden in ["looks_like_", "contains_uuid_v4_substring"] {
        if pipeline.contains(forbidden) {
            offenders.push(format!("pipeline/mod.rs still re-exports {forbidden}"));
        }
    }

    assert!(
        offenders.is_empty(),
        "shape/path suppression predicates must use suppression::shape or suppression::path_filter: {offenders:#?}"
    );
}

#[test]
fn legacy_shape_gate_module_homes_do_not_return() {
    let src = scanner_src();
    let legacy_root = src.join("suppression/shape.rs");
    let legacy_gates = src.join("suppression/shape_gates.rs");
    assert!(
        !legacy_root.exists(),
        "{} must stay moved to suppression/shape/mod.rs",
        legacy_root.display()
    );
    assert!(
        !legacy_gates.exists(),
        "{} must stay moved under suppression/shape/",
        legacy_gates.display()
    );

    let shape_mod = src.join("suppression/shape/mod.rs");
    let canonical = src.join("suppression/shape/canonical.rs");
    assert!(shape_mod.exists(), "{} is missing", shape_mod.display());
    assert!(canonical.exists(), "{} is missing", canonical.display());

    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    let mut offenders = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&src)
            .expect("scanner src path")
            .to_string_lossy()
            .replace('\\', "/");
        let code = uncommented_code(&read(&path));
        for forbidden in [
            "mod shape_gates",
            "shape_gates::",
            "suppression::shape_gates",
        ] {
            if code.contains(forbidden) {
                offenders.push(format!("{rel} contains {forbidden}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "legacy shape-gate owner returned:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn entropy_keywords_does_not_own_shape_predicates() {
    let src = scanner_src();
    let entropy_keywords = read(&src.join("entropy/keywords.rs"));
    let mut offenders = Vec::new();

    for forbidden in [
        "fn looks_like_english_prose",
        "fn entropy_value_looks_like_prose",
        "fn looks_like_program_identifier",
        "fn looks_like_dotted_source_identifier",
        "fn is_dash_segmented_alnum_decoy",
    ] {
        if entropy_keywords.contains(forbidden) {
            offenders.push(format!("entropy/keywords.rs defines {forbidden}"));
        }
    }

    let shape_mod = read(&src.join("suppression/shape/mod.rs"));
    for required in [
        "looks_like_english_prose",
        "looks_like_program_identifier",
        "looks_like_dotted_source_identifier",
        "is_dash_segmented_alnum_decoy",
        "looks_like_entropy_canonical_non_secret_shape",
        "looks_like_entropy_canonical_hex_digest",
        "looks_like_entropy_uuid_shape",
    ] {
        if !shape_mod.contains(required) {
            offenders.push(format!(
                "suppression/shape/mod.rs does not re-export {required}"
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "shape predicates leaked back into entropy keywords:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn entropy_canonical_shapes_live_in_shape_owner() {
    let src = scanner_src();
    let scanner = uncommented_code(&read(&src.join("entropy/scanner.rs")));
    let plausibility = uncommented_code(&read(&src.join("entropy/plausibility.rs")));
    let shape = uncommented_code(&read(&src.join("suppression/shape/canonical.rs")));

    assert!(
        shape.contains("fn looks_like_entropy_canonical_non_secret_shape(")
            && shape.contains("fn looks_like_entropy_canonical_hex_digest(")
            && shape.contains("fn looks_like_entropy_uuid_shape(")
            && shape.contains("fn is_five_by_five_dash_shape("),
        "suppression::shape::canonical must own entropy canonical non-secret shape predicates"
    );
    assert!(
        !shape.contains("Vec<&str>") && !shape.contains(".split('-').collect()"),
        "canonical dashed serial predicates must stay allocation-free fixed-width byte scans"
    );
    assert!(
        scanner.contains(
            "crate::suppression::shape::looks_like_entropy_canonical_non_secret_shape(value)"
        ) && scanner.contains("crate::suppression::shape::looks_like_entropy_uuid_shape(value)")
            && !scanner.contains("fn is_uuid_shape("),
        "entropy/scanner.rs must call the shape owner for canonical non-secret and UUID checks without local UUID aliases"
    );
    assert!(
        plausibility.contains("crate::suppression::shape::looks_like_entropy_uuid_shape(value)")
            && plausibility.contains(
                "crate::suppression::shape::looks_like_entropy_canonical_hex_digest(value)"
            ),
        "entropy/plausibility.rs must call the shape owner for canonical UUID/hex checks"
    );

    for (rel, code) in [
        ("entropy/scanner.rs", scanner.as_str()),
        ("entropy/plausibility.rs", plausibility.as_str()),
    ] {
        for forbidden in [
            "bytes[8] == b'-'",
            "bytes[13] == b'-'",
            "bytes[18] == b'-'",
            "bytes[23] == b'-'",
            "matches!(len, 32 | 40 | 64 | 128)",
            "[32, 40, 64, 128].contains",
            "[\"sha512-\", \"sha384-\", \"sha256-\"]",
        ] {
            assert!(
                !code.contains(forbidden),
                "{rel} must not re-own canonical entropy shape predicate token {forbidden:?}"
            );
        }
    }
}

#[test]
fn random_byte_base64_shape_lives_in_shape_owner() {
    let src = scanner_src();
    let shape = uncommented_code(&read(&src.join("suppression/shape/canonical.rs")));
    let shape_mod = uncommented_code(&read(&src.join("suppression/shape/mod.rs")));
    let generic_shape = uncommented_code(&read(&src.join("engine/phase2_generic_shape.rs")));
    let entropy_gates = uncommented_code(&read(&src.join("engine/phase2_entropy/gates.rs")));

    assert!(
        shape.contains("fn looks_like_random_byte_base64_blob(")
            && shape.contains("fn looks_like_entropy_random_base64_blob_decoy(")
            && shape.contains("fn looks_like_generic_random_base64_blob_decoy(")
            && shape.contains("fn generic_base64_candidate_is_ambiguous(")
            && shape_mod.contains("looks_like_random_byte_base64_blob"),
        "suppression::shape must own and re-export the random-byte base64 blob predicate"
    );
    assert!(
        !src.join("engine/phase2_generic/shape_helpers.rs").exists(),
        "generic engine helpers must not own base64 shape predicates"
    );
    assert!(
        !entropy_gates.contains("entropy_path_looks_like_random_base64_blob("),
        "entropy gates must not call an entropy-owned base64 blob predicate"
    );
    assert!(
        generic_shape.contains("crate::suppression::shape::looks_like_random_byte_base64_blob(value)")
            && entropy_gates.contains(
                "crate::suppression::shape::looks_like_random_byte_base64_blob(&entropy_match.value)"
            ),
        "generic and entropy callers must use the shared suppression::shape owner"
    );
    assert!(
        entropy_gates
            .contains("crate::suppression::shape::looks_like_entropy_random_base64_blob_decoy("),
        "entropy-specific base64 decoy policy must call the suppression::shape owner"
    );
    assert!(
        generic_shape
            .contains("crate::suppression::shape::looks_like_generic_random_base64_blob_decoy(")
            && generic_shape
                .contains("crate::suppression::shape::generic_base64_candidate_is_ambiguous(")
            && !generic_shape.contains("generic_path_looks_like_random_base64_blob(")
            && !generic_shape.contains("generic_path_allows_ambiguous_base64_candidate("),
        "generic base64 policy must call suppression::shape owners"
    );
    assert!(
        !generic_shape.contains("generic_path_looks_like_random_byte_blob(")
            && !entropy_gates.contains("generic_path_looks_like_random_byte_blob("),
        "scanner paths must not call the removed generic-owned random-byte predicate"
    );
}

#[test]
fn path_suppression_predicates_live_in_path_filter_owner() {
    let src = scanner_src();
    let path_filter = uncommented_code(&read(&src.join("suppression/path_filter.rs")));
    let suppression_api = uncommented_code(&read(&src.join("suppression/api.rs")));
    let entropy_helpers = uncommented_code(&read(&src.join("engine/phase2_entropy/helpers.rs")));
    let entropy_gates = uncommented_code(&read(&src.join("engine/phase2_entropy/gates.rs")));

    for required in [
        "fn path_is_ci_workflow_file(",
        "fn path_is_i18n_file(",
        "fn looks_like_raw_base64_file_path(",
        "fn looks_like_entropy_raw_base64_file_path(",
        "fn raw_base64_path_match(",
    ] {
        assert!(
            path_filter.contains(required),
            "suppression/path_filter.rs must own path predicate {required}"
        );
    }

    for forbidden in [
        "fn entropy_path_is_ci_workflow_file(",
        "fn entropy_path_is_i18n_file(",
        "ends_with_ignore_ascii_case(bytes, b\".b64\")",
        "ci_find(basename, b\"base64_string\")",
    ] {
        assert!(
            !entropy_helpers.contains(forbidden),
            "entropy helpers must not own path predicate token {forbidden:?}"
        );
        assert!(
            !entropy_gates.contains(forbidden),
            "entropy gates must not own path predicate token {forbidden:?}"
        );
    }

    assert!(
        entropy_gates.contains("looks_like_entropy_raw_base64_file_path(")
            && entropy_gates.contains("path_is_ci_workflow_file(")
            && entropy_gates.contains("path_is_i18n_file("),
        "entropy gates must call suppression::path_filter-owned path predicates"
    );
    assert!(
        suppression_api.contains("looks_like_raw_base64_file_path(path)")
            && !suppression_api.contains("looks_like_hot_pattern_base64_path(")
            && !suppression_api.contains("ends_with_ignore_ascii_case(bytes, b\".b64\")")
            && !suppression_api.contains("ci_find(basename, b\"base64_string\")"),
        "suppression API must use path_filter for base64 path policy instead of owning duplicate matching code"
    );
}

#[test]
fn entropy_value_reference_shapes_live_in_shape_owner() {
    let src = scanner_src();
    let shape_path = uncommented_code(&read(&src.join("suppression/shape/path.rs")));
    let shape_source = uncommented_code(&read(&src.join("suppression/shape/source.rs")));
    let shape_mod = uncommented_code(&read(&src.join("suppression/shape/mod.rs")));
    let entropy_helpers = uncommented_code(&read(&src.join("engine/phase2_entropy/helpers.rs")));
    let entropy_gates = uncommented_code(&read(&src.join("engine/phase2_entropy/gates.rs")));

    assert!(
        shape_path.contains("fn looks_like_filename_reference(")
            && shape_mod.contains("looks_like_filename_reference"),
        "suppression::shape::path must own filename-reference value shapes"
    );
    assert!(
        shape_source.contains("fn looks_like_kebab_config_identifier(")
            && shape_mod.contains("looks_like_kebab_config_identifier"),
        "suppression::shape::source must own kebab config identifier value shapes"
    );
    for forbidden in [
        "fn entropy_path_looks_like_kebab_identifier(",
        "fn entropy_path_looks_like_filename(",
    ] {
        assert!(
            !entropy_helpers.contains(forbidden),
            "entropy helpers must not own value-shape predicate {forbidden}"
        );
        assert!(
            !entropy_gates.contains(forbidden),
            "entropy gates must not call value-shape predicate {forbidden}"
        );
    }
    assert!(
        entropy_gates.contains("crate::suppression::shape::looks_like_kebab_config_identifier(")
            && entropy_gates.contains("crate::suppression::shape::looks_like_filename_reference("),
        "entropy gates must call suppression::shape value-reference owners"
    );
}

#[test]
fn aws_iam_arn_shape_lives_in_shape_owner() {
    let src = scanner_src();
    let shape = uncommented_code(&read(&src.join("suppression/shape/canonical.rs")));
    let shape_mod = uncommented_code(&read(&src.join("suppression/shape/mod.rs")));
    let generic_shape = uncommented_code(&read(&src.join("engine/phase2_generic_shape.rs")));
    let decision = uncommented_code(&read(&src.join("suppression/decision.rs")));

    assert!(
        shape.contains("fn looks_like_aws_iam_arn(")
            && shape.contains("fn looks_like_trimmed_aws_iam_arn(")
            && shape.contains("fn aws_iam_arn_body_has_resource_target(")
            && shape_mod.contains("looks_like_aws_iam_arn")
            && shape_mod.contains("looks_like_trimmed_aws_iam_arn"),
        "suppression::shape must own full and trimmed AWS IAM ARN predicates"
    );
    assert!(
        !src.join("engine/phase2_generic/shape_helpers.rs").exists()
            && !decision.contains("fn decoded_looks_like_aws_iam_arn("),
        "generic helpers must stay deleted and suppression decision must not re-own AWS IAM ARN predicates"
    );
    assert!(
        generic_shape.contains("crate::suppression::shape::looks_like_trimmed_aws_iam_arn(value)")
            && decision.contains("crate::suppression::shape::looks_like_aws_iam_arn(credential)")
            && decision.contains("crate::suppression::shape::looks_like_aws_iam_arn(decoded)"),
        "generic, direct suppression, and decoded suppression paths must call the shape owner"
    );
}

/// Lock the SRI dash-label unification: `strip_hash_algo_prefix` (the report-time
/// integrity strip) MUST chain the ONE owner `HASH_ALGO_INTEGRITY_LABELS` and
/// MUST NOT re-own the dash-form SRI labels as byte literals. A diverging
/// `{sha512-, sha256-}` subset here previously dropped `sha384-`, so `sha384-`
/// SRI bodies suppressed at entropy generation / decode yet leaked at report
/// time. This gate fails the instant a second dash-label copy reappears.
#[test]
fn strip_hash_algo_prefix_binds_the_sri_label_owner() {
    let shape = uncommented_code(&read(&scanner_src().join("suppression/shape/canonical.rs")));
    // Whitespace-insensitive: `cargo fmt` wraps the `.iter().map(...)` chain
    // across lines. Normalize whitespace before matching so the gate pins the
    // semantic owner-binding, not a particular line layout.
    let shape_ws = source_without_whitespace(&shape);
    assert!(
        shape_ws.contains("HASH_ALGO_INTEGRITY_LABELS.iter().map(|label|label.as_bytes())"),
        "strip_hash_algo_prefix must chain the HASH_ALGO_INTEGRITY_LABELS owner for its dash labels"
    );
    for reowned in ["b\"sha512-\"", "b\"sha384-\"", "b\"sha256-\""] {
        assert!(
            !shape.contains(reowned),
            "canonical.rs must not re-own the dash SRI label {reowned} as a byte literal, bind the owner instead"
        );
    }
}
