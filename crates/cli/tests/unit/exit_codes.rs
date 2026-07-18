//! Coherence lock for the CLI exit-code contract (#133).
//!
//! `crate::exit_codes` declares three things that MUST agree: the numeric
//! constants, the `DEFINITIONS` table (code + label + scan-reachability), and the
//! human `HELP` text printed under `EXIT CODES:`. Nothing forces them to stay in
//! sync, a code added to `DEFINITIONS` but forgotten in `HELP` (or a semantic
//! alias pointed at an undefined number) silently drifts the documented contract
//! from the real one. These tests pin the single source of truth: the numbers, the
//! alias resolutions, and the exact set-equality between `DEFINITIONS` and `HELP`.

use keyhog::exit_codes::{
    help, ExitCodeDefinition, DEFINITIONS, EXIT_BACKEND_SELF_TEST_FAILED, EXIT_CREDENTIALS_FOUND,
    EXIT_DETECTOR_AUDIT_FAILED, EXIT_DOCTOR_UNHEALTHY, EXIT_FINDINGS, EXIT_HEALTH_FAILURE,
    EXIT_INTERRUPTED, EXIT_LIVE_CREDENTIALS, EXIT_REPAIR_FAILED, EXIT_REQUIRE_GPU_UNMET,
    EXIT_SCANNER_PANIC, EXIT_SOURCE_FAILED, EXIT_SUCCESS, EXIT_SYSTEM_ERROR, EXIT_UPDATE_AVAILABLE,
    EXIT_USER_ERROR,
};

/// The leading integer of every `HELP` line that starts with one (the header line
/// `EXIT CODES:` and any wrapped text lines yield nothing).
fn help_codes() -> Vec<u8> {
    help()
        .lines()
        .filter_map(|line| line.trim_start().split_whitespace().next())
        .filter_map(|token| token.parse::<u8>().ok())
        .collect()
}

fn defined_codes() -> Vec<u8> {
    DEFINITIONS.iter().map(|d| d.code).collect()
}

/// Every semantic alias constant, paired with the number it resolves to.
const ALIASES: &[(&str, u8)] = &[
    (
        "EXIT_BACKEND_SELF_TEST_FAILED",
        EXIT_BACKEND_SELF_TEST_FAILED,
    ),
    ("EXIT_DETECTOR_AUDIT_FAILED", EXIT_DETECTOR_AUDIT_FAILED),
    ("EXIT_DOCTOR_UNHEALTHY", EXIT_DOCTOR_UNHEALTHY),
    ("EXIT_REPAIR_FAILED", EXIT_REPAIR_FAILED),
    ("EXIT_UPDATE_AVAILABLE", EXIT_UPDATE_AVAILABLE),
    ("EXIT_CREDENTIALS_FOUND", EXIT_CREDENTIALS_FOUND),
];

// ── DEFINITIONS table integrity ──────────────────────────────────────────

#[test]
fn definitions_have_unique_codes() {
    let mut seen = std::collections::HashSet::new();
    for def in DEFINITIONS {
        assert!(
            seen.insert(def.code),
            "exit code {} is defined more than once",
            def.code
        );
    }
}

#[test]
fn definitions_labels_are_nonempty() {
    for def in DEFINITIONS {
        assert!(
            !def.label.trim().is_empty(),
            "exit code {} has an empty label",
            def.code
        );
    }
}

#[test]
fn definitions_are_sorted_ascending_by_code() {
    let codes = defined_codes();
    let mut sorted = codes.clone();
    sorted.sort_unstable();
    assert_eq!(
        codes, sorted,
        "DEFINITIONS must be ordered by ascending code"
    );
}

#[test]
fn definition_count_is_ten() {
    assert_eq!(DEFINITIONS.len(), 10);
}

#[test]
fn definitions_labels_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for def in DEFINITIONS {
        assert!(seen.insert(def.label), "duplicate label {:?}", def.label);
    }
}

// ── The documented numeric contract (each value is a public promise) ──────

#[test]
fn success_is_zero() {
    assert_eq!(EXIT_SUCCESS, 0);
}

#[test]
fn findings_is_one() {
    assert_eq!(EXIT_FINDINGS, 1);
}

#[test]
fn user_error_is_two() {
    assert_eq!(EXIT_USER_ERROR, 2);
}

#[test]
fn system_error_is_three() {
    assert_eq!(EXIT_SYSTEM_ERROR, 3);
}

#[test]
fn health_failure_is_four() {
    assert_eq!(EXIT_HEALTH_FAILURE, 4);
}

#[test]
fn live_credentials_is_ten() {
    assert_eq!(EXIT_LIVE_CREDENTIALS, 10);
}

#[test]
fn scanner_panic_is_eleven() {
    assert_eq!(EXIT_SCANNER_PANIC, 11);
}

#[test]
fn require_gpu_unmet_is_twelve() {
    assert_eq!(EXIT_REQUIRE_GPU_UNMET, 12);
}

#[test]
fn source_failed_is_thirteen() {
    assert_eq!(EXIT_SOURCE_FAILED, 13);
}

#[test]
fn interrupted_is_130() {
    // 128 + SIGINT(2); the conventional shell code for Ctrl-C.
    assert_eq!(EXIT_INTERRUPTED, 130);
}

// ── Semantic aliases resolve to real, defined codes ──────────────────────

#[test]
fn every_alias_resolves_to_a_defined_code() {
    let defined = defined_codes();
    for (name, code) in ALIASES {
        assert!(
            defined.contains(code),
            "alias {name} resolves to {code}, which is not in DEFINITIONS"
        );
    }
}

#[test]
fn backend_self_test_alias_is_health_failure() {
    assert_eq!(EXIT_BACKEND_SELF_TEST_FAILED, EXIT_HEALTH_FAILURE);
}

#[test]
fn doctor_unhealthy_alias_is_health_failure() {
    assert_eq!(EXIT_DOCTOR_UNHEALTHY, EXIT_HEALTH_FAILURE);
}

#[test]
fn repair_failed_alias_is_health_failure() {
    assert_eq!(EXIT_REPAIR_FAILED, EXIT_HEALTH_FAILURE);
}

#[test]
fn detector_audit_alias_is_system_error() {
    assert_eq!(EXIT_DETECTOR_AUDIT_FAILED, EXIT_SYSTEM_ERROR);
}

#[test]
fn update_available_alias_is_live_credentials() {
    assert_eq!(EXIT_UPDATE_AVAILABLE, EXIT_LIVE_CREDENTIALS);
}

#[test]
fn credentials_found_alias_is_findings() {
    assert_eq!(EXIT_CREDENTIALS_FOUND, EXIT_FINDINGS);
}

// ── HELP text agrees with DEFINITIONS (the drift-preventing lock) ─────────

#[test]
fn help_starts_with_exit_codes_header() {
    assert!(
        help().starts_with("EXIT CODES:"),
        "HELP must open with the EXIT CODES header"
    );
}

#[test]
fn generated_help_is_byte_identical_to_the_documented_block() {
    // The help block is now GENERATED from DEFINITIONS; this pins its exact bytes so
    // the refactor did not change a single character of `--help` output, and any
    // future edit to a description/code is caught here.
    let expected = "EXIT CODES:\n  \
0   Success (no secrets found)\n  \
1   Secrets found, none confirmed live (unverified, skipped, or verified-inactive: dead/revoked)\n  \
2   User error (bad flag/config, missing path/baseline, detector-load failure, invalid autoroute calibration, not-found/permission-denied path)\n  \
3   System error (local environment failure: low-level I/O, fatal daemon service failure, or selected SIMD/Hyperscan unavailable)\n  \
4   Health/self-test failure (doctor unhealthy / repair could not restore a working binary / backend --self-test failed)\n  \
10  Live credentials found under scan --verify, or update available under update --check\n  \
11  Scanner thread panicked mid-scan (state is unreliable)\n  \
12  Required GPU unavailable (--require-gpu, explicit gpu, or proof-selected daemon GPU before readiness)\n  \
13  Requested source failed or input coverage was incomplete\n  \
130 Interrupted (SIGINT / Ctrl-C)";
    assert_eq!(help(), expected);
}

#[test]
fn every_definition_has_nonempty_help() {
    for def in DEFINITIONS {
        assert!(
            !def.help.trim().is_empty(),
            "exit code {} has an empty help description",
            def.code
        );
    }
}

#[test]
fn help_descriptions_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for def in DEFINITIONS {
        assert!(
            seen.insert(def.help),
            "duplicate help description {:?}",
            def.help
        );
    }
}

#[test]
fn generated_help_renders_every_definition_description() {
    // Proves the generated view is sourced from DEFINITIONS: every row's description
    // appears verbatim in the output.
    let rendered = help();
    for def in DEFINITIONS {
        assert!(
            rendered.contains(def.help),
            "generated help is missing the description for code {}: {:?}",
            def.code,
            def.help
        );
    }
}

#[test]
fn generated_help_starts_each_row_with_its_padded_code() {
    // The `  {code:<3} ` layout: a single-digit code is padded so descriptions align.
    let rendered = help();
    assert!(rendered.contains("\n  0   Success"), "0 row layout");
    assert!(rendered.contains("\n  10  Live"), "10 row layout");
    assert!(rendered.contains("\n  130 Interrupted"), "130 row layout");
}

#[test]
fn help_lists_every_defined_code() {
    let listed = help_codes();
    for code in defined_codes() {
        assert!(
            listed.contains(&code),
            "exit code {code} is in DEFINITIONS but missing from HELP text"
        );
    }
}

#[test]
fn help_has_no_undefined_codes() {
    let defined = defined_codes();
    for code in help_codes() {
        assert!(
            defined.contains(&code),
            "HELP text documents exit code {code}, which is not in DEFINITIONS"
        );
    }
}

#[test]
fn help_code_set_equals_definition_set() {
    let mut listed = help_codes();
    listed.sort_unstable();
    listed.dedup();
    let mut defined = defined_codes();
    defined.sort_unstable();
    assert_eq!(
        listed, defined,
        "the set of codes in HELP must exactly equal the set in DEFINITIONS"
    );
}

#[test]
fn help_documents_exactly_one_line_per_code() {
    // No duplicate code lines, no code without a line.
    assert_eq!(
        help_codes().len(),
        DEFINITIONS.len(),
        "HELP must have exactly one line per defined exit code"
    );
}

// ── scan-reachability flag is coherent ───────────────────────────────────

#[test]
fn only_health_failure_is_not_scan_reachable() {
    for def in DEFINITIONS {
        let expected = def.code != EXIT_HEALTH_FAILURE;
        assert_eq!(
            def.scan_reachable, expected,
            "scan_reachable for code {} should be {expected}",
            def.code
        );
    }
}

#[test]
fn health_failure_definition_is_present_and_unreachable_from_scan() {
    let def = DEFINITIONS
        .iter()
        .find(|d: &&ExitCodeDefinition| d.code == EXIT_HEALTH_FAILURE)
        .expect("health-failure code must be defined");
    assert!(
        !def.scan_reachable,
        "a scan must never exit with the health/self-test code"
    );
}
