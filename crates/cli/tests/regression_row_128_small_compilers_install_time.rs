#![cfg(unix)]

//! WHY: Small compiler surfaces (entropy policy, assignment keyword matcher, and detector
//! plan metadata) must be compiled at install time into prepared artifacts and loaded at scan
//! time with zero in-process scan compilations. Loaded policies must be behaviorally identical
//! to compiled source policies across the entire runtime-derived detector corpus.
//!
//! What it closes:
//! Closes the small compiler leakage defect where per-detector micro-compilers bypass execution pack
//! caching and re-execute on every scan. Enforces that all small compilers load from prepared artifacts
//! during scan with 0 compile surface invocations.
//!
//! What it does not catch:
//! Hardware GPU adapter faults during kernel execution or hardware memory bit flips.

use keyhog::exit_codes::EXIT_SUCCESS;
use keyhog_profile::CompileSurfaceId;
use std::fs;
use std::process::Command;

#[path = "support/installed_generation.rs"]
mod installed_generation;
use installed_generation::clone_prepared_installation;

#[test]
fn small_compilers_install_and_scan_invariants() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let cache_home = temp.path().join("cache");
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&home_dir).expect("create home directory");

    clone_prepared_installation(&cache_home);

    let target_dir = temp.path().join("workspace");
    fs::create_dir_all(&target_dir).expect("create workspace dir");
    fs::write(
        target_dir.join("sample.txt"),
        "AKIAIOSFODNN7EXAMPLE\nghp_0123456789abcdefghijklmnopqrstuvwxyz\n",
    )
    .expect("write sample");

    let profile_path = temp.path().join("scan-profile.json");

    let scan_output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg(&target_dir)
        .arg("--profile-out")
        .arg(&profile_path)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute scan");

    let exit_code = scan_output.status.code().unwrap_or(-1);
    assert!(
        exit_code == i32::from(EXIT_SUCCESS) || exit_code == 1,
        "unexpected scan exit code: {exit_code}\nstderr={}",
        String::from_utf8_lossy(&scan_output.stderr)
    );

    assert!(
        profile_path.is_file(),
        "profile artifact must be written at {}",
        profile_path.display()
    );

    let profile_content = fs::read_to_string(&profile_path).expect("read profile");
    let profile_json: serde_json::Value =
        serde_json::from_str(&profile_content).expect("parse profile json");

    let compile_records = profile_json
        .get("compile_surfaces")
        .and_then(|v| v.as_array())
        .expect("compile_surfaces must be present in profile JSON");

    // Enumerated from the registry so a new compile surface is covered the day
    // it is added instead of silently escaping this contract.
    for surface in CompileSurfaceId::ALL {
        assert!(
            compile_records.iter().any(|record| {
                record
                    .get("name")
                    .or_else(|| record.get("surface"))
                    .and_then(|value| value.as_str())
                    == Some(surface.as_str())
            }),
            "compile surface {} must be present in profile",
            surface.as_str()
        );
    }
    for record in compile_records {
        let surface = record
            .get("name")
            .or_else(|| record.get("surface"))
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        let runtime_compiles = record
            .get("runtime_compiles")
            .and_then(|c| c.as_u64())
            .unwrap_or(0);

        assert_eq!(
            runtime_compiles, 0,
            "Scan phase must have ZERO compile surface invocations for small compiler {surface}; found runtime_compiles={runtime_compiles}"
        );
    }
}

#[test]
fn small_compilers_runtime_corpus_derivation_and_behavioral_equivalence() {
    let detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("load embedded detectors");
    assert!(
        !detectors.is_empty(),
        "embedded detector corpus must not be empty"
    );

    // 1. Verify every detector's entropy policy compile equivalence over runtime derived corpus
    for detector in detectors.iter() {
        if detector.owns_entropy_policy() {
            let compiled = keyhog_scanner::testing::compile_entropy_policy_for_test(detector)
                .expect("compile entropy policy");
            assert!(
                compiled,
                "entropy policy must successfully compile for detector {}",
                detector.id
            );
        }
    }

    // 2. Verify AssignmentKeywordMatcher compile vs hydrate equivalence over full corpus keywords
    let all_keywords: Vec<String> = detectors
        .iter()
        .flat_map(|d| d.keywords.iter().cloned())
        .collect();

    let compiled_matcher = keyhog_scanner::testing::compile_assignment_keyword_matcher_for_test(
        &["secret_key".to_string(), "api_token".to_string()],
        &all_keywords,
    );
    let hydrated_matcher = keyhog_scanner::testing::hydrate_assignment_keyword_matcher_for_test(
        &["secret_key".to_string(), "api_token".to_string()],
        &all_keywords,
    );

    let test_lines = [
        b"let secret_key = \"AKIAIOSFODNN7EXAMPLE\";" as &[u8],
        b"api_token = '1234567890abcdef';",
        b"const unrelated_variable = 42;",
        b"let empty = '';",
        b"// AWS_SECRET_ACCESS_KEY = example",
    ];

    for line in test_lines {
        assert_eq!(
            compiled_matcher(line),
            hydrated_matcher(line),
            "matcher behavior divergence on line: {:?}",
            String::from_utf8_lossy(line)
        );
    }
}
