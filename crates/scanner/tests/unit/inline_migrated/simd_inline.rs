//! Migrated from src/simd.rs — silent_drop_regression gate.
//!
//! `HsScanner` is only exposed when the `simd` (Hyperscan) feature is on;
//! the lean ci build skips this test entirely.
#![cfg(feature = "simd")]

use keyhog_scanner::testing::HsScanner;
use keyhog_scanner::types::REGEX_SIZE_LIMIT_BYTES;

#[test]
fn no_embedded_detector_pattern_silently_drops_at_hyperscan_compile() {
    let mut specs = Vec::new();
    for (name, toml_text) in keyhog_core::embedded_detector_tomls() {
        match keyhog_core::load_detectors_from_str(toml_text) {
            Ok(parsed) => specs.extend(parsed),
            Err(err) => panic!(
                "embedded detector `{name}` failed to parse — fix the TOML \
                 first. Inner: {err}"
            ),
        }
    }
    assert!(
        !specs.is_empty(),
        "embedded_detector_tomls() returned empty after parse — build.rs \
         likely skipped embedding; rebuild keyhog-core from a clean target/."
    );

    let mut dropped: Vec<(String, String, String)> = Vec::new();
    for spec in &specs {
        for (pat_idx, pattern) in spec.patterns.iter().enumerate() {
            let regex_str = pattern.regex.as_str();

            let single = [(0usize, pat_idx, regex_str, false)];
            match HsScanner::compile(&single) {
                Ok((_scanner, unsupported)) => {
                    if !unsupported.is_empty() {
                        dropped.push((
                            spec.id.to_string(),
                            regex_str.to_string(),
                            "Hyperscan: single-pattern compile returned unsupported — \
                             probable DFA-size or unsupported-feature rejection"
                                .to_string(),
                        ));
                    }
                }
                Err(err) => {
                    dropped.push((
                        spec.id.to_string(),
                        regex_str.to_string(),
                        format!("Hyperscan: {err}"),
                    ));
                }
            }

            let regex_build_result = regex::RegexBuilder::new(regex_str)
                .size_limit(REGEX_SIZE_LIMIT_BYTES)
                .dfa_size_limit(REGEX_SIZE_LIMIT_BYTES)
                .case_insensitive(true)
                .build();
            if let Err(err) = regex_build_result {
                dropped.push((
                    spec.id.to_string(),
                    regex_str.to_string(),
                    format!("regex-crate: {err}"),
                ));
            }
        }
    }

    if !dropped.is_empty() {
        let mut msg = format!(
            "{} detector pattern(s) silently dropped at regex compile:\n",
            dropped.len()
        );
        for (det, regex, why) in dropped.iter().take(10) {
            msg.push_str(&format!("  - {det}: {regex}\n    -> {why}\n"));
        }
        if dropped.len() > 10 {
            msg.push_str(&format!("  ... and {} more.\n", dropped.len() - 10));
        }
        msg.push_str(
            "\nCommon cause: a bounded repetition `{0,N}` over a wide \
             character class (e.g. `[^\\s\"']` or `[A-Za-z0-9+/=]`) \
             explodes the per-pattern DFA past 1 MiB. Fix: drop the \
             upper bound or shrink N. Prior art: aws-ecr-token + \
             supabase-realtime-credentials, 2026-05-24.",
        );
        panic!("{msg}");
    }
}
