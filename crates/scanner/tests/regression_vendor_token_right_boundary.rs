//! Right-boundary contract for a curated set of fixed-length, non-checksummed
//! vendor token detectors, sharing the root cause fixed for the hot-token
//! detectors (see `regression_github_pat_boundary` / `regression_hot_token_right_boundary`).
//!
//! Each detector matches `<prefix>[word-class]{N}`. Without a right boundary the
//! whole-text extraction path reports the capped N-char prefix of a longer
//! word-character run; the trailing `\b` in each regex fails closed instead.
//!
//! This suite is SELF-VALIDATING for recall: only detectors whose exact-length
//! token PROVABLY surfaces on both the SimdCpu hot path and the CpuFallback
//! regex path are enrolled here (so the `\b` cost no real recall), and each
//! asserts the overlong run is suppressed on both (the precision gain). The
//! remaining fixed-length candidates from the audit are tracked in the
//! boundary-sweep memory pending the same per-detector proof, including npm /
//! Shopify, which did NOT surface a valid token even before the boundary was
//! added (a separate recall investigation, not a boundary regression).

mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

/// Enrolled detectors (every one is proven (below) to surface its exact token).
const DETECTOR_IDS: &[&str] = &[
    "buildkite-api-access-token",
    "render-api-key",
    "deepseek-api-key",
    "digitalocean-pat",
];
const CPU_BACKENDS: [ScanBackend; 2] = [ScanBackend::SimdCpu, ScanBackend::CpuFallback];

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        // Full detector set: non-hot vendor detectors fire through the regular
        // AC+phase2 pipeline. Assertions target a specific detector_id, so
        // co-firing of other detectors is harmless.
        let detectors =
            keyhog_core::load_detectors(&support::paths::detector_dir()).expect("detectors");
        CompiledScanner::compile(detectors).expect("compile")
    })
}

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "vendor-token-boundary".into(),
            path: Some("fixtures/tokens.env".into()),
            ..Default::default()
        },
    }
}

fn per_backend_hit(text: &str, detector: &str, credential: &str) -> Vec<bool> {
    let scanner = scanner();
    CPU_BACKENDS
        .iter()
        .map(|&backend| {
            scanner.clear_fragment_cache();
            scanner
                .scan_with_backend(&chunk(text), backend)
                .iter()
                .any(|m| m.detector_id.as_ref() == detector && m.credential.as_ref() == credential)
        })
        .collect()
}

fn reports_on_both(detector: &str, text: &str, credential: &str) -> bool {
    per_backend_hit(text, detector, credential) == vec![true, true]
}

fn suppressed_on_both(detector: &str, text: &str) -> bool {
    let scanner = scanner();
    CPU_BACKENDS.iter().all(|&backend| {
        scanner.clear_fragment_cache();
        scanner
            .scan_with_backend(&chunk(text), backend)
            .iter()
            .all(|m| m.detector_id.as_ref() != detector)
    })
}

/// Emit five distinct tests per detector: env-report, end-of-input report, two
/// overlong-run suppressions (extra in-class letter and digit), and an explicit
/// both-backend agreement on suppression.
macro_rules! vendor_boundary {
    ($det:literal, $tok:literal, $ov_letter:literal, $ov_digit:literal,
     $env:ident, $eof:ident, $ovl:ident, $ovd:ident, $agree:ident) => {
        #[test]
        fn $env() {
            assert!(
                reports_on_both($det, &format!("API_TOKEN={}\n", $tok), $tok),
                "{} exact token must surface (env): {:?}",
                $det,
                per_backend_hit(&format!("API_TOKEN={}\n", $tok), $det, $tok)
            );
        }
        #[test]
        fn $eof() {
            // End of input is a word boundary (no trailing delimiter needed).
            assert!(
                reports_on_both($det, $tok, $tok),
                "{} exact token must surface at end of input",
                $det
            );
        }
        #[test]
        fn $ovl() {
            assert!(
                suppressed_on_both($det, &format!("API_TOKEN={}{}\n", $tok, $ov_letter)),
                "{} overlong (+{}) must fail closed on both backends",
                $det,
                $ov_letter
            );
        }
        #[test]
        fn $ovd() {
            assert!(
                suppressed_on_both($det, &format!("API_TOKEN={}{}\n", $tok, $ov_digit)),
                "{} overlong (+{}) must fail closed on both backends",
                $det,
                $ov_digit
            );
        }
        #[test]
        fn $agree() {
            let per = per_backend_hit(&format!("API_TOKEN={}{}\n", $tok, $ov_letter), $det, $tok);
            assert_eq!(
                per,
                vec![false, false],
                "{} hot and fallback must agree (suppress)",
                $det
            );
        }
    };
}

vendor_boundary!(
    "buildkite-api-access-token",
    "bkua_9mZ2xQ7wB4nR1tY6vC3sJ8fG5hL0pP2o",
    "Z",
    "9",
    buildkite_env_reports,
    buildkite_eof_reports,
    buildkite_overlong_letter_suppressed,
    buildkite_overlong_digit_suppressed,
    buildkite_backends_agree_suppressed
);
vendor_boundary!(
    "render-api-key",
    "rnd_wB4nR1tY6vC3sJ8fG5hL0pP2",
    "Z",
    "9",
    render_env_reports,
    render_eof_reports,
    render_overlong_letter_suppressed,
    render_overlong_digit_suppressed,
    render_backends_agree_suppressed
);
vendor_boundary!(
    "deepseek-api-key",
    "sk-4e1d93c6b8072a5f9e13d0c7b4a8623f",
    "a",
    "0",
    deepseek_env_reports,
    deepseek_eof_reports,
    deepseek_overlong_letter_suppressed,
    deepseek_overlong_digit_suppressed,
    deepseek_backends_agree_suppressed
);
vendor_boundary!(
    "digitalocean-pat",
    "dop_v1_6528a0f4e1d93c6b8072a5f9e13d0c7b4a8623f9a1c7e5b2d8046af31e9c04d7",
    "a",
    "0",
    digitalocean_env_reports,
    digitalocean_eof_reports,
    digitalocean_overlong_letter_suppressed,
    digitalocean_overlong_digit_suppressed,
    digitalocean_backends_agree_suppressed
);

#[test]
fn every_enrolled_detector_regex_ends_with_word_boundary() {
    let detectors =
        keyhog_core::load_detectors(&support::paths::detector_dir()).expect("detectors");
    for id in DETECTOR_IDS {
        let det = detectors
            .iter()
            .find(|d| &d.id.as_str() == id)
            .unwrap_or_else(|| panic!("{id} must exist"));
        let fixed = det
            .patterns
            .iter()
            .find(|p| regex_ends_in_fixed_quantifier(&p.regex))
            .unwrap_or_else(|| panic!("{id} must have a fixed-length token pattern"));
        assert!(
            fixed.regex.trim_end().ends_with(r"\b"),
            "{id} fixed-length token regex must keep its trailing \\b: {}",
            fixed.regex
        );
    }
}

/// True when the regex (ignoring a trailing `\b`) ends in a `[...]{N}` class.
fn regex_ends_in_fixed_quantifier(regex: &str) -> bool {
    let core = regex
        .trim_end()
        .strip_suffix(r"\b")
        .unwrap_or(regex.trim_end());
    if let Some(open) = core.rfind('{') {
        let tail = &core[open..];
        return tail.ends_with('}')
            && tail[1..tail.len() - 1].chars().all(|c| c.is_ascii_digit())
            && core[..open].ends_with(']');
    }
    false
}
