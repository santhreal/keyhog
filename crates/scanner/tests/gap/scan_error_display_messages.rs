//! Gap test: exact `ScanError` Display text + the "Fix:" guidance contract.
//!
//! The engineering standard is that error messages "include context and the
//! fix" (CLAUDE.md Engineering Standards; task #131). This pins the EXACT Display
//! string of every fully-controlled variant, proves each carries actionable
//! `Fix:` guidance, and checks that the operator-visible detail (`{0}` / the
//! detector id / index / group) survives into the rendered message.

use keyhog_scanner::ScanError;

const GPU_FIX: &str = ". Fix: rerun with `--backend cpu` to scan on the CPU path, or run \
                       `keyhog doctor` to diagnose the GPU stack";
const SIMD_FIX: &str = ". Fix: rerun with `--backend cpu` for the portable scalar path, or run \
                        `keyhog doctor` to check CPU feature detection";

/// The String-carrying variants, each rendered with a sentinel inner detail.
fn string_variant_messages() -> Vec<(&'static str, String)> {
    vec![
        (
            "Gpu",
            ScanError::Gpu("INNER_DETAIL".to_string()).to_string(),
        ),
        (
            "Simd",
            ScanError::Simd("INNER_DETAIL".to_string()).to_string(),
        ),
        (
            "Config",
            ScanError::Config("INNER_DETAIL".to_string()).to_string(),
        ),
    ]
}

#[test]
fn gpu_failure_display_is_exact() {
    assert_eq!(
        ScanError::Gpu("probe failed".to_string()).to_string(),
        format!("GPU scanner failure: probe failed{GPU_FIX}")
    );
}

#[test]
fn simd_failure_display_is_exact() {
    assert_eq!(
        ScanError::Simd("init blew up".to_string()).to_string(),
        format!("SIMD scanner failure: init blew up{SIMD_FIX}")
    );
}

#[test]
fn config_failure_display_is_exact() {
    assert_eq!(
        ScanError::Config("rules file missing".to_string()).to_string(),
        "scanner configuration failure: rules file missing. Fix: correct the bundled scanner rules"
    );
}

#[test]
fn every_string_variant_message_carries_fix_guidance() {
    for (name, msg) in string_variant_messages() {
        assert!(
            msg.contains(". Fix: "),
            "ScanError::{name} display must carry `. Fix: ` guidance; got: {msg}"
        );
    }
}

#[test]
fn every_string_variant_message_preserves_the_inner_detail() {
    for (name, msg) in string_variant_messages() {
        assert!(
            msg.contains("INNER_DETAIL"),
            "ScanError::{name} display must preserve the operator-visible inner detail; got: {msg}"
        );
    }
}

#[test]
fn every_string_variant_puts_fix_after_the_detail() {
    // The fix guidance must come AFTER the inner detail so operators read what
    // failed before what to do about it.
    for (name, msg) in string_variant_messages() {
        let detail = msg.find("INNER_DETAIL").expect("detail present");
        let fix = msg.find(". Fix: ").expect("fix present");
        assert!(
            detail < fix,
            "ScanError::{name} must render the detail before the Fix; got: {msg}"
        );
    }
}

#[test]
fn gpu_and_simd_fix_offers_the_cpu_backend_fallback() {
    // A fatal GPU/SIMD failure is exactly when the operator needs to know they can
    // fall back to the portable path — the single most actionable next step.
    assert!(ScanError::Gpu("x".to_string())
        .to_string()
        .contains("--backend cpu"));
    assert!(ScanError::Simd("x".to_string())
        .to_string()
        .contains("--backend cpu"));
}

#[test]
fn gpu_and_simd_fix_points_at_doctor() {
    assert!(ScanError::Gpu("x".to_string())
        .to_string()
        .contains("keyhog doctor"));
    assert!(ScanError::Simd("x".to_string())
        .to_string()
        .contains("keyhog doctor"));
}

#[test]
fn gpu_fix_suffix_is_exact() {
    assert!(
        ScanError::Gpu("x".to_string())
            .to_string()
            .ends_with(GPU_FIX),
        "GPU fix suffix drifted"
    );
}

#[test]
fn simd_fix_suffix_is_exact() {
    assert!(
        ScanError::Simd("x".to_string())
            .to_string()
            .ends_with(SIMD_FIX),
        "SIMD fix suffix drifted"
    );
}

#[test]
fn gpu_and_simd_fix_guidance_is_distinct() {
    // The two paths point at different diagnostics (GPU stack vs CPU feature
    // detection); they must not collapse to one generic string.
    assert_ne!(GPU_FIX, SIMD_FIX);
    assert!(GPU_FIX.contains("GPU stack"));
    assert!(SIMD_FIX.contains("CPU feature detection"));
}

#[test]
fn config_fix_names_the_bundled_rules() {
    assert!(ScanError::Config("x".to_string())
        .to_string()
        .contains("Fix: correct the bundled scanner rules"));
}

#[test]
fn regex_compile_display_template_and_fix_suffix_are_exact() {
    let err = ScanError::RegexCompile {
        detector_id: "aws-key".to_string(),
        index: 2,
        source: regex::Error::Syntax("oops".to_string()),
    };
    let msg = err.to_string();
    assert!(
        msg.starts_with("failed to compile regex for detector aws-key pattern 2: "),
        "got: {msg}"
    );
    assert!(
        msg.ends_with(". Fix: correct the detector regex or capture group configuration"),
        "got: {msg}"
    );
}

#[test]
fn regex_compile_preserves_detector_and_index() {
    let err = ScanError::RegexCompile {
        detector_id: "stripe-secret-key".to_string(),
        index: 7,
        source: regex::Error::Syntax("bad".to_string()),
    };
    let msg = err.to_string();
    assert!(msg.contains("detector stripe-secret-key"), "got: {msg}");
    assert!(msg.contains("pattern 7"), "got: {msg}");
}

#[test]
fn regex_set_compile_display_carries_fix() {
    let err: ScanError = regex::Error::Syntax("setboom".to_string()).into();
    let msg = err.to_string();
    assert!(
        msg.starts_with("failed to compile scanner regex set: "),
        "got: {msg}"
    );
    assert!(
        msg.ends_with(". Fix: simplify the detector regex set or remove the invalid pattern"),
        "got: {msg}"
    );
}

#[test]
fn regex_compile_and_regex_set_fixes_are_distinct() {
    // The single-pattern compile failure and the whole-set compile failure give
    // different remedies; a shared generic fix would mislead the operator.
    let compile = ScanError::RegexCompile {
        detector_id: "d".to_string(),
        index: 0,
        source: regex::Error::Syntax("a".to_string()),
    }
    .to_string();
    let set: String = Into::<ScanError>::into(regex::Error::Syntax("b".to_string())).to_string();
    assert_ne!(
        compile.rsplit(". Fix: ").next(),
        set.rsplit(". Fix: ").next(),
        "single-pattern and regex-set failures must give distinct fixes"
    );
}

#[test]
fn capture_group_out_of_range_names_every_field_and_the_fix() {
    let err = ScanError::CaptureGroupOutOfRange {
        detector_id: "gh-pat".to_string(),
        index: 1,
        group: 3,
        captures_len: 1,
    };
    let msg = err.to_string();
    assert!(msg.contains("detector gh-pat pattern 1"), "got: {msg}");
    assert!(msg.contains("capture group 3"), "got: {msg}");
    assert!(msg.contains("only 1 group(s)"), "got: {msg}");
    assert!(msg.contains("valid indices 0..1"), "got: {msg}");
    assert!(msg.contains("Fix: set `group`"), "got: {msg}");
}

#[test]
fn capture_group_out_of_range_explains_the_fallback_risk() {
    // The message must explain WHY the misconfiguration matters (context), not just
    // state it — the whole-match fallback silently captures the wrong bytes.
    let msg = ScanError::CaptureGroupOutOfRange {
        detector_id: "d".to_string(),
        index: 0,
        group: 2,
        captures_len: 1,
    }
    .to_string();
    assert!(
        msg.contains("fall back to the whole match"),
        "capture-group error must explain the fallback risk; got: {msg}"
    );
}

#[test]
fn regex_compile_renders_the_inner_source_error() {
    // The `{source}` render sits BETWEEN the context prefix and the Fix suffix;
    // prove the underlying regex error text actually reaches the operator.
    let err = ScanError::RegexCompile {
        detector_id: "d".to_string(),
        index: 0,
        source: regex::Error::Syntax("UNIQUE_SYNTAX_TEXT".to_string()),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("UNIQUE_SYNTAX_TEXT"),
        "the {{source}} regex error must render into the message; got: {msg}"
    );
    // ...and it must sit before the Fix so the operator reads the cause first.
    assert!(
        msg.find("UNIQUE_SYNTAX_TEXT") < msg.find(". Fix:"),
        "the source detail must precede the Fix; got: {msg}"
    );
}

#[test]
fn aho_corasick_variant_error_template_declares_the_fix() {
    // Source-level guarantee independent of whether a BuildError can be provoked at
    // runtime: the variant's `#[error]` template carries the Fix guidance.
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/error.rs"))
        .expect("scanner error.rs readable");
    assert!(
        src.contains("failed to build Aho-Corasick literal matcher: {0}. Fix: check for empty or invalid detector keywords"),
        "AhoCorasick variant must declare Fix guidance in its #[error] template"
    );
}

#[test]
fn every_error_variant_template_declares_a_fix() {
    // Whole-enum guard: no ScanError `#[error(...)]` template may ship without a
    // `Fix:` clause. The two String-detail variants render the fix after `{0}`; the
    // structured variants embed it in the template. This catches a NEW variant
    // added without fix guidance.
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/error.rs"))
        .expect("scanner error.rs readable");
    // Count `#[error(` templates and `Fix:` occurrences inside the enum; each
    // template must contribute exactly one Fix clause.
    let templates = src.matches("#[error(").count();
    let fixes = src.matches("Fix:").count();
    assert!(
        templates >= 7,
        "expected all ScanError variants present; got {templates}"
    );
    assert_eq!(
        templates, fixes,
        "every ScanError #[error(...)] template must carry exactly one `Fix:` clause \
         ({templates} templates, {fixes} Fix clauses)"
    );
}
