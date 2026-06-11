//! MC-02 regression: a preset (`--deep`/`--fast`/`--precision`) is a BASE that
//! seeds defaults, then per-flag overrides layer on top. The pre-fix
//! `build_scanner_config` early-returned at the preset, so `--deep
//! --decode-depth 3` silently dropped the explicit `--decode-depth` — "what the
//! operator asked for" != "what ran". These asserts pin TRUTH (the resolved
//! config field values), not the shape of the parsed args: `--deep` alone must
//! apply the thorough preset's decode depth (10), and `--deep --decode-depth 3`
//! must let the explicit override win (3).

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::orchestrator_config::build_scanner_config;

#[test]
fn deep_preset_applies_thorough_decode_depth_base() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--deep"]).unwrap();
    let cfg = build_scanner_config(&args);
    // ScannerConfig::thorough() seeds max_decode_depth = 10.
    assert_eq!(
        cfg.max_decode_depth, 10,
        "--deep must apply the thorough preset's decode-depth base (10), got {}",
        cfg.max_decode_depth
    );
}

#[test]
fn deep_preset_then_explicit_decode_depth_override_wins() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--deep", "--decode-depth", "3"]).unwrap();
    let cfg = build_scanner_config(&args);
    // The explicit override must layer on top of the preset base — the MC-02 bug
    // was this value being silently dropped to the preset's 10.
    assert_eq!(
        cfg.max_decode_depth, 3,
        "--deep --decode-depth 3 must yield 3 (override layers over preset), got {}",
        cfg.max_decode_depth
    );
}
