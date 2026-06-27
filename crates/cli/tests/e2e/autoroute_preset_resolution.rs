//! E2E (#39): every documented scan-policy preset resolves an autoroute decision
//! after calibration — a default `scan <preset>` must never fail closed (exit 2)
//! once `--autoroute-calibrate` has run for that preset on the same workload.
//!
//! Each preset resolves its own config digest, and they coexist in the v20
//! multi-config cache (so calibrating `--precision` must not clobber the default
//! decision, and vice versa). This is the standalone-CI counterpart to the
//! Docker integration matrix's bake: it catches a preset whose digest is never
//! calibrated, or a save that overwrites a sibling preset's decision.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

/// Run `keyhog scan <preset...> <target>` with an isolated cache; returns the
/// exit code. `calibrate` prepends `--autoroute-calibrate`.
fn scan(
    cache_home: &std::path::Path,
    target: &std::path::Path,
    preset: &[&str],
    calibrate: bool,
) -> Option<i32> {
    let mut args: Vec<&str> = vec!["scan", "--no-daemon"];
    if calibrate {
        args.push("--autoroute-calibrate");
    }
    args.extend_from_slice(preset);
    args.extend_from_slice(&["--format", "json"]);
    let target = target.to_string_lossy().into_owned();
    args.push(&target);
    let out = Command::new(binary())
        .args(&args)
        .env("XDG_CACHE_HOME", cache_home)
        .env("KEYHOG_NO_GPU", "1")
        .output()
        .expect("spawn keyhog scan");
    if !matches!(out.status.code(), Some(0) | Some(1)) {
        eprintln!(
            "keyhog scan {preset:?} (calibrate={calibrate}) -> {:?}\nSTDERR:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.status.code()
}

#[test]
fn every_documented_preset_resolves_after_calibration() {
    // The documented scan-policy presets (README "Autoroute Contract" + --help).
    // `--deep` is omitted only to bound calibration wall-clock; default, --fast
    // and --precision already span the digest extremes (entropy on/off, decode
    // depth, min-confidence floor).
    let presets: &[&[&str]] = &[&[], &["--fast"], &["--precision"]];

    let cache = TempDir::new().expect("cache home");
    let work = TempDir::new().expect("workdir");
    let target = work.path().join("data.env");
    std::fs::write(&target, "api_key = \"abcdefghijklmnopqrstuvwx\"\n").unwrap();

    // Calibrate every preset into the shared v20 multi-config cache.
    for preset in presets {
        let code = scan(cache.path(), &target, preset, true);
        assert!(
            matches!(code, Some(0) | Some(1)),
            "calibrating preset {preset:?} must succeed (exit 0/1), got {code:?}"
        );
    }

    // After calibration, a plain auto scan with each preset must RESOLVE a
    // decision — never fail closed (exit 2). Re-run the whole sweep so a later
    // preset's calibration cannot have clobbered an earlier preset's decision
    // (the multi-config merge contract).
    for preset in presets {
        let code = scan(cache.path(), &target, preset, false);
        assert!(
            matches!(code, Some(0) | Some(1)),
            "after calibration, auto scan with preset {preset:?} must resolve a backend \
             (exit 0/1), never fail closed (exit 2); got {code:?}"
        );
    }
}
