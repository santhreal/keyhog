//! E2E (#32): `keyhog calibrate-autoroute` primes the full preset × workload
//! matrix in one command — the in-binary counterpart to the installer's
//! `prime_autoroute_cache` shell loop. Afterward a plain auto scan whose
//! workload matches a calibrated bucket must resolve a backend for EVERY
//! documented preset (never fail closed, exit 2), proving the subcommand
//! persisted the same buckets the shell loop did.
//!
//! Unlike the lighter `autoroute_preset_resolution` test (which calibrates and
//! verifies the same file), this drives the real subcommand end to end — it
//! sweeps `--deep` too and inherits its env into the child probes — then
//! verifies against a SEPARATE file at a calibrated ladder size, so it also
//! proves the spawn + cache-path plumbing and that decisions persist across
//! processes.
//!
//! The verifying targets cover (a) the ladder's exact single-file buckets
//! (4 KiB, 64 KiB) and (b) a sub-floor tiny file (`keyhog scan small.env`),
//! which resolves through the #44 below-floor clamp to setup-free CpuFallback
//! rather than failing closed — so this also proves the everyday small-file
//! scan never exits 2 after calibration.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

/// Write `bytes` of plain, low-decode-density text. The block is the same
/// trigger-free seed `calibrate-autoroute` builds its plain single-file probes
/// from (no decode-trigger bytes like `=`/`"`, no 24-char+ alnum runs), so the
/// file lands in decode-density bucket 0 — the exact class of the calibrated
/// plain single-file rungs. A `=` or a long token would shift it to a different
/// density class the rungs never calibrate.
fn write_plain_bytes(path: &std::path::Path, bytes: usize) {
    let block = "src path one. scan text two. keyhog route plain. config value sample. ";
    let mut buf = String::with_capacity(bytes + block.len());
    while buf.len() < bytes {
        buf.push_str(block);
    }
    buf.truncate(bytes);
    std::fs::write(path, buf).expect("write calibration-sized probe");
}

#[test]
fn calibrate_autoroute_primes_every_preset_for_a_later_scan() {
    let cache = TempDir::new().expect("cache home");
    let work = TempDir::new().expect("workdir");

    // One command calibrates the default policy + every preset across the whole
    // workload ladder. The child `keyhog scan --autoroute-calibrate` probes
    // inherit XDG_CACHE_HOME + KEYHOG_NO_GPU, so they write to the isolated
    // cache and route on CPU exactly like the verifying scans below.
    let out = Command::new(binary())
        .arg("calibrate-autoroute")
        .env("XDG_CACHE_HOME", cache.path())
        .env("KEYHOG_NO_GPU", "1")
        .output()
        .expect("spawn keyhog calibrate-autoroute");
    assert!(
        out.status.success(),
        "calibrate-autoroute must exit 0; got {:?}\nSTDOUT:\n{}\nSTDERR:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // Verify against SEPARATE files at calibrated ladder sizes (4 KiB and
    // 64 KiB single files). After one sweep, a plain auto scan with each
    // documented preset must RESOLVE a decision (exit 0/1), never fail closed
    // (exit 2). Each scan keys the same `--no-config` default digest the
    // calibration probes used, so a miss would mean the subcommand failed to
    // persist that bucket.
    let four_kib = work.path().join("probe-4kib.txt");
    let sixty_four_kib = work.path().join("probe-64kib.txt");
    write_plain_bytes(&four_kib, 4 * 1024);
    write_plain_bytes(&sixty_four_kib, 64 * 1024);
    // A sub-floor tiny file — the everyday `keyhog scan small.config`. At 512
    // bytes it is strictly below the ladder's smallest single-file probe (4 KiB)
    // on both size axes, so it can only resolve via the #44 below-floor clamp;
    // before that fix this exited 2. Built from the same trigger-free plain block
    // as the rungs, so it shares their decode-density class and the clamp finds
    // its floor.
    let tiny = work.path().join("small.config");
    write_plain_bytes(&tiny, 512);

    for preset in [&[][..], &["--fast"], &["--deep"], &["--precision"]] {
        for target in [&four_kib, &sixty_four_kib, &tiny] {
            let target_arg = target.to_string_lossy().into_owned();
            let mut args: Vec<&str> = vec!["scan", "--no-daemon", "--no-config"];
            args.extend_from_slice(preset);
            args.extend_from_slice(&["--format", "json", &target_arg]);
            let scan = Command::new(binary())
                .args(&args)
                .env("XDG_CACHE_HOME", cache.path())
                .env("KEYHOG_NO_GPU", "1")
                .output()
                .expect("spawn keyhog scan");
            let code = scan.status.code();
            assert!(
                matches!(code, Some(0) | Some(1)),
                "after calibrate-autoroute, auto scan {preset:?} of {} must resolve a backend \
                 (exit 0/1), never fail closed (exit 2); got {code:?}\nSTDERR:\n{}",
                target.display(),
                String::from_utf8_lossy(&scan.stderr),
            );
        }
    }
}

#[test]
fn calibrate_autoroute_rejects_cache_off_up_front() {
    // Calibration must persist; `--autoroute-cache off` disables persistence, so
    // it is rejected up front with ONE clear line — not a flood of per-probe
    // "did not persist a routing decision" failures (the original dogfood bug).
    let out = Command::new(binary())
        .args(["calibrate-autoroute", "--autoroute-cache", "off"])
        .env("KEYHOG_NO_GPU", "1")
        .output()
        .expect("spawn keyhog calibrate-autoroute");
    assert!(
        !out.status.success(),
        "calibrate-autoroute --autoroute-cache off must exit non-zero; got {:?}",
        out.status.code(),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("disables persistence")
            && stderr.contains("calibrate-autoroute exists to"),
        "the rejection must explain why `off` is incompatible with calibration; stderr={stderr}"
    );
    // Fail-fast: it must NOT have flooded per-probe failures before bailing.
    assert!(
        !stderr.contains("did not persist a routing decision"),
        "off must be rejected BEFORE any probe runs, not after each fails; stderr={stderr}"
    );
}
