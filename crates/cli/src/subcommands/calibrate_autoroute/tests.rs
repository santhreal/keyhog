//! Unit tests for `subcommands::calibrate_autoroute`. Split into a separate
//! `tests.rs` module (rather than an inline `#[cfg(test)] mod tests {}` block) so
//! the `no_inline_tests_in_src` gate stays green while these still reach the
//! parent module's PRIVATE helpers (`calibration_block`, `core_workload_plan`,
//! the seeds) via `use super::*`: coverage an out-of-crate integration test
//! could not provide.

use super::*;

#[test]
fn scan_policy_plan_covers_every_digest_changing_preset() {
    assert_eq!(SCAN_POLICY_PRESETS, ["--fast", "--deep", "--precision"]);
}

#[test]
fn plain_block_is_exactly_one_kib() {
    assert_eq!(calibration_block(PLAIN_SEED).len(), 1024);
    assert_eq!(calibration_block(DECODE_HEAVY_SEED).len(), 1024);
}

#[test]
fn calibration_bytes_are_exact_block_prefix_runs() {
    assert!(calibration_bytes(PLAIN_SEED, 0).is_empty());
    assert_eq!(calibration_bytes(PLAIN_SEED, 512).len(), 512);
    assert_eq!(calibration_bytes(PLAIN_SEED, 4 * 1024).len(), 4 * 1024);
    assert_eq!(calibration_bytes(PLAIN_SEED, 64 * 1024).len(), 64 * 1024);
    // The first 1024 bytes equal one block (probes are block runs, not noise).
    let buf = calibration_bytes(PLAIN_SEED, 8 * 1024);
    assert_eq!(&buf[..1024], calibration_block(PLAIN_SEED).as_slice());
}

#[test]
fn workload_plan_matches_the_installer_ladder() {
    let plan = core_workload_plan();
    // 2 stdin + 18 single-file (incl. decode-heavy) + 3 file-tree workloads.
    assert_eq!(plan.len(), 23);
    let labels: Vec<&str> = plan.iter().map(Workload::label).collect();
    assert!(labels.contains(&"empty stdin workload"));
    assert!(labels.contains(&"1 KiB workload"));
    assert!(labels.contains(&"16 KiB workload"));
    assert!(labels.contains(&"256 KiB workload"));
    assert!(labels.contains(&"4 MiB workload"));
    assert!(labels.contains(&"decode-heavy 256 KiB workload"));
    assert!(labels.contains(&"32 MiB workload"));
    assert!(labels.contains(&"32 x 4 KiB files workload"));

    let plain_file_bytes: Vec<usize> = plan
        .iter()
        .filter_map(|workload| match workload {
            Workload::File {
                bytes,
                decode_heavy: false,
                ..
            } => Some(*bytes),
            _ => None,
        })
        .collect();
    assert_eq!(
        plain_file_bytes,
        [
            512,
            1024,
            2 * 1024,
            4 * 1024,
            8 * 1024,
            16 * 1024,
            32 * 1024,
            64 * 1024,
            128 * 1024,
            256 * 1024,
            512 * 1024,
            1024 * 1024,
            2 * 1024 * 1024,
            4 * 1024 * 1024,
            8 * 1024 * 1024,
            16 * 1024 * 1024,
            32 * 1024 * 1024,
        ],
        "plain probes must represent every power-of-two file-size band through 32 MiB"
    );
}

#[test]
fn decode_heavy_block_is_denser_than_plain() {
    // The decode-heavy seed must carry materially more base64-alphabet run
    // content than the plain seed, or the two probes collapse into the same
    // decode-density bucket and the decode-through path is never timed.
    fn longest_b64_run(bytes: &[u8]) -> usize {
        let mut best = 0usize;
        let mut run = 0usize;
        for &b in bytes {
            let b64 = b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=');
            if b64 {
                run += 1;
                best = best.max(run);
            } else {
                run = 0;
            }
        }
        best
    }
    let plain = longest_b64_run(calibration_block(PLAIN_SEED).as_slice());
    let heavy = longest_b64_run(calibration_block(DECODE_HEAVY_SEED).as_slice());
    assert!(
        heavy >= plain + 24,
        "decode-heavy block (longest b64 run {heavy}) must clear the plain block \
         (longest run {plain}) by the encoded-run threshold"
    );
}
