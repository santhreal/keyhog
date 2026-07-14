//! Unit tests for `subcommands::calibrate_autoroute`. Split into a separate
//! `tests.rs` module (rather than an inline `#[cfg(test)] mod tests {}` block) so
//! the `no_inline_tests_in_src` gate stays green while these still reach the
//! parent module's PRIVATE helpers (`calibration_block`, `core_workload_plan`,
//! the seeds) via `use super::*`: coverage an out-of-crate integration test
//! could not provide.

use super::*;
use keyhog_core::Source;

#[test]
fn scan_policy_plan_covers_every_digest_changing_preset() {
    assert_eq!(SCAN_POLICY_PRESETS, ["--fast", "--deep", "--precision"]);
}

#[test]
fn measured_route_count_deduplicates_aliases_and_excludes_a_seeded_row() {
    let digest = "00000000000000aa";
    let host = "host-identity-a";
    let aliased_key = "bytes_log2=13 chunks_log2=1 source_mixture=[filesystem/full]";
    let measured = ["2-file representative", "3-file representative"]
        .into_iter()
        .map(|_| {
            (
                digest.to_string(),
                host.to_string(),
                aliased_key.to_string(),
            )
        })
        .chain(std::iter::once((
            "00000000000000bb".to_string(),
            host.to_string(),
            aliased_key.to_string(),
        )))
        .collect();

    // Both representatives resolve to one canonical workload key. The same
    // config also contains one externally seeded route decision. The other
    // config's identical workload key remains a distinct measured class.
    let persisted_routes = [
        (
            digest.to_string(),
            host.to_string(),
            aliased_key.to_string(),
        ),
        (
            "00000000000000bb".to_string(),
            host.to_string(),
            aliased_key.to_string(),
        ),
        (
            digest.to_string(),
            host.to_string(),
            "externally seeded web route".to_string(),
        ),
    ]
    .into_iter()
    .collect();
    let (persisted, measured_now) =
        calibration_summary_counts(&persisted_routes, &measured).expect("summary counts");

    assert_eq!(persisted, 3);
    assert_eq!(measured_now, 2);
}

#[test]
fn calibration_summary_rejects_a_measured_class_missing_from_final_cache() {
    let measured = [(
        "00000000000000aa".to_string(),
        "host-identity-a".to_string(),
        "canonical workload".to_string(),
    )]
    .into_iter()
    .collect();

    let error = calibration_summary_counts(&BTreeSet::new(), &measured)
        .expect_err("missing measured receipt must fail closed");

    assert!(error
        .to_string()
        .contains("final cache readback did not contain it"));
}

#[test]
fn calibration_summary_rejects_another_hosts_matching_config_and_workload() {
    let persisted = [(
        "00000000000000aa".to_string(),
        "host-identity-a".to_string(),
        "canonical workload".to_string(),
    )]
    .into_iter()
    .collect();
    let measured = [(
        "00000000000000aa".to_string(),
        "host-identity-b".to_string(),
        "canonical workload".to_string(),
    )]
    .into_iter()
    .collect();

    let error = calibration_summary_counts(&persisted, &measured)
        .expect_err("another host's row must not satisfy current-host readback");

    assert!(error.to_string().contains("host-identity-b"));
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
fn plain_route_probe_has_sparse_real_phase2_work_without_changing_size() {
    let below_interval = plain_calibration_bytes(SPARSE_TRIGGER_INTERVAL - 1);
    assert_eq!(below_interval.len(), SPARSE_TRIGGER_INTERVAL - 1);
    assert!(!below_interval
        .windows(SPARSE_TRIGGER.len())
        .any(|window| window == SPARSE_TRIGGER));

    let two_intervals = plain_calibration_bytes(2 * SPARSE_TRIGGER_INTERVAL);
    assert_eq!(two_intervals.len(), 2 * SPARSE_TRIGGER_INTERVAL);
    assert_eq!(
        two_intervals
            .windows(SPARSE_TRIGGER.len())
            .filter(|window| *window == SPARSE_TRIGGER)
            .count(),
        2,
        "plain calibration must model one valid sparse confirmation per 64 KiB"
    );
}

#[test]
fn workload_plan_matches_the_installer_ladder() {
    let plan = core_workload_plan();
    // 1 stdin + 27 single-file + every fused count for full-size and extracted payloads.
    assert_eq!(plan.len(), 92);
    let labels: Vec<&str> = plan.iter().map(Workload::label).collect();
    assert!(labels.contains(&"stdin 64 KiB workload"));
    assert!(labels.contains(&"1 B workload"));
    assert!(labels.contains(&"1 KiB workload"));
    assert!(labels.contains(&"16 KiB workload"));
    assert!(labels.contains(&"256 KiB workload"));
    assert!(labels.contains(&"4 MiB workload"));
    assert!(labels.contains(&"decode-heavy 256 KiB workload"));
    assert!(labels.contains(&"32 MiB workload"));
    assert!(labels.contains(&"1 x 4 KiB files workload"));
    assert!(labels.contains(&"17 x 4 KiB files workload"));
    assert!(labels.contains(&"32 x 4 KiB files workload"));
    assert!(labels.contains(&"1 x 4 KiB tar members workload"));
    assert!(labels.contains(&"17 x 4 KiB tar members workload"));
    assert!(labels.contains(&"32 x 4 KiB tar members workload"));

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
            1,
            2,
            4,
            8,
            16,
            32,
            64,
            128,
            256,
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

    let tree_counts: Vec<usize> = plan
        .iter()
        .filter_map(|workload| match workload {
            Workload::Tree { files, .. } => Some(*files),
            _ => None,
        })
        .collect();
    assert_eq!(
        tree_counts,
        (1..=crate::orchestrator_config::FUSED_BATCH_DEFAULT).collect::<Vec<_>>(),
        "tree probes must represent every exact count in the default fused batch"
    );

    let tar_member_counts: Vec<usize> = plan
        .iter()
        .filter_map(|workload| match workload {
            Workload::Tar { members, .. } => Some(*members),
            _ => None,
        })
        .collect();
    assert_eq!(
        tar_member_counts,
        (1..=crate::orchestrator_config::FUSED_BATCH_DEFAULT).collect::<Vec<_>>(),
        "archive probes must represent every exact extracted payload count"
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

#[test]
fn tar_probe_materializes_exact_payload_derived_member_batch() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let workload = Workload::Tar {
        label: "test tar".to_string(),
        members: 17,
        kib: 4,
    };
    let MaterializedProbe::Filesystem(path) =
        materialize_probe(workspace.path(), 1, &workload).expect("materialize tar")
    else {
        panic!("tar representative must remain a filesystem source");
    };
    let source = keyhog_sources::FilesystemSource::new(path);
    let chunks: Vec<keyhog_core::Chunk> = source
        .chunks()
        .map(|chunk| chunk.expect("read tar member"))
        .collect();

    assert_eq!(chunks.len(), 17);
    assert!(chunks.iter().all(|chunk| {
        chunk.data.len() == 4 * 1024
            && chunk.metadata.size_bytes.is_none()
            && chunk.metadata.source_type.starts_with("filesystem/archive")
    }));
}
