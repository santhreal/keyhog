//! Unit tests for `subcommands::calibrate_autoroute`. Split into a separate
//! `tests.rs` module (rather than an inline `#[cfg(test)] mod tests {}` block) so
//! the `no_inline_tests_in_src` gate stays green while these still reach the
//! parent module's PRIVATE helpers (`calibration_block`, `core_workload_plan`,
//! the seeds) via `use super::*`: coverage an out-of-crate integration test
//! could not provide.

use super::*;
use keyhog_core::Source;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;

#[test]
fn scan_policy_plan_covers_every_digest_changing_preset() {
    assert_eq!(SCAN_POLICY_PRESETS, ["--fast", "--deep", "--precision"]);
}

#[test]
fn isolated_policy_children_use_stable_cli_values() {
    assert_eq!(
        policy_cli_value(AutorouteCalibrationPolicy::Default),
        "default"
    );
    assert_eq!(policy_cli_value(AutorouteCalibrationPolicy::Fast), "fast");
    assert_eq!(policy_cli_value(AutorouteCalibrationPolicy::Deep), "deep");
    assert_eq!(
        policy_cli_value(AutorouteCalibrationPolicy::Precision),
        "precision"
    );
}

/// WHY: the all-policy parent measures nothing itself; four child processes do.
/// A flag that reaches the parent and not the child changes what was measured
/// against what was asked for. `--no-config` was dropped exactly there, so an
/// `install.sh` that asked for the compiled-in baseline published 629 decisions
/// under the `.keyhog.toml` the install directory happened to carry, and the
/// first ordinary scan after a clean 40-minute install exited 2.
///
/// WHAT IT DOES NOT CATCH: a flag the child parses but ignores.
#[test]
fn isolated_policy_children_inherit_the_parents_measurement_flags() {
    let staged = Path::new("/tmp/staged-autoroute.json");
    let receipts = Path::new("/tmp/receipts.json");
    for no_config in [true, false] {
        for quiet in [true, false] {
            for packs in [None, Some(PathBuf::from("/opt/keyhog/packs"))] {
                let parent = CalibrateAutorouteArgs {
                    autoroute_cache: Some("/home/user/.cache/keyhog/autoroute.json".to_string()),
                    execution_packs: packs.clone(),
                    measurement_receipts: None,
                    policy: AutorouteCalibrationPolicy::All,
                    no_config,
                    quiet,
                };
                let argv = isolated_policy_argv(&parent, "fast", staged, receipts);
                assert_eq!(
                    argv.first().map(OsString::as_os_str),
                    Some(OsStr::new("calibrate-autoroute")),
                    "the child re-enters this subcommand"
                );
                let child = CalibrateAutorouteArgs::try_parse_from(
                    std::iter::once(OsString::from("keyhog")).chain(argv.into_iter().skip(1)),
                )
                .expect("the child argv the parent spawns must parse");

                assert_eq!(
                    child.no_config, parent.no_config,
                    "the child measures under the configuration the parent was asked for"
                );
                assert_eq!(child.quiet, parent.quiet);
                assert_eq!(child.execution_packs, parent.execution_packs);
                // Parent-owned: one policy per child, the parent's staged
                // transaction rather than the live cache, one receipt sink.
                assert_eq!(child.policy, AutorouteCalibrationPolicy::Fast);
                assert_eq!(child.autoroute_cache.as_deref(), staged.to_str());
                assert_eq!(child.measurement_receipts.as_deref(), Some(receipts));
            }
        }
    }
}

/// WHY: the forwarding above is a decision per flag, and a flag added later
/// gets no decision at all unless something demands one. The flag set is read
/// out of clap at run time, so a new `#[arg]` on `CalibrateAutorouteArgs` turns
/// this red until it is either forwarded or recorded as parent-owned.
#[test]
fn every_calibration_flag_has_a_forwarding_decision() {
    use clap::CommandFactory;

    // Forwarded to every child: these change what gets measured or printed.
    let forwarded = ["no-config", "quiet", "execution-packs"];
    // Owned by the parent: the child gets a different value by construction.
    let parent_owned = ["policy", "autoroute-cache", "measurement-receipts"];

    let declared: BTreeSet<String> = CalibrateAutorouteArgs::command()
        .get_arguments()
        .filter_map(|arg| arg.get_long().map(str::to_string))
        .filter(|long| long != "help")
        .collect();
    let decided: BTreeSet<String> = forwarded
        .iter()
        .chain(parent_owned.iter())
        .map(|flag| (*flag).to_string())
        .collect();
    assert_eq!(
        declared,
        decided,
        "every calibrate-autoroute flag must be forwarded to the isolated policy \
         children or explicitly owned by the parent\n  undecided: {:?}\n  stale: {:?}",
        declared.difference(&decided).collect::<Vec<_>>(),
        decided.difference(&declared).collect::<Vec<_>>(),
    );
}

#[test]
fn only_inconclusive_timing_failures_are_retryable() {
    assert!(retryable_inconclusive_calibration(&anyhow::anyhow!(
        "cache decision has no confidence-supported daemon route across every measured point"
    )));
    assert!(retryable_inconclusive_calibration(&anyhow::anyhow!(
        "calibration timing does not resolve one route: the measured points disagree"
    )));
    for diagnostic in [
        "workload class changes its confidence-supported backend across measured points",
        "workload class changes its confidence-supported remaining daemon recovery backend",
        "existing workload evidence has no unanimous daemon recovery route after simd-regex",
        "new workload point does not resolve one one-shot route",
        "new workload point has no daemon recovery route after gpu-cuda-region-presence",
    ] {
        assert!(
            retryable_inconclusive_calibration(&anyhow::anyhow!(diagnostic)),
            "timing disagreement must be retried: {diagnostic}",
        );
    }
    assert!(
        !retryable_inconclusive_calibration(&anyhow::anyhow!(
            "calibration timing is inconclusive: intervals overlap"
        )),
        "overlapping intervals now resolve to a dead-heat route instead of failing"
    );
    assert!(!retryable_inconclusive_calibration(&anyhow::anyhow!(
        "autoroute cache path is not writable"
    )));
}

/// Calibration persists its decisions under the config digest its own argv
/// resolves, and a later scan looks them up under the digest ITS argv resolves.
/// Any flag calibration adds that the digest hashes therefore hides the whole
/// generation from every scan.
///
/// `--no-gpu` was such a flag. On a host with no eligible GPU every one of the
/// four calibrated policies was written under a `gpu_runtime_policy = Disabled`
/// digest, and the ordinary scan that followed reported "7 calibrated
/// config(s), none matching config digest" and exited 2.
///
/// `--no-config` is the same class, reached from the other side. Calibration
/// used to pass it unconditionally, so calibrating inside a repository that
/// carries a `.keyhog.toml` published every decision under the compiled-in
/// baseline digest while the scans in that repository asked for the resolved
/// one. It is now a caller decision, and BOTH modes are pinned here: the digest
/// must match the scan that resolves configuration the same way.
///
/// The preset list is read from `SCAN_POLICY_PRESETS` at run time, so a new
/// preset is covered without editing this test.
#[test]
fn calibration_argv_resolves_the_config_digest_a_plain_scan_requests() {
    let digest_of = |args: &mut crate::args::ScanArgs| {
        let resolved = crate::orchestrator_config::resolve_scan_config(args)
            .expect("calibration and scan argv both resolve");
        crate::orchestrator_config::autoroute_config_digest(&resolved)
    };
    for policy in std::iter::once(None).chain(SCAN_POLICY_PRESETS.iter().copied().map(Some)) {
        for no_config in [true, false] {
            let mut plain_argv = vec![OsString::from("keyhog-scan")];
            if no_config {
                plain_argv.push(OsString::from("--no-config"));
            }
            if let Some(policy) = policy {
                plain_argv.push(OsString::from(policy));
            }
            let mut plain = crate::args::ScanArgs::try_parse_from(plain_argv)
                .expect("a documented preset parses as a plain scan");
            let scanned = digest_of(&mut plain);
            for include_gpu in [true, false] {
                let mut calibration = calibration_scan_args(None, policy, include_gpu, no_config)
                    .expect("internal calibration scan args");
                assert_eq!(
                    digest_of(&mut calibration),
                    scanned,
                    "calibration for {} with include_gpu={include_gpu} no_config={no_config} must \
                     persist under the digest the same scan requests",
                    policy.unwrap_or("the default policy"),
                );
            }
        }
    }
}

#[test]
fn calibration_runtime_admits_gpu_only_when_requested() {
    let without = calibration_scan_args(None, None, false, false).expect("internal scan args");
    assert!(!without.autoroute_gpu);
    assert!(
        !without.no_gpu,
        "declining GPU candidates must not change the scan's resolved GPU policy"
    );
    let with = calibration_scan_args(None, None, true, false).expect("internal scan args");
    assert!(with.autoroute_gpu);
    assert!(!with.no_gpu);
}

/// Which configuration calibration measures under is a caller decision, and
/// the default is the one an operator's scans use. `resolve_scan_config`
/// short-circuits to the compiled-in baseline the moment `no_config` is set
/// (`config.rs`), so this bit alone decides whether a repository
/// `.keyhog.toml` is inside the persisted digest. The unit-test process has no
/// discovered config, which is exactly why the digest gate above cannot see a
/// mode mix-up: assert the bit itself.
#[test]
fn calibration_resolves_repository_config_unless_the_caller_declines_it() {
    let resolving = calibration_scan_args(None, None, false, false).expect("internal scan args");
    assert!(
        !resolving.no_config,
        "a bare `keyhog calibrate-autoroute` must measure the configuration the \
         scans in this directory resolve"
    );
    let baseline = calibration_scan_args(None, None, false, true).expect("internal scan args");
    assert!(
        baseline.no_config,
        "an installer priming a host baseline must be able to decline the \
         repository configuration it happens to be standing in"
    );
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

/// The bounded E2E fixture must retain every bucket used by its post-calibration
/// scans while leaving the complete production workload plan independently intact.
#[test]
fn bounded_e2e_workload_fixture_keeps_verified_buckets() {
    let plan = bounded_e2e_workload_plan(core_workload_plan()).expect("bounded workload fixture");
    assert_eq!(
        plan.iter().map(Workload::label).collect::<Vec<_>>(),
        ["1 KiB workload", "4 KiB workload", "64 KiB workload"]
    );
}

/// Every canonical source class must be timed in streamed and known-size form so normal scans never hit an uncalibrated source identity.
#[test]
fn workload_plan_matches_the_installer_ladder() {
    let plan = core_workload_plan();
    // 1 stdin + 30 plain single-file + 3 decode-heavy single-file + both edges
    // of every fused count bucket for full-size and extracted payloads + two
    // metadata shapes per source class.
    assert_eq!(
        plan.len(),
        34 + 2 * crate::orchestrator_config::fused_batch_calibration_counts().len()
            + 2 * crate::orchestrator::canonical_source_classes().len()
    );
    let labels: Vec<&str> = plan.iter().map(Workload::label).collect();
    assert!(labels.contains(&"stdin 64 KiB workload"));
    assert!(labels.contains(&"1 B workload"));
    assert!(labels.contains(&"1 KiB workload"));
    assert!(labels.contains(&"16 KiB workload"));
    assert!(labels.contains(&"256 KiB workload"));
    assert!(labels.contains(&"4 MiB workload"));
    assert!(labels.contains(&"decode-heavy 4 KiB workload"));
    assert!(labels.contains(&"decode-heavy 64 KiB workload"));
    assert!(labels.contains(&"decode-heavy 256 KiB workload"));
    assert!(labels.contains(&"32 MiB workload"));
    assert!(labels.contains(&"1 x 4 KiB files workload"));
    assert!(labels.contains(&"31 x 4 KiB files workload"));
    assert!(labels.contains(&"32 x 4 KiB files workload"));
    assert!(labels.contains(&"1024 x 4 KiB files workload"));
    assert!(labels.contains(&"1 x 4 KiB tar members workload"));
    assert!(labels.contains(&"31 x 4 KiB tar members workload"));
    assert!(labels.contains(&"32 x 4 KiB tar members workload"));
    assert!(labels.contains(&"1024 x 4 KiB tar members workload"));
    for source_class in crate::orchestrator::canonical_source_classes() {
        let shapes = plan
            .iter()
            .filter_map(|workload| match workload {
                Workload::SourceClass {
                    source_class: actual,
                    has_full_size,
                    ..
                } if *actual == source_class => Some(*has_full_size),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(shapes, [false, true], "source class {source_class}");
    }

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
            4 * 1024 * 1024 + 1,
            8 * 1024 * 1024 - 1,
            8 * 1024 * 1024,
            8 * 1024 * 1024 + 1,
            16 * 1024 * 1024 - 1,
            16 * 1024 * 1024,
            32 * 1024 * 1024,
        ],
        "plain probes must represent every power-of-two band plus both sides of the measured 8 MiB crossover"
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
        crate::orchestrator_config::fused_batch_calibration_counts(),
        "tree probes must cover both edges of every fused-batch count bucket"
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
        crate::orchestrator_config::fused_batch_calibration_counts(),
        "archive probes must cover both edges of every fused-batch count bucket"
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

/// A source-class calibration probe must carry the exact class and size-presence axis into production workload classification.
#[test]
fn source_class_probe_materializes_exact_routing_metadata() {
    let workspace = tempfile::tempdir().expect("tempdir");
    for has_full_size in [false, true] {
        let workload = Workload::SourceClass {
            label: "test source class".to_owned(),
            source_class: "web:js",
            bytes: 64 * 1024,
            has_full_size,
        };
        let MaterializedProbe::SourceClass(source) =
            materialize_probe(workspace.path(), 1, &workload).expect("materialize source class")
        else {
            panic!("source-class representative must remain an in-memory source");
        };
        let chunks = source
            .chunks()
            .collect::<Result<Vec<_>, _>>()
            .expect("read calibration source");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].data.len(), 64 * 1024);
        assert_eq!(chunks[0].metadata.source_type.as_ref(), "web:js");
        assert_eq!(
            chunks[0].metadata.size_bytes,
            has_full_size.then_some(64 * 1024)
        );
    }
}

/// WHY: the all-policy parent may publish only route classes proved by its isolated children.
#[test]
fn measurement_receipts_round_trip_exact_route_identity() {
    let workspace = tempfile::tempdir().expect("receipt tempdir");
    let path = workspace.path().join("receipts.json");
    let receipts = [
        (
            "config-a".to_string(),
            "host-a".to_string(),
            "workload-a".to_string(),
        ),
        (
            "config-b".to_string(),
            "host-a".to_string(),
            "workload-a".to_string(),
        ),
    ]
    .into_iter()
    .collect();

    write_measurement_receipts(&path, &receipts).expect("write receipts");
    assert_eq!(
        read_measurement_receipts(&path).expect("read receipts"),
        receipts
    );
}

/// `decode_admitted` is a keyed workload dimension, and a routing family is
/// only reusable evidence when at least two of its size bands were measured.
/// A ladder that probes one decode state at a single size therefore leaves
/// every decoding scan uncalibrated, whatever else it measures.
///
/// The band set is derived from the plan at run time, so shrinking or
/// relabelling the decode-heavy probes turns this test red instead of
/// silently reintroducing a single-band family.
///
/// WHAT IT DOES NOT CATCH: whether the measured bands bracket a real
/// production workload. It proves invariance is measurable, not that any
/// particular scan is covered.
#[test]
fn workload_plan_measures_both_decode_states_across_multiple_size_bands() {
    let mut bands: BTreeMap<bool, BTreeSet<u32>> = BTreeMap::new();
    for workload in core_workload_plan() {
        if let Workload::File {
            bytes,
            decode_heavy,
            ..
        } = workload
        {
            bands
                .entry(decode_heavy)
                .or_default()
                .insert(u64::from(bytes as u64).next_power_of_two().trailing_zeros());
        }
    }
    assert_eq!(
        bands.keys().copied().collect::<Vec<_>>(),
        vec![false, true],
        "the ladder must probe both decode states"
    );
    for (decode_heavy, measured) in &bands {
        assert!(
            measured.len() >= 2,
            "decode_heavy={decode_heavy} is measured at {} size band(s); a single-band \
             family is never reusable evidence, so every decoding scan would fail closed",
            measured.len()
        );
    }
}
