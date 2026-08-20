use super::super::{HsCompileOpts, HsScanner};

/// Regression: dropping a scanner must not strand database-bound scratch
/// on the thread that performed its last scan.
#[test]
fn dropping_scanner_purges_current_thread_tls_scratch() {
    let patterns = [(0usize, 0usize, "KHDROP_[A-Z0-9]{8}", false)];
    let (scanner, unsupported) = HsScanner::compile(&patterns).expect("probe pattern compiles");
    assert!(
        unsupported.is_empty(),
        "probe pattern must be Hyperscan-supported, got unsupported={unsupported:?}"
    );
    let scanner_id = scanner.scanner_id;

    let mut ids = Vec::new();
    scanner
        .scan_matches_result(b"KHDROP_AB12CD34", |id, _start, _end| ids.push(id))
        .expect("scan succeeds and retains scratch in this thread");
    assert_eq!(ids, vec![0]);
    assert!(
        super::current_thread_scratch_count_for_test(scanner_id) > 0,
        "scan should retain at least one scratch for the live scanner"
    );

    drop(scanner);

    assert_eq!(
        super::current_thread_scratch_count_for_test(scanner_id),
        0,
        "dropping a scanner must evict its thread-local Hyperscan scratches"
    );
}

/// Regression: pruning one scanner's cache must not evict another live
/// scanner interleaved on the same worker.
#[test]
fn interleaved_live_scanners_keep_thread_local_scratches() {
    let patterns_a = [(0usize, 0usize, "KHA_[A-Z0-9]{8}", false)];
    let patterns_b = [(0usize, 0usize, "KHB_[A-Z0-9]{8}", false)];
    let (scanner_a, unsupported_a) =
        HsScanner::compile(&patterns_a).expect("scanner A pattern compiles");
    let (scanner_b, unsupported_b) =
        HsScanner::compile(&patterns_b).expect("scanner B pattern compiles");
    assert!(
        unsupported_a.is_empty() && unsupported_b.is_empty(),
        "probe patterns must be Hyperscan-supported"
    );

    scanner_a
        .scan_matches_result(b"KHA_AB12CD34", |_, _, _| {})
        .expect("scanner A scan succeeds");
    assert!(
        super::current_thread_scratch_count_for_test(scanner_a.scanner_id) > 0,
        "scanner A should retain its current-thread scratch"
    );

    scanner_b
        .scan_matches_result(b"KHB_AB12CD34", |_, _, _| {})
        .expect("scanner B scan succeeds");

    assert!(
        super::current_thread_scratch_count_for_test(scanner_a.scanner_id) > 0,
        "interleaving scanner B must not evict live scanner A scratch"
    );
    assert!(
        super::current_thread_scratch_count_for_test(scanner_b.scanner_id) > 0,
        "scanner B should retain its own current-thread scratch"
    );
}

/// Regression: persistent workers must reclaim stale scratch after the
/// owning scanner is dropped on a different thread.
#[test]
fn dead_scanner_scratch_is_pruned_on_worker_next_cache_touch() {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (continue_tx, continue_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let patterns_a = [(0usize, 0usize, "KHSTALE_[A-Z0-9]{8}", false)];
        let (scanner_a, unsupported_a) =
            HsScanner::compile(&patterns_a).expect("scanner A pattern compiles");
        assert!(
            unsupported_a.is_empty(),
            "scanner A pattern must be Hyperscan-supported"
        );
        let scanner_a_id = scanner_a.scanner_id;
        scanner_a
            .scan_matches_result(b"KHSTALE_AB12CD34", |_, _, _| {})
            .expect("scanner A scan succeeds");
        ready_tx
            .send((
                scanner_a_id,
                super::current_thread_scratch_count_for_test(scanner_a_id),
                scanner_a,
            ))
            .expect("send scanner A cache count");
        continue_rx.recv().expect("wait for prune command");

        let patterns_b = [(0usize, 0usize, "KHFRESH_[A-Z0-9]{8}", false)];
        let (scanner_b, unsupported_b) =
            HsScanner::compile(&patterns_b).expect("scanner B pattern compiles");
        assert!(
            unsupported_b.is_empty(),
            "scanner B pattern must be Hyperscan-supported"
        );
        scanner_b
            .scan_matches_result(b"KHFRESH_AB12CD34", |_, _, _| {})
            .expect("scanner B scan succeeds and prunes stale entries on miss");
        (
            super::current_thread_scratch_count_for_test(scanner_a_id),
            super::current_thread_scratch_count_for_test(scanner_b.scanner_id),
        )
    });

    let (_scanner_a_id, cached_before_drop, scanner_a) =
        ready_rx.recv().expect("receive scanner A cache count");
    assert!(
        cached_before_drop > 0,
        "worker should retain scanner A scratch before scanner A is dropped"
    );
    drop(scanner_a);
    continue_tx.send(()).expect("release worker");
    let (stale_after_touch, fresh_after_touch) = worker.join().expect("worker joins");

    assert_eq!(
        stale_after_touch, 0,
        "dead scanner A scratch must be pruned on the worker's next cache touch"
    );
    assert!(
        fresh_after_touch > 0,
        "worker should retain scanner B scratch after pruning stale scanner A"
    );
}

/// Regression: lazy scratch construction keeps compile free of
/// executor-width-dependent scratch allocation and failure.
#[test]
fn compile_does_not_allocate_thread_local_scratch() {
    let patterns = [(0usize, 0usize, "KHDROP_[A-Z0-9]{8}", false)];
    let (scanner, unsupported) = HsScanner::compile(&patterns).expect("probe pattern compiles");
    assert!(
        unsupported.is_empty(),
        "probe pattern must be Hyperscan-supported"
    );

    assert_eq!(
        super::current_thread_scratch_count_for_test(scanner.scanner_id),
        0,
        "compile must not allocate any thread-local Hyperscan scratch"
    );
}

/// Regression: the first cold scan must populate the complete per-shard
/// cache and subsequent scans must reuse it without growth.
#[test]
fn first_scan_lazily_warms_then_reuses_scratch() {
    let patterns = [(0usize, 0usize, "KHLAZY_[A-Z0-9]{8}", false)];
    let (scanner, unsupported) = HsScanner::compile(&patterns).expect("probe pattern compiles");
    assert!(
        unsupported.is_empty(),
        "probe pattern must be Hyperscan-supported"
    );

    let mut ids = Vec::new();
    scanner
        .scan_matches_result(b"KHLAZY_AB12CD34", |id, _start, _end| ids.push(id))
        .expect("first scan lazily allocates scratch");
    assert_eq!(ids, vec![0]);

    let after_first = super::current_thread_scratch_count_for_test(scanner.scanner_id);
    assert_eq!(
        after_first,
        scanner.shard_count(),
        "first scan must allocate exactly one scratch per shard"
    );

    scanner
        .scan_matches_result(b"KHLAZY_AB12CD34", |_, _, _| {})
        .expect("second scan reuses warm scratch");

    let after_second = super::current_thread_scratch_count_for_test(scanner.scanner_id);
    assert_eq!(
        after_second, after_first,
        "post-warm scan must not allocate additional scratch"
    );
}

/// Regression: explicit warm-up seeds caller thread-local scratch so normal
/// request traffic does not allocate Hyperscan scratch.
#[test]
fn warm_seeds_one_scratch_per_shard() {
    let patterns = [
        (0usize, 0usize, "KHWORKER_[A-Z0-9]{8}", false),
        (1usize, 0usize, "ZZWORKER_[a-z0-9]{6}", false),
    ];
    let (scanner, unsupported) = HsScanner::compile(&patterns).expect("probe patterns compile");
    assert!(
        unsupported.is_empty(),
        "probe patterns must be Hyperscan-supported"
    );

    scanner
        .warm()
        .expect("warm must seed caller thread-local scratch");

    let shard_count = scanner.shard_count();
    let warm_count = super::current_thread_scratch_count_for_test(scanner.scanner_id);
    assert_eq!(
        warm_count, shard_count,
        "caller thread must have one scratch per shard after warm, got {warm_count}"
    );

    let probe = b"x KHWORKER_AB12CD34 y ZZWORKER_xy99zz z";
    let mut ids = Vec::new();
    scanner
        .scan_matches_result(probe, |id, _, _| ids.push(id))
        .expect("post-warm scan succeeds");
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids, vec![0, 1], "post-warm scan must preserve exact parity");
    assert_eq!(
        super::current_thread_scratch_count_for_test(scanner.scanner_id),
        shard_count,
        "post-warm scan must reuse warm scratch without growth"
    );
}

/// Regression: concurrency beyond the Rayon executor width must grow
/// exact per-thread scratch instead of skipping shards or over-marking.
#[test]
fn oversubscribed_threads_allocate_once_and_keep_exact_parity() {
    let patterns = [
        (0usize, 0usize, "KHSCRATCH_[A-Z0-9]{8}", false),
        (1usize, 0usize, "ZZTOK_[a-z0-9]{6}", false),
    ];
    let (scanner, unsupported) = HsScanner::compile(&patterns).expect("probe patterns compile");
    assert!(
        unsupported.is_empty(),
        "probe patterns must be Hyperscan-supported"
    );

    let probe = b"x KHSCRATCH_AB12CD34 y ZZTOK_xy99zz z";
    let mut expected = Vec::new();
    scanner
        .scan_matches_result(probe, |id, _, _| expected.push(id))
        .expect("reference scan succeeds");
    expected.sort_unstable();
    expected.dedup();

    let extra_threads = 3;
    let n_threads = rayon::current_num_threads()
        .saturating_add(extra_threads)
        .max(2);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..n_threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut ids = Vec::new();
                    scanner
                        .scan_matches_result(probe, |id, _, _| ids.push(id))
                        .expect("oversubscribed scan succeeds");
                    ids.sort_unstable();
                    ids.dedup();
                    (
                        ids,
                        super::current_thread_scratch_count_for_test(scanner.scanner_id),
                    )
                })
            })
            .collect();

        for (i, (ids, count)) in handles
            .into_iter()
            .map(|h| h.join().expect("scan thread joins"))
            .enumerate()
        {
            assert_eq!(
                ids, expected,
                "thread {i} must match exact reference parity"
            );
            assert_eq!(
                count,
                scanner.shard_count(),
                "thread {i} must retain exactly one scratch per shard"
            );
        }
    });
}

/// Regression: a later-shard scratch allocation failure previously made
/// earlier shard callbacks observable before returning an error. The
/// one-shot failure also proves retained scratch can recover cleanly.
#[test]
fn scratch_failure_precedes_callbacks_and_next_scan_recovers_all_findings() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .expect("two-thread compile pool builds");
    let patterns = [
        (0usize, 0usize, "KHFAIL_[A-Z0-9]{8}", false),
        (1usize, 0usize, "ZZFAIL_[a-z0-9]{6}", false),
    ];
    let (scanner, unsupported) = pool
        .install(|| {
            HsScanner::compile_with_opts(
                &patterns,
                HsCompileOpts {
                    shard_target: Some(1),
                    ..Default::default()
                },
            )
        })
        .expect("two-shard probe compiles");
    assert!(
        unsupported.is_empty(),
        "probe patterns must be Hyperscan-supported"
    );
    assert_eq!(
        scanner.shard_count(),
        2,
        "failure probe requires two shards"
    );

    super::fail_next_scratch_allocation_for_test(1);
    let mut callbacks = Vec::new();
    let error = scanner
        .scan_matches_result(b"x KHFAIL_AB12CD34 y ZZFAIL_xy99zz z", |id, _, _| {
            callbacks.push(id)
        })
        .expect_err("second shard scratch allocation must fail");
    assert!(
        error.contains("scratch on-demand growth failed")
            && error.contains("shard 1")
            && error.contains("injected allocation failure"),
        "allocation failure must retain actionable scanner/shard context: {error}"
    );
    assert!(
        callbacks.is_empty(),
        "scratch acquisition must complete for every shard before callbacks run"
    );
    assert_eq!(
        super::current_thread_scratch_count_for_test(scanner.scanner_id),
        1,
        "scratch acquired before failure must be returned to TLS for recovery"
    );

    let mut recovered = Vec::new();
    scanner
        .scan_matches_result(b"x KHFAIL_AB12CD34 y ZZFAIL_xy99zz z", |id, _, _| {
            recovered.push(id)
        })
        .expect("one-shot allocation failure must recover on the next scan");
    recovered.sort_unstable();
    recovered.dedup();
    assert_eq!(
        recovered,
        vec![0, 1],
        "recovery scan must report the complete cross-shard finding set"
    );

    super::purge_scanner_scratch(scanner.scanner_id);
    super::fail_next_scratch_allocation_for_test(1);
    let mut each_callbacks = Vec::new();
    scanner
        .scan_each_result(b"x KHFAIL_AB12CD34 y ZZFAIL_xy99zz z", |id| {
            each_callbacks.push(id)
        })
        .expect_err("scan_each must propagate scratch allocation failure");
    assert!(
        each_callbacks.is_empty(),
        "scan_each scratch failure must precede every callback"
    );

    super::purge_scanner_scratch(scanner.scanner_id);
    super::fail_next_scratch_allocation_for_test(1);
    scanner
        .any_match_result(b"x KHFAIL_AB12CD34 y ZZFAIL_xy99zz z")
        .expect_err("any_match must propagate scratch allocation failure");
    assert!(
        scanner
            .any_match_result(b"x KHFAIL_AB12CD34 y ZZFAIL_xy99zz z")
            .expect("any_match must recover after one-shot allocation failure"),
        "any_match recovery must observe the cross-shard finding set"
    );
}

/// Regression: a wrapped/reused numeric scanner id must never retrieve
/// scratch bound to another scanner's database; owner identity is the
/// adversarial backstop against incompatible scratch reuse.
#[test]
fn scanner_id_collision_rejects_foreign_scratch_and_both_scanners_recover() {
    let patterns_a = [(0usize, 0usize, "KHCOLLIDEA_[A-Z0-9]{8}", false)];
    let patterns_b = [(0usize, 0usize, "KHCOLLIDEB_[a-z0-9]{6}", false)];
    let (scanner_a, unsupported_a) =
        HsScanner::compile(&patterns_a).expect("scanner A pattern compiles");
    let (mut scanner_b, unsupported_b) =
        HsScanner::compile(&patterns_b).expect("scanner B pattern compiles");
    assert!(
        unsupported_a.is_empty() && unsupported_b.is_empty(),
        "collision probes must be Hyperscan-supported"
    );

    scanner_a
        .scan_matches_result(b"KHCOLLIDEA_AB12CD34", |_, _, _| {})
        .expect("scanner A seeds its scratch");
    scanner_b.scanner_id = scanner_a.scanner_id;

    let mut b_hits = 0;
    scanner_b
        .scan_matches_result(b"KHCOLLIDEB_xy99zz", |_, _, _| b_hits += 1)
        .expect("scanner B must reject and replace scanner A scratch");
    assert_eq!(
        b_hits, 1,
        "scanner B must retain exact findings after collision"
    );

    let mut a_hits = 0;
    scanner_a
        .scan_matches_result(b"KHCOLLIDEA_AB12CD34", |_, _, _| a_hits += 1)
        .expect("scanner A must replace scanner B scratch on reuse");
    assert_eq!(
        a_hits, 1,
        "scanner A must recover exact findings after collision"
    );
}
