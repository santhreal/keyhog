//! Regression for the `verify_all` task-drain loop (CodeRabbit critical, Law 10).
//!
//! `verify_all` previously drained its `JoinSet` with `while let Some(Ok(_))`,
//! which BREAKS on the first `Err(JoinError)` (a cancelled task / runtime
//! shutdown). That silently dropped every other in-flight result AND every
//! still-pending credential group — verification truncated with no signal. The
//! fix extracts `drain_join_set`, which matches `Ok`/`Err` explicitly: it logs
//! the lost task loudly and CONTINUES, so one cancelled task never truncates the
//! rest. These tests drive the extracted helper through the hidden `testing`
//! re-export.

use keyhog_verifier::testing::drain_join_set;
use tokio::task::JoinSet;

/// A cancelled task surfaces a `JoinError`; the drain must skip it and keep the
/// other tasks' outputs. Deterministic: the aborted task is ready immediately
/// (cancelled tasks complete at once) while the `Ok` tasks `yield_now()` so they
/// are still pending on the first `join_next` poll — so the `Err` is delivered
/// FIRST, exactly the interleaving that truncated the old `while let Some(Ok)`.
#[tokio::test]
async fn drain_join_set_continues_past_cancel() {
    let mut js: JoinSet<u32> = JoinSet::new();
    js.spawn(async {
        tokio::task::yield_now().await;
        1
    });
    let cancelled = js.spawn(async {
        tokio::task::yield_now().await;
        2
    });
    js.spawn(async {
        tokio::task::yield_now().await;
        3
    });
    cancelled.abort();

    let mut out = drain_join_set(js, 3, || None::<std::future::Ready<u32>>).await;
    out.sort_unstable();
    assert_eq!(
        out,
        vec![1, 3],
        "the cancelled task (2) is skipped, but 1 and 3 must survive the drain; \
         a truncated result means a JoinError broke the loop early"
    );
}

/// Completeness: with no cancellation and a refill source, EVERY task's output
/// is collected — the contract the refill loop must preserve when the work count
/// exceeds the initial concurrency window.
#[tokio::test]
async fn drain_join_set_collects_all_with_refill() {
    let mut js: JoinSet<u32> = JoinSet::new();
    // Prime two, then refill the remaining six one-at-a-time as tasks finish.
    js.spawn(async { 0 });
    js.spawn(async { 1 });
    let mut next = 2u32;
    let mut out = drain_join_set(js, 8, move || {
        if next < 8 {
            let v = next;
            next += 1;
            Some(std::future::ready(v))
        } else {
            None
        }
    })
    .await;
    out.sort_unstable();
    assert_eq!(out, (0..8).collect::<Vec<_>>());
}
