use keyhog_verifier::oob::{OobAccept, OobConfig};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::sync::Arc;
use std::time::Duration;

/// WHY: the collector poller must remain idle without callback work and receive
/// a monotonic demand signal whenever a verification request begins waiting.
#[tokio::test]
async fn callback_wait_registers_poller_demand() {
    let client = Arc::new(
        TestApi
            .interactsh_client_for_test("https://oast.fun")
            .expect("for_test client builds without network"),
    );
    let session = TestApi.oob_session_for_test(client, OobConfig::default());
    assert_eq!(TestApi.oob_session_poll_generation(&session), 0);

    let waiting_session = Arc::clone(&session);
    let waiter = tokio::spawn(async move {
        waiting_session
            .wait_for(
                "poll-demand-callback",
                OobAccept::Any,
                Duration::from_secs(30),
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if TestApi.oob_session_poll_generation(&session) == 1
                && TestApi.oob_session_active_waiter_count(&session) == 1
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("callback waiter did not publish poll demand");

    waiter.abort();
    let _ = waiter.await;
    assert_eq!(TestApi.oob_session_active_waiter_count(&session), 0);
}
