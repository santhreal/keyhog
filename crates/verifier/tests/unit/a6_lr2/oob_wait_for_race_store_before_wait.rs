use keyhog_verifier::oob::{Interaction, InteractionProtocol, OobAccept, OobConfig};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn oob_wait_for_race_store_before_wait() {
    let client = Arc::new(
        TestApi
            .interactsh_client_for_test("https://example.test")
            .expect("for_test RSA keygen must succeed"),
    );
    let session = TestApi.oob_session_for_test(client, OobConfig::default());
    let id = "abcdefghijklmnopqrstabc";
    TestApi.oob_session_store_and_notify(
        &session,
        Interaction {
            unique_id: id.into(),
            protocol: InteractionProtocol::Dns,
            remote_address: "1.2.3.4".into(),
            timestamp: "2026-01-01".into(),
            raw_payload: "ping".into(),
        },
    );
    let obs = session
        .wait_for(id, OobAccept::Dns, Duration::from_secs(1))
        .await;
    assert!(matches!(
        obs,
        keyhog_verifier::oob::OobObservation::Observed { .. }
    ));
}
