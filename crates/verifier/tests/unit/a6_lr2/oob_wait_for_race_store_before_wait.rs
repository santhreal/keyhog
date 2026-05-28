use keyhog_verifier::oob::{InteractshClient, OobAccept, OobConfig, OobSession, Interaction, InteractionProtocol};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn oob_wait_for_race_store_before_wait() {
    let client = Arc::new(InteractshClient::for_test("https://example.test"));
    let session = OobSession::for_test(client, OobConfig::default());
    let id = "abcdefghijklmnopqrstabc";
    session.store_and_notify_for_test(Interaction {
        unique_id: id.into(),
        protocol: InteractionProtocol::Dns,
        remote_address: "1.2.3.4".into(),
        timestamp: "2026-01-01".into(),
        raw_payload: "ping".into(),
    });
    let obs = session.wait_for(id, OobAccept::Dns, Duration::from_secs(1)).await;
    assert!(matches!(obs, keyhog_verifier::oob::OobObservation::Observed { .. }));
}
