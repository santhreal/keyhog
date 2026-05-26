use keyhog_verifier::oob::{InteractionProtocol, OobAccept};

#[test]
fn oob_accept_filters_protocols() {
    assert!(OobAccept::Any.matches(InteractionProtocol::Dns));
    assert!(OobAccept::Any.matches(InteractionProtocol::Other));
    assert!(OobAccept::Http.matches(InteractionProtocol::Http));
    assert!(!OobAccept::Http.matches(InteractionProtocol::Dns));
    assert!(OobAccept::Smtp.matches(InteractionProtocol::Smtp));
    assert!(!OobAccept::Smtp.matches(InteractionProtocol::Http));
}
