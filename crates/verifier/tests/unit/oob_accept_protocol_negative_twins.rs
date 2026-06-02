//! Negative twin test: OobAccept protocol filtering must reject unwanted protocols.
//! Asserts that each OobAccept variant ONLY matches its designated protocol(s),
//! not spurious alternatives.

use keyhog_verifier::oob::{InteractionProtocol, OobAccept};

#[test]
fn oob_accept_dns_rejects_http() {
    assert!(
        !OobAccept::Dns.matches(InteractionProtocol::Http),
        "Dns filter must reject Http protocol"
    );
}

#[test]
fn oob_accept_dns_rejects_smtp() {
    assert!(
        !OobAccept::Dns.matches(InteractionProtocol::Smtp),
        "Dns filter must reject Smtp protocol"
    );
}

#[test]
fn oob_accept_dns_rejects_other() {
    assert!(
        !OobAccept::Dns.matches(InteractionProtocol::Other),
        "Dns filter must reject Other protocol"
    );
}

#[test]
fn oob_accept_http_rejects_dns() {
    assert!(
        !OobAccept::Http.matches(InteractionProtocol::Dns),
        "Http filter must reject Dns protocol"
    );
}

#[test]
fn oob_accept_http_rejects_smtp() {
    assert!(
        !OobAccept::Http.matches(InteractionProtocol::Smtp),
        "Http filter must reject Smtp protocol"
    );
}

#[test]
fn oob_accept_http_rejects_other() {
    assert!(
        !OobAccept::Http.matches(InteractionProtocol::Other),
        "Http filter must reject Other protocol"
    );
}

#[test]
fn oob_accept_smtp_rejects_dns() {
    assert!(
        !OobAccept::Smtp.matches(InteractionProtocol::Dns),
        "Smtp filter must reject Dns protocol"
    );
}

#[test]
fn oob_accept_smtp_rejects_http() {
    assert!(
        !OobAccept::Smtp.matches(InteractionProtocol::Http),
        "Smtp filter must reject Http protocol"
    );
}

#[test]
fn oob_accept_smtp_rejects_other() {
    assert!(
        !OobAccept::Smtp.matches(InteractionProtocol::Other),
        "Smtp filter must reject Other protocol"
    );
}

#[test]
fn oob_accept_any_matches_all() {
    // Any must match all protocols
    assert!(OobAccept::Any.matches(InteractionProtocol::Dns));
    assert!(OobAccept::Any.matches(InteractionProtocol::Http));
    assert!(OobAccept::Any.matches(InteractionProtocol::Smtp));
    assert!(OobAccept::Any.matches(InteractionProtocol::Other));
}

#[test]
fn oob_accept_dns_accepts_only_dns() {
    // Positive case: Dns must match exactly Dns
    assert!(
        OobAccept::Dns.matches(InteractionProtocol::Dns),
        "Dns filter must accept Dns protocol"
    );
}

#[test]
fn oob_accept_http_accepts_only_http() {
    // Positive case: Http must match exactly Http
    assert!(
        OobAccept::Http.matches(InteractionProtocol::Http),
        "Http filter must accept Http protocol"
    );
}

#[test]
fn oob_accept_smtp_accepts_only_smtp() {
    // Positive case: Smtp must match exactly Smtp
    assert!(
        OobAccept::Smtp.matches(InteractionProtocol::Smtp),
        "Smtp filter must accept Smtp protocol"
    );
}
