//! Boundary test: InteractionProtocol::parse() must correctly categorize protocol strings.
//! Asserts that protocol detection is case-insensitive, exact-match per variant,
//! and defaults to Other for unknown values.

use keyhog_verifier::oob::InteractionProtocol;

#[test]
fn oob_protocol_parse_dns_case_insensitive() {
    assert_eq!(InteractionProtocol::parse("dns"), InteractionProtocol::Dns);
    assert_eq!(InteractionProtocol::parse("DNS"), InteractionProtocol::Dns);
    assert_eq!(InteractionProtocol::parse("Dns"), InteractionProtocol::Dns);
    assert_eq!(InteractionProtocol::parse("dNs"), InteractionProtocol::Dns);
}

#[test]
fn oob_protocol_parse_http_case_insensitive() {
    assert_eq!(
        InteractionProtocol::parse("http"),
        InteractionProtocol::Http
    );
    assert_eq!(
        InteractionProtocol::parse("HTTP"),
        InteractionProtocol::Http
    );
    assert_eq!(
        InteractionProtocol::parse("Http"),
        InteractionProtocol::Http
    );
    assert_eq!(
        InteractionProtocol::parse("hTtP"),
        InteractionProtocol::Http
    );
}

#[test]
fn oob_protocol_parse_smtp_case_insensitive() {
    assert_eq!(
        InteractionProtocol::parse("smtp"),
        InteractionProtocol::Smtp
    );
    assert_eq!(
        InteractionProtocol::parse("SMTP"),
        InteractionProtocol::Smtp
    );
    assert_eq!(
        InteractionProtocol::parse("Smtp"),
        InteractionProtocol::Smtp
    );
}

#[test]
fn oob_protocol_parse_smtp_mail_variant() {
    // interactsh uses "smtp-mail" as an alternate for SMTP
    assert_eq!(
        InteractionProtocol::parse("smtp-mail"),
        InteractionProtocol::Smtp
    );
    assert_eq!(
        InteractionProtocol::parse("SMTP-MAIL"),
        InteractionProtocol::Smtp
    );
}

#[test]
fn oob_protocol_parse_unknown_defaults_to_other() {
    assert_eq!(
        InteractionProtocol::parse("ftp"),
        InteractionProtocol::Other
    );
    assert_eq!(
        InteractionProtocol::parse("ssh"),
        InteractionProtocol::Other
    );
    assert_eq!(
        InteractionProtocol::parse("telnet"),
        InteractionProtocol::Other
    );
    assert_eq!(
        InteractionProtocol::parse("unknown"),
        InteractionProtocol::Other
    );
    assert_eq!(InteractionProtocol::parse(""), InteractionProtocol::Other);
}

#[test]
fn oob_protocol_parse_partial_match_returns_other() {
    // Partial matches should not match (e.g., "dns" prefix of "dns-tcp")
    assert_eq!(
        InteractionProtocol::parse("dns-tcp"),
        InteractionProtocol::Other
    );
    assert_eq!(
        InteractionProtocol::parse("http2"),
        InteractionProtocol::Other
    );
    assert_eq!(
        InteractionProtocol::parse("https"),
        InteractionProtocol::Other
    );
    assert_eq!(
        InteractionProtocol::parse("smtp2"),
        InteractionProtocol::Other
    );
}

#[test]
fn oob_protocol_parse_whitespace_returns_other() {
    assert_eq!(
        InteractionProtocol::parse("  dns  "),
        InteractionProtocol::Other
    );
    assert_eq!(
        InteractionProtocol::parse("\tdns\n"),
        InteractionProtocol::Other
    );
}

#[test]
fn oob_protocol_variants_are_distinct() {
    // Ensure all variants are distinct (not accidentally equal)
    assert_ne!(InteractionProtocol::Dns, InteractionProtocol::Http);
    assert_ne!(InteractionProtocol::Dns, InteractionProtocol::Smtp);
    assert_ne!(InteractionProtocol::Dns, InteractionProtocol::Other);
    assert_ne!(InteractionProtocol::Http, InteractionProtocol::Smtp);
    assert_ne!(InteractionProtocol::Http, InteractionProtocol::Other);
    assert_ne!(InteractionProtocol::Smtp, InteractionProtocol::Other);
}
