//! Credential-URI scheme-coverage recall lock. The `url-credentials` detector is
//! scheme-generic (`[a-z][a-z0-9+.-]*://user:<password>@host`), but the existing
//! recall test (regression_creddata_url_credentials_recall) only exercises the
//! db/http/mqtt schemes. Mail, file-transfer, and directory-service URIs leak
//! credentials just as often (SMTP relays, SFTP drops, LDAP binds), so this pins
//! that the embedded password surfaces across the FULL real scheme space, and
//! that the precision guards (no-userinfo, dictionary/placeholder/short/template
//! passwords) hold uniformly regardless of scheme. Non-overlapping with the
//! existing file: only schemes it does NOT cover are asserted here.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

/// Deterministic high-entropy, non-dictionary alphanumeric password of length `n`
/// (seeded LCG → flat distribution). Guarantees a miss is a real scheme gap, not a
/// dictionary/short-token suppression.
fn pw(n: usize, seed: usize) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x5DEE_CE66);
    (0..n)
        .map(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            A[((s >> 33) % 62) as usize] as char
        })
        .collect()
}

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "services.conf");
    s.clear_fragment_cache();
    s.scan(&chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

/// Some surfaced credential contains `needle` (the embedded password).
fn surfaces(text: &str, needle: &str) -> bool {
    scan(text).iter().any(|(_, cred)| cred.contains(needle))
}

/// No surfaced credential contains `needle`.
fn nothing_surfaces(text: &str, needle: &str) -> bool {
    !scan(text).iter().any(|(_, cred)| cred.contains(needle))
}

/// The `url-credentials` detector fired on `text`.
fn fires_url_credentials(text: &str) -> bool {
    scan(text).iter().any(|(id, _)| id == "url-credentials")
}

/// Assert a `scheme://user:<pw>@host` credential surfaces for the given scheme.
fn scheme_password_surfaces(scheme: &str, seed: usize) {
    let p = pw(12, seed);
    let text = format!("{scheme}://svcuser:{p}@host.example.net:1234");
    assert!(
        surfaces(&text, &p),
        "{scheme}:// userinfo password must surface"
    );
}

// ── positives: high-entropy userinfo password surfaces across schemes ─────────

#[test]
fn smtp_userinfo_password_surfaces() {
    scheme_password_surfaces("smtp", 1);
}

#[test]
fn smtps_userinfo_password_surfaces() {
    scheme_password_surfaces("smtps", 2);
}

#[test]
fn imap_userinfo_password_surfaces() {
    scheme_password_surfaces("imap", 3);
}

#[test]
fn imaps_userinfo_password_surfaces() {
    scheme_password_surfaces("imaps", 4);
}

#[test]
fn sftp_userinfo_password_surfaces() {
    scheme_password_surfaces("sftp", 5);
}

#[test]
fn ftps_userinfo_password_surfaces() {
    scheme_password_surfaces("ftps", 6);
}

#[test]
fn ldap_userinfo_password_surfaces() {
    scheme_password_surfaces("ldap", 7);
}

#[test]
fn ldaps_userinfo_password_surfaces() {
    scheme_password_surfaces("ldaps", 8);
}

#[test]
fn amqps_userinfo_password_surfaces() {
    scheme_password_surfaces("amqps", 9);
}

#[test]
fn ssh_url_form_userinfo_password_surfaces() {
    // The URL form ssh://user:pass@host (NOT the scp-style user@host:path).
    scheme_password_surfaces("ssh", 10);
}

#[test]
fn mongodb_srv_scheme_with_plus_surfaces() {
    // Exercises the `+` allowed in the scheme grammar (`[a-z0-9+.-]*`).
    let p = pw(12, 11);
    let text = format!("mongodb+srv://app:{p}@cluster0.mongodb.net/db");
    assert!(
        surfaces(&text, &p),
        "mongodb+srv password must surface (plus in scheme)"
    );
}

#[test]
fn smtp_url_as_env_value_surfaces() {
    let p = pw(12, 12);
    let text = format!("SMTP_URL=smtp://mailer:{p}@smtp.relay.net");
    assert!(surfaces(&text, &p), "smtp URL as an env value must surface");
}

#[test]
fn novel_custom_scheme_still_surfaces() {
    // Generality: an unknown scheme must work (the detector is not an allowlist).
    let p = pw(12, 13);
    let text = format!("acmesvc://robot:{p}@api.internal.acme");
    assert!(
        surfaces(&text, &p),
        "a novel custom scheme must still surface its password"
    );
}

// ── precision: guards hold uniformly across these schemes ─────────────────────

#[test]
fn smtp_without_userinfo_does_not_fire() {
    assert!(!fires_url_credentials("smtp://smtp.relay.net:587"));
}

#[test]
fn imap_host_only_does_not_fire() {
    assert!(!fires_url_credentials("imap://imap.mailhost.io:143/INBOX"));
}

#[test]
fn ldap_dn_path_without_userinfo_does_not_fire() {
    assert!(!fires_url_credentials(
        "ldap://ldap.corp.local/dc=corp,dc=local"
    ));
}

#[test]
fn sftp_dictionary_password_suppressed() {
    // "password" is a dictionary word (suppressed regardless of scheme).
    assert!(nothing_surfaces(
        "sftp://user:password@files.partner.com",
        "password"
    ));
}

#[test]
fn ftps_placeholder_changeme_suppressed() {
    assert!(nothing_surfaces(
        "ftps://upload:changeme@ftp.vendor.net",
        "changeme"
    ));
}

#[test]
fn smtp_five_char_password_below_floor_no_match() {
    // 5 chars is below the regex's {6,128} minimum.
    assert!(nothing_surfaces(
        "smtp://mailer:Xk9p2@smtp.relay.net",
        "Xk9p2"
    ));
}

#[test]
fn ldap_angle_bracket_template_password_no_match() {
    // The regex excludes < and >, so a `<...>` placeholder never matches, even a
    // high-entropy value inside the brackets must not surface (it's a template).
    let p = pw(12, 14);
    let text = format!("ldap://binduser:<{p}>@ldap.corp.local");
    assert!(
        nothing_surfaces(&text, &p),
        "angle-bracket template password must not match"
    );
}

// ── cross-scheme co-surfacing ─────────────────────────────────────────────────

#[test]
fn smtp_and_ldap_credentials_cosurface() {
    let smtp_pw = pw(12, 21);
    let ldap_pw = pw(12, 22);
    let text =
        format!("smtp://mailer:{smtp_pw}@smtp.relay.net\nldap://bind:{ldap_pw}@ldap.corp.local\n");
    assert!(
        surfaces(&text, &smtp_pw),
        "SMTP password must surface alongside LDAP"
    );
    assert!(
        surfaces(&text, &ldap_pw),
        "LDAP password must surface alongside SMTP"
    );
}
