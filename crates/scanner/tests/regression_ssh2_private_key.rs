//! Recall + precision lock for `ssh2-private-key`: RFC 4716 / ssh.com Tectia
//! private keys use the 4-dash SPACED framing `---- BEGIN SSH2 [ENCRYPTED ]
//! PRIVATE KEY ----`, which the 5-dash no-space PEM detectors never match.
//!
//! Drives the REAL `CompiledScanner::scan` path, asserts the exact detector id
//! + captured bytes (Law 6). 24 pass/fail tests.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::CompiledScanner;

const ID: &str = "ssh2-private-key";

fn scan(text: &str) -> Vec<RawMatch> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("id_rsa.ssh2".into()),
            ..Default::default()
        },
    };
    scanner.scan(&chunk)
}

fn ssh2(text: &str) -> Option<RawMatch> {
    scan(text)
        .into_iter()
        .find(|m| m.detector_id.as_ref() == ID)
}
fn fires(text: &str) -> bool {
    ssh2(text).is_some()
}

fn enc_block(marker: &str) -> String {
    format!(
        "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n\
         Comment: \"2048-bit rsa\"\n\
         P2/56wAAAgI{marker}ssh2bodyssh2bodyssh2bodyssh2bodyssh2body0001\n\
         HpW3RqwsULLotTK1HAIPDqATPve1M6CgtxzBSBRKasyo1SSqT21dxfF1yAUHk\n\
         ---- END SSH2 ENCRYPTED PRIVATE KEY ----"
    )
}
fn plain_block(marker: &str) -> String {
    format!(
        "---- BEGIN SSH2 PRIVATE KEY ----\n\
         Subject: deploy\n\
         {marker}unencbodyunencbodyunencbodyunencbody0002base64base64\n\
         ---- END SSH2 PRIVATE KEY ----"
    )
}

// ---- RECALL: encrypted variant --------------------------------------

#[test]
fn encrypted_block_fires() {
    assert!(fires(&enc_block("ENCA")));
}
#[test]
fn encrypted_capture_includes_body() {
    let m = ssh2(&enc_block("BODYMARK7")).expect("fires");
    assert!(m.credential.as_ref().contains("BODYMARK7"));
}
#[test]
fn encrypted_capture_spans_begin_to_end() {
    let m = ssh2(&enc_block("SPN")).expect("fires");
    let c = m.credential.as_ref();
    assert!(c.contains("BEGIN SSH2 ENCRYPTED PRIVATE KEY"));
    assert!(c.contains("END SSH2 ENCRYPTED PRIVATE KEY"));
}
#[test]
fn encrypted_comment_with_quotes_fires() {
    // The `Comment: "..."` header carries embedded quotes; must not break the
    // lazy block capture.
    assert!(fires(&enc_block("QTC")));
}

// ---- RECALL: plain (unencrypted) variant ----------------------------

#[test]
fn plain_block_fires() {
    assert!(fires(&plain_block("PLNA")));
}
#[test]
fn plain_capture_includes_body() {
    let m = ssh2(&plain_block("UNENCMARK")).expect("fires");
    assert!(m.credential.as_ref().contains("UNENCMARK"));
}
#[test]
fn plain_capture_spans_begin_to_end() {
    let m = ssh2(&plain_block("PSP")).expect("fires");
    let c = m.credential.as_ref();
    assert!(c.contains("BEGIN SSH2 PRIVATE KEY"));
    assert!(c.contains("END SSH2 PRIVATE KEY"));
}

// ---- RECALL: framing / layout robustness ----------------------------

#[test]
fn embedded_in_larger_file_fires() {
    let text = format!("# key backup\n\n{}\n# eof\n", enc_block("EMB"));
    assert!(fires(&text));
}
#[test]
fn block_at_start_of_file_fires() {
    // No leading content before the BEGIN line.
    assert!(fires(&enc_block("STARTAA")));
}
#[test]
fn crlf_line_endings_fire() {
    let text = enc_block("CRLF").replace('\n', "\r\n");
    let m = ssh2(&text).expect("CRLF framing must still fire");
    assert!(m.credential.as_ref().contains("CRLF"));
}
#[test]
fn mismatched_encrypted_begin_plain_end_still_fires() {
    let text = "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nComment: x\nMISMATCHBODY0009base64base64base64\n---- END SSH2 PRIVATE KEY ----";
    let m = ssh2(text).expect("lenient framing must still fire");
    assert!(m.credential.as_ref().contains("MISMATCHBODY0009"));
}
#[test]
fn multi_header_subject_and_comment_fires() {
    let text = "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n\
                Subject: deploy@host\n\
                Comment: \"imported-openssh-key\"\n\
                MULTIHDRbodybodybodybodybodybodybody0011base64base64\n\
                ---- END SSH2 ENCRYPTED PRIVATE KEY ----";
    let m = ssh2(text).expect("fires");
    assert!(m.credential.as_ref().contains("MULTIHDRbody"));
}

// ---- RECALL: multiplicity -------------------------------------------

#[test]
fn two_distinct_blocks_yield_two_findings() {
    let text = format!("{}\n\n{}", enc_block("FIRSTAA"), plain_block("SECNDBB"));
    let hits: Vec<_> = scan(&text)
        .into_iter()
        .filter(|m| m.detector_id.as_ref() == ID)
        .collect();
    assert_eq!(hits.len(), 2);
    assert!(hits
        .iter()
        .any(|m| m.credential.as_ref().contains("FIRSTAA")));
    assert!(hits
        .iter()
        .any(|m| m.credential.as_ref().contains("SECNDBB")));
}
#[test]
fn two_encrypted_blocks_distinct_captures() {
    let a = ssh2(&enc_block("DISTA")).expect("a");
    let b = ssh2(&enc_block("DISTB")).expect("b");
    assert!(a.credential.as_ref().contains("DISTA"));
    assert!(b.credential.as_ref().contains("DISTB"));
    assert_ne!(a.credential.as_ref(), b.credential.as_ref());
}
#[test]
fn lazy_capture_does_not_span_two_blocks() {
    // Lazy `*?` must stop at the FIRST END, not swallow a second block, else
    // two findings would collapse into one greedy span.
    let text = format!("{}\n\n{}", enc_block("LAZYA"), enc_block("LAZYB"));
    let first = ssh2(&text).expect("at least one");
    // The earliest capture must contain LAZYA but NOT LAZYB.
    assert!(first.credential.as_ref().contains("LAZYA"));
    assert!(!first.credential.as_ref().contains("LAZYB"));
}

// ---- PRECISION ------------------------------------------------------

#[test]
fn public_key_block_does_not_fire() {
    let text = "---- BEGIN SSH2 PUBLIC KEY ----\nAAAAB3NzaC1yc2EpublicpublicpublicPub\n---- END SSH2 PUBLIC KEY ----";
    assert!(!fires(text));
}
#[test]
fn encrypted_header_only_no_end_does_not_fire() {
    assert!(!fires("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"));
}
#[test]
fn plain_header_only_no_end_does_not_fire() {
    assert!(!fires(
        "---- BEGIN SSH2 PRIVATE KEY ----\nSubject: deploy\nbodybodybody"
    ));
}
#[test]
fn format_mention_does_not_fire() {
    assert!(!fires(
        "See the ---- BEGIN SSH2 PRIVATE KEY ---- header described in RFC 4716."
    ));
}
#[test]
fn three_dash_framing_does_not_fire() {
    // Wrong dash count (3, not 4) (not the RFC 4716 framing).
    let text = "--- BEGIN SSH2 PRIVATE KEY ---\nbodybodybodybody\n--- END SSH2 PRIVATE KEY ---";
    assert!(!fires(text));
}
#[test]
fn pem_five_dash_block_does_not_fire_ssh2() {
    // PEM framing (5 dashes, NO space) is owned by private-key/ssh-private-key,
    // not the SSH2 4-dash-spaced detector.
    let pem =
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKnotssh2notssh2\n-----END RSA PRIVATE KEY-----";
    assert!(!fires(pem));
}

// ---- IDENTITY / RESOLUTION ------------------------------------------

#[test]
fn fires_under_exact_id_and_service() {
    let m = ssh2(&enc_block("IDA")).expect("fires");
    assert_eq!(m.detector_id.as_ref(), ID);
    assert_eq!(m.service.as_ref(), "ssh");
}
#[test]
fn ssh2_block_does_not_also_fire_pem_private_key() {
    // No double-report: the SSH2 block's 4-dash framing must NOT also trip the
    // 5-dash PEM `private-key` detector.
    let hits = scan(&enc_block("NODUP"));
    assert!(hits.iter().any(|m| m.detector_id.as_ref() == ID));
    assert!(
        !hits.iter().any(|m| m.detector_id.as_ref() == "private-key"),
        "PEM private-key must not co-fire on an SSH2 block"
    );
}
#[test]
fn captured_credential_is_substantial() {
    // The whole-block capture is the credential; assert it is non-trivial
    // (header + body + footer), not an empty or 1-char match.
    let m = ssh2(&enc_block("LEN")).expect("fires");
    assert!(m.credential.as_ref().len() > 80);
}

// ---- CONFIDENCE FLOOR (the `---- BEGIN SSH2` known-prefix lift) -------

#[test]
fn encrypted_block_gets_known_prefix_floor() {
    // The SSH2 framing is the high-confidence signal: the whole captured block
    // is floored to 0.8 like PEM `-----BEGIN` / PuTTY, NOT scored on its base64
    // body. Lock it so a real key with a short/low-entropy body still surfaces.
    let floor =
        keyhog_scanner::testing::confidence::known_prefix_confidence_floor(&enc_block("FLR"));
    assert_eq!(floor, Some(0.8));
}
#[test]
fn unencrypted_low_entropy_body_still_floored() {
    // Regression: the unencrypted contract positive (repetitive base64 body)
    // previously MISSED because it fell below the entropy-scored confidence
    // floor. The `---- BEGIN SSH2` prefix floor is what makes it fire.
    let floor =
        keyhog_scanner::testing::confidence::known_prefix_confidence_floor(&plain_block("FLR2"));
    assert_eq!(floor, Some(0.8));
}
#[test]
fn unencrypted_block_fires_after_floor_fix() {
    // The end-to-end proof of the fix: the low-entropy unencrypted block that the
    // contract caught as a miss now surfaces through the real scan path.
    let m = ssh2(&plain_block("RECALLFIX")).expect("unencrypted SSH2 block must fire");
    assert!(m.credential.as_ref().contains("RECALLFIX"));
}
