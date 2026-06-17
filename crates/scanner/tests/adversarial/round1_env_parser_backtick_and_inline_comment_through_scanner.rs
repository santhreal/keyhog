//! Round 1 FN-recovery regression contract: the structured `.env`
//! preprocessor must strip backtick quotes around values AND drop
//! trailing `# inline comment` segments on unquoted values, so the
//! captured credential byte range matches the secret exactly.
//!
//! Investigator finding (d60fa9d6, structured/parsers): pre-fix,
//! backtick-wrapped tokens kept the surrounding backticks. Named
//! detector AC literals (e.g. `ghp_`) were offset by one byte and never
//! matched. Inline `# comment` text bled into the captured credential,
//! over-extending the recorded credential bytes past the actual secret.
//!
//! The fix lives in `crates/scanner/src/structured/parsers.rs`. Module-
//! local `#[cfg(test)]` tests in that file cover the parser in
//! isolation. This file is the end-to-end lockdown: drive the production
//! scanner pipeline over a `.env` chunk and assert the surfaced
//! credential matches the secret bytes exactly, with NO leading/
//! trailing punctuation, NO backticks, NO comment text.
//!
//! Adversarial style: CROSS-FILE. The SAME GitHub PAT secret is planted
//! into two sibling `.env` files (one backtick-wrapped, one with a
//! trailing inline comment). The scan must surface BOTH with credential
//! bytes equal to the bare token; a regression in either parser branch
//! fails the assertion immediately. This pairs a real disclosed-shape
//! GitHub PAT prefix (CVE replay shape, body redacted to deterministic
//! synthetic bytes that still pass the detector's length+alphabet
//! contract) against a CamelCase identifier that decorates the comment
//! to make sure inline-comment bytes do not survive the strip.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

fn shared_scanner() -> &'static CompiledScanner {
    // Shared single scanner (LG2): all adversarial full-detector tests
    // route through one compiled instance instead of one per file.
    crate::adversarial::oracle_support::production_scanner()
}

fn scan_path(body: &str, path: &str) -> Vec<keyhog_core::RawMatch> {
    let chunk = Chunk {
        data: body.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    shared_scanner().scan(&chunk)
}

/// CVE-replay shape: real GitHub classic PAT prefix `ghp_` plus 36
/// deterministic-but-synthetic body bytes that pass the contract regex
/// `ghp_[A-Za-z0-9]{36,255}`. The body deliberately mixes the full
/// base62 alphabet so the named detector's downstream entropy/shape
/// gates do not slam the match for low-entropy.
const SYNTHETIC_GHP: &str = "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";

/// Positive truth: a `.env` line with a BACKTICK-wrapped GitHub PAT
/// must surface the credential WITHOUT the wrapping backticks. The
/// captured bytes must equal the bare token; a regression that re-
/// admits the backticks would offset the named detector's `ghp_`
/// literal by one byte and the value would land in generic-secret with
/// the wrong span.
#[test]
fn env_backtick_wrapped_ghp_surfaces_without_backticks() {
    let body = format!("GITHUB_TOKEN=`{SYNTHETIC_GHP}`\n");
    let matches = scan_path(&body, "/repo/.env");
    let exact_hits: Vec<_> = matches
        .iter()
        .filter(|m| m.credential.as_ref() == SYNTHETIC_GHP)
        .collect();
    assert!(
        !exact_hits.is_empty(),
        "backtick-wrapped ghp_ must surface with credential equal to the \
         bare token (no wrapping backticks). Found {} exact matches; ALL findings: {:?}",
        exact_hits.len(),
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );

    // Adversarial: no surfaced finding may carry the backticks inside
    // its credential. A regression that drops the strip would surface a
    // credential like "`ghp_..." or "ghp_...`".
    let with_backticks: Vec<_> = matches
        .iter()
        .filter(|m| m.credential.as_ref().contains('`'))
        .collect();
    assert!(
        with_backticks.is_empty(),
        "no finding may contain backticks in the credential bytes; \
         offenders: {:?}",
        with_backticks
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

/// Positive truth: a `.env` line with an UNQUOTED value followed by
/// `# rotate quarterly` (whitespace + hash + prose) must surface the
/// credential WITHOUT the comment. Captured bytes must equal the bare
/// token. The comment text "RotateQuarterly" is a CamelCase identifier
/// shape; without the strip it would be appended to the credential and
/// over-extend the recorded span.
#[test]
fn env_unquoted_with_inline_comment_strips_comment_from_credential() {
    let body = format!("GITHUB_TOKEN={SYNTHETIC_GHP} # RotateQuarterlyOnFridays\n");
    let matches = scan_path(&body, "/repo/secrets/.env");

    let exact_hits: Vec<_> = matches
        .iter()
        .filter(|m| m.credential.as_ref() == SYNTHETIC_GHP)
        .collect();
    assert!(
        !exact_hits.is_empty(),
        "inline-comment line must surface a finding whose credential \
         equals the bare token without the comment text. ALL findings: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );

    // Adversarial: no surfaced finding may have the comment prose bleed
    // into the credential. "RotateQuarterly" is the canonical marker.
    for m in &matches {
        let cred = m.credential.as_ref();
        assert!(
            !cred.contains("RotateQuarterly"),
            "inline-comment prose leaked into credential bytes: \
             detector={} credential={:?}",
            m.detector_id.as_ref(),
            cred
        );
    }
}

/// Adversarial negative twin: a `#` INSIDE a quoted value is part of
/// the literal credential and must NOT be treated as a comment. Real
/// passphrase / base64 / JWT credentials can embed `#`. Dropping bytes
/// after `#` inside quotes would silently truncate the captured bytes.
#[test]
fn env_hash_inside_quoted_value_is_preserved() {
    let credential_with_hash = "p4ss#w0rd#with#hashes";
    let body = format!("DB_PASSWORD=\"{credential_with_hash}\"\n");
    let matches = scan_path(&body, "/repo/.env");

    // The credential MUST surface with all hashes intact somewhere.
    let surfaced = matches.iter().any(|m| {
        let c = m.credential.as_ref();
        c == credential_with_hash || c.contains(credential_with_hash)
    });
    assert!(
        surfaced,
        "credential containing `#` inside DOUBLE quotes must NOT be \
         truncated. ALL findings: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

/// CROSS-FILE adversarial: the SAME synthetic ghp_ token planted in
/// two different `.env` shapes (backtick + inline-comment) MUST both
/// surface with the bare credential bytes. A regression in either
/// parser branch (backtick-strip OR comment-strip) fails this test.
#[test]
fn cross_file_same_secret_in_backtick_and_inline_comment_env_shapes() {
    let scanner = shared_scanner();
    scanner.clear_fragment_cache();

    let file_a_body = format!("GITHUB_TOKEN=`{SYNTHETIC_GHP}`\n");
    let len_a = file_a_body.len();
    let file_b_body = format!("GITHUB_TOKEN={SYNTHETIC_GHP} # rotate after launch\n");

    let chunk_a = Chunk {
        data: file_a_body.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("/repo/svc-a/.env".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    let chunk_b = Chunk {
        data: file_b_body.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("/repo/svc-b/.env".into()),
            base_offset: len_a,
            ..Default::default()
        },
    };

    let groups = scanner.scan_coalesced(&[chunk_a, chunk_b]);
    let flat: Vec<_> = groups.into_iter().flatten().collect();

    let svc_a_exact = flat.iter().any(|m| {
        m.credential.as_ref() == SYNTHETIC_GHP
            && m.location
                .file_path
                .as_deref()
                .map(|p| p.contains("svc-a"))
                .unwrap_or(false)
    });
    let svc_b_exact = flat.iter().any(|m| {
        m.credential.as_ref() == SYNTHETIC_GHP
            && m.location
                .file_path
                .as_deref()
                .map(|p| p.contains("svc-b"))
                .unwrap_or(false)
    });

    assert!(
        svc_a_exact,
        "backtick-wrapped variant in svc-a/.env must surface SYNTHETIC_GHP exactly. \
         findings: {:?}",
        flat.iter()
            .map(|m| (
                m.detector_id.as_ref(),
                m.credential.as_ref(),
                m.location.file_path.as_deref(),
            ))
            .collect::<Vec<_>>()
    );
    assert!(
        svc_b_exact,
        "inline-comment variant in svc-b/.env must surface SYNTHETIC_GHP exactly. \
         findings: {:?}",
        flat.iter()
            .map(|m| (
                m.detector_id.as_ref(),
                m.credential.as_ref(),
                m.location.file_path.as_deref(),
            ))
            .collect::<Vec<_>>()
    );
}
