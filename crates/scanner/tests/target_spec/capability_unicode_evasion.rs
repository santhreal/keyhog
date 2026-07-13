//! CAPABILITY TARGET-SPEC: unicode / homoglyph evasion recall.
//!
//! An attacker (or a copy-paste through a rich-text editor) can swap an ASCII
//! character in the SURROUNDING context, or, more dangerously, inside the
//! credential's keyword anchor, for a visually identical Cyrillic / fullwidth
//! homoglyph, or insert a non-breaking space, and a naive regex stops matching.
//! keyhog ships a unicode-normalization pass (`normalize_homoglyphs`,
//! crates/scanner/src/unicode_hardening.rs) precisely so this evasion fails. This
//! lane proves the normalization actually reaches detection: it homoglyph-
//! substitutes the CONTEXT around a credential-sufficient token (and inserts a
//! NBSP separator) and asserts the credential still surfaces.
//!
//! Soundness: every variant preserves the credential's own bytes verbatim, only
//! the surrounding ASCII (keyword, separators) is perturbed with confusables
//! that `normalize_homoglyphs` is documented to fold back to ASCII. A miss is a
//! normalization-coverage gap (the confusable wasn't in the fold table, or
//! normalization didn't run on this path), never a fixture artifact.
//!
//! Expected partially RED: the fold table (cyrillic_to_latin + fullwidth) covers
//! a finite confusable set; characters outside it slip through. Each miss is a
//! tracked gap to close by widening the table (never weakened to pass (Law 9)).

use crate::target_spec::{join_capped, load_canonicals, scan, sufficient_canonicals, surfaces};

/// Replace ASCII letters in `s` with the Cyrillic homoglyph keyhog's
/// `cyrillic_to_latin` fold table is documented to reverse. Only the letters
/// that have a confusable are swapped; the rest (and ALL digits) are left
/// ASCII so the credential body stays byte-identical when this is applied to
/// CONTEXT only.
fn cyrillicize_letters(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a' => 'а', // U+0430 CYRILLIC SMALL A
            'e' => 'е', // U+0435 CYRILLIC SMALL IE
            'o' => 'о', // U+043E CYRILLIC SMALL O
            'p' => 'р', // U+0440 CYRILLIC SMALL ER
            'c' => 'с', // U+0441 CYRILLIC SMALL ES
            'y' => 'у', // U+0443 CYRILLIC SMALL U
            'x' => 'х', // U+0445 CYRILLIC SMALL HA
            'A' => 'А',
            'E' => 'Е',
            'O' => 'О',
            'P' => 'Р',
            'C' => 'С',
            'X' => 'Х',
            other => other,
        })
        .collect()
}

/// Replace ASCII printable chars with their fullwidth (U+FF01..U+FF5E)
/// equivalents that `fullwidth_to_ascii` folds back. Digits included (so this is
/// applied to CONTEXT only, never to the credential body).
fn fullwidthize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if ('!'..='~').contains(&c) {
                char::from_u32(c as u32 - 0x21 + 0xFF01).unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

/// TARGET: a credential-sufficient token whose surrounding keyword/context is
/// homoglyph- or NBSP-evaded must still surface, because normalization runs
/// before detection. Pinned at 0.95; expected red for confusables outside the
/// fold table.
const UNICODE_TARGET_RECALL: f64 = 0.95;

/// Cyrillic-homoglyph CONTEXT around an untouched credential. The keyword anchor
/// (`api_token`) is cyrillicized; the credential bytes are preserved verbatim.
#[test]
fn credential_survives_cyrillic_homoglyph_context() {
    let all = load_canonicals();
    let sufficient = sufficient_canonicals(&all);
    assert!(
        sufficient.len() >= 150,
        "expected >= 150 credential-sufficient detectors, found {}",
        sufficient.len()
    );

    let mut total = 0usize;
    let mut surfaced = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for canon in &sufficient {
        // Cyrillicize ONLY the keyword prefix; keep the credential ASCII.
        let prefix = cyrillicize_letters("api_token = ");
        let body = format!("{prefix}\"{}\"\n", canon.credential);
        // Soundness: credential bytes untouched.
        assert!(
            body.contains(&canon.credential),
            "cyrillic context mangled credential for {}",
            canon.detector_id
        );
        let matches = scan(&body, "evasion/cyrillic.conf");
        total += 1;
        if surfaces(&matches, &canon.credential) {
            surfaced += 1;
        } else {
            failures.push(canon.detector_id.clone());
        }
    }

    let ratio = surfaced as f64 / total.max(1) as f64;
    println!(
        "cyrillic-context recall: {surfaced}/{total} = {ratio:.4}; {} lost",
        failures.len()
    );
    assert!(
        ratio >= UNICODE_TARGET_RECALL,
        "cyrillic-homoglyph context dropped {}/{total} credential-sufficient tokens \
         (recall {ratio:.4}, target {UNICODE_TARGET_RECALL:.2}); normalization is not folding the \
         confusable keyword before detection for these:\n  - {}",
        total - surfaced,
        join_capped(&failures, 50)
    );
}

/// Fullwidth CONTEXT around an untouched credential.
#[test]
fn credential_survives_fullwidth_context() {
    let all = load_canonicals();
    let sufficient = sufficient_canonicals(&all);

    let mut total = 0usize;
    let mut surfaced = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for canon in &sufficient {
        let prefix = fullwidthize("API_TOKEN=");
        let body = format!("{prefix}{}\n", canon.credential);
        assert!(
            body.contains(&canon.credential),
            "fullwidth context mangled credential for {}",
            canon.detector_id
        );
        let matches = scan(&body, "evasion/fullwidth.env");
        total += 1;
        if surfaces(&matches, &canon.credential) {
            surfaced += 1;
        } else {
            failures.push(canon.detector_id.clone());
        }
    }

    let ratio = surfaced as f64 / total.max(1) as f64;
    println!(
        "fullwidth-context recall: {surfaced}/{total} = {ratio:.4}; {} lost",
        failures.len()
    );
    assert!(
        ratio >= UNICODE_TARGET_RECALL,
        "fullwidth context dropped {}/{total} tokens (recall {ratio:.4}, target \
         {UNICODE_TARGET_RECALL:.2}); fullwidth keyword not normalized before detection for:\n  - {}",
        total - surfaced,
        join_capped(&failures, 50)
    );
}

/// Non-breaking-space (U+00A0) separator between the keyword and the credential
///: a classic copy-from-PDF/rich-editor artifact. keyhog normalizes NBSP to a
/// regular space (see regression_unicode_nbsp_separator_normalization); this
/// asserts that reach across every credential-sufficient detector.
#[test]
fn credential_survives_nbsp_separator() {
    let all = load_canonicals();
    let sufficient = sufficient_canonicals(&all);

    let mut total = 0usize;
    let mut surfaced = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for canon in &sufficient {
        // NBSP (\u{00A0}) where a normal space/`=` would be.
        let body = format!("api_token\u{00A0}=\u{00A0}{}\n", canon.credential);
        assert!(
            body.contains(&canon.credential),
            "nbsp context mangled credential for {}",
            canon.detector_id
        );
        let matches = scan(&body, "evasion/nbsp.conf");
        total += 1;
        if surfaces(&matches, &canon.credential) {
            surfaced += 1;
        } else {
            failures.push(canon.detector_id.clone());
        }
    }

    let ratio = surfaced as f64 / total.max(1) as f64;
    println!(
        "nbsp-separator recall: {surfaced}/{total} = {ratio:.4}; {} lost",
        failures.len()
    );
    assert!(
        ratio >= UNICODE_TARGET_RECALL,
        "NBSP separator dropped {}/{total} tokens (recall {ratio:.4}, target \
         {UNICODE_TARGET_RECALL:.2}); NBSP not folded to space before detection for:\n  - {}",
        total - surfaced,
        join_capped(&failures, 50)
    );
}
