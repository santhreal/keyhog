//! Board-wide inter-keyword separator canonicalization.
//!
//! Detector anchors hand-wrote the separator between keyword words in 17
//! inconsistent, recall-leaky forms (`[_-]?`: no whitespace; `[_\s]?`: one
//! separator; `[_]*`: underscore only; over-escaped `[\\s_-]`: a literal
//! backslash/`s` instead of `\s`). `keyhog_core` now collapses every one of them
//! to a single canonical `[_\-\s]*` at spec-load, so a real secret is never
//! missed because a leaked file used a tab, a double space, or a hyphen where
//! the author allowed only one underscore. These tests pin that behaviour over
//! the LIVE corpus and prove the recall gain (incl. the over-escape fix) end to
//! end through the compiled scanner.

mod support;
use support::contracts::{load_contracts, make_chunk, primaries, scanner, surfaces};
use support::paths::detector_dir;

use keyhog_core::{canonicalize_keyword_separators, load_detectors, CANONICAL_SEPARATOR};

const SOURCE_TYPE: &str = "kwsep-canonicalization";

/// Every regex, AS LOADED through the production `load_detectors` path, must be a
/// fixed point of the canonicalizer, i.e. the separator canonicalization is
/// actually applied (no load path bypasses it) and no recall-leaky form survives
/// into the compiled corpus. Also asserts the canonical class is applied widely,
/// so the test cannot pass vacuously on an empty/uncanonicalized corpus.
#[test]
fn loaded_corpus_separators_are_all_canonical() {
    let dets = load_detectors(&detector_dir()).expect("load detectors");
    let mut patterns = 0usize;
    let mut canonical_uses = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    for d in &dets {
        let regexes = d
            .patterns
            .iter()
            .map(|p| &p.regex)
            .chain(d.companions.iter().map(|c| &c.regex));
        for r in regexes {
            patterns += 1;
            if canonicalize_keyword_separators(r).as_ref() != r.as_str() {
                offenders.push(format!(
                    "{}: non-canonical separator survived load: {r:?}",
                    d.id
                ));
            }
            if r.contains(CANONICAL_SEPARATOR) {
                canonical_uses += 1;
            }
        }
    }
    assert!(
        patterns > 800,
        "expected the full corpus, only saw {patterns} regexes"
    );
    assert!(
        offenders.is_empty(),
        "{} regex(es) carry a non-canonical inter-keyword separator after load, a load path \
         bypassed canonicalization:\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
    assert!(
        canonical_uses > 200,
        "the canonical separator should be applied across hundreds of detectors; saw only \
         {canonical_uses} (is canonicalization wired in?)"
    );
}

/// Double every inter-keyword separator (a space/`_`/`-` flanked by word chars)
/// in `prefix`. `8x8_api_key=` -> `8x8__api__key=`. The credential is never part
/// of `prefix`, so it is preserved byte-exact.
fn double_interword_separators(prefix: &str) -> String {
    let chars: Vec<char> = prefix.chars().collect();
    let mut out = String::with_capacity(prefix.len() + 8);
    for (i, &c) in chars.iter().enumerate() {
        out.push(c);
        let is_sep = matches!(c, ' ' | '_' | '-');
        let between_words = i > 0
            && chars[i - 1].is_alphanumeric()
            && chars.get(i + 1).is_some_and(|n| n.is_alphanumeric());
        if is_sep && between_words {
            out.push(c); // a SECOND separator a single-`?` form could never match
        }
    }
    out
}

/// Detectors whose contract positive anchors with an underscore-joined keyword
/// phrase (`8x8_api_key`, `AVAYA_CLOUD_CLIENT_ID`, …). Before canonicalization
/// their `[_\-\s]?` / `[_-]?` separators matched at most ONE underscore, so the
/// doubled form below was dropped; after it, the canonical `[_\-\s]*` rescues it.
const DOUBLED_SEPARATOR_DETECTORS: &[&str] = &[
    "8x8-api-credentials",
    "avaya-api-credentials",
    "bluejeans-api",
    "countly-api-key",
    "fathom-api-key",
    "goatcounter-api-credentials",
    "google-meet-api",
    "goto-meeting-api",
    "matomo-api-token",
    "piwikpro-api-credentials",
    "simpleanalytics-api-key",
    "umami-api-key",
    "zoom-phone-api-credentials",
];

#[test]
fn detectors_fire_under_doubled_keyword_separators() {
    let scanner = scanner();
    let contracts = load_contracts();
    let primaries = primaries(&contracts);

    let mut proven = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for id in DOUBLED_SEPARATOR_DETECTORS {
        let p = primaries
            .iter()
            .find(|p| p.detector_id == *id)
            .unwrap_or_else(|| panic!("no contract primary for {id}"));
        let pos = p
            .text
            .find(&p.credential)
            .unwrap_or_else(|| panic!("{id}: credential not a substring of its positive text"));
        let prefix = double_interword_separators(&p.text[..pos]);
        // The transform MUST have introduced a real doubled separator, else this
        // case proves nothing (Law 6: no vacuous green).
        assert_ne!(
            prefix,
            &p.text[..pos],
            "{id}: contract positive {:?} has no inter-keyword separator to double. \
             pick a different fixture",
            p.text
        );
        let text = format!(
            "{prefix}{}{}",
            p.credential,
            &p.text[pos + p.credential.len()..]
        );
        let chunk = make_chunk(&text, SOURCE_TYPE, "anchor.txt");
        if surfaces(&scanner, &chunk, &p.credential) {
            proven += 1;
        } else {
            failures.push(format!(
                "{id}: doubled-separator anchor {text:?} dropped the credential"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "canonicalization failed to rescue doubled keyword separators:\n  {}",
        failures.join("\n  ")
    );
    assert!(
        proven >= 12,
        "expected to prove >=12 detectors, proved only {proven}"
    );
}

/// The over-escape fix: lastfm's anchor was `[\\s_-]`: a literal backslash/`s`,
/// never whitespace, so `LAST FM=<key>` (a real, space-separated mention) was
/// silently missed. Canonicalization rewrites it to `[_\-\s]*`, so the spaced
/// form now fires. (Its contract positive is the joined `LASTFM=` form, which
/// matched even with the bug; only a genuine whitespace separator exposes it.)
#[test]
fn over_escaped_separator_now_matches_whitespace() {
    let scanner = scanner();
    let key = "e7a40edf8635d0cdb47ea9f156d972bc"; // 32 hex, lastfm's contract body
    let text = format!("LAST FM={key}");
    let chunk = make_chunk(&text, SOURCE_TYPE, "lastfm.txt");
    assert!(
        surfaces(&scanner, &chunk, key),
        "the over-escaped lastfm separator must match a real space after canonicalization: \
         {text:?} dropped {key:?}"
    );
}
