//! Detector-owned inter-keyword separator behavior.
//!
//! Shipped detectors write their intended `[_\-\s]*` semantics directly in
//! TOML. Loading does not broaden a pattern behind its owner's back. These
//! behavioral cases retain the multi-separator and former over-escape recall
//! guarantees through the compiled scanner.

mod support;
use support::contracts::{load_contracts, make_chunk, primaries, scanner, surfaces};

const SOURCE_TYPE: &str = "detector-owned-keyword-separators";

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
/// phrase (`8x8_api_key`, `AVAYA_CLOUD_CLIENT_ID`, …). These TOMLs now own the
/// explicit `[_\-\s]*` separator needed to accept the doubled form below.
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
        "detector-owned separator patterns dropped doubled keyword separators:\n  {}",
        failures.join("\n  ")
    );
    assert!(
        proven >= 12,
        "expected to prove >=12 detectors, proved only {proven}"
    );
}

/// The over-escape fix: lastfm's anchor was `[\\s_-]`: a literal backslash/`s`,
/// never whitespace, so `LAST FM=<key>` (a real, space-separated mention) was
/// silently missed. LastFM now owns `[_\-\s]*` directly in its TOML, so the
/// spaced form fires. Its joined `LASTFM=` contract did not expose this case.
#[test]
fn over_escaped_separator_now_matches_whitespace() {
    let scanner = scanner();
    let key = "e7a40edf8635d0cdb47ea9f156d972bc"; // 32 hex, lastfm's contract body
    let text = format!("LAST FM={key}");
    let chunk = make_chunk(&text, SOURCE_TYPE, "lastfm.txt");
    assert!(
        surfaces(&scanner, &chunk, key),
        "the detector-owned lastfm separator must match a real space: \
         {text:?} dropped {key:?}"
    );
}
