//! A vendor anchor that is two or three letters must not match at the tail of
//! an unrelated identifier.
//!
//! `africastalking-api-key` began `(?:...|at|AT)[_.-]?API...` with no leading
//! boundary, so `SNAPCHAT_API_KEY=` matched. Four more detectors carried the
//! same shape, and two of them were reproducibly wrong on ordinary input:
//! `xapi_key=<uuid>` near the word "mexico" was reported as a Mexican
//! government key, and `LEIGH_WEBHOOK_SECRET=` was reported as a GitHub webhook
//! secret.
//!
//! Every case below was run against the scanner before the fix. The two marked
//! as previously firing did fire; the rest are pinned so the anchors cannot
//! loosen later. The true positives are here for the same reason: `\b` is only
//! the right fix if the real credential still surfaces, so each detector's
//! genuine form is asserted beside the identifier it must now ignore.

use keyhog_scanner::CompiledScanner;

mod support;
use support::contracts::{scanner, test_chunk};

const UUID: &str = "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d";
const HEX40: &str = "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8";

/// Which detectors fire on one line of text.
fn detectors_firing(scanner: &CompiledScanner, text: &str) -> Vec<String> {
    scanner.clear_fragment_cache();
    let mut ids: Vec<String> = scanner
        .scan(&test_chunk(text, "anchor.env"))
        .expect("short-anchor regression scan should succeed")
        .into_iter()
        .map(|m| m.detector_id.to_string())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

#[track_caller]
fn assert_fires(scanner: &CompiledScanner, detector: &str, text: &str) {
    let firing = detectors_firing(scanner, text);
    assert!(
        firing.iter().any(|id| id == detector),
        "{detector} must still match its genuine form; fired: {firing:?}"
    );
}

#[track_caller]
fn assert_silent(scanner: &CompiledScanner, detector: &str, text: &str) {
    let firing = detectors_firing(scanner, text);
    assert!(
        !firing.iter().any(|id| id == detector),
        "{detector} matched at the tail of an unrelated identifier; fired: {firing:?}"
    );
}

/// `SNAPCHAT_API_KEY=` contains a literal `AT_API_KEY=`.
///
/// This is the case that broke GPU autoroute calibration: the region-presence
/// route found the extra raw match, the scalar route did not, and calibration
/// refused to route the class. The report never showed it, because
/// cross-detector deduplication collapses two matches on one credential, so a
/// finding-level assertion would have missed it entirely.
#[test]
fn africastalking_ignores_the_at_inside_snapchat() {
    let scanner = scanner();
    let secret = "a573881b385d7370d17ec84d8f8264a6f9a8d7709bc9323e8be592ba1c474c1a";

    assert_silent(
        &scanner,
        "africastalking-api-key",
        &format!("SNAPCHAT_API_KEY={secret}"),
    );
    assert_silent(
        &scanner,
        "africastalking-api-key",
        &format!("FORMAT_API_KEY={secret}"),
    );
    assert_fires(
        &scanner,
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
    // `AT_API_KEY=<32 chars>` is deliberately absent. It is the vendor's own
    // environment variable and a declared keyword, but it does not surface as
    // this detector, and it did not before the anchor either, verified against
    // a corpus holding the pre-fix pattern. Asserting either outcome here would
    // be wrong: firing is not true today, and not-firing would enshrine a
    // recall gap this change did not cause. It is tracked as KH-1583.
}

/// A bare `api` made this detector generic.
///
/// Before the fix `xapi_key=<uuid>` near the word "mexico" was reported as a
/// Mexican government key. Verified firing on the pre-fix binary, so this is a
/// reproduction, not a hypothetical.
#[test]
fn datosgobmx_ignores_an_api_key_inside_another_identifier() {
    let scanner = scanner();

    assert_silent(
        &scanner,
        "mexico-datosgobmx-api-key",
        &format!("xapi_key={UUID} mexico"),
    );
    assert_fires(
        &scanner,
        "mexico-datosgobmx-api-key",
        &format!("api_key={UUID} datos.gob.mx"),
    );
}

/// A bare `gh` made any identifier ending in those letters a GitHub secret.
///
/// Before the fix `LEIGH_WEBHOOK_SECRET=` was reported. Verified firing on the
/// pre-fix binary.
#[test]
fn github_webhook_secret_ignores_the_gh_inside_leigh() {
    let scanner = scanner();
    let value = "N-hyshMKLyl_Pj_laamriw0VaNok";

    assert_silent(
        &scanner,
        "github-webhook-secret",
        &format!("LEIGH_WEBHOOK_SECRET={value}"),
    );
    assert_fires(
        &scanner,
        "github-webhook-secret",
        &format!("GITHUB_WEBHOOK_SECRET={value}"),
    );
}

/// A bare `nr` and a bare `license` are both reachable mid-identifier.
///
/// Neither surfaced a finding before the fix, because other gates happened to
/// stop them, but the pattern admitted the match and those gates are not part
/// of this detector's contract. Anchoring makes the detector itself correct.
#[test]
fn newrelic_ignores_the_nr_inside_another_identifier() {
    let scanner = scanner();

    assert_silent(
        &scanner,
        "newrelic-license-key",
        &format!("SOLNR_KEY={HEX40}"),
    );
    assert_fires(
        &scanner,
        "newrelic-license-key",
        &format!("NEW_RELIC_LICENSE_KEY={HEX40}"),
    );
    assert_fires(
        &scanner,
        "newrelic-license-key",
        &format!("NR_LICENSE_KEY={HEX40}"),
    );
}

/// A bare `cm` is two of the commonest letters to end an identifier with.
#[test]
fn cmcom_ignores_the_cm_inside_another_identifier() {
    let scanner = scanner();

    assert_silent(&scanner, "cmcom-api-key", &format!("WEBCM_TOKEN={UUID}"));
    assert_fires(&scanner, "cmcom-api-key", &format!("CM_PRODUCT_TOKEN={UUID}"));
    assert_fires(
        &scanner,
        "cmcom-api-key",
        &format!("X-CM-PRODUCTTOKEN={UUID}"),
    );
}
