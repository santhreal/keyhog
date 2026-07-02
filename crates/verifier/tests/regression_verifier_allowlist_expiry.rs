//! Regression coverage for allowlist expiry + inline-metadata governance, the
//! suppression gate that runs before a verifier ever fires a request.
//!
//! Everything here drives the SHIPPED public surface of `keyhog_core`:
//!   - `Allowlist::load_with_metadata_policy` (the real on-disk loader), and
//!   - the `keyhog_core::testing` facade (`allowlist_parse`,
//!     `allowlist_is_hash_allowed`, `allowlist_days_since_epoch_for_test`).
//!
//! Contract under test:
//!   1. An expired entry (`expires=<past>`) is NEVER an active suppression.
//!   2. A future-dated entry (`expires=<future>`) loads and DOES suppress.
//!   3. Inline `reason="..."` metadata is parsed verbatim (semicolons inside
//!      the quoted value stay part of the value), and an absent/empty reason is
//!      rejected under `require_reason`.
//!   4. A system clock before UNIX_EPOCH is rejected with an operator message.
//!
//! Every assertion pins a concrete value (bool / integer / exact substring /
//! io::ErrorKind), never a bare `is_empty()`/`is_ok()`.

use std::io::ErrorKind;
use std::time::{Duration, SystemTime};

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::Allowlist;

/// A clearly-past expiry (UNIX day 0). Always < today for any sane host clock.
const PAST: &str = "1970-01-01";
/// A clearly-future expiry. Always > today for any sane host clock.
const FUTURE: &str = "9999-12-31";

fn temp_ignore(tag: &str, contents: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "keyhog_verifier_allowlist_{}_{}.keyhogignore",
        std::process::id(),
        tag
    ));
    std::fs::write(&path, contents).expect("write allowlist temp file");
    path
}

fn zero_hash() -> String {
    "0".repeat(64)
}

// ---------------------------------------------------------------------------
// 1. Expired entries do NOT suppress (detector / hash / path).
// ---------------------------------------------------------------------------

#[test]
fn expired_detector_entry_does_not_suppress() {
    let content = format!("detector:leaked-token ; expires={PAST}\n");
    let al = TestApi.allowlist_parse(&content);
    // Expired => dropped, so the detector is NOT an active suppression.
    assert_eq!(al.ignored_detectors.contains("leaked-token"), false);
    assert_eq!(al.ignored_detectors.len(), 0);
}

#[test]
fn expired_hash_entry_does_not_suppress() {
    let hash = zero_hash();
    let content = format!("hash:{hash} ; expires={PAST}\n");
    let al = TestApi.allowlist_parse(&content);
    assert_eq!(TestApi.allowlist_is_hash_allowed(&al, &hash), false);
    assert_eq!(TestApi.allowlist_is_raw_hash_ignored(&al, &hash), false);
    assert_eq!(al.credential_hashes.len(), 0);
}

#[test]
fn expired_path_entry_does_not_suppress() {
    let content = format!("path:**/*.env ; expires={PAST}\n");
    let al = TestApi.allowlist_parse(&content);
    assert_eq!(al.is_path_ignored("config/prod/.env"), false);
    assert_eq!(al.ignored_paths.len(), 0);
}

// ---------------------------------------------------------------------------
// 2. Future-dated entries load and DO suppress (negative twins of the above).
// ---------------------------------------------------------------------------

#[test]
fn future_dated_detector_entry_loads_and_suppresses() {
    let content = format!("detector:approved-token ; expires={FUTURE}\n");
    let al = TestApi.allowlist_parse(&content);
    assert_eq!(al.ignored_detectors.contains("approved-token"), true);
    assert_eq!(al.ignored_detectors.len(), 1);
}

#[test]
fn future_dated_hash_entry_suppresses() {
    let hash = zero_hash();
    let content = format!("hash:{hash} ; expires={FUTURE}\n");
    let al = TestApi.allowlist_parse(&content);
    assert_eq!(TestApi.allowlist_is_hash_allowed(&al, &hash), true);
    assert_eq!(TestApi.allowlist_is_raw_hash_ignored(&al, &hash), true);
    assert_eq!(al.credential_hashes.len(), 1);
}

#[test]
fn future_dated_path_entry_suppresses_only_matching_paths() {
    let content = format!("path:**/*.env ; expires={FUTURE}\n");
    let al = TestApi.allowlist_parse(&content);
    assert_eq!(al.ignored_paths, vec!["**/*.env".to_string()]);
    // Positive: a matching path is suppressed.
    assert_eq!(al.is_path_ignored("config/prod/.env"), true);
    // Negative twin: a same-directory non-match is NOT suppressed.
    assert_eq!(al.is_path_ignored("config/prod/env.sample"), false);
}

// ---------------------------------------------------------------------------
// 3. On-disk loader: expired => fail-closed error; future => Ok + active.
// ---------------------------------------------------------------------------

#[test]
fn load_file_with_expired_entry_fails_closed_invalid_data() {
    let path = temp_ignore("expired", &format!("detector:stale ; expires={PAST}\n"));
    let result = Allowlist::load_with_metadata_policy(&path, false, false, None);
    let _ = std::fs::remove_file(&path);

    let err = result.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(
        msg.contains("contains expired allowlist policy"),
        "expected expired-policy phrasing, got: {msg}"
    );
    assert!(msg.contains("line 1"), "expected line number, got: {msg}");
    assert!(
        msg.contains(&format!("expired on {PAST}")),
        "expected the exact expiry date, got: {msg}"
    );
    assert!(
        msg.contains("refusing to scan with stale suppressions"),
        "expected fail-closed rationale, got: {msg}"
    );
}

#[test]
fn load_file_with_future_entry_succeeds_and_is_active() {
    let path = temp_ignore("future", &format!("detector:ok ; expires={FUTURE}\n"));
    let result = Allowlist::load_with_metadata_policy(&path, false, false, None);
    let _ = std::fs::remove_file(&path);

    let al = result.expect("future-dated entry must load");
    assert_eq!(al.ignored_detectors.contains("ok"), true);
    assert_eq!(al.ignored_detectors.len(), 1);
}

// ---------------------------------------------------------------------------
// 4. Inline `reason` metadata parsing + require_reason governance.
// ---------------------------------------------------------------------------

#[test]
fn require_reason_missing_reason_fails_with_exact_message() {
    let path = temp_ignore("noreason", "detector:svc\n");
    // require_reason = true, require_approved_by = false, max_expires_days = None.
    let result = Allowlist::load_with_metadata_policy(&path, true, false, None);
    let _ = std::fs::remove_file(&path);

    let err = result.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(
        msg.contains("violates allowlist governance at line 1"),
        "expected governance+line phrasing, got: {msg}"
    );
    assert!(
        msg.contains("missing/invalid reason (required by [allowlist].require_reason)"),
        "expected the exact reason-required detail, got: {msg}"
    );
    assert!(
        msg.contains("refusing to scan with unapproved suppressions"),
        "expected fail-closed rationale, got: {msg}"
    );
}

#[test]
fn require_reason_present_reason_loads() {
    let path = temp_ignore(
        "withreason",
        "detector:svc ; reason=\"approved by appsec\"\n",
    );
    let result = Allowlist::load_with_metadata_policy(&path, true, false, None);
    let _ = std::fs::remove_file(&path);

    let al = result.expect("entry with a reason must satisfy require_reason");
    assert_eq!(al.ignored_detectors.contains("svc"), true);
    assert_eq!(al.ignored_detectors.len(), 1);
}

#[test]
fn empty_reason_is_treated_as_missing_under_require_reason() {
    // Boundary: `reason=""` is present syntactically but empty => rejected.
    let path = temp_ignore("emptyreason", "detector:svc ; reason=\"\"\n");
    let result = Allowlist::load_with_metadata_policy(&path, true, false, None);
    let _ = std::fs::remove_file(&path);

    let err = result.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(
        msg.contains("missing/invalid reason (required by [allowlist].require_reason)"),
        "empty reason must be rejected like a missing one, got: {msg}"
    );
}

#[test]
fn quoted_reason_preserves_embedded_semicolon_as_single_value() {
    // A `;` inside the quoted reason must stay part of the value, NOT split a
    // spurious metadata token. The whole entry loads cleanly.
    let path = temp_ignore(
        "quotedsemi",
        "detector:svc ; reason=\"rotate later; ticket SEC-9\"\n",
    );
    let result = Allowlist::load_with_metadata_policy(&path, false, false, None);
    let _ = std::fs::remove_file(&path);

    let al = result.expect("quoted reason with an embedded ';' must parse as one value");
    assert_eq!(al.ignored_detectors, {
        let mut s = std::collections::HashSet::new();
        s.insert("svc".to_string());
        s
    });
}

#[test]
fn unquoted_reason_semicolon_splits_into_malformed_token() {
    // Negative twin of the quoted case: without quotes, `; ticket SEC-9`
    // becomes its own token, which has no `=` and is reported as malformed.
    let path = temp_ignore(
        "unquotedsemi",
        "detector:svc ; reason=rotate later; ticket SEC-9\n",
    );
    let result = Allowlist::load_with_metadata_policy(&path, false, false, None);
    let _ = std::fs::remove_file(&path);

    let err = result.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(
        msg.contains("metadata token `ticket SEC-9` is missing `=`"),
        "expected the exact malformed-token detail, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// 5. Expiry date parser: invalid calendar dates never create suppressions.
// ---------------------------------------------------------------------------

#[test]
fn invalid_month_expiry_is_dropped_and_load_errors() {
    // Month 13 is not a valid YYYY-MM-DD; the entry must not load.
    let content = "detector:x ; expires=2026-13-01\n";
    let al = TestApi.allowlist_parse(content);
    assert_eq!(al.ignored_detectors.contains("x"), false);

    let path = temp_ignore("badmonth", content);
    let result = Allowlist::load_with_metadata_policy(&path, false, false, None);
    let _ = std::fs::remove_file(&path);

    let err = result.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(
        msg.contains("missing/invalid expires") && msg.contains("must use YYYY-MM-DD"),
        "malformed expires must be an operator-actionable governance error, got: {msg}"
    );
}

#[test]
fn leap_day_expiry_validity_follows_the_calendar() {
    // 2028 is a leap year => 2028-02-29 is a valid (future) expiry => active.
    let leap_ok = TestApi.allowlist_parse("detector:leap-ok ; expires=2028-02-29\n");
    assert_eq!(leap_ok.ignored_detectors.contains("leap-ok"), true);

    // 2027 is NOT a leap year => 2027-02-29 is an invalid date => dropped.
    let leap_bad = TestApi.allowlist_parse("detector:leap-bad ; expires=2027-02-29\n");
    assert_eq!(leap_bad.ignored_detectors.contains("leap-bad"), false);
}

// ---------------------------------------------------------------------------
// 6. days-since-epoch clock math: exact integers + before-epoch rejection.
// ---------------------------------------------------------------------------

#[test]
fn days_since_epoch_has_exact_integer_boundaries() {
    // Exactly the epoch => day 0.
    assert_eq!(
        TestApi
            .allowlist_days_since_epoch_for_test(SystemTime::UNIX_EPOCH)
            .unwrap(),
        0
    );
    // One second short of a day still floors to day 0 (floor division).
    assert_eq!(
        TestApi
            .allowlist_days_since_epoch_for_test(
                SystemTime::UNIX_EPOCH + Duration::from_secs(86_399)
            )
            .unwrap(),
        0
    );
    // Exactly 86_400s => day 1.
    assert_eq!(
        TestApi
            .allowlist_days_since_epoch_for_test(
                SystemTime::UNIX_EPOCH + Duration::from_secs(86_400)
            )
            .unwrap(),
        1
    );
    // 100 days + a partial day => still day 100.
    assert_eq!(
        TestApi
            .allowlist_days_since_epoch_for_test(
                SystemTime::UNIX_EPOCH + Duration::from_secs(86_400 * 100 + 50_000)
            )
            .unwrap(),
        100
    );
}

#[test]
fn system_clock_before_epoch_is_rejected_with_exact_error() {
    let before = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .expect("a pre-epoch SystemTime must be representable");
    let err = TestApi
        .allowlist_days_since_epoch_for_test(before)
        .unwrap_err();
    assert!(
        err.starts_with("system clock is before UNIX_EPOCH"),
        "expected the before-epoch error prefix, got: {err}"
    );
    assert!(
        err.contains("fix host time before loading allowlist suppressions"),
        "expected the operator remediation hint, got: {err}"
    );

    // A larger negative offset is rejected the same way (not a boundary fluke).
    let much_before = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_secs(86_400))
        .expect("a pre-epoch SystemTime must be representable");
    let err = TestApi
        .allowlist_days_since_epoch_for_test(much_before)
        .unwrap_err();
    assert!(
        err.starts_with("system clock is before UNIX_EPOCH"),
        "expected the before-epoch error prefix, got: {err}"
    );
}
