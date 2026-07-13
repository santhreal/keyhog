//! Detector-owned generic-keyword bridge (`engine/phase2_generic.rs`), reached via the
//! `keyhog_scanner::testing` facade. Migrated from an inline `#[cfg(test)]` block
//! to satisfy the `engine_phase2_generic_no_inline_tests` +
//! `engine_phase2_generic_no_unwrap_expect` gates (the inline block's helper
//! unwrap/expect were test-body, cleared by moving the whole block out).

use keyhog_scanner::testing::{
    assignment_keywords_for_test as assignment_keywords, build_generic_re_for_test,
    compile_generic_re_for_test, force_generic_re, generic_keyword_alternation_for_test,
    generic_re_vendor_suffix_arm, is_strong_keyword_anchored_encoded_text_secret_for_test,
};
use std::collections::BTreeSet;

/// Recover the literal keyword set that group-1's alternation is built from by
/// stripping the appended vendor arm and un-escaping each alternative. The only
/// escaped characters our vocabulary can contain are the regex-meta separators
/// (`.`/`-`), each escaped as a single `\<char>`, so removing every backslash
/// reconstructs the original keyword exactly.
fn alternation_keyword_set() -> BTreeSet<String> {
    let alternation = generic_keyword_alternation_for_test();
    let literals = alternation
        .strip_suffix(&format!("|{}", generic_re_vendor_suffix_arm()))
        .expect("the vendor structural arm is appended last");
    literals
        .split('|')
        .map(|escaped| escaped.replace('\\', ""))
        .collect()
}

// ── DEDUP LOCK: the alternation's keyword set IS the derived vocab ──────

#[test]
fn generic_re_keyword_set_equals_the_derived_vocabulary() {
    // ONE HOME: the group-1 literal alternation is exactly the derived
    // assignment-keyword vocabulary, no more, no less. A second hand-kept
    // keyword list (or a dropped keyword) makes these sets diverge.
    let from_regex = alternation_keyword_set();
    let derived: BTreeSet<String> = assignment_keywords().iter().cloned().collect();
    assert_eq!(
        from_regex, derived,
        "GENERIC_RE keyword alternation diverged from the derived vocabulary"
    );
    // The set is non-trivial, pin a real lower bound so the equality is not
    // vacuously comparing two empty sets.
    assert!(
        derived.len() >= 40,
        "expected the full derived vocab (>=40 spellings), got {}",
        derived.len()
    );
}

#[test]
fn every_derived_keyword_that_appears_in_the_alternation_is_a_real_vocab_entry() {
    // The reverse containment, asserted independently of the set-equality
    // test: nothing in the alternation is a stray literal absent from the vocab.
    let derived: BTreeSet<&str> = assignment_keywords().iter().map(String::as_str).collect();
    for keyword in alternation_keyword_set() {
        assert!(
            derived.contains(keyword.as_str()),
            "alternation carries a keyword `{keyword}` not present in the derived vocab"
        );
    }
}

// ── every derived keyword actually fires and captures the value ─────────

#[test]
fn every_derived_keyword_captures_its_assigned_value() {
    let re = build_generic_re_for_test().expect("GENERIC_RE compiles from the derived vocab");
    // A concrete high-entropy value from the group-2 charset, 16 chars.
    let value = "Xh8Kd93mZq0Lp2Rt";
    for keyword in assignment_keywords() {
        let line = format!("{keyword}={value}");
        let caps = re
            .captures(&line)
            .unwrap_or_else(|| panic!("keyword `{keyword}` failed to bridge line `{line}`"));
        // Group 1 is the keyword (case-insensitively equal, separators intact).
        assert_eq!(
            caps.get(1).unwrap().as_str().to_ascii_lowercase(),
            keyword.to_ascii_lowercase(),
            "keyword capture mismatch for `{keyword}`"
        );
        // Group 2 is the exact value (a real-value assertion, not !is_empty).
        assert_eq!(
            caps.get(2).unwrap().as_str(),
            value,
            "value capture mismatch for `{keyword}`"
        );
    }
}

#[test]
fn shipped_detector_ceiling_captures_long_values_whole_without_prefix_truncation() {
    let re = build_generic_re_for_test().expect("detector-owned generic bridge compiles");
    let long_value = "aB3dE5fG7hJ9kL2m".repeat(16);
    assert_eq!(long_value.len(), 256);
    let line = format!("api_key={long_value}");
    let captures = re
        .captures(&line)
        .expect("the shipped 512-byte API-key ceiling admits a 256-byte value");
    assert_eq!(captures.get(2).expect("value capture").as_str(), long_value);

    let over = "a".repeat(513);
    assert!(
        re.captures(&format!("api_key={over}")).is_none(),
        "an over-ceiling token must not yield a truncated 512-byte prefix"
    );
}

#[test]
fn vendor_prefixed_key_bridges_via_the_structural_arm() {
    let re = build_generic_re_for_test().unwrap();
    // `stripe_publishable_key` is NOT a derived vocab literal, but the vendor
    // arm (`<vendor>_key`) still admits it (proving the arm survived the move).
    let caps = re
        .captures("stripe_publishable_key = Xh8Kd93mZq0Lp2Rt")
        .expect("vendor-prefixed *_key must bridge via the structural arm");
    assert_eq!(caps.get(1).unwrap().as_str(), "stripe_publishable_key");
    assert_eq!(caps.get(2).unwrap().as_str(), "Xh8Kd93mZq0Lp2Rt");
}

#[test]
fn multi_segment_vendor_secret_captures_the_complete_key_and_padded_value() {
    let re = build_generic_re_for_test().expect("GENERIC_RE compiles");
    let value = "Y2FsaWNvLW9uLWt1YmUtYXV0aC1rZXk=";
    let line = format!("K8S_FULL_SECRET=\"{value}\"");
    let caps = re
        .captures(&line)
        .expect("vendor-prefixed *_secret must bridge");
    assert_eq!(
        caps.get(1).expect("keyword capture").as_str(),
        "K8S_FULL_SECRET"
    );
    assert_eq!(caps.get(2).expect("value capture").as_str(), value);
    assert!(is_strong_keyword_anchored_encoded_text_secret_for_test(
        caps.get(1).expect("keyword capture").as_str(),
        caps.get(2).expect("value capture").as_str(),
    ));
}

#[test]
fn a_non_keyword_assignment_does_not_bridge() {
    // Adversarial twin: a value-shaped assignment with NO credential keyword
    // must not match, or the generic bridge would fire on ordinary config.
    let re = build_generic_re_for_test().unwrap();
    assert!(
        re.captures("hostname = Xh8Kd93mZq0Lp2Rt").is_none(),
        "a non-credential key must not bridge"
    );
}

// ── FAIL CLOSED: a broken pattern is a hard error, never a silent Ok ────

#[test]
fn real_vocabulary_and_detector_ceiling_compile_fail_closed() {
    // The shipped vocabulary and detector-owned ceiling compile.
    force_generic_re();
    assert!(build_generic_re_for_test().is_ok());
}

#[test]
fn a_malformed_alternation_fails_compilation_so_the_lazylock_panics_closed() {
    // Encodes the LAW-10 fail-closed contract: an invalid group-1 alternation
    // is a hard compile error (which the LazyLock turns into a panic), never a
    // silent `Ok` with a disabled bridge. `(?P<` is an unterminated group.
    assert!(compile_generic_re_for_test("(?P<broken").is_err());
    // And a valid alternation still yields a usable regex, the Err branch is
    // reachable only on genuinely broken input.
    assert!(compile_generic_re_for_test("secret").is_ok());
}
