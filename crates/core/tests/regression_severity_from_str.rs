//! Regression lock for parsing a `Severity` from its string wire forms.
//!
//! `Severity` has **no** `impl FromStr` / no public `parse()`; the operator-
//! facing "parse a severity from text" path is serde deserialization of the
//! `#[serde(rename_all = "kebab-case")]` enum (with the single
//! `#[serde(alias = "client_safe")]` compatibility alias on `ClientSafe`) and
//! the mirror is the public `Display` (`Severity::as_str` is crate-private, so
//! `to_string()` is the importable round-trip anchor). Detector TOMLs and
//! `.keyhogignore.toml` rules carry severities as bare strings, so this suite
//! pins the two wire paths that config actually flows through:
//!   * `toml::from_str` (the real detector / ignore-file deserializer), and
//!   * `serde_json::from_str` for the edge spellings config never legitimately
//!     produces but an attacker/typo can.
//!
//! Scope note: `regression_severity_ordering.rs` owns the JSON serialize +
//! `Ord` + Display-exact contracts; `regression_severity_downgrade_threshold.rs`
//! owns `downgrade_one`; `regression_severity_cmp.rs`/`_filter_label.rs` own the
//! comparison + `--severity`-filter label path. This file's distinct contracts
//! are: the TOML deserializer path, whitespace/empty/type-mismatch *parse*
//! rejection, sequence (severity-list) parsing, the alias→canonical
//! *reserialize* asymmetry, and that the unknown-variant diagnostic advertises
//! the canonical set while hiding the private alias. Every assertion pins a
//! concrete variant, string, or error substring.

use keyhog_core::Severity;

/// Every variant paired with its canonical `kebab-case` wire string. Declared
/// locally because the crate-private `Severity::as_str` table is not importable
/// from an integration test; `Display` is asserted to equal these below.
const CANONICAL: [(Severity, &str); 6] = [
    (Severity::Info, "info"),
    (Severity::ClientSafe, "client-safe"),
    (Severity::Low, "low"),
    (Severity::Medium, "medium"),
    (Severity::High, "high"),
    (Severity::Critical, "critical"),
];

/// Minimal config-shaped carrier: a detector TOML / ignore rule holds a
/// severity as a bare string under a key. This is the exact deserializer path
/// (`toml::from_str` / `serde_json::from_str`) that real config flows through.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Wrap {
    severity: Severity,
}

// ---------------------------------------------------------------------------
// Positive: Display (public as_str mirror) re-parses to the same variant.
// ---------------------------------------------------------------------------

#[test]
fn display_string_reparses_to_same_variant_for_every_spelling() {
    // The task's "round-trip via as_str": render each variant through the
    // public Display, feed that exact text back through the parse path, and
    // require identity. This ties the (crate-private) `as_str` wire form to the
    // deserializer with no reach into private API.
    for (variant, wire) in CANONICAL {
        assert_eq!(
            variant.to_string(),
            wire,
            "Display drifted from canonical wire form for {variant:?}"
        );
        let parsed: Severity = serde_json::from_str(&format!("\"{wire}\""))
            .unwrap_or_else(|e| panic!("canonical spelling {wire:?} must parse, got {e}"));
        assert_eq!(parsed, variant, "{wire:?} parsed to the wrong variant");
    }
}

// ---------------------------------------------------------------------------
// TOML wire path (the real detector / .keyhogignore.toml deserializer).
// ---------------------------------------------------------------------------

#[test]
fn toml_parses_every_canonical_spelling() {
    for (variant, wire) in CANONICAL {
        let doc = format!("severity = \"{wire}\"");
        let wrap: Wrap =
            toml::from_str(&doc).unwrap_or_else(|e| panic!("TOML {doc:?} must parse, got {e}"));
        assert_eq!(wrap.severity, variant, "TOML {wire:?} parsed wrong");
    }
}

#[test]
fn toml_client_safe_snake_alias_equals_kebab() {
    // Old configs wrote the snake_case alias; it must resolve to ClientSafe so
    // an operator's existing ignore rule keeps gating.
    let via_alias: Wrap =
        toml::from_str("severity = \"client_safe\"").expect("snake alias parses in TOML");
    let via_kebab: Wrap =
        toml::from_str("severity = \"client-safe\"").expect("kebab parses in TOML");
    assert_eq!(via_alias.severity, Severity::ClientSafe);
    assert_eq!(via_kebab.severity, Severity::ClientSafe);
    assert_eq!(via_alias.severity, via_kebab.severity);
}

#[test]
fn toml_unknown_variant_fails_closed_and_names_token() {
    // Negative twin: an unknown label is an error (never a silent default to
    // Info/Critical) and the diagnostic names the offending token.
    let err = toml::from_str::<Wrap>("severity = \"warning\"")
        .expect_err("unknown severity must fail closed in TOML");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown variant"),
        "expected unknown-variant, got: {msg}"
    );
    assert!(
        msg.contains("warning"),
        "error should name the bad token, got: {msg}"
    );
}

#[test]
fn toml_capitalized_variant_rejected_case_sensitive() {
    // Adversarial: serde variant matching is case-sensitive on the TOML path
    // too, so a `Debug`-style capitalized identifier must not sneak in.
    let err = toml::from_str::<Wrap>("severity = \"Critical\"")
        .expect_err("capitalized Critical must be rejected in TOML");
    assert!(
        err.to_string().contains("unknown variant"),
        "expected unknown-variant for capitalized form, got: {err}"
    );
}

#[test]
fn toml_reserializes_alias_input_to_canonical_kebab() {
    // Round-trip normalization: text that entered via the snake alias must come
    // back out as the canonical kebab wire form, never `client_safe`, never
    // `ClientSafe`. Pins that serialize goes through the kebab rename, not Debug.
    let wrap: Wrap = toml::from_str("severity = \"client_safe\"").expect("alias parses");
    let out = toml::to_string(&wrap).expect("Wrap serializes to TOML");
    assert_eq!(
        out, "severity = \"client-safe\"\n",
        "TOML reserialize not canonical"
    );
}

// ---------------------------------------------------------------------------
// JSON edge spellings the parse path must reject (config never emits these).
// ---------------------------------------------------------------------------

#[test]
fn whitespace_padded_spelling_is_not_trimmed_and_rejected() {
    // serde does NOT trim before variant matching, so a padded token is a
    // distinct (rejected) string, not `Critical`. (`from_filter_label` trims;
    // the raw deserializer does not — this pins that difference.)
    for bad in ["\" critical \"", "\"critical \"", "\" info\"", "\"low\\t\""] {
        let res = serde_json::from_str::<Severity>(bad);
        assert!(
            res.is_err(),
            "padded token {bad} must be rejected, not trimmed"
        );
        assert!(
            res.unwrap_err().to_string().contains("unknown variant"),
            "padded token {bad} should take the unknown-variant path"
        );
    }
}

#[test]
fn empty_string_is_rejected_as_unknown_variant() {
    let err = serde_json::from_str::<Severity>("\"\"")
        .expect_err("empty string must not parse to a severity");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown variant"),
        "empty string wrong error: {msg}"
    );
}

#[test]
fn mixed_case_client_safe_forms_rejected() {
    // Only exactly `client-safe` (kebab) or `client_safe` (alias) are accepted;
    // any re-cased form is neither and must fail closed.
    for bad in [
        "\"Client-Safe\"",
        "\"CLIENT-SAFE\"",
        "\"Client_Safe\"",
        "\"clientSafe\"",
    ] {
        let res = serde_json::from_str::<Severity>(bad);
        assert!(res.is_err(), "re-cased client-safe {bad} must be rejected");
        assert!(
            res.unwrap_err().to_string().contains("unknown variant"),
            "{bad} should be an unknown-variant error"
        );
    }
}

#[test]
fn non_string_number_takes_type_mismatch_path_not_variant_path() {
    // A JSON number is a *type* mismatch (expected a variant identifier), a
    // categorically different failure from an unknown string variant. Pinning
    // the discriminator guards against a future custom deserializer that would
    // coerce `5` into some default severity.
    let err = serde_json::from_str::<Severity>("5")
        .expect_err("a bare number must not parse to a severity");
    let msg = err.to_string();
    assert!(
        !msg.contains("unknown variant"),
        "number must NOT take the unknown-variant path, got: {msg}"
    );
    assert!(
        msg.contains("invalid type"),
        "expected an invalid-type error, got: {msg}"
    );
}

#[test]
fn non_string_bool_and_null_rejected() {
    for bad in ["true", "null", "false"] {
        let res = serde_json::from_str::<Severity>(bad);
        assert!(
            res.is_err(),
            "non-string JSON {bad} must not parse to a severity"
        );
        let msg = res.unwrap_err().to_string();
        assert!(
            !msg.contains("unknown variant"),
            "{bad} is a type error, not an unknown variant: {msg}"
        );
    }
}

// ---------------------------------------------------------------------------
// Severity-list parsing (a config allowlist of severities).
// ---------------------------------------------------------------------------

#[test]
fn json_sequence_parses_each_element_to_exact_variant() {
    let list: Vec<Severity> =
        serde_json::from_str("[\"info\",\"client-safe\",\"low\",\"critical\"]")
            .expect("severity list parses");
    assert_eq!(
        list,
        vec![
            Severity::Info,
            Severity::ClientSafe,
            Severity::Low,
            Severity::Critical,
        ],
        "severity list parsed to the wrong variants"
    );
}

#[test]
fn json_sequence_with_one_bad_element_fails_whole_parse() {
    // A single unknown element fails the whole sequence closed (no partial /
    // silently-dropped element that would shrink a severity allowlist).
    let err = serde_json::from_str::<Vec<Severity>>("[\"low\",\"nope\",\"high\"]")
        .expect_err("a bad element must fail the whole list");
    assert!(
        err.to_string().contains("unknown variant"),
        "expected unknown-variant naming the bad element, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Unknown-variant diagnostic advertises the canonical set, hides the alias.
// ---------------------------------------------------------------------------

#[test]
fn unknown_variant_error_lists_canonical_forms_but_not_the_alias() {
    let err = serde_json::from_str::<Severity>("\"nope\"").expect_err("unknown token must error");
    let msg = err.to_string();
    // The diagnostic enumerates every canonical kebab form...
    for (_, wire) in CANONICAL {
        assert!(
            msg.contains(wire),
            "unknown-variant error should list canonical form {wire:?}, got: {msg}"
        );
    }
    // ...but the private snake alias is NOT advertised in the expected set.
    assert!(
        !msg.contains("client_safe"),
        "the client_safe alias must stay hidden from the expected list, got: {msg}"
    );
    assert!(
        msg.contains("nope"),
        "error must name the offending token, got: {msg}"
    );
}
