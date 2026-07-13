//! Regression lock for the `Severity` total order and its serde wire form.
//!
//! Severity is the spine of every suppression / gating decision in keyhog:
//! `--hide-client-safe`, `severity_lte` `.keyhogignore.toml` rules, reporter
//! sort order, and diff-aware downgrade all lean on the derived `Ord` matching
//! the *declared* variant sequence
//! (`Info < ClientSafe < Low < Medium < High < Critical`) and on the serde
//! `kebab-case` wire form (`client-safe`, never `clientsafe`, never `Debug`'s
//! `ClientSafe`). If a future edit reorders the enum, drops the
//! `#[serde(alias = "client_safe")]`, or lets `format!("{:?}")` leak into a
//! serialized surface, the ranking silently inverts (over- or under-suppression)
//! and old `.keyhogignore.toml` files parse differently. Every assertion below
//! pins a CONCRETE value: an exact variant, an exact `bool`, an exact quoted
//! JSON string, or an exact error substring.
//!
//! Scope note: this file owns *ordering + parse/serialize + alias + reject*.
//! The one-tier `downgrade_one` ladder and `severity_lte` suppression semantics
//! are pinned separately in `regression_severity_downgrade_threshold.rs`, and
//! full `VerifiedFinding` serde round-trips live in the iter8 finding-serde
//! suite; there is no overlap in the asserted contracts.

use std::cmp::Ordering;

use keyhog_core::Severity;

/// The documented total ordering, lowest rank to highest. Declared locally so
/// the test proves the public `Ord` behaviour without reaching into the
/// crate-private `Severity::ORDERED` table.
const ORDER_LOW_TO_HIGH: [Severity; 6] = [
    Severity::Info,
    Severity::ClientSafe,
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];

/// Each variant paired with its canonical `kebab-case` string. Single source of
/// truth for the display / serialize / deserialize assertions below.
const VARIANT_STRINGS: [(Severity, &str); 6] = [
    (Severity::Info, "info"),
    (Severity::ClientSafe, "client-safe"),
    (Severity::Low, "low"),
    (Severity::Medium, "medium"),
    (Severity::High, "high"),
    (Severity::Critical, "critical"),
];

// ---------------------------------------------------------------------------
// Display / string form
// ---------------------------------------------------------------------------

#[test]
fn display_strings_are_exact_kebab_case() {
    // Positive: every variant renders to its exact wire string; ClientSafe is
    // the one that would regress to `clientsafe` if `Display` ever routed
    // through `{:?}` instead of `as_str`.
    assert_eq!(Severity::Info.to_string(), "info");
    assert_eq!(Severity::ClientSafe.to_string(), "client-safe");
    assert_eq!(Severity::Low.to_string(), "low");
    assert_eq!(Severity::Medium.to_string(), "medium");
    assert_eq!(Severity::High.to_string(), "high");
    assert_eq!(Severity::Critical.to_string(), "critical");
}

#[test]
fn debug_and_display_diverge_only_for_client_safe() {
    // Adversarial guard: `Debug` intentionally keeps the Rust identifier
    // (`ClientSafe`) while `Display` uses the wire form (`client-safe`). This
    // pins that a reporter must use `Display`, never `{:?}`, for ClientSafe.
    assert_eq!(format!("{:?}", Severity::ClientSafe), "ClientSafe");
    assert_ne!(
        format!("{:?}", Severity::ClientSafe),
        Severity::ClientSafe.to_string()
    );
    // For a single-word variant the two coincide (lowercased) except for case.
    assert_eq!(format!("{:?}", Severity::High), "High");
    assert_eq!(Severity::High.to_string(), "high");
}

// ---------------------------------------------------------------------------
// serde serialize
// ---------------------------------------------------------------------------

#[test]
fn serialize_json_is_exact_kebab_case() {
    for (variant, wire) in VARIANT_STRINGS {
        let json = serde_json::to_string(&variant).expect("severity serializes");
        // JSON string is the wire form wrapped in double quotes.
        assert_eq!(
            json,
            format!("\"{wire}\""),
            "variant {variant:?} serialized wrong"
        );
    }
    // Spot-pin the ClientSafe case explicitly so a rename regression names it.
    assert_eq!(
        serde_json::to_string(&Severity::ClientSafe).expect("serializes"),
        "\"client-safe\""
    );
}

// ---------------------------------------------------------------------------
// serde deserialize (parse)
// ---------------------------------------------------------------------------

#[test]
fn deserialize_primary_kebab_forms() {
    for (variant, wire) in VARIANT_STRINGS {
        let parsed: Severity =
            serde_json::from_str(&format!("\"{wire}\"")).expect("primary kebab form parses");
        assert_eq!(parsed, variant, "wire {wire:?} parsed to wrong variant");
    }
}

#[test]
fn deserialize_client_safe_alias_equals_kebab() {
    // The `#[serde(alias = "client_safe")]` snake_case form and the canonical
    // `client-safe` kebab form MUST resolve to the identical variant so old
    // configs keep working.
    let kebab: Severity = serde_json::from_str("\"client-safe\"").expect("kebab parses");
    let snake: Severity = serde_json::from_str("\"client_safe\"").expect("alias parses");
    assert_eq!(kebab, Severity::ClientSafe);
    assert_eq!(snake, Severity::ClientSafe);
    assert_eq!(kebab, snake, "client_safe alias must equal client-safe");
}

#[test]
fn roundtrip_serialize_then_deserialize_is_identity_for_all_variants() {
    for (variant, _) in VARIANT_STRINGS {
        let json = serde_json::to_string(&variant).expect("serializes");
        let back: Severity = serde_json::from_str(&json).expect("re-parses");
        assert_eq!(
            back, variant,
            "round trip drifted for {variant:?} via {json}"
        );
    }
}

#[test]
fn deserialize_unknown_variant_errors_with_named_message() {
    // Negative twin: an unknown label fails closed (an error), and the error is
    // the serde "unknown variant" diagnostic naming the offending token, not a
    // silent default to Info/Critical.
    let err = serde_json::from_str::<Severity>("\"totally-not-a-severity\"").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unknown variant"),
        "expected unknown-variant error, got: {msg}"
    );
    assert!(
        msg.contains("totally-not-a-severity"),
        "error should name the bad token, got: {msg}"
    );
}

#[test]
fn deserialize_is_case_sensitive_capitalized_rejected() {
    // Adversarial: serde variant matching is case-sensitive. The `Debug`-style
    // capitalized identifiers must NOT parse, or a `{:?}`-serialized value would
    // silently round-trip and mask the Display-vs-Debug bug.
    for bad in [
        "\"Critical\"",
        "\"CRITICAL\"",
        "\"Info\"",
        "\"ClientSafe\"",
        "\"High\"",
    ] {
        let res = serde_json::from_str::<Severity>(bad);
        assert!(res.is_err(), "case-variant {bad} must be rejected");
        let msg = res.unwrap_err().to_string();
        assert!(
            msg.contains("unknown variant"),
            "expected unknown-variant for {bad}, got: {msg}"
        );
    }
}

#[test]
fn deserialize_clientsafe_without_separator_rejected() {
    // Only `client-safe` and `client_safe` are accepted; the run-together form
    // is neither the kebab wire form nor the alias, so it must fail closed.
    let res = serde_json::from_str::<Severity>("\"clientsafe\"");
    assert!(res.is_err(), "clientsafe (no separator) must be rejected");
    assert!(res.unwrap_err().to_string().contains("unknown variant"));
}

// ---------------------------------------------------------------------------
// Ordering (derived Ord follows declaration order)
// ---------------------------------------------------------------------------

#[test]
fn critical_is_strictly_highest_info_strictly_lowest() {
    // Critical outranks every other tier.
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::Critical > Severity::Medium);
    assert!(Severity::Critical > Severity::Low);
    assert!(Severity::Critical > Severity::ClientSafe);
    assert!(Severity::Critical > Severity::Info);
    // Info is below every other tier.
    assert!(Severity::Info < Severity::ClientSafe);
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::Info < Severity::Medium);
    assert!(Severity::Info < Severity::High);
    assert!(Severity::Info < Severity::Critical);
}

#[test]
fn client_safe_sits_between_info_and_low() {
    // The bug-bounty tier is the one non-obvious placement: strictly above Info,
    // strictly below Low. This is what makes `--hide-client-safe` render it
    // below `Low` rather than folding it into `Info`.
    assert!(Severity::ClientSafe > Severity::Info);
    assert!(Severity::ClientSafe < Severity::Low);
    assert!(Severity::ClientSafe < Severity::Medium);
    // And it is NOT equal to either neighbour.
    assert_ne!(Severity::ClientSafe, Severity::Info);
    assert_ne!(Severity::ClientSafe, Severity::Low);
}

#[test]
fn adjacent_pairs_are_monotonically_increasing() {
    // Walk the documented order and assert each neighbour is strictly greater
    // than the one before (a full transitive check of the declaration order).
    for window in ORDER_LOW_TO_HIGH.windows(2) {
        let lower = window[0];
        let higher = window[1];
        assert!(lower < higher, "{lower:?} should rank below {higher:?}");
        assert_eq!(lower.cmp(&higher), Ordering::Less);
        assert_eq!(higher.cmp(&lower), Ordering::Greater);
    }
}

#[test]
fn sorting_shuffled_vec_yields_declaration_order() {
    let mut shuffled = vec![
        Severity::High,
        Severity::Info,
        Severity::Critical,
        Severity::ClientSafe,
        Severity::Medium,
        Severity::Low,
    ];
    shuffled.sort();
    assert_eq!(
        shuffled,
        ORDER_LOW_TO_HIGH.to_vec(),
        "sort must produce low..=high order"
    );
}

#[test]
fn cmp_max_and_min_pick_expected_tiers() {
    assert_eq!(
        std::cmp::max(Severity::Low, Severity::Critical),
        Severity::Critical
    );
    assert_eq!(
        std::cmp::min(Severity::Low, Severity::Critical),
        Severity::Low
    );
    assert_eq!(
        std::cmp::max(Severity::ClientSafe, Severity::Info),
        Severity::ClientSafe
    );
    assert_eq!(
        std::cmp::min(Severity::High, Severity::Medium),
        Severity::Medium
    );
    // Equal inputs: max/min return the (equal) value.
    assert_eq!(
        std::cmp::max(Severity::High, Severity::High),
        Severity::High
    );
}

#[test]
fn partial_cmp_reports_exact_orderings() {
    assert_eq!(
        Severity::High.partial_cmp(&Severity::Low),
        Some(Ordering::Greater)
    );
    assert_eq!(
        Severity::Low.partial_cmp(&Severity::High),
        Some(Ordering::Less)
    );
    assert_eq!(
        Severity::Medium.partial_cmp(&Severity::Medium),
        Some(Ordering::Equal)
    );
    assert_eq!(
        Severity::ClientSafe.partial_cmp(&Severity::Info),
        Some(Ordering::Greater)
    );
}

// ---------------------------------------------------------------------------
// Default / Copy / Eq semantics
// ---------------------------------------------------------------------------

#[test]
fn default_severity_is_info() {
    // The `#[default]` attribute is on `Info`; a drift here would change the
    // implicit severity of any spec/finding that omits the field.
    assert_eq!(Severity::default(), Severity::Info);
    assert_eq!(Severity::default().to_string(), "info");
}

#[test]
fn copy_and_eq_semantics_hold() {
    // `Severity` is `Copy`: assigning does not move, so the source stays usable.
    let source = Severity::High;
    let copy = source;
    assert_eq!(
        source,
        Severity::High,
        "source still usable after copy (Copy, not move)"
    );
    assert_eq!(copy, Severity::High);
    assert_eq!(source, copy);
    // Distinct variants are unequal.
    assert_ne!(Severity::High, Severity::Critical);
    assert_ne!(Severity::Info, Severity::ClientSafe);
}
