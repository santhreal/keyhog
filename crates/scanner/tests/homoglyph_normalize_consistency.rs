//! Cross-map consistency gate: the AC/regex-expand homoglyph map
//! (`homoglyph::homoglyph_map`) and the normalize-path folds
//! (`unicode_hardening::{cyrillic_to_latin, greek_to_latin, fullwidth_to_ascii}`)
//! are TWO independent scan paths. If they disagree on a shared codepoint, one
//! path catches an evasion the other misses — a silent recall/precision split
//! (the `С`-under-`S` vs `С`→`C` class, backlog DR-317). This gate walks every
//! Cyrillic/Greek/fullwidth glyph in the expand map and asserts the normalize
//! fold agrees, so any NEW drift fails loudly. The currently-known divergences
//! (DR-317) are enumerated explicitly as a shrinking ratchet: each is asserted
//! to still hold, so when DR-317 reconciles a pair this test forces the waiver
//! list to shrink in lockstep instead of silently masking the fix.

use keyhog_scanner::testing::unicode_hardening::{
    cyrillic_to_latin, fullwidth_to_ascii, greek_to_latin, homoglyph_confusables,
};

/// The normalize-path fold for a single confusable glyph, trying each fold
/// owner in turn. `None` means no normalize path recognizes the glyph — a
/// recall hole relative to the expand map, which DID list it.
fn normalize_fold(glyph: char) -> Option<char> {
    if let Some(c) = cyrillic_to_latin(glyph) {
        return Some(c);
    }
    if let Some(c) = greek_to_latin(glyph) {
        return Some(c);
    }
    // Fullwidth forms of printable ASCII (U+FF01..=U+FF5E) fold via the arithmetic
    // `- 0xFEE0` twin, not the Cyrillic/Greek tables.
    if ('\u{FF01}'..='\u{FF5E}').contains(&glyph) {
        return Some(fullwidth_to_ascii(glyph));
    }
    None
}

/// The known, backlog-tracked divergences (DR-317): `(glyph, expand_map_ascii_key,
/// current_normalize_fold)`. A naive reconciliation (moving `С`→`C`, `ν`→`v`, adding
/// `Ь`/`н`/`п`/`м` folds + `w`/`Z` expand keys) was ATTEMPTED and BENCH-REJECTED
/// (2026-07-04): the mirror corpus precision collapsed 0.9945→0.7465 (+918 false
/// positives) because expanding the homoglyph AC map for common ASCII letters
/// over-matches on diverse text. So the divergence stays (tracked, guarded here),
/// and a precision-preserving reconciliation (e.g. length/entropy-gated homoglyph
/// expansion) is the real fix — NOT a bare map merge. See backlog DR-317.
const KNOWN_DIVERGENCES: &[(char, char, Option<char>)] = &[
    ('\u{0421}', 'S', Some('C')), // DR-317a: Cyrillic Es visually IS `C`; expand map lists it under `S`.
    ('\u{03BD}', 'n', Some('v')), // DR-317b: Greek nu visually IS `v`; expand map lists it under `n`.
    ('\u{042C}', 'b', None),      // DR-317c: Ь absent from cyrillic_to_latin.
    ('\u{043D}', 'h', None),      // DR-317c: н absent.
    ('\u{043F}', 'n', None),      // DR-317c: п absent.
    ('\u{043C}', 'm', None),      // DR-317c: м absent.
];

/// True for the intentional, documented `l`/`i`/`I`/`1` confusable cluster: the
/// expand map lists `і`/`І`/`ι`/`Ι` under `l` (they are all vertical-stroke
/// lookalikes), while the normalize path folds them to `i`/`I`. This is a
/// deliberate cross-cluster mapping, not drift (see `homoglyph.rs` `'l'` comment).
fn is_l_cluster(ascii_key: char, fold: Option<char>) -> bool {
    ascii_key == 'l' && matches!(fold, Some('i') | Some('I'))
}

#[test]
fn expand_map_agrees_with_normalize_folds_on_every_shared_glyph() {
    let mut unexpected: Vec<String> = Vec::new();

    for (ascii_key, glyphs) in homoglyph_confusables() {
        for glyph in glyphs {
            if glyph.is_ascii() {
                continue; // trivially folds to itself
            }
            let fold = normalize_fold(glyph);

            if fold == Some(ascii_key) || is_l_cluster(ascii_key, fold) {
                continue; // agrees
            }
            if KNOWN_DIVERGENCES.contains(&(glyph, ascii_key, fold)) {
                continue; // tracked DR-317 divergence, allowed until reconciled
            }
            unexpected.push(format!(
                "U+{:04X} listed under expand key '{}' folds to {:?} on the normalize path \
                 (expected Some('{}')) — new homoglyph-map drift, reconcile both maps + backlog",
                glyph as u32, ascii_key, fold, ascii_key
            ));
        }
    }

    assert!(
        unexpected.is_empty(),
        "homoglyph expand map and normalize folds disagree on {} glyph(s):\n{}",
        unexpected.len(),
        unexpected.join("\n")
    );
}

#[test]
fn known_divergences_are_still_present_ratchet() {
    // If any DR-317 divergence has been reconciled, the glyph now agrees and this
    // stale waiver must be removed. Failing here is the SIGNAL to shrink the list.
    let confusables = homoglyph_confusables();
    for &(glyph, ascii_key, expected_fold) in KNOWN_DIVERGENCES {
        let listed_under_key = confusables
            .iter()
            .any(|(k, glyphs)| *k == ascii_key && glyphs.contains(&glyph));
        assert!(
            listed_under_key,
            "DR-317 waiver stale: U+{:04X} is no longer listed under expand key '{}' — \
             the map was reconciled; remove this entry from KNOWN_DIVERGENCES",
            glyph as u32, ascii_key
        );
        assert_eq!(
            normalize_fold(glyph),
            expected_fold,
            "DR-317 waiver stale: U+{:04X} now folds differently on the normalize path — \
             reconciled or drifted; update/remove this KNOWN_DIVERGENCES entry",
            glyph as u32
        );
    }
}
