//! Boundary + adversarial coverage for the shared `resolve_value_shaped_group`
//! variable-name -> value-shaped-sibling heuristic.
//!
//! `value_shaped_group_shared_heuristic.rs` pins the four canonical behaviours
//! (fall back, leave-unchanged, short-sibling-kept, <=2-groups-short-circuit).
//! This file pins the EDGES that a future tweak could silently slide across 
//! each one a recall/precision drift hazard because the heuristic is shared by
//! the whole-chunk walk (`extract_grouped_matches`) and the phase-2 anchored
//! path (`extract_anchored`), so a boundary that moves in one definition moves
//! in both at once and is invisible at scan time.
//!
//! The two definitions under exercise (`scan_filters.rs`):
//!   * `looks_like_variable_name(s)`: `true` iff `s` is non-empty, `<= 64`
//!     bytes, and every byte is `[A-Za-z0-9_]`. (So an empty group, a `> 64`
//!     byte group, or any non-ASCII / punctuation byte makes it value-shaped.)
//!   * a sibling qualifies as the replacement iff it PARTICIPATED in the match,
//!     is NOT variable-name shaped, and is `>= 8` bytes; the FIRST such sibling
//!     by ascending capture-group index wins (early return).
//!
//! Every test drives a real compiled regex through the shared test seam and
//! asserts the EXACT resolved bytes (Law 6 (real values, never `is_some`)).

use keyhog_scanner::testing::resolve_value_shaped_group_for_test as resolve;

/// Resolve `group` of `pattern` over `text` and return the exact resolved slice.
fn resolved_slice<'t>(pattern: &str, text: &'t str, group: usize) -> &'t str {
    let (s, e) = resolve(pattern, text, group).expect("pattern must match the text");
    &text[s..e]
}

// ── sibling length boundary: `>= 8` ─────────────────────────────────────────

#[test]
fn sibling_exactly_8_bytes_qualifies() {
    // "ab-cdefg" is 8 bytes and contains '-' (not variable-name shaped). 8 is
    // the inclusive floor, so it must be picked over the variable-name group 1.
    let text = "name=val key=ab-cdefg";
    let pattern = r"(\w+)=\w+ \w+=([\w-]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "ab-cdefg");
}

#[test]
fn sibling_exactly_7_bytes_is_rejected_and_original_group_kept() {
    // "ab-cdef" is 7 bytes, one below the floor, so it does NOT qualify and
    // the original variable-name group is returned unchanged.
    let text = "name=val key=ab-cdef";
    let pattern = r"(\w+)=\w+ \w+=([\w-]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "name");
}

// ── variable-name length boundary: `<= 64` ──────────────────────────────────

#[test]
fn configured_group_of_exactly_64_word_bytes_is_a_name_so_heuristic_engages() {
    // 64 word bytes is the inclusive ceiling for "variable-name shaped", so the
    // heuristic engages and falls back to the value-shaped sibling.
    let name64 = "a".repeat(64);
    let text = format!("{name64}=val key=value-shaped-token");
    let pattern = r"(\w+)=\w+ \w+=([\w-]+)";
    assert_eq!(resolved_slice(pattern, &text, 1), "value-shaped-token");
}

#[test]
fn configured_group_of_65_word_bytes_is_value_shaped_so_left_unchanged() {
    // 65 word bytes exceeds the ceiling -> NOT variable-name shaped -> the group
    // is already treated as the value and returned unchanged, sibling ignored.
    let name65 = "a".repeat(65);
    let text = format!("{name65}=val key=value-shaped-token");
    let pattern = r"(\w+)=\w+ \w+=([\w-]+)";
    assert_eq!(resolved_slice(pattern, &text, 1), name65);
}

// ── configured-group self-skip (`g == group`) ───────────────────────────────

#[test]
fn configured_group_two_skips_itself_and_resolves_lower_indexed_sibling() {
    // The configured group is index 2 (a variable name); the loop must skip
    // g==2 and find the value-shaped sibling at the LOWER index 1.
    let text = "sk-abcdefgh varname=plainword";
    let pattern = r"([\w-]+) \w+=(\w+)";
    assert_eq!(resolved_slice(pattern, text, 2), "sk-abcdefgh");
}

#[test]
fn configured_group_two_with_no_qualifying_sibling_keeps_group_two() {
    // Configured group 2 is a variable name; the only sibling (group 1) is also
    // pure-word (rejected), so group 2's exact bytes are kept.
    let text = "plainone plaintwo";
    let pattern = r"(\w+) (\w+)";
    assert_eq!(resolved_slice(pattern, text, 2), "plaintwo");
}

// ── sibling selection order (first qualifying by index, early return) ────────

#[test]
fn first_value_shaped_sibling_by_index_wins_even_when_a_later_one_is_longer() {
    // Both group 2 and group 3 qualify; the lower index must win, proving the
    // selection is first-by-index, not longest / last.
    let text = "name a-shortone b-longer-token-here";
    let pattern = r"(\w+) (a[\w-]+) (b[\w-]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "a-shortone");
}

#[test]
fn skips_too_short_then_pure_word_then_picks_the_value_shaped_sibling() {
    // Exercises all three rejection branches in sequence before a hit:
    //   g2 "a-bcd"  -> non-word but only 5 bytes (too short)
    //   g3 "plainword" -> >= 8 bytes but pure word (variable-name shaped)
    //   g4 "x-qualifying-token" -> non-word AND >= 8 -> picked.
    let text = "name a-bcd plainword x-qualifying-token";
    let pattern = r"(\w+) (a[\w-]+) (\w+) (x[\w-]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "x-qualifying-token");
}

#[test]
fn qualifying_sibling_at_the_last_group_index_is_found() {
    // Only the highest-index sibling qualifies; the intervening pure-word
    // siblings must all be skipped.
    let text = "name aaaa bbbb x-final-token";
    let pattern = r"(\w+) (\w+) (\w+) (x[\w-]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "x-final-token");
}

// ── non-participating optional sibling is skipped without panic ──────────────

#[test]
fn non_participating_optional_group_is_skipped_and_later_sibling_found() {
    // Group 2 `(zzz)?` does not participate (locs.get(2) == None); the scan must
    // skip the None without panicking and resolve the participating group 3.
    let text = "name x/qualifies/here";
    let pattern = r"(\w+)(zzz)? (x[\w/]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "x/qualifies/here");
}

// ── pure-word sibling never qualifies (must contain a non-word byte) ─────────

#[test]
fn long_pure_word_sibling_does_not_qualify_so_original_group_kept() {
    // "plainwordvalue" is 14 bytes but all word bytes -> variable-name shaped ->
    // not a value-shaped candidate -> original variable-name group kept.
    let text = "name=val key=plainwordvalue";
    let pattern = r"(\w+)=\w+ \w+=(\w+)";
    assert_eq!(resolved_slice(pattern, text, 1), "name");
}

#[test]
fn no_qualifying_sibling_returns_the_exact_original_group_bytes() {
    // A short non-word sibling and a pure-word sibling both fail; the original
    // group's EXACT bytes come back (not merely "unchanged").
    let text = "name a-short plainword";
    let pattern = r"(\w+) (a[\w-]+) (\w+)";
    assert_eq!(resolved_slice(pattern, text, 1), "name");
}

// ── groups_total boundary (the `<= 2` short-circuit) ─────────────────────────

#[test]
fn exactly_three_total_groups_runs_the_sibling_scan() {
    // Two explicit groups -> groups_total == 3, one above the `<= 2`
    // short-circuit, so the sibling scan runs and resolves group 2.
    let text = "name=val key=sib-token-x";
    let pattern = r"(\w+)=\w+ \w+=([\w-]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "sib-token-x");
}

#[test]
fn exactly_two_total_groups_short_circuits_even_for_a_variable_name_group() {
    // One explicit group -> groups_total == 2, so the heuristic short-circuits
    // and returns the variable-name group untouched even though a secret value
    // (`\S+`) clearly follows.
    let text = "username=sk-secret-value";
    let pattern = r"(\w+)=\S+";
    assert_eq!(resolved_slice(pattern, text, 1), "username");
}

// ── empty / zero-width configured group ──────────────────────────────────────

#[test]
fn empty_configured_group_is_value_shaped_and_returned_without_panic() {
    // `(\w*)` matches zero-width before '='. An empty string is NOT
    // variable-name shaped, so the heuristic returns the (empty) current range
    // unchanged (and must not panic re-slicing it).
    let text = "=sk-secret-value";
    let pattern = r"(\w*)=(\S+)";
    let (s, e) = resolve(pattern, text, 1).expect("pattern must match");
    assert_eq!(s, e, "the zero-width group must resolve to an empty range");
    assert_eq!(&text[s..e], "");
}

// ── unicode / multibyte safety ───────────────────────────────────────────────

#[test]
fn multibyte_sibling_qualifies_and_re_slices_on_a_char_boundary() {
    // "café-token" carries a 2-byte 'é' (so NOT variable-name shaped) and is 11
    // bytes (>= 8), so it qualifies. The exact-bytes assertion also pins that
    // the resolved range lands on UTF-8 char boundaries (a bad range panics).
    let text = "name=val key=café-token";
    let pattern = r"(\w+)=\w+ \w+=([\w-]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "café-token");
}

#[test]
fn multibyte_configured_group_is_value_shaped_and_short_circuits() {
    // The configured group "café" has a non-ASCII byte -> NOT variable-name
    // shaped -> the heuristic returns it unchanged without scanning siblings.
    let text = "café=val key=plain-sibling-here";
    let pattern = r"(\w+)=\w+ \w+=([\w-]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "café");
}

// ── configured-group character classes that ARE variable-name shaped ─────────

#[test]
fn digit_only_configured_group_is_a_name_so_heuristic_engages() {
    // "12345678" is all ASCII alphanumerics -> variable-name shaped -> engages.
    let text = "12345678=val key=value-shaped-x";
    let pattern = r"(\w+)=\w+ \w+=([\w-]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "value-shaped-x");
}

#[test]
fn underscore_and_digit_name_is_variable_name_shaped() {
    // "api_key_v2" mixes letters, digits and underscores, all in the
    // [A-Za-z0-9_] set (so it is variable-name shaped and the heuristic engages).
    let text = "api_key_v2=val key=resolved-value-x";
    let pattern = r"(\w+)=\w+ \w+=([\w-]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "resolved-value-x");
}

#[test]
fn uppercase_env_style_name_with_digits_and_underscores_engages() {
    // A realistic env-var name "VAR_2024_KEY" is variable-name shaped.
    let text = "VAR_2024_KEY=val key=resolved-secret-x";
    let pattern = r"(\w+)=\w+ \w+=([\w-]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "resolved-secret-x");
}

// ── value-shaped via different non-word bytes ────────────────────────────────

#[test]
fn dot_separated_sibling_qualifies() {
    // '.' is a non-word byte, so "ver.1.2.3.x" (11 bytes) is value-shaped.
    let text = "name=val key=ver.1.2.3.x";
    let pattern = r"(\w+)=\w+ \w+=([\w.]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "ver.1.2.3.x");
}

#[test]
fn slash_path_sibling_qualifies() {
    // '/' is a non-word byte, so "a/b/c/d/ee" (10 bytes) is value-shaped.
    let text = "name=val key=a/b/c/d/ee";
    let pattern = r"(\w+)=\w+ \w+=([\w/]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "a/b/c/d/ee");
}

#[test]
fn plus_containing_sibling_qualifies() {
    // '+' (base64-ish) is a non-word byte, so "ab+cd+efgh" (10 bytes) qualifies.
    let text = "name=val key=ab+cd+efgh";
    let pattern = r"(\w+)=\w+ \w+=([\w+]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "ab+cd+efgh");
}

#[test]
fn trailing_hyphen_sibling_at_floor_length_qualifies() {
    // "token123-" is 9 bytes with a single trailing '-': value-shaped and at the
    // length floor, so it is picked over the variable-name group.
    let text = "name=val key=token123-";
    let pattern = r"(\w+)=\w+ \w+=([\w-]+)";
    assert_eq!(resolved_slice(pattern, text, 1), "token123-");
}
