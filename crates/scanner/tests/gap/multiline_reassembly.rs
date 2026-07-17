//! Integration tests for the multiline fragment-reassembly path.
//!
//! Source under test:
//!   * `crates/scanner/src/multiline/preprocessor.rs`  (`preprocess_multiline`,
//!     `process_line_chain`, `extract_string_part`, `extract_quoted_content`,
//!     `extract_plus_concatenation`, `extract_python_implicit_concatenation`,
//!     `extract_function_concatenation`, `extract_template_literal_continuation`,
//!     `filter_line_content`)
//!   * `crates/scanner/src/multiline/config.rs`        (`should_passthrough`,
//!     `has_concatenation_indicators`, `PreprocessedText::line_for_offset`,
//!     `PreprocessedText::passthrough`, `MultilineConfig::default`,
//!     `MAX_MULTILINE_PREPROCESS_BYTES`, `MAX_MULTILINE_LINE_BYTES`)
//!   * `crates/scanner/src/multiline/structural.rs`    (`collect_structural_fragments`,
//!     `resolve_concat_reference`, `resolve_template_reference`,
//!     `join_inline_array_strings`)
//!   * `crates/scanner/src/fragment_cache.rs` (`FragmentCache`,
//!     same-file join, cross-file no-join, anchor path+line)
//!
//! Every expected value here is derived by tracing the real source, not guessed.
//! The test surface used is `keyhog_scanner::testing::multiline::*` and
//! `keyhog_scanner::testing::fragment_cache::*`.

#[cfg(feature = "simd")]
use keyhog_scanner::testing::fragment_cache::ReassembledCandidate;
use keyhog_scanner::testing::fragment_cache::{FragmentCache, SecretFragment};
use keyhog_scanner::testing::multiline::{
    preprocess_multiline, LineMapping, MultilineConfig, PreprocessedText,
};
use std::sync::Arc;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cfg() -> MultilineConfig {
    MultilineConfig::default()
}

fn pre(text: &str) -> PreprocessedText<'_> {
    preprocess_multiline(
        std::borrow::Cow::Borrowed(text),
        &cfg(),
        &FragmentCache::new(100),
    )
}

fn frag(prefix: &str, var: &str, value: &str, line: usize, path: Option<&str>) -> SecretFragment {
    SecretFragment {
        prefix: prefix.to_string(),
        var_name: var.to_string(),
        value: Zeroizing::new(value.to_string()),
        line,
        path: path.map(Arc::from),
    }
}

// ---------------------------------------------------------------------------
// MultilineConfig defaults (config.rs Default impl)
// ---------------------------------------------------------------------------

#[test]
fn default_config_values_match_source() {
    let c = MultilineConfig::default();
    assert_eq!(c.max_join_lines, 64);
    assert!(c.python_implicit);
    assert!(c.backslash_continuation);
    assert!(c.plus_concatenation);
    assert!(c.dot_concatenation);
    assert!(c.template_literals);
}

// ---------------------------------------------------------------------------
// Passthrough: no concatenation indicators -> text returned verbatim
// ---------------------------------------------------------------------------

#[test]
fn plain_text_passthrough_returns_input_verbatim() {
    // No "+", no backslash, no backtick, no implicit "x" "y", no var-ref concat.
    let text = "just plain text here\nanother ordinary line\n";
    let p = pre(text);
    assert_eq!(p.text, text);
    assert_eq!(p.original_end, text.len());
}

#[test]
fn passthrough_single_line_offset_maps_to_line_one() {
    // `passthrough_text` uses the shared identity mapping owner. For
    // "abcdefghij" len 10 -> mapping {0,10,line 1}.
    let text = "abcdefghij";
    let p = pre(text);
    assert_eq!(p.mappings.len(), 1);
    assert_eq!(p.mappings[0].line_number, 1);
    assert_eq!(p.mappings[0].start_offset, 0);
    assert_eq!(p.mappings[0].end_offset, 10);
    assert_eq!(p.line_for_offset(0), Some(1));
    assert_eq!(p.line_for_offset(9), Some(1));
    // end_offset is exclusive -> offset 10 falls past the (only) mapping window.
    assert_eq!(p.line_for_offset(10), None);
}

#[test]
fn passthrough_multiline_offsets_include_the_newline_byte() {
    // `passthrough_text`: for each non-final line, mapping is
    // [offset, offset+len+1), so the newline byte stays attached to the
    // preceding source line.
    let text = "abc\ndefgh"; // line1 "abc"(0..3), '\n'@3, line2 "defgh"(4..9)
    let p = pre(text);
    assert_eq!(p.mappings.len(), 2);
    assert_eq!(p.mappings[0].start_offset, 0);
    assert_eq!(p.mappings[0].end_offset, 4);
    assert_eq!(p.mappings[0].line_number, 1);
    assert_eq!(p.mappings[1].start_offset, 4);
    assert_eq!(p.mappings[1].end_offset, 9);
    assert_eq!(p.mappings[1].line_number, 2);
    assert_eq!(p.line_for_offset(0), Some(1));
    assert_eq!(p.line_for_offset(2), Some(1));
    assert_eq!(p.line_for_offset(3), Some(1));
    assert_eq!(p.line_for_offset(4), Some(2));
    assert_eq!(p.line_for_offset(8), Some(2));
}

#[test]
fn brace_prefixed_invalid_json_concat_is_preprocessed_valid_json_passes_through() {
    // The old blanket leading-`{`/`[` reject was REMOVED (Law 10: it silently
    // dropped the entire multiline surface of a JS/TS module that opens with an
    // object literal but carries a concatenated secret, e.g.
    // `{ apiKey: "gh" +\n "p_…" }`). A `{`-prefixed buffer with a concat shape
    // that does NOT parse as strict JSON is JS/TS source and is now PREPROCESSED
    // (its string literals joined and appended for scanning) instead of skipped.
    // The exact join form is a preprocessor artifact, what this pins is that the
    // buffer is no longer passed through unchanged.
    let js = "{ \"a\": \"x\" + \"y\" }\n";
    let p = pre(js);
    assert_ne!(
        p.text, js,
        "invalid-JSON braces with a concat must be preprocessed, not passed through"
    );
    assert!(p.text.starts_with(js), "original bytes preserved as prefix");
    assert_eq!(p.original_end, js.len());

    // A `{`-prefixed buffer that DOES parse as strict JSON is genuine data with
    // no recoverable concat surface (the `" +` shape lived inside a quoted,
    // escaped value), so the strict-JSON disambiguation keeps it a passthrough.
    let json = "{ \"a\": \"x\\\" + \\\"y\" }\n";
    let pj = pre(json);
    assert_eq!(pj.text, json, "valid JSON data must pass through unchanged");
}

#[test]
fn passthrough_xml_and_angle_prefixed_text() {
    // trimmed starts with '<' or "<?xml" -> not an indicator.
    let xml = "<?xml version=\"1.0\"?>\n<root>\"a\" + \"b\"</root>\n";
    let p = pre(xml);
    assert_eq!(p.text, xml);
    let html = "<div>token = \"AKIA\" + \"REST\"</div>\n";
    let p2 = pre(html);
    assert_eq!(p2.text, html);
}

#[test]
fn empty_input_passthrough() {
    // should_passthrough -> has_concatenation_indicators("") false -> passthrough.
    let p = pre("");
    assert_eq!(p.text, "");
    assert_eq!(p.original_end, 0);
    assert!(p.mappings.is_empty());
}

#[test]
fn oversized_line_forces_passthrough() {
    // A single line longer than MAX_MULTILINE_LINE_BYTES (64 KiB) forces
    // passthrough even though it carries a concatenation indicator.
    let huge = "x".repeat(64 * 1024 + 1);
    let text = format!("key = \"{huge}\" + \"tail\"\n");
    let p = pre(&text);
    // passthrough_text returns the input verbatim (no appended join).
    assert_eq!(p.text, text);
    assert_eq!(p.original_end, text.len());
}

// ---------------------------------------------------------------------------
// Same-line / same-chunk plus (+) concatenation join
// ---------------------------------------------------------------------------

#[test]
fn plus_concat_join_across_two_lines_appends_reassembled_secret() {
    // line0 ends with '+', continues; line1 is the tail literal.
    let text = "key = \"AKIA\" +\n\"IOSFODNN7\"\n";
    let p = pre(text);
    // joined "AKIA"+"IOSFODNN7" appended after the original text.
    assert!(
        p.text.contains("AKIAIOSFODNN7"),
        "expected reassembled join in {:?}",
        p.text
    );
    // The original bytes are preserved as a prefix (will_append path keeps text).
    assert!(p.text.starts_with(text));
    assert_eq!(p.original_end, text.len());
}

#[test]
fn plus_concat_single_line_two_literals_joined() {
    // `a = "AKIA" + "IOSFODNN7EXAMPLE"` on ONE line: extract_plus_concatenation
    // splits on '+' (no trailing '+'), joins both quoted contents.
    let text = "a = \"AKIA\" + \"IOSFODNN7EXAMPLE\"\n";
    let p = pre(text);
    assert!(p.text.contains("AKIAIOSFODNN7EXAMPLE"), "{:?}", p.text);
}

#[test]
fn plus_concat_strips_assignment_keywords_and_lhs() {
    // filter_line_content strips `const ` etc.; extract_plus_concatenation
    // takes the substring after '=' before splitting. The LHS identifier and
    // keyword must not appear in the reassembled value.
    let text = "const secret = \"sk-aaaa\" +\n\"bbbbcccc\"\n";
    let p = pre(text);
    assert!(p.text.contains("sk-aaaabbbbcccc"), "{:?}", p.text);
    // The reassembled fragment region must not re-embed the LHS keyword.
    let appended = &p.text[p.original_end..];
    assert!(!appended.contains("const"), "appended={:?}", appended);
    assert!(!appended.contains("secret ="), "appended={:?}", appended);
}

#[test]
fn plus_concat_three_lines_chain() {
    let text = "k = \"sk-\" +\n\"part2-\" +\n\"part3xyz\"\n";
    let p = pre(text);
    assert!(p.text.contains("sk-part2-part3xyz"), "{:?}", p.text);
}

// ---------------------------------------------------------------------------
// Backslash line continuation
// ---------------------------------------------------------------------------

#[test]
fn backslash_continuation_joins_next_line() {
    // line0 ends with a single '\' -> Backslash continuation; line1 is tail.
    let text = "key = \"sk-aaaa\" \\\n    \"bbbbcccc\"\n";
    let p = pre(text);
    assert!(p.text.contains("sk-aaaabbbbcccc"), "{:?}", p.text);
}

#[test]
fn single_backslash_line_continues_joining_value() {
    // Positive twin for the double-backslash guard: a line ending in ONE '\'
    // is a backslash continuation, so "keep" + "next0000" glue together.
    // The leading url '+' supplies the chunk indicator.
    let text = concat!(
        "url = \"x\" +\n",
        "      \"yyyyyyyy\"\n",
        "b = \"keep\" \\\n",
        "c = \"next0000\"\n",
    );
    let p = pre(text);
    assert!(p.text.contains("keepnext0000"), "{:?}", p.text);
}

#[test]
fn double_backslash_is_not_a_continuation() {
    // extract_string_part requires ends_with('\\') && !ends_with("\\\\").
    // A line ending in "\\" (two backslash chars = escaped backslash) must NOT
    // be treated as a continuation, so "keep" is NOT glued to "next0000".
    let text = concat!(
        "url = \"x\" +\n",
        "      \"yyyyyyyy\"\n",
        "b = \"keep\" \\\\\n",
        "c = \"next0000\"\n",
    );
    let p = pre(text);
    assert!(!p.text.contains("keepnext0000"), "{:?}", p.text);
}

#[test]
fn backslash_continuation_disabled_by_config() {
    let mut c = MultilineConfig::default();
    c.backslash_continuation = false;
    c.plus_concatenation = false;
    c.python_implicit = false;
    c.template_literals = false;
    let text = "key = \"sk-aaaa\" \\\n    \"bbbbcccc\"\n";
    let p = preprocess_multiline(
        std::borrow::Cow::Borrowed(text),
        &c,
        &FragmentCache::new(100),
    );
    // With every join mode off, no "+", and only a backslash indicator,
    // the chain processes line-by-line as plain content and never produces
    // the glued token.
    assert!(!p.text.contains("sk-aaaabbbbcccc"), "{:?}", p.text);
}

// ---------------------------------------------------------------------------
// Python implicit string concatenation ("a" "b")
// ---------------------------------------------------------------------------

#[test]
fn python_implicit_adjacent_literals_join() {
    // Single line "AKIA" "IOSFODNN7" with only whitespace between -> join.
    let text = "key = \"AKIA\" \"IOSFODNN7\"\n";
    let p = pre(text);
    assert!(p.text.contains("AKIAIOSFODNN7"), "{:?}", p.text);
}

#[test]
fn python_implicit_rejects_nonwhitespace_gap() {
    // extract_python_implicit_concatenation returns None if the gap between two
    // closed string literals has any non-whitespace char. Here the two literals
    // are separated by `,` so they are NOT implicitly concatenated.
    // The indicator scan still fires on the `" "` substring inside the gap text
    // is absent; force the indicator with an explicit `" "` adjacency elsewhere.
    let text = "vals = \"AKIA\" , \"IOSFODNN7\" \"z\"\n";
    let p = pre(text);
    // Because of the comma between the first two, the python-implicit pass
    // returns None for the whole line; the line is then treated as plain
    // content (first line, not continuation) and emitted verbatim. The naive
    // glue "AKIAIOSFODNN7" must NOT appear.
    assert!(!p.text.contains("AKIAIOSFODNN7"), "{:?}", p.text);
}

#[test]
fn python_implicit_disabled_by_config() {
    let mut c = MultilineConfig::default();
    c.python_implicit = false;
    c.plus_concatenation = false;
    c.backslash_continuation = false;
    c.template_literals = false;
    let text = "key = \"AKIA\" \"IOSFODNN7\"\n";
    let p = preprocess_multiline(
        std::borrow::Cow::Borrowed(text),
        &c,
        &FragmentCache::new(100),
    );
    assert!(!p.text.contains("AKIAIOSFODNN7"), "{:?}", p.text);
}

// ---------------------------------------------------------------------------
// Function-style concatenation: paste0()/paste()/concat!()
// ---------------------------------------------------------------------------

#[test]
fn r_paste0_concatenation_joins_quoted_args() {
    // extract_function_concatenation triggers on "paste0(" and joins all
    // quoted string literals inside.
    let text = "key <- paste0(\"AKIA\", \"IOSFODNN7\", \"EXAMPLE\")\n";
    let p = pre(text);
    assert!(p.text.contains("AKIAIOSFODNN7EXAMPLE"), "{:?}", p.text);
}

#[test]
fn rust_concat_macro_joins_quoted_args() {
    let text = "let k = concat!(\"sk-\", \"abcd\", \"efgh\");\n";
    let p = pre(text);
    assert!(p.text.contains("sk-abcdefgh"), "{:?}", p.text);
}

#[test]
fn paste_single_string_does_not_join() {
    // extract_function_concatenation requires >= 2 quoted parts. One quoted
    // arg -> None -> no synthetic glue.
    let text = "x <- paste(\"only-one-string-here\")\nq = `tail`\n";
    let p = pre(text);
    // Only one literal inside paste(); nothing to concatenate.
    assert!(!p.text.contains("only-one-string-heretail"), "{:?}", p.text);
}

// ---------------------------------------------------------------------------
// JS/TS template literals
// ---------------------------------------------------------------------------

#[test]
fn template_literal_string_interpolation_reassembles() {
    // `ghp_${"BODY"}` reassembles to ghp_BODY: literal text outside ${} kept,
    // string-literal contents inside ${...} appended.
    let text = "const t = `ghp_${\"abcdefghij\"}`;\n";
    let p = pre(text);
    assert!(p.text.contains("ghp_abcdefghij"), "{:?}", p.text);
}

#[test]
fn template_literal_bare_identifier_interpolation_is_dropped() {
    // Inside ${...}, a bare identifier (runtime expression) is NOT literal text
    // and is skipped by extract_template_literal_continuation: `ghp_${token}suffix`
    // -> "ghp_suffix". A single bare-identifier template carries no concat
    // indicator on its own, so a leading url '+' supplies the chunk indicator
    // and the template line (line 3) is then processed.
    let text = concat!(
        "url = \"x\" +\n",
        "      \"yyyyyyyy\"\n",
        "const t = `ghp_${token}suffix0000`;\n",
    );
    let p = pre(text);
    assert!(p.text.contains("ghp_suffix0000"), "{:?}", p.text);
    // The bare identifier `token` must not leak into the reassembled candidate.
    let appended = &p.text[p.original_end..];
    assert!(!appended.contains("token"), "appended={:?}", appended);
}

#[test]
fn template_literal_disabled_by_config_no_join() {
    let mut c = MultilineConfig::default();
    c.template_literals = false;
    c.plus_concatenation = false;
    c.python_implicit = false;
    c.backslash_continuation = false;
    let text = "const t = `ghp_${\"abcdefghij\"}`;\n";
    let p = preprocess_multiline(
        std::borrow::Cow::Borrowed(text),
        &c,
        &FragmentCache::new(100),
    );
    // With template handling off the literal is not reassembled into ghp_<body>.
    // (`}${` / `${"` structural passes are separate; this single `${"..."}`
    // line carries neither a cluster nor a `}${` adjacency.)
    assert!(!p.text.contains("ghp_abcdefghij"), "{:?}", p.text);
}

// ---------------------------------------------------------------------------
// extract_quoted_content f-string handling (preprocessor.rs)
// observed via the public preprocess path.
// ---------------------------------------------------------------------------

#[test]
fn fstring_adjacent_prefix_drops_brace_interpolation() {
    // A real Python f-string `f"..."` where `f` directly abuts the quote DOES
    // strip `{...}` spans. Use backslash continuation so extract_string_content
    // runs the f-string-aware extractor on the raw line.
    let text = "token = f\"sk-{user}-tail0000\" \\\n    \"_more\"\n";
    let p = pre(text);
    // `{user}` is interpolation -> dropped; "sk--tail0000" + "_more".
    assert!(p.text.contains("sk--tail0000_more"), "{:?}", p.text);
    // The original raw line (with `{user}`) is preserved verbatim as the prefix
    // of `final_text`, so the raw interpolation IS present in `p.text` as a
    // whole. The reassembled candidate lives in the APPENDED region past
    // `original_end`; that is where the `{user}` span must NOT leak (matching
    // the `template_literal_bare_identifier_interpolation_is_dropped` pattern).
    let appended = &p.text[p.original_end..];
    assert!(!appended.contains("{user}"), "appended={:?}", appended);
    assert!(
        !appended.contains("sk-{user}-tail0000"),
        "appended={:?}",
        appended
    );
}

#[test]
fn non_adjacent_f_in_identifier_preserves_braces() {
    // M13 regression: an `f` that is part of an identifier (here `prefix_token`)
    // and not adjacent to the quote must NOT enable f-string handling; the
    // `{live}` span must survive.
    let text = "prefix_token = \"sk-{live}-abcdef1234567890\" \\\n    \"_cont\"\n";
    let p = pre(text);
    assert!(
        p.text.contains("sk-{live}-abcdef1234567890"),
        "{:?}",
        p.text
    );
    assert!(!p.text.contains("sk--abcdef1234567890"), "{:?}", p.text);
}

#[test]
fn fstring_escaped_double_brace_is_literal() {
    // Python f-string `{{kept}}` is an escaped literal brace span that evaluates
    // to `{kept}`, so the reassembled secret value is `sk-{kept}-zzzz0000`.
    // extract_quoted_content consumes the SECOND brace of each `{{`/`}}` pair
    // and emits one literal brace, so `kept` survives between them (it is NOT
    // mistaken for a `{...}` interpolation). Regression lock for that escape.
    let text = "tok = f\"sk-{{kept}}-zzzz0000\" \\\n    \"_cont\"\n";
    let p = pre(text);
    assert!(
        p.text.contains("sk-{kept}-zzzz0000"),
        "escaped `{{{{kept}}}}` must reassemble to literal `{{kept}}`; got: {:?}",
        p.text
    );
}

// ---------------------------------------------------------------------------
// Structural cluster reassembly (structural.rs) + anchor line attribution
// ---------------------------------------------------------------------------

#[test]
fn structural_cluster_two_related_assignments_reassemble() {
    // A pure 2-assignment cluster carries NO concatenation indicator, so it
    // would passthrough. A co-occurring '+' concat (the url line) supplies the
    // indicator and the structural pass then runs over ALL lines, clustering
    // aws_key_part1 / aws_key_part2 (extract_prefix == "awskey") and appending
    // their joined value (len >= 12).
    let text = concat!(
        "url = \"https://\" +\n",
        "      \"example.com\"\n",
        "aws_key_part1 = \"AKIAIOSFODNN7EXAMPLE\"\n",
        "aws_key_part2 = \"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\"\n",
    );
    let p = pre(text);
    let joined = "AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY";
    assert!(p.text.contains(joined), "{:?}", p.text);
}

#[test]
fn structural_cluster_no_indicator_passthrough_no_reassembly() {
    // Two related assignments with NO concat indicator anywhere -> the whole
    // chunk is passthrough'd and `collect_structural_fragments` never runs, so
    // the cluster is NOT reassembled.
    let text = concat!(
        "aws_key_part1 = \"AKIAIOSFODNN7EXAMPLE\"\n",
        "aws_key_part2 = \"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\"\n",
    );
    let p = pre(text);
    assert_eq!(p.text, text, "no indicator -> verbatim passthrough");
    let joined = "AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY";
    assert!(!p.text.contains(joined), "{:?}", p.text);
}

#[test]
fn structural_cluster_with_cooccurring_concat_join_keeps_true_line() {
    // C11 regression: a url '+' concat join AND a structural cluster in one
    // chunk. The cluster (lines 3,4) must still map to line 3, not the concat
    // line, despite the will_append base arithmetic.
    let text = concat!(
        "url = \"https://\" +\n",
        "      \"example.com\"\n",
        "aws_key_part1 = \"AKIAIOSFODNN7EXAMPLE\"\n",
        "aws_key_part2 = \"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\"\n",
    );
    let p = pre(text);
    let joined = "AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY";
    let off = p.text.find(joined).expect("cluster secret present");
    assert_eq!(p.line_for_offset(off), Some(3));
}

#[test]
fn structural_cluster_below_min_length_is_dropped() {
    // The structural pass runs (url '+' concat supplies the indicator). The
    // tok cluster joins to "abcdef" (len 6 < 12) -> dropped, never appended.
    let text = concat!(
        "url = \"https://\" +\n",
        "      \"example.com\"\n",
        "tok_part1 = \"abc\"\n",
        "tok_part2 = \"def\"\n",
    );
    let p = pre(text);
    // The glued short cluster value must not appear anywhere in the buffer.
    assert!(!p.text.contains("abcdef"), "{:?}", p.text);
}

#[test]
fn structural_unrelated_prefixes_do_not_cluster() {
    // The structural pass runs (url '+' concat indicator), but foo_key and
    // bar_key have different extract_prefix values -> never one cluster.
    let text = concat!(
        "url = \"https://\" +\n",
        "      \"example.com\"\n",
        "foo_key = \"AKIAIOSFODNN7EXAMPLE0\"\n",
        "bar_key = \"wJalrXUtnFEMIK7MDENGbP0\"\n",
    );
    let p = pre(text);
    let glued = "AKIAIOSFODNN7EXAMPLE0wJalrXUtnFEMIK7MDENGbP0";
    assert!(!p.text.contains(glued), "{:?}", p.text);
}

// ---------------------------------------------------------------------------
// resolve_concat_reference: `lhs = a + b` resolves prior literals (structural)
// ---------------------------------------------------------------------------

#[test]
fn var_ref_concatenation_resolves_prior_literals() {
    // aws_prefix and aws_suffix have no common var prefix needed; they are
    // recorded as literals, then `aws_key = aws_prefix + aws_suffix` resolves
    // both via CONCAT_RE -> joined value (>=12) appended.
    let text = concat!(
        "aws_prefix = \"AKIAIOSFODNN7\"\n",
        "aws_suffix = \"EXAMPLEKEY01234\"\n",
        "aws_key = aws_prefix + aws_suffix\n",
    );
    let p = pre(text);
    let resolved = "AKIAIOSFODNN7EXAMPLEKEY01234";
    assert!(p.text.contains(resolved), "{:?}", p.text);
    // The resolved-concat structural entry is stamped with a synthetic line
    // number (SYNTHETIC_BASE_LINE = 1_000_000_000 + offset_idx 0).
    let off = p.text.find(resolved).expect("resolved secret present");
    assert_eq!(p.line_for_offset(off), Some(1_000_000_000));
}

#[test]
fn var_ref_concatenation_resolves_known_prefix_with_weak_target_name() {
    // `aws_access` is a common shorthand for an access-key value but is not a
    // strong generic assignment key by itself. The resolved RHS carries the
    // known AKIA credential prefix, so the structural pass must append it for
    // named detectors instead of treating the weak target name as proof that
    // the join is irrelevant.
    let text = concat!(
        "key_head = \"AKIA\"\n",
        "key_tail = \"R7VXNPLMQ3HSKWJT\"\n",
        "aws_access = key_head + key_tail\n",
    );
    let p = pre(text);
    assert!(p.text.contains("AKIAR7VXNPLMQ3HSKWJT"), "{:?}", p.text);
}

#[test]
fn var_ref_concatenation_weak_target_without_known_prefix_yields_nothing() {
    let text = concat!(
        "left_part = \"R7VXNPLMQ3HSKWJT\"\n",
        "right_part = \"XK4P9MQ2WE5RT8YU\"\n",
        "output = left_part + right_part\n",
    );
    let p = pre(text);
    assert!(
        !p.text.contains("R7VXNPLMQ3HSKWJTXK4P9MQ2WE5RT8YU"),
        "{:?}",
        p.text
    );
}

#[test]
fn var_ref_concatenation_unresolved_ident_yields_nothing() {
    // resolve_concat_reference returns None if any RHS ident is unknown.
    // `bbb` is never assigned -> the `+`-concat line resolves to None.
    let text = concat!("head = \"AKIAIOSFODNN7\"\n", "out = head + bbb\n",);
    let p = pre(text);
    // No fully-resolved join -> "AKIAIOSFODNN7" + nothing glued. The bare
    // identifier "bbb" must never be glued onto the literal.
    assert!(!p.text.contains("AKIAIOSFODNN7bbb"), "{:?}", p.text);
}

// ---------------------------------------------------------------------------
// resolve_template_reference + }${ adjacency (structural template pass)
// ---------------------------------------------------------------------------

#[test]
fn template_var_interpolation_pass_reassembles_two_vars() {
    // Third structural pass is gated on a `}${` adjacency anywhere in the chunk.
    // a="xoxb-aaaa", b="bbbbcccc", token=`${a}${b}` -> "xoxb-aaaabbbbcccc".
    let text = concat!(
        "const a = \"xoxb-aaaa\";\n",
        "const b = \"bbbbcccc\";\n",
        "token = `${a}${b}`;\n",
    );
    let p = pre(text);
    assert!(p.text.contains("xoxb-aaaabbbbcccc"), "{:?}", p.text);
}

#[test]
fn template_var_interpolation_unresolved_var_emits_nothing() {
    // resolve_template_reference returns None if any `${ident}` is unresolved,
    // so a partial candidate is never emitted.
    let text = concat!("const a = \"xoxb-aaaa\";\n", "token = `${a}${missing}`;\n",);
    let p = pre(text);
    // `missing` never assigned -> whole template resolves to None. The `xoxb-`
    // literal must not be glued onto the bare identifier.
    assert!(!p.text.contains("xoxb-aaaamissing"), "{:?}", p.text);
}

// ---------------------------------------------------------------------------
// join_inline_array_strings (structural.rs)
// ---------------------------------------------------------------------------

#[test]
fn inline_array_strings_are_concatenated_when_long_enough() {
    // A bare array line carries no concat indicator, so a leading '+' concat
    // supplies it; the structural pass then concatenates the array's quoted
    // fragments. Emitted only when the joined length is >= 16.
    let text = concat!(
        "url = \"https://\" +\n",
        "      \"example.com\"\n",
        "api_key_parts = [\"AKIAIOSF\", \"ODNN7EXAMPLE12\"]\n",
    );
    let p = pre(text);
    // "AKIAIOSF" + "ODNN7EXAMPLE12" = "AKIAIOSFODNN7EXAMPLE12" (len 22 >= 16).
    assert!(p.text.contains("AKIAIOSFODNN7EXAMPLE12"), "{:?}", p.text);
}

#[test]
fn inline_array_short_join_is_dropped() {
    // Structural pass runs (url indicator), but joined array content "abcd"
    // (len 4 < 16) is not appended.
    let text = concat!(
        "url = \"https://\" +\n",
        "      \"example.com\"\n",
        "api_key_parts = [\"ab\", \"cd\"]\n",
    );
    let p = pre(text);
    assert!(!p.text.contains("abcd"), "{:?}", p.text);
}

#[test]
fn inline_array_non_credential_metadata_is_not_concatenated() {
    let text = concat!(
        "url = \"https://\" +\n",
        "      \"example.com\"\n",
        "vx_rows = [\"VX-701\", \"VX-703\", \"VX-709\", \"VX-710\"]\n",
    );
    let p = pre(text);
    assert!(!p.text.contains("VX-701VX-703VX-709VX-710"), "{:?}", p.text);
}

#[test]
fn inline_array_escaped_quote_does_not_split_literal_early() {
    // Without backslash-escape handling, the `\"` inside the first array element
    // closes the literal at the escaped quote, dropping "IOSFOD" and corrupting
    // reassembly. Must match extract_quoted_content: keep `\` + `"` in content.
    let text = concat!(
        "url = \"https://\" +\n",
        "      \"example.com\"\n",
        "api_key_parts = [\"AKIA\\\"IOSFOD\", \"NN7EXAMPLE12\"]\n",
    );
    let p = pre(text);
    assert!(
        p.text.contains("AKIA\\\"IOSFODNN7EXAMPLE12"),
        "{:?}",
        p.text
    );
}

// ---------------------------------------------------------------------------
// FragmentCache same-file join / cross-file no-join / anchor (fragment_cache.rs)
// ---------------------------------------------------------------------------

#[test]
fn fragment_cache_single_fragment_no_join() {
    // cluster.len() < 2 -> empty result.
    let cache = FragmentCache::new(100);
    let out = cache.record_and_reassemble(frag("awskey", "aws_key_part1", "AKIA", 1, Some("a.py")));
    assert!(out.is_empty());
}

#[test]
fn fragment_cache_same_file_near_join_emits_both_orderings() {
    // Two fragments, same prefix, same path, lines 1 & 2 (|diff| < 100).
    // The (i,j) double loop with i!=j produces BOTH f1+f2 and f2+f1.
    let cache = FragmentCache::new(100);
    let _ = cache.record_and_reassemble(frag("awskey", "k1", "AKIAHEAD", 1, Some("a.py")));
    let out = cache.record_and_reassemble(frag("awskey", "k2", "TAILVALUE", 2, Some("a.py")));
    assert_eq!(out.len(), 2);
    let joined: Vec<&str> = out.iter().map(|z| z.as_str()).collect();
    assert!(joined.contains(&"AKIAHEADTAILVALUE"));
    assert!(joined.contains(&"TAILVALUEAKIAHEAD"));
}

#[test]
fn fragment_cache_cross_file_does_not_join() {
    // Same prefix but DIFFERENT paths -> scoped_key differs -> different cluster
    // keys, so the second insert lands in a fresh (size-1) cluster: no join.
    let cache = FragmentCache::new(100);
    let _ = cache.record_and_reassemble(frag("awskey", "k1", "AKIAHEAD", 1, Some("a.py")));
    let out = cache.record_and_reassemble(frag("awskey", "k2", "TAILVALUE", 2, Some("b.py")));
    assert!(
        out.is_empty(),
        "cross-file pairs must not reassemble: {:?}",
        out
    );
}

#[test]
fn fragment_cache_same_path_too_far_apart_no_join() {
    // Same prefix and path, but |line1 - line2| >= 100 -> `near` is false.
    let cache = FragmentCache::new(100);
    let _ = cache.record_and_reassemble(frag("awskey", "k1", "AKIAHEAD", 1, Some("a.py")));
    let out = cache.record_and_reassemble(frag("awskey", "k2", "TAILVALUE", 200, Some("a.py")));
    assert!(
        out.is_empty(),
        "fragments >=100 lines apart must not join: {:?}",
        out
    );
}

#[test]
fn fragment_cache_line_distance_boundary_99_joins_100_does_not() {
    // `near` guard is `abs(diff) < 100`. diff 99 joins; diff 100 does not.
    let cache99 = FragmentCache::new(100);
    let _ = cache99.record_and_reassemble(frag("awskey", "k1", "AKIAHEAD", 1, Some("a.py")));
    let out99 = cache99.record_and_reassemble(frag("awskey", "k2", "TAILVALUE", 100, Some("a.py")));
    assert_eq!(out99.len(), 2, "line diff 99 (< 100) must join");

    let cache100 = FragmentCache::new(100);
    let _ = cache100.record_and_reassemble(frag("awskey", "k1", "AKIAHEAD", 1, Some("a.py")));
    let out100 =
        cache100.record_and_reassemble(frag("awskey", "k2", "TAILVALUE", 101, Some("a.py")));
    assert!(out100.is_empty(), "line diff 100 (== 100) must NOT join");
}

#[test]
fn fragment_cache_no_path_fragments_share_empty_scope_and_join() {
    // path == None -> scope "" for both -> same scoped_key -> same cluster.
    // f1.path == f2.path (both None) and lines near -> join.
    let cache = FragmentCache::new(100);
    let _ = cache.record_and_reassemble(frag("awskey", "k1", "AKIAHEAD", 1, None));
    let out = cache.record_and_reassemble(frag("awskey", "k2", "TAILVALUE", 2, None));
    assert_eq!(out.len(), 2);
}

#[test]
fn fragment_cache_duplicate_fragment_not_inserted_twice() {
    // Same (path,line,value) is deduped; recording it twice keeps cluster len 1.
    let cache = FragmentCache::new(100);
    let _ = cache.record_and_reassemble(frag("awskey", "k1", "AKIAHEAD", 1, Some("a.py")));
    let out = cache.record_and_reassemble(frag("awskey", "k1", "AKIAHEAD", 1, Some("a.py")));
    // Duplicate -> cluster still size 1 -> no join.
    assert!(
        out.is_empty(),
        "duplicate must not create a 2-element cluster: {:?}",
        out
    );
}

#[cfg(feature = "simd")]
#[test]
fn fragment_cache_stamped_anchor_is_prefix_fragment_path_and_line() {
    // record_and_reassemble_stamped: anchor (f1) is the prefix fragment of each
    // pair. f1.path is stamped on the candidate. Both inserts share path "a.py".
    let cache = FragmentCache::new(100);
    let _ = cache.record_and_reassemble_stamped(frag("awskey", "k1", "AKIAHEAD", 5, Some("a.py")));
    let out: Vec<ReassembledCandidate> =
        cache.record_and_reassemble_stamped(frag("awskey", "k2", "TAILVALUE", 7, Some("a.py")));
    assert_eq!(out.len(), 2);
    // Every candidate is anchored to the same file path.
    for c in &out {
        assert_eq!(c.path.as_deref(), Some("a.py"));
    }
    // The two anchor lines (5 and 7) both appear as f1.line across the orderings.
    let lines: Vec<usize> = out.iter().map(|c| c.line).collect();
    assert!(lines.contains(&5));
    assert!(lines.contains(&7));
}

#[cfg(feature = "simd")]
#[test]
fn fragment_cache_stamped_cross_file_no_join() {
    let cache = FragmentCache::new(100);
    let _ = cache.record_and_reassemble_stamped(frag("awskey", "k1", "AKIAHEAD", 1, Some("a.py")));
    let out =
        cache.record_and_reassemble_stamped(frag("awskey", "k2", "TAILVALUE", 2, Some("b.py")));
    assert!(out.is_empty());
}

#[test]
fn fragment_cache_clear_resets_clusters() {
    // After clear(), a previously-recorded prefix fragment is gone, so a single
    // new fragment cannot find a partner to join with.
    let cache = FragmentCache::new(100);
    let _ = cache.record_and_reassemble(frag("awskey", "k1", "AKIAHEAD", 1, Some("a.py")));
    cache.clear();
    let out = cache.record_and_reassemble(frag("awskey", "k2", "TAILVALUE", 2, Some("a.py")));
    assert!(
        out.is_empty(),
        "after clear the prior fragment must be gone: {:?}",
        out
    );
}

#[test]
fn fragment_cache_three_near_fragments_emit_six_ordered_pairs() {
    // cluster len 3, all near & same path -> ordered pairs (i!=j) = 3*2 = 6.
    let cache = FragmentCache::new(100);
    let _ = cache.record_and_reassemble(frag("awskey", "k1", "AAA", 1, Some("a.py")));
    let _ = cache.record_and_reassemble(frag("awskey", "k2", "BBB", 2, Some("a.py")));
    let out = cache.record_and_reassemble(frag("awskey", "k3", "CCC", 3, Some("a.py")));
    assert_eq!(out.len(), 6);
}

// ---------------------------------------------------------------------------
// PreprocessedText::passthrough (config.rs), constructor used elsewhere
// ---------------------------------------------------------------------------

#[test]
fn preprocessed_text_passthrough_clamps_last_mapping_to_text_len() {
    // `PreprocessedText::passthrough` and the internal passthrough path share
    // the split('\n') identity-mapping contract: end_offset = end+1, then the
    // last mapping is clamped to text.len().
    let text = "abc\ndef"; // len 7. split: "abc"(0..3 -> end_off 4), "def"(4..7).
    let p = PreprocessedText::passthrough(std::borrow::Cow::Borrowed(text));
    assert_eq!(p.original_end, 7);
    assert_eq!(p.mappings.len(), 2);
    assert_eq!(p.mappings[0].start_offset, 0);
    assert_eq!(p.mappings[0].end_offset, 4); // 3 + 1, not clamped (not last)
    assert_eq!(p.mappings[0].line_number, 1);
    assert_eq!(p.mappings[1].start_offset, 4);
    assert_eq!(p.mappings[1].end_offset, 7); // last -> clamped to text.len()
    assert_eq!(p.mappings[1].line_number, 2);
}

#[test]
fn preprocessed_text_passthrough_line_for_offset_covers_newline() {
    // Because passthrough() sets end_offset = end+1 for non-last lines, the
    // '\n' byte at offset 3 is inside mapping[0]'s window.
    let text = "abc\ndef";
    let p = PreprocessedText::passthrough(std::borrow::Cow::Borrowed(text));
    assert_eq!(p.line_for_offset(0), Some(1));
    assert_eq!(p.line_for_offset(3), Some(1)); // the '\n' maps to line 1 here
    assert_eq!(p.line_for_offset(4), Some(2));
    assert_eq!(p.line_for_offset(6), Some(2));
    assert_eq!(p.line_for_offset(7), None); // == text.len(), past last window
}

// ---------------------------------------------------------------------------
// line_for_offset binary-search semantics (config.rs)
// ---------------------------------------------------------------------------

#[test]
fn line_for_offset_before_any_mapping_is_none() {
    // Construct a PreprocessedText whose first mapping starts at offset 5.
    let p = PreprocessedText {
        text: std::borrow::Cow::Owned("0123456789".to_string()),
        original_end: 10,
        mappings: vec![LineMapping {
            start_offset: 5,
            end_offset: 8,
            line_number: 3,
            original_start_offset: 5,
            transport_decoded: false,
        }],
    };
    // offset 4 < first start_offset -> partition_point returns 0 -> None.
    assert_eq!(p.line_for_offset(4), None);
    assert_eq!(p.line_for_offset(5), Some(3));
    assert_eq!(p.line_for_offset(7), Some(3));
    // offset 8 == end_offset (exclusive) -> None.
    assert_eq!(p.line_for_offset(8), None);
}

#[test]
fn line_for_offset_gap_between_mappings_is_none() {
    // Two non-contiguous windows: [0,3) line1 and [10,13) line5. An offset in
    // the gap resolves to mapping[0] by start_offset, then fails the end check.
    let p = PreprocessedText {
        text: std::borrow::Cow::Owned("x".repeat(20)),
        original_end: 20,
        mappings: vec![
            LineMapping {
                start_offset: 0,
                end_offset: 3,
                line_number: 1,
                original_start_offset: 0,
                transport_decoded: false,
            },
            LineMapping {
                start_offset: 10,
                end_offset: 13,
                line_number: 5,
                original_start_offset: 10,
                transport_decoded: false,
            },
        ],
    };
    assert_eq!(p.line_for_offset(2), Some(1));
    // offset 5: partition_point(start<=5) -> idx 1 -> mapping[0] end 3, 5 !< 3 -> None.
    assert_eq!(p.line_for_offset(5), None);
    assert_eq!(p.line_for_offset(10), Some(5));
    assert_eq!(p.line_for_offset(12), Some(5));
    assert_eq!(p.line_for_offset(13), None);
}

#[test]
fn line_for_offset_empty_mappings_is_none() {
    let p = PreprocessedText {
        text: std::borrow::Cow::Owned(String::new()),
        original_end: 0,
        mappings: Vec::new(),
    };
    assert_eq!(p.line_for_offset(0), None);
    assert_eq!(p.line_for_offset(99), None);
}

// ---------------------------------------------------------------------------
// will_append vs structural base offset arithmetic, observed via byte layout
// ---------------------------------------------------------------------------

#[test]
fn concat_join_appended_region_starts_after_original_plus_newline() {
    // will_append path: final_text = text + '\n' + joined_text. So original_end
    // is exactly text.len() and the byte at original_end is '\n'.
    let text = "key = \"AKIA\" +\n\"IOSFODNN7\"\n";
    let p = pre(text);
    assert_eq!(p.original_end, text.len());
    assert!(p.text.len() > p.original_end, "join must extend the buffer");
    assert_eq!(p.text.as_bytes()[p.original_end], b'\n');
}

#[test]
fn lone_mid_line_backtick_lacks_per_line_indicator_passthrough() {
    // `has_concatenation_indicators` first OR-gate passes (a '`' exists), but the
    // per-line loop finds no triggering clause: the line does not end with '`'
    // (so the `count()==1` clause is false), has no '+', no `${"`, no `}${`.
    // -> returns false -> passthrough verbatim.
    let text = "note = a `b\n";
    let p = pre(text);
    assert_eq!(p.text, text);
    assert_eq!(p.original_end, text.len());
}

// ---------------------------------------------------------------------------
// Quote-aware `+`-concatenation split (string_extract::split_concatenation_operators)
//
// extract_plus_concatenation must split ONLY on the `+` that JOIN string
// literals (outside any quoted span). A `+` INSIDE a quoted literal is part of
// the value, base64 uses `+` in its alphabet and a fragment can even end in
// one (so a blind `split('+')` truncated those secrets and broke reassembly).
// `result_lines` rebuilds every line of a chunk, so any chunk that carries a
// real concat indicator routes its other lines (e.g. a base64 value) through
// this splitter; the bug therefore corrupts real-world config files mixing a
// concatenation with a base64 string.
// ---------------------------------------------------------------------------

/// The reassembled/joined region the preprocessor appends after the original
/// text (empty when nothing was appended).
fn appended(p: &PreprocessedText<'_>) -> String {
    p.text[p.original_end..].to_string()
}

#[test]
fn plus_concat_two_double_quote_literals_still_join() {
    let p = pre("a = \"AKIA\" + \"IOSFODNN7EXAMPLE\"\n");
    assert!(p.text.contains("AKIAIOSFODNN7EXAMPLE"), "{:?}", p.text);
}

#[test]
fn plus_concat_three_literals_single_line_still_join() {
    let p = pre("k = \"sk-\" + \"part2-\" + \"part3xyz\"\n");
    assert!(p.text.contains("sk-part2-part3xyz"), "{:?}", p.text);
}

#[test]
fn plus_concat_single_quote_literals_join() {
    // `' +` is itself a concatenation indicator, so this self-triggers.
    let p = pre("a = 'AKIA' + 'IOSFODNN7EXAMPLE'\n");
    assert!(p.text.contains("AKIAIOSFODNN7EXAMPLE"), "{:?}", p.text);
}

#[test]
fn ordinary_join_with_no_interior_plus_unchanged() {
    let p = pre("a = \"AKIA\" + \"REST\"\n");
    assert!(p.text.contains("AKIAREST"), "{:?}", p.text);
}

#[test]
fn base64_operands_with_interior_plus_join_same_line() {
    // The `+` inside each quoted operand is base64 data, NOT a join; only the
    // `+` between the operands joins them.
    let p = pre("t = \"aGVsbG8+\" + \"d29ybGQ=\"\n");
    assert!(
        p.text.contains("aGVsbG8+d29ybGQ="),
        "interior '+' must survive; got {:?}",
        p.text
    );
}

#[test]
fn base64_fragment_ending_in_plus_reassembles_across_lines() {
    // line 1 value ends with a base64 '+', THEN a real join '+' continues onto
    // line 2. The contiguous secret only appears if the in-quote '+' is kept.
    let p = pre("key = \"aGVsbG8+\" +\n\"d29ybGQ=\"\n");
    assert!(
        p.text.contains("aGVsbG8+d29ybGQ="),
        "cross-line base64 with trailing '+' must reassemble; got {:?}",
        p.text
    );
}

#[test]
fn two_literals_each_with_interior_plus_join() {
    let p = pre("x = \"a+b\" + \"c+d\"\n");
    assert!(p.text.contains("a+bc+d"), "{:?}", p.text);
}

#[test]
fn base64_value_with_plus_and_slash_joins() {
    let p = pre("s = \"aB+/cd\" + \"Ef+/gh\"\n");
    assert!(p.text.contains("aB+/cdEf+/gh"), "{:?}", p.text);
}

#[test]
fn single_quoted_values_with_interior_plus_join() {
    let p = pre("s = 'aB+cd' + 'Ef+gh'\n");
    assert!(p.text.contains("aB+cdEf+gh"), "{:?}", p.text);
}

#[test]
fn cross_line_two_interior_plus_fragments_reassemble() {
    let p = pre("t = \"ab+cd+\" +\n\"ef+gh\"\n");
    assert!(p.text.contains("ab+cd+ef+gh"), "{:?}", p.text);
}

#[test]
fn interior_plus_value_then_trailing_join_plus_cross_line() {
    let p = pre("key = \"a+b\" +\n\"c+d\"\n");
    assert!(p.text.contains("a+bc+d"), "{:?}", p.text);
}

#[test]
fn base64_operands_uppercase_join_same_line() {
    let p = pre("cfg = \"QUtJQQ+\" + \"QllMUE0=\"\n");
    assert!(p.text.contains("QUtJQQ+QllMUE0="), "{:?}", p.text);
}

#[test]
fn escaped_quote_keeps_span_open_across_interior_plus() {
    // `"a\"+b"` is ONE literal: the escaped quote does not close it, so the `+`
    // after it is in-quote and must not split. Value tail `b` then joins `cd`.
    let p = pre("x = \"a\\\"+b\" + \"cd\"\n");
    assert!(
        p.text.contains("bcd"),
        "escaped-quote span must keep '+b' attached so it joins 'cd'; got {:?}",
        p.text
    );
}

#[test]
fn standalone_base64_in_concat_chunk_is_not_corrupted() {
    // The `url` line supplies the chunk's concat indicator; the base64 line is
    // routed through extract_plus_concatenation but must NOT be split.
    let p = pre("url = \"ab\" + \"cd\"\nsecret = \"aGVsbG8+d29ybGQ=\"\n");
    let app = appended(&p);
    assert!(
        app.contains("aGVsbG8+d29ybGQ="),
        "base64 in a concat chunk must stay intact in the reassembled region; appended={app:?}"
    );
}

#[test]
fn co_occurring_real_join_still_works_in_mixed_chunk() {
    let p = pre("url = \"ab\" + \"cd\"\nsecret = \"aGVsbG8+d29ybGQ=\"\n");
    let app = appended(&p);
    assert!(
        app.contains("abcd"),
        "the genuine `\"ab\" + \"cd\"` join must still reassemble; appended={app:?}"
    );
}

#[test]
fn base64_without_padding_interior_plus_in_concat_chunk_intact() {
    let p = pre("url = \"ab\" + \"cd\"\ntoken = \"aGVsbG8+d29ybG8\"\n");
    let app = appended(&p);
    assert!(
        app.contains("aGVsbG8+d29ybG8"),
        "unpadded base64 with interior '+' must stay intact; appended={app:?}"
    );
}

#[test]
fn interior_plus_only_value_is_not_treated_as_concatenation() {
    // A single literal whose only `+` are in-quote is NOT a concatenation: it
    // must pass through verbatim (no truncated `"abc"` fragment).
    let p = pre("url = \"ab\" + \"cd\"\nx = \"a+b+c\"\n");
    let app = appended(&p);
    assert!(
        app.contains("a+b+c"),
        "interior-only '+' value must not be split; appended={app:?}"
    );
}

#[test]
fn plus_concat_lhs_keyword_not_in_appended_region() {
    let p = pre("const secret = \"sk-aaaa\" + \"bbbbcccc\"\n");
    assert!(p.text.contains("sk-aaaabbbbcccc"), "{:?}", p.text);
    let app = appended(&p);
    assert!(!app.contains("const"), "appended={app:?}");
    assert!(!app.contains("secret ="), "appended={app:?}");
}

#[test]
fn trailing_join_plus_continuation_still_reassembles() {
    let p = pre("v = \"AKIA\" +\n\"REST00\"\n");
    assert!(p.text.contains("AKIAREST00"), "{:?}", p.text);
}

#[test]
fn mixed_base64_and_real_join_same_chunk_both_correct() {
    let p = pre("url = \"https://\" + \"ex.com\"\nblob = \"aGVsbG8+d29ybGQ=\"\n");
    assert!(p.text.contains("https://ex.com"), "{:?}", p.text);
    let app = appended(&p);
    assert!(
        app.contains("aGVsbG8+d29ybGQ="),
        "base64 must survive alongside a real join; appended={app:?}"
    );
}

#[test]
fn python_implicit_adjacency_still_joins() {
    // Regression: the quote-aware change must not affect implicit concatenation.
    let p = pre("key = \"AKIA\" \"IOSFODNN7\"\n");
    assert!(p.text.contains("AKIAIOSFODNN7"), "{:?}", p.text);
}

#[test]
fn var_ref_concatenation_still_resolves() {
    // Regression: variable-reference joins are handled by the structural pass,
    // not the string splitter, and must still reassemble.
    let text = concat!(
        "aws_prefix = \"AKIAIOSFODNN7\"\n",
        "aws_suffix = \"EXAMPLEKEY01234\"\n",
        "aws_key = aws_prefix + aws_suffix\n",
    );
    let p = pre(text);
    assert!(
        p.text.contains("AKIAIOSFODNN7EXAMPLEKEY01234"),
        "{:?}",
        p.text
    );
}

// ---------------------------------------------------------------------------
// f-string `{expr}` interpolation skip (string_extract::extract_quoted_content)
//
// A real `{expr}` interpolation is a runtime value and is dropped from the
// reassembled literal; escaped `{{`/`}}` collapse to one literal brace. The skip
// must track string literals INSIDE the expression so a `{`/`}` that appears in
// a quoted span (f"{d['}']}tail") does not miscount brace depth and leak the
// expression tail into the secret, the same quote-awareness the `${...}`
// template handler already has.
// ---------------------------------------------------------------------------

/// Reassemble an f-string `body` (the text between `f"` and the closing `"`)
/// through the real extractor via a backslash continuation, and return the
/// appended/reassembled region. The continuation tail `_KCONT` is glued onto the
/// f-string's literal output, so the reassembled value is
/// `<literal-of-body>` + `_KCONT`. `body` must use single quotes for any inner
/// strings (the outer delimiter is `"`).
fn fstring_reassembled(body: &str) -> String {
    let text = format!("tok = f\"{body}\" \\\n    \"_KCONT\"\n");
    let p = pre(&text);
    p.text[p.original_end..].to_string()
}

#[test]
fn fstring_drops_simple_var_interpolation() {
    let app = fstring_reassembled("ghp_{user}body");
    assert!(app.contains("ghp_body_KCONT"), "{app:?}");
    assert!(
        !app.contains("user"),
        "interpolation var must be dropped: {app:?}"
    );
}

#[test]
fn fstring_drops_var_at_end() {
    let app = fstring_reassembled("ghp_{user}");
    assert!(app.contains("ghp__KCONT"), "{app:?}");
    assert!(!app.contains("user"), "{app:?}");
}

#[test]
fn fstring_drops_var_at_start() {
    let app = fstring_reassembled("{user}ghp_");
    assert!(app.contains("ghp__KCONT"), "{app:?}");
    assert!(!app.contains("user"), "{app:?}");
}

#[test]
fn fstring_drops_two_named_vars() {
    let app = fstring_reassembled("{alpha}mid{beta}end");
    assert!(app.contains("midend_KCONT"), "{app:?}");
    assert!(!app.contains("alpha") && !app.contains("beta"), "{app:?}");
}

#[test]
fn fstring_escaped_open_brace_is_literal() {
    let app = fstring_reassembled("a{{b");
    assert!(app.contains("a{b_KCONT"), "{app:?}");
}

#[test]
fn fstring_escaped_close_brace_is_literal() {
    let app = fstring_reassembled("a}}b");
    assert!(app.contains("a}b_KCONT"), "{app:?}");
}

#[test]
fn fstring_both_escaped_braces_are_literal() {
    let app = fstring_reassembled("{{x}}");
    assert!(app.contains("{x}_KCONT"), "{app:?}");
}

#[test]
fn fstring_close_brace_inside_interp_string_does_not_end_skip() {
    // THE FIX: the `}` inside `'}'` must not close the interpolation early.
    let app = fstring_reassembled("{d['}']}tail");
    assert!(app.contains("tail_KCONT"), "{app:?}");
    assert!(
        !app.contains("']}"),
        "expression tail must not leak: {app:?}"
    );
}

#[test]
fn fstring_open_brace_inside_interp_string_does_not_unbalance() {
    // Before the fix the in-string `{` inflated brace_depth so the real `}` never
    // balanced and the whole tail was consumed (empty literal).
    let app = fstring_reassembled("{d['{']}tail");
    assert!(
        app.contains("tail_KCONT"),
        "tail must survive a balanced skip: {app:?}"
    );
}

#[test]
fn fstring_brace_in_string_between_literal_text() {
    let app = fstring_reassembled("pre{d['}']}post");
    assert!(app.contains("prepost_KCONT"), "{app:?}");
    assert!(!app.contains("']}"), "{app:?}");
}

#[test]
fn fstring_nested_format_spec_braces_are_skipped() {
    let app = fstring_reassembled("{x:>{w}}tail");
    assert!(app.contains("tail_KCONT"), "{app:?}");
}

#[test]
fn fstring_interp_with_brackets_no_brace_skipped() {
    let app = fstring_reassembled("{f(a[b])}tail");
    assert!(app.contains("tail_KCONT"), "{app:?}");
}

#[test]
fn fstring_interp_with_plain_string_no_brace_skipped() {
    let app = fstring_reassembled("{d['key']}tail");
    assert!(app.contains("tail_KCONT"), "{app:?}");
    assert!(!app.contains("key"), "{app:?}");
}

#[test]
fn fstring_consecutive_interps_with_brace_strings() {
    let app = fstring_reassembled("{a['}']}{b['{']}z");
    assert!(app.contains("z_KCONT"), "{app:?}");
    assert!(
        !app.contains("']"),
        "no expression fragment may leak: {app:?}"
    );
}

#[test]
fn fstring_no_interpolation_is_verbatim() {
    let app = fstring_reassembled("plainbody123");
    assert!(app.contains("plainbody123_KCONT"), "{app:?}");
}

#[test]
fn fstring_empty_interpolation_is_dropped() {
    let app = fstring_reassembled("a{}b");
    assert!(app.contains("ab_KCONT"), "{app:?}");
}

#[test]
fn fstring_var_with_underscores_is_dropped() {
    let app = fstring_reassembled("{my_secret_var}realbody");
    assert!(app.contains("realbody_KCONT"), "{app:?}");
    assert!(!app.contains("my_secret_var"), "{app:?}");
}

#[test]
fn fstring_interp_then_escaped_brace_literal() {
    let app = fstring_reassembled("{alpha}{{lit}}");
    assert!(app.contains("{lit}_KCONT"), "{app:?}");
    assert!(!app.contains("alpha"), "{app:?}");
}

#[test]
fn uppercase_f_prefix_enables_interpolation_skip() {
    // The `F"..."` (capital) prefix must also enable interpolation handling.
    let p = pre("tok = F\"ghp_{user}y\" \\\n    \"_KCONT\"\n");
    let app = p.text[p.original_end..].to_string();
    assert!(app.contains("ghp_y_KCONT"), "{app:?}");
    assert!(!app.contains("user"), "{app:?}");
}

#[test]
fn non_fstring_braces_are_preserved_verbatim() {
    // A plain (non-`f`) string must keep its braces (they are not interpolation).
    let p = pre("tok = \"a{b}c\" \\\n    \"_KCONT\"\n");
    let app = p.text[p.original_end..].to_string();
    assert!(
        app.contains("a{b}c_KCONT"),
        "non-f-string braces must survive: {app:?}"
    );
}
