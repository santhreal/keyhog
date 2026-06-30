//! Recall + precision lock for PHP / Perl `.`-operator string concatenation
//! (task #109). PHP and Perl join string literals with `.`:
//!
//!   $token = "ghp_" . "abcdef" . "012345";   // PHP
//!   my $key = "AKIA" . "Z7Q2LMN4XKCD9PQR";   // Perl
//!
//! The `+`-concatenation path (Java/JS/Python/C#) never matched these, so a
//! secret split across `.` joins slipped through. The dot extractor reassembles
//! the joined literal so the contiguous secret surfaces — while staying STRICT
//! so the overloaded `.` (member access, floats, path separators, file
//! extensions) never fabricates a candidate.
//!
//! Source under test:
//!   * `crates/scanner/src/multiline/string_extract.rs`
//!         (`extract_dot_concatenation`, `first_quoted_literal`,
//!          `split_concatenation_operators`)
//!   * `crates/scanner/src/multiline/config.rs`
//!         (`MultilineConfig::dot_concatenation`, `has_concatenation_indicators`
//!          dot-join indicators)
//!   * `crates/scanner/src/multiline/preprocessor.rs`
//!         (`process_line_chain` DotOperator continuation join)
//!
//! Positive tests assert the reassembled value is present in the preprocessed
//! buffer (the same proof model as the `+`-concat gap tests); precision tests
//! assert an overloaded `.` is NOT turned into a join; the e2e tests drive the
//! real `CompiledScanner::scan` path so a dot-split AWS key actually surfaces.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig, PreprocessedText};
use keyhog_scanner::CompiledScanner;

// ── helpers ──────────────────────────────────────────────────────────────

fn pre(text: &str) -> PreprocessedText<'_> {
    preprocess_multiline(
        std::borrow::Cow::Borrowed(text),
        &MultilineConfig::default(),
        &FragmentCache::new(100),
    )
}

fn pre_cfg<'a>(text: &'a str, config: &MultilineConfig) -> PreprocessedText<'a> {
    preprocess_multiline(
        std::borrow::Cow::Borrowed(text),
        config,
        &FragmentCache::new(100),
    )
}

/// The bytes appended past the original input (the reassembled join region).
fn appended(p: &PreprocessedText<'_>) -> String {
    p.text[p.original_end..].to_string()
}

fn scan(text: &str) -> Vec<RawMatch> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("config.php".into()),
            ..Default::default()
        },
    };
    scanner.scan(&chunk)
}

// ── POSITIVE: reassembly across quote styles ───────────────────────────────

#[test]
fn inline_two_double_quoted_literals_reassemble() {
    let p = pre("$token = \"ALPHA111\" . \"BETA222\";\n");
    assert!(p.text.contains("ALPHA111BETA222"), "{:?}", p.text);
}

#[test]
fn inline_three_literals_reassemble() {
    let p = pre("$k = \"AAA1\" . \"BBB2\" . \"CCC3\";\n");
    assert!(p.text.contains("AAA1BBB2CCC3"), "{:?}", p.text);
}

#[test]
fn single_quoted_literals_reassemble() {
    // Perl/PHP single-quoted strings join the same way; the `' .` indicator
    // gates this form.
    let p = pre("$k = 'GAMMA33' . 'DELTA44';\n");
    assert!(p.text.contains("GAMMA33DELTA44"), "{:?}", p.text);
}

#[test]
fn three_part_api_key_reassembles() {
    let p = pre("$apikey = \"PARTX_\" . \"PARTY_\" . \"PARTZ99\";\n");
    assert!(p.text.contains("PARTX_PARTY_PARTZ99"), "{:?}", p.text);
}

#[test]
fn extra_spaces_around_dot_reassemble() {
    let p = pre("$k = \"WIDE11\"  .   \"GAP22\";\n");
    assert!(p.text.contains("WIDE11GAP22"), "{:?}", p.text);
}

// ── POSITIVE: trailing-dot line continuation ───────────────────────────────

#[test]
fn trailing_dot_continuation_reassembles_across_lines() {
    let p = pre("$token = \"MULTIA\" .\n         \"MULTIB\";\n");
    assert!(p.text.contains("MULTIAMULTIB"), "{:?}", p.text);
}

#[test]
fn trailing_dot_three_line_chain() {
    let p = pre("$k = \"P1AAA\" .\n     \"P2BBB\" .\n     \"P3CCC\";\n");
    assert!(p.text.contains("P1AAAP2BBBP3CCC"), "{:?}", p.text);
}

#[test]
fn embedded_in_larger_file_reassembles() {
    // Not led by `<` (that trips the XML/HTML passthrough guard, by design).
    let text = "# app config\n$cfg = load();\n$token = \"EMBEDA9\" . \"EMBEDB8\";\nreturn $cfg;\n";
    let p = pre(text);
    assert!(p.text.contains("EMBEDA9EMBEDB8"), "{:?}", p.text);
}

// ── POSITIVE: adjacent literals reassemble, trailing non-literal dropped ─────

#[test]
fn trailing_runtime_segment_dropped_adjacent_literals_kept() {
    // The two leading literals are adjacent (`"a" . "b"`), so they reassemble;
    // a trailing runtime segment (`. $logsuffix`) is not literal bytes and is
    // dropped from the candidate.
    let p = pre("$x = \"ADJA11\" . \"ADJB22\" . $logsuffix;\n");
    assert!(p.text.contains("ADJA11ADJB22"), "{:?}", p.text);
    assert!(!appended(&p).contains("logsuffix"), "appended={:?}", appended(&p));
}

#[test]
fn trailing_constant_segment_dropped_adjacent_literals_kept() {
    let p = pre("$x = \"SEKRET99\" . \"MORE88\" . PHP_EOL;\n");
    assert!(p.text.contains("SEKRET99MORE88"), "{:?}", p.text);
    assert!(!appended(&p).contains("PHP_EOL"), "appended={:?}", appended(&p));
}

// ── POSITIVE: layout robustness ────────────────────────────────────────────

#[test]
fn leading_indentation_handled() {
    let p = pre("        $k = \"INDENTA\" . \"INDENTB\";\n");
    assert!(p.text.contains("INDENTAINDENTB"), "{:?}", p.text);
}

#[test]
fn trailing_semicolon_stripped_from_last_segment() {
    // The closing `"` ends the literal; the trailing `;` must not bleed into the
    // reassembled value.
    let p = pre("$k = \"SEMIA11\" . \"SEMIB22\";\n");
    assert!(p.text.contains("SEMIA11SEMIB22"), "{:?}", p.text);
    assert!(!appended(&p).contains("SEMIB22;"), "appended={:?}", appended(&p));
}

#[test]
fn escaped_quote_inside_literal_does_not_break_join() {
    // The splitter's quote tracking honors `\"`, so the join `.` after the REAL
    // closing quote is found — the segment is not ended early at the escaped
    // quote.
    let p = pre("$k = \"AAA\\\"BBB\" . \"CCC777\";\n");
    assert!(p.text.contains("BBBCCC777"), "{:?}", p.text);
}

#[test]
fn perl_my_assignment_dot_concat() {
    let p = pre("my $key = \"PERLX1\" . \"PERLY2\";\n");
    assert!(p.text.contains("PERLX1PERLY2"), "{:?}", p.text);
}

// ── POSITIVE: exactness / structure ────────────────────────────────────────

#[test]
fn reassembled_value_has_no_separator_between_parts() {
    let p = pre("$k = \"NOSEP11\" . \"NOSEP22\";\n");
    let app = appended(&p);
    assert!(app.contains("NOSEP11NOSEP22"), "appended={app:?}");
    // No `.`, space, or quote survives between the two reassembled fragments.
    assert!(!app.contains("NOSEP11 "), "appended={app:?}");
    assert!(!app.contains("NOSEP11."), "appended={app:?}");
    assert!(!app.contains("NOSEP11\""), "appended={app:?}");
}

#[test]
fn original_text_preserved_alongside_append() {
    let text = "$k = \"ORIGA11\" . \"ORIGB22\";\n";
    let p = pre(text);
    // The original source is preserved verbatim at the head; the reassembly is
    // appended past `original_end`.
    assert!(p.text.starts_with(text), "{:?}", p.text);
    assert_eq!(p.original_end, text.len());
    assert!(appended(&p).contains("ORIGA11ORIGB22"));
}

#[test]
fn appended_region_excludes_lhs_keyword_and_identifier() {
    let p = pre("$secret_token = \"LHSA111\" . \"LHSB222\";\n");
    let app = appended(&p);
    assert!(app.contains("LHSA111LHSB222"), "appended={app:?}");
    assert!(!app.contains("secret_token"), "appended={app:?}");
}

// ── PRECISION: non-adjacent / overloaded `.` is NOT a join ─────────────────

#[test]
fn runtime_variable_separated_literals_not_reassembled() {
    // Two literals separated by a runtime variable are NOT adjacent, so the
    // join is not recognized — reassembling them would fabricate a partial value
    // (`PRE111POST222`) the real secret never had.
    let p = pre("$x = \"PRE111\" . $mid . \"POST222\";\n");
    assert!(!p.text.contains("PRE111POST222"), "{:?}", p.text);
}

#[test]
fn function_call_separated_literals_not_reassembled() {
    let p = pre("$x = \"PRE333\" . trim($y) . \"POST444\";\n");
    assert!(!p.text.contains("PRE333POST444"), "{:?}", p.text);
}

#[test]
fn function_argument_string_not_promoted_to_join() {
    // A function call (with its own string argument) separates the literals, so
    // no join is recognized: neither a `KEEPA1KEEPB2` partial nor the argument
    // `DROPME` is promoted into a reassembled candidate.
    let p = pre("$x = \"KEEPA1\" . substr(\"DROPME\", 0) . \"KEEPB2\";\n");
    assert!(!p.text.contains("KEEPA1KEEPB2"), "{:?}", p.text);
    assert!(!p.text.contains("KEEPA1DROPME"), "{:?}", p.text);
}

#[test]
fn dotted_hostname_value_not_split() {
    let text = "$host = \"api.example.com\";\n";
    let p = pre(text);
    assert!(!p.text.contains("apiexamplecom"), "{:?}", p.text);
    assert!(p.text.contains("api.example.com"), "value preserved: {:?}", p.text);
}

#[test]
fn version_string_not_split() {
    let p = pre("$v = \"1.2.3-beta\";\n");
    assert!(!p.text.contains("123-beta"), "{:?}", p.text);
    assert!(!p.text.contains("123beta"), "{:?}", p.text);
}

#[test]
fn url_with_dots_not_split() {
    let p = pre("$u = \"https://a.b.c/path\";\n");
    assert!(!p.text.contains("abc/path"), "{:?}", p.text);
    assert!(p.text.contains("https://a.b.c/path"), "{:?}", p.text);
}

#[test]
fn float_literal_not_concatenated() {
    let p = pre("$ratio = 3.14159;\n");
    assert!(!p.text.contains("314159"), "{:?}", p.text);
}

#[test]
fn method_call_chain_not_concatenated() {
    let p = pre("$out = obj.method().other();\n");
    // No quoted literals at all: nothing to reassemble, text unchanged.
    assert_eq!(p.text, "$out = obj.method().other();\n");
}

#[test]
fn explode_dot_argument_not_concatenated() {
    // The `.` lives INSIDE a single quoted literal (`"."`), and there is only
    // one quoted literal, so the two-literal guard rejects it.
    let p = pre("$parts = explode(\".\", $serialized);\n");
    assert!(!appended(&p).contains("explode"), "appended={:?}", appended(&p));
    // `.` was not promoted to a join: the lone `.` literal is untouched.
    assert!(p.text.contains("explode(\".\", $serialized)"), "{:?}", p.text);
}

#[test]
fn array_index_member_access_not_concatenated() {
    let p = pre("$len = $arr[\"key\"].length;\n");
    // `"key"` is one quoted literal; the `.length` member access is not a join.
    assert!(!p.text.contains("keylength"), "{:?}", p.text);
}

#[test]
fn config_dotted_key_not_split() {
    // The `.` is inside the single quoted key (`"db.host"`); not a join.
    let p = pre("$h = $cfg[\"db.host\"];\n");
    assert!(!p.text.contains("dbhost"), "{:?}", p.text);
    assert!(p.text.contains("db.host"), "{:?}", p.text);
}

#[test]
fn single_quoted_literal_with_internal_dots_preserved() {
    let p = pre("$x = 'a.b.c.d';\n");
    assert!(!p.text.contains("abcd"), "{:?}", p.text);
    assert!(p.text.contains("a.b.c.d"), "{:?}", p.text);
}

// ── CONFIG TOGGLE ──────────────────────────────────────────────────────────

#[test]
fn dot_concatenation_disabled_does_not_reassemble() {
    let cfg = MultilineConfig {
        dot_concatenation: false,
        ..Default::default()
    };
    let p = pre_cfg("$k = \"SEKRETALPHA\" . \"SEKRETBETA\";\n", &cfg);
    assert!(
        !p.text.contains("SEKRETALPHASEKRETBETA"),
        "disabled toggle must not reassemble: {:?}",
        p.text
    );
}

#[test]
fn default_config_enables_dot_concatenation() {
    assert!(MultilineConfig::default().dot_concatenation);
}

// ── E2E: real scan path ────────────────────────────────────────────────────

#[test]
fn e2e_scan_dot_concatenated_aws_key_fires() {
    // `AKIA` and its 16-char body live in SEPARATE quoted literals, so the
    // contiguous `AKIA…` never appears in the original line — only the dot-concat
    // reassembly produces it. A finding therefore proves the join worked.
    let matches = scan("$key = \"AKIA\" . \"Z7Q2LMN4XKCD9PQR\";\n");
    assert!(
        matches
            .iter()
            .any(|m| m.credential.as_ref().contains("AKIAZ7Q2LMN4XKCD9PQR")),
        "dot-split AWS key must surface via reassembly: {:?}",
        matches.iter().map(|m| m.credential.as_ref()).collect::<Vec<_>>()
    );
}

#[test]
fn e2e_scan_dot_concatenated_aws_key_attributed_to_aws_detector() {
    let m = scan("$key = \"AKIA\" . \"Z7Q2LMN4XKCD9PQR\";\n")
        .into_iter()
        .find(|m| m.credential.as_ref().contains("AKIAZ7Q2LMN4XKCD9PQR"))
        .expect("reassembled AWS key recovered");
    assert_eq!(m.detector_id.as_ref(), "aws-access-key");
    assert_eq!(m.service.as_ref(), "aws");
}

#[test]
fn e2e_benign_dot_concat_does_not_fabricate_aws_key() {
    // A benign dot-concatenation (`"us" . "east" . "1"` -> `useast1`) must not
    // be reassembled INTO a spurious AWS finding.
    let matches = scan("$region = \"us\" . \"east\" . \"1\";\n");
    assert!(
        !matches.iter().any(|m| m.detector_id.as_ref() == "aws-access-key"),
        "benign dot-concat must not fabricate an AWS key: {:?}",
        matches.iter().map(|m| m.detector_id.as_ref()).collect::<Vec<_>>()
    );
}

#[test]
fn e2e_dotted_hostname_does_not_fire_aws() {
    let matches = scan("$endpoint = \"sts.amazonaws.com\";\n");
    assert!(
        !matches.iter().any(|m| m.detector_id.as_ref() == "aws-access-key"),
        "a dotted hostname is not a key: {:?}",
        matches.iter().map(|m| m.detector_id.as_ref()).collect::<Vec<_>>()
    );
}
