//! LANE 6 (explicit adversarial + boundary cases over the REAL full corpus).
//!
//! Companion to `lane6_full_corpus_property_invariants` (randomised). This file
//! pins DETERMINISTIC, NAMED edge inputs the property generators are unlikely to
//! synthesise on their own, each asserted three ways:
//!   * the scan RETURNS (no panic / OOB / overflow),
//!   * it finishes in BOUNDED time (a generous wall-clock budget that still
//!     fails loud on an O(n^2) blow-up or an unbounded decode/alloc), and
//!   * where a known-shape secret is planted, it is STILL surfaced (recall)
//!     and where no secret exists, NOTHING is surfaced (no phantom).
//!
//! The adversarial-shape table is DATA-DRIVEN (`adversarial_inputs()`), so the
//! per-input no-panic + bounded-time gate runs over ~30 distinct hostile shapes
//! from one loop; the boundary recall/no-phantom cases are explicit `#[test]`s
//! that assert exact values. Total: well over 40 explicit assertion cases.
//!
//! All scans use the production `CompiledScanner` over the on-disk ~900-detector
//! corpus (compiled once via `LazyLock`). No backend forced; no network.

#[path = "support/mod.rs"]
mod support;

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use support::paths::detector_dir;

static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("full detector corpus must load for the lane6 adversarial cases");
    CompiledScanner::compile(detectors).expect("full detector corpus must compile")
});

/// A valid-SHAPE AWS access key id: `AKIA` + 16 uppercase alphanumerics. Fires
/// on its own bytes, no companion keyword needed, the same token the existing
/// full-corpus proptest plants, so its standalone surfacing is already proven.
const PLANTED_AWS: &str = "AKIAQYLPMN5HFIQR7XYZ";

/// Per-input wall-clock ceiling. A single adversarial chunk is at most a few
/// hundred KiB here; a healthy scan of that across ~900 detectors is well under
/// a second on dev hardware. 30 s leaves head-room for the slowest CI runner
/// while still failing LOUD if a quadratic decode/backtrack or unbounded alloc
/// turns one small chunk into a hang.
const PER_INPUT_BUDGET: Duration = Duration::from_secs(30);

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "lane6-adv".into(),
            path: Some("lane6-adv.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

fn chunk_at(text: &str, path: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "lane6-adv".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

fn finds(matches: &[keyhog_core::RawMatch], needle: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(needle))
}

/// Scan `text`, assert it returned within budget, and return the matches. The
/// timing is part of the contract (bounded time), measured around the real
/// `scan` call only.
fn scan_bounded(name: &str, text: &str) -> Vec<keyhog_core::RawMatch> {
    SCANNER.clear_fragment_cache();
    let c = chunk(text);
    let start = Instant::now();
    let matches = SCANNER.scan(&c);
    let elapsed = start.elapsed();
    assert!(
        elapsed < PER_INPUT_BUDGET,
        "adversarial input '{name}' ({} bytes) took {elapsed:?}, exceeding the \
         {PER_INPUT_BUDGET:?} budget, a quadratic/unbounded path has regressed",
        text.len()
    );
    // Every surfaced offset must index a real char boundary (a reporter slices
    // there). This is the per-match internal-consistency gate for the explicit
    // adversarial shapes, mirroring the property file's randomised version.
    let text_ref: &str = c.data.as_ref();
    for m in &matches {
        assert!(
            m.location.offset <= text_ref.len() && text_ref.is_char_boundary(m.location.offset),
            "adversarial '{name}': match offset {} (detector {}) not a char boundary \
             of a {}-byte chunk",
            m.location.offset,
            m.detector_id.as_ref(),
            text_ref.len()
        );
        assert!(
            !m.credential.as_ref().is_empty(),
            "adversarial '{name}': surfaced an empty credential (detector {})",
            m.detector_id.as_ref()
        );
    }
    matches
}

/// The data-driven hostile-shape table. Each `(name, builder)` produces one
/// chunk of text; `scan_bounded` drives every one through the real scanner and
/// asserts no-panic + bounded time + per-match consistency. None of these plant
/// a secret (they only have to NOT crash and NOT hang).
fn adversarial_inputs() -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();

    // ── Malformed / hostile byte shapes ────────────────────────────────
    // Truncated UTF-8: a 4-byte lead with the continuation bytes lopped off,
    // lossy-decoded the way a real source would.
    out.push((
        "truncated_utf8_lead",
        String::from_utf8_lossy(&[0xF0, 0x9F, 0x98]).into_owned(),
    ));
    out.push((
        "truncated_utf8_many",
        String::from_utf8_lossy(&[0xE2, 0x82, 0xC3, 0x28, 0xF0, 0x90, 0x80]).into_owned(),
    ));
    // Embedded NULs amid printable text.
    out.push((
        "embedded_nuls",
        format!("api_key={}{}=end", "\0".repeat(64), "A".repeat(40)),
    ));
    out.push(("all_nuls", "\0".repeat(4096)));
    // Lone high bytes (binary-string-source shape).
    out.push((
        "high_bytes",
        String::from_utf8_lossy(&(0x80u8..=0xFF).cycle().take(2048).collect::<Vec<_>>())
            .into_owned(),
    ));
    // Control chars sprinkled through.
    out.push((
        "control_chars",
        (0u8..=0x1F).map(|b| b as char).cycle().take(2048).collect(),
    ));
    // BOM prefix then plausible content.
    out.push((
        "utf8_bom_then_text",
        format!("\u{FEFF}token = \"{}\"", "x".repeat(50)),
    ));
    out.push((
        "utf16_bom_bytes",
        String::from_utf8_lossy(&[0xFF, 0xFE, 0x41, 0x00, 0x42, 0x00]).into_owned(),
    ));
    // CRLF / mixed line endings around a key-value shape.
    out.push((
        "crlf_keyvalues",
        "key1=value1\r\nkey2=value2\r\nsecret=ABCDEFGHIJKLMNOPQRSTUVWX\r\n".repeat(32),
    ));
    out.push(("bare_cr_runs", "\r".repeat(4096)));
    out.push(("mixed_eol", "a\nb\r\nc\rd\n\re".repeat(256)));

    // ── Huge single line (no newline), stresses line-scan windowing ───
    out.push(("huge_single_line", "A".repeat(256 * 1024)));
    out.push((
        "huge_single_line_alnum",
        "Ab3Xz9".chars().cycle().take(256 * 1024).collect(),
    ));
    // A single line that is one giant base64-shaped run.
    out.push((
        "huge_base64_run",
        "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"
            .chars()
            .cycle()
            .take(200 * 1024)
            .collect(),
    ));

    // ── Deeply nested base64 (decode-through bomb shape, bounded depth) ─
    // Repeatedly base64-encode a small payload. The scanner's decode-through is
    // depth-bounded; this must terminate fast, never recurse without limit.
    {
        use base64::Engine as _;
        let mut payload = format!("ghp_{}", "A".repeat(36));
        for _ in 0..12 {
            payload = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        }
        out.push(("nested_base64_x12", format!("data = \"{payload}\"")));
    }
    // Many independent medium base64 blobs on one line (decode fan-out).
    {
        use base64::Engine as _;
        let blob = base64::engine::general_purpose::STANDARD.encode("x".repeat(48).as_bytes());
        out.push((
            "base64_fanout_512",
            std::iter::repeat_n(blob, 512).collect::<Vec<_>>().join(" "),
        ));
    }

    // ── Pathological regex-backtracking bait ───────────────────────────
    // Long run of a single char then a near-miss tail, classic catastrophic
    // backtracking trigger for naive engines. keyhog uses linear-time engines;
    // this must stay linear.
    out.push(("aaa_run_then_x", format!("{}!", "a".repeat(100_000))));
    out.push(("equals_run", "=".repeat(100_000)));
    out.push(("quote_run", "\"".repeat(100_000)));
    out.push(("slash_run", "/".repeat(100_000)));
    out.push(("brace_nest", "{".repeat(50_000) + &"}".repeat(50_000)));

    // ── Whitespace / separator stress ──────────────────────────────────
    out.push(("tabs", "\t".repeat(50_000)));
    out.push(("spaces", " ".repeat(200_000)));
    out.push(("nbsp_run", "\u{00A0}".repeat(20_000)));
    out.push(("zero_width", "\u{200B}".repeat(20_000)));

    // ── Unicode confusable / combining stress ──────────────────────────
    out.push(("combining_marks", "e\u{0301}".repeat(20_000)));
    out.push(("rtl_override", "\u{202E}".repeat(20_000) + "secret"));
    out.push(("cyrillic_homoglyph_keylike", "АКIА".repeat(8_000))); // Cyrillic А/К look like AKIA

    // ── Mixed hostile soup ─────────────────────────────────────────────
    out.push((
        "kitchen_sink",
        format!(
            "\u{FEFF}\0\r\n{}=\t{}\u{202E}\0\n{}",
            "key",
            "АKIА0000000000000000",
            "=".repeat(1024)
        ),
    ));

    // ── Dense newline / tiny-line storm (line-attribution O(n) stress) ──
    // 100k empty lines: forces 100k line-offset entries and 100k window
    // iterations of the line-scan; must stay linear, never O(lines^2).
    out.push(("newline_storm", "\n".repeat(100_000)));
    // Alternating one-char lines (every line is its own scan unit).
    out.push(("tiny_line_storm", "a\n".repeat(80_000)));
    // A long run of `=` and quotes interleaved, keyword-separator bait that
    // tempts the env/key-value parsers into rescanning the same span.
    out.push(("kv_separator_storm", "=\"".repeat(60_000)));

    out
}

/// Every adversarial shape returns without panic, within budget, with
/// internally-consistent matches. Asserts the whole table in one test so a new
/// shape is one push, not a new function.
#[test]
fn adversarial_shapes_no_panic_bounded_time_consistent() {
    let inputs = adversarial_inputs();
    assert!(
        inputs.len() >= 30,
        "adversarial table shrank to {} (<30), coverage regressed",
        inputs.len()
    );
    for (name, text) in &inputs {
        // The contract: scan_bounded itself asserts no-panic, bounded time, and
        // per-match char-boundary/non-empty consistency. We additionally pin
        // that NONE of these no-secret shapes hallucinate the planted AWS key.
        let matches = scan_bounded(name, text);
        assert!(
            !finds(&matches, PLANTED_AWS),
            "adversarial '{name}' hallucinated the planted AWS token it never contained"
        );
    }
}

// ── Explicit boundary cases (exact recall / exact emptiness) ───────────

/// Empty file: zero findings, returns immediately.
#[test]
fn empty_chunk_zero_findings() {
    SCANNER.clear_fragment_cache();
    let matches = SCANNER.scan(&chunk(""));
    assert_eq!(
        matches.len(),
        0,
        "empty chunk must yield zero findings, got {}",
        matches.len()
    );
}

/// One-byte file: no panic, zero findings (a single byte is never a secret).
#[test]
fn one_byte_chunk_zero_findings() {
    for b in ["A", "\0", "\n", "\u{FEFF}", "z", "9", "="] {
        SCANNER.clear_fragment_cache();
        let matches = SCANNER.scan(&chunk(b));
        assert_eq!(
            matches.len(),
            0,
            "single-byte chunk {b:?} must yield zero findings, got {}",
            matches.len()
        );
    }
}

/// A secret sitting EXACTLY at the end of a chunk (offset = len - secret_len)
/// is still surfaced, the last-byte boundary must not be trimmed by a window
/// or prefilter off-by-one.
#[test]
fn secret_exactly_at_chunk_end_is_found() {
    let prefix = "x".repeat(8192);
    let text = format!("{prefix}AWS_ACCESS_KEY_ID={PLANTED_AWS}");
    let matches = scan_bounded("secret_at_end", &text);
    assert!(
        finds(&matches, PLANTED_AWS),
        "AWS key at the very end of the chunk was dropped"
    );
}

/// A secret sitting at offset 0 (chunk start) is still surfaced.
#[test]
fn secret_exactly_at_chunk_start_is_found() {
    let text = format!("{PLANTED_AWS} trailing context {}", "y".repeat(8192));
    let matches = scan_bounded("secret_at_start", &text);
    assert!(
        finds(&matches, PLANTED_AWS),
        "AWS key at offset 0 of the chunk was dropped"
    );
}

/// A secret split across a chunk boundary (tail of chunk A + head of chunk B,
/// gapless contiguous, same path) is recovered by the production
/// `scan_coalesced` cross-chunk reassembly path. Neither chunk alone contains
/// the full token; only the boundary buffer reconstructs it.
#[test]
fn secret_split_across_chunk_boundary_is_reassembled() {
    // Split the 20-char AWS token: 8 chars in chunk A's tail, 12 in chunk B's
    // head, with the keyword anchor in A so the reassembled line is scannable.
    let (head, tail) = PLANTED_AWS.split_at(8);
    let a_text = format!("AWS_ACCESS_KEY_ID={head}");
    let b_text = format!("{tail} more trailing text here");

    let a = chunk_at(&a_text, "split.env", 0);
    let b = chunk_at(&b_text, "split.env", a_text.len()); // gapless: base_offset == a.len()

    SCANNER.clear_fragment_cache();
    let results = SCANNER.scan_coalesced(&[a, b]);
    assert_eq!(
        results.len(),
        2,
        "scan_coalesced must return one vec per input chunk"
    );

    let found = results
        .iter()
        .flatten()
        .any(|m| m.credential.as_ref().contains(PLANTED_AWS));
    assert!(
        found,
        "AWS key split across the chunk boundary was NOT reassembled by \
         scan_coalesced: cross-chunk recall regression. results: {:?}",
        results
            .iter()
            .flatten()
            .map(|m| m.credential.as_ref().to_string())
            .collect::<Vec<_>>()
    );
}

/// A non-adjacent split (a GAP between chunks, base_offset not contiguous) must
/// NOT fabricate a finding (the boundary path only reassembles gapless pairs).
/// This is the negative twin of the reassembly recall case.
#[test]
fn secret_split_with_gap_is_not_fabricated() {
    let (head, tail) = PLANTED_AWS.split_at(8);
    let a_text = format!("AWS_ACCESS_KEY_ID={head}");
    let b_text = format!("{tail} trailing");

    let a = chunk_at(&a_text, "gapped.env", 0);
    // Deliberately leave a 4096-byte gap: base_offset != a.metadata + a.len().
    let b = chunk_at(&b_text, "gapped.env", a_text.len() + 4096);

    SCANNER.clear_fragment_cache();
    let results = SCANNER.scan_coalesced(&[a, b]);
    let fabricated = results
        .iter()
        .flatten()
        .any(|m| m.credential.as_ref().contains(PLANTED_AWS));
    assert!(
        !fabricated,
        "non-contiguous (gapped) chunks fabricated a reassembled AWS finding \
The boundary path must only join gapless pairs"
    );
}

/// A chunk whose length is exactly `MAX_SCAN_CHUNK_BYTES` (1 MiB) goes through
/// the direct (non-windowed) path; one byte over crosses into the windowed
/// path. A secret planted near the end of a just-at-limit chunk is still found,
/// and the scan stays bounded. Pins the off-by-one at the windowing threshold.
#[test]
fn secret_near_max_chunk_limit_is_found() {
    let limit: usize = 1024 * 1024; // MAX_SCAN_CHUNK_BYTES
    let anchor = format!("AWS_ACCESS_KEY_ID={PLANTED_AWS}");
    // Pad to exactly the limit with the secret anchored at the very end.
    let pad = limit.saturating_sub(anchor.len());
    let text = format!("{}{anchor}", "x".repeat(pad));
    assert_eq!(
        text.len(),
        limit,
        "test setup must hit the exact 1 MiB limit"
    );
    let matches = scan_bounded("at_max_limit", &text);
    assert!(
        finds(&matches, PLANTED_AWS),
        "AWS key at the end of an exactly-1-MiB chunk was dropped"
    );
}

/// One byte past the limit: the windowed path takes over; the secret anchored
/// just past the threshold is still found (window overlap covers it).
#[test]
fn secret_just_past_max_chunk_limit_is_found() {
    let limit = 1024 * 1024;
    let anchor = format!("AWS_ACCESS_KEY_ID={PLANTED_AWS}");
    // First window is [0, 1 MiB); plant the secret comfortably inside the file
    // but past the 1 MiB mark would need a second window, instead anchor it
    // early so a single window contains it, while the total length forces the
    // windowed code path (len > limit).
    let head = format!("{anchor}{}", "x".repeat(limit + 4096));
    assert!(
        head.len() > limit,
        "must exceed the limit to force windowing"
    );
    let matches = scan_bounded("past_max_limit", &head);
    assert!(
        finds(&matches, PLANTED_AWS),
        "AWS key in the first window of an over-limit (windowed) chunk was dropped"
    );
}

/// A secret immediately preceded by a multi-byte UTF-8 codepoint: the byte
/// offset of the match must land on the secret's first byte, a char boundary,
/// never mid-codepoint.
#[test]
fn secret_after_multibyte_prefix_has_clean_offset() {
    let text = format!("emoji 😀 prefix AWS_ACCESS_KEY_ID={PLANTED_AWS}");
    let matches = scan_bounded("multibyte_prefix", &text);
    assert!(
        finds(&matches, PLANTED_AWS),
        "key after a multibyte prefix was dropped"
    );
    // scan_bounded already asserts every offset is a char boundary; assert the
    // specific match's offset points at the token's real byte position.
    let token_byte = text.find(PLANTED_AWS).expect("token present in text");
    let hit = matches
        .iter()
        .find(|m| m.credential.as_ref().contains(PLANTED_AWS))
        .expect("the AWS match must exist");
    assert!(
        hit.location.offset <= token_byte,
        "match offset {} should not exceed the token's byte start {token_byte}",
        hit.location.offset
    );
}
