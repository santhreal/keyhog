// Doc-hidden scanner test facade. Kept out of lib.rs so the crate root
// remains a module map and public API surface, not a test-probe dumping ground.

#[cfg(test)]
use keyhog_core::Chunk;
#[cfg(test)]
use std::sync::{Mutex, MutexGuard, OnceLock};

#[cfg(test)]
pub(crate) use crate::engine::scan_chunk_boundaries;
#[cfg(all(test, feature = "simd"))]
pub(crate) use crate::simd::backend::HsScanner;
#[cfg(all(test, feature = "simd"))]
pub(crate) const REGEX_SIZE_LIMIT_BYTES: usize = crate::types::REGEX_SIZE_LIMIT_BYTES;

pub fn pattern_regex_strs(scanner: &crate::CompiledScanner) -> Vec<&str> {
    scanner.pattern_regex_strs()
}

/// Production scan-window ceiling used by behavioral tests that must force the
/// real windowed path without duplicating its tuning constant.
pub fn max_scan_chunk_bytes() -> usize {
    crate::types::MAX_SCAN_CHUNK_BYTES
}

/// SPEED/som-window (backlog 4786) lever-ceiling analysis: classify the CONFIRMED
/// `ac_map` patterns of the embedded detector corpus by how they can be localized
/// in the scan window, returning
/// `(prefix_anchored, prefixless_with_internal_literal, whole_chunk_residue)`:
/// - `prefix_anchored`: has a required PREFIX literal; already localized to
///   candidate positions by `ConfirmedAnchorIndex` (no whole-chunk scan).
/// - `prefixless_with_internal_literal`: no required prefix literal BUT has a
///   required internal literal run (≥ `MIN_INNER_LITERAL_CHARS`); this is the set
///   an internal-literal-AC extension of `ConfirmedAnchorIndex` could localize
///   (the addressable ceiling of the 4786 lever). HS-SOM is NOT viable for these
///   (it errors "Pattern too large" on complex regexes (see simd/backend.rs)).
/// - `whole_chunk_residue`: no required literal run at all; irreducibly
///   whole-chunk-scanned.
///
/// The three buckets partition the confirmed `ac_map`. This is the durable
/// introspection behind the 4786 scoping decision (how much of the whole-chunk
/// confirmed-pass cost is actually localizable).
pub fn confirmed_pattern_localization_distribution() -> (usize, usize, usize) {
    let detectors = keyhog_core::load_embedded_detectors_or_fail()
        .expect("embedded detector corpus must parse");
    let scanner = crate::CompiledScanner::compile_with_gpu_policy(
        detectors,
        crate::GpuInitPolicy::ForceDisabled,
    )
    .expect("embedded detector corpus must compile without GPU acquisition");
    let mut prefix_anchored = 0usize;
    let mut prefixless_with_internal_literal = 0usize;
    let mut whole_chunk_residue = 0usize;
    for pattern in &scanner.ac_map {
        let src = pattern.regex.as_str();
        if crate::engine::required_prefix_literals_with_cap(
            src,
            crate::engine::CONFIRMED_MAX_LITERALS_PER_PATTERN,
        )
        .is_some()
        {
            prefix_anchored += 1;
        } else if crate::compiler::compiler_prefix::regex_has_required_literal_run(
            src,
            crate::compiler::compiler_prefix::MIN_INNER_LITERAL_CHARS,
        ) {
            prefixless_with_internal_literal += 1;
        } else {
            whole_chunk_residue += 1;
        }
    }
    (
        prefix_anchored,
        prefixless_with_internal_literal,
        whole_chunk_residue,
    )
}

/// Process-wide count of `LazyRegex` first-use compilations (see
/// `crate::types::lazy_regex_compile_events`). The zero-recompile regression gate
/// snapshots this around `warm()` + repeated scans to prove steady-state scanning
/// rebuilds no regex - locking the #13 "cache the pattern compile" fix.
pub fn lazy_regex_compile_events() -> u64 {
    crate::types::lazy_regex_compile_events()
}

/// The absolute path to a crate source file given a path **relative to this
/// crate's manifest root** (`crates/scanner/`).
///
/// The value is anchored to the compile-time [`CARGO_MANIFEST_DIR`] constant,
/// so it is fully independent of the process working directory. Exposed
/// alongside [`read_crate_source`] for tests that need the path itself
/// (existence checks, `Path` operations) rather than the contents.
///
/// [`CARGO_MANIFEST_DIR`]: https://doc.rust-lang.org/cargo/reference/environment-variables.html
pub fn crate_source_path(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Read a crate source file by its manifest-root-relative path, independent of
/// the process working directory.
///
/// Source-introspection tests (e.g. "this module routes through the shared
/// predicate", "this file keeps exactly one copy of the helper") read crate
/// source files off disk. A bare `read_to_string("src/...")` resolves the
/// relative path against the *process* CWD, which only equals the package root
/// under a plain `cargo test`. That makes the read break when the test binary
/// is run directly, under `cargo-nextest` (which sets CWD to the workspace
/// root, not the package), or whenever a sibling test mutates the global CWD
/// turning a deterministic structural check into a parallel-load `NotFound`
/// flake. Anchoring to [`crate_source_path`] (compile-time `CARGO_MANIFEST_DIR`)
/// makes the read deterministic from any CWD and under any runner.
///
/// This is the ONE canonical crate-source reader for tests; the
/// `no_cwd_relative_source_reads` gate forbids re-open-coding
/// `read_to_string("src/...")` so the bug class cannot return.
///
/// Panics with the resolved absolute path when the file is missing, so a typo
/// in `rel` is an obvious failure rather than a silent empty string.
pub fn read_crate_source(rel: &str) -> String {
    let path = crate_source_path(rel);
    match std::fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) => panic!("read crate source {}: {error}", path.display()),
    }
}

/// Resolver tie-break priority for a synthetic match. Exposes the private
/// `resolution::match_priority` so a behavioral gap test can pin the named
/// weight constants (in particular `KNOWN_PREFIX_SERVICE_BONUS`) from the
/// observable priority difference between two otherwise-identical matches.
pub fn match_priority_for_test(
    detector_id: &str,
    credential: &str,
    confidence: Option<f64>,
) -> f64 {
    let service = keyhog_core::detector_spec_by_id(detector_id)
        .map(|spec| std::sync::Arc::from(spec.service.as_str()))
        .unwrap_or_else(|| {
            std::sync::Arc::from(
                if crate::detector_ids::is_generic_or_entropy_detector(detector_id) {
                    "generic"
                } else {
                    "test"
                },
            )
        });
    let m = keyhog_core::RawMatch {
        detector_id: std::sync::Arc::from(detector_id),
        detector_name: std::sync::Arc::from(detector_id),
        service,
        severity: keyhog_core::Severity::High,
        credential: keyhog_core::SensitiveString::from(credential),
        credential_hash: [0u8; 32].into(),
        companions: std::collections::HashMap::new(),
        location: keyhog_core::MatchLocation {
            source: std::sync::Arc::from("unit"),
            file_path: Some(std::sync::Arc::from("unit.env")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence,
    };
    crate::resolution::match_priority(&m)
}

/// Resolution's "service-specific detector" predicate, exposed so a gap test can
/// pin that it stays identical to the canonical `is_service_anchored_detector`
/// (the two were a duplicated, drift-prone predicate before consolidation).
pub fn is_service_specific_detector_for_test(detector_id: &str) -> bool {
    crate::resolution::is_service_specific_detector(detector_id)
}

/// The canonical detector-anchoring predicate that the resolution predicate now
/// delegates to.
pub fn is_service_anchored_detector_for_test(detector_id: &str) -> bool {
    crate::detector_ids::is_service_anchored_detector(detector_id)
}

/// Test seam for the pre-decode encoded-value extractor: returns each extracted
/// candidate as `(value, start, end)` so a gap test can pin the exact spans the
/// single-pass scan pulls from quoted strings and `key = value` assignments,
/// including the minimum-length floor that drops sub-4-char values.
pub fn extract_encoded_value_spans_for_test(text: &str) -> Vec<(String, usize, usize)> {
    crate::decode::with_extracted_value_spans(text, |spans| {
        spans
            .iter()
            .filter_map(|v| v.span().map(|(s, e)| (v.value.clone(), s, e)))
            .collect()
    })
}

/// Test seam for the decode-splice newline counter (now a `memchr` SIMD count):
/// the per-decoded-candidate parent-prefix newline tally that fixes the spliced
/// chunk's `base_line`. Lets a gap test pin that the count is exact.
pub fn bytecount_newlines_for_test(bytes: &[u8]) -> usize {
    crate::decode::bytecount_newlines(bytes)
}

/// Test seam for the protobuf-wire decode-structure verdict: parse `data` as a
/// protobuf wire stream and return whether it consumes the whole buffer as
/// >= 3 valid (tag, value) fields. Lets a gap test pin that fixed-width fields
/// (wire 1 = 64-bit, wire 5 = 32-bit) share one bounds-checked advance and that
/// truncation / too-few-fields fail closed.
pub fn parse_protobuf_wire_for_test(data: &[u8]) -> bool {
    crate::decode_structure::parse_protobuf_wire(data)
}

/// Test seam for the placeholder-word boundary + entropy-collision gate: does
/// `token_upper` (an already-uppercased placeholder word, e.g. `"EXAMPLE"`)
/// suppress `credential`? Pins that a both-sided word boundary always
/// suppresses, a one-sided match suppresses only when the credential is NOT a
/// long high-entropy `+`/`/` secret, and the exact entropy threshold at which a
/// one-sided match flips from suppress to collision (driven by `entropy_hint`).
pub fn placeholder_word_suppresses_for_test(
    credential: &str,
    token_upper: &str,
    entropy_hint: Option<f64>,
) -> bool {
    let upper = credential.to_ascii_uppercase();
    crate::placeholder_words::placeholder_word_suppresses(
        credential,
        &upper,
        token_upper,
        entropy_hint,
    )
}

/// Test seam for the Caesar/ROT-N letter rotation: shift `input`'s ASCII
/// letters forward by `shift` (mod the alphabet length), leaving digits and
/// punctuation untouched. Lets a gap test pin the exact rotated string,
/// including wraparound and the digit/punct identity.
#[cfg(feature = "decode")]
pub fn caesar_shift_for_test(input: &str, shift: u8) -> String {
    crate::decode::caesar::caesar_shift(input, shift)
}

/// Test seam for the reverse decoder's string reversal: reverse `s` by
/// Unicode scalar (not byte), so a gap test can pin the exact reversed string.
#[cfg(feature = "decode")]
pub fn reverse_str_for_test(s: &str) -> String {
    crate::decode::reverse::reverse_str(s)
}

/// Test seam for the quoted-printable decoder: `=XX` hex octets decode to the
/// byte; `=`-before-newline soft line breaks (`=\n`, `=\r\n`, `=\r`) are removed
/// so a secret a QP encoder wrapped across a soft break stays contiguous; a
/// non-hex `=X` or a trailing `=` is a literal. (The `_`→space rule is MIME
/// Q-encoding, not plain QP, and is deliberately NOT applied here.) Returns
/// `None` when the decoded bytes are not valid UTF-8.
#[cfg(feature = "decode")]
pub fn quoted_printable_decode_for_test(input: &str) -> Option<String> {
    match crate::decode::quoted_printable_decode(input) {
        Ok(decoded) => Some(decoded),
        Err(()) => None,
    }
}

/// Test seam for the RFC2047 MIME encoded-word decoder (`=?charset?enc?text?=`,
/// used to hide non-ASCII, and secrets, in email/HAR headers). `B` is base64,
/// `Q` is quoted-printable-like (`_`→space, `=XX` hex); the encoding letter is
/// case-insensitive and the charset label is ignored (the raw bytes are what
/// scanning wants). Returns `None` on a malformed word (missing `=?`/`?=`, an
/// unknown encoding, a decode failure) or when the decoded bytes are not valid
/// UTF-8. Lets a gap test pin the B/Q dispatch and boundary handling exactly.
#[cfg(feature = "decode")]
pub fn mime_encoded_word_decode_for_test(input: &str) -> Option<String> {
    match crate::decode::mime_encoded_word_decode(input) {
        Ok(decoded) => Some(decoded),
        Err(()) => None,
    }
}

/// Test seam for the C-style octal escape decoder (`\NNN`, 1–3 octal digits per
/// escape). A short or non-3-digit escape decodes to its byte value instead of
/// aborting the whole candidate; values above 0o377 wrap mod 256. Each byte
/// becomes `char::from(u8)` (Latin-1), so decoding never fails on the byte
/// values themselves; `None` means the input contained no `\`-escape at all
/// (nothing was decoded). Lets a gap test pin the greedy 1–3 digit consumption
/// and the mixed-escape recall behaviour exactly.
#[cfg(feature = "decode")]
pub fn octal_escape_decode_for_test(input: &str) -> Option<String> {
    match crate::decode::octal_escape_decode(input) {
        Ok(decoded) => Some(decoded),
        Err(()) => None,
    }
}

/// Test seam for the bounded gzip/zlib inflate on the decode-through recall path
/// (`decode::inflate::try_inflate_to_text`). Given decoded bytes beginning with a
/// gzip (`1f 8b`) or zlib (`78 {01,9c,da}`) magic, inflates them capped at
/// `MAX_INFLATE_BYTES` (16 MiB) and returns the UTF-8 text; `None` for
/// non-container bytes, malformed streams, or non-UTF-8 output. This is the
/// decompression-BOMB surface: a tiny blob can encode gigabytes, so the cap is a
/// hard DoS bound. Lets an adversarial test feed a real bomb and prove the output
/// never exceeds the cap (fails LOUDLY. OOM/hang, if the `Read::take` guard
/// regresses).
#[cfg(feature = "decode")]
pub fn try_inflate_to_text_for_test(bytes: &[u8]) -> Option<String> {
    crate::decode::inflate::try_inflate_to_text(bytes)
}

/// The inflate output ceiling (`MAX_INFLATE_BYTES`, 16 MiB) exposed so an
/// adversarial DoS test can assert the bomb-truncation bound against the real
/// constant instead of a hardcoded copy (ONE-PLACE).
#[cfg(feature = "decode")]
#[must_use]
pub fn inflate_output_cap_for_test() -> usize {
    crate::decode::inflate::MAX_INFLATE_BYTES as usize
}

/// Build a gzip container (`1f 8b …`) wrapping `data`, for use as an inflate
/// fixture. Uses the scanner's own `flate2` dep so the integration-test binary
/// which cannot link `flate2` directly, can still construct a decompression
/// bomb (compress a huge run of one byte into a tiny blob) and feed it to
/// [`try_inflate_to_text_for_test`]. Deterministic; no I/O.
#[cfg(feature = "decode")]
#[must_use]
pub fn gzip_compress_for_test(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(data)
        .expect("gzip encode into Vec never fails");
    enc.finish().expect("gzip finish into Vec never fails")
}

/// Build a zlib container (`78 9c …`) wrapping `data`, the zlib twin of
/// [`gzip_compress_for_test`] (exercises the `try_inflate_to_text` zlib branch).
#[cfg(feature = "decode")]
#[must_use]
pub fn zlib_compress_for_test(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data)
        .expect("zlib encode into Vec never fails");
    enc.finish().expect("zlib finish into Vec never fails")
}

/// Test seam for the decode-density gate on the main scan path
/// (`decode::has_decodable_payload`): recognizes encoded, escaped, and numeric
/// entity shapes worth routing into decode-through, including a
/// `MIN_DECODABLE_RUN` (24) contiguous base64/hex run, `MIN_PERCENT_ESCAPES` (4)
/// `%XX` escapes, `MIN_HTML_NUMERIC_ENTITIES` (4) valid numeric entities, or
/// `MIN_BACKSLASH_ESCAPES` (2) `\u`/`\x`/`\NNN` escapes. This gate is
/// recall-load-bearing (it routes an otherwise prefilter-skipped, fully-encoded
/// chunk into decode-through), so a silent threshold drift is a recall bug; this
/// seam lets a test pin the exact boundaries.
#[cfg(feature = "decode")]
pub fn has_decodable_payload_for_test(data: &[u8]) -> bool {
    crate::decode::has_decodable_payload(data)
}

/// Test seam for the reverse decoder's admission gate: a candidate is worth
/// reverse-decoding only when it has a `MIN_REVERSE_ALNUM_RUN`+ contiguous
/// ASCII-alphanumeric run AND its reversed form would contain a known provider
/// prefix. Lets a gap test pin both gates exactly.
#[cfg(feature = "decode")]
pub fn looks_reversible_for_test(candidate: &str) -> bool {
    crate::decode::reverse::looks_reversible(candidate)
}

/// Test seam for the shared `ASSIGN_RE` assignment-detection regex (the single
/// `key = "value"` source consumed by BOTH `engine` fragment reassembly and the
/// `multiline::structural` preprocessor). Returns the `(key, value)` capture
/// groups for one line, or `None` when the line is not a quoted assignment the
/// regex admits. Lets a gap test pin the shared detection contract exactly so a
/// future edit to the one regex source can't silently shift either scan path.
pub fn assign_re_captures_for_test(line: &str) -> Option<(String, String)> {
    let re = &*crate::shared_regexes::ASSIGN_RE;
    let caps = re.captures(line)?;
    Some((
        caps.get(1)?.as_str().to_string(),
        caps.get(2)?.as_str().to_string(),
    ))
}

/// Test seams for detector-owned classification flags.
pub fn detector_is_residual_weak_anchor_for_test(detector_id: &str) -> bool {
    keyhog_core::detector_spec_by_id(detector_id).is_some_and(|spec| spec.weak_anchor)
}

pub fn detector_is_private_key_block_for_test(detector_id: &str) -> bool {
    crate::detector_ids::is_private_key_block_detector(detector_id)
}

/// Test seam for the decode-pipeline registry's default decoder composition.
/// Returns each default decoder's `name()` in registration ORDER, the order is
/// load-bearing (reverse/caesar run last) and the count must stay within the
/// profiler's fixed slot capacity, neither of which was pinned anywhere.
#[cfg(feature = "decode")]
pub fn default_decoder_names_for_test() -> Vec<&'static str> {
    crate::decode::default_decoder_names()
}

/// Test seam for the scanner's hard-exit code constants
/// (crates/scanner/src/process_exit.rs). Returns
/// `(REQUIRE_GPU_UNMET_EXIT_CODE, BACKEND_UNAVAILABLE_EXIT_CODE)`, which must
/// mirror `keyhog::exit_codes::{EXIT_REQUIRE_GPU_UNMET, EXIT_SYSTEM_ERROR}`.
/// Lets a scanner-side gap test pin the compiled values (the CLI contract test
/// only source-string-checks them).
pub fn process_exit_codes_for_test() -> (i32, i32) {
    (
        crate::process_exit::REQUIRE_GPU_UNMET_EXIT_CODE,
        crate::process_exit::BACKEND_UNAVAILABLE_EXIT_CODE,
    )
}

/// Test seam for the decode-splice core: splice `decoded_text` into the bounded
/// `[start, end)` window of `parent`, keeping `SPLICE_CONTEXT_WINDOW` bytes of
/// companion context on each side. Returns `(window_start, spliced_payload,
/// decoded_offset_within_payload)` or `None` when the span is out of bounds or
/// lands off a char boundary. Lets a gap test pin the exact spliced bytes.
pub fn splice_decoded_payload_at_for_test(
    parent: &str,
    start: usize,
    end: usize,
    decoded_text: &str,
    decoder_name: &str,
) -> Option<(usize, String, usize)> {
    crate::decode::splice_decoded_payload_at(parent, start, end, decoded_text, decoder_name)
}

/// Test seam for the per-finding context-window slicer. Borrows the
/// `[line - radius, line + radius]` window (1-based `line`) out of `text` and
/// returns it owned so a gap test can pin the exact byte slice: the trailing
/// newline of the last window line is excluded, neighbours stay `\n`-joined,
/// and a window that would start before line 1 clamps to the file start.
pub fn local_context_window_for_test(text: &str, line: usize, radius: usize) -> String {
    crate::pipeline::local_context_window(text, line, radius).to_string()
}

/// Drive the cross-chunk fragment reassembler: record each `(prefix, value,
/// line, path)` fragment in order, return the glued candidates from the LAST
/// record call as plain `String`s (the `Zeroizing` wrapper unwrapped for
/// assertion). Lets a gap test pin the exact reassembly output that the
/// `with_capacity` join build must preserve.
pub fn fragment_reassemble_for_test(
    fragments: &[(&str, &str, usize, Option<&str>)],
) -> Vec<String> {
    let cache = crate::fragment_cache::FragmentCache::new(1024);
    let mut last = Vec::new();
    for &(prefix, value, line, path) in fragments {
        let fragment = crate::fragment_cache::SecretFragment {
            prefix: prefix.to_string(),
            var_name: String::new(),
            value: zeroize::Zeroizing::new(value.to_string()),
            line,
            path: path.map(std::sync::Arc::from),
        };
        last = cache
            .record_and_reassemble(fragment)
            .into_iter()
            .map(|joined| joined.as_str().to_string())
            .collect();
    }
    last
}

/// The extracted cadence gate shared by the deadline cadence wrappers.
pub fn cadence_tick_for_test(iteration: usize, cadence: usize) -> bool {
    crate::deadline::cadence_tick(iteration, cadence)
}

/// The single hot-loop deadline re-check cadence the generic-assignment, regex
/// extract, and anchor scan loops all share. Lets a gap test pin its exact value
/// (and that those loops tick on the same boundary).
pub fn hot_loop_deadline_cadence_for_test() -> usize {
    crate::deadline::HOT_LOOP_DEADLINE_CADENCE
}

/// Minimum literal-prefix byte length before a homoglyph phase-2 variant is
/// generated (compiler_build.rs). Lets a gap test pin its exact value.
pub fn compiler_min_homoglyph_prefix_len_for_test() -> usize {
    crate::compiler::compiler_build::MIN_HOMOGLYPH_PREFIX_LEN
}

/// Minimum distinctive-infix length before a pattern is treated as having a
/// usable required literal run (compiler_prefix.rs). Lets a gap test pin its
/// exact value.
pub fn compiler_min_distinctive_infix_chars_for_test() -> usize {
    crate::compiler::compiler_prefix::MIN_DISTINCTIVE_INFIX_CHARS
}

/// Maximum char-class cardinality still enumerated into AC prefixes before the
/// class is treated as a body matcher (compiler_prefix.rs). Lets a gap test pin
/// its exact value.
pub fn compiler_max_charclass_prefix_expansion_for_test() -> usize {
    crate::compiler::compiler_prefix::MAX_CHARCLASS_PREFIX_EXPANSION
}

/// Split a leading non-capturing boundary-guard group `(?:^|[^...])` into
/// `(guard, rest)`; `None` when the leading group is anything other than an
/// all-boundary-token alternation (compiler_prefix.rs). Returns owned `String`s
/// so the borrow does not leak the internal lifetime to an integration test.
pub fn split_leading_boundary_guard_for_test(pattern: &str) -> Option<(String, String)> {
    crate::compiler::compiler_prefix::split_leading_boundary_guard(pattern)
        .map(|(guard, rest)| (guard.to_string(), rest.to_string()))
}

/// The `rest` half of [`split_leading_boundary_guard_for_test`], the slice past
/// the boundary guard (compiler_prefix.rs `strip_leading_boundary_guard`). Lets
/// a gap test pin that strip == split's rest.
pub fn strip_leading_boundary_guard_for_test(pattern: &str) -> Option<String> {
    crate::compiler::compiler_prefix::strip_leading_boundary_guard(pattern).map(str::to_string)
}

/// Whether a `/proc/sys/kernel/osrelease` string reports an io_uring-capable
/// kernel (Linux 5.1+); pure parse, so a gap test can pin the version gate
/// without a real kernel (hw_probe::platform).
#[cfg(target_os = "linux")]
pub fn kernel_supports_io_uring_for_test(osrelease: &str) -> bool {
    crate::hw_probe::platform::kernel_supports_io_uring(osrelease)
}

/// The emit-drop byte-distribution base64 gate (decode_structure.rs). Lets a gap
/// test pin its exact admit policy (requires both `+` and `/`, or padding with
/// one) without going through the suppression callers.
pub fn is_byte_distribution_base64_blob_for_test(
    value: &str,
    min_len: usize,
    max_len: usize,
) -> bool {
    crate::decode_structure::is_byte_distribution_base64_blob(value, min_len, max_len)
}

/// The universal-rejection rule set (entropy::plausibility), the first gate
/// in the plausibility checks that drops obvious non-secrets (URLs, paths,
/// template vars, JWTs, key/PEM/age/vault envelopes, Windows drive paths,
/// markdown fences). Lets a gap test pin its exact reject/accept decisions.
pub fn entropy_matches_universal_rejection_for_test(value: &str) -> bool {
    crate::entropy::plausibility::matches_universal_rejection(value)
}

/// Apply the embedded isolated-bare owner's minimum alphanumeric ratio.
pub fn entropy_has_low_alnum_ratio_for_test(value: &str) -> bool {
    let ratio = keyhog_core::detector_spec_by_id("generic-keyword-secret")
        .expect("embedded generic-keyword-secret detector must load")
        .plausibility
        .expect("embedded generic-keyword-secret must own plausibility policy")
        .min_alnum_ratio;
    crate::entropy::plausibility::has_low_alnum_ratio(value, ratio)
}

pub fn entropy_has_low_alnum_ratio_with_policy_for_test(value: &str, min_ratio: f64) -> bool {
    crate::entropy::plausibility::has_low_alnum_ratio(value, min_ratio)
}

/// Distinct-scalar counter (entropy::plausibility), the ASCII fast path
/// delegates to the single-owner distinct-byte primitive, the non-ASCII branch
/// counts chars not bytes. Exposed so the counting contract can be pinned
/// externally instead of an inline unit test.
pub fn entropy_unique_char_count_for_test(value: &str) -> usize {
    crate::entropy::plausibility::unique_char_count(value)
}

/// The canonical distinct-byte primitive (entropy::unique_byte_count) that the
/// ASCII `unique_char_count` path delegates to. Exposed alongside it so a test
/// can pin that the two agree exactly on ASCII input.
pub fn entropy_unique_byte_count_for_test(bytes: &[u8]) -> usize {
    crate::entropy::unique_byte_count(bytes)
}

/// (ml_scorer::ml_features) distinct-bigram window stats + the bigram-bitset word
/// count, exposed to pin the counting + bitset-sizing contract externally instead
/// of an inline unit test.
pub fn ml_unique_bigram_stats_for_test(bytes: &[u8]) -> (usize, usize) {
    crate::ml_scorer::ml_features::unique_bigram_stats(bytes)
}
pub fn ml_bigram_bitset_words_for_test() -> usize {
    crate::ml_scorer::ml_features::BIGRAM_BITSET_WORDS
}

/// (ml_scorer) the sigmoid squashing fn plus its single-owner saturation bound
/// and score-cache capacity, exposed to pin the clamp/interior + capacity
/// contract externally.
pub fn ml_sigmoid_for_test(value: f32) -> f32 {
    crate::ml_scorer::sigmoid(value)
}
pub fn ml_sigmoid_saturation_for_test() -> f32 {
    crate::ml_scorer::SIGMOID_SATURATION
}
pub fn ml_score_cache_capacity_for_test() -> usize {
    crate::ml_scorer::SCORE_CACHE_CAPACITY
}

/// (ml_scorer::model_arch) every MoE architecture dimension, derived parameter
/// count, and flat-buffer offset the single owner defines. Exposed so
/// `tests/ml_model_arch_wgsl_parity.rs` can pin the WGSL shader's string literals
/// (and the CPU weight-buffer strides) to these exact values, the anti-drift
/// guard that replaces four hand-copied definitions.
pub struct MlModelArch {
    pub input_dim: usize,
    pub expert_count: usize,
    pub expert_fc1_out: usize,
    pub expert_fc2_out: usize,
    pub expert_fc3_out: usize,
    pub sigmoid_saturation: f32,
    pub gate_w_count: usize,
    pub gate_b_count: usize,
    pub gate_w_off: usize,
    pub gate_b_off: usize,
    pub experts_off: usize,
    pub expert_fc1_w_count: usize,
    pub expert_fc1_b_count: usize,
    pub expert_fc2_w_count: usize,
    pub expert_fc2_b_count: usize,
    pub expert_fc3_w_count: usize,
    pub expert_fc3_b_count: usize,
    pub expert_param_count: usize,
    pub total_f32_count: usize,
    pub workgroup_size: usize,
}

/// gpu-gated accessor to the GENERATED MoE WGSL shader string (`gpu::gpu_shader::moe_shader`)
/// so `tests/unit/gates/gpu_shader_arch_consts_match_model_arch.rs` can pin the GENERATED
/// shader's arch literals (complementing the SOURCE-level check in
/// `tests/ml_model_arch_wgsl_parity.rs`) without reaching into `pub(crate)` gpu internals.
#[cfg(feature = "gpu")]
pub fn moe_shader_for_test() -> String {
    crate::gpu::gpu_shader::moe_shader()
}

pub fn ml_model_arch_for_test() -> MlModelArch {
    use crate::ml_scorer::model_arch as a;
    MlModelArch {
        input_dim: a::INPUT_DIM,
        expert_count: a::EXPERT_COUNT,
        expert_fc1_out: a::EXPERT_FC1_OUT,
        expert_fc2_out: a::EXPERT_FC2_OUT,
        expert_fc3_out: a::EXPERT_FC3_OUT,
        sigmoid_saturation: a::SIGMOID_SATURATION,
        gate_w_count: a::GATE_W_COUNT,
        gate_b_count: a::GATE_B_COUNT,
        gate_w_off: a::GATE_W_OFF,
        gate_b_off: a::GATE_B_OFF,
        experts_off: a::EXPERTS_OFF,
        expert_fc1_w_count: a::EXPERT_FC1_W_COUNT,
        expert_fc1_b_count: a::EXPERT_FC1_B_COUNT,
        expert_fc2_w_count: a::EXPERT_FC2_W_COUNT,
        expert_fc2_b_count: a::EXPERT_FC2_B_COUNT,
        expert_fc3_w_count: a::EXPERT_FC3_W_COUNT,
        expert_fc3_b_count: a::EXPERT_FC3_B_COUNT,
        expert_param_count: a::EXPERT_PARAM_COUNT,
        total_f32_count: a::TOTAL_F32_COUNT,
        workgroup_size: a::WORKGROUP_SIZE,
    }
}

/// (structured::parsers) the single-owner structured-traversal depth cap that the
/// JSON and YAML recursion guards both read.
pub fn structured_max_traversal_depth_for_test() -> usize {
    crate::structured::parsers::MAX_STRUCTURED_TRAVERSAL_DEPTH
}

/// (multiline::config) the concatenation-marker predicates, exposed to pin the
/// marker recognition + both-scan indicator routing externally.
#[cfg(feature = "multiline")]
pub fn multiline_has_function_concat_marker_for_test(s: &str) -> bool {
    crate::multiline::config::has_function_concat_marker(s)
}
#[cfg(feature = "multiline")]
pub fn multiline_has_concatenation_indicators_for_test(text: &str) -> bool {
    crate::multiline::config::has_concatenation_indicators(text)
}

/// The fast probabilistic noise gate (`probabilistic_gate`), rejects obvious
/// high-entropy non-secrets (UUIDs, low-diversity pads) before heavy ML scoring.
/// Lets a gap test pin its exact promising/not-promising decisions, in
/// particular the bigram-distribution branch that the diversity-count and UUID
/// branches shadow on simpler inputs.
pub fn probabilistic_gate_looks_promising_for_test(value: &str) -> bool {
    crate::probabilistic_gate::ProbabilisticGate::looks_promising(value)
}

/// The leading-assignment-key extractor (`generic_keyword_owner`), pulls the
/// `key` out of a `key=`/`key:`/`key~` candidate prefix so named-detector owner
/// attribution can test it. Returns an owned copy so a gap test can pin the
/// exact key slice and the `None` boundaries (no terminator, leading non-key
/// byte, non-`=`/`:`/`~` terminator).
pub fn leading_assignment_key_for_test(candidate: &str) -> Option<String> {
    crate::generic_keyword_owner::leading_assignment_key(candidate).map(str::to_owned)
}

/// The assignment-keyword normalizer (`engine::phase2_generic::keywords`)
/// folds `SEGMENT_WRITE_KEY` / `segment-write-key` / `segment.write.key` into
/// one comparable `segment_write_key` token. Lets a gap test pin the exact
/// normalized string (case-fold, separator collapse, leading/trailing-separator
/// trim, drop of unrecognized bytes) and the empty -> `None` boundary.
pub fn normalize_assignment_keyword_for_test(keyword: &str) -> Option<String> {
    crate::engine::phase2_generic::keywords::normalize_assignment_keyword(keyword)
}

/// The secret-suffix classifier (`engine::phase2_generic::keywords`), true when
/// a normalized assignment key claims a credential slot. Lets a gap test pin the
/// exact split between the last-`_`-segment match set (`key`/`secret`/`token`/
/// `password`/`passwd`/`pwd`) and the `ends_with` suffix set
/// (`key`/`secret`/`token`/`password`).
pub fn normalized_assignment_keyword_has_secret_suffix_for_test(normalized: &str) -> bool {
    crate::engine::phase2_generic::keywords::normalized_assignment_keyword_has_secret_suffix(
        normalized,
    )
}

/// The password-family keyword classifier (`entropy::keywords`), the ONE PLACE
/// both entropy detector classifiers use to route `*_PASS=`/`*_PASSWORD=` keys
/// to the Password tier. Lets a gap test pin the boundary that keeps
/// `bypass`/`compass` out.
pub fn keyword_is_password_family_for_test(keyword: &str) -> bool {
    crate::entropy::keywords::keyword_is_password_family(keyword)
}

/// The generic-keyword prefilter-stem classifier (`engine::phase2_generic::
/// keywords`), collapses a detector keyword to the single literal the prefilter
/// scans for, via a PRIORITY-ORDERED `contains` chain
/// (`secret`>`pass`>`pwd`>`token`>`webhook`>`key`>`auth`>`credential`), falling
/// back to the keyword itself. Returns owned so a gap test can pin the precedence
/// (e.g. `secret_key` -> `secret`, `auth_key` -> `key`).
pub fn generic_keyword_prefilter_stem_for_test(keyword: &'static str) -> String {
    crate::engine::phase2_generic::keywords::generic_keyword_prefilter_stem(keyword).to_string()
}

/// `compact_keyword_eq` (`engine::phase2_generic::keywords`) driven with the real
/// assignment separator set (`_`/`-`/`.`), true iff the keyword, case-folded
/// with those separators dropped, EXACTLY equals the needle. Lets a gap test pin
/// the exact-equality contract (no trailing/leading slop) used by encoded-text
/// anchor matching.
pub fn compact_keyword_eq_for_test(keyword: &str, needle: &str) -> bool {
    crate::engine::phase2_generic::keywords::compact_keyword_eq(
        keyword,
        needle.as_bytes(),
        crate::engine::phase2_generic::keywords::is_assignment_compact_separator,
    )
}

/// `compact_keyword_ends_with` driven with the assignment separator set.
pub fn compact_keyword_ends_with_for_test(keyword: &str, suffix: &str) -> bool {
    crate::engine::phase2_generic::keywords::compact_keyword_ends_with(
        keyword,
        suffix.as_bytes(),
        crate::engine::phase2_generic::keywords::is_assignment_compact_separator,
    )
}

/// `normalized_assignment_keyword_owned_by_named_detector` (`generic_keyword_
/// owner`), the binary-search owner check. The facade sorts and dedups the
/// supplied keywords through the same `BTreeSet` the real builder uses, so a gap
/// test can pass an UNSORTED list and still pin the EXACT-match contract (a
/// prefix, superstring, substring, or differently-cased query is NOT owned).
pub fn assignment_keyword_owned_by_named_detector_for_test(
    owned: &[&str],
    normalized: &str,
) -> bool {
    let sorted: Vec<std::sync::Arc<str>> = owned
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<&str>>()
        .into_iter()
        .map(std::sync::Arc::from)
        .collect();
    crate::generic_keyword_owner::normalized_assignment_keyword_owned_by_named_detector(
        &sorted, normalized,
    )
}

/// `keyword_span_owned_by_named_detector` (`generic_keyword_owner`), checks
/// whether the assignment key under `[keyword_start, keyword_end)` (or the
/// `is_assignment_key_byte` run it sits inside, after expanding left/right) is
/// owned by a named detector. Lets a gap test pin the bounds guard, the
/// exact-span hit, the left/right boundary expansion, and that a non-expanding
/// unowned span stays unowned. The owned keywords are sorted/deduped via the
/// same `BTreeSet` the real builder uses.
pub fn keyword_span_owned_by_named_detector_for_test(
    owned: &[&str],
    line: &str,
    keyword_start: usize,
    keyword_end: usize,
) -> bool {
    let sorted: Vec<std::sync::Arc<str>> = owned
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<&str>>()
        .into_iter()
        .map(std::sync::Arc::from)
        .collect();
    crate::generic_keyword_owner::keyword_span_owned_by_named_detector(
        &sorted,
        line,
        keyword_start,
        keyword_end,
    )
}

/// `candidate_embeds_owned_assignment_key` driven with an explicit owned set:
/// the OR-composition of the exact-key, prefix-embed, and no-terminator-fallback
/// paths. The facade rebuilds the owned slice through a sorted `BTreeSet` because
/// the inner exact-key check is a `binary_search`.
pub fn candidate_embeds_owned_assignment_key_for_test(owned: &[&str], candidate: &str) -> bool {
    let keys: Vec<std::sync::Arc<str>> = owned
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<&str>>()
        .into_iter()
        .map(std::sync::Arc::from)
        .collect();
    crate::generic_keyword_owner::candidate_embeds_owned_assignment_key(&keys, candidate)
}

/// `line_assignment_owned_by_named_detector` driven with an explicit owned set:
/// extracts the line's assignment keyword (`assignment_keyword_for_line`, which
/// applies the credential-first selection) and checks whether THAT keyword is
/// owned. The facade rebuilds the owned slice through a sorted `BTreeSet` because
/// the membership check is a `binary_search`.
pub fn line_assignment_owned_by_named_detector_for_test(owned: &[&str], line: &str) -> bool {
    let keys: Vec<std::sync::Arc<str>> = owned
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<&str>>()
        .into_iter()
        .map(std::sync::Arc::from)
        .collect();
    crate::generic_keyword_owner::line_assignment_owned_by_named_detector(&keys, line)
}

/// `entropy_candidate_owned_by_named_assignment` driven with an explicit owned
/// set: the candidate is owned if it embeds an owned assignment key OR (when a
/// `same_line` is supplied) that line's assignment keyword is owned. The facade
/// rebuilds the owned slice through a sorted `BTreeSet` because both inner paths
/// use a `binary_search`.
pub fn entropy_candidate_owned_by_named_assignment_for_test(
    owned: &[&str],
    candidate: &str,
    same_line: Option<&str>,
) -> bool {
    let keys: Vec<std::sync::Arc<str>> = owned
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<&str>>()
        .into_iter()
        .map(std::sync::Arc::from)
        .collect();
    crate::generic_keyword_owner::entropy_candidate_owned_by_named_assignment(
        &keys, candidate, same_line,
    )
}

/// `is_strong_keyword_anchored_encoded_text_secret`: true when the keyword is a
/// strong credential anchor (a secret suffix, or one of the encoded-text-secret
/// anchors like `credential`/`passphrase`) AND the value decodes to printable
/// text. Short value (<24) or a value containing `.` is rejected up front.
pub fn is_strong_keyword_anchored_encoded_text_secret_for_test(keyword: &str, value: &str) -> bool {
    crate::engine::phase2_generic::keywords::is_strong_keyword_anchored_encoded_text_secret(
        keyword, value,
    )
}

/// `is_likely_concatenation_fragment`: true when a trimmed line looks like a
/// string-concatenation fragment, it opens with a single balanced quoted run
/// whose trailing text is empty or a concat glue (`+`/`\`/`,`/`)`), or the line
/// ends with `\"` or `-\`. Such lines are dropped from entropy candidate
/// extraction (treated as code, not a secret-bearing assignment).
pub fn is_likely_concatenation_fragment_for_test(line: &str) -> bool {
    crate::entropy::keywords::is_likely_concatenation_fragment(line)
}

/// `is_likely_innocuous_line`: true when a trimmed line is a non-secret shape
/// dropped before entropy extraction, a bare URI, an `import`/`use`/`package`
/// declaration, an algo-labelled hash digest (`sha256:`/`sha512:`/`sha1:`/`md5:`/
/// `git-sha:`, matched case-insensitively) or a bare 40-hex git SHA.
pub fn is_likely_innocuous_line_for_test(line: &str) -> bool {
    crate::entropy::keywords::is_likely_innocuous_line(line)
}

/// `is_keyword_assignment_line`: true when a line is a `key = value` assignment
/// whose key seeds a credential-keyword entropy context. Space/paren-terminated
/// import-prefix owner: a key that merely BEGINS with `import`/`package`
/// (`important_key`, `package_secret`) still seeds, while genuine
/// `import`/`use`/`include` declarations are rejected.
pub fn is_keyword_assignment_line_for_test(line: &str, secret_keywords: &[String]) -> bool {
    crate::entropy::keywords::is_keyword_assignment_line(line, secret_keywords)
}

/// `is_import_like_prefix`: true when a trimmed line begins with an
/// import/use/include/require/package/from declaration prefix (the single owner
/// that drives BOTH the keyword-assignment reject and the innocuous-line drop).
pub fn is_import_like_prefix_for_test(trimmed: &str) -> bool {
    crate::entropy::keywords::is_import_like_prefix(trimmed)
}

/// The `KEY_MATERIAL_COMPACT_KEYWORDS` vocabulary as UTF-8 strings, so an
/// external test can prove every key-material anchor split out of
/// `CREDENTIAL_COMPACT_KEYWORDS` is still recognized as a credential keyword.
pub fn key_material_compact_keywords_for_test() -> Vec<&'static str> {
    crate::entropy::keywords::KEY_MATERIAL_COMPACT_KEYWORDS
        .iter()
        .map(|word| std::str::from_utf8(word).expect("key-material anchor is ascii"))
        .collect()
}

/// `parse_weights`: the fail-closed parser for the embedded little-endian `f32`
/// weight buffer, rejects a size mismatch and any non-finite value (returning
/// the offending index in the error). Returns the parsed weights as a `Vec`.
pub fn parse_ml_weights_for_test(raw: &[u8]) -> Result<Vec<f32>, String> {
    crate::ml_scorer::ml_weights::parse_weights(raw).map(|weights| weights.into_vec())
}

/// The canonical `TOTAL_F32_COUNT` (the exact `f32` count `parse_weights`
/// requires) so an external test can build correctly/incorrectly sized buffers.
pub fn ml_weights_total_f32_count() -> usize {
    crate::ml_scorer::model_arch::TOTAL_F32_COUNT
}

/// The shipped embedded `weights.bin` bytes, so an external test can prove the
/// production weights pass the fail-closed parse.
pub fn ml_weights_embedded_bytes() -> &'static [u8] {
    crate::ml_scorer::ml_weights::WEIGHTS
}

/// `reject_oversized_window_chunk`: the windowed-scan hard-skip backstop, true
/// only when a chunk exceeds the absolute OOM ceiling (NOT a routine per-chunk
/// gate: `scan_windowed` covers everything below it in bounded slices).
pub fn reject_oversized_window_chunk_for_test(
    chunk: &keyhog_core::Chunk,
    chunk_text: &str,
) -> bool {
    crate::engine::reject_oversized_window_chunk(chunk, chunk_text)
}

/// The `MAX_WINDOW_CHUNK_BYTES` OOM-backstop ceiling (4 GiB), pinned against the
/// old 512 MiB recall cliff that silently dropped scannable large chunks.
pub fn max_window_chunk_bytes() -> usize {
    crate::engine::MAX_WINDOW_CHUNK_BYTES
}

/// `unique_bigram_stats`: `(distinct_bigrams, total_bigram_windows)` over `bytes`,
/// exercising the reused thread-local scratch (a leaked bit would inflate a later
/// distinct count).
pub fn unique_bigram_stats_for_test(bytes: &[u8]) -> (usize, usize) {
    crate::ml_scorer::ml_features::unique_bigram_stats(bytes)
}

// ── SIMD ↔ scalar Shannon-entropy parity accessors ───────────────────────────
// The entropy reduction has a scalar reference (`shannon_entropy_scalar`) plus
// AVX2 / AVX-512 / NEON specializations, all counting through the one
// `histogram_8way` contract. They MUST agree with the scalar path on every
// input (Law 8: SIMD/scalar parity is not optional). These accessors expose the
// scalar reference, the once-dispatched `shannon_entropy_simd`, and each
// architecture path RUNTIME-GATED on the CPU actually carrying its features, so
// the parity proptest only invokes a `#[target_feature]` fn where it is legal.

/// Scalar reference Shannon entropy (bits/byte), the parity oracle every SIMD
/// path is compared against. [`crate::entropy::fast::shannon_entropy_scalar`].
pub fn shannon_entropy_scalar_for_test(data: &[u8]) -> f64 {
    crate::entropy::fast::shannon_entropy_scalar(data)
}

/// The once-resolved SIMD dispatcher [`crate::entropy::fast::shannon_entropy_simd`]
/// whatever tier this CPU selected. Must equal the scalar reference.
pub fn shannon_entropy_simd_for_test(data: &[u8]) -> f64 {
    crate::entropy::fast::shannon_entropy_simd(data)
}

/// AVX2 entropy IFF this x86_64 CPU carries `avx2`+`fma`, else `None` (so the
/// test skips loudly rather than calling an illegal `#[target_feature]` fn on a
/// CPU without it). [`crate::entropy::fast_x86::shannon_entropy_avx2`].
#[cfg(target_arch = "x86_64")]
pub fn shannon_entropy_avx2_if_supported_for_test(data: &[u8]) -> Option<f64> {
    if std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("fma") {
        // SAFETY: both required features were just runtime-detected above, and
        // CPU features do not change during the process lifetime.
        Some(unsafe { crate::entropy::fast_x86::shannon_entropy_avx2(data) })
    } else {
        None
    }
}

/// AVX-512 entropy IFF this CPU carries `avx512f`+`avx512bw`+`avx512dq`, else
/// `None`. [`crate::entropy::avx512::calculate_shannon_entropy`].
#[cfg(target_arch = "x86_64")]
pub fn shannon_entropy_avx512_if_supported_for_test(data: &[u8]) -> Option<f64> {
    if std::is_x86_feature_detected!("avx512f")
        && std::is_x86_feature_detected!("avx512bw")
        && std::is_x86_feature_detected!("avx512dq")
    {
        // SAFETY: all three required features were just runtime-detected above.
        Some(unsafe { crate::entropy::avx512::calculate_shannon_entropy(data) })
    } else {
        None
    }
}

/// NEON entropy on aarch64 (NEON is baseline on aarch64, so always available).
/// [`crate::entropy::fast_neon::shannon_entropy_neon`].
#[cfg(target_arch = "aarch64")]
pub fn shannon_entropy_neon_for_test(data: &[u8]) -> f64 {
    crate::entropy::fast_neon::shannon_entropy_neon(data)
}

/// The shipped detector-owned generic-keyword bridge regex, built from the
/// derived assignment vocabulary and detector maximum; `Err` iff the resulting
/// expression fails to compile.
pub fn build_generic_re_for_test() -> Result<regex::Regex, String> {
    crate::engine::phase2_generic::build_generic_re()
}

/// Compile the generic bridge regex from an ARBITRARY group-1 alternation, so a
/// test can prove a malformed alternation is a hard `Err` (never a silent `Ok`
/// with the bridge disabled).
pub fn compile_generic_re_for_test(alternation: &str) -> Result<regex::Regex, regex::Error> {
    crate::engine::phase2_generic::compile_generic_re_with_max(alternation, 8)
}

/// The group-1 keyword alternation string that the generic bridge uses (derived
/// vocabulary literals plus the appended vendor structural arm).
pub fn generic_keyword_alternation_for_test() -> String {
    crate::engine::phase2_generic::generic_keyword_alternation()
}

/// The appended `<vendor>_key` structural arm literal, so a test can strip it back
/// off the alternation to recover the pure derived-vocabulary set.
pub fn generic_re_vendor_suffix_arm() -> &'static str {
    crate::engine::phase2_generic::GENERIC_RE_VENDOR_SUFFIX_ARM
}

/// Compile the shipped detector-owned generic bridge; panics (fail-closed) iff
/// the bundled detector vocabulary or maximum is invalid.
pub fn force_generic_re() {
    if let Err(error) = crate::engine::phase2_generic::build_generic_re() {
        panic!("shipped generic assignment bridge failed to compile: {error}");
    }
}

/// The derived assignment-keyword vocabulary (single owner), so a test can prove
/// the generic bridge alternation equals exactly this set.
pub fn assignment_keywords_for_test() -> &'static [String] {
    crate::assignment_keywords::assignment_keywords()
}

/// The resolved entropy threshold that `keyword_context` derives from the
/// owning detector policy and the supplied operator threshold.
pub fn keyword_context_threshold_for_test(
    keyword_line: &str,
    min_length: usize,
    entropy_threshold: f64,
    secret_keywords: &[String],
) -> f64 {
    crate::entropy::scanner::keyword_context(
        keyword_line,
        min_length,
        entropy_threshold,
        secret_keywords,
    )
    .threshold
}

/// The detector-owned minimum length used by the embedded API-key entropy policy.
pub fn credential_context_min_len() -> usize {
    crate::entropy::scanner::credential_keyword_context("api_key").min_len
}

/// True iff `candidate` is rejected by the credential-context too-short gate
/// specifically (`EntropyShapeStage::CredentialContextTooShort`). Encapsulates the
/// white-box `KeywordContext` construction so the private struct/enum stay
/// crate-internal; `threshold = 0` isolates the length gate from the entropy floor.
pub fn credential_context_too_short_rejection_for_test(
    candidate: &str,
    keyword: &str,
    min_len: usize,
) -> bool {
    use crate::adjudicate::{EntropyShapeStage, StageId};
    let plausibility_policy =
        crate::entropy::scanner::credential_keyword_context(keyword).plausibility_policy;
    let context = crate::entropy::keywords::KeywordContext {
        keyword: keyword.to_string(),
        threshold: 0.0,
        min_len,
        is_credential_context: true,
        plausibility_policy,
    };
    let entropy = crate::entropy::shannon_entropy(candidate.as_bytes());
    matches!(
        crate::entropy::scanner::candidate_plausibility_rejection_stage(
            candidate,
            entropy,
            &context,
            &[],
        ),
        Some(StageId::EntropyValueShape(
            EntropyShapeStage::CredentialContextTooShort
        ))
    )
}

/// Seed every scanner coverage-gap counter to 9, run the single per-scan reset
/// owner `reset_for_scan`, and report whether ALL counters were zeroed. Encapsulates
/// the white-box `ScannerCoverageGapEvent::ALL` / `.counter()` access in-crate so
/// the per-scan reset-completeness contract can be pinned externally. The historical
/// bug omitted `STRUCTURED_OVERSIZE_SKIPS` from the reset, leaking a count into the
/// next scan's report.
pub fn telemetry_reset_zeroes_all_seeded_gap_counters() -> bool {
    use crate::telemetry::ScannerCoverageGapEvent;
    use std::sync::atomic::Ordering;
    for gap in ScannerCoverageGapEvent::ALL {
        gap.counter().store(9, Ordering::Relaxed);
    }
    crate::telemetry::reset_for_scan();
    ScannerCoverageGapEvent::ALL
        .iter()
        .all(|gap| gap.counter().load(Ordering::Relaxed) == 0)
}

/// `(ALL.len(), all_six_variants_present)` for `ScannerCoverageGapEvent::ALL`: the
/// reset owner iterates `ALL`, so a new variant added without extending `ALL` would
/// silently escape the per-scan reset. Encapsulates the private variant set in-crate.
pub fn telemetry_coverage_gap_all_completeness() -> (usize, bool) {
    use crate::telemetry::ScannerCoverageGapEvent as E;
    let all_present = [
        E::StructuredParseFailure,
        E::StructuredOversizeSkip,
        E::DecodeTruncation,
        E::InvalidPatternIndexSkip,
        E::BoundaryResultCardinalityMismatch,
        E::LineOffsetMappingMismatch,
    ]
    .iter()
    .all(|variant| E::ALL.contains(variant));
    (E::ALL.len(), all_present)
}

/// Drive `find_entropy_secrets_with_lines` with a `line_offsets`
/// slice shorter than `lines`: the desynced pair that must FAIL CLOSED (panic at
/// the boundary assert) rather than index out of bounds. Used by a `#[should_panic]`
/// external test.
pub fn trigger_desynced_line_offsets_for_test() {
    let lines = ["alpha", "beta", "gamma"];
    let line_offsets = [0usize]; // shorter than lines: invariant violated
    crate::entropy::scanner::find_entropy_secrets_with_lines(
        &lines,
        &line_offsets,
        8,
        0,
        4.5,
        5.8,
        &[],
        &[],
        &[],
        None,
    );
}

/// `xml_assignment_tag`: returns the opening tag name of an XML-shaped line that
/// has a matching `</tag>` close, for ANY well-formed element (NOT just
/// credential-named ones, that filter lives in `xml_assignment_value`). Returns
/// `None` for close/comment/PI markers (`</`,`<!`,`<?`), an empty/whitespace tag,
/// a missing `>` or `<`, or a close-tag whose name does not match the open tag.
pub fn xml_assignment_tag_for_test(line: &str) -> Option<String> {
    crate::entropy::keywords::xml_assignment_tag(line).map(str::to_string)
}

/// `standard_base64_shape`: classifies a candidate as standard (non-url-safe)
/// base64 and returns its shape, or `None` when it mixes alphabets, is url-safe,
/// has `=` in an invalid position, or has a length remainder incompatible with
/// its padding. The owned tuple is
/// `(has_padding, length_multiple_of_four, has_plus, has_slash, distinct_alnum)`.
pub fn standard_base64_shape_for_test(candidate: &str) -> Option<(bool, bool, bool, bool, u32)> {
    crate::decode::standard_base64_shape(candidate).map(|shape| {
        (
            shape.has_padding,
            shape.length_multiple_of_four,
            shape.has_plus,
            shape.has_slash,
            shape.distinct_alnum,
        )
    })
}

/// `contains_non_padding_equals`: the single base64-padding discriminator shared
/// by the isolated-bare entropy candidate gate and the leading-slash secret gate
/// `true` iff the value holds an `=` that is not valid trailing base64 padding
/// (a third-or-later trailing `=`, or any `=` before the padding run).
pub fn contains_non_padding_equals(value: &str) -> bool {
    crate::decode::contains_non_padding_equals(value)
}

/// `is_standard_base64_byte`: the RFC 4648 standard base64 alphabet test
/// (alphanumeric + `+` `/` `=`), the single owner that three
/// `context/false_positive.rs` byte scans delegate to.
pub fn is_standard_base64_byte(byte: u8) -> bool {
    crate::decode::is_standard_base64_byte(byte)
}

/// `is_base64_candidate_byte`: the standard alphabet plus the url-safe `-` and
/// `_`, the single owner the JWT-like segment check in
/// `suppression/shape/canonical.rs` delegates to.
pub fn is_base64_candidate_byte(byte: u8) -> bool {
    crate::decode::is_base64_candidate_byte(byte)
}

/// `candidate_starts_with_owned_assignment_key` driven with an explicit owned
/// set: true iff the candidate normalizes to a STRICTLY longer key that begins
/// with one of the owned keys AND that owned key carries a credential suffix.
/// The facade maps `&[&str]` to `Arc<str>` (the real fn uses `.any()`, so the
/// owned order does not matter).
pub fn candidate_starts_with_owned_assignment_key_for_test(
    owned: &[&str],
    candidate: &str,
) -> bool {
    let keys: Vec<std::sync::Arc<str>> = owned.iter().copied().map(std::sync::Arc::from).collect();
    crate::generic_keyword_owner::candidate_starts_with_owned_assignment_key(&keys, candidate)
}

/// `normalized_assignment_keyword_is_credential` on an already-normalized key:
/// true via either the separated-secret-suffix branch (`*_key`/`*_secret`/...
/// where the LAST `_`-segment is the credential word, which requires a `_`) or
/// the compact branch (exact membership in the credential list, or a
/// `salt`/`nonce`/`seed` suffix).
pub fn normalized_assignment_keyword_is_credential_for_test(normalized: &str) -> bool {
    crate::entropy::keywords::normalized_assignment_keyword_is_credential(normalized)
}

/// The SCAN-FACING credential-keyword UNION used by the multiline fragment and
/// structural reassembly paths (`fragment_assignment_name_is_credential_like`):
/// `normalized_assignment_keyword_is_credential` (the compact list + salt/nonce/
/// seed) OR `normalized_assignment_keyword_has_secret_suffix` (the `*key`/
/// `*secret`/`*token`/`*password` suffix family), MINUS the bare-ambiguous-owner
/// (`key`/`token`/`secret`/`password`/`auth`/...) and public-metadata-owner
/// (`*_digest`/`*_hash`/`*_dedup_key`/`version`/...) exclusions. Takes the RAW
/// var name (it normalizes internally). Exposed so the union recall contract can
/// pin that BOTH predicate sets contribute and neither exclusion regresses.
pub fn fragment_assignment_name_is_credential_like_for_test(var_name: &str) -> bool {
    crate::multiline::fragment_assignment_name_is_credential_like(var_name)
}

/// `assignment_keyword_for_line` extracts the assignment keyword a line is most
/// likely keying on: an XML tag takes precedence, else the `=`/`:` separators
/// are scanned right-to-left, the first credential key short-circuits, and the
/// rightmost non-credential key is the fallback. Returns the owned normalized
/// keyword (already `Option<String>`, so this is a passthrough).
pub fn assignment_keyword_for_line_for_test(line: &str) -> Option<String> {
    crate::entropy::keywords::assignment_keyword_for_line(line)
}

/// `expired_on_cadence` driven with an already-reached (`now`) deadline, so the
/// result is exactly the cadence gate, pins that the wrapper ANDs
/// `cadence_tick` with the deadline check.
pub fn expired_on_cadence_now_for_test(iteration: usize, cadence: usize) -> bool {
    crate::deadline::expired_on_cadence(Some(std::time::Instant::now()), iteration, cadence)
}

/// `loop_expired_on_cadence` driven with an already-reached deadline (zero
/// budget), so the result is exactly the cadence gate for the loop variant.
pub fn loop_expired_on_cadence_now_for_test(iteration: usize, cadence: usize) -> bool {
    let deadline = crate::deadline::LoopDeadline::from_deadline(Some(std::time::Instant::now()));
    crate::deadline::loop_expired_on_cadence(deadline, iteration, cadence)
}

/// `deadline::expired(None)`: no configured deadline must NEVER report expired
/// (else an unbounded scan would abort immediately). The cadence-wrapper tests
/// only ever drive `expired` with a reached deadline, so this None arm and the
/// not-yet-reached arm below are otherwise unexercised.
pub fn deadline_expired_none_for_test() -> bool {
    crate::deadline::expired(None)
}

/// `deadline::expired(Some(now))`: an already-reached deadline reports expired
/// (the leaf `now >= deadline` true path, tested directly rather than only
/// through the cadence wrapper's AND).
pub fn deadline_expired_now_for_test() -> bool {
    crate::deadline::expired(Some(std::time::Instant::now()))
}

/// `deadline::expired(Some(now + 1h))`: a comfortably-future deadline must NOT
/// report expired. This is the not-yet-reached arm the reached-deadline cadence
/// tests never hit; a regression flipping `>=`/`<` here would abort every scan.
pub fn deadline_expired_far_future_for_test() -> bool {
    match std::time::Instant::now().checked_add(std::time::Duration::from_secs(3600)) {
        Some(future) => crate::deadline::expired(Some(future)),
        // `now + 1h` is representable on any real clock; treat the impossible
        // overflow as "not expired" rather than unwrap (no_unwrap_expect gate).
        None => false,
    }
}

/// `LoopDeadline::from_deadline(None).is_none()`: no deadline yields no loop
/// deadline (the `deadline?` early return).
pub fn loop_deadline_from_none_is_none_for_test() -> bool {
    crate::deadline::LoopDeadline::from_deadline(None).is_none()
}

/// `LoopDeadline::from_deadline(Some(now)).expired()`: a deadline already in the
/// past yields a ZERO budget (the `checked_duration_since` → `Duration::ZERO`
/// fallback), and `expired()` reports true via the `budget.is_zero()` arm.
pub fn loop_deadline_expired_reached_for_test() -> bool {
    crate::deadline::LoopDeadline::from_deadline(Some(std::time::Instant::now()))
        .map(crate::deadline::LoopDeadline::expired)
        .map_or(false, |expired| expired)
}

/// `LoopDeadline::from_deadline(Some(now + 1h)).expired()`: a comfortably-future
/// budget must NOT report expired (positive budget, ~zero elapsed): the
/// `elapsed >= budget` false path.
pub fn loop_deadline_expired_far_future_for_test() -> bool {
    match std::time::Instant::now().checked_add(std::time::Duration::from_secs(3600)) {
        Some(future) => crate::deadline::LoopDeadline::from_deadline(Some(future))
            .map(crate::deadline::LoopDeadline::expired)
            .map_or(false, |expired| expired),
        None => false,
    }
}

/// `platform_compat::path::path_basename`: the cross-platform final-component
/// extractor that accepts BOTH `/` and `\` separators (the single owner every
/// context/suppression path uses for file attribution). Exposed so a gap test can
/// pin the mixed-separator BEHAVIOR, not just the source-shape one-owner gate.
pub fn path_basename_for_test(path: &str) -> &str {
    crate::platform_compat::path_basename(path)
}

/// `platform_compat::path::path_basename_bytes`: the byte-slice twin of
/// [`path_basename_for_test`] used on the raw-bytes suppression hot path
/// (`suppression::path_filter`). Exposed so a parity proptest can pin that the
/// two implementations agree byte-for-byte (a divergence is a real suppression
/// bug: the string path and the byte path would attribute a finding differently).
pub fn path_basename_bytes_for_test(path: &[u8]) -> &[u8] {
    crate::platform_compat::path_basename_bytes(path)
}

/// `platform_compat::path::path_has_any_component`: case-insensitive match of
/// any exact `/`-or-`\`-delimited path component against `components`. This is
/// the load-bearing predicate behind example-path suppression
/// (`suppression::decision` / `context::inference`), so exposing it lets a test
/// pin the exact-component (not substring) + case-insensitive + mixed-separator
/// contract directly rather than only through a full scan.
pub fn path_has_any_component_for_test(path: &str, components: &[&str]) -> bool {
    crate::platform_compat::path_has_any_component(path, components)
}

/// `engine::phase2_truncate::regex_prefix_anchorable`: the soundness
/// precondition for driving a pattern from prefix-anchor positions instead of a
/// whole-chunk walk (finite, enumerable required-prefix set, every member >= 3
/// bytes). A false TRUE would anchor a pattern that has no such prefix and
/// silently miss matches; a false FALSE forfeits the fast path. Untested before.
pub fn regex_prefix_anchorable_for_test(src: &str) -> bool {
    crate::engine::phase2_truncate::regex_prefix_anchorable(src)
}

/// `engine::phase2_truncate::focus_floor_boundary`: round an index DOWN to the
/// nearest UTF-8 char boundary (the decode-focus window's lower snap). Exposed so
/// the multibyte-boundary contract can be pinned directly.
pub fn focus_floor_boundary_for_test(s: &str, idx: usize) -> usize {
    crate::engine::phase2_truncate::focus_floor_boundary(s, idx)
}

/// `engine::phase2_truncate::focus_ceil_boundary`: round an index UP to the
/// nearest UTF-8 char boundary (the decode-focus window's upper snap).
pub fn focus_ceil_boundary_for_test(s: &str, idx: usize) -> usize {
    crate::engine::phase2_truncate::focus_ceil_boundary(s, idx)
}

/// `engine::phase2_truncate::truncate_src`: truncate `s` to at most `n` bytes on
/// a char boundary, appending `…` when truncation occurred. Exposed so the
/// boundary-safety + verbatim-when-short contract is pinned.
pub fn truncate_src_for_test(s: &str, n: usize) -> String {
    crate::engine::phase2_truncate::truncate_src(s, n)
}

/// `compiler::compiler_compile::compile_companion`: compile a `CompanionSpec`
/// regex into a `CompiledCompanion`, returning `(name, capture_group)`. The
/// capture group resolves to `Some(1)` iff the regex declares a (capturing)
/// group, else `None`; a regex that fails to compile is an `Err` naming the
/// detector. The capture-group resolution + error path were untested.
pub fn compile_companion_for_test(
    name: &str,
    regex: &str,
    detector_id: &str,
) -> Result<(String, Option<usize>), String> {
    let spec = keyhog_core::CompanionSpec {
        name: name.to_string(),
        regex: regex.to_string(),
        within_lines: 1,
        required: false,
    };
    crate::compiler::compiler_compile::compile_companion(&spec, detector_id)
        .map(|c| (c.name, c.capture_group))
        .map_err(|e| e.to_string())
}

/// `simdsieve_prefilter::build_hot_pattern_validators`: build the per-hot-pattern
/// validator regexes from a detector set, returning `is_some()` per slot. Pins
/// the "loaded hot detector => Some, absent or pattern-less => None" mapping
/// without exposing the compiled `Regex`. Order matches
/// [`hot_pattern_detector_ids_for_test`].
#[cfg(feature = "simdsieve")]
pub fn hot_pattern_validator_is_some_for_test(
    detectors: &[keyhog_core::DetectorSpec],
) -> Result<Vec<bool>, String> {
    crate::simdsieve_prefilter::build_hot_pattern_validators(detectors)
        .map(|v| v.iter().map(Option::is_some).collect())
        .map_err(|e| e.to_string())
}

/// For hot-pattern slot `index`, whether the built validator (if any) matches
/// `sample`; `None` when the slot has no validator. Pins the validator's
/// `^`-anchored match behavior.
#[cfg(feature = "simdsieve")]
pub fn hot_pattern_validator_matches_for_test(
    detectors: &[keyhog_core::DetectorSpec],
    index: usize,
    sample: &str,
) -> Result<Option<bool>, String> {
    crate::simdsieve_prefilter::build_hot_pattern_validators(detectors)
        .map(|v| {
            v.get(index)
                .and_then(|slot| slot.as_ref())
                .map(|re| re.is_match(sample))
        })
        .map_err(|e| e.to_string())
}

/// The canonical hot-pattern detector-id list, so a test can locate a slot.
#[cfg(feature = "simdsieve")]
pub fn hot_pattern_detector_ids_for_test() -> &'static [&'static str] {
    *crate::simdsieve_prefilter::HOT_PATTERN_DETECTOR_IDS
}

/// Round-trip a `ScannerTuningConfig` override (`None`/`Some(true)`/`Some(false)`)
/// through its setter + getter, pinning the `BoolOverride` resolve logic:
/// `None` ⇒ the compiled default, `Some(true)` ⇒ true, `Some(false)` ⇒ false.
/// Uses a FRESH local config and sets the override EXPLICITLY, so the result is
/// deterministic and independent of any process env seeding.
pub fn tuning_phase2_plain_localizer_roundtrip_for_test(mode: Option<bool>) -> bool {
    let cfg = crate::tuning::ScannerTuning::default();
    cfg.set_phase2_plain_localizer(mode);
    cfg.phase2_plain_localizer_enabled()
}

/// As [`tuning_phase2_plain_localizer_roundtrip_for_test`] for the GPU region-presence
/// CPU recall floor override. Gated to `gpu`: it exercises the reader
/// `gpu_recall_floor_enabled`, which is itself `#[cfg(feature = "gpu")]` (the
/// GPU region-presence recall floor is a GPU-path-only knob), so the roundtrip
/// helper, and its one test, compile only where that reader exists. The
/// `ci-lean`/`portable` binaries have no GPU region path, so there is nothing
/// to round-trip there.
#[cfg(feature = "gpu")]
pub fn tuning_gpu_recall_floor_roundtrip_for_test(mode: Option<bool>) -> bool {
    let cfg = crate::tuning::ScannerTuning::default();
    cfg.set_gpu_recall_floor(mode);
    cfg.gpu_recall_floor_enabled()
}

/// Compiled default for the phase-2 localizer flag (what an unset override
/// resolves to).
pub const TUNING_LOCALIZER_DEFAULT: bool =
    crate::scanner_config::ScannerTuningConfig::FALLBACK_LOCALIZER_DEFAULT;

/// Compiled default for the GPU recall-floor flag.
pub const TUNING_GPU_RECALL_FLOOR_DEFAULT: bool =
    crate::scanner_config::ScannerTuningConfig::GPU_RECALL_FLOOR_DEFAULT;

/// GitLab detector-owned structural-validator verdict for `credential`, as a stable string
/// (`"valid"` / `"structurally-valid"` / `"invalid"` / `"not-applicable"`). Lets
/// a gap test pin the classic (20) and routable (16) body-length floors.
pub fn gitlab_checksum_verdict_for_test(credential: &str) -> &'static str {
    match crate::checksum::validate_checksum(credential) {
        crate::checksum::ChecksumResult::Valid => "valid",
        crate::checksum::ChecksumResult::StructurallyValid => "structurally-valid",
        crate::checksum::ChecksumResult::Invalid => "invalid",
        crate::checksum::ChecksumResult::NotApplicable => "not-applicable",
    }
}

/// Every detector-declared offline-validator prefix, exposed for behavioral
/// corpus tests. Values come from the embedded TOMLs, not a second Rust table.
pub fn checksum_prefixes() -> Vec<&'static str> {
    crate::checksum::detector_declared_prefixes()
}

/// SIMD prefilter hot-pattern `(prefix bytes, detector id)` bindings, exposed so
/// the `hot_pattern_prefixes_are_backed_by_their_detector` guard (an external
/// test crate) can bind each recall-load-bearing prefilter prefix to its
/// authoritative `detectors/<id>.toml` and prove the SIMD fast-path trigger set
/// never silently drifts from the detection pattern that surfaces the
/// credential. Detector ids are already single-owned via `crate::detector_ids`;
/// this surfaces the (prefix, id) pairing the guard needs.
#[cfg(feature = "simdsieve")]
pub fn simdsieve_hot_pattern_bindings() -> Vec<(&'static [u8], &'static str)> {
    (*crate::simdsieve_prefilter::HOT_PATTERNS)
        .iter()
        .copied()
        .zip(
            (*crate::simdsieve_prefilter::HOT_PATTERN_DETECTOR_IDS)
                .iter()
                .copied(),
        )
        .collect()
}

/// The single-owner PEM armor marker (`crate::credential_shapes::PEM_BEGIN_MARKER`),
/// exposed so a guard can bind it to its authoritative private-key detector TOML
/// proving the suppression carve-out and the entropy plausibility gate key off the
/// exact literal the detector uses to surface a PEM key (no bare-literal drift).
pub fn pem_begin_marker() -> &'static str {
    crate::credential_shapes::PEM_BEGIN_MARKER
}

/// The single-owner JWT base64url header marker
/// (`crate::jwt::JWT_BASE64_HEADER_PREFIX`), exposed so a guard can bind it to
/// the authoritative jwt-token detector TOML, proving the entropy plausibility
/// gate and the canonical-shape suppression check key off the exact `eyJ` marker
/// the detector uses to surface a JWT (no bare-literal drift).
pub fn jwt_header_prefix() -> &'static str {
    crate::jwt::JWT_BASE64_HEADER_PREFIX
}

/// npm checksum verdict for `credential`, as a stable string. Lets a gap test
/// pin the 36-char body length gate and the Valid path end to end.
pub fn npm_checksum_verdict_for_test(credential: &str) -> &'static str {
    match crate::checksum::validate_for_detector(crate::detector_ids::NPM_ACCESS_TOKEN, credential)
        .result()
    {
        crate::checksum::ChecksumResult::Valid => "valid",
        crate::checksum::ChecksumResult::StructurallyValid => "structurally-valid",
        crate::checksum::ChecksumResult::Invalid => "invalid",
        crate::checksum::ChecksumResult::NotApplicable => "not-applicable",
    }
}

/// The correct 6-char base62 CRC32 checksum for an npm token's `entropy`
/// prefix, so a gap test can build a genuinely-valid `npm_` token and pin the
/// entropy/checksum split (30 + 6) through the Valid path.
pub fn npm_expected_checksum_for_test(entropy: &str) -> String {
    crate::checksum::base62_encode_u32(crate::checksum::crc32(entropy.as_bytes()), 6)
}

/// Slack detector-owned structural-validator verdict for `credential`, as a
/// stable string. Both bot and user shapes come from their detector patterns.
pub fn slack_checksum_verdict_for_test(credential: &str) -> &'static str {
    match crate::checksum::validate_checksum(credential) {
        crate::checksum::ChecksumResult::Valid => "valid",
        crate::checksum::ChecksumResult::StructurallyValid => "structurally-valid",
        crate::checksum::ChecksumResult::Invalid => "invalid",
        crate::checksum::ChecksumResult::NotApplicable => "not-applicable",
    }
}

/// GitHub classic-PAT structural+checksum verdict for `credential`, as a stable
/// string. Lets a gap test pin the 36-char body gate and the 30/6 split.
pub fn github_classic_checksum_verdict_for_test(credential: &str) -> &'static str {
    match crate::checksum::validate_for_detector(
        crate::detector_ids::GITHUB_CLASSIC_PAT,
        credential,
    )
    .result()
    {
        crate::checksum::ChecksumResult::Valid => "valid",
        crate::checksum::ChecksumResult::StructurallyValid => "structurally-valid",
        crate::checksum::ChecksumResult::Invalid => "invalid",
        crate::checksum::ChecksumResult::NotApplicable => "not-applicable",
    }
}

/// GitHub fine-grained-PAT structural+checksum verdict for `credential`, as a
/// stable string.
pub fn github_fine_grained_checksum_verdict_for_test(credential: &str) -> &'static str {
    match crate::checksum::validate_for_detector(
        crate::detector_ids::GITHUB_PAT_FINE_GRAINED,
        credential,
    )
    .result()
    {
        crate::checksum::ChecksumResult::Valid => "valid",
        crate::checksum::ChecksumResult::StructurallyValid => "structurally-valid",
        crate::checksum::ChecksumResult::Invalid => "invalid",
        crate::checksum::ChecksumResult::NotApplicable => "not-applicable",
    }
}

/// Build the named-detector-owned assignment-key set from a single synthetic
/// detector (`service` + `keywords`) and return the owned keywords as plain
/// strings. Lets a gap test pin `build_generic_named_assignment_keywords`,
/// including the `MIN_SERVICE_NAME_LEN` service-name-length floor (a 2-char
/// service contributes nothing; a 3-char service can own a matching anchor).
pub fn generic_named_owned_keywords_for_test(service: &str, keywords: &[&str]) -> Vec<String> {
    let detector = keyhog_core::DetectorSpec {
        id: "acme-secret".to_string(),
        name: "Acme Secret".to_string(),
        service: service.to_string(),
        keywords: keywords.iter().map(|k| k.to_string()).collect(),
        ..Default::default()
    };
    crate::generic_keyword_owner::build_generic_named_assignment_keywords(std::slice::from_ref(
        &detector,
    ))
    .into_iter()
    .map(|owned| owned.to_string())
    .collect()
}

/// Probe the static interner's frozen source-type seed contract: build an
/// interner from zero detector strings (so its arena is exactly the seed
/// universe), then return the full `SEED_SOURCE_TYPES` list, whether each entry
/// is pre-interned (a `lookup` hit), and whether an unknown string is wrongly
/// interned. Lets a gap test pin the exact seed list so the module doc and the
/// constant cannot drift apart again.
pub fn static_interner_seed_probe_for_test() -> (Vec<&'static str>, Vec<bool>, bool) {
    let interner = crate::static_intern::StaticInterner::from_detector_strings(Vec::<&str>::new());
    let seeds: Vec<&'static str> = crate::static_intern::seed_source_types_leaked();
    let interned: Vec<bool> = seeds
        .iter()
        .map(|&s| interner.lookup(s).is_some())
        .collect();
    let unknown_interned = interner.lookup("definitely-not-a-source-type").is_some();
    (seeds, interned, unknown_interned)
}

#[cfg(feature = "simd")]
pub fn scan_coalesced_phase2_with_admission_for_test(
    scanner: &crate::CompiledScanner,
    chunks: &[keyhog_core::Chunk],
    triggers: Vec<Option<Vec<u64>>>,
    phase2_admission: Option<&[bool]>,
    phase2_admission_complete: Option<&[bool]>,
) -> Vec<Vec<keyhog_core::RawMatch>> {
    let negative_keyword_hints =
        phase2_admission_complete.map(|_| vec![Vec::<u32>::new(); chunks.len()]);
    let negative_anchor_presence = phase2_admission_complete.map(|_| vec![false; chunks.len()]);
    scanner.scan_coalesced_phase2_with_admission(
        chunks,
        triggers,
        phase2_admission,
        phase2_admission_complete,
        negative_keyword_hints.as_deref(),
        negative_anchor_presence.as_deref(),
        None,
        None,
        None,
        scanner.default_execution_route(),
    )
}

#[cfg(any(feature = "simd", feature = "gpu", test))]
pub fn scan_windowed_with_triggered_for_test(
    scanner: &crate::CompiledScanner,
    chunk: &keyhog_core::Chunk,
    triggered_patterns: &[u64],
) -> Vec<keyhog_core::RawMatch> {
    scanner.scan_windowed_with_triggered(
        chunk,
        triggered_patterns,
        None,
        None,
        None,
        None,
        None,
        scanner.default_execution_route(),
    )
}

#[cfg(any(feature = "simd", feature = "gpu", test))]
pub fn scan_windowed_with_triggered_evidence_for_test(
    scanner: &crate::CompiledScanner,
    chunk: &keyhog_core::Chunk,
    triggered_patterns: &[u64],
    confirmed_anchor_literal_matches: Option<&[(u32, u32)]>,
    generic_keyword_positions: Option<&[u32]>,
) -> Vec<keyhog_core::RawMatch> {
    scanner.scan_windowed_with_triggered(
        chunk,
        triggered_patterns,
        None,
        None,
        None,
        confirmed_anchor_literal_matches,
        generic_keyword_positions,
        scanner.default_execution_route(),
    )
}

#[cfg(test)]
pub(crate) fn scan_with_deadline(
    scanner: &crate::CompiledScanner,
    chunk: &Chunk,
    deadline: Option<std::time::Instant>,
) -> Vec<keyhog_core::RawMatch> {
    scanner.scan_with_deadline(chunk, deadline)
}

#[cfg(test)]
#[must_use = "hold the telemetry serial lock across scanner tests that touch process-global telemetry"]
pub(crate) fn telemetry_serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let lock = LOCK.get_or_init(|| Mutex::new(()));
    match lock.lock() {
        Ok(guard) => guard,
        // LAW10: testing-only mutex poisoning would cascade unrelated failures;
        // recover the inner guard so process-global telemetry state stays serialized.
        Err(poisoned) => {
            lock.clear_poison();
            poisoned.into_inner()
        }
    }
}

#[cfg(test)]
pub(crate) mod jwt {
    pub(crate) use crate::jwt::{JwtAnalysis, JwtAnomaly};

    pub(crate) fn analyze(s: &str) -> Option<JwtAnalysis> {
        crate::jwt::analyze(s)
    }

    pub(crate) fn anomalies_to_metadata(
        analysis: &JwtAnalysis,
    ) -> Option<std::collections::BTreeMap<String, String>> {
        crate::jwt::anomalies_to_metadata(analysis)
    }

    pub(crate) fn looks_like_jwt(s: &str) -> bool {
        crate::jwt::looks_like_jwt(s)
    }
}

pub mod confidence {
    #[derive(Debug, Clone, Copy)]
    pub struct ConfidenceSignals {
        pub has_literal_prefix: bool,
        pub has_context_anchor: bool,
        pub entropy: f64,
        pub keyword_nearby: bool,
        pub sensitive_file: bool,
        pub match_length: usize,
        pub has_companion: bool,
    }

    impl From<&ConfidenceSignals> for crate::confidence::ConfidenceSignals {
        fn from(signals: &ConfidenceSignals) -> Self {
            Self {
                has_literal_prefix: signals.has_literal_prefix,
                has_context_anchor: signals.has_context_anchor,
                entropy: signals.entropy,
                keyword_nearby: signals.keyword_nearby,
                sensitive_file: signals.sensitive_file,
                match_length: signals.match_length,
                has_companion: signals.has_companion,
            }
        }
    }

    pub fn compute_confidence(signals: &ConfidenceSignals) -> f64 {
        let detector = keyhog_core::detector_spec_by_id("generic-secret")
            .expect("embedded generic-secret detector");
        crate::confidence::policy::CompiledMatchConfidencePolicy::compile(detector)
            .expect("embedded generic-secret match confidence")
            .score(&signals.into(), crate::entropy::HIGH_ENTROPY_THRESHOLD)
    }

    pub fn known_prefix_confidence_floor(credential: &str) -> Option<f64> {
        crate::confidence::known_prefix_confidence_floor(credential)
    }

    pub fn known_prefix_body(credential: &str) -> Option<&str> {
        crate::confidence::known_prefix_body(credential)
    }

    pub use crate::confidence::KNOWN_PREFIXES;

    #[cfg(test)]
    pub(crate) fn finalize_confidence(score: f64) -> f64 {
        crate::confidence::penalties::finalize_confidence(score)
    }

    #[cfg(test)]
    pub(crate) fn contains_placeholder_word(credential: &str) -> bool {
        crate::confidence::penalties::contains_placeholder_word(credential)
    }

    pub fn placeholder_words() -> Vec<String> {
        crate::placeholder_words::words()
            .iter()
            .map(|word| word.lower().to_string())
            .collect()
    }

    /// The entropy-plausibility placeholder/decoy marker gate
    /// (`bytes_contain_entropy_placeholder_marker`), exposed so the integration
    /// tree can pin its exact suppression decisions. This is a SECOND, hardcoded
    /// marker vocabulary distinct from `placeholder_words()` (it carries
    /// heterogeneous match semantics: substring, length-gated, compound AKIA,
    /// angle-bracket, and whole-value-exact), so a behavioral lock is the
    /// prerequisite for any future move to Tier-B data without a recall change.
    pub fn entropy_placeholder_marker(bytes: &[u8]) -> bool {
        crate::placeholder_words::bytes_contain_entropy_placeholder_marker(bytes)
    }

    #[cfg(test)]
    pub(crate) fn parse_placeholder_words_for_test(raw: &str) -> Result<Vec<String>, String> {
        crate::placeholder_words::parse_placeholder_words(raw).map(|words| {
            words
                .into_iter()
                .map(|word| word.lower().to_string())
                .collect()
        })
    }

    #[cfg(test)]
    pub(crate) fn char_diversity(credential: &str) -> f64 {
        crate::confidence::penalties::char_diversity(credential)
    }

    /// Distinct-byte-count primitive shared by normalized_entropy /
    /// char_diversity / the ML unique_byte_count feature (DEDUP'd to one impl).
    pub fn unique_byte_count(data: &[u8]) -> usize {
        crate::entropy::unique_byte_count(data)
    }

    #[cfg(test)]
    pub(crate) fn max_repeat_run(credential: &str) -> f64 {
        crate::confidence::penalties::max_repeat_run(credential)
    }

    #[cfg(test)]
    pub(crate) fn apply_post_ml_penalties(score: f64, credential: &str, is_named: bool) -> f64 {
        crate::confidence::penalties::apply_post_ml_penalties_with_encoded_text_lift(
            score, credential, is_named, false, false,
        )
    }

    pub fn apply_calibration_multiplier(score: f64, detector_id: &str) -> f64 {
        crate::confidence::penalties::apply_calibration_multiplier(score, detector_id, None)
    }

    /// The whole report-confidence tail as one call, so the integration tree can
    /// lock the CONTRACTUAL ORDER of the penalty pipeline (post-ML penalties +
    /// encoded-text lift → path penalties → known-prefix floor → calibration
    /// multiplier → checksum decision) and its terminal behaviors, most
    /// importantly that the checksum decision runs LAST and can veto a match to
    /// `None` even after a known-prefix floor lifted it. `calibration` is fixed to
    /// `None` (the shipped default when no per-detector calibration store is
    /// loaded); the multiplier-bearing leg is covered separately via
    /// `apply_calibration_multiplier_with_store`. Primitive args only, since
    /// `ReportConfidencePolicy` is `pub(crate)`.
    pub fn finalize_report_confidence(
        confidence: f64,
        credential: &str,
        detector_id: &str,
        file_path: Option<&str>,
        is_named_detector: bool,
        penalize_test_paths: bool,
        allow_encoded_text_lift: bool,
    ) -> Option<f64> {
        crate::confidence::policy::finalize_report_confidence(
            confidence,
            crate::confidence::policy::ReportConfidencePolicy {
                credential,
                detector_id,
                file_path,
                is_named_detector,
                penalize_test_paths,
                allow_encoded_text_lift,
                allow_canonical_hex_key: false,
                checksum: crate::checksum::ChecksumConfidenceDecision::for_credential(credential),
                calibration: None,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn apply_calibration_multiplier_with_store(
        score: f64,
        detector_id: &str,
        calibration: &keyhog_core::Calibration,
    ) -> f64 {
        crate::confidence::penalties::apply_calibration_multiplier(
            score,
            detector_id,
            Some(calibration),
        )
    }

    #[cfg(test)]
    pub(crate) fn apply_path_confidence_penalties(
        score: f64,
        path: Option<&str>,
        penalize: bool,
    ) -> f64 {
        crate::confidence::penalties::apply_path_confidence_penalties(score, path, penalize)
    }

    #[cfg(test)]
    pub(crate) fn apply_known_prefix_floor(score: f64, credential: &str) -> f64 {
        crate::confidence::policy::apply_known_prefix_floor(score, credential)
    }

    #[cfg(test)]
    pub(crate) fn pre_ml_heuristic_confidence(
        raw_confidence: f64,
        code_context: crate::context::CodeContext,
        penalize_test_paths: bool,
    ) -> f64 {
        let confidence = crate::confidence::policy::CompiledMatchConfidencePolicy::compile(
            keyhog_core::detector_spec_by_id("generic-secret")
                .expect("embedded generic-secret detector"),
        )
        .expect("embedded generic-secret match confidence");
        crate::confidence::policy::pre_ml_heuristic_confidence(
            raw_confidence,
            code_context,
            penalize_test_paths,
            &confidence,
        )
    }

    #[cfg(test)]
    pub(crate) fn match_heuristic_confidence(
        signals: &crate::confidence::ConfidenceSignals,
        entropy_threshold: f64,
        code_context: crate::context::CodeContext,
        penalize_test_paths: bool,
    ) -> f64 {
        let confidence = crate::confidence::policy::CompiledMatchConfidencePolicy::compile(
            keyhog_core::detector_spec_by_id("generic-secret")
                .expect("embedded generic-secret detector"),
        )
        .expect("embedded generic-secret match confidence");
        crate::confidence::policy::match_heuristic_confidence(
            crate::confidence::policy::MatchHeuristicConfidencePolicy {
                has_literal_prefix: signals.has_literal_prefix,
                has_context_anchor: signals.has_context_anchor,
                entropy: signals.entropy,
                entropy_threshold,
                keyword_nearby: signals.keyword_nearby,
                sensitive_file: signals.sensitive_file,
                match_length: signals.match_length,
                has_companion: signals.has_companion,
                code_context,
                penalize_test_paths,
                confidence: &confidence,
            },
        )
    }

    #[cfg(all(test, feature = "ml"))]
    pub(crate) fn ml_pending_confidence(
        heuristic_confidence: f64,
        model_confidence: f64,
        ml_weight: f64,
        mode: keyhog_core::DetectorMlMode,
        code_context: crate::context::CodeContext,
        scan_comments: bool,
        penalize_test_paths: bool,
    ) -> f64 {
        let confidence = crate::confidence::policy::CompiledMatchConfidencePolicy::compile(
            keyhog_core::detector_spec_by_id("generic-secret")
                .expect("embedded generic-secret detector"),
        )
        .expect("embedded generic-secret match confidence");
        crate::confidence::policy::ml_pending_confidence(
            crate::confidence::policy::MlConfidencePolicy {
                heuristic_confidence,
                model_confidence,
                ml_weight,
                mode: match mode {
                    keyhog_core::DetectorMlMode::Lift => {
                        crate::detector_ml_policy::ActiveMlMode::Lift
                    }
                    keyhog_core::DetectorMlMode::Blend => {
                        crate::detector_ml_policy::ActiveMlMode::Blend
                    }
                    keyhog_core::DetectorMlMode::Authoritative => {
                        crate::detector_ml_policy::ActiveMlMode::Authoritative
                    }
                    keyhog_core::DetectorMlMode::Disabled => {
                        return heuristic_confidence;
                    }
                },
                code_context,
                context_multiplier: confidence.context_multiplier(code_context),
                scan_comments,
                penalize_test_paths,
            },
        )
    }

    #[cfg(all(test, feature = "ml"))]
    pub(crate) fn ml_score_for_candidate_text(text: &str, score: f64) -> f64 {
        crate::confidence::policy::ml_score_for_candidate_text(text, || score)
    }

    #[cfg(all(test, feature = "ml", feature = "gpu"))]
    pub(crate) fn apply_empty_candidate_score_policy(texts: &[&str], scores: &mut [f64]) {
        crate::confidence::policy::apply_empty_candidate_score_policy(texts.iter().copied(), scores)
    }

    #[cfg(all(test, feature = "ml"))]
    pub(crate) fn probabilistic_promise_confidence_override(
        credential: &str,
        is_named_detector: bool,
        has_companion: bool,
    ) -> Option<f64> {
        let detector_id = if is_named_detector {
            "aws-access-key"
        } else {
            "generic-secret"
        };
        let low_promise_confidence = keyhog_core::detector_spec_by_id(detector_id)
            .and_then(|detector| detector.match_confidence)
            .and_then(|confidence| confidence.low_promise_confidence);
        crate::confidence::policy::probabilistic_promise_confidence_override(
            credential,
            has_companion,
            low_promise_confidence,
        )
    }
}

pub mod entropy_fast {
    pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
        crate::entropy::fast::shannon_entropy_simd(data)
    }

    /// The exact scalar reference reduction (always-compiled production owner,
    /// shared by the x86/NEON fallbacks and `scan_loop`). Exposed so an external
    /// test can pin the SIMD dispatch against it to a few ULPs.
    pub fn shannon_entropy_scalar(data: &[u8]) -> f64 {
        crate::entropy::fast::shannon_entropy_scalar(data)
    }

    /// `(tier_is_stable_across_calls, tier_is_a_known_variant)` for the x86 entropy
    /// SIMD-tier resolver. The tier is `cpuid`-resolved exactly once and cached in a
    /// `OnceLock`, so two calls must return the identical variant, and it must be one
    /// of the three known tiers. Encapsulates the private `X86EntropyTier` in-crate.
    #[cfg(target_arch = "x86_64")]
    pub fn x86_entropy_tier_stability() -> (bool, bool) {
        use crate::entropy::fast::X86EntropyTier;
        let first = crate::entropy::fast::resolve_x86_entropy_tier();
        let second = crate::entropy::fast::resolve_x86_entropy_tier();
        let stable = first == second;
        let known = matches!(
            first,
            X86EntropyTier::Avx512 | X86EntropyTier::Avx2 | X86EntropyTier::Scalar
        );
        (stable, known)
    }
}

pub mod context {
    pub fn documentation_line_flags(lines: &[&str]) -> Vec<bool> {
        crate::context::documentation_line_flags(lines)
    }

    /// `is_false_positive_context`: true when the line at `line_idx` sits in a
    /// false-positive suppression context (SRI integrity body, disclaimer
    /// comment, …). External-test wrapper (the `#[cfg(test)]` sibling below is
    /// only visible to the lib's own inline tests).
    pub fn is_false_positive_context_for_test(
        lines: &[&str],
        line_idx: usize,
        file_path: Option<&str>,
    ) -> bool {
        crate::context::is_false_positive_context(lines, line_idx, file_path)
    }

    /// `is_false_positive_match_context`: same suppression decision resolved from
    /// a byte offset into the full text rather than a line index.
    pub fn is_false_positive_match_context_for_test(
        text: &str,
        match_start: usize,
        file_path: Option<&str>,
    ) -> bool {
        crate::context::is_false_positive_match_context(text, match_start, file_path)
    }

    /// `is_integrity_hash_bytes`: true when a line is an SRI `"integrity": "…"`
    /// body carrying a canonical `sha512-`/`sha384-`/`sha256-` label, the
    /// false-positive gate that must recognise EVERY canonical label.
    pub fn is_integrity_hash_bytes_for_test(bytes: &[u8]) -> bool {
        crate::context::is_integrity_hash_bytes(bytes)
    }

    /// `has_disclaimer_comment_bytes`: true when a line carries a disclaimer
    /// phrase INSIDE a comment marker (`<#`, `* `, …), a bare phrase without a
    /// comment marker must not trip.
    pub fn has_disclaimer_comment_bytes_for_test(bytes: &[u8]) -> bool {
        crate::context::has_disclaimer_comment_bytes(bytes)
    }

    /// The canonical `HASH_ALGO_INTEGRITY_LABELS` vocabulary, so an external test
    /// can prove the integrity gate recognises every label (sha384- regressed
    /// once when a diverging subset omitted it).
    pub fn hash_algo_integrity_labels_for_test() -> Vec<&'static str> {
        crate::suppression::shape::HASH_ALGO_INTEGRITY_LABELS.to_vec()
    }

    /// `is_in_test_function`: look-back classifier, true when the match line
    /// sits inside a test function. The look-back must STOP at a real
    /// `pub(crate) fn` boundary instead of walking past it to a sibling `#[test]`.
    pub fn is_in_test_function_for_test(lines: &[&str], line_idx: usize) -> bool {
        crate::context::is_in_test_function(lines, line_idx)
    }

    /// `is_rust_fn_signature`: true when a trimmed line is a Rust `fn` signature
    /// across the full qualifier family (pub/const/unsafe/async/extern/default).
    pub fn is_rust_fn_signature_for_test(trimmed: &str) -> bool {
        crate::context::is_rust_fn_signature(trimmed)
    }

    /// `strip_comment_prefix`: strips a leading canonical comment marker
    /// (`//`, `#`, `<#`, `* `, …) and returns the remainder, or `None` when the
    /// line is not comment-prefixed.
    pub fn strip_comment_prefix_for_test(trimmed: &str) -> Option<&str> {
        crate::context::strip_comment_prefix(trimmed)
    }

    #[cfg(test)]
    pub(crate) fn is_false_positive_match_context(
        text: &str,
        match_start: usize,
        file_path: Option<&str>,
    ) -> bool {
        crate::context::is_false_positive_match_context(text, match_start, file_path)
    }

    #[cfg(test)]
    pub(crate) fn is_false_positive_context(
        lines: &[&str],
        line_idx: usize,
        file_path: Option<&str>,
    ) -> bool {
        crate::context::is_false_positive_context(lines, line_idx, file_path)
    }

    #[cfg(test)]
    pub(crate) fn parse_disclaimer_phrases_for_test(raw: &str) -> Result<Vec<String>, String> {
        crate::context::parse_disclaimer_phrases(raw)
    }

    #[cfg(test)]
    pub(crate) fn parse_test_path_rules_for_test(
        raw: &str,
    ) -> Result<(Vec<String>, Vec<String>, Vec<String>), String> {
        let rules = crate::context::parse_test_path_rules(raw)?;
        Ok((
            rules.filename_prefixes,
            rules.filename_suffixes,
            rules.path_components,
        ))
    }

    pub fn is_known_example_credential(credential: &str) -> bool {
        crate::context::is_known_example_credential(credential)
    }

    #[cfg(test)]
    pub(crate) fn is_sequential_placeholder(credential: &str) -> bool {
        crate::context::is_sequential_placeholder(credential)
    }
}

pub mod fragment_cache {
    use std::sync::Arc;

    use zeroize::Zeroizing;

    #[derive(Clone)]
    pub struct SecretFragment {
        pub prefix: String,
        pub var_name: String,
        pub value: Zeroizing<String>,
        pub line: usize,
        pub path: Option<Arc<str>>,
    }

    impl std::fmt::Debug for SecretFragment {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SecretFragment")
                .field("prefix", &self.prefix)
                .field("var_name", &self.var_name)
                .field(
                    "value",
                    &format_args!("<redacted {} bytes>", self.value.len()),
                )
                .field("line", &self.line)
                .field("path", &self.path)
                .finish()
        }
    }

    pub struct ReassembledCandidate {
        pub value: Zeroizing<String>,
        pub path: Option<Arc<str>>,
        pub line: usize,
    }

    impl std::fmt::Debug for ReassembledCandidate {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ReassembledCandidate")
                .field(
                    "value",
                    &format_args!("<redacted {} bytes>", self.value.len()),
                )
                .field("path", &self.path)
                .field("line", &self.line)
                .finish()
        }
    }

    pub struct FragmentCache(crate::fragment_cache::FragmentCache);

    impl FragmentCache {
        pub fn new(capacity: usize) -> Self {
            Self(crate::fragment_cache::FragmentCache::new(capacity))
        }

        #[cfg(feature = "multiline")]
        pub(super) fn inner(&self) -> &crate::fragment_cache::FragmentCache {
            &self.0
        }

        pub fn record_and_reassemble(&self, fragment: SecretFragment) -> Vec<Zeroizing<String>> {
            self.0.record_and_reassemble(inner_fragment(fragment))
        }

        #[cfg(any(feature = "simd", test))]
        pub fn record_and_reassemble_stamped(
            &self,
            fragment: SecretFragment,
        ) -> Vec<ReassembledCandidate> {
            self.0
                .record_and_reassemble_stamped(inner_fragment(fragment))
                .into_iter()
                .map(|candidate| ReassembledCandidate {
                    value: candidate.value,
                    path: candidate.path,
                    line: candidate.line,
                })
                .collect()
        }

        pub fn clear(&self) {
            self.0.clear();
        }
    }

    fn inner_fragment(fragment: SecretFragment) -> crate::fragment_cache::SecretFragment {
        crate::fragment_cache::SecretFragment {
            prefix: fragment.prefix,
            var_name: fragment.var_name,
            value: fragment.value,
            line: fragment.line,
            path: fragment.path,
        }
    }

    pub fn shard_index_drift_probe(prefix: &str, scope: &str) -> (usize, usize) {
        crate::fragment_cache::shard_index_drift_probe(prefix, scope)
    }
}

#[cfg(feature = "multiline")]
pub mod multiline {
    pub use crate::multiline::MultilineConfig;

    /// Test seam for the multiline concatenation-indicator pre-scan, so a gap
    /// test can pin the `LARGE_FILE_KEYWORD_GATE_BYTES` (4096) threshold: under
    /// it the structural scan runs unconditionally; over it a secret-related
    /// keyword must be present or the chunk passes through unpreprocessed.
    pub fn has_concatenation_indicators_for_test(text: &str) -> bool {
        crate::multiline::has_concatenation_indicators(text)
    }

    /// Test seam for the structural template-interpolation resolver. Resolves a
    /// `` `${a}${b}` `` / `` `${"lit"}` `` template RHS against the given
    /// `(name, value)` variable bindings, returning the concatenated literal
    /// or `None` if any interpolation is an unresolved reference (so a partial
    /// candidate is never emitted). Lets a gap test pin the exact reassembly.
    pub fn resolve_template_reference_for_test(
        line: &str,
        vars: &[(&str, &str)],
    ) -> Option<String> {
        let map: std::collections::HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        crate::multiline::resolve_template_reference(line, &map)
    }

    /// Test seam for the fragment-name prefix extractor: strips `_`/`-`
    /// separators and `part` segments, lowercases, and trims a trailing numeric
    /// run so split-credential fragment names collapse to a shared base prefix.
    pub fn extract_prefix_for_test(var_name: &str) -> String {
        crate::multiline::extract_prefix(var_name)
    }

    /// Test seam for the `+`-concatenation string extractor. Returns the
    /// reassembled literal value and whether the line continues (trailing `+`),
    /// or `None` when the line is not a quoted-literal `+` concatenation. Lets a
    /// gap test pin the quote-aware assignment-prefix strip directly, so a
    /// base64 padding `=` inside the value's first literal never truncates the
    /// reassembled secret.
    #[cfg(feature = "multiline")]
    pub fn extract_plus_concatenation_for_test(line: &str) -> Option<(String, bool)> {
        crate::multiline::extract_plus_concatenation(line)
    }

    /// Test seam for the `.`-concatenation string extractor (PHP/Perl). Same
    /// contract as [`extract_plus_concatenation_for_test`] for the `.` join
    /// operator.
    #[cfg(feature = "multiline")]
    pub fn extract_dot_concatenation_for_test(line: &str) -> Option<(String, bool)> {
        crate::multiline::extract_dot_concatenation(line)
    }

    /// Test seam for the assignment-line RHS extractor: strips the Tier-B
    /// variable-declaration keyword prefix
    /// (`rules/multiline-var-decl-keywords.toml`) and returns the value side of
    /// the assignment. Lets a test pin that the keyword set is data-driven and
    /// complete without exposing the loader internals.
    #[cfg(feature = "multiline")]
    pub fn filter_line_content_for_test(line: &str) -> String {
        crate::multiline::filter_line_content(line)
    }

    /// Test seam for the multiline preprocessor join pass, returning the joined
    /// text and the preserved original-region length so a gap test can pin its
    /// contract: a passthrough chunk is carried through byte-identically while a
    /// real concatenation reassembles split string literals, and `original_end`
    /// always equals the input byte length on every path.
    pub fn preprocess_multiline_for_test(text: &str) -> (String, usize) {
        let config = MultilineConfig::default();
        let cache = crate::fragment_cache::FragmentCache::new(1024);
        let result = crate::multiline::preprocess_multiline(text, &config, &cache);
        (result.text.into_owned(), result.original_end)
    }

    #[derive(Debug, Clone)]
    pub struct LineMapping {
        pub start_offset: usize,
        pub end_offset: usize,
        pub line_number: usize,
        pub original_start_offset: usize,
        pub transport_decoded: bool,
    }

    #[derive(Debug, Clone)]
    pub struct PreprocessedText<'a> {
        pub text: std::borrow::Cow<'a, str>,
        pub original_end: usize,
        pub mappings: Vec<LineMapping>,
    }

    impl<'a> PreprocessedText<'a> {
        pub fn passthrough(text: impl Into<std::borrow::Cow<'a, str>>) -> Self {
            public_preprocessed(crate::multiline::PreprocessedText::passthrough(text))
        }

        pub fn line_for_offset(&self, offset: usize) -> Option<usize> {
            let idx = self.mappings.partition_point(|m| m.start_offset <= offset);
            if idx == 0 {
                return None;
            }
            let mapping = &self.mappings[idx - 1];
            if offset < mapping.end_offset {
                Some(mapping.line_number)
            } else {
                None
            }
        }
    }

    pub fn preprocess_multiline<'a>(
        text: impl Into<std::borrow::Cow<'a, str>>,
        config: &MultilineConfig,
        fragment_cache: &super::fragment_cache::FragmentCache,
    ) -> PreprocessedText<'a> {
        public_preprocessed(crate::multiline::preprocess_multiline(
            text,
            config,
            fragment_cache.inner(),
        ))
    }

    pub fn collect_structural_fragments_for_test(
        lines: &[&str],
        source_line_offsets: &[usize],
        initial_offset: usize,
        fragment_cache: &super::fragment_cache::FragmentCache,
    ) -> (Vec<String>, Vec<LineMapping>) {
        let (joined, mappings) = crate::multiline::collect_structural_fragments_for_test(
            lines,
            source_line_offsets,
            initial_offset,
            fragment_cache.inner(),
        );
        (
            joined,
            mappings
                .into_iter()
                .map(|mapping| LineMapping {
                    start_offset: mapping.start_offset,
                    end_offset: mapping.end_offset,
                    line_number: mapping.line_number,
                    original_start_offset: mapping.original_start_offset,
                    transport_decoded: mapping.transport_decoded,
                })
                .collect(),
        )
    }

    /// Test seam for the match-offset remap path. Builds the REAL
    /// `crate::multiline::PreprocessedText` from a single crafted mapping and
    /// drives `source_offset_for_match`, which ultimately slices `source` at the
    /// mapping's `original_start_offset`. On binary / lossy-UTF-8 input that
    /// offset can land inside a multi-byte scalar; before the
    /// `floor_char_boundary` snap that slice panicked ("byte index N is not a
    /// char boundary") and aborted the worker. Exercises the production code, not
    /// the facade mirror.
    pub fn source_offset_for_match_for_test(
        source: &str,
        offset: usize,
        credential: &str,
        mapping: LineMapping,
    ) -> usize {
        let pre = crate::multiline::PreprocessedText {
            text: std::borrow::Cow::Borrowed(source),
            original_end: source.len(),
            mappings: vec![crate::multiline::LineMapping {
                start_offset: mapping.start_offset,
                end_offset: mapping.end_offset,
                line_number: mapping.line_number,
                original_start_offset: mapping.original_start_offset,
                transport_decoded: mapping.transport_decoded,
            }],
        };
        pre.source_offset_for_match(source, offset, credential)
    }

    fn public_preprocessed<'a>(
        preprocessed: crate::multiline::PreprocessedText<'a>,
    ) -> PreprocessedText<'a> {
        PreprocessedText {
            text: preprocessed.text,
            original_end: preprocessed.original_end,
            mappings: preprocessed
                .mappings
                .into_iter()
                .map(|mapping| LineMapping {
                    start_offset: mapping.start_offset,
                    end_offset: mapping.end_offset,
                    line_number: mapping.line_number,
                    original_start_offset: mapping.original_start_offset,
                    transport_decoded: mapping.transport_decoded,
                })
                .collect(),
        }
    }
}

#[cfg(all(test, feature = "gpu"))]
pub(crate) use crate::compiler::build_gpu_literals;
#[cfg(all(test, feature = "gpu"))]
pub(crate) fn gpu_matcher_cache_dir_from_base(
    base: Option<std::path::PathBuf>,
) -> Result<std::path::PathBuf, String> {
    crate::engine::gpu_matcher_cache_dir_from_base(base).map_err(|error| error.to_string())
}
#[cfg(test)]
pub(crate) use crate::compiler::{
    build_ac_pattern_set, build_prefix_propagation, build_same_prefix_patterns,
    extract_inner_literals, extract_literal_prefix, extract_literal_prefixes, is_escaped_literal,
    rewrite_alternation_prefix, rewrite_homoglyph_literal_prefix, split_leading_inline_flag,
};
pub use crate::engine::{
    floor_char_boundary, line_number_for_offset, next_window_offset, record_window_match,
    window_chunk, window_end_offset, window_ranges,
};
#[cfg(test)]
pub(crate) use crate::homoglyph::expand_homoglyphs;
pub fn code_lines_from_offsets_for_test<'a>(text: &'a str, line_offsets: &[usize]) -> Vec<&'a str> {
    crate::engine::code_lines_from_offsets(text, line_offsets)
}
pub fn ascii_fold_regex_src_for_test(src: &str) -> String {
    crate::engine::phase2::ascii_fold_regex_src(src)
}
pub fn trigger_bitmap_words_for_test(n_patterns: usize) -> usize {
    crate::engine::trigger_bitmap::words_for(n_patterns)
}
pub fn has_fragment_assignment_syntax_for_test(data: &[u8]) -> bool {
    crate::engine::CompiledScanner::has_fragment_assignment_syntax(data)
}
pub fn suffix_gate_literals_for_test(src: &str) -> Vec<String> {
    crate::engine::suffix_gate_literals(src)
}
pub fn new_trigger_bitmap_for_test(n_patterns: usize) -> Vec<u64> {
    crate::engine::trigger_bitmap::new_trigger_bitmap(n_patterns)
}
/// Collect the bit indices `for_each_set_bit` reports for `words`, so a property
/// test can prove the confirmed-pass hot-path bit walk recovers EXACTLY the set
/// bits (no miss, no duplicate, strictly ascending). A missed bit silently drops
/// a detector trigger; a duplicate double-fires the confirmed extraction.
pub fn for_each_set_bit_collect_for_test(words: &[u64]) -> Vec<usize> {
    let mut out = Vec::new();
    crate::engine::trigger_bitmap::for_each_set_bit(words, |idx| out.push(idx));
    out
}
/// Whether an entropy candidate's keyword reads as a strong credential anchor
/// (admits the candidate past the file-extension gate). Reachable from
/// integration tests so the lazy-`to_ascii_lowercase` refactor can be pinned by
/// its real true/false outputs, not just source shape.
#[cfg(feature = "entropy")]
pub fn keyword_is_credential_anchor_for_test(keyword: &str) -> bool {
    crate::engine::phase2_entropy::helpers::keyword_is_credential_anchor(keyword)
}

/// Drive the shared `resolve_value_shaped_group` variable-name fallback through
/// a real compiled regex: compile `pattern`, match it against `text`, take the
/// configured `group`'s range as the starting credential, and return the range
/// the heuristic resolves to (the value-shaped sibling, or the original group).
/// Lets a test pin the heuristic behaviour both `extract_grouped_matches` and
/// `extract_anchored` now share.
pub fn resolve_value_shaped_group_for_test(
    pattern: &str,
    text: &str,
    group: usize,
) -> Option<(usize, usize)> {
    let re = regex::Regex::new(pattern).expect(
        "resolve_value_shaped_group_for_test: caller-supplied `pattern` must be a valid \
         regex (a malformed test pattern is a test-authoring bug, not a no-match result; \
         fix the pattern). `None` is reserved for the real no-match path below.",
    );
    let mut locs = re.capture_locations();
    re.captures_read(&mut locs, text)?;
    let current = locs.get(group)?;
    let groups_total = locs.len();
    Some(crate::engine::scan_filters::resolve_value_shaped_group(
        &locs,
        text,
        group,
        groups_total,
        current,
    ))
}
/// Compile a detector pattern (or companion) regex through the engine's EXACT
/// builder (`compiler_compile::shared_regex_compile`: case-insensitive, CRLF,
/// the engine's size / DFA limits) and return its capture-group count
/// `Regex::captures_len()`, i.e. the implicit whole-match group 0 plus every
/// explicit capture group.
///
/// The corpus capture-group-bound guard uses this to assert a detector's
/// declared `group = N` is a valid index in its OWN compiled regex. When it is
/// not (the regex has fewer than `N + 1` groups), `extract_grouped_matches`
/// falls back to the whole match (`locs.get(group).unwrap_or((full_start,
/// full_end))`), capturing keyword + separator + value instead of just the
/// secret, which both pollutes the reported credential and usually fails the
/// detector's checksum, dropping a real secret. Compiling through the engine
/// builder (not a fresh `Regex::new`) keeps the count identical to what the
/// scanner sees at run time and avoids a size-limit mismatch on the corpus's
/// largest patterns.
pub fn detector_regex_captures_len_for_test(pattern: &str) -> Result<usize, regex::Error> {
    crate::compiler::compiler_compile::shared_regex_compile(pattern).map(|re| re.captures_len())
}
/// Build a `CsrU32` from per-row index lists and read every row back out via
/// the public `get`, so a test can pin that the (now exactly-capacity-reserved)
/// build reconstructs the input rows byte-for-byte, including empty rows, the
/// case CSR specifically collapses to zero data bytes.
pub fn csr_from_rows_roundtrip_for_test(rows: Vec<Vec<usize>>) -> Vec<Vec<u32>> {
    let csr = crate::engine::CsrU32::from(rows.clone());
    (0..rows.len())
        .map(|i| csr.get(i).expect("row in range").to_vec())
        .collect()
}
pub use crate::pipeline::compute_line_offsets;
pub fn normalize_chunk_data(data: &str) -> std::borrow::Cow<'_, str> {
    crate::normalize_chunk_data(data)
}

/// Baseline confidence a service-anchored ("named") detector match is lifted to
/// when its regex required a context anchor. Exposed for the
/// `named_detector_anchor_floor` regression test.
pub const NAMED_DETECTOR_ANCHOR_FLOOR: f64 = 0.55;

/// Test seam for [`crate::confidence::policy::apply_named_detector_anchor_floor`].
/// `has_anchor` is `has_context_anchor || has_literal_prefix` at the call site.
pub fn apply_named_detector_anchor_floor(
    confidence: f64,
    is_named_detector: bool,
    has_anchor: bool,
) -> f64 {
    let floor = is_named_detector
        .then(|| keyhog_core::detector_spec_by_id("aws-access-key"))
        .flatten()
        .and_then(|detector| detector.match_confidence)
        .and_then(|policy| policy.named_anchor_floor);
    crate::confidence::policy::apply_named_detector_anchor_floor(confidence, floor, has_anchor)
}

/// Test seam for [`crate::suppression::shape::looks_like_english_prose`], the
/// prose-run heuristic that tightens FP filtering when a captured value reads like
/// English text rather than a credential (all-lowercase >= 16, or >= 2 all-alpha
/// words with at least one lowercase word).
pub fn looks_like_english_prose_for_test(value: &str) -> bool {
    crate::suppression::shape::looks_like_english_prose(value)
}

/// Test seam for [`crate::suppression::shape::looks_like_dashed_serial_key`], a
/// license/serial 5×5 dash shape (`XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`, 29 chars, alnum
/// groups). A product key, not a credential.
pub fn looks_like_dashed_serial_key_for_test(value: &str) -> bool {
    crate::suppression::shape::looks_like_dashed_serial_key(value)
}

/// Test seam for [`crate::suppression::shape::looks_like_prefixed_hash_digest`], a
/// hash-algo-labelled digest (`sha256:<64hex>`, `md5:<32hex>`, `sha256-<b64>`, …),
/// case-insensitive label, substring-matched (so `nginx@sha256:<hex>` counts). The
/// stripped body must itself be a canonical-length uniform hex or base64 integrity blob.
pub fn looks_like_prefixed_hash_digest_for_test(value: &str) -> bool {
    crate::suppression::shape::looks_like_prefixed_hash_digest(value)
}

/// Test seam for [`crate::suppression::shape::looks_like_prefixed_masked_sequence`]
/// a placeholder body: trailing `...` / `…`, OR an `xxx`/`***` mask prefix
/// followed by a sequential digit/alpha run (`xxxx1234567890`, `***abcdefgh`).
pub fn looks_like_prefixed_masked_sequence_for_test(value: &str) -> bool {
    crate::suppression::shape::looks_like_prefixed_masked_sequence(value)
}

/// Test seam for [`crate::suppression::shape::has_repeated_block_mask`], a masked
/// value: three or more long (>= 4) identical-char runs, OR a short block that
/// tiles the whole string (`abcabcabc…`).
pub fn has_repeated_block_mask_for_test(value: &str) -> bool {
    crate::suppression::shape::has_repeated_block_mask(value)
}

/// Test seam for [`crate::suppression::shape::looks_like_scheme_prefixed_uri`], a
/// `scheme:` / `scheme://` / hash-algo-labelled string (URI/URN shapes are not
/// secrets even though their tails look random).
pub fn looks_like_scheme_prefixed_uri_for_test(value: &str) -> bool {
    crate::suppression::shape::looks_like_scheme_prefixed_uri(value)
}

/// Test seam for [`crate::suppression::shape::looks_like_url_or_path_segment`], a
/// `/`-separated path (>= 2 non-empty segments, each alnum/`_`/`-`/`.` with a letter).
pub fn looks_like_url_or_path_segment_for_test(value: &str) -> bool {
    crate::suppression::shape::looks_like_url_or_path_segment(value)
}

/// Test seam for [`crate::suppression::shape::looks_like_filename_reference`], a
/// value ending (case-insensitively) in a known config/keystore file suffix.
pub fn looks_like_filename_reference_for_test(value: &str) -> bool {
    crate::suppression::shape::looks_like_filename_reference(value)
}

/// Test seam for [`crate::suppression::shape::looks_like_aws_iam_arn`], matches a
/// FULL IAM ARN (`arn:<partition>:iam::…:role|user|group|policy|instance-profile/…`).
pub fn looks_like_aws_iam_arn_for_test(value: &str) -> bool {
    crate::suppression::shape::looks_like_aws_iam_arn(value)
}

/// Test seam for [`crate::suppression::shape::looks_like_trimmed_aws_iam_arn`], the
/// PRE-TRIMMED gate: matches the same body WITHOUT the leading `arn:`. Deliberately
/// mutually exclusive with the full gate on the `arn:` prefix.
pub fn looks_like_trimmed_aws_iam_arn_for_test(value: &str) -> bool {
    crate::suppression::shape::looks_like_trimmed_aws_iam_arn(value)
}

/// Test seam for [`crate::suppression::shape::has_three_or_more_consecutive_identical`]
/// a masking-run detector that counts a run of ANY byte, dashes INCLUDED.
pub fn has_three_or_more_consecutive_identical_for_test(value: &str) -> bool {
    crate::suppression::shape::has_three_or_more_consecutive_identical(value)
}

/// Test seam for [`crate::suppression::shape::has_n_or_more_consecutive_identical`]
/// the parameterized run detector that EXCLUDES dashes (legitimate delimiters in
/// PEM/UUID/JWT). Deliberately diverges from the three-or-more variant on dash runs.
pub fn has_n_or_more_consecutive_identical_for_test(value: &str, n: usize) -> bool {
    crate::suppression::shape::has_n_or_more_consecutive_identical(value, n)
}

/// Test seam for [`crate::suppression::shape::looks_like_bracketed_template_placeholder`]
/// a `{…}` / `<…>` / `${…}` wrapper no longer than the placeholder cap (80 bytes).
pub fn looks_like_bracketed_template_placeholder_for_test(value: &str) -> bool {
    crate::suppression::shape::looks_like_bracketed_template_placeholder(value)
}

/// Test seam for [`crate::suppression::shape::source::looks_like_program_identifier`]
/// a bare snake_case (`my_program`) or camelCase (`myProgram`) all-alpha program
/// name; identifier grammar, not a secret.
pub fn looks_like_program_identifier_for_test(value: &str) -> bool {
    crate::suppression::shape::source::looks_like_program_identifier(value)
}

/// Test seam for [`crate::suppression::shape::source::looks_like_kebab_config_identifier`]
/// a short (<= 24) dash-joined majority-lowercase config key (`log-level`) with
/// no base64-ish `+`/`/`/`=` chars.
pub fn looks_like_kebab_config_identifier_for_test(value: &str) -> bool {
    crate::suppression::shape::source::looks_like_kebab_config_identifier(value)
}

/// Test seam for [`crate::suppression::shape::public::looks_like_public_reference_selector`]
/// a value made entirely of `[sources.IDENT]` TOML-table selectors (IDENT =
/// 3-80 upper/digit/`_`); a config reference, not a credential.
pub fn looks_like_public_reference_selector_for_test(value: &str) -> bool {
    crate::suppression::shape::public::looks_like_public_reference_selector(value)
}

/// Test seam for [`crate::suppression::shape::public::looks_like_percent_encoded_markup`]
/// percent-encoded XSS markup (encoded `<`…`>` around a script/handler keyword);
/// an attack payload the scanner captured, not a secret.
pub fn looks_like_percent_encoded_markup_for_test(value: &str) -> bool {
    crate::suppression::shape::public::looks_like_percent_encoded_markup(value)
}

/// Test seam for [`crate::suppression::shape::public::looks_like_html_event_handler_fragment`]
/// a bare `oneventname=` HTML event-handler attribute; executable grammar, not a secret.
pub fn looks_like_html_event_handler_fragment_for_test(value: &str) -> bool {
    crate::suppression::shape::public::looks_like_html_event_handler_fragment(value)
}

/// Test seam for [`crate::suppression::shape::is_canonical_service_hex_key`], a
/// uniform-case pure-hex value at a SERVICE-KEY width (`32/40/48/64`). Deliberately
/// a SUBSET of the bare-hex-digest widths (no 56/72/128), so a 56/72/128-hex value
/// is a digest but NOT a service key (the two must not be conflated).
pub fn is_canonical_service_hex_key_for_test(value: &str) -> bool {
    crate::suppression::shape::is_canonical_service_hex_key(value)
}

/// Test seam for [`crate::suppression::shape::looks_like_truncated_uuid_v4_suffix`]
/// a UUID v4 with its 2 leading hex chars dropped (34 chars, `6-4-4-4-12`,
/// version `4` at 12 + variant `8/9/a/b` at 17, uniform-case hex).
pub fn looks_like_truncated_uuid_v4_suffix_for_test(value: &str) -> bool {
    crate::suppression::shape::looks_like_truncated_uuid_v4_suffix(value)
}

/// Test seam for [`crate::suppression::shape::is_uuid_v4_shape`], a 36-char
/// canonical UUID (`8-4-4-4-12` with uniform-case hex bodies). Standard-shaped
/// UUIDs are FP decoys, so the gate matches every RFC-4122 version, not just v4.
pub fn is_uuid_v4_shape_for_test(value: &str) -> bool {
    crate::suppression::shape::is_uuid_v4_shape(value)
}

/// Test seam for [`crate::suppression::shape::looks_like_bare_hex_digest`], a
/// uniform-case pure-hex value at a hash / truncated-hash-prefix length
/// (`32/40/48/56/64/72/128`). These are digests or detector greedy-captures of a
/// digest span, never real keys (real keys of those widths are base64, not hex).
pub fn looks_like_bare_hex_digest_for_test(value: &str) -> bool {
    crate::suppression::shape::looks_like_bare_hex_digest(value)
}

fn generic_api_key_entropy_policy_for_test(
) -> &'static crate::entropy::policy::CompiledEntropyPolicy {
    static POLICY: std::sync::LazyLock<crate::entropy::policy::CompiledEntropyPolicy> =
        std::sync::LazyLock::new(|| {
            let detector = keyhog_core::detector_spec_by_id("generic-api-key")
                .expect("embedded generic-api-key detector must load");
            crate::entropy::policy::CompiledEntropyPolicy::compile(detector)
                .expect("embedded generic-api-key entropy policy must compile")
        });
    &POLICY
}

/// Test seam for [`crate::adjudicate::generic::bare_auth_value_allowed`], using
/// the shipped `generic-api-key` detector policy. Production passes the active
/// custom-corpus owner instead.
pub fn bare_auth_value_allowed_for_test(value: &str) -> bool {
    crate::adjudicate::generic::bare_auth_value_allowed(
        value,
        generic_api_key_entropy_policy_for_test(),
    )
}

/// Test seam for [`crate::suppression::shape::is_structured_dotted_token`], the
/// tight allowlist of dotted credential shapes (a JWT `header.payload.signature`
/// or a Discord `id.timestamp.hmac` token) that the scanner may trust despite the
/// dots. Property/method chains (`obj.field.method`) also use dots, so this must
/// stay a precise shape gate, never a general "contains a dot" relaxation.
pub fn is_structured_dotted_token_for_test(value: &str) -> bool {
    crate::suppression::shape::is_structured_dotted_token(value)
}

/// Test seam for [`crate::adjudicate::generic::generic_bridge_keyword_requires_word_boundary`]:
/// only the substring-ambiguous bridge keywords `pass`/`auth` require a
/// whole-word left boundary (others are distinctive enough to fire anywhere).
pub fn generic_bridge_keyword_requires_word_boundary_for_test(keyword: &str) -> bool {
    crate::adjudicate::generic::generic_bridge_keyword_requires_word_boundary(keyword)
}

/// Test seam for [`crate::adjudicate::generic::keyword_has_word_boundary`], the
/// left-boundary check that admits a camelCase hinge (`myPass` → boundary before
/// `Pass`) while rejecting a substring tail (`bypass` → no boundary). Pins the
/// exact FP-vs-recall contract for the `pass`/`auth` bridge keywords.
pub fn keyword_has_word_boundary_for_test(line: &str, keyword_start: usize) -> bool {
    crate::adjudicate::generic::keyword_has_word_boundary(line, keyword_start)
}

/// Test seam for [`crate::adjudicate::is_hex_digest_fragment`], the precision
/// gate that suppresses a detector match which is really a SUBSTRING of a longer
/// contiguous hex digest (a SHA-1/256 split across the match boundary). Returns
/// `true` (suppress) only when the credential is all-hex, at least the detector's
/// `min_len`, has hex context on at least one side, and the total surrounding hex
/// run reaches 40 chars (SHA-1 width). An unknown `detector_id` uses the default
/// `min_len` of 16, giving deterministic behavior without the detector registry.
pub fn is_hex_digest_fragment_for_test(
    detector_id: &str,
    data: &str,
    start: usize,
    end: usize,
    credential: &str,
) -> bool {
    let detector_min_len = keyhog_core::detector_spec_by_id(detector_id).and_then(|s| s.min_len);
    crate::adjudicate::is_hex_digest_fragment(detector_min_len, data, start, end, credential)
}

/// Test seam for the active-spec generic entropy floor. Accepts the exact
/// detector spec a compiled scanner would pass, so tests can prove a custom
/// detector policy wins without mutating the embedded corpus.
pub fn generic_entropy_floor_for_test(
    detector: &keyhog_core::DetectorSpec,
    entropy_threshold: f64,
    credential_len: usize,
) -> f64 {
    crate::entropy::policy::CompiledEntropyFloorPolicy::compile(detector)
        .expect("test detector entropy floor must compile")
        .expect("test detector must declare entropy_floor")
        .effective_floor(credential_len, entropy_threshold)
}

/// Test seam for [`crate::confidence::policy::entropy_fallback_confidence`].
/// `keyword_present=false` selects the keyword-free label; `true` applies the
/// embedded generic-secret detector's declared keyword lift. Exposed to pin the
/// NaN-sanitize contract without duplicating detector confidence values.
#[cfg(feature = "entropy")]
pub fn entropy_fallback_confidence_for_test(
    entropy: f64,
    keyword_present: bool,
    entropy_high: f64,
    entropy_very_high: f64,
) -> f64 {
    let keyword = if keyword_present {
        "password"
    } else {
        crate::entropy::KEYWORD_FREE_LABEL
    };
    let confidence = keyhog_core::detector_spec_by_id("generic-secret")
        .and_then(|detector| detector.entropy_fallback_confidence)
        .expect("embedded generic-secret detector must declare fallback confidence");
    crate::confidence::policy::entropy_fallback_confidence(
        entropy,
        keyword,
        entropy_high,
        entropy_very_high,
        confidence,
    )
}

/// Test seam for [`crate::confidence::policy::generic_assignment_confidence`].
/// `context_label` selects the `CodeContext` ("test" / "comment" / "doc" /
/// anything else = ordinary source) so a gap test can pin the exact confidence
/// formula without depending on the crate-internal `CodeContext` enum.
pub fn generic_secret_confidence_for_test(
    context_label: &str,
    scan_comments: bool,
    penalize_test_paths: bool,
    entropy: f64,
    value_len: usize,
) -> f64 {
    let context = match context_label {
        "test" => crate::context::CodeContext::TestCode,
        "comment" => crate::context::CodeContext::Comment,
        "doc" => crate::context::CodeContext::Documentation,
        "assignment" => crate::context::CodeContext::Assignment,
        _ => crate::context::CodeContext::Unknown,
    };
    let policy = keyhog_core::detector_spec_by_id("generic-secret")
        .and_then(|detector| detector.generic_assignment_confidence)
        .expect("embedded generic-secret detector must declare assignment confidence");
    crate::confidence::policy::generic_assignment_confidence(
        context,
        scan_comments,
        penalize_test_paths,
        entropy,
        value_len,
        policy,
    )
}

/// Test seam for [`crate::suppression::shape::is_canonical_service_hex_key`]: the
/// predicate that exempts a service-anchored detector's canonical-length pure-hex
/// capture from the bare-hex-digest shape gate.
pub fn is_canonical_service_hex_key(credential: &str) -> bool {
    crate::suppression::shape::is_canonical_service_hex_key(credential)
}
pub fn normalize_scannable_chunk<'a>(
    chunk: &'a keyhog_core::Chunk,
    owned: &'a mut Option<keyhog_core::Chunk>,
) -> &'a keyhog_core::Chunk {
    crate::pipeline::normalize_scannable_chunk(chunk, owned)
}
pub fn is_within_hex_context(data: &str, match_start: usize, match_end: usize) -> bool {
    crate::pipeline::is_within_hex_context(data, match_start, match_end)
}
pub fn local_context_window(text: &str, line: usize, radius: usize) -> &str {
    crate::pipeline::local_context_window(text, line, radius)
}
#[cfg(feature = "ml")]
pub fn ml_context_for_candidate(
    text: &str,
    line: usize,
    file_path: Option<&str>,
    context_radius_lines: usize,
) -> String {
    crate::scan_state::ml_context_for_candidate(text, line, file_path, context_radius_lines)
}

#[cfg(feature = "ml")]
/// Compute the exact feature vector stored in the production pending queue.
pub fn queued_ml_features(
    text: &str,
    line: usize,
    file_path: Option<&str>,
    credential: &str,
    context_radius_lines: usize,
    config: &crate::ScannerConfig,
    detector_id: &str,
    entropy_channel: bool,
) -> Vec<f32> {
    let detector = keyhog_core::detector_spec_by_id(detector_id)
        .unwrap_or_else(|| panic!("test detector {detector_id:?} must exist"));
    let detector_features =
        crate::ml_scorer::ml_features::CompiledDetectorMlFeatures::compile(detector);
    crate::scan_state::ml_features_for_candidate(
        text,
        line,
        file_path,
        credential,
        context_radius_lines,
        config,
        detector.service.as_str(),
        detector_features,
        if entropy_channel {
            crate::ml_scorer::MlCandidateChannel::Entropy
        } else {
            crate::ml_scorer::MlCandidateChannel::Pattern
        },
    )
    .to_vec()
}
pub fn match_entropy(data: &[u8]) -> f64 {
    crate::pipeline::match_entropy(data)
}
#[cfg(all(feature = "multiline", test))]
pub(crate) use crate::pipeline::{find_companion, line_window_offsets, match_line_number};
#[cfg(all(feature = "multiline", test))]
pub(crate) use crate::types::{CompiledCompanion, ScannerPreprocessedText};

#[cfg(all(feature = "multiline", not(test)))]
pub use multiline::PreprocessedText as ScannerPreprocessedText;
#[cfg(all(feature = "multiline", not(test)))]
pub struct CompiledCompanion {
    pub name: String,
    pub regex: regex::Regex,
    pub capture_group: Option<usize>,
    pub within_lines: usize,
    pub required: bool,
}
#[cfg(all(feature = "multiline", not(test)))]
fn inner_preprocessed<'a>(
    preprocessed: &ScannerPreprocessedText<'a>,
) -> crate::types::ScannerPreprocessedText<'a> {
    crate::types::ScannerPreprocessedText {
        text: preprocessed.text.clone(),
        original_end: preprocessed.original_end,
        mappings: preprocessed
            .mappings
            .iter()
            .map(|mapping| crate::multiline::LineMapping {
                start_offset: mapping.start_offset,
                end_offset: mapping.end_offset,
                line_number: mapping.line_number,
                original_start_offset: mapping.original_start_offset,
                transport_decoded: mapping.transport_decoded,
            })
            .collect(),
    }
}
#[cfg(all(feature = "multiline", not(test)))]
fn inner_companion(companion: &CompiledCompanion) -> crate::types::CompiledCompanion {
    crate::types::CompiledCompanion {
        name: companion.name.clone(),
        regex: companion.regex.clone(),
        capture_group: companion.capture_group,
        within_lines: companion.within_lines,
        required: companion.required,
    }
}
#[cfg(all(feature = "multiline", not(test)))]
pub fn match_line_number(
    preprocessed: &ScannerPreprocessedText<'_>,
    line_offsets: &[usize],
    offset: usize,
) -> usize {
    let inner = inner_preprocessed(preprocessed);
    crate::pipeline::match_line_number(&inner, line_offsets, offset)
}
#[cfg(all(feature = "multiline", not(test)))]
pub fn line_window_offsets(
    preprocessed: &ScannerPreprocessedText<'_>,
    start_line: usize,
    end_line: usize,
) -> Option<(usize, usize)> {
    let inner = inner_preprocessed(preprocessed);
    crate::pipeline::line_window_offsets(&inner, start_line, end_line)
}
#[cfg(all(feature = "multiline", not(test)))]
pub fn find_companion(
    preprocessed: &ScannerPreprocessedText<'_>,
    primary_line: usize,
    companion: &CompiledCompanion,
) -> Option<String> {
    let inner_preprocessed = inner_preprocessed(preprocessed);
    let inner_companion = inner_companion(companion);
    crate::pipeline::find_companion(&inner_preprocessed, primary_line, &inner_companion)
}
#[cfg(test)]
pub(crate) use crate::prefix_trie::build_propagation_table;
#[cfg(test)]
pub(crate) use crate::suppression::detector_weak_anchor;

pub fn detector_weak_anchor_for_test(spec: &keyhog_core::DetectorSpec) -> bool {
    crate::suppression::detector_weak_anchor(spec)
}

pub fn known_example_suppressed(
    credential: &str,
    path: Option<&str>,
    context: crate::context::CodeContext,
) -> bool {
    let stage = crate::suppression::api::suppress_known_example_credential_stage(
        credential,
        crate::suppression::api::KnownExampleSuppressionCtx::new(path, context, None),
    );
    if let Some(stage) = stage {
        let ctx = crate::adjudicate::MatchCtx::for_stage(stage);
        crate::adjudicate::record_suppression(path, credential, &ctx).is_some()
    } else {
        false
    }
}

pub fn known_example_suppressed_with_source(
    credential: &str,
    path: Option<&str>,
    context: crate::context::CodeContext,
    source_type: Option<&str>,
) -> bool {
    let stage = crate::suppression::api::suppress_known_example_credential_stage(
        credential,
        crate::suppression::api::KnownExampleSuppressionCtx::new(path, context, source_type),
    );
    if let Some(stage) = stage {
        let ctx = crate::adjudicate::MatchCtx::for_stage(stage);
        crate::adjudicate::record_suppression(path, credential, &ctx).is_some()
    } else {
        false
    }
}

pub fn named_detector_suppressed(
    credential: &str,
    path: Option<&str>,
    context: crate::context::CodeContext,
    source_type: Option<&str>,
    detector_id: &str,
) -> bool {
    let detector = keyhog_core::detector_spec_by_id(detector_id);
    let structural_password_slot = detector.is_some_and(|spec| spec.structural_password_slot);
    let service_anchored =
        detector.is_none_or(|spec| spec.kind != keyhog_core::DetectorKind::Phase2Generic);
    crate::suppression::api::suppress_named_detector_finding(
        credential,
        crate::suppression::api::NamedDetectorSuppressionCtx::with_weak_anchor(
            path,
            context,
            source_type,
            detector_id,
            service_anchored,
            false,
            structural_password_slot,
        ),
    )
}

pub fn scan_state_drain(
    matches: Vec<keyhog_core::RawMatch>,
    limit: usize,
) -> Vec<keyhog_core::RawMatch> {
    let mut state = crate::scan_state::ScanState::default();
    for m in matches {
        state.push_match(m, limit);
    }
    state.into_matches()
}

#[cfg(any(feature = "entropy", feature = "simdsieve"))]
pub fn scan_state_lazy_duplicate_probe_for_test() -> (bool, bool, Vec<keyhog_core::RawMatch>) {
    fn raw_match(confidence: f64) -> keyhog_core::RawMatch {
        scan_state_probe_match("duplicate", 7, confidence)
    }

    const LIMIT: usize = 2;
    let mut state = crate::scan_state::ScanState::default();
    state.push_match(raw_match(0.50), LIMIT);

    let mut worse_built = false;
    state.push_match_lazy(
        crate::scan_state::RawMatchPriority {
            confidence: Some(0.10),
            severity: keyhog_core::Severity::High,
            detector_id: "gate",
            credential: "duplicate",
            offset: 7,
            line: Some(8),
        },
        LIMIT,
        |_| {
            worse_built = true;
            raw_match(0.10)
        },
    );

    let mut better_built = false;
    state.push_match_lazy(
        crate::scan_state::RawMatchPriority {
            confidence: Some(0.90),
            severity: keyhog_core::Severity::High,
            detector_id: "gate",
            credential: "duplicate",
            offset: 7,
            line: Some(8),
        },
        LIMIT,
        |_| {
            better_built = true;
            raw_match(0.90)
        },
    );

    (worse_built, better_built, state.into_matches())
}

#[cfg(any(feature = "entropy", feature = "simdsieve"))]
pub fn scan_state_lazy_overestimated_priority_probe_for_test() -> (bool, Vec<keyhog_core::RawMatch>)
{
    const LIMIT: usize = 1;
    let mut state = crate::scan_state::ScanState::default();
    state.push_match(scan_state_probe_match("retained", 7, 0.90), LIMIT);

    let mut built = false;
    state.push_match_lazy(
        crate::scan_state::RawMatchPriority {
            confidence: Some(0.99),
            severity: keyhog_core::Severity::High,
            detector_id: "gate",
            credential: "overestimated",
            offset: 14,
            line: Some(15),
        },
        LIMIT,
        |_| {
            built = true;
            scan_state_probe_match("overestimated", 14, 0.10)
        },
    );

    (built, state.into_matches())
}

#[cfg(any(feature = "entropy", feature = "simdsieve"))]
pub fn scan_state_lazy_identity_tiebreak_probe_for_test() -> (bool, Vec<keyhog_core::RawMatch>) {
    const LIMIT: usize = 1;
    let mut state = crate::scan_state::ScanState::default();
    let mut retained = scan_state_probe_match("duplicate", 7, 0.50);
    retained.detector_name = std::sync::Arc::from("Zulu detector");
    state.push_match(retained, LIMIT);

    let mut built = false;
    state.push_match_lazy(
        crate::scan_state::RawMatchPriority {
            confidence: Some(0.50),
            severity: keyhog_core::Severity::High,
            detector_id: "gate",
            credential: "duplicate",
            offset: 7,
            line: Some(8),
        },
        LIMIT,
        |_| {
            built = true;
            let mut candidate = scan_state_probe_match("duplicate", 7, 0.50);
            candidate.detector_name = std::sync::Arc::from("Alpha detector");
            candidate
        },
    );

    (built, state.into_matches())
}

#[cfg(any(feature = "entropy", feature = "simdsieve"))]
fn scan_state_probe_match(
    credential: &'static str,
    offset: usize,
    confidence: f64,
) -> keyhog_core::RawMatch {
    keyhog_core::RawMatch {
        detector_id: std::sync::Arc::from("gate"),
        detector_name: std::sync::Arc::from("Gate"),
        service: std::sync::Arc::from("test"),
        severity: keyhog_core::Severity::High,
        credential: keyhog_core::SensitiveString::from(credential),
        credential_hash: [0u8; 32].into(),
        companions: std::collections::HashMap::new(),
        location: keyhog_core::MatchLocation {
            source: std::sync::Arc::from("unit"),
            file_path: Some(std::sync::Arc::from("unit.env")),
            line: Some(offset + 1),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(confidence),
    }
}

#[cfg(test)]
pub(crate) fn scan_state_drain_with_static_intern(
    matches: Vec<keyhog_core::RawMatch>,
    limit: usize,
) -> Vec<keyhog_core::RawMatch> {
    let interner = std::sync::Arc::new(crate::static_intern::StaticInterner::default());
    let mut state = crate::scan_state::ScanState::with_static_intern(interner);
    for m in matches {
        state.push_match(m, limit);
    }
    state.into_matches()
}

#[derive(Clone)]
#[cfg(test)]
pub(crate) struct LazyRegexProbe(crate::types::LazyRegex);

#[cfg(test)]
impl LazyRegexProbe {
    pub(crate) fn detector(src: impl Into<std::sync::Arc<str>>) -> Self {
        Self(crate::types::LazyRegex::detector(src))
    }

    pub(crate) fn detector_compiled(
        src: impl Into<std::sync::Arc<str>>,
        compiled: std::sync::Arc<regex::Regex>,
    ) -> Self {
        Self(crate::types::LazyRegex::detector_compiled(src, compiled))
    }

    pub(crate) fn plain(src: impl Into<std::sync::Arc<str>>) -> Self {
        Self(crate::types::LazyRegex::plain(src))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn get(&self) -> &regex::Regex {
        self.0.get()
    }

    pub(crate) fn has_literal_prefix(&self) -> bool {
        self.0.has_literal_prefix()
    }
}

#[cfg(test)]
pub(crate) fn phase2_keyword_ac_summary(regex: &str, keywords: Vec<String>) -> (bool, usize) {
    let pattern = crate::types::CompiledPattern {
        detector_index: 0,
        regex: crate::types::LazyRegex::detector(regex),
        group: None,
        client_safe: false,
        weak_anchor: false,
        match_proves_keyword_nearby: false,
        homoglyph_variant: false,
    };
    let phase2_patterns = vec![(pattern, keywords)];
    let (ac, mapping, _keywords) = crate::compiler::build_phase2_keyword_ac(&phase2_patterns);
    (ac.is_some(), mapping.len())
}

#[cfg(test)]
pub(crate) fn compile_state_ac_literals(
    detectors: &[keyhog_core::DetectorSpec],
) -> crate::error::Result<Vec<String>> {
    crate::compiler::build_compile_state(detectors).map(|state| state.ac_literals)
}

#[cfg(test)]
pub(crate) fn compile_state_phase2_regexes(
    detectors: &[keyhog_core::DetectorSpec],
) -> crate::error::Result<Vec<String>> {
    crate::compiler::build_compile_state(detectors).map(|state| {
        state
            .phase2_patterns
            .into_iter()
            .map(|(pattern, _)| pattern.regex.as_str().to_string())
            .collect()
    })
}

#[cfg(test)]
pub(crate) fn compile_state_is_ok(detectors: &[keyhog_core::DetectorSpec]) -> bool {
    crate::compiler::build_compile_state(detectors).is_ok()
}

#[cfg(test)]
pub(crate) fn compile_state_error(
    detectors: &[keyhog_core::DetectorSpec],
) -> Option<crate::ScanError> {
    crate::compiler::build_compile_state(detectors).err()
}

#[cfg(test)]
pub(crate) fn phase2_anchor_stats(
    scanner: &crate::engine::CompiledScanner,
) -> (usize, usize, usize) {
    scanner.phase2_anchor_stats()
}

#[cfg(test)]
pub(crate) fn phase2_pattern_diagnostics(
    scanner: &crate::engine::CompiledScanner,
) -> Vec<(String, Vec<String>)> {
    scanner.phase2_pattern_diagnostics()
}

#[cfg(test)]
pub(crate) use crate::compiled_scanner::Phase2PoolBreakdown;

#[cfg(test)]
pub(crate) fn phase2_always_active_family_breakdown(
    scanner: &crate::engine::CompiledScanner,
) -> Phase2PoolBreakdown {
    scanner.phase2_always_active_family_breakdown()
}

#[cfg(all(test, feature = "simd"))]
pub(crate) fn bench_hs_homoglyph_skip(
    scanner: &crate::engine::CompiledScanner,
    haystack: &str,
    n_calls: u32,
) -> (f64, f64, usize, usize) {
    scanner.bench_hs_homoglyph_skip(haystack, n_calls)
}

#[cfg(all(test, feature = "simd"))]
pub(crate) fn hs_mark_full_vs_lean_diff(
    scanner: &crate::engine::CompiledScanner,
    ascii_text: &str,
) -> (usize, usize, Vec<usize>, Vec<usize>) {
    scanner.hs_mark_full_vs_lean_diff(ascii_text)
}

#[cfg(test)]
pub(crate) fn phase2_required_prefix_literals(src: &str) -> Option<Vec<String>> {
    crate::engine::phase2_required_prefix_literals_for_test(src)
}

/// Return the exact finite prefixes that make a confirmed pattern eligible for
/// shared-anchor extraction. Integration tests use the production cap and
/// parser rather than duplicating either contract.
pub fn confirmed_required_prefix_literals(src: &str) -> Option<Vec<String>> {
    crate::engine::required_prefix_literals_with_cap(
        src,
        crate::engine::CONFIRMED_MAX_LITERALS_PER_PATTERN,
    )
}

#[cfg(test)]
pub(crate) fn phase2_gate_prefix_literals(src: &str) -> Option<Vec<Vec<u8>>> {
    crate::engine::phase2::gate_prefix_literals(src)
}

#[cfg(test)]
pub(crate) fn set_test_backend_override(mode: Option<crate::hw_probe::ScanBackend>) {
    crate::hw_probe::select::set_test_backend_override(mode);
}

#[cfg(test)]
pub(crate) fn clear_test_backend_override() {
    crate::hw_probe::select::clear_test_backend_override();
}

#[cfg(test)]
pub(crate) mod thresholds {
    pub(crate) const GPU_MIN_BYTES: u64 = crate::hw_probe::thresholds::GPU_MIN_BYTES;
    pub(crate) const GPU_MIN_BYTES_MID_TIER: u64 =
        crate::hw_probe::thresholds::GPU_MIN_BYTES_MID_TIER;
    pub(crate) const GPU_MIN_BYTES_HIGH_TIER: u64 =
        crate::hw_probe::thresholds::GPU_MIN_BYTES_HIGH_TIER;
    pub(crate) const GPU_PATTERN_BREAKEVEN: usize =
        crate::hw_probe::thresholds::GPU_PATTERN_BREAKEVEN;
    pub(crate) const GPU_PATTERN_BREAKEVEN_HIGH_TIER: usize =
        crate::hw_probe::thresholds::GPU_PATTERN_BREAKEVEN_HIGH_TIER;
    pub(crate) const GPU_BYTES_BREAKEVEN_SOLO: u64 =
        crate::hw_probe::thresholds::GPU_BYTES_BREAKEVEN_SOLO;
    pub(crate) const GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER: u64 =
        crate::hw_probe::thresholds::GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER;
}

pub fn set_phase2_hs(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning.set_phase2_hs(mode);
}

#[cfg(feature = "simd")]
pub fn phase2_hyperscan_initialized(scanner: &crate::engine::CompiledScanner) -> bool {
    scanner
        .phase2_always_active_prefilter
        .as_ref()
        .is_some_and(|prefilter| prefilter.hyperscan_initialized())
}

/// Score the production cl100k token-efficiency gate. Benchmarks use this
/// instead of substituting Shannon entropy under a BPE label.
#[cfg(feature = "entropy")]
pub fn entropy_bpe_bytes_per_token(value: &str) -> f64 {
    crate::entropy::bpe::bytes_per_token(value)
}

/// Construct the same cl100k tokenizer used by the production BPE gate. This
/// isolates initialization cost from warm per-candidate scoring.
#[cfg(feature = "entropy")]
pub fn build_entropy_bpe_tokenizer() -> Result<tiktoken_rs::CoreBPE, String> {
    tiktoken_rs::cl100k_base().map_err(|error| error.to_string())
}

/// Process-global file and byte counts recorded by scanner entry points.
pub fn telemetry_scan_counts() -> (usize, usize) {
    crate::telemetry::global_scan_counts()
}

#[cfg(all(test, feature = "simd"))]
pub(crate) fn set_hs_prefilter_max_len(
    scanner: &crate::engine::CompiledScanner,
    threshold: Option<usize>,
) {
    scanner.tuning().set_hs_prefilter_max_len(threshold);
}

#[cfg(test)]
pub(crate) fn set_phase2_anchor_mode(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning().set_phase2_anchor_mode(mode);
}

#[cfg(test)]
pub(crate) fn set_phase2_homoglyph_gate(
    scanner: &crate::engine::CompiledScanner,
    mode: Option<bool>,
) {
    scanner.tuning().set_phase2_homoglyph_gate(mode);
}

pub fn set_homoglyph_ascii_skip(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning.set_homoglyph_ascii_skip(mode);
}

pub fn set_phase2_reverse(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning.set_phase2_reverse(mode);
}

#[cfg(test)]
pub(crate) fn set_prefilter_truncate(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning().set_prefilter_truncate(mode);
}

#[cfg(test)]
pub(crate) fn set_phase2_prefix_gate(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning().set_phase2_prefix_gate(mode);
}

#[cfg(test)]
pub(crate) fn set_decode_focus(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning().set_decode_focus(mode);
}

#[cfg(test)]
pub(crate) fn set_confirmed_suffix_gate(
    scanner: &crate::engine::CompiledScanner,
    mode: Option<bool>,
) {
    scanner.tuning().set_confirmed_suffix_gate(mode);
}

#[cfg(test)]
pub(crate) fn disable_confirmed_anchor(scanner: &mut crate::engine::CompiledScanner) {
    scanner.disable_confirmed_anchor_for_test();
}

#[cfg(test)]
pub(crate) fn confirmed_anchor_eligible_count(scanner: &crate::engine::CompiledScanner) -> usize {
    scanner.confirmed_anchor_eligible_count_for_test()
}

#[cfg(test)]
pub(crate) fn confirmed_anchor_kind(
    scanner: &crate::engine::CompiledScanner,
) -> Option<aho_corasick::AhoCorasickKind> {
    scanner.confirmed_anchor_kind_for_test()
}

#[cfg(test)]
pub(crate) fn set_no_candidate_gate(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning().set_no_candidate_gate(mode);
}

/// SWE-101 perf probe: directly time `mark_matches` on a no-candidate text,
/// bypassing the phase-1 HS scan so only the gate path is measured.
/// Returns mean ns/call over `n_calls` warm iterations.
#[cfg(test)]
pub(crate) fn mark_matches_gate_ns_per_call(
    scanner: &crate::engine::CompiledScanner,
    text: &str,
    n_calls: u32,
) -> f64 {
    scanner.mark_matches_gate_ns_per_call(text, n_calls)
}

/// Prefilter `{N,}`→`{N}` truncation, exposed for the sound-superset unit
/// tests migrated out of `src/engine/phase2.rs` (no-inline-tests gate).
#[cfg(test)]
pub(crate) fn truncate_for_prefilter(src: &str) -> Option<String> {
    crate::engine::phase2_truncate::truncate_for_prefilter(src)
}

#[cfg(test)]
pub(crate) fn phase2_truncated_set_failure_matches_full_set(
    srcs: &[&str],
    trunc_srcs: &[String],
    case_insensitive: bool,
    text: &str,
) -> Result<Vec<usize>, regex::Error> {
    crate::engine::phase2::Phase2AlwaysActivePrefilter::compile_truncated_or_full_set(
        srcs,
        trunc_srcs,
        case_insensitive,
    )
    .map(|set| set.matches(text).iter().collect())
}
#[cfg(test)]
pub(crate) fn looks_like_program_identifier(value: &str) -> bool {
    crate::suppression::shape::looks_like_program_identifier(value)
}

/// The single shared prose-whitespace predicate behind BOTH the direct
/// `prose_whitespace` suppression gate and the base64-decoded
/// `decoded_prose_whitespace` twin (DEDUP, µ-dcn-12). Exposed so a test can pin
/// the one threshold both paths now share.
#[cfg(test)]
pub(crate) fn looks_like_prose_whitespace_run(value: &str) -> bool {
    crate::suppression::decision::looks_like_prose_whitespace_run(value)
}

/// Internal entropy shape-classification predicates, exposed for the
/// canonical-shape unit tests migrated out of `src/entropy/scanner.rs`
/// (KH-GAP-004). `credential_keyword_context` builds the production
/// credential anchor so tests need not know the private tuning constants.
pub mod entropy_scanner {
    fn compile_detector_plans(
        detectors: &[keyhog_core::DetectorSpec],
    ) -> crate::detector_plan::CompiledDetectorPlans {
        let strings = detectors
            .iter()
            .flat_map(|detector| {
                [
                    detector.id.as_str(),
                    detector.name.as_str(),
                    detector.service.as_str(),
                ]
                .into_iter()
                .chain(
                    detector
                        .entropy_fallback
                        .as_ref()
                        .into_iter()
                        .flat_map(|metadata| {
                            [
                                metadata.id.as_str(),
                                metadata.name.as_str(),
                                metadata.service.as_str(),
                            ]
                        }),
                )
            })
            .collect::<Vec<_>>();
        let interner = crate::static_intern::StaticInterner::from_detector_strings(strings);
        let companions = std::iter::repeat_with(Vec::new)
            .take(detectors.len())
            .collect();
        crate::detector_plan::CompiledDetectorPlans::compile(detectors, &interner, companions)
            .expect("test detector plans must compile")
    }

    pub struct KeywordContext {
        inner: crate::entropy::keywords::KeywordContext,
        pub threshold: f64,
    }

    impl KeywordContext {
        fn from_inner(inner: crate::entropy::keywords::KeywordContext) -> Self {
            Self {
                threshold: inner.threshold,
                inner,
            }
        }
    }

    pub fn credential_keyword_context(keyword: &str) -> KeywordContext {
        KeywordContext::from_inner(crate::entropy::scanner::credential_keyword_context(keyword))
    }

    pub fn candidate_is_plausible(
        candidate: &str,
        entropy: f64,
        context: &KeywordContext,
        placeholder_keywords: &[String],
    ) -> bool {
        crate::entropy::scanner::candidate_is_plausible(
            candidate,
            entropy,
            &context.inner,
            placeholder_keywords,
        )
    }

    /// Run the production entropy generator against a caller-supplied detector
    /// corpus. This proves custom keyword ownership affects real candidate
    /// admission rather than only the index shape.
    pub fn active_policy_match_values(
        detectors: Vec<keyhog_core::DetectorSpec>,
        keyword: &str,
        line: &str,
    ) -> Vec<String> {
        use crate::entropy::scanner::ActiveDetectorPolicy;
        use crate::generic_keyword_owner::GenericOwningDetectorIndex;

        let index = GenericOwningDetectorIndex::build(&detectors)
            .expect("test detector entropy roles must be unique");
        let detector_plans = compile_detector_plans(&detectors);
        let policy = ActiveDetectorPolicy::new(&index, &detector_plans);
        let secret_keywords = vec![keyword.to_string()];
        crate::entropy::scanner::find_entropy_secrets_with_precomputed_keywords_and_policy(
            &[line],
            &[0],
            &[(0, line)],
            1,
            0,
            0.0,
            Some(crate::entropy::VERY_HIGH_ENTROPY_THRESHOLD),
            &secret_keywords,
            &[],
            &[],
            None,
            Some(policy),
            crate::entropy::scanner::KeywordFreeLineScope::All,
        )
        .into_iter()
        .filter(|candidate| candidate.keyword == keyword)
        .map(|candidate| candidate.value)
        .collect()
    }

    /// Resolve the exact active detector that owns entropy policy for a
    /// keyword or synthetic entropy label.
    pub fn active_policy_owner_id(
        detectors: &[keyhog_core::DetectorSpec],
        keyword: &str,
    ) -> Option<String> {
        let index =
            crate::generic_keyword_owner::GenericOwningDetectorIndex::build(detectors).ok()?;
        crate::entropy::scanner::active_policy_detector_index(&index, keyword)
            .and_then(|owner| detectors.get(owner))
            .map(|detector| detector.id.clone())
    }

    #[cfg(test)]
    pub(crate) fn candidate_plausibility_rejection_reason(
        candidate: &str,
        entropy: f64,
        context: &KeywordContext,
        placeholder_keywords: &[String],
    ) -> Option<&'static str> {
        crate::entropy::scanner::candidate_plausibility_rejection_stage(
            candidate,
            entropy,
            &context.inner,
            placeholder_keywords,
        )
        .map(|stage| stage.as_str())
    }

    pub fn is_canonical_non_secret_shape(value: &str) -> bool {
        crate::entropy::scanner::is_canonical_non_secret_shape(value)
    }

    #[cfg(test)]
    pub fn isolated_keyword_free_match_count_with_min_len(
        secret: &str,
        generic_keyword_secret_min_len: usize,
    ) -> usize {
        use crate::entropy::scanner::ActiveDetectorPolicy;
        use crate::generic_keyword_owner::GenericOwningDetectorIndex;

        let mut detectors = keyhog_core::embedded_detector_specs().to_vec();
        detectors
            .iter_mut()
            .find(|detector| {
                detector
                    .entropy_roles
                    .contains(&keyhog_core::EntropyDetectionRole::IsolatedBare)
            })
            .expect("embedded corpus must declare an isolated-bare entropy owner")
            .keyword_free_min_len = Some(generic_keyword_secret_min_len);
        let index = GenericOwningDetectorIndex::build(&detectors)
            .expect("embedded detector entropy roles must be unique");
        let detector_plans = compile_detector_plans(&detectors);
        let policy = ActiveDetectorPolicy::new(&index, &detector_plans);
        crate::entropy::scanner::find_entropy_secrets_with_precomputed_keywords_and_policy(
            &[secret],
            &[0],
            &[],
            1,
            1,
            crate::entropy::HIGH_ENTROPY_THRESHOLD,
            Some(crate::entropy::VERY_HIGH_ENTROPY_THRESHOLD),
            &[],
            &[],
            &[],
            None,
            Some(policy),
            crate::entropy::scanner::KeywordFreeLineScope::All,
        )
        .into_iter()
        .filter(|candidate| candidate.keyword == "none (isolated-token)")
        .count()
    }
}

/// Keyword-free ("isolated bare") high-entropy secret recall floors. These rescue
/// a high-entropy token that carries NO surrounding secret keyword, so each has a
/// carefully-tuned entropy + shape threshold. Exposed so the thresholds can be
/// pinned at their boundaries against silent recall regression.
#[cfg(feature = "entropy")]
pub mod entropy_isolated {
    fn generic_keyword_policy() -> crate::entropy::policy::CompiledEntropyPolicy {
        let detector = keyhog_core::detector_spec_by_id("generic-keyword-secret")
            .expect("embedded generic-keyword-secret detector must load");
        crate::entropy::policy::CompiledEntropyPolicy::compile(detector)
            .expect("embedded generic-keyword-secret entropy policy must compile")
    }

    /// Apply the embedded isolated-bare owner's mixed-token floor and minimum
    /// length to an underscore-separated mixed token.
    pub fn mixed_separator_token_floor_met(candidate: &str, entropy: f64) -> bool {
        let policy = generic_keyword_policy();
        crate::entropy::scanner::mixed_separator_token_floor_met(
            candidate,
            entropy,
            policy.isolated_mixed_entropy_floor,
            policy.keyword_free_min_len,
        )
    }

    /// The shipped generic-secret TOML's lower-dash shape policy: four
    /// `-`-separated groups of lowercase/digit chars (each with a letter AND a
    /// digit), with at least one non-hex letter so a pure-hex UUID-ish token
    /// does not qualify.
    pub fn lower_dash_app_password_floor_met(candidate: &str, entropy: f64) -> bool {
        let shape = generic_keyword_policy().entropy_shape;
        crate::entropy::scanner::lower_dash_app_password_floor_met_with_policy(
            candidate,
            entropy,
            shape.as_ref(),
        )
    }

    /// Apply the embedded isolated-bare owner's mixed-token floor and minimum
    /// length to the contiguous mixed-token sibling.
    pub fn mixed_contiguous_token_floor_met(candidate: &str, entropy: f64) -> bool {
        let policy = generic_keyword_policy();
        crate::entropy::scanner::mixed_contiguous_token_floor_met(
            candidate,
            entropy,
            policy.isolated_mixed_entropy_floor,
            policy.keyword_free_min_len,
        )
    }

    /// The randomness gate the contiguous floor depends on, exposed so a boundary
    /// test can self-validate its positive/negative candidates' precondition
    /// if the English-bigram model ever reclassifies a fixture, the precondition
    /// assert fails loudly instead of the floor test passing for the wrong reason.
    pub fn is_random_token(value: &str) -> bool {
        crate::suppression::token_randomness::is_random_token(value)
    }

    /// Mirror of [`is_random_token`]: the model is CONFIDENT `value` is a
    /// pronounceable English word (>= MIN_ALPHA alpha, mean bigram log-prob ABOVE
    /// the random threshold, and at least one non-hex letter). NOT the negation
    /// of `is_random_token` (both are `false` on a too-short/sparse token).
    pub fn is_confident_dictionary_word(value: &str) -> bool {
        crate::suppression::token_randomness::is_confident_dictionary_word(value)
    }

    /// `value` has fewer than MIN_DISTINCT_LETTERS distinct ASCII letters, a
    /// repetitive/alternating/digit mask, never a real password.
    pub fn has_low_letter_diversity(value: &str) -> bool {
        crate::suppression::token_randomness::has_low_letter_diversity(value)
    }

    /// Cache-HIT path: build the `TokenRandomness` handle over `value` itself and
    /// ask it about the SAME `&str`: the ptr+len fast path returns the precomputed
    /// evidence. Must equal [`is_random_token`] (the no-cache path) for every value.
    pub fn token_randomness_self_is_random(value: &str) -> bool {
        crate::suppression::token_randomness::TokenRandomness::for_candidate(value)
            .is_random_token(value)
    }

    /// Cache-MISS path: build the handle over `candidate` and ask about a
    /// DIFFERENT `value` (distinct allocation ⇒ ptr mismatch ⇒ recompute). Must
    /// also equal [`is_random_token`] of `value`: the handle's candidate never
    /// leaks into another value's verdict.
    pub fn token_randomness_cross_is_random(candidate: &str, value: &str) -> bool {
        crate::suppression::token_randomness::TokenRandomness::for_candidate(candidate)
            .is_random_token(value)
    }

    /// Minimum alphabetic chars for a meaningful randomness verdict (below ⇒ fail
    /// safe to NOT random). Exposed so the fail-safe boundary test reads the real
    /// owner instead of hard-coding 6.
    pub const MIN_ALPHA: usize = crate::suppression::token_randomness::MIN_ALPHA;

    /// Minimum distinct letters for a `random` verdict (below ⇒ NOT random).
    pub const MIN_DISTINCT_LETTERS: usize =
        crate::suppression::token_randomness::MIN_DISTINCT_LETTERS;

    /// Apply the embedded isolated-bare owner's `opaque:opaque` component
    /// lengths to an all-alphanumeric letter-plus-digit pair.
    pub fn colon_separated_opaque(candidate: &str) -> bool {
        let policy = generic_keyword_policy();
        crate::entropy::scanner::colon_separated_opaque_candidate(
            candidate,
            policy.isolated_colon_left_min_len,
            policy.isolated_colon_right_min_len,
        )
    }

    /// Apply the embedded isolated-bare owner's symbolic minimum length to an
    /// alpha-only mixed-case opaque token.
    pub fn symbolic_alpha_only_opaque(candidate: &str) -> bool {
        let policy = generic_keyword_policy();
        crate::entropy::scanner::symbolic_alpha_only_opaque_candidate_with_policy(
            candidate, &policy,
        )
    }

    pub fn symbolic_alpha_only_opaque_with_policy(
        candidate: &str,
        plausibility: keyhog_core::DetectorPlausibilityPolicySpec,
    ) -> bool {
        let mut detector = keyhog_core::detector_spec_by_id("generic-keyword-secret")
            .expect("embedded generic-keyword-secret detector must load")
            .clone();
        detector.plausibility = Some(plausibility);
        let policy = crate::entropy::policy::CompiledEntropyPolicy::compile(&detector)
            .expect("test isolated-bare policy must compile");
        crate::entropy::scanner::symbolic_alpha_only_opaque_candidate_with_policy(
            candidate, &policy,
        )
    }

    /// Apply the embedded isolated-bare owner's symbol-count and underscore
    /// policy to a symbolic bare token.
    pub fn symbolic_bare(candidate: &str) -> bool {
        let policy = generic_keyword_policy();
        crate::entropy::scanner::symbolic_isolated_bare_candidate_with_policy(candidate, &policy)
    }

    pub fn symbolic_bare_with_policy(
        candidate: &str,
        plausibility: keyhog_core::DetectorPlausibilityPolicySpec,
    ) -> bool {
        let mut detector = keyhog_core::detector_spec_by_id("generic-keyword-secret")
            .expect("embedded generic-keyword-secret detector must load")
            .clone();
        detector.plausibility = Some(plausibility);
        let policy = crate::entropy::policy::CompiledEntropyPolicy::compile(&detector)
            .expect("test isolated-bare policy must compile");
        crate::entropy::scanner::symbolic_isolated_bare_candidate_with_policy(candidate, &policy)
    }
}

/// Entropy plausibility and shape predicates exposed for unit tests migrated
/// out of their original inline homes (KH-GAP-004).
pub mod entropy_keywords {
    use crate::entropy::plausibility::PlausibilityContext;

    fn context(is_credential_context: bool, allow_canonical_hex_key: bool) -> PlausibilityContext {
        PlausibilityContext::from_compiled(
            is_credential_context,
            allow_canonical_hex_key,
            super::generic_api_key_entropy_policy_for_test(),
        )
    }

    pub fn looks_like_english_prose(value: &str) -> bool {
        crate::suppression::shape::looks_like_english_prose(value)
    }

    pub fn entropy_value_looks_like_prose(value: &str) -> bool {
        crate::suppression::shape::looks_like_english_prose(value)
    }

    pub fn passes_secret_strength_checks(value: &str, is_credential_context: bool) -> bool {
        crate::entropy::plausibility::passes_secret_strength_checks(
            value,
            context(is_credential_context, false),
        )
    }

    pub fn passes_secret_strength_checks_with_plausibility_policy(
        value: &str,
        is_credential_context: bool,
        policy: keyhog_core::DetectorPlausibilityPolicySpec,
    ) -> bool {
        let mut detector = keyhog_core::detector_spec_by_id("generic-api-key")
            .expect("embedded generic-api-key detector must load")
            .clone();
        detector.plausibility = Some(policy);
        let compiled = crate::entropy::policy::CompiledEntropyPolicy::compile(&detector)
            .expect("test plausibility policy must compile");
        crate::entropy::plausibility::passes_secret_strength_checks(
            value,
            PlausibilityContext::from_compiled(is_credential_context, false, &compiled),
        )
    }

    pub fn is_dash_segmented_alnum_decoy(value: &str) -> bool {
        crate::suppression::shape::is_dash_segmented_alnum_decoy(value)
    }

    /// The token extracted from an `Authorization: Bearer|Basic <token>` line,
    /// or `None` for a non-authorization header / unknown scheme. Exposed so the
    /// zero-alloc case-insensitive scheme match has a direct regression.
    pub fn authorization_header_value(line: &str) -> Option<String> {
        crate::entropy::keywords::authorization_header_value(line).map(str::to_string)
    }

    pub fn xml_assignment_value(line: &str) -> Option<String> {
        crate::entropy::keywords::xml_assignment_value(line).map(str::to_string)
    }

    #[cfg(test)]
    pub(crate) fn is_candidate_plausible(value: &str, placeholder_keywords: &[String]) -> bool {
        crate::entropy::plausibility::is_candidate_plausible(
            value,
            placeholder_keywords,
            context(false, false),
        )
    }

    pub fn is_secret_plausible(value: &str, placeholder_keywords: &[String]) -> bool {
        crate::entropy::plausibility::is_secret_plausible(
            value,
            placeholder_keywords,
            context(false, false),
        )
    }

    #[cfg(test)]
    pub(crate) fn is_candidate_plausible_in_context(
        value: &str,
        placeholder_keywords: &[String],
        is_credential_context: bool,
        allow_canonical_hex_key: bool,
    ) -> bool {
        crate::entropy::plausibility::is_candidate_plausible(
            value,
            placeholder_keywords,
            context(is_credential_context, allow_canonical_hex_key),
        )
    }

    #[cfg(test)]
    pub(crate) fn is_secret_plausible_in_context(
        value: &str,
        placeholder_keywords: &[String],
        is_credential_context: bool,
        allow_canonical_hex_key: bool,
    ) -> bool {
        crate::entropy::plausibility::is_secret_plausible(
            value,
            placeholder_keywords,
            context(is_credential_context, allow_canonical_hex_key),
        )
    }
}

pub mod checksum {
    pub use crate::checksum::{
        checksum_adjusted_confidence, validate_checksum, ChecksumResult, CHECKSUM_VALID_FLOOR,
    };

    fn crc32_base62_suffix(data: &[u8], width: usize) -> String {
        crate::checksum::base62_encode_u32(crate::checksum::crc32(data), width)
    }

    /// Mint a valid token for ANY github classic-format prefix. `ghp_` (classic
    /// PAT) plus the `gho_`/`ghu_`/`ghs_`/`ghr_` OAuth-family siblings, which share
    /// the identical 30-entropy + 6-CRC32-base62 body (the CRC is over the body
    /// only, so it is prefix-independent). ONE owner for all five families.
    pub fn github_classic_format_with_checksum(prefix: &str, body30: &str) -> String {
        assert_eq!(
            body30.len(),
            30,
            "github classic-format body must be 30 chars"
        );
        format!(
            "{prefix}{body30}{}",
            crc32_base62_suffix(body30.as_bytes(), 6)
        )
    }

    pub fn github_classic_pat_with_checksum(body30: &str) -> String {
        github_classic_format_with_checksum("ghp_", body30)
    }

    pub fn npm_token_with_checksum(body30: &str) -> String {
        assert_eq!(body30.len(), 30, "npm body must be 30 chars");
        format!(
            "npm_{}{}",
            body30,
            crc32_base62_suffix(body30.as_bytes(), 6)
        )
    }

    pub fn github_fine_grained_pat_with_checksum(left22: &str, right_body53: &str) -> String {
        assert_eq!(left22.len(), 22, "github fine-grained left segment");
        assert_eq!(
            right_body53.len(),
            53,
            "github fine-grained right body before checksum"
        );
        format!(
            "github_pat_{left22}_{}{}",
            right_body53,
            crc32_base62_suffix(right_body53.as_bytes(), 6)
        )
    }

    pub trait ChecksumValidator {
        fn validator_id(&self) -> &str;
        fn validate(&self, credential: &str) -> ChecksumResult;
    }

    macro_rules! checksum_validator_wrapper {
        ($name:ident, $validator_id:expr) => {
            pub struct $name;

            impl ChecksumValidator for $name {
                fn validator_id(&self) -> &str {
                    $validator_id
                }

                fn validate(&self, credential: &str) -> ChecksumResult {
                    crate::checksum::validate_for_detector($validator_id, credential).result()
                }
            }

            impl $name {
                pub fn validator_id(&self) -> &str {
                    <Self as ChecksumValidator>::validator_id(self)
                }

                pub fn validate(&self, credential: &str) -> ChecksumResult {
                    <Self as ChecksumValidator>::validate(self, credential)
                }
            }
        };
    }

    checksum_validator_wrapper!(
        GithubClassicPatValidator,
        crate::detector_ids::GITHUB_CLASSIC_PAT
    );
    checksum_validator_wrapper!(
        GithubFineGrainedPatValidator,
        crate::detector_ids::GITHUB_PAT_FINE_GRAINED
    );
    pub struct GitlabTokenValidator;

    impl ChecksumValidator for GitlabTokenValidator {
        fn validator_id(&self) -> &str {
            crate::detector_ids::GITLAB_PERSONAL_ACCESS_TOKEN
        }

        fn validate(&self, credential: &str) -> ChecksumResult {
            crate::checksum::validate_checksum(credential)
        }
    }

    impl GitlabTokenValidator {
        pub fn validator_id(&self) -> &str {
            <Self as ChecksumValidator>::validator_id(self)
        }

        pub fn validate(&self, credential: &str) -> ChecksumResult {
            <Self as ChecksumValidator>::validate(self, credential)
        }
    }
    checksum_validator_wrapper!(NpmTokenValidator, crate::detector_ids::NPM_ACCESS_TOKEN);
    checksum_validator_wrapper!(PypiTokenValidator, crate::detector_ids::PYPI_API_TOKEN);
    pub struct SlackTokenValidator;

    impl ChecksumValidator for SlackTokenValidator {
        fn validator_id(&self) -> &str {
            crate::detector_ids::SLACK_BOT_TOKEN
        }

        fn validate(&self, credential: &str) -> ChecksumResult {
            crate::checksum::validate_checksum(credential)
        }
    }

    impl SlackTokenValidator {
        pub fn validator_id(&self) -> &str {
            <Self as ChecksumValidator>::validator_id(self)
        }

        pub fn validate(&self, credential: &str) -> ChecksumResult {
            <Self as ChecksumValidator>::validate(self, credential)
        }
    }
    checksum_validator_wrapper!(StripeTokenValidator, crate::detector_ids::STRIPE_SECRET_KEY);
}

#[cfg(test)]
pub(crate) const NUM_FEATURES: usize = crate::ml_scorer::NUM_FEATURES;

#[cfg(all(test, feature = "ml"))]
pub(crate) fn compute_features_public(text: &str, context: &str) -> [f32; NUM_FEATURES] {
    crate::ml_scorer::compute_features_public(text, context)
}

/// Full feature extractor (with detector-config keyword lists) exposed for
/// the ML training-pipeline parity harness (`ml/parity_check.py`), which
/// must compute byte-identical features to the serve path.
#[cfg(test)]
pub(crate) fn compute_features_with_config(
    text: &str,
    context: &str,
    known_prefixes: &[String],
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
) -> [f32; NUM_FEATURES] {
    crate::ml_scorer::compute_features_with_config(
        text,
        context,
        known_prefixes,
        secret_keywords,
        test_keywords,
        placeholder_keywords,
    )
}

#[cfg(test)]
pub(crate) struct ProbabilisticGate;

#[cfg(test)]
impl ProbabilisticGate {
    pub(crate) fn looks_promising(s: &str) -> bool {
        crate::probabilistic_gate::ProbabilisticGate::looks_promising(s)
    }
}
#[derive(Default)]
#[cfg(test)]
pub(crate) struct StaticInterner(crate::static_intern::StaticInterner);

#[cfg(test)]
impl StaticInterner {
    pub(crate) fn from_detector_strings<I, S>(detector_strings: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self(crate::static_intern::StaticInterner::from_detector_strings(
            detector_strings,
        ))
    }

    pub(crate) fn lookup(&self, s: &str) -> Option<std::sync::Arc<str>> {
        self.0.lookup(s)
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
pub(crate) fn seed_source_type_count() -> usize {
    crate::static_intern::seed_source_type_count()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AlphabetMask(crate::alphabet_filter::AlphabetMask);

impl AlphabetMask {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(crate::alphabet_filter::AlphabetMask::from_bytes(bytes))
    }

    fn from_bytes_scalar(bytes: &[u8]) -> Self {
        Self(crate::alphabet_filter::AlphabetMask::from_bytes_scalar(
            bytes,
        ))
    }

    #[cfg(target_arch = "aarch64")]
    pub unsafe fn from_bytes_neon(bytes: &[u8]) -> Self {
        Self(unsafe { crate::alphabet_filter::AlphabetMask::from_bytes_neon(bytes) })
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub unsafe fn from_bytes_avx2(bytes: &[u8]) -> Self {
        Self(unsafe { crate::alphabet_filter::AlphabetMask::from_bytes_avx2(bytes) })
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    pub unsafe fn from_bytes_sse2(bytes: &[u8]) -> Self {
        Self(unsafe { crate::alphabet_filter::AlphabetMask::from_bytes_sse2(bytes) })
    }

    pub fn from_text(s: &str) -> Self {
        Self(crate::alphabet_filter::AlphabetMask::from_text(s))
    }

    pub fn intersects(&self, other: &Self) -> bool {
        self.0.intersects(&other.0)
    }

    pub fn union(&mut self, other: &Self) {
        self.0.union(&other.0);
    }
}

#[derive(Clone, Debug, Default)]
pub struct AlphabetScreen(crate::alphabet_filter::AlphabetScreen);

impl AlphabetScreen {
    pub fn new(targets: &[String]) -> Self {
        Self(crate::alphabet_filter::AlphabetScreen::new(targets))
    }

    pub fn screen(&self, data: &[u8]) -> bool {
        self.0.screen(data)
    }

    fn screen_scalar_fallback(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        self.0
            .target_mask
            .intersects(&crate::alphabet_filter::AlphabetMask::from_bytes_scalar(
                data,
            ))
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub unsafe fn screen_avx2(&self, data: &[u8]) -> bool {
        unsafe { self.0.screen_avx2(data) }
    }
}

pub fn assert_alphabet_prefilter_backend_parity(targets: &[String], data: &[u8]) -> bool {
    let mask_scalar = AlphabetMask::from_bytes_scalar(data);
    let mask_auto = AlphabetMask::from_bytes(data);
    assert_eq!(
        mask_scalar, mask_auto,
        "AlphabetMask auto vs scalar parity failed"
    );

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            let mask_avx2 = unsafe { AlphabetMask::from_bytes_avx2(data) };
            assert_eq!(mask_scalar, mask_avx2, "AVX2 AlphabetMask parity failed");
        }
        if is_x86_feature_detected!("sse2") {
            let mask_sse2 = unsafe { AlphabetMask::from_bytes_sse2(data) };
            assert_eq!(mask_scalar, mask_sse2, "SSE2 AlphabetMask parity failed");
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let mask_neon = unsafe { AlphabetMask::from_bytes_neon(data) };
        assert_eq!(mask_scalar, mask_neon, "NEON AlphabetMask parity failed");
    }

    let screen = AlphabetScreen::new(targets);
    let screen_auto = screen.screen(data);
    let screen_scalar = screen.screen_scalar_fallback(data);
    assert_eq!(
        screen_auto, screen_scalar,
        "AlphabetScreen auto vs scalar parity failed"
    );

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            let screen_avx2 = unsafe { screen.screen_avx2(data) };
            assert_eq!(
                screen_scalar, screen_avx2,
                "AVX2 AlphabetScreen parity failed"
            );
        }
    }

    screen_auto
}

pub fn decode_chunk(
    chunk: &keyhog_core::Chunk,
    max_depth: usize,
    validate: bool,
    deadline: Option<std::time::Instant>,
    screen: Option<&AlphabetScreen>,
) -> Vec<keyhog_core::Chunk> {
    crate::decode::decode_chunk(chunk, max_depth, validate, deadline, screen.map(|s| &s.0))
}

/// Benchmark-only admission probe for the fail-open custom-decoder default.
#[cfg(feature = "decode")]
#[doc(hidden)]
pub fn decode_admission_sketch_with_custom_unknown(
    chunk: &keyhog_core::Chunk,
) -> crate::decode::DecodeAdmissionSketch {
    struct CustomUnknown;

    impl crate::decode::Decoder for CustomUnknown {
        fn name(&self) -> &'static str {
            "benchmark-custom-unknown"
        }

        fn decode_chunk(&self, _chunk: &keyhog_core::Chunk) -> Vec<keyhog_core::Chunk> {
            Vec::new()
        }
    }

    let mut sketch = crate::decode::decode_admission_sketch(chunk);
    sketch.merge(crate::decode::Decoder::admission_sketch(
        &CustomUnknown,
        chunk,
    ));
    sketch
}

#[cfg(test)]
pub(crate) fn register_thread_decoder(
    decoder: Box<dyn crate::decode::Decoder>,
) -> crate::decode::ScopedDecoderRegistration {
    crate::decode::register_thread_decoder(decoder)
}

pub fn ml_score(text: &str, context: &str) -> f64 {
    crate::ml_scorer::score(text, context)
}

#[cfg(feature = "ml")]
pub fn ml_score_for_detector(
    text: &str,
    context: &str,
    detector_id: &str,
    entropy_channel: bool,
) -> f64 {
    let detector = keyhog_core::detector_spec_by_id(detector_id)
        .unwrap_or_else(|| panic!("test detector {detector_id:?} must exist"));
    let features = crate::ml_scorer::compute_features_for_detector_with_config(
        text,
        context,
        &[],
        &[],
        &[],
        &[],
        detector,
        if entropy_channel {
            crate::ml_scorer::MlCandidateChannel::Entropy
        } else {
            crate::ml_scorer::MlCandidateChannel::Pattern
        },
    );
    crate::ml_scorer::score_features(&features)
}

#[cfg(feature = "ml")]
/// Exercise production score-cardinality repair with borrowed model inputs.
pub fn complete_ml_batch_scores(
    candidates: &[(&str, &str)],
    scores: Vec<f64>,
    config: &crate::ScannerConfig,
) -> Vec<f64> {
    crate::ml_scorer::complete_batch_scores_with_config(scores, candidates, config)
}

#[cfg(feature = "ml")]
pub fn ml_score_with_config_uncached(
    text: &str,
    context: &str,
    known_prefixes: &[String],
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
) -> f64 {
    let features = crate::ml_scorer::compute_features_with_config(
        text,
        context,
        known_prefixes,
        secret_keywords,
        test_keywords,
        placeholder_keywords,
    );
    crate::ml_scorer::score_features(&features)
}

#[cfg(feature = "ml")]
pub fn ml_score_cache_key(
    text: &str,
    context: &str,
    known_prefixes: &[String],
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
) -> u64 {
    crate::ml_scorer::score_cache_key(
        text,
        context,
        known_prefixes,
        secret_keywords,
        test_keywords,
        placeholder_keywords,
    )
}

/// Capture the coalesced GPU region-presence batch for `chunks`: `(haystack bytes
/// the GPU DFA scans, region start offsets, borrowed-single-chunk-fast-path?)`.
/// Lets behavioral tests prove both borrowed and coalesced paths preserve raw
/// bytes and positioned offsets now that VYRE owns case-insensitive matching.
/// Delegates to the single `engine::gpu_region_batch` owner. Gated to the
/// `gpu` feature because that owner (and the whole region-presence batch path)
/// only exists in the GPU build; the `ci-lean`/`portable` binaries have no GPU
/// region path to differentially test.
#[cfg(feature = "gpu")]
pub fn region_presence_batch_capture(
    chunks: &[keyhog_core::Chunk],
) -> Result<(Vec<u8>, Vec<u32>, bool), String> {
    crate::engine::gpu_region_batch::region_presence_batch_capture(chunks)
}

pub mod unicode_hardening {
    use std::borrow::Cow;

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum EvasionKind {
        CyrillicHomoglyph,
        GreekHomoglyph,
        Fullwidth,
        ZeroWidth,
        RTLOverride,
        Decomposed,
        Suspicious,
    }

    impl EvasionKind {
        pub fn description(&self) -> &'static str {
            match self {
                Self::CyrillicHomoglyph => "Cyrillic lookalike character",
                Self::GreekHomoglyph => "Greek lookalike character",
                Self::Fullwidth => "Fullwidth ASCII variant",
                Self::ZeroWidth => "Zero-width character",
                Self::RTLOverride => "Right-to-left override",
                Self::Decomposed => "Decomposed Unicode form",
                Self::Suspicious => "Suspicious separator or control character",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct EvasionMatch {
        pub position: usize,
        pub kind: EvasionKind,
        pub char: char,
        pub replacement: Option<char>,
    }

    fn kind(kind: crate::unicode_hardening::EvasionKind) -> EvasionKind {
        match kind {
            crate::unicode_hardening::EvasionKind::CyrillicHomoglyph => {
                EvasionKind::CyrillicHomoglyph
            }
            crate::unicode_hardening::EvasionKind::GreekHomoglyph => EvasionKind::GreekHomoglyph,
            crate::unicode_hardening::EvasionKind::Fullwidth => EvasionKind::Fullwidth,
            crate::unicode_hardening::EvasionKind::ZeroWidth => EvasionKind::ZeroWidth,
            crate::unicode_hardening::EvasionKind::RTLOverride => EvasionKind::RTLOverride,
            crate::unicode_hardening::EvasionKind::Decomposed => EvasionKind::Decomposed,
            crate::unicode_hardening::EvasionKind::Suspicious => EvasionKind::Suspicious,
        }
    }

    pub fn detect_unicode_attacks(text: &str) -> Vec<EvasionMatch> {
        crate::unicode_hardening::detect_unicode_attacks(text)
            .into_iter()
            .map(|m| EvasionMatch {
                position: m.position,
                kind: kind(m.kind),
                char: m.char,
                replacement: m.replacement,
            })
            .collect()
    }

    pub fn normalize_homoglyphs(text: &str) -> Cow<'_, str> {
        crate::unicode_hardening::normalize_homoglyphs(text)
    }

    pub fn full_normalize(text: &str) -> String {
        crate::unicode_hardening::full_normalize(text)
    }

    pub fn strip_interior_evasion_controls(text: &str) -> Cow<'_, str> {
        crate::unicode_hardening::strip_interior_evasion_controls(text)
    }

    #[cfg(test)]
    pub(crate) fn parse_evasion_anchors_for_test(raw: &str) -> Result<Vec<String>, String> {
        crate::unicode_hardening::parse_evasion_anchors(raw)
    }

    pub fn contains_evasion(text: &str) -> bool {
        crate::unicode_hardening::contains_evasion(text)
    }

    pub fn is_evasion_char(ch: char) -> bool {
        crate::unicode_hardening::is_evasion_char(ch)
    }

    /// Per-character homoglyph-fold owners, so the parity tests can assert each
    /// class's individual mapping truth (not just the composed `normalize_homoglyphs`).
    pub fn cyrillic_to_latin(ch: char) -> Option<char> {
        crate::unicode_hardening::cyrillic_to_latin(ch)
    }

    pub fn greek_to_latin(ch: char) -> Option<char> {
        crate::unicode_hardening::greek_to_latin(ch)
    }

    /// The AC/regex-expand homoglyph map's `(ascii, glyphs)` entries, so the
    /// cross-map consistency gate can assert it agrees with the normalize-path
    /// folds (`cyrillic_to_latin`/`greek_to_latin`) on every shared codepoint.
    pub fn homoglyph_confusables() -> Vec<(char, Vec<char>)> {
        crate::homoglyph::homoglyph_confusables()
    }

    pub fn fullwidth_to_ascii(ch: char) -> char {
        crate::unicode_hardening::fullwidth_to_ascii(ch)
    }

    /// True iff `ch` is a fullwidth ASCII variant (U+FF01–FF5E), the only slice of
    /// the Halfwidth-and-Fullwidth block that maps to an ASCII twin.
    pub fn is_fullwidth(ch: char) -> bool {
        crate::unicode_hardening::is_fullwidth(ch)
    }

    /// Invisible/zero-width classifier (incl. the newly-added filler/tag ranges).
    pub fn is_zero_width(ch: char) -> bool {
        crate::unicode_hardening::is_zero_width(ch)
    }

    pub fn is_combining_mark(ch: char) -> bool {
        crate::unicode_hardening::is_combining_mark(ch)
    }

    pub fn is_rtl_override(ch: char) -> bool {
        crate::unicode_hardening::is_rtl_override(ch)
    }

    /// True iff the per-char normalizer DROPS `ch` (invisible/evasion), exposing the
    /// private `NormalizedChar::Drop` disposition without leaking the enum.
    pub fn char_normalization_is_drop(ch: char) -> bool {
        matches!(
            crate::unicode_hardening::normalized_char(ch),
            crate::unicode_hardening::NormalizedChar::Drop
        )
    }

    /// True iff the per-char normalizer KEEPS `ch` unchanged (`NormalizedChar::Keep`).
    pub fn char_normalization_is_keep(ch: char) -> bool {
        matches!(
            crate::unicode_hardening::normalized_char(ch),
            crate::unicode_hardening::NormalizedChar::Keep
        )
    }
}

#[derive(Clone)]
pub struct BigramBloom(crate::bigram_bloom::BigramBloom);

impl BigramBloom {
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self(crate::bigram_bloom::BigramBloom::empty())
    }

    #[cfg(test)]
    pub(crate) fn insert_all(&mut self, bytes: &[u8]) {
        self.0.insert_all(bytes);
    }

    pub fn from_literal_prefixes(literals: &[String]) -> Self {
        Self(crate::bigram_bloom::BigramBloom::from_literal_prefixes(
            literals,
        ))
    }

    pub fn maybe_overlaps(&self, chunk: &[u8]) -> bool {
        self.0.maybe_overlaps(chunk)
    }

    #[cfg(test)]
    pub(crate) fn popcount(&self) -> u32 {
        self.0.popcount()
    }

    #[cfg(test)]
    pub(crate) fn is_saturated(&self) -> bool {
        self.0.is_saturated()
    }

    #[cfg(test)]
    pub(crate) fn scalar_overlaps_reference(&self, chunk: &[u8]) -> bool {
        self.0.scalar_overlaps_reference(chunk)
    }

    #[cfg(test)]
    pub(crate) fn saturated_for_test() -> Self {
        Self(crate::bigram_bloom::BigramBloom::saturated_for_test())
    }
}

pub fn looks_like_standard_base64_blob(credential: &str) -> bool {
    crate::suppression::shape::looks_like_standard_base64_blob(credential)
}

#[cfg(all(test, feature = "entropy"))]
pub(crate) mod phase2_entropy_helpers {
    pub(crate) fn keyword_is_credential_anchor(keyword: &str) -> bool {
        crate::engine::phase2_entropy::helpers::keyword_is_credential_anchor(keyword)
    }

    pub(crate) fn looks_like_entropy_random_base64_blob_decoy(value: &str) -> bool {
        crate::suppression::shape::looks_like_entropy_random_base64_blob_decoy(value)
    }
}

#[cfg(test)]
pub(crate) fn hash_fast(data: &[u8]) -> u64 {
    crate::util_hash::hash_fast(data)
}

#[cfg(test)]
pub(crate) fn memoize_by_hash<T: Copy>(
    cache: &'static std::thread::LocalKey<std::cell::RefCell<std::collections::HashMap<u64, T>>>,
    key: u64,
    max_entries: usize,
    compute: impl FnOnce() -> T,
) -> T {
    crate::util_hash::memoize_by_hash(cache, key, max_entries, compute)
}

#[cfg(test)]
pub(crate) mod ascii_ci {
    pub(crate) fn ci_find(haystack: &[u8], needle_lower: &[u8]) -> bool {
        crate::ascii_ci::ci_find(haystack, needle_lower)
    }

    pub(crate) fn ci_find_nonempty(haystack: &[u8], needle: &[u8]) -> bool {
        crate::ascii_ci::ci_find_nonempty(haystack, needle)
    }

    pub(crate) fn ci_find_at(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        crate::ascii_ci::ci_find_at(haystack, needle)
    }

    /// Every match offset (ascending), collected, the multi-match yield of the
    /// rare-byte-anchored `ci_find_iter` that `ci_find_at` takes the first of.
    pub(crate) fn ci_find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
        crate::ascii_ci::ci_find_iter(haystack, needle).collect()
    }

    pub(crate) fn contains_path_segment(path: &str, segment: &str) -> bool {
        crate::ascii_ci::contains_path_segment(path, segment)
    }

    pub(crate) fn contains_path_segment_two(path: &str, a: &str, b: &str) -> bool {
        crate::ascii_ci::contains_path_segment_two(path, a, b)
    }
}

pub mod shape {
    pub fn looks_like_credential_colliding_punctuation(credential: &str) -> bool {
        crate::suppression::shape::looks_like_credential_colliding_punctuation(credential)
    }

    pub fn looks_like_punctuation_decorated_identifier(credential: &str) -> bool {
        crate::suppression::shape::looks_like_punctuation_decorated_identifier(credential)
    }

    pub fn looks_like_syntactic_punctuation_marker(credential: &str) -> bool {
        crate::suppression::shape::looks_like_syntactic_punctuation_marker(credential)
    }

    #[cfg(test)]
    pub(crate) fn looks_like_train_case_prose_identifier(credential: &str) -> bool {
        crate::suppression::shape::looks_like_train_case_prose_identifier(credential)
    }

    #[cfg(test)]
    pub(crate) fn looks_like_filename_reference(credential: &str) -> bool {
        crate::suppression::shape::looks_like_filename_reference(credential)
    }

    #[cfg(test)]
    pub(crate) fn looks_like_kebab_config_identifier(credential: &str) -> bool {
        crate::suppression::shape::looks_like_kebab_config_identifier(credential)
    }

    #[cfg(test)]
    pub(crate) fn looks_like_dotted_source_identifier(credential: &str) -> bool {
        crate::suppression::shape::looks_like_dotted_source_identifier(credential)
    }

    #[cfg(test)]
    pub(crate) fn looks_like_public_evidence_identifier(credential: &str) -> bool {
        crate::suppression::shape::looks_like_public_evidence_identifier(credential)
    }

    #[cfg(test)]
    pub(crate) fn looks_like_generic_random_base64_blob_decoy(
        credential: &str,
        entropy: f64,
    ) -> bool {
        crate::suppression::shape::looks_like_generic_random_base64_blob_decoy(credential, entropy)
    }

    #[cfg(test)]
    pub(crate) fn generic_base64_candidate_is_ambiguous(credential: &str, entropy: f64) -> bool {
        crate::suppression::shape::generic_base64_candidate_is_ambiguous(credential, entropy)
    }

    #[cfg(test)]
    pub(crate) fn public_noncredential_shape_full(credential: &str) -> Option<&'static str> {
        crate::suppression::shape::public_noncredential_shape(
            credential,
            crate::suppression::shape::PublicShapeScope::Full,
        )
    }

    #[cfg(test)]
    pub(crate) fn public_noncredential_shape_weak_anchor(credential: &str) -> Option<&'static str> {
        crate::suppression::shape::public_noncredential_shape(
            credential,
            crate::suppression::shape::PublicShapeScope::WeakAnchor,
        )
    }
}

#[cfg(test)]
pub(crate) mod compiler_prefix {
    pub(crate) fn extract_literal_prefixes(pattern: &str) -> Vec<String> {
        crate::compiler::compiler_prefix::extract_literal_prefixes(pattern)
    }

    pub(crate) fn strip_leading_boundary_guard(pattern: &str) -> Option<&str> {
        crate::compiler::compiler_prefix::strip_leading_boundary_guard(pattern)
    }

    pub(crate) fn strip_leading_inline_flags(pattern: &str) -> &str {
        crate::compiler::compiler_prefix::strip_leading_inline_flags(pattern)
    }

    pub(crate) const MAX_CHARCLASS_PREFIX_EXPANSION: usize =
        crate::compiler::compiler_prefix::MAX_CHARCLASS_PREFIX_EXPANSION;

    pub(crate) const MIN_DISTINCTIVE_INFIX_CHARS: usize =
        crate::compiler::compiler_prefix::MIN_DISTINCTIVE_INFIX_CHARS;

    pub(crate) fn extract_literal_prefix(pattern: &str) -> Option<String> {
        crate::compiler::compiler_prefix::extract_literal_prefix(pattern)
    }

    pub(crate) fn strip_leading_zero_width_assertions(pattern: &str) -> &str {
        crate::compiler::compiler_prefix::strip_leading_zero_width_assertions(pattern)
    }

    pub(crate) fn expand_leading_charclass_prefixes(pattern: &str) -> Option<Vec<String>> {
        crate::compiler::compiler_prefix::expand_leading_charclass_prefixes(pattern)
    }

    pub(crate) fn expand_leading_literal_alternation_with_tail(
        pattern: &str,
    ) -> Option<Vec<String>> {
        crate::compiler::compiler_prefix::expand_leading_literal_alternation_with_tail(pattern)
    }

    pub(crate) fn leading_literal_run(s: &str) -> String {
        crate::compiler::compiler_prefix::leading_literal_run(s)
    }

    pub(crate) fn regex_has_required_literal_run(pattern: &str, min_len: usize) -> bool {
        crate::compiler::compiler_prefix::regex_has_required_literal_run(pattern, min_len)
    }
}

/// Engine scan-filter boundary helpers, exposed for the credential-boundary
/// extension suite migrated out of `engine/scan_filters.rs` (no-inline-tests
/// gate). Crate-private; not part of the public API.
#[cfg(test)]
pub(crate) mod scan_filters {
    pub(crate) fn extend_known_prefix_credential<'a>(
        data: &'a str,
        credential: &'a str,
        match_end: usize,
    ) -> (&'a str, usize) {
        let (credential, match_end, _) =
            crate::engine::scan_filters::extend_known_prefix_credential(
                data,
                credential,
                match_end,
                |candidate, _| {
                    crate::checksum::ChecksumConfidenceDecision::for_credential(candidate)
                },
            );
        (credential, match_end)
    }
}

#[cfg(test)]
pub(crate) fn match_proves_keyword_nearby(regex: &str, keywords: &[String]) -> bool {
    crate::compiler::match_proves_keyword_nearby(regex, keywords)
}

/// Caesar shift-selection internals, exposed for the 100k differential
/// shift-selection parity test migrated out of `src/decode/caesar.rs`
/// (no-inline-tests gate). The `matched_caesar_shifts` optimization must emit
/// the exact same decoded-variant set as the all-25-shifts reference.
pub mod decode_caesar {
    pub use crate::confidence::KNOWN_PREFIXES;

    pub const MIN_CAESAR_LEN: usize = crate::decode::caesar::MIN_CAESAR_LEN;

    pub fn caesar_shift(input: &str, shift: u8) -> String {
        crate::decode::caesar::caesar_shift(input, shift)
    }

    pub fn candidate_shape_invariant(value: &str) -> bool {
        crate::decode::caesar::candidate_shape_invariant(value)
    }

    pub fn contains_known_prefix(value: &str) -> bool {
        crate::decode::caesar::contains_known_prefix(value)
    }

    /// The full per-shift credential-shape gate the Caesar decoder applies to a
    /// decoded variant: the shift-invariant structural half
    /// (`candidate_shape_invariant`: ≥1 digit + an 8+ alnum run) AND the
    /// shift-variant half (`contains_known_prefix`). This mirrors the exact
    /// conjunction the decode loop enforces; it replaces the removed standalone
    /// `looks_credential_shaped` combined predicate (dead in production, the
    /// loop composes the two halves directly) so the shape tests still pin one
    /// named contract.
    pub fn caesar_credential_shape_gate(value: &str) -> bool {
        candidate_shape_invariant(value) && contains_known_prefix(value)
    }

    pub fn matched_caesar_shifts(candidate: &str) -> [bool; 26] {
        crate::decode::caesar::matched_caesar_shifts(candidate)
    }

    pub fn is_source_code_path(path: Option<&str>) -> bool {
        crate::decode::caesar::is_source_code_path(path)
    }

    pub fn is_program_source_code_path(path: Option<&str>) -> bool {
        crate::decode::caesar::is_program_source_code_path(path)
    }
}

#[cfg(test)]
pub(crate) mod decode_structure {
    #[derive(Debug, Clone, Default, PartialEq)]
    pub(crate) struct DecodeStructure {
        pub(crate) decodable: bool,
        pub(crate) decoded_len: usize,
        pub(crate) printable_ratio: f32,
        pub(crate) magic: Option<&'static str>,
        pub(crate) protobuf_wire: bool,
    }

    impl DecodeStructure {
        pub(crate) fn is_binary_payload(&self) -> bool {
            self.magic.is_some() || (self.protobuf_wire && self.decoded_len >= 8)
        }
    }

    fn expose(inner: crate::decode_structure::DecodeStructure) -> DecodeStructure {
        DecodeStructure {
            decodable: inner.decodable,
            decoded_len: inner.decoded_len,
            printable_ratio: inner.printable_ratio,
            magic: inner.magic,
            protobuf_wire: inner.protobuf_wire,
        }
    }

    pub(crate) fn analyze(candidate: &str) -> DecodeStructure {
        expose(crate::decode_structure::analyze(candidate))
    }

    pub(crate) fn decoded_contains_placeholder(candidate: &str) -> bool {
        crate::decode_structure::evidence(candidate).decoded_contains_placeholder()
    }

    #[cfg(any(feature = "entropy", test))]
    pub(crate) fn decoded_contains_nul_byte(candidate: &str) -> bool {
        crate::decode_structure::evidence(candidate).decoded_contains_nul_byte()
    }

    pub fn decoded_is_base64_blob(candidate: &str) -> bool {
        crate::decode_structure::evidence(candidate).decoded_is_base64_blob()
    }

    pub fn decoded_hex_text_len(candidate: &str) -> Option<usize> {
        crate::decode_structure::evidence(candidate).decoded_hex_text_len()
    }

    pub(crate) fn decodes_to_printable_text(candidate: &str) -> bool {
        crate::decode_structure::decodes_to_printable_text(candidate)
    }

    pub(crate) fn is_encoded_binary(candidate: &str) -> bool {
        crate::decode_structure::evidence(candidate).is_binary_payload()
    }

    pub(crate) fn looks_like_uniform_base64_blob(value: &str) -> bool {
        crate::decode_structure::looks_like_uniform_base64_blob(value)
    }
}

pub mod segment_attribution {
    //! Doc-hidden test facade over the single owner
    //! [`crate::engine::segment_attribution`]. Re-exports (no second hand-copied
    //! body: ONE-PLACE / Law-11) so external tests reach the primitive at
    //! `keyhog_scanner::testing::segment_attribution::*`.
    pub use crate::engine::segment_attribution::{
        map_offsets_to_segments, AttributedMatch, GlobalMatch, Segment, SegmentAttributionError,
    };
}

pub struct CaesarDecoder;

impl CaesarDecoder {
    pub fn decode_chunk(&self, chunk: &keyhog_core::Chunk) -> Vec<keyhog_core::Chunk> {
        use crate::decode::Decoder;
        let inner = crate::decode::caesar::CaesarDecoder;
        inner.decode_chunk(chunk)
    }
}

pub fn caesar_shift(input: &str, shift: u8) -> String {
    crate::decode::caesar::caesar_shift(input, shift)
}

pub fn is_source_code_path(path: Option<&str>) -> bool {
    crate::decode::caesar::is_source_code_path(path)
}

/// Test-only Caesar credential-shape gate (shift-invariant + shift-variant
/// conjunction the decode loop enforces). Re-exported at the `testing` top level
/// so migrated inline tests reach it at `keyhog_scanner::testing::` alongside the
/// sibling caesar helpers, instead of the nested `decode_caesar` path.
pub fn caesar_credential_shape_gate(value: &str) -> bool {
    decode_caesar::caesar_credential_shape_gate(value)
}

pub fn find_hex_strings(text: &str, min_length: usize) -> Vec<crate::decode::EncodedString> {
    crate::decode::find_hex_strings(text, min_length)
}

pub fn take_hex_digits<I>(chars: &mut std::iter::Peekable<I>, count: usize) -> Result<u32, ()>
where
    I: Iterator<Item = char>,
{
    crate::decode::take_hex_digits(chars, count)
}

pub fn unicode_escape_decode(input: &str) -> Result<String, ()> {
    crate::decode::unicode_escape_decode(input)
}

pub fn extracted_value_strings_for_test(text: &str) -> Vec<String> {
    crate::decode::extracted_value_strings_for_test(text)
}

pub fn looks_reversible(candidate: &str) -> bool {
    crate::decode::reverse::looks_reversible(candidate)
}

pub fn reverse_str(s: &str) -> String {
    crate::decode::reverse::reverse_str(s)
}

/// Shannon entropy of `chunk` in bits/byte.
///
/// # Safety
///
/// On `x86_64` this dispatches straight to the AVX-512 kernel, which
/// requires the running CPU to support `avx512f`/`avx512bw`. The caller
/// must confirm those features first (e.g. via `is_x86_feature_detected!`);
/// calling it on a CPU without them is undefined behavior.
///
/// On every other target (aarch64/macOS, wasm, …) the AVX-512 kernel does
/// not exist, so this routes to the portable feature-detecting dispatcher
/// (`entropy::fast::shannon_entropy_simd`), which is itself safe and always
/// correct. The `unsafe` marker is kept for one cross-platform signature.
/// Without this arch split the non-x86 build failed to compile
/// (`E0425: cannot find calculate_shannon_entropy`), breaking the portable
/// / macOS-arm64 build.
#[cfg(test)]
pub(crate) unsafe fn calculate_shannon_entropy(chunk: &[u8]) -> f64 {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { crate::entropy::avx512::calculate_shannon_entropy(chunk) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        crate::entropy::fast::shannon_entropy_simd(chunk)
    }
}

#[cfg(feature = "simd")]
pub fn hyperscan_oversubscribed_match_ids_are_stable(
    patterns: &[(usize, usize, &str, bool)],
    probe: &[u8],
    threads: usize,
    rounds: usize,
) -> Result<Vec<usize>, String> {
    if threads == 0 {
        return Err("threads must be greater than zero".into());
    }
    if rounds == 0 {
        return Err("rounds must be greater than zero".into());
    }

    let (scanner, unsupported) = crate::simd::backend::HsScanner::compile_with_opts(
        patterns,
        crate::simd::backend::HsCompileOpts::default(),
    )?;
    if !unsupported.is_empty() {
        return Err(format!(
            "probe patterns must all be Hyperscan-supported, got unsupported={unsupported:?}"
        ));
    }

    let mut expected = Vec::new();
    scanner.scan_matches_result(probe, |id, _start, _end| expected.push(id))?;
    expected.sort_unstable();
    expected.dedup();

    let barrier = std::sync::Barrier::new(threads);
    let scanner_ref = &scanner;
    let barrier_ref = &barrier;
    let expected_ref = &expected;

    let failures = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(move || {
                    barrier_ref.wait();
                    for _ in 0..rounds {
                        let mut ids = Vec::new();
                        scanner_ref
                            .scan_matches_result(probe, |id, _start, _end| ids.push(id))
                            .map_err(|error| {
                                format!("scan errored under oversubscription: {error}")
                            })?;
                        ids.sort_unstable();
                        ids.dedup();
                        if &ids != expected_ref {
                            return Err(format!(
                                "oversubscribed scan produced {ids:?}, expected {expected_ref:?}"
                            ));
                        }
                    }
                    Ok::<(), String>(())
                })
            })
            .collect();

        handles
            .into_iter()
            .filter_map(|handle| handle.join().expect("scan thread did not panic").err())
            .collect::<Vec<String>>()
    });

    if failures.is_empty() {
        Ok(expected)
    } else {
        Err(format!(
            "{}/{} oversubscribed scan threads diverged from the complete match set:\n{}",
            failures.len(),
            threads,
            failures.join("\n")
        ))
    }
}

#[cfg(all(test, feature = "simd"))]
pub(crate) fn cache_dir_under_allowed_root(
    path: &std::path::Path,
    home: &std::path::Path,
    temp_root: &std::path::Path,
    uid: u32,
) -> bool {
    crate::simd::backend::cache_dir_under_allowed_root(path, home, temp_root, uid)
}

#[cfg(all(test, feature = "simd"))]
pub(crate) fn set_hyperscan_cache_dir(path: Option<std::path::PathBuf>) {
    crate::set_hyperscan_cache_dir(path);
}

#[cfg(all(test, feature = "simdsieve"))]
pub(crate) fn hot_pattern_index_at(
    scanner: &crate::CompiledScanner,
    text_bytes: &[u8],
    offset: usize,
) -> Option<usize> {
    crate::simdsieve_prefilter::hot_pattern_index_at(&scanner.hot_pattern_slots, text_bytes, offset)
}

/// Standalone hot-pattern index resolver using the embedded detector corpus's
/// static prefix table (no scanner required). Returns the first slot whose
/// prefix is present at `offset`, or `None`.
#[cfg(all(test, feature = "simdsieve"))]
pub(crate) fn hot_pattern_index_at_standalone(text_bytes: &[u8], offset: usize) -> Option<usize> {
    let rest = text_bytes.get(offset..)?;
    (*crate::simdsieve_prefilter::HOT_PATTERNS)
        .iter()
        .enumerate()
        .find_map(|(idx, prefix)| rest.starts_with(prefix).then_some(idx))
}

/// Return the hot-pattern prefix slice, dereferencing the LazyLock safely.
#[cfg(all(test, feature = "simdsieve"))]
pub(crate) fn hot_patterns_ref() -> &'static [&'static [u8]] {
    *std::ops::Deref::deref(&crate::simdsieve_prefilter::HOT_PATTERNS)
}

/// Number of hot patterns, for proptest generators that need it at compile time.
#[cfg(all(test, feature = "simdsieve"))]
pub(crate) fn hot_patterns_len() -> usize {
    hot_patterns_ref().len()
}
#[cfg(all(test, feature = "simdsieve"))]
pub(crate) fn hot_pattern_rows(
    scanner: &crate::CompiledScanner,
) -> Vec<(Vec<u8>, String, String, String)> {
    scanner
        .hot_pattern_slots
        .iter()
        .map(|slot| {
            let entry = &scanner.ac_map[slot.ac_map_index];
            let metadata = &scanner.detector_plans.get(entry.detector_index).metadata;
            (
                slot.prefix.to_vec(),
                metadata.0.to_string(),
                metadata.1.to_string(),
                metadata.2.to_string(),
            )
        })
        .collect()
}

/// Integration-test facade: parse a docker-compose `environment:` block into
/// `(context, value, line)` tuples on the original-file (non-decode-derived)
/// path. Plain `pub` (unlike the `cfg(test)` StructuredPair variant) so the
/// out-of-crate tests/gap suite can reach it.
pub fn parse_docker_compose_tuples(text: &str) -> Vec<(String, String, usize)> {
    crate::structured::parsers::parse_docker_compose(text, false)
        .into_iter()
        .map(|pair| (pair.context, pair.value, pair.line))
        .collect()
}

/// Integration-test facade: parse a Kubernetes Secret into `(context, value,
/// line)` tuples on the original-file path. `stringData:` values surface raw;
/// `data:` values are base64-decoded.
pub fn parse_k8s_secret_tuples(text: &str) -> Vec<(String, String, usize)> {
    crate::structured::parsers::parse_k8s_secret(text, false)
        .into_iter()
        .map(|pair| (pair.context, pair.value, pair.line))
        .collect()
}

/// Integration-test facade: parse Terraform/HCL (`variable` blocks, flat
/// assignments, heredocs) into `(context, value, line)` tuples.
pub fn parse_hcl_tuples(text: &str) -> Vec<(String, String, usize)> {
    crate::structured::parsers::parse_hcl(text)
        .into_iter()
        .map(|pair| (pair.context, pair.value, pair.line))
        .collect()
}

/// Integration-test facade: parse Terraform state JSON into `(context, value,
/// line)` tuples on the original-file path. Resource instance contexts carry the
/// rendered `index_key` (e.g. `aws_secret.db["primary"].password`).
pub fn parse_tfstate_tuples(text: &str) -> Vec<(String, String, usize)> {
    crate::structured::parsers::parse_tfstate(text, false)
        .into_iter()
        .map(|pair| (pair.context, pair.value, pair.line))
        .collect()
}

/// Integration-test facade: the structured-oversize coverage-gap partition
/// (task #52). Returns whether an oversize skip of `(text, path)` would be
/// counted as a *decode-through* coverage gap, true only for a recognised
/// decode-through format (k8s Secret / compose / tfstate / notebook) that is not
/// a decode-derived buffer; false for `Env`/`Hcl` (context-only, lossless) and
/// unrecognised inputs. Exposes the exact predicate `preprocess` applies at the
/// `MAX_STRUCTURED_PARSE_BYTES` cap.
pub fn structured_oversize_skip_is_counted(
    text: &str,
    path: Option<&str>,
    decode_derived: bool,
) -> bool {
    crate::structured::oversize_skip_is_counted(text, path, decode_derived)
}

/// Integration-test facade: expand a regex pattern to a homoglyph-aware regex
/// (ASCII chars become `[<ascii><glyphs>]` classes; regex-special chars are
/// escaped). Plain `pub` so the out-of-crate tests/gap suite can pin the exact
/// expansion.
pub fn expand_homoglyphs_str(pattern: &str) -> String {
    crate::homoglyph::expand_homoglyphs(pattern)
}

/// Integration-test facade: build the prefix-superstring propagation table for a
/// set of literal prefixes (entry `i` lists the indices whose prefix is a strict
/// superstring of `prefixes[i]`). Plain `pub` for the out-of-crate tests/gap suite.
pub fn build_propagation_table_for_test(prefixes: &[String]) -> Vec<Vec<usize>> {
    crate::prefix_trie::build_propagation_table(prefixes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct StructuredPair {
    pub(crate) context: String,
    pub(crate) value: String,
    pub(crate) line: usize,
}

#[cfg(test)]
fn structured_pair(pair: crate::structured::ExtractedPair) -> StructuredPair {
    StructuredPair {
        context: pair.context,
        value: pair.value,
        line: pair.line,
    }
}

#[cfg(test)]
fn structured_pairs(pairs: Vec<crate::structured::ExtractedPair>) -> Vec<StructuredPair> {
    pairs.into_iter().map(structured_pair).collect()
}

#[cfg(test)]
pub(crate) fn parse_docker_compose(text: &str) -> Vec<StructuredPair> {
    // Test facade exercises the original-file (non-decode-derived) path.
    structured_pairs(crate::structured::parsers::parse_docker_compose(
        text, false,
    ))
}

#[cfg(test)]
pub(crate) fn parse_env(text: &str) -> Vec<StructuredPair> {
    structured_pairs(crate::structured::parsers::parse_env(text))
}

#[cfg(test)]
pub(crate) fn parse_hcl(text: &str) -> Vec<StructuredPair> {
    structured_pairs(crate::structured::parsers::parse_hcl(text))
}

#[cfg(test)]
pub(crate) fn parse_jupyter(text: &str) -> Vec<StructuredPair> {
    // Test facade exercises the original-file (non-decode-derived) path.
    structured_pairs(crate::structured::parsers::parse_jupyter(text, false))
}

#[cfg(test)]
pub(crate) fn parse_k8s_secret(text: &str) -> Vec<StructuredPair> {
    // Test facade exercises the original-file (non-decode-derived) path.
    structured_pairs(crate::structured::parsers::parse_k8s_secret(text, false))
}

#[cfg(test)]
pub(crate) fn parse_tfstate(text: &str) -> Vec<StructuredPair> {
    // Test facade exercises the original-file (non-decode-derived) path.
    structured_pairs(crate::structured::parsers::parse_tfstate(text, false))
}

// Decode-derived-aware facades: expose the `decode_derived` flag so integration
// tests can pin both depth-0 (original file) extraction AND the depth>0
// (decode-through-derived buffer) behavior of the structured parsers without
// widening the crate-internal parser surface to `pub`.
#[cfg(test)]
pub(crate) fn parse_k8s_secret_derived(text: &str, decode_derived: bool) -> Vec<StructuredPair> {
    structured_pairs(crate::structured::parsers::parse_k8s_secret(
        text,
        decode_derived,
    ))
}

#[cfg(test)]
pub(crate) fn parse_tfstate_derived(text: &str, decode_derived: bool) -> Vec<StructuredPair> {
    structured_pairs(crate::structured::parsers::parse_tfstate(
        text,
        decode_derived,
    ))
}

#[cfg(test)]
pub(crate) fn parse_jupyter_derived(text: &str, decode_derived: bool) -> Vec<StructuredPair> {
    structured_pairs(crate::structured::parsers::parse_jupyter(
        text,
        decode_derived,
    ))
}

/// Test seam for `structured/parsers/line.rs::resolve_line_number_options`: the
/// JSON/YAML value-anchor line locator `finalize_pending_pairs` uses to attribute
/// each extracted pair to its 1-based source line. Exposed through the sanctioned
/// `testing` surface (rather than widening the parser module to `pub`) so
/// integration proptests can pin its contract directly: repeated-needle dedup
/// (two slots sharing one AC pattern both take the FIRST match's line), empty-needle
/// skip (stays `None`), all-empty/empty-text early return, not-found `None`, and
/// overlapping-substring resolution via `find_overlapping_iter`.
pub fn resolve_line_number_options_for_test(text: &str, needles: &[&str]) -> Vec<Option<usize>> {
    crate::structured::parsers::resolve_line_number_options(text, needles)
}
