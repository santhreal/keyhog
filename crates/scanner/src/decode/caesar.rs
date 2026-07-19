use super::pipeline::{push_decoded_text_chunk, with_extracted_value_spans};
use super::{DecodeAdmissionSketch, Decoder};
use keyhog_core::Chunk;
use std::sync::LazyLock;

/// Caesar/ROT13/ROT-N decoder. A handful of malware-config dumps and CTF
/// fixtures store their tokens ROT13'd (`AKIA...` → `NXVN...`). For every
/// candidate ≥ 16 chars, emit decoded variants for the 25 non-trivial Caesar
/// shifts that produce a *plausibly credential-shaped* string.
///
/// "Plausibly shaped" gates the explosion: a 100-char chunk would otherwise
/// produce 25 sibling chunks per candidate. We require:
///   1. The decoded variant contains ≥1 ASCII digit (most modern API key
///      formats include digits - pure-letter Caesar output rarely indicates
///      a real secret).
///   2. The decoded variant has at least 8 ASCII alphanumeric chars in a
///      contiguous run (matches AWS / GitHub / Slack token shapes).
///
/// Both checks together keep the chunk count flat on prose-heavy inputs.
///
/// Source-code files are skipped entirely. Real secrets are never Caesar-
/// encoded inside source - the 25-shift fan-out on every prose-comment in
/// a codebase just hallucinates detector matches from random letter runs
/// (helicone-api-key on a `//! Source trait` doc comment was the original
/// reproducer; see dogfood-2026-05-21.md finding #5).
pub(crate) struct CaesarDecoder;

/// Semantic alias of the shared evasion-decode floor, same value as
/// `reverse::MIN_REVERSE_LEN`, owned once in [`super::util::MIN_EVASION_DECODE_LEN`].
pub(crate) const MIN_CAESAR_LEN: usize = super::util::MIN_EVASION_DECODE_LEN;
const MIN_ALNUM_RUN: usize = 8;

/// Minimum accumulated base64 run (in chars) before [`encoded_private_key_payload_spans`]
/// attempts a decode to look for a PEM `-----BEGIN … PRIVATE KEY-----` envelope.
/// 128 base64 chars decode to ~96 bytes, enough to hold the framing markers
/// so shorter runs cannot be a wrapped private key and are skipped rather than
/// decoded on every short base64-ish config line.
const MIN_ENCODED_PRIVATE_KEY_B64_LEN: usize = 128;

/// Per-line base64 floor: a single line's trimmed value must reach this many
/// standard-base64 chars before it joins (or starts) an accumulated
/// private-key run. Below it the line is too short to be a wrapped-PEM body
/// line and is treated as a run terminator. Distinct from the whole-run
/// `MIN_ENCODED_PRIVATE_KEY_B64_LEN` accumulation threshold above.
const MIN_PRIVATE_KEY_B64_LINE_LEN: usize = 16;

/// Number of letters in the ASCII alphabet, the modulus for a Caesar/ROT-N
/// letter rotation (and the base for the `26 - k` inverse shift). This is the
/// rotation modulus ONLY; the `[bool; 26]` shift table is sized `25 shifts + 1`
/// (a coincidental 26) and must NOT be folded into this constant.
pub(crate) const ALPHABET_LEN: u8 = 26;

#[derive(serde::Deserialize)]
struct ProgramSourceCodeExtensions {
    extensions: Vec<String>,
}

/// Program/source extensions where source-like identifier density makes
/// Caesar-decoding pure noise. Matched against the suffix of
/// `chunk.metadata.path` after ASCII-lowercasing and slash normalization.
/// Parse the bundled Tier-B program-source-extension list. Returns an error
/// rather than panicking so the `PROGRAM_SOURCE_CODE_EXTENSIONS` owner below is
/// the single fail-closed site (the `no_unwrap_expect` gate bans `expect`).
fn parse_program_source_extensions(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<ProgramSourceCodeExtensions>(raw)
        .map(|parsed| parsed.extensions)
        .map_err(|error| error.to_string())
}

/// Program/source extensions where source-like identifier density makes
/// Caesar-decoding pure noise. Matched against the suffix of
/// `chunk.metadata.path` after ASCII-lowercasing and slash normalization.
static PROGRAM_SOURCE_CODE_EXTENSIONS: LazyLock<Vec<String>> = LazyLock::new(|| {
    match parse_program_source_extensions(include_str!(
        "../../../../rules/program-source-extensions.toml"
    )) {
        Ok(extensions) => extensions,
        Err(error) => panic!(
            "rules/program-source-extensions.toml is invalid: {error}. \
             Fix the bundled Tier-B metadata file list."
        ),
    }
});

#[derive(serde::Deserialize)]
struct CaesarNoiseLists {
    source_code_filenames: Vec<String>,
    text_noise_extensions: Vec<String>,
}

fn parse_caesar_noise_lists(raw: &str) -> Result<CaesarNoiseLists, String> {
    toml::from_str::<CaesarNoiseLists>(raw).map_err(|error| error.to_string())
}

/// Single parse of the caesar-noise Tier-B list: both classifiers below read
/// one field each from this owner instead of re-parsing the embedded TOML twice
/// (the previous two statics each `include_str!`'d + parsed the whole file).
/// Fail-closed (Law 10): invalid bundled metadata panics loudly at first use.
static CAESAR_NOISE_LISTS: LazyLock<CaesarNoiseLists> = LazyLock::new(|| {
    match parse_caesar_noise_lists(include_str!("../../../../rules/caesar-noise-lists.toml")) {
        Ok(lists) => lists,
        Err(error) => panic!(
            "rules/caesar-noise-lists.toml is invalid: {error}. \
             Fix the bundled Tier-B metadata file list."
        ),
    }
});

static SOURCE_CODE_FILENAMES: LazyLock<Vec<String>> =
    LazyLock::new(|| CAESAR_NOISE_LISTS.source_code_filenames.clone());

/// Text/document paths are also decode-noise for ROT-N, but they are not
/// program source for entropy suppression. Keep this separate so entropy does
/// not inherit a Caesar-specific broad definition of "source".
static CAESAR_TEXT_NOISE_EXTENSIONS: LazyLock<Vec<String>> =
    LazyLock::new(|| CAESAR_NOISE_LISTS.text_noise_extensions.clone());

/// Zero-allocation path classification. The previous form built TWO heap
/// allocations per call: `p.replace('\\', "/").to_ascii_lowercase()`: on a
/// path that runs once per chunk per decoder pass (Law 7). The extension check
/// is a case-insensitive suffix compare (`ends_with_ignore_ascii_case`, and the
/// `\`/`/` distinction is irrelevant to a suffix like `.rs`); the filename
/// check extracts the basename over BOTH separators via `path_basename_bytes`
/// (no allocation) and compares case-insensitively against the (lowercase)
/// constant filenames. Behaviour is identical to the lowered-string form.
fn source_path_matches<S: AsRef<str>, F: AsRef<str>>(
    path: &str,
    extensions: &[S],
    filenames: &[F],
) -> bool {
    use crate::ascii_ci::ends_with_ignore_ascii_case;
    let bytes = path.as_bytes();
    if !filenames.is_empty() {
        let base = crate::platform_compat::path_basename_bytes(bytes);
        if filenames
            .iter()
            .any(|name| base.eq_ignore_ascii_case(name.as_ref().as_bytes()))
        {
            return true;
        }
    }
    extensions
        .iter()
        .any(|ext| ends_with_ignore_ascii_case(bytes, ext.as_ref().as_bytes()))
}

pub(crate) fn is_program_source_code_path(path: Option<&str>) -> bool {
    let Some(p) = path else { return false };
    source_path_matches(p, &*PROGRAM_SOURCE_CODE_EXTENSIONS, &*SOURCE_CODE_FILENAMES)
}

pub(crate) fn is_source_code_path(path: Option<&str>) -> bool {
    // Superset of `is_program_source_code_path` (reuse it as the ONE owner of the
    // program-source check) plus the Caesar-specific text-noise extensions.
    is_program_source_code_path(path)
        || path
            .is_some_and(|p| source_path_matches(p, &*CAESAR_TEXT_NOISE_EXTENSIONS, &[] as &[&str]))
}

/// True when `line` contains a `scheme://user:pass@host` URL with embedded
/// credentials. The plaintext URL itself is the credential; Caesar /
/// ROT-N decoding cannot reveal anything new, and (worse) the 25-shift
/// emission produces a high-confidence decoded chunk whose body wins the
/// per-line resolution group over the real connection-string detector.
///
/// Match shape: `<scheme>://[^/@\s]+:[^/@\s]+@[^\s]+`. The presence of
/// `:` between scheme and `@` is what distinguishes a credentialled URL
/// (`postgres://u:p@h`) from a bare host URL (`https://example.com`) -
/// the bare-host case has no credential to lose, so we leave it alone.
pub(crate) fn line_has_credential_url(line: &str) -> bool {
    let Some(scheme_end) = line.find("://") else {
        return false;
    };
    // Scheme must be 2+ alphabetic bytes immediately before `://`.
    let scheme_bytes = &line.as_bytes()[..scheme_end];
    let scheme_ok = scheme_bytes.len() >= 2
        && scheme_bytes
            .iter()
            .rev()
            .take_while(|b| b.is_ascii_alphabetic() || **b == b'+')
            .count()
            >= 2;
    if !scheme_ok {
        return false;
    }
    let rest = &line[scheme_end + 3..];
    // Walk userinfo: bytes up to the FIRST `/` or whitespace. The first
    // `@` in that span splits user[:pass]@host. Require a `:` BEFORE the
    // `@` so we only match URLs with embedded passwords.
    let userinfo_end = rest
        .find(|c: char| c == '/' || c == '?' || c == '#' || c.is_ascii_whitespace())
        .unwrap_or(rest.len()); // LAW10: search/boundary miss => span end (whole remainder), recall-safe boundary default
    let userinfo = &rest[..userinfo_end];
    let Some(at_pos) = userinfo.find('@') else {
        return false;
    };
    userinfo[..at_pos].contains(':')
}

fn credential_url_line_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut line_start = 0usize;
    for line in text.split_inclusive('\n') {
        let line_body = line.trim_end_matches(['\r', '\n']);
        if line_has_credential_url(line_body) {
            spans.push((line_start, line_start + line_body.len()));
        }
        line_start += line.len();
    }
    spans
}

fn private_key_material_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = private_key_block_spans(text);
    spans.extend(encoded_private_key_payload_spans(text));
    spans
}

fn private_key_block_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel_begin) = text[search_from..].find("-----BEGIN ") {
        let begin = search_from + rel_begin;
        let header_end = match text[begin..].find('\n') {
            Some(rel) => begin + rel,
            None => text.len(),
        };
        if !text[begin..header_end].contains("PRIVATE KEY") {
            search_from = begin + "-----BEGIN ".len();
            continue;
        }
        let Some(rel_end) = text[header_end..].find("-----END ") else {
            break;
        };
        let end_start = header_end + rel_end;
        let end_line = match text[end_start..].find('\n') {
            Some(rel) => end_start + rel + 1,
            None => text.len(),
        };
        if text[end_start..end_line].contains("PRIVATE KEY") {
            spans.push((begin, end_line));
            search_from = end_line;
        } else {
            search_from = end_start + "-----END ".len();
        }
    }
    spans
}

fn encoded_private_key_payload_spans(text: &str) -> Vec<(usize, usize)> {
    struct Run {
        start: usize,
        end: usize,
        encoded: String,
    }

    fn flush(run: &mut Option<Run>, spans: &mut Vec<(usize, usize)>) {
        let Some(run) = run.take() else {
            return;
        };
        if run.encoded.len() < MIN_ENCODED_PRIVATE_KEY_B64_LEN {
            return;
        }
        let Ok(decoded) = super::base64_decode(&run.encoded) else {
            return;
        };
        let Ok(decoded_text) = String::from_utf8(decoded) else {
            return;
        };
        if decoded_text.contains("-----BEGIN ")
            && decoded_text.contains("PRIVATE KEY")
            && decoded_text.contains("-----END ")
        {
            spans.push((run.start, run.end));
        }
    }

    let mut spans = Vec::new();
    let mut run: Option<Run> = None;
    let mut line_start = 0usize;
    for line in text.split_inclusive('\n') {
        let line_body = line.trim_end_matches(['\r', '\n']);
        let absolute_line_end = line_start + line_body.len();
        let (value_start, value) = base64ish_line_value(line_body, line_start);
        if value.len() >= MIN_PRIVATE_KEY_B64_LINE_LEN
            && value.bytes().all(super::is_standard_base64_byte)
        {
            match &mut run {
                Some(active) => {
                    active.end = absolute_line_end;
                    active.encoded.push_str(value);
                }
                None => {
                    run = Some(Run {
                        start: value_start,
                        end: absolute_line_end,
                        encoded: value.to_string(),
                    });
                }
            }
        } else {
            flush(&mut run, &mut spans);
        }
        line_start += line.len();
    }
    flush(&mut run, &mut spans);
    spans
}

fn base64ish_line_value(line: &str, line_start: usize) -> (usize, &str) {
    let mut start = 0usize;
    let mut end = line.len();
    if let Some(colon) = line.find(':') {
        start = colon + 1;
    }
    while start < end && line.as_bytes()[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && line.as_bytes()[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (line_start + start, &line[start..end])
}

fn candidate_inside_spans(
    candidate_span: Option<(usize, usize)>,
    spans: &[(usize, usize)],
) -> bool {
    let Some((start, end)) = candidate_span else {
        return false;
    };
    spans
        .iter()
        .any(|(span_start, span_end)| *span_start <= start && end <= *span_end)
}

impl CaesarDecoder {
    fn name(&self) -> &'static str {
        "caesar"
    }

    pub(super) fn admission_sketch_with_policy(
        &self,
        chunk: &Chunk,
        policy: &super::policy::CompiledDecodeTransformPolicy,
    ) -> DecodeAdmissionSketch {
        if chunk.metadata.source_type.contains("/caesar")
            || is_source_code_path(chunk.metadata.path.as_deref())
        {
            return DecodeAdmissionSketch::NONE;
        }
        with_extracted_value_spans(&chunk.data, |candidates| {
            let mut count = 0usize;
            let mut bytes = 0usize;
            for candidate in candidates {
                let Some(shifts) = candidate_caesar_shifts(&candidate.value, policy) else {
                    continue;
                };
                let shift_count = shifts.iter().filter(|matched| **matched).count();
                count = count.saturating_add(shift_count);
                bytes = bytes.saturating_add(candidate.value.len().saturating_mul(shift_count));
            }
            if count == 0 {
                DecodeAdmissionSketch::NONE
            } else {
                DecodeAdmissionSketch::possible(DecodeAdmissionSketch::CAESAR, count, bytes)
            }
        })
    }

    pub(super) fn decode_chunk_with_policy(
        &self,
        chunk: &Chunk,
        policy: &super::policy::CompiledDecodeTransformPolicy,
    ) -> Vec<Chunk> {
        // Refuse to recurse on our own output: shifting all 25 non-trivial
        // shifts on a previous output's would re-shift back to the original
        // (one of those 25 covers it) and trip evasion-aware downstream
        // logic. One pass per input is enough.
        if chunk.metadata.source_type.contains("/caesar") {
            return Vec::new();
        }
        if is_source_code_path(chunk.metadata.path.as_deref()) {
            return Vec::new();
        }
        let mut out = Vec::new();
        // Skip Caesar on chunks whose lines already carry a URL with
        // embedded credentials (`scheme://user:pass@host`). Every db
        // connection-string URL is plaintext-readable already, so the
        // 25-shift fan-out cannot reveal new information; its only
        // observed effect is to emit a high-confidence garbage finding
        // whose decoded body out-resolves the real URL match during the
        // per-line resolution group. Investigator empirically attributed
        // the postgres / mongo log-line + .env database FNs to this
        // exact resolution loss. Gate per-line so a chunk that mixes
        // URL traffic with Caesar-encoded creds elsewhere still gets
        // the decoder where it matters.
        let credential_url_line_spans = credential_url_line_spans(&chunk.data);
        let private_key_spans = private_key_material_spans(&chunk.data);
        with_extracted_value_spans(&chunk.data, |candidates| {
            for candidate in candidates {
                if candidate_inside_spans(candidate.span(), &credential_url_line_spans) {
                    continue;
                }
                if candidate_inside_spans(candidate.span(), &private_key_spans) {
                    continue;
                }
                let candidate = candidate.value.as_str();
                // SHIFT-INVARIANT PRECONDITION (sound; a true superset of "some
                // shift is credential-shaped"). `caesar_shift` maps letter->letter,
                // digit->digit, other->other, so the two structural gates inside
                // the per-shift credential-shape gate are identical for the candidate and ALL
                // 25 of its shifts:
                //   * "contains >=1 ASCII digit"        - digits are shift-identity
                //   * "has an 8+ ASCII-ALPHANUMERIC run" - alnum-ness is preserved
                // If the RAW candidate fails either gate, NONE of its 25 shifts can
                // pass the per-shift credential-shape gate, so we skip the entire 25x
                // `caesar_shift` allocation + re-scan loop for it. Only the
                // detector-prefix check (the one gate a shift CAN newly satisfy) is
                // left to the per-shift loop. This is byte-for-byte recall-
                // equivalent - it removes pure-waste allocations, it does not gate
                // out any shift that could have been shaped (unlike an
                // alphabetic-run length gate, which is unsound: a `0x`/`SG.`/`hf_`
                // prefix needs only a 1-2 letter run, so a credential-shaped shift
                // can arise from a chunk with no long alphabetic run at all).
                // Rotated-prefix SHIFT SELECTION (recall- AND precision-exact, not
                // merely a prefilter). A shifted variant's final gate is a
                // active detector prefix in `caesar_shift(candidate, k)`. By the
                // position-wise bijection (see ROTATED_PREFIX_AC),
                //   caesar_shift(candidate, k).contains(P) ⟺ candidate.contains(needle(P,k))
                // where needle(P,k) = caesar_shift(P, 26-k) is needle index
                // `prefix_idx*25 + (k-1)`. So a shift `k` can satisfy
                // the per-shift credential-shape gate ONLY if some needle with that `k` matched.
                // The old code learned "≥1 needle matched" (`is_match`) then tried ALL
                // 25 shifts; instead, recover the exact set of matched `k`s and shift
                // to only those. Every shift that could pass is in this set, so the
                // emitted-chunk set is byte-identical, but the 25× `caesar_shift`
                // allocation + re-scan fan-out collapses to the 1–3 aligned shifts.
                // Caesar emits ~84% of all decode sub-chunks; this is the lever.
                // `find_overlapping_iter` (not `find_iter`) is required: a needle can
                // sit inside/over another, and a non-overlapping walk would drop its
                // `k`, losing a shift that should fire.
                let Some(try_shift) = candidate_caesar_shifts(candidate, policy) else {
                    continue;
                };
                for shift in 1..=25u8 {
                    if !try_shift[shift as usize] {
                        continue;
                    }
                    let decoded = caesar_shift(candidate, shift);
                    // Only the detector-prefix substring (the sole shift-VARIANT
                    // gate) can differ per shift; `candidate_shape_invariant`
                    // already proved the digit + 8-alnum-run half above, and
                    // both are shift-invariant, so re-running the full
                    // the per-shift credential-shape gate here would recompute a
                    // provably-constant predicate on every emitted shift.
                    if !contains_known_prefix_with_policy(&decoded, policy) {
                        continue;
                    }
                    // NOTE: we intentionally use the non-spliced push.
                    // Splicing the decoded variant back into the parent
                    // (which the base64/hex paths do for companion-anchor
                    // preservation) is wrong for Caesar: Caesar produces
                    // 25 candidate shifts per blob, of which several can
                    // randomly satisfy hex/UUID shape gates. Splicing
                    // those into the parent multiplies findings under
                    // keyword-anchored detectors with shifted credentials
                    // that don't match the ground-truth value the user
                    // planted. Caesar's value is the bare decoded
                    // candidate; let it surface as its own chunk so the
                    // dedup layer can collapse identical findings.
                    push_decoded_text_chunk(&mut out, chunk, decoded, self.name());
                }
            }
        });
        out
    }
}

impl Decoder for CaesarDecoder {
    fn name(&self) -> &'static str {
        "caesar"
    }

    fn admission_sketch(&self, chunk: &Chunk) -> DecodeAdmissionSketch {
        self.admission_sketch_with_policy(chunk, super::policy::bundled_compat_policy())
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        self.decode_chunk_with_policy(chunk, super::policy::bundled_compat_policy())
    }
}

fn candidate_caesar_shifts(
    candidate: &str,
    policy: &super::policy::CompiledDecodeTransformPolicy,
) -> Option<[bool; 26]> {
    if candidate.len() < MIN_CAESAR_LEN || !candidate_shape_invariant(candidate) {
        return None;
    }
    let shifts = policy.matched_caesar_shifts(candidate);
    shifts.iter().any(|matched| *matched).then_some(shifts)
}

/// The set of Caesar shifts `k ∈ 1..=25` worth trying for `candidate`, as a
/// `[bool; 26]` indexed by `k`. A shift can satisfy the per-shift credential-shape gate
/// (whose binding gate is an active detector prefix in the shifted text) ONLY
/// if some rotated-prefix needle with that `k` matched the raw candidate, by
/// the `caesar_shift` bijection, `caesar_shift(candidate,k).contains(P)` iff
/// `candidate.contains(needle(P,k))`, where needle index `i` carries `k =
/// (i % 25) + 1`. So restricting the shift loop to these `k`s is recall- and
/// precision-EXACT: every shift that could pass is included, and the dead 22–24
/// shifts (84% of all decode sub-chunks come from Caesar's fan-out) are dropped.
/// The automaton is fail-closed (a build defect panics at first use), so there
/// is no silent all-25-shifts degrade path.
pub(crate) fn matched_caesar_shifts(candidate: &str) -> [bool; 26] {
    super::policy::bundled_compat_policy().matched_caesar_shifts(candidate)
}

/// Shift-invariant half of the per-shift credential-shape gate, evaluated ONCE on the raw
/// candidate before the 25x shift loop. A Caesar/ROT-N shift is a permutation
/// within the letters and the identity on digits/punctuation, so both of these
/// gates produce the SAME answer for the candidate and for every one of its 25
/// shifts:
///   1. at least one ASCII digit (digits are never moved by a shift), and
///   2. an 8+ contiguous ASCII-alphanumeric run (alphanumeric-ness of each
///      byte is preserved under a shift).
/// If the raw candidate fails either, no shift can satisfy
/// the per-shift credential-shape gate, so the whole 25-allocation fan-out for that
/// candidate is pure waste and is skipped. This is a true SUPERSET of the
/// per-shift the per-shift credential-shape gate predicate (it only ever short-circuits
/// candidates that would have produced zero shaped shifts), so it is exactly
/// recall-preserving. It deliberately does NOT pre-check the detector-prefix
/// substring - that is the one gate a shift CAN newly satisfy by rotating
/// letters into a prefix (e.g. `BLJB`+25 -> `AKIA`), so it stays in the loop.
pub(crate) fn candidate_shape_invariant(s: &str) -> bool {
    let bytes = s.as_bytes();
    // Must contain at least one letter for any shift to do anything, AND the
    // shift-invariant ">=1 digit + an 8+ alphanumeric run" shape that
    // the per-shift credential-shape gate also requires (the one gate it adds, a
    // detector-prefix substring, is the only thing a shift can newly satisfy, so
    // it stays out of this precondition).
    bytes.iter().any(|b| b.is_ascii_alphabetic()) && has_digit_and_long_alnum_run(bytes)
}

/// `true` iff `bytes` contains at least one ASCII digit AND a contiguous run of
/// at least [`MIN_ALNUM_RUN`] ASCII-alphanumeric bytes. This is the structural
/// half shared verbatim by [`candidate_shape_invariant`] (evaluated once on the
/// raw candidate) and the per-shift credential-shape gate (`contains_known_prefix` + the shift-invariant `candidate_shape_invariant`) (evaluated per shift), both
/// are shift-invariant under `caesar_shift`, so factoring them here keeps the two
/// callers from drifting on the digit/run thresholds.
fn has_digit_and_long_alnum_run(bytes: &[u8]) -> bool {
    if !bytes.iter().any(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut run = 0usize;
    for &b in bytes {
        if b.is_ascii_alphanumeric() {
            run += 1;
            if run >= MIN_ALNUM_RUN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

pub(crate) fn caesar_shift(input: &str, shift: u8) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        let shifted = match ch {
            'A'..='Z' => {
                let base = b'A';
                let off = (ch as u8 - base + shift) % ALPHABET_LEN;
                (base + off) as char
            }
            'a'..='z' => {
                let base = b'a';
                let off = (ch as u8 - base + shift) % ALPHABET_LEN;
                (base + off) as char
            }
            _ => ch,
        };
        out.push(shifted);
    }
    out
}

/// The shift-VARIANT half of the Caesar credential-shape gate: a known provider
/// prefix appears in the decoded text. Gating on this is what stops any Caesar
/// shift of a credential-shaped input (e.g. `sk_live_...` shifted +23 →
/// `ph_ifsb_...`) from being emitted as a decoded chunk whose substrings can
/// incidentally collide with detector regexes (`sb_4bZ39EnIvgT...` matching the
/// stackblitz `sb_[a-zA-Z0-9_-]{20,}` regex purely by letter coincidence). The
/// downstream `suppress_named_detector_finding` bypasses the
/// EXAMPLE / INSERT / CHANGE / REPLACE markers for `/caesar` source_types
/// (evasion-decoded inputs CAN legitimately be a planted-credential rotation),
/// so the gate has to happen here at decoder-output time. Split out so the
/// per-shift loop evaluates ONLY this variant part, the invariant digit/run
/// half is proved once by [`candidate_shape_invariant`].
pub(crate) fn contains_known_prefix(s: &str) -> bool {
    contains_known_prefix_with_policy(s, super::policy::bundled_compat_policy())
}

fn contains_known_prefix_with_policy(
    candidate: &str,
    policy: &super::policy::CompiledDecodeTransformPolicy,
) -> bool {
    policy.caesar_matches_plaintext(candidate)
}
