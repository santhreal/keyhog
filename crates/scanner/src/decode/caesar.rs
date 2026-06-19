use super::pipeline::{extract_encoded_values, push_decoded_text_chunk};
use super::Decoder;
use aho_corasick::AhoCorasick;
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

pub(crate) const MIN_CAESAR_LEN: usize = 16;
const MIN_ALNUM_RUN: usize = 8;

/// Aho-Corasick over the "rotated known-prefix" needle set: for every
/// [`crate::confidence::KNOWN_PREFIXES`] entry `P` and every non-trivial shift
/// `k` in `1..=25`, the string `caesar_shift(P, 26 - k)` — i.e. `P` with its
/// ASCII letters rotated BACKWARD by `k` (digits / punctuation fixed).
///
/// SOUNDNESS (recall-exact, not merely a superset). `caesar_shift(_, k)` is a
/// position-wise bijection on a string, so for any candidate `c`:
///   `caesar_shift(c, k).contains(P)`  ⟺  `c.contains(caesar_shift(P, 26 - k))`.
/// Therefore "some shift in `1..=25` of `c` contains some known prefix" is
/// EXACTLY "`c` contains some needle in this automaton". The final gate inside
/// [`looks_credential_shaped`] is precisely that `KNOWN_PREFIXES` substring
/// test, and its other two gates (≥1 digit, an 8+ alphanumeric run) are
/// shift-invariant and checked once by [`candidate_shape_invariant`]. So a
/// candidate that matches NO needle here can never produce a credential-shaped
/// variant under any shift — its entire 25× `caesar_shift` fan-out + re-scan is
/// provably dead work and is skipped with zero recall loss. This replaces the
/// unsound "longest alphabetic run ≥ 16" gate (a `0x` / `SG.` / `hf_` prefix
/// needs only a 1–2 letter run, so a credential-shaped shift can arise from a
/// chunk with no long alphabetic run). See `perf_decode_caesar.rs`.
static ROTATED_PREFIX_AC: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
    let mut needles: Vec<String> = Vec::new();
    for prefix in crate::confidence::KNOWN_PREFIXES {
        for k in 1..=25u8 {
            // rot_{-k}(P) == caesar_shift(P, 26 - k); k in 1..=25 => 26-k in 1..=25.
            needles.push(caesar_shift(prefix, 26 - k));
        }
    }
    match AhoCorasick::new(&needles) {
        Ok(ac) => Some(ac),
        // Law 10: built from the constant `KNOWN_PREFIXES`, so a build failure is
        // an invariant violation. `matched_caesar_shifts` falls back to trying
        // all 25 shifts (recall-preserving), but that must not happen silently.
        Err(e) => {
            crate::prefilter_degrade::warn_prefilter_disabled(
                "Caesar rotated-prefix gate (ROTATED_PREFIX_AC)",
                &e,
            );
            None
        }
    }
});

/// File extensions where Caesar-decoding is pure noise. Matched against the
/// suffix of `chunk.metadata.path` (lower-cased). Kept short - only the
/// dominant source-code extensions a scanner is realistically pointed at.
const SOURCE_CODE_EXTENSIONS: &[&str] = &[
    ".rs", ".py", ".go", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".scala", ".c", ".cc",
    ".cpp", ".cxx", ".h", ".hh", ".hpp", ".cs", ".rb", ".php", ".swift", ".m", ".mm", ".sh",
    ".bash", ".zsh", ".fish", ".lua", ".pl", ".pm", ".sql", ".html", ".htm", ".css", ".scss",
    ".sass", ".vue", ".svelte", ".md", ".rst", ".txt", ".adoc", ".tbl", ".mk", ".cmake",
];

const SOURCE_CODE_FILENAMES: &[&str] = &["kconfig", "makefile", "cmakelists.txt"];

pub(crate) fn is_source_code_path(path: Option<&str>) -> bool {
    let Some(p) = path else { return false };
    let lower = p.replace('\\', "/").to_ascii_lowercase();
    if let Some(file_name) = lower.rsplit('/').next() {
        if SOURCE_CODE_FILENAMES.contains(&file_name) {
            return true;
        }
    }
    SOURCE_CODE_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(ext))
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
    let scheme_bytes = line[..scheme_end].as_bytes();
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

impl Decoder for CaesarDecoder {
    fn name(&self) -> &'static str {
        "caesar"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
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
        let chunk_has_credential_url = chunk.data.lines().any(line_has_credential_url);
        if chunk_has_credential_url {
            return Vec::new();
        }
        for candidate in extract_encoded_values(&chunk.data) {
            if candidate.len() < MIN_CAESAR_LEN {
                continue;
            }
            // SHIFT-INVARIANT PRECONDITION (sound; a true superset of "some
            // shift is credential-shaped"). `caesar_shift` maps letter->letter,
            // digit->digit, other->other, so the two structural gates inside
            // `looks_credential_shaped` are identical for the candidate and ALL
            // 25 of its shifts:
            //   * "contains >=1 ASCII digit"        - digits are shift-identity
            //   * "has an 8+ ASCII-ALPHANUMERIC run" - alnum-ness is preserved
            // If the RAW candidate fails either gate, NONE of its 25 shifts can
            // pass `looks_credential_shaped`, so we skip the entire 25x
            // `caesar_shift` allocation + re-scan loop for it. Only the
            // KNOWN_PREFIXES check (the one gate a shift CAN newly satisfy) is
            // left to the per-shift loop. This is byte-for-byte recall-
            // equivalent - it removes pure-waste allocations, it does not gate
            // out any shift that could have been shaped (unlike an
            // alphabetic-run length gate, which is unsound: a `0x`/`SG.`/`hf_`
            // prefix needs only a 1-2 letter run, so a credential-shaped shift
            // can arise from a chunk with no long alphabetic run at all).
            if !candidate_shape_invariant(&candidate) {
                continue;
            }
            // Rotated-prefix SHIFT SELECTION (recall- AND precision-exact, not
            // merely a prefilter). A shifted variant's final gate is a
            // KNOWN_PREFIXES substring in `caesar_shift(candidate, k)`. By the
            // position-wise bijection (see ROTATED_PREFIX_AC),
            //   caesar_shift(candidate, k).contains(P) ⟺ candidate.contains(needle(P,k))
            // where needle(P,k) = caesar_shift(P, 26-k) is needle index
            // `prefix_idx*25 + (k-1)`. So a shift `k` can satisfy
            // `looks_credential_shaped` ONLY if some needle with that `k` matched.
            // The old code learned "≥1 needle matched" (`is_match`) then tried ALL
            // 25 shifts; instead, recover the exact set of matched `k`s and shift
            // to only those. Every shift that could pass is in this set, so the
            // emitted-chunk set is byte-identical — but the 25× `caesar_shift`
            // allocation + re-scan fan-out collapses to the 1–3 aligned shifts.
            // Caesar emits ~84% of all decode sub-chunks; this is the lever.
            // `find_overlapping_iter` (not `find_iter`) is required: a needle can
            // sit inside/over another, and a non-overlapping walk would drop its
            // `k`, losing a shift that should fire.
            let try_shift = matched_caesar_shifts(&candidate);
            for shift in 1..=25u8 {
                if !try_shift[shift as usize] {
                    continue;
                }
                let decoded = caesar_shift(&candidate, shift);
                if !looks_credential_shaped(&decoded) {
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
        out
    }
}

/// The set of Caesar shifts `k ∈ 1..=25` worth trying for `candidate`, as a
/// `[bool; 26]` indexed by `k`. A shift can satisfy `looks_credential_shaped`
/// (whose binding gate is a KNOWN_PREFIXES substring in the shifted text) ONLY
/// if some rotated-prefix needle with that `k` matched the raw candidate — by
/// the `caesar_shift` bijection, `caesar_shift(candidate,k).contains(P)` iff
/// `candidate.contains(needle(P,k))`, where needle index `i` carries `k =
/// (i % 25) + 1`. So restricting the shift loop to these `k`s is recall- and
/// precision-EXACT: every shift that could pass is included, and the dead 22–24
/// shifts (84% of all decode sub-chunks come from Caesar's fan-out) are dropped.
/// Falls back to all 25 shifts if the AC failed to build.
pub(crate) fn matched_caesar_shifts(candidate: &str) -> [bool; 26] {
    let mut try_shift = [false; 26];
    match ROTATED_PREFIX_AC.as_ref() {
        Some(ac) => {
            // `find_overlapping_iter` is required (not `find_iter`): needles can
            // nest/overlap, and a non-overlapping walk would drop a matched `k`.
            for m in ac.find_overlapping_iter(candidate) {
                try_shift[(m.pattern().as_usize() % 25) + 1] = true;
            }
        }
        None => {
            for slot in try_shift.iter_mut().skip(1) {
                *slot = true;
            }
        }
    }
    try_shift
}

/// Shift-invariant half of `looks_credential_shaped`, evaluated ONCE on the raw
/// candidate before the 25x shift loop. A Caesar/ROT-N shift is a permutation
/// within the letters and the identity on digits/punctuation, so both of these
/// gates produce the SAME answer for the candidate and for every one of its 25
/// shifts:
///   1. at least one ASCII digit (digits are never moved by a shift), and
///   2. an 8+ contiguous ASCII-alphanumeric run (alphanumeric-ness of each
///      byte is preserved under a shift).
/// If the raw candidate fails either, no shift can satisfy
/// `looks_credential_shaped`, so the whole 25-allocation fan-out for that
/// candidate is pure waste and is skipped. This is a true SUPERSET of the
/// per-shift `looks_credential_shaped` predicate (it only ever short-circuits
/// candidates that would have produced zero shaped shifts), so it is exactly
/// recall-preserving. It deliberately does NOT pre-check the KNOWN_PREFIXES
/// substring - that is the one gate a shift CAN newly satisfy by rotating
/// letters into a prefix (e.g. `BLJB`+25 -> `AKIA`), so it stays in the loop.
pub(crate) fn candidate_shape_invariant(s: &str) -> bool {
    let bytes = s.as_bytes();
    if !bytes.iter().any(|b| b.is_ascii_digit()) {
        return false;
    }
    // Must also contain at least one letter for any shift to do anything.
    if !bytes.iter().any(|b| b.is_ascii_alphabetic()) {
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
                let off = (ch as u8 - base + shift) % 26;
                (base + off) as char
            }
            'a'..='z' => {
                let base = b'a';
                let off = (ch as u8 - base + shift) % 26;
                (base + off) as char
            }
            _ => ch,
        };
        out.push(shifted);
    }
    out
}

pub(crate) fn looks_credential_shaped(s: &str) -> bool {
    let bytes = s.as_bytes();
    if !bytes.iter().any(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut run = 0usize;
    let mut saw_long_run = false;
    for &b in bytes {
        if b.is_ascii_alphanumeric() {
            run += 1;
            if run >= MIN_ALNUM_RUN {
                saw_long_run = true;
                break;
            }
        } else {
            run = 0;
        }
    }
    if !saw_long_run {
        return false;
    }
    // Same rationale as `reverse::looks_reversible`: gate on a known
    // provider prefix appearing in the decoded text. Without this, any
    // Caesar shift of a credential-shaped input (e.g. `sk_live_...`
    // shifted +23 → `ph_ifsb_...`) gets emitted as a decoded chunk
    // whose substrings can incidentally collide with detector regexes
    // (`sb_4bZ39EnIvgT...` matches the stackblitz `sb_[a-zA-Z0-9_-]{20,}`
    // regex purely by letter coincidence). The downstream
    // `should_suppress_named_detector_finding` bypasses the
    // EXAMPLE / INSERT / CHANGE / REPLACE markers for `/caesar`
    // source_types (because evasion-decoded inputs CAN legitimately
    // be a planted-credential rotation), so the gate has to happen
    // here at decoder-output time.
    crate::confidence::KNOWN_PREFIXES
        .iter()
        .any(|prefix| s.contains(prefix))
}
