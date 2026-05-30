use super::pipeline::{extract_encoded_values, push_decoded_text_chunk};
use super::Decoder;
use keyhog_core::Chunk;

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
pub struct CaesarDecoder;

const MIN_CAESAR_LEN: usize = 16;
const MIN_ALNUM_RUN: usize = 8;

/// File extensions where Caesar-decoding is pure noise. Matched against the
/// suffix of `chunk.metadata.path` (lower-cased). Kept short - only the
/// dominant source-code extensions a scanner is realistically pointed at.
const SOURCE_CODE_EXTENSIONS: &[&str] = &[
    ".rs", ".py", ".go", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".scala", ".c", ".cc",
    ".cpp", ".cxx", ".h", ".hh", ".hpp", ".cs", ".rb", ".php", ".swift", ".m", ".mm", ".sh",
    ".bash", ".zsh", ".fish", ".lua", ".pl", ".pm", ".sql", ".html", ".htm", ".css", ".scss",
    ".sass", ".vue", ".svelte", ".md", ".rst", ".txt", ".adoc",
];

pub fn is_source_code_path(path: Option<&str>) -> bool {
    let Some(p) = path else { return false };
    let lower = p.to_ascii_lowercase();
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
        .unwrap_or(rest.len());
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
            // kimi-decode audit: caesar_shift is the identity for
            // digits / punctuation / non-ASCII. A pure-digit candidate
            // (e.g. a 16-digit PIN) produces 25 IDENTICAL shifts, all
            // equal to the original. The seen-set later dedups them
            // but each unnecessarily walks the full detector pipeline
            // and emits a bare decoded chunk that scans the same text
            // we already scanned in the parent. Skip if the input has
            // no a-z/A-Z character to shift.
            if !candidate.chars().any(|c| c.is_ascii_alphabetic()) {
                continue;
            }
            for shift in 1..=25u8 {
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

pub fn caesar_shift(input: &str, shift: u8) -> String {
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

pub fn looks_credential_shaped(s: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Positive truth case: every documented DB scheme with embedded
    /// `user:pass@host` is detected. This is the gate that prevents
    /// caesar from masking real connection-string credentials.
    #[test]
    fn credential_url_detected_for_db_schemes() {
        let cases = [
            "postgres://app:secret@db.example.org:5432/app",
            "postgresql://u:p@host/dbname",
            "mysql://u:p@host:3306/dbname",
            "mongodb://u:p@host/dbname",
            "mongodb+srv://u:p@host/db?retryWrites=true",
            "redis://:password@host:6379",
            "rediss://u:p@host:6380",
            r#"DB_URL="postgres://app:secret@db/app""#,
            "log: connecting mongodb+srv://prhvtsuw:TpDkVI0CIr0lSVjMf3ySeNu4@dqudscouyssx.example.org/test",
        ];
        for line in cases {
            assert!(
                line_has_credential_url(line),
                "expected credential URL detection on: {}",
                line
            );
        }
    }

    /// Adversarial negative twin: URLs WITHOUT embedded credentials must
    /// not gate Caesar off. Bare-host URLs, doc placeholders, and code
    /// comments still need the decoder pass.
    #[test]
    fn credential_url_silent_on_bare_or_placeholderless_urls() {
        let cases = [
            "https://example.com/path?query=1",
            "http://localhost:8080",
            "ftp://files.example.com/pub/",
            "see docs at https://docs.example.org/setup",
            "git://github.com/owner/repo.git",
            // `:` after scheme but no user (`@` absent)
            "redis://host:6379",
            // `@` present but no `:` before it (anonymous SSH-style URL)
            "ssh://user@host:22/repo.git",
            // Bare text mentioning `://` without a real scheme prefix.
            "looks like ://typo without a scheme",
        ];
        for line in cases {
            assert!(
                !line_has_credential_url(line),
                "credential-URL gate fired on a non-credential line: {}",
                line
            );
        }
    }
}
