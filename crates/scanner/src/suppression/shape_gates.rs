pub(crate) const RFC7519_EXAMPLE_JWT_PREFIX: &str =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw";

/// True if `credential` matches the XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
/// dashed-serial / license-key shape: exactly 5 dash-separated
/// blocks, each exactly 5 alphanumeric characters. Microsoft Office,
/// Adobe, Atlassian, JetBrains and many other product-key surfaces
/// use this shape; real credentials almost never do.
pub(crate) fn looks_like_dashed_serial_key(credential: &str) -> bool {
    if credential.len() != 29 {
        return false;
    }
    let parts: Vec<&str> = credential.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == 5 && p.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// True if `credential` is a bare cryptographic hash digest
/// (MD5/SHA1/SHA256/SHA512) or an RFC-4122 UUID-v4. These are the
/// dominant false-positive class in the SecretBench mirror corpus.
///
/// Strictness: the entire credential must be only hex (or, for UUIDs,
/// hex + dashes in the canonical 8-4-4-4-12 shape with version-4
/// nibble). Mixed-case is tolerated only when uniform - `Abcd1234`
/// in a real secret would NOT match because it's not all-lower or
/// all-upper hex. A scanner that already coincidentally classifies
/// the credential as a known-prefix secret (AKIA…, ghp_… etc.) has
/// already returned `false` upstream of this function.
// Retained for test scaffolding asserting the pre-split combined-
// shape behaviour. Production paths call `is_uuid_v4_shape` and
// `looks_like_hash_digest` individually because the UUID arm is gated
// by `bypass_shape_gates` while the hash arm is always-on.
#[allow(dead_code)]
pub(crate) fn looks_like_pure_hash_digest_or_uuid(credential: &str) -> bool {
    is_uuid_v4_shape(credential) || looks_like_hash_digest(credential)
}

/// Hash-digest sub-check of [`looks_like_pure_hash_digest_or_uuid`].
/// Always safe to apply (real secrets at these lengths use base64, not
/// uniform hex). Exposed so the named-detector path can apply it
/// without the UUID arm.
pub(crate) fn looks_like_hash_digest(credential: &str) -> bool {
    looks_like_prefixed_hash_digest(credential) || looks_like_bare_hex_digest(credential)
}

/// Algo-labelled hash-digest sub-shape of [`looks_like_hash_digest`]:
/// docker (`sha256:<64-hex>`), npm package-lock integrity
/// (`sha512-<base64>`), python requirements (`sha256:<64-hex>`), git-LFS
/// pointers (`sha256:<64-hex>`). The `sha256:` / `sha512-` label is a
/// structural decoy marker that NO service-specific detector regex ever
/// requests as the body of its credential, so this sub-shape stays a
/// false positive even when a generic keyword anchor (`token=`,
/// `integrity:`) is attached. Split out from the bare-hex arm so the
/// decision tree can fire it regardless of `bypass_shape_gates` while
/// the ambiguous bare-hex arm (Algolia / New Relic / Redis Labs use
/// 32/40/64-hex bodies) stays anchor-gated.
pub(crate) fn looks_like_prefixed_hash_digest(credential: &str) -> bool {
    if let Some(body) = strip_hash_algo_prefix(credential) {
        // Stripped body must itself be a hash digest of the
        // corresponding length OR a base64 blob (npm-style).
        if body.len() == 64 && is_uniform_hex(body) {
            return true;
        }
        if body.len() == 128 && is_uniform_hex(body) {
            return true;
        }
        if body.len() == 40 && is_uniform_hex(body) {
            return true;
        }
        if looks_like_base64_blob_with_padding(body) {
            return true;
        }
    }
    false
}

/// Bare uniform-hex digest arm of [`looks_like_hash_digest`]. AMBIGUOUS
/// with real service-anchored hex keys (Algolia admin 32-hex, New Relic
/// 40-hex, Redis Labs 64-hex), so the decision tree keeps this arm gated
/// on `!bypass_shape_gates`: a service-fingerprinted detector that
/// requested pure hex IS positive evidence the value is a key, not a
/// git SHA. The bare-hex-under-a-bare-keyword case (`token=<64-hex>`)
/// is handled in `suppression/api.rs` by reclassifying generic-keyword
/// pure-hex captures as `weak_anchor` (→ `!bypass_shape_gates` here).
pub(crate) fn looks_like_bare_hex_digest(credential: &str) -> bool {
    // Bare hash-digest hex. Lengths that real secrets use commonly
    // (e.g. 40-char AWS secret-access-key body) DON'T match because
    // those are base64, not pure hex.
    //
    // The 48-char length is included because several detector
    // regexes (e.g. honeybadger-api-key `[a-f0-9]{32,48}`) greedy-
    // capture the FIRST 48 chars of a 64-char sha256 hex span,
    // producing a 48-char credential that is the prefix of a hash
    // and not a real key. Same for 56 and 72 - common boundary
    // lengths produced by detectors that quantify hex spans without
    // a non-hex terminator. The 64/128 already-covered cases catch
    // the full-length hash; the 48/56/72 extension covers the
    // truncated-prefix variants. Each added length is justified by
    // a SecretBench-medium FP cluster.
    matches!(credential.len(), 32 | 40 | 48 | 56 | 64 | 72 | 128) && is_uniform_hex(credential)
}

/// If `credential` begins with - OR contains - one of the well-known
/// hash-algorithm labels (`sha256:`, `sha512:`, `sha512-`, `sha1:`,
/// `md5:`), return the body after the label. Otherwise None.
///
/// Substring match (not prefix-only) is intentional. Docker image
/// digests are commonly written `nginx@sha256:<64-hex>`, python
/// requirements as `--hash=sha256:<64-hex>`, both of which keyhog's
/// value extractor surfaces as one credential string that doesn't
/// START with the algo label.
fn strip_hash_algo_prefix(credential: &str) -> Option<&str> {
    const LABELS: &[&str] = &["sha256:", "sha512:", "sha512-", "sha256-", "sha1:", "md5:"];
    for label in LABELS {
        if let Some(idx) = credential.find(label) {
            return Some(&credential[idx + label.len()..]);
        }
    }
    None
}

/// True if `s` looks like a base64-encoded blob with one or two
/// trailing `=` padding chars (the canonical shape of npm package-
/// lock `integrity` values after stripping `sha512-`). Conservative
/// length floor of 40 chars to avoid catching short base64 tokens
/// that might be real secrets.
fn looks_like_base64_blob_with_padding(s: &str) -> bool {
    if s.len() < 40 {
        return false;
    }
    if !(s.ends_with("==") || s.ends_with('=')) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// True if `credential` is a standard-base64-encoded arbitrary-bytes
/// blob (protobuf wire format, marshalled binary, etc.) rather than
/// a credential token.
///
/// Heuristics (all required):
///   1. Length in `[40, 80]` chars - the window where the SecretBench
///      protobuf negatives concentrate (30-60 random bytes → 40-80
///      base64 chars). Above 80 the decode-and-recheck gate handles
///      it (random binary doesn't decode to UTF-8 - no recheck
///      fires - and real long-form positives like Azure storage key
///      (88 chars) keep their recall). Below 40 we'd over-suppress
///      short tokens that happen to contain `+/`.
///   2. Alphabet limited to `[A-Za-z0-9+/=]` (standard base64).
///   3. Either ends in `=`/`==` padding OR length is a multiple of
///      4 (proper base64 of byte-aligned data). 40 % 4 == 0 so the
///      40-char unpadded case is admitted; previously the gate
///      rejected those, leaking thousands of FPs from the no-pad
///      40-char `generic-password`/`generic-secret` shape in the
///      SecretBench mirror corpus.
///   4. Admit clause - at least ONE of:
///        * contains `+` / `/` (standard-base64 punct), OR
///        * trailing `=` padding, OR
///        * length is a multiple of 4 AND alphabet diversity is
///          >= 32 distinct alphanumeric chars (random bytes
///          encoded; placeholder / dictionary-word shapes never
///          reach that diversity at >= 40 chars).
///
/// Mirror v32 had 52 base64-protobuf FPs surviving every other
/// suppression; the v33 widening (drop the strict `+/` requirement,
/// add a high-diversity admit) collapses the pure-alphanumeric and
/// padded sub-classes that were leaking.
///
/// Why this is safe for recall: PEM-framed credentials get the
/// hard bypass above (they start with `-----BEGIN`), so
/// EC/RSA/PGP/OpenSSH private keys are unaffected even though
/// their bodies are standard base64. The 86/88-char Azure storage
/// key sits OUTSIDE the [40, 80] window so recall is preserved.
/// AWS secret keys are 40 chars base62 with diversity typically
/// < 32, so the diversity clause does not bite them.
pub fn looks_like_standard_base64_blob(credential: &str) -> bool {
    // Single source of truth for the random-base64-blob shape: the
    // parameterized `decode_structure::is_random_base64_blob`. This caller
    // pins the [40, 80] length band and the diversity floor of 32 distinct
    // alphanumeric chars; the sibling `decode_structure::looks_like_uniform_
    // base64_blob` pins (44, 600, 32). The two were byte-identical scan loops
    // before being reconciled here so their bands can never silently drift in
    // opposite directions again (org/dedup audit finding).
    crate::decode_structure::is_random_base64_blob(credential, 40, 80, 32)
}

fn is_uniform_hex(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut saw_lower = false;
    let mut saw_upper = false;
    for &b in bytes {
        match b {
            b'0'..=b'9' => {}
            b'a'..=b'f' => saw_lower = true,
            b'A'..=b'F' => saw_upper = true,
            _ => return false,
        }
    }
    // Reject MiXeD-case hex (real hash digests are emitted by every
    // standard library in one case or the other, never mixed). The
    // mixed-case bar saves recall on Base16-ish secrets that happen
    // to look hex-shaped.
    !(saw_lower && saw_upper)
}

pub(crate) fn is_uuid_v4_shape(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
        return false;
    }
    // Version-4 marker at position 14, variant marker at position 19
    // (8/9/a/b) per RFC 4122. We don't require the version digit so
    // we also catch v1/v3/v5 - every standard-shaped UUID is FP.
    let mut saw_lower = false;
    let mut saw_upper = false;
    for (i, &c) in b.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            continue;
        }
        match c {
            b'0'..=b'9' => {}
            b'a'..=b'f' => saw_lower = true,
            b'A'..=b'F' => saw_upper = true,
            _ => return false,
        }
    }
    !(saw_lower && saw_upper)
}

/// Return true if the credential contains three or more consecutive identical characters.
pub(crate) fn has_three_or_more_consecutive_identical(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let mut run = 1usize;
        while i + run < bytes.len() && bytes[i + run] == b {
            run += 1;
        }
        if run >= 3 {
            return true;
        }
        i += run;
    }
    false
}

pub(crate) fn known_prefix_body(credential: &str) -> Option<&str> {
    // Single source of truth: crate::confidence::KNOWN_PREFIXES.
    // Pre-2026-05-24 this function carried a hand-curated 27-entry list
    // that drifted from the canonical 38-entry KNOWN_PREFIXES. Missing
    // entries (sk-, xoxs-, glcbt-, glrt-, vercel_, sbp_, 0x, rk_test_,
    // -----BEGIN, TESTKEY_) meant credentials with those prefixes
    // bypassed the early-return-false fast path and fell into the
    // repetitive-mask/filler gates below, where a legitimate
    // `sk-abcdefghijklmnopqrstuvwxyz...` OpenAI key with naturally-
    // occurring repeated characters would be dropped. Kimi-suppress
    // audit finding #1.
    crate::confidence::KNOWN_PREFIXES
        .iter()
        .find_map(|prefix| credential.strip_prefix(prefix))
}

pub(crate) fn looks_like_prefixed_masked_sequence(body: &str) -> bool {
    // Trailing-ellipsis is an unambiguous placeholder signal: real secrets
    // never end in `...`. UI prompt strings like `ghp_1a2b3c4...` (vscode
    // input-box placeholder) and docs snippets like `sk_live_abcd1234...`
    // are the dominant failure mode. Same for unicode horizontal ellipsis.
    if body.ends_with("...") || body.ends_with('…') {
        return true;
    }
    let upper = body.to_ascii_uppercase();
    let starts_with_mask = upper.starts_with("XXX") || upper.starts_with("***");
    let contains_fake_sequence = ["1234567890", "0123456789", "ABCDEFGH", "ABCDEFGHIJ"]
        .iter()
        .any(|seq| upper.contains(seq));
    starts_with_mask && contains_fake_sequence
}

pub(crate) fn has_repeated_block_mask(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut long_runs = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let mut run = 1usize;
        while i + run < bytes.len() && bytes[i + run] == b {
            run += 1;
        }
        if run >= 4 && b.is_ascii_alphanumeric() {
            long_runs += 1;
            if long_runs >= 3 {
                return true;
            }
        }
        i += run;
    }
    false
}

pub(crate) fn has_n_or_more_consecutive_identical(s: &str, n: usize) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let mut run = 1usize;
        while i + run < bytes.len() && bytes[i + run] == b {
            run += 1;
        }
        // Dashes are legitimate delimiters in structured formats (PEM headers,
        // UUIDs, JWT separators). Don't count them as repetitive masking.
        if run >= n && b != b'-' {
            return true;
        }
        i += run;
    }
    false
}
