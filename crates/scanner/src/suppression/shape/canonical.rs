//! Canonical non-secret credential body shapes such as digests, UUIDs,
//! serial keys, JWT examples, and mask runs.

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

/// Canonical non-secret shapes rejected at entropy candidate generation.
///
/// This intentionally preserves the historical entropy semantics instead of
/// reusing broader report-time suppression helpers. For example,
/// [`looks_like_bare_hex_digest`] also suppresses truncated digest lengths
/// 48/56/72, and [`looks_like_dashed_serial_key`] accepts lowercase serial
/// groups; entropy generation only treats exact UUID, 32/40/64/128 pure-hex,
/// npm SRI, and uppercase 5x5 license serial shapes as canonical non-secrets.
pub(crate) fn looks_like_entropy_canonical_non_secret_shape(value: &str) -> bool {
    looks_like_entropy_uuid_shape(value)
        || looks_like_entropy_canonical_hex_digest(value)
        || looks_like_entropy_integrity_digest(value)
        || looks_like_entropy_upper_license_serial(value)
}

pub(crate) fn looks_like_entropy_uuid_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && value.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit())
}

pub(crate) fn looks_like_entropy_canonical_hex_digest(value: &str) -> bool {
    matches!(value.len(), 32 | 40 | 64 | 128) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn looks_like_entropy_integrity_digest(value: &str) -> bool {
    for prefix in ["sha512-", "sha384-", "sha256-"] {
        if let Some(body) = value.strip_prefix(prefix) {
            if !body.is_empty() && crate::decode::standard_base64_shape(body).is_some() {
                return true;
            }
        }
    }
    false
}

fn looks_like_entropy_upper_license_serial(value: &str) -> bool {
    if value.len() != 29 || value.as_bytes().iter().filter(|&&b| b == b'-').count() != 4 {
        return false;
    }
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups.iter().all(|group| {
            group.len() == 5
                && group
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        })
}

/// Algo-labelled hash-digest sub-shape:
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
        if looks_like_base64_integrity_body(body) {
            return true;
        }
    }
    false
}

/// Bare uniform-hex digest arm. AMBIGUOUS
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

/// True if `s` looks like a base64-encoded package-integrity body after
/// stripping `sha512-` / `sha256-`. Padding is common but not required:
/// value extractors and lockfile generators can surface the same structural
/// integrity string without trailing `=`, and the algorithm label is the
/// non-secret evidence. Conservative length floor of 40 chars avoids catching
/// short base64-ish provider tokens.
fn looks_like_base64_integrity_body(s: &str) -> bool {
    if s.len() < 40 {
        return false;
    }
    crate::decode::standard_base64_shape(s).is_some()
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
pub(crate) fn looks_like_standard_base64_blob(credential: &str) -> bool {
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

/// True when a quoted-printable assignment delimiter (`=3d`, `=3a`, etc.)
/// has eaten the first byte-pair of a UUID and left the still-identifiable
/// v4 suffix (`xxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`). This is narrower than
/// [`is_uuid_v4_shape`]: it requires the v4 and RFC-4122 variant nibbles so
/// arbitrary 6-4-4-4-12 credential strings are not treated as generic UUIDs.
pub(crate) fn looks_like_truncated_uuid_v4_suffix(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 34 {
        return false;
    }
    if b[6] != b'-' || b[11] != b'-' || b[16] != b'-' || b[21] != b'-' {
        return false;
    }
    if b[12] != b'4' {
        return false;
    }
    if !matches!(b[17], b'8' | b'9' | b'a' | b'b' | b'A' | b'B') {
        return false;
    }
    let mut saw_lower = false;
    let mut saw_upper = false;
    for (i, &c) in b.iter().enumerate() {
        if matches!(i, 6 | 11 | 16 | 21) {
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
    if long_runs >= 3 {
        return true;
    }
    has_repeated_full_block(bytes)
}

fn has_repeated_full_block(bytes: &[u8]) -> bool {
    if bytes.len() < 24 || !bytes.iter().any(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    let max_block_len = (bytes.len() / 3).min(64);
    for block_len in 3..=max_block_len {
        if bytes.len() % block_len != 0 {
            continue;
        }
        let first = &bytes[..block_len];
        if first.iter().all(|b| !b.is_ascii_alphanumeric()) {
            continue;
        }
        if bytes[block_len..]
            .chunks_exact(block_len)
            .all(|chunk| chunk == first)
        {
            return true;
        }
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

/// Heuristic for dash-segmented non-secret shapes. Matches fixed-width
/// uppercase/digit product serials and multi-part letter identifiers. It
/// deliberately does not reject every dash-separated alnum value: high-entropy
/// service tokens commonly carry one dash or random dash-separated chunks.
pub(crate) fn is_dash_segmented_alnum_decoy(value: &str) -> bool {
    let randomness = crate::suppression::token_randomness::TokenRandomness::for_candidate(value);
    is_dash_segmented_alnum_decoy_with_randomness(value, &randomness)
}

pub(crate) fn is_dash_segmented_alnum_decoy_with_randomness(
    value: &str,
    randomness: &crate::suppression::token_randomness::TokenRandomness<'_>,
) -> bool {
    if !value.contains('-') {
        return false;
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return false;
    }
    let mut groups = Vec::new();
    for group in value.split('-') {
        if group.is_empty() {
            return false;
        }
        groups.push(group);
    }

    let fixed_width_upper_serial = groups.len() >= 3
        && groups.iter().all(|group| {
            group.len() == 5
                && group
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        });
    if fixed_width_upper_serial {
        return true;
    }

    groups.len() >= 3
        && groups
            .iter()
            .all(|group| group.bytes().all(|b| b.is_ascii_alphabetic()))
        && !randomness.is_random_token(value)
}
