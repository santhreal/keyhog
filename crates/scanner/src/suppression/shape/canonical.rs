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
    is_five_by_five_dash_shape(credential, |b| b.is_ascii_alphanumeric())
}

/// `true` iff `len` (in hex chars) is a canonical cryptographic digest width
/// (md5 = 32, sha1 = 40, sha256 = 64, sha512 = 128). The widths are Tier-B data
/// (`rules/hex-digest-policy.toml`), so a new digest family is a data edit and
/// every shape gate that recognises a fixed-length hex digest reads the one
/// list instead of re-listing widths inline.
#[inline]
pub(super) fn is_canonical_hex_digest_length(len: usize) -> bool {
    crate::hex_digest_policy::is_canonical_length(len)
}

/// Exact dotted credential shapes the scanner may treat as real tokens.
///
/// Property/method chains also use dots, so keep this as a tight allowlist
/// instead of a general punctuation relaxation.
pub(crate) fn is_structured_dotted_token(value: &str) -> bool {
    if !value.contains('.') {
        return false;
    }
    let mut parts = value.split('.');
    let (Some(first), Some(second), Some(third), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let segments = [first, second, third];
    let is_jwt_like = crate::jwt::has_jwt_header_prefix(first)
        && segments.iter().all(|segment| {
            segment.len() >= 4 && segment.bytes().all(crate::decode::is_base64_candidate_byte)
        });
    let is_discord_style = (23..=28).contains(&first.len())
        && (6..=8).contains(&second.len())
        && (27..=38).contains(&third.len())
        && segments.iter().all(|segment| {
            segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        });
    is_jwt_like || is_discord_style
}

// Canonical SRI/package-integrity hash-algo dash labels (`sha512-`, `sha384-`,
// `sha256-`). Loaded from `rules/hash-algo-labels.toml` (integrity_labels).
// ONE owner for the integrity-body gates in this module and the decoded-
// labelled-hash gate in `decision.rs`. Distinct from `strip_hash_algo_prefix`'s
// broader label set, which also carries the colon forms and `sha1:`/`md5:`.
crate::tier_b_list::tier_b_vec!(
    pub(crate) HASH_ALGO_INTEGRITY_LABELS,
    "hash-algo-labels.toml",
    integrity_labels
);

/// Canonical COLON-form hash-algo labels (docker/python/git-LFS hex digests:
/// `sha256:`/`sha512:`/`sha1:`/`md5:`). Loaded from `rules/hash-algo-labels.toml`
/// (colon_labels). SINGLE OWNER of this shared vocabulary, consumed BOTH by
/// `strip_hash_algo_prefix` (suppression digest-shape strip) here AND by the
/// entropy assignment-value gate (`entropy::keywords`). The entropy gate
/// additionally recognizes `git-sha:` (git commit refs), that stays a documented
/// entropy-LOCAL extra, since colon-digest SUPPRESSION intentionally covers only
/// the docker/python/git-LFS digest formats, not commit references.
pub(crate) static HASH_ALGO_COLON_LABELS: std::sync::LazyLock<Vec<Vec<u8>>> =
    std::sync::LazyLock::new(|| {
        #[derive(serde::Deserialize)]
        struct HashAlgoLabels {
            colon_labels: Vec<String>,
        }
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/rules/hash-algo-labels.toml"
        ));
        let parsed: HashAlgoLabels = toml::from_str(raw).unwrap_or_else(|error| {
            panic!(
                "rules/hash-algo-labels.toml is invalid: {error}. \
             Fix the bundled Tier-B data file."
            )
        });
        assert!(
        !parsed.colon_labels.is_empty(),
        "rules/hash-algo-labels.toml colon_labels is empty; refusing to run without the Tier-B list it owns."
    );
        parsed
            .colon_labels
            .into_iter()
            .map(|s| s.into_bytes())
            .collect()
    });

pub(super) fn is_five_by_five_dash_shape(value: &str, body_byte_ok: impl Fn(u8) -> bool) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 29 {
        return false;
    }
    bytes.iter().enumerate().all(|(idx, &byte)| {
        if matches!(idx, 5 | 11 | 17 | 23) {
            byte == b'-'
        } else {
            body_byte_ok(byte)
        }
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
    let Some(body) = strip_hash_algo_prefix(credential) else {
        return false;
    };
    // Stripped body must itself be a fixed-length hash digest (md5 32, sha1 40,
    // sha256 64, sha512 128 hex) OR a base64 package-integrity blob (npm-style).
    // The 32-hex md5 length closes the `md5:`/`sha1:`-labelled-body gap: the
    // label set includes `md5:` but the body-length set previously omitted 32,
    // so `md5:<32-hex>` leaked back out as a false-positive credential.
    (is_canonical_hex_digest_length(body.len()) && is_uniform_hex(body))
        || looks_like_base64_integrity_body(body)
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
    // those are base64, not pure hex. The recognized widths are Tier-B
    // data (`rules/hex-digest-policy.toml` `bare_digest_lengths`): the
    // canonical digest widths plus the truncation boundaries produced by
    // detectors that quantify hex spans without a non-hex terminator
    // (48/56/72), each justified by a SecretBench-medium FP cluster.
    crate::hex_digest_policy::is_bare_digest_length(credential.len()) && is_uniform_hex(credential)
}

// The AWS partitions whose IAM ARNs this suppression recognizes. Loaded from
// `rules/hash-algo-labels.toml` (aws_iam_arn_partitions). Single owner for
// both the full (`arn:<p>:iam::`) and trimmed (`<p>:iam::`) gates.
crate::tier_b_list::tier_b_vec!(
    AWS_IAM_ARN_PARTITIONS,
    "hash-algo-labels.toml",
    aws_iam_arn_partitions
);

/// Strip a `<partition>:iam::` prefix (using the single partition list) and return
/// the ARN body. `require_arn` selects whether a literal `arn:` must lead (the full
/// gate) or must be absent (the pre-trimmed gate), preserving the two callers'
/// original distinction while sharing one partition list. Zero-alloc.
fn strip_aws_iam_arn_body(value: &str, require_arn: bool) -> Option<&str> {
    let rest = match value.strip_prefix("arn:") {
        Some(rest) if require_arn => rest,
        None if !require_arn => value,
        _ => return None,
    };
    AWS_IAM_ARN_PARTITIONS.iter().find_map(|partition| {
        rest.strip_prefix(partition.as_str())?
            .strip_prefix(":iam::")
    })
}

pub(crate) fn looks_like_aws_iam_arn(value: &str) -> bool {
    strip_aws_iam_arn_body(value, true).is_some_and(aws_iam_arn_body_has_resource_target)
}

pub(crate) fn looks_like_trimmed_aws_iam_arn(value: &str) -> bool {
    strip_aws_iam_arn_body(value, false).is_some_and(aws_iam_arn_body_has_resource_target)
}

// AWS IAM ARN resource targets that mark a value as an ARN, not a credential.
// Loaded from `rules/hash-algo-labels.toml` (aws_iam_arn_resource_targets).
crate::tier_b_list::tier_b_vec!(
    AWS_IAM_ARN_RESOURCE_TARGETS,
    "hash-algo-labels.toml",
    aws_iam_arn_resource_targets
);

fn aws_iam_arn_body_has_resource_target(body: &str) -> bool {
    AWS_IAM_ARN_RESOURCE_TARGETS
        .iter()
        .any(|target| body.contains(target.as_str()))
}

/// If `credential` begins with - OR contains - one of the well-known
/// hash-algorithm labels (colon forms `sha256:`, `sha512:`, `sha1:`, `md5:`
/// plus the SRI dash forms `sha512-`, `sha384-`, `sha256-`), return the body
/// after the first such label. Otherwise None.
///
/// Substring match (not prefix-only) is intentional. Docker image
/// digests are commonly written `nginx@sha256:<64-hex>`, python
/// requirements as `--hash=sha256:<64-hex>`, both of which keyhog's
/// value extractor surfaces as one credential string that doesn't
/// START with the algo label.
///
/// The dash-form (SRI) labels are NOT hardcoded here: they come from the ONE
/// owner [`HASH_ALGO_INTEGRITY_LABELS`], so this report-time strip and the
/// entropy-generation assignment role in `shape::assignment` / decoded
/// (`decision::decoded_looks_like_labelled_hash`) integrity gates can never
/// disagree on the SRI label set. This list previously pasted a diverging
/// `{sha512-, sha256-}` dash subset that DROPPED `sha384-`, so a raw `sha384-`
/// SRI body (the recommended, most common SRI algorithm) was suppressed by the
/// entropy/decoded paths yet leaked back out at report time (DEDUP: same-set-
/// different-value latent bug).
///
/// The label match is ASCII-case-insensitive: `ssh-keygen -lf` renders key
/// fingerprints as upper-case `SHA256:<base64>`, and Windows `certutil
/// -hashfile` emits upper-case `SHA256` before the digest. Matching only the
/// lower-case spelling used to leak those upper-case digest bodies back out as
/// false-positive credentials. Widening the label match is recall-safe because
/// the sole caller ([`looks_like_prefixed_hash_digest`]) still re-checks that
/// the stripped body is itself a fixed-length hex digest or base64 integrity
/// blob before suppressing (the label alone never suppresses anything).
fn strip_hash_algo_prefix(credential: &str) -> Option<&str> {
    // Colon-form algo labels (docker/python/git-LFS hex digests), now the shared
    // `HASH_ALGO_COLON_LABELS` owner above (was a fn-local copy the entropy gate
    // duplicated). The SRI dash labels are chained in from
    // `HASH_ALGO_INTEGRITY_LABELS` (single owner).
    let bytes = credential.as_bytes();
    HASH_ALGO_COLON_LABELS
        .iter()
        .map(|v| v.as_slice())
        .chain(
            HASH_ALGO_INTEGRITY_LABELS
                .iter()
                .map(|label| label.as_bytes()),
        )
        .find_map(|label| {
            // `label` is ASCII, so `idx + label.len()` is a UTF-8 char boundary
            // and the slice cannot split a codepoint even for a multibyte tail.
            crate::ascii_ci::ci_find_at(bytes, label).map(|idx| &credential[idx + label.len()..])
        })
}

/// True if `s` looks like a base64-encoded package-integrity body after
/// stripping `sha512-` / `sha256-`. Padding is common but not required:
/// value extractors and lockfile generators can surface the same structural
/// integrity string without trailing `=`, and the algorithm label is the
/// non-secret evidence. Conservative length floor of 40 chars avoids catching
/// short base64-ish provider tokens.
pub(crate) fn looks_like_base64_integrity_body(s: &str) -> bool {
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

/// Pure standard-base64 random-byte decoy shape in the 40-80 char band.
///
/// This is the decode-through sibling for decoys that miss the punctuation /
/// padding hard-drop gates: pure base62-looking standard-base64 values that
/// decode to bytes which are neither printable text nor recognizable binary
/// magic. It is a shape predicate, not a generic-engine concern; callers decide
/// whether their surrounding evidence is strong enough to apply it.
pub(crate) fn looks_like_random_byte_base64_blob(value: &str) -> bool {
    if !(40..=80).contains(&value.len()) {
        return false;
    }
    if value.bytes().any(|b| matches!(b, b'+' | b'/')) {
        return false;
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'=')
    {
        return false;
    }
    let structure = crate::decode_structure::analyze(value);
    if !structure.decodable {
        return false;
    }
    if structure.magic.is_some() {
        return true;
    }
    structure.printable_ratio < 0.85
}

pub(super) fn is_uniform_hex(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    hex_bytes_are_uniform_case(bytes, &[])
}

fn hex_bytes_are_uniform_case(bytes: &[u8], skipped_positions: &[usize]) -> bool {
    let mut saw_lower = false;
    let mut saw_upper = false;
    for (index, &b) in bytes.iter().enumerate() {
        if skipped_positions.contains(&index) {
            continue;
        }
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
    hex_bytes_are_uniform_case(b, &[8, 13, 18, 23])
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
    hex_bytes_are_uniform_case(b, &[6, 11, 16, 21])
}

/// Maximum length of a template-placeholder value. Above this a brace/angle-
/// wrapped value is likely a real structured payload (JSON body, XML doc), not a
/// `${VAR}`-style placeholder, so the suppression must not fire. Single named
/// owner for the two suppression sites that previously pasted `<= 80` inline.
const TEMPLATE_PLACEHOLDER_MAX_LEN: usize = 80;

/// True when `value` is a template placeholder wrapped in `{...}`, `<...>`, or
/// `${...}` and is no longer than [`TEMPLATE_PLACEHOLDER_MAX_LEN`] bytes. Real
/// credentials are never delivered wrapped in brace/angle markers; the
/// dotenv/yaml extractor sometimes preserves the wrapper when the placeholder is
/// the entire RHS. Callers pass an already-trimmed `value` (the raw-credential
/// gate trims first; the base64-decode gate receives pre-trimmed text), so this
/// predicate performs no trimming of its own, the two suppression sites in
/// `decision.rs` that carried byte-identical copies of this check now share this
/// one owner (DEDUP).
pub(crate) fn looks_like_bracketed_template_placeholder(value: &str) -> bool {
    let bracketed = (value.starts_with('{') && value.ends_with('}'))
        || (value.starts_with('<') && value.ends_with('>'))
        || (value.starts_with("${") && value.ends_with('}'));
    bracketed && value.len() <= TEMPLATE_PLACEHOLDER_MAX_LEN
}

/// True when `value` is exactly a bare shell / Make / CI variable reference:
/// `$` followed by one identifier (`$DB_PASSWORD`, `$db_pass_2`). The braced
/// form `${VAR}` is [`looks_like_bracketed_template_placeholder`]'s; this is the
/// unbraced twin, which that predicate cannot see because there is no closing
/// marker to anchor on. A literal credential never begins with `$` followed by
/// nothing but identifier bytes, so no length ceiling is needed here.
pub(crate) fn looks_like_shell_variable_reference(value: &str) -> bool {
    let Some(name) = value.strip_prefix('$') else {
        return false;
    };
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Return true if the credential contains three or more consecutive identical characters.
/// Iterate the maximal runs of identical bytes in `bytes` as `(byte, run_len)`.
/// The single owner of the run-length scan shared by every masking/repetition
/// suppressor below (previously each hand-rolled the same `while` loop).
fn byte_runs(bytes: &[u8]) -> impl Iterator<Item = (u8, usize)> + '_ {
    let mut i = 0;
    std::iter::from_fn(move || {
        let b = *bytes.get(i)?;
        let mut run = 1usize;
        while i + run < bytes.len() && bytes[i + run] == b {
            run += 1;
        }
        i += run;
        Some((b, run))
    })
}

pub(crate) fn has_three_or_more_consecutive_identical(s: &str) -> bool {
    byte_runs(s.as_bytes()).any(|(_, run)| run >= 3)
}

// Mask prefix and sequence run patterns loaded from `rules/mask-sequences.toml`.
crate::tier_b_list::tier_b_vec!(MASK_PREFIXES, "mask-sequences.toml", mask_prefixes);
crate::tier_b_list::tier_b_vec!(MASK_DIGIT_RUNS, "mask-sequences.toml", digit_runs);
crate::tier_b_list::tier_b_vec!(MASK_ALPHA_RUNS, "mask-sequences.toml", alpha_runs);

pub(crate) fn looks_like_prefixed_masked_sequence(body: &str) -> bool {
    // Trailing-ellipsis is an unambiguous placeholder signal: real secrets
    // never end in `...`. UI prompt strings like `ghp_1a2b3c4...` (vscode
    // input-box placeholder) and docs snippets like `sk_live_abcd1234...`
    // are the dominant failure mode. Same for unicode horizontal ellipsis.
    if body.ends_with("...") || body.ends_with('…') {
        return true;
    }
    // Case-insensitive byte scans instead of allocating an uppercased copy of
    // EVERY candidate (Law 7). Mask prefixes and sequence runs are loaded from
    // `rules/mask-sequences.toml` so new mask shapes are a data edit.
    use crate::ascii_ci::{ci_find, starts_with_ignore_ascii_case};
    let bytes = body.as_bytes();
    let starts_with_mask = MASK_PREFIXES
        .iter()
        .any(|p| starts_with_ignore_ascii_case(bytes, p.as_bytes()));
    if !starts_with_mask {
        return false;
    }
    MASK_DIGIT_RUNS
        .iter()
        .any(|run| ci_find(bytes, run.as_bytes()))
        || MASK_ALPHA_RUNS
            .iter()
            .any(|run| ci_find(bytes, run.as_bytes()))
}

pub(crate) fn has_repeated_block_mask(s: &str) -> bool {
    let bytes = s.as_bytes();
    // Three or more long (>=4) alphanumeric runs is the mask signal; `take(3)`
    // preserves the original early-return the moment the third run is seen.
    let long_runs = byte_runs(bytes)
        .filter(|&(b, run)| run >= 4 && b.is_ascii_alphanumeric())
        .take(3)
        .count();
    long_runs >= 3 || has_repeated_full_block(bytes)
}

fn has_repeated_full_block(bytes: &[u8]) -> bool {
    if bytes.len() < 24 || !bytes.iter().any(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    let max_block_len = (bytes.len() / 2).min(64);
    for block_len in 3..=max_block_len {
        let first = &bytes[..block_len];
        if first.iter().all(|b| !b.is_ascii_alphanumeric()) {
            continue;
        }
        // Masks are often truncated while copied, so accept two complete
        // repetitions followed by a prefix of the same block. Requiring every
        // byte after the first block to match its periodic position keeps the
        // predicate exact and allocation-free while catching forms such as
        // `passwordispasswordispassword`.
        if bytes[block_len..]
            .iter()
            .enumerate()
            .all(|(index, byte)| *byte == first[index % block_len])
        {
            return true;
        }
    }
    false
}

pub(crate) fn has_n_or_more_consecutive_identical(s: &str, n: usize) -> bool {
    // Dashes are legitimate delimiters in structured formats (PEM headers,
    // UUIDs, JWT separators). Don't count them as repetitive masking.
    byte_runs(s.as_bytes()).any(|(b, run)| run >= n && b != b'-')
}

/// A value that is one byte repeated (`xxxxxxxx`, `********`, `........`): a
/// mask, never a secret.
///
/// Whole-value by design. The substring twin
/// [`has_n_or_more_consecutive_identical`] cannot condemn a value on its own,
/// because a real secret may carry a short repeated run; requiring the ENTIRE
/// value to be one byte removes that ambiguity. Dashes are excluded for the
/// same reason they are excluded there: they are structural delimiters.
pub(crate) fn is_single_byte_mask(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 4 && bytes[0] != b'-' && bytes.iter().all(|byte| *byte == bytes[0])
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
    // Single pass over dash groups (Law 7: per-candidate suppression predicate,
    // no `Vec`). Tracks group count and the two all-group predicates together.
    let mut group_count = 0usize;
    let mut all_len5_upperdigit = true;
    let mut all_alpha = true;
    for group in value.split('-') {
        if group.is_empty() {
            return false;
        }
        group_count += 1;
        if group.len() != 5
            || !group
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            all_len5_upperdigit = false;
        }
        if !group.bytes().all(|b| b.is_ascii_alphabetic()) {
            all_alpha = false;
        }
    }

    if group_count >= 3 && all_len5_upperdigit {
        return true;
    }

    group_count >= 3 && all_alpha && !randomness.is_random_token(value)
}

#[cfg(test)]
#[path = "../../../tests/unit/suppression_shape_canonical.rs"]
mod tests;
