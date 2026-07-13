//! Canonical non-secret credential body shapes such as digests, UUIDs,
//! serial keys, JWT examples, and mask runs.

pub(crate) const RFC7519_EXAMPLE_JWT_PREFIX: &str =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw";

/// Shannon-entropy (bits/char) threshold separating high-entropy base64 blobs
/// from lower-entropy generic candidates. Single source of truth shared by the
/// two generic-base64 decoy gates: below it a value is treated as a byte-
/// distribution decoy, at/above it a value is instead routed to the ambiguous
/// high-entropy path. The two gates MUST agree on this boundary, they were two
/// byte-identical `4.8` locals before being hoisted here so the split can never
/// silently drift.
///
/// `pub(crate)` so the sibling `decision.rs` repetitive-run / high-entropy-blob
/// gate and `shape::looks_like_high_entropy_punctuation_payload` bind the SAME
/// boundary instead of re-pasting a bare `4.8`: the whole point of a single
/// source of truth is that every gate that pivots on the cutoff moves with it.
pub(crate) const HIGH_ENTROPY_BASE64_CUTOFF: f64 = 4.8;

/// True if `credential` matches the XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
/// dashed-serial / license-key shape: exactly 5 dash-separated
/// blocks, each exactly 5 alphanumeric characters. Microsoft Office,
/// Adobe, Atlassian, JetBrains and many other product-key surfaces
/// use this shape; real credentials almost never do.
pub(crate) fn looks_like_dashed_serial_key(credential: &str) -> bool {
    is_five_by_five_dash_shape(credential, |b| b.is_ascii_alphanumeric())
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
    // ONE UUID-shape owner: entropy generation and report-time suppression bind
    // the SAME uniform-case predicate. A mixed-case UUID must not be a non-secret
    // in one path and a candidate in the other (was: mixed-case hex here vs
    // uniform-case in `is_uuid_v4_shape`) (DEDUP).
    is_uuid_v4_shape(value)
}

/// The four canonical cryptographic hex-digest lengths in HEX CHARS: md5 = 32,
/// sha1 = 40, sha256 = 64, sha512 = 128. Single owner, every shape gate that
/// recognises a fixed-length hex digest consults [`is_canonical_hex_digest_length`]
/// instead of re-listing the four widths inline, so a new digest width (or a
/// correction) is made in exactly ONE place and two gates can never drift.
pub(crate) const CANONICAL_HEX_DIGEST_LENGTHS: [usize; 4] = [32, 40, 64, 128];

/// `true` iff `len` (in hex chars) is one of the [`CANONICAL_HEX_DIGEST_LENGTHS`].
#[inline]
pub(crate) fn is_canonical_hex_digest_length(len: usize) -> bool {
    CANONICAL_HEX_DIGEST_LENGTHS.contains(&len)
}

pub(crate) fn looks_like_entropy_canonical_hex_digest(value: &str) -> bool {
    is_canonical_hex_digest_length(value.len()) && value.bytes().all(|b| b.is_ascii_hexdigit())
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

/// Canonical SRI/package-integrity hash-algo dash labels (`sha512-`, `sha384-`,
/// `sha256-`). ONE owner for the integrity-body gates in this module and the
/// decoded-labelled-hash gate in `decision.rs`, which previously pasted their own
/// (diverging) subsets of this set (DEDUP). Distinct from `strip_hash_algo_prefix`'s
/// broader label set, which also carries the colon forms and `sha1:`/`md5:`.
pub(crate) const HASH_ALGO_INTEGRITY_LABELS: &[&str] = &["sha512-", "sha384-", "sha256-"];

/// Canonical COLON-form hash-algo labels (docker/python/git-LFS hex digests:
/// `sha256:`/`sha512:`/`sha1:`/`md5:`). SINGLE OWNER of this shared vocabulary,
/// consumed BOTH by `strip_hash_algo_prefix` (suppression digest-shape strip)
/// here AND by the entropy assignment-value gate (`entropy::keywords`), which
/// previously hand-rolled a byte-identical copy free to drift. The entropy gate
/// additionally recognizes `git-sha:` (git commit refs), that stays a documented
/// entropy-LOCAL extra, since colon-digest SUPPRESSION intentionally covers only
/// the docker/python/git-LFS digest formats, not commit references.
pub(crate) const HASH_ALGO_COLON_LABELS: &[&[u8]] = &[b"sha256:", b"sha512:", b"sha1:", b"md5:"];

fn looks_like_entropy_integrity_digest(value: &str) -> bool {
    for &prefix in HASH_ALGO_INTEGRITY_LABELS {
        if let Some(body) = value.strip_prefix(prefix) {
            if !body.is_empty() && crate::decode::standard_base64_shape(body).is_some() {
                return true;
            }
        }
    }
    false
}

fn looks_like_entropy_upper_license_serial(value: &str) -> bool {
    is_five_by_five_dash_shape(value, |b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn is_five_by_five_dash_shape(value: &str, body_byte_ok: impl Fn(u8) -> bool) -> bool {
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

/// True for a complete, uniform-case pure-hex value of a canonical service-key
/// length (32 / 40 / 48 / 64). A *service-anchored* detector's regex required
/// its service-specific keyword to match (`ALCHEMY_API_KEY=`, `CROWDIN_API_TOKEN=`,
/// `DATADOG_API_KEY:`), so a capture of this shape is a real key, not a
/// coincidental git-SHA / MD5 / SHA-1 digest sitting next to that exact keyword.
///
/// Callers gate this on [`crate::detector_ids::is_service_anchored_detector`] and
/// pass it as `allow_canonical_hex_key` into [`super::super::decision::suppression_stage_inner`],
/// which exempts the value from the bare-hex-digest and algorithmic-placeholder
/// arms ONLY: every decoy gate (repetitive runs, fake sequences, prefixed-hash
/// labels, UUID, dashed serials) still runs, so explicit placeholder hex
/// (`0000…`, `…ABCDEFGH…`-dominated) is still suppressed. This is the same
/// KH-L-0110 escape hatch the generic bridge applies via
/// [`crate::engine::phase2_generic::is_strong_keyword_anchored_hex_key`], keyed
/// here on the detector's own service anchor rather than a captured keyword.
///
/// The 56/72/128 lengths the bare-hex-digest gate also catches are deliberately
/// excluded: those are SHA-224/384/512 digest lengths that no service detector
/// requests as a key body, so they stay suppressed even under a service anchor.
pub(crate) fn is_canonical_service_hex_key(credential: &str) -> bool {
    matches!(credential.len(), 32 | 40 | 48 | 64) && is_uniform_hex(credential)
}

/// The AWS partitions whose IAM ARNs this suppression recognizes. Single owner
/// for both the full (`arn:<p>:iam::`) and trimmed (`<p>:iam::`) gates, so adding
/// a future partition happens in exactly ONE place instead of two parallel lists.
const AWS_IAM_ARN_PARTITIONS: [&str; 3] = ["aws", "aws-cn", "aws-us-gov"];

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
    AWS_IAM_ARN_PARTITIONS
        .iter()
        .find_map(|&partition| rest.strip_prefix(partition)?.strip_prefix(":iam::"))
}

pub(crate) fn looks_like_aws_iam_arn(value: &str) -> bool {
    strip_aws_iam_arn_body(value, true).is_some_and(aws_iam_arn_body_has_resource_target)
}

pub(crate) fn looks_like_trimmed_aws_iam_arn(value: &str) -> bool {
    strip_aws_iam_arn_body(value, false).is_some_and(aws_iam_arn_body_has_resource_target)
}

fn aws_iam_arn_body_has_resource_target(body: &str) -> bool {
    [
        ":role/",
        ":user/",
        ":group/",
        ":policy/",
        ":instance-profile/",
    ]
    .iter()
    .any(|&target| body.contains(target))
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
/// entropy-generation (`looks_like_entropy_integrity_digest`) / decoded
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
        .copied()
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

pub(crate) fn looks_like_entropy_random_base64_blob_decoy(value: &str) -> bool {
    crate::decode_structure::is_byte_distribution_base64_blob(value, 50, 300)
}

pub(crate) fn looks_like_generic_random_base64_blob_decoy(value: &str, entropy: f64) -> bool {
    if entropy >= HIGH_ENTROPY_BASE64_CUTOFF {
        return false;
    }
    crate::decode_structure::is_byte_distribution_base64_blob(value, 40, 300)
}

pub(crate) fn generic_base64_candidate_is_ambiguous(value: &str, entropy: f64) -> bool {
    const MIN_DISTINCT_ALNUM: u32 = 32;

    if entropy < HIGH_ENTROPY_BASE64_CUTOFF {
        return false;
    }
    let Some(shape) = crate::decode::standard_base64_shape(value) else {
        return false;
    };
    shape.distinct_alnum >= MIN_DISTINCT_ALNUM
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

fn is_uniform_hex(s: &str) -> bool {
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

pub(crate) fn looks_like_prefixed_masked_sequence(body: &str) -> bool {
    // Trailing-ellipsis is an unambiguous placeholder signal: real secrets
    // never end in `...`. UI prompt strings like `ghp_1a2b3c4...` (vscode
    // input-box placeholder) and docs snippets like `sk_live_abcd1234...`
    // are the dominant failure mode. Same for unicode horizontal ellipsis.
    if body.ends_with("...") || body.ends_with('…') {
        return true;
    }
    // Case-insensitive byte scans instead of allocating an uppercased copy of
    // EVERY candidate, this runs per-match in the suppression hot path, where an
    // avoidable allocation is a production bug at scale (Law 7). The same
    // ci_find / starts_with_ignore_ascii_case primitives path_filter uses to
    // dodge this exact `to_ascii_uppercase()` cost. `ci_find` needles MUST be
    // pre-lowercased; "abcdefghij" is subsumed by "abcdefgh" so the redundant
    // longer literal is dropped (the two digit runs stay distinct, different
    // first byte). Semantics are identical to the prior upper-then-contains form.
    use crate::ascii_ci::{ci_find, starts_with_ignore_ascii_case};
    let bytes = body.as_bytes();
    let starts_with_mask = starts_with_ignore_ascii_case(bytes, b"xxx")
        || starts_with_ignore_ascii_case(bytes, b"***");
    if !starts_with_mask {
        return false;
    }
    ci_find(bytes, b"1234567890") || ci_find(bytes, b"0123456789") || ci_find(bytes, b"abcdefgh")
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
    // Dashes are legitimate delimiters in structured formats (PEM headers,
    // UUIDs, JWT separators). Don't count them as repetitive masking.
    byte_runs(s.as_bytes()).any(|(b, run)| run >= n && b != b'-')
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
mod tests {
    use super::HASH_ALGO_INTEGRITY_LABELS;
    use super::TEMPLATE_PLACEHOLDER_MAX_LEN;
    use super::{
        generic_base64_candidate_is_ambiguous, is_dash_segmented_alnum_decoy,
        is_structured_dotted_token, is_uuid_v4_shape, looks_like_aws_iam_arn,
        looks_like_bare_hex_digest, looks_like_base64_integrity_body,
        looks_like_bracketed_template_placeholder, looks_like_dashed_serial_key,
        looks_like_entropy_canonical_non_secret_shape, looks_like_entropy_uuid_shape,
        looks_like_generic_random_base64_blob_decoy, looks_like_prefixed_hash_digest,
        looks_like_prefixed_masked_sequence, looks_like_random_byte_base64_blob,
        looks_like_trimmed_aws_iam_arn, strip_hash_algo_prefix,
    };
    use crate::suppression::decision::decoded_benign_text_reason;
    // Imported separately: rustfmt groups the UPPER_SNAKE const after the
    // lower-snake fn names in a `use` list, so keep it on its own line.
    use super::HIGH_ENTROPY_BASE64_CUTOFF;

    /// A real `sha512-` npm SRI integrity body (proven suppressed by the
    /// `regression_reverse_integrity_decoy_suppression` corpus): standard
    /// base64, `==` padded, length a multiple of four, well over the 40-char
    /// integrity floor.
    const NPM_SRI_BODY: &str =
        "1msyKcoKgxiewdylfpoWNSrFFW3ojqO5LKa5wDu1Ivsn9KJyenY5VvFVFvg3LtJWzI3b3d8GNNngKmP1Zdzpfy==";

    #[test]
    fn prefixed_masked_sequence_matches_mask_plus_fake_run_case_insensitively() {
        // Mask prefix (XXX / *** / xxx) AND a fake ascending run, in any case.
        assert!(looks_like_prefixed_masked_sequence("XXXXX1234567890"));
        assert!(looks_like_prefixed_masked_sequence("xxx_abcdefgh_key"));
        assert!(looks_like_prefixed_masked_sequence("***0123456789zz"));
        // "ABCDEFGHIJ" must still match via the subsuming "abcdefgh" needle.
        assert!(looks_like_prefixed_masked_sequence("XXXabcdefghij"));
        // Uppercase fake run under an uppercase mask (the old to_ascii_uppercase
        // path) must remain a match through the case-insensitive ci_find.
        assert!(looks_like_prefixed_masked_sequence("XXXABCDEFGH"));
    }

    #[test]
    fn prefixed_masked_sequence_matches_trailing_ellipsis() {
        assert!(looks_like_prefixed_masked_sequence("ghp_1a2b3c4..."));
        assert!(looks_like_prefixed_masked_sequence("sk_live_abcd1234…"));
    }

    #[test]
    fn prefixed_masked_sequence_rejects_partial_signals() {
        // Mask prefix but NO fake sequence: not a placeholder.
        assert!(!looks_like_prefixed_masked_sequence("XXXrandomtokenbody"));
        // Fake sequence but NO mask prefix: a real-looking token containing a
        // run must not be suppressed by this gate.
        assert!(!looks_like_prefixed_masked_sequence("1234567890realbody"));
        assert!(!looks_like_prefixed_masked_sequence("abcdefghkey"));
        // Empty / short bodies.
        assert!(!looks_like_prefixed_masked_sequence(""));
        assert!(!looks_like_prefixed_masked_sequence("xx"));
    }

    #[test]
    fn structured_dotted_token_accepts_jwt_like_shape() {
        assert!(is_structured_dotted_token(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ));
    }

    #[test]
    fn structured_dotted_token_accepts_discord_style_shape() {
        assert!(is_structured_dotted_token(
            "MTIzNDU2Nzg5MDEyMzQ1Njc4.Oabc12.xYz0123456789abcDEFghijk_lmnop"
        ));
    }

    #[test]
    fn structured_dotted_token_rejects_property_chains() {
        assert!(!is_structured_dotted_token("this.someService.copilotToken"));
        assert!(!is_structured_dotted_token("example.com"));
        assert!(!is_structured_dotted_token("alpha.beta.gamma.delta"));
    }

    #[test]
    fn dashed_serial_key_accepts_exact_five_by_five_shape() {
        assert!(looks_like_dashed_serial_key(
            "JQQJN-VBWHG-XBC8R-2MV9F-CD7P9"
        ));
        assert!(looks_like_dashed_serial_key(
            "jqqjn-vbwhg-xbc8r-2mv9f-cd7p9"
        ));
    }

    #[test]
    fn dashed_serial_key_rejects_broken_boundaries() {
        for value in [
            "JQQJN-VBWHG-XBC8R-2MV9F-CD7P",
            "JQQJN-VBWHG-XBC8R-2MV9F-CD7P99",
            "JQQJN--VBWHG-XBC8R-2MV9F-CD7P",
            "JQQJN_VBWHG-XBC8R-2MV9F-CD7P9",
            "JQQJN-VBWHG-XBC8R-2MV9F-CD7P!",
        ] {
            assert!(
                !looks_like_dashed_serial_key(value),
                "broken 5x5 serial boundary must not suppress: {value}"
            );
        }
    }

    #[test]
    fn entropy_license_serial_remains_uppercase_only() {
        assert!(looks_like_entropy_canonical_non_secret_shape(
            "JQQJN-VBWHG-XBC8R-2MV9F-CD7P9"
        ));
        assert!(
            !looks_like_entropy_canonical_non_secret_shape("jqqjn-vbwhg-xbc8r-2mv9f-cd7p9"),
            "entropy generation intentionally keeps lowercase dashed keys outside the canonical serial decoy set"
        );
    }

    #[test]
    fn random_byte_base64_blob_accepts_pure_alnum_decoy() {
        assert!(looks_like_random_byte_base64_blob(
            "VqsjpzT2Jauz6vo76xb5vNB8XXxfBTQyNX6G5Kx1AEEk"
        ));
    }

    #[test]
    fn random_byte_base64_blob_rejects_slash_bearing_token() {
        assert!(!looks_like_random_byte_base64_blob(
            "PvgsQdw6b5r9JqFzmaVkh/PBOtxkvFtq3OLNhcdqlOcoSqgnQx"
        ));
    }

    #[test]
    fn random_byte_base64_blob_rejects_urlsafe_token_shape() {
        assert!(!looks_like_random_byte_base64_blob(
            "ghp_0123456789abcdefghijklmnopqrstuvwxyzABCDEF"
        ));
    }

    #[test]
    fn aws_iam_arn_accepts_full_and_trimmed_resource_identifiers() {
        assert!(looks_like_aws_iam_arn(
            "arn:aws:iam::123456789012:role/ReadOnly"
        ));
        assert!(looks_like_aws_iam_arn(
            "arn:aws-us-gov:iam::123456789012:instance-profile/Worker"
        ));
        assert!(looks_like_trimmed_aws_iam_arn(
            "aws-cn:iam::123456789012:user/alice"
        ));
    }

    #[test]
    fn aws_iam_arn_rejects_non_iam_secret_references() {
        assert!(!looks_like_aws_iam_arn(
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db"
        ));
        assert!(!looks_like_aws_iam_arn(
            "arn:aws:iam::123456789012:server-certificate/cert"
        ));
        assert!(!looks_like_trimmed_aws_iam_arn(
            "arn:aws:iam::123456789012:role/ReadOnly"
        ));
    }

    // ---- strip_hash_algo_prefix: the case-insensitive label strip ----

    #[test]
    fn strip_hash_algo_prefix_strips_lowercase_sha256() {
        assert_eq!(strip_hash_algo_prefix("sha256:deadbeef"), Some("deadbeef"));
    }

    #[test]
    fn strip_hash_algo_prefix_strips_uppercase_sha256() {
        // ssh-keygen -lf renders `SHA256:<base64>`; certutil emits upper-case.
        // The lower-case-only match used to leak these back out.
        assert_eq!(strip_hash_algo_prefix("SHA256:deadbeef"), Some("deadbeef"));
    }

    #[test]
    fn strip_hash_algo_prefix_strips_mixed_case_sha256() {
        assert_eq!(strip_hash_algo_prefix("Sha256:body"), Some("body"));
        assert_eq!(strip_hash_algo_prefix("sHa256:body"), Some("body"));
    }

    #[test]
    fn strip_hash_algo_prefix_strips_embedded_lowercase_docker_digest() {
        // Value extractor surfaces `nginx@sha256:<hex>` as one string that does
        // NOT start with the algo label - substring match is intentional.
        assert_eq!(
            strip_hash_algo_prefix("nginx@sha256:cafebabe"),
            Some("cafebabe")
        );
    }

    #[test]
    fn strip_hash_algo_prefix_strips_embedded_uppercase_digest() {
        assert_eq!(
            strip_hash_algo_prefix("nginx@SHA256:cafebabe"),
            Some("cafebabe")
        );
    }

    #[test]
    fn strip_hash_algo_prefix_strips_sha512_dash_both_cases() {
        assert_eq!(strip_hash_algo_prefix("sha512-Zm9vYmFy"), Some("Zm9vYmFy"));
        assert_eq!(strip_hash_algo_prefix("SHA512-Zm9vYmFy"), Some("Zm9vYmFy"));
    }

    #[test]
    fn strip_hash_algo_prefix_strips_sha256_dash_both_cases() {
        assert_eq!(strip_hash_algo_prefix("sha256-Zm9v"), Some("Zm9v"));
        assert_eq!(strip_hash_algo_prefix("SHA256-Zm9v"), Some("Zm9v"));
    }

    #[test]
    fn strip_hash_algo_prefix_strips_sha1_both_cases() {
        assert_eq!(strip_hash_algo_prefix("sha1:0badf00d"), Some("0badf00d"));
        assert_eq!(strip_hash_algo_prefix("SHA1:0badf00d"), Some("0badf00d"));
    }

    #[test]
    fn strip_hash_algo_prefix_strips_md5_both_cases() {
        assert_eq!(strip_hash_algo_prefix("md5:abcd"), Some("abcd"));
        assert_eq!(strip_hash_algo_prefix("MD5:abcd"), Some("abcd"));
    }

    #[test]
    fn strip_hash_algo_prefix_returns_none_without_label() {
        assert_eq!(strip_hash_algo_prefix("randomtokenbody"), None);
        // `sha:` is NOT a label (bare algo family, no `256`/`512`/`384` digits).
        assert_eq!(strip_hash_algo_prefix("sha:foo"), None);
        // `sha224-` is deliberately absent from the SRI owner set too.
        assert_eq!(strip_hash_algo_prefix("sha224-foo"), None);
    }

    #[test]
    fn strip_hash_algo_prefix_strips_sha384_dash_both_cases() {
        // THE FIX: `sha384-` is the recommended SRI algorithm and lives in the
        // ONE owner `HASH_ALGO_INTEGRITY_LABELS`; the report-time strip now binds
        // that owner instead of a diverging {sha512-,sha256-} subset that dropped
        // it. Previously this returned None and leaked sha384 SRI at report time.
        assert_eq!(strip_hash_algo_prefix("sha384-Zm9vYmFy"), Some("Zm9vYmFy"));
        assert_eq!(strip_hash_algo_prefix("SHA384-Zm9vYmFy"), Some("Zm9vYmFy"));
    }

    #[test]
    fn strip_hash_algo_prefix_first_label_in_array_order_wins() {
        // LABELS are scanned in array order (sha256: before md5:), so the
        // earlier-in-array label wins even when it appears later in the string.
        assert_eq!(strip_hash_algo_prefix("md5:AAAA sha256:BBBB"), Some("BBBB"));
    }

    #[test]
    fn strip_hash_algo_prefix_empty_body() {
        assert_eq!(strip_hash_algo_prefix("sha256:"), Some(""));
        assert_eq!(strip_hash_algo_prefix("SHA256:"), Some(""));
    }

    #[test]
    fn strip_hash_algo_prefix_multibyte_body_does_not_panic() {
        // The label is ASCII so the slice boundary is codepoint-safe even when
        // the body tail is multibyte UTF-8.
        assert_eq!(strip_hash_algo_prefix("sha256:café☕"), Some("café☕"));
        assert_eq!(strip_hash_algo_prefix("SHA256:café☕"), Some("café☕"));
    }

    #[test]
    fn strip_hash_algo_prefix_ssh_keygen_fingerprint_line() {
        // `ssh-keygen -lf key.pub` output: "256 SHA256:<base64> user@host".
        assert_eq!(
            strip_hash_algo_prefix("256 SHA256:abcDEF012+/ghi comment"),
            Some("abcDEF012+/ghi comment")
        );
    }

    // ---- looks_like_prefixed_hash_digest: end-to-end suppression contract ----

    #[test]
    fn prefixed_hash_digest_lowercase_docker_64hex_true() {
        let v = format!("sha256:{}", "a".repeat(64));
        assert!(looks_like_prefixed_hash_digest(&v));
    }

    #[test]
    fn prefixed_hash_digest_uppercase_label_64hex_true() {
        // THE FIX end-to-end: upper-case label + lower-case 64-hex body.
        let v = format!("SHA256:{}", "a".repeat(64));
        assert!(looks_like_prefixed_hash_digest(&v));
    }

    #[test]
    fn prefixed_hash_digest_uppercase_label_uppercase_hex_certutil_true() {
        // Windows certutil emits `SHA256` + UPPER-case hex; is_uniform_hex
        // accepts uniform upper-case, so the whole thing suppresses.
        let v = format!("SHA256:{}", "A".repeat(64));
        assert!(looks_like_prefixed_hash_digest(&v));
    }

    #[test]
    fn prefixed_hash_digest_sha512_128hex_both_cases_true() {
        assert!(looks_like_prefixed_hash_digest(&format!(
            "sha512:{}",
            "b".repeat(128)
        )));
        assert!(looks_like_prefixed_hash_digest(&format!(
            "SHA512:{}",
            "B".repeat(128)
        )));
    }

    #[test]
    fn prefixed_hash_digest_sha1_40hex_both_cases_true() {
        assert!(looks_like_prefixed_hash_digest(&format!(
            "sha1:{}",
            "c".repeat(40)
        )));
        assert!(looks_like_prefixed_hash_digest(&format!(
            "SHA1:{}",
            "c".repeat(40)
        )));
    }

    #[test]
    fn prefixed_hash_digest_npm_integrity_base64_both_cases_true() {
        assert!(looks_like_prefixed_hash_digest(&format!(
            "sha512-{NPM_SRI_BODY}"
        )));
        assert!(looks_like_prefixed_hash_digest(&format!(
            "SHA512-{NPM_SRI_BODY}"
        )));
    }

    #[test]
    fn prefixed_hash_digest_short_body_below_base64_floor_false() {
        // Bodies shorter than the 40-char base64-integrity floor that are also
        // not a {32,40,64,128}-length hex digest are not suppressed by this shape.
        assert!(!looks_like_prefixed_hash_digest(&format!(
            "sha256:{}",
            "a".repeat(30)
        )));
    }

    #[test]
    fn prefixed_hash_digest_md5_32hex_both_cases_true() {
        // `md5:`/`sha1:` are in the label set; the 32-hex md5 body must suppress
        // (previously omitted from the body-length set, leaking `md5:<32hex>`).
        assert!(looks_like_prefixed_hash_digest(&format!(
            "md5:{}",
            "a".repeat(32)
        )));
        assert!(looks_like_prefixed_hash_digest(&format!(
            "MD5:{}",
            "A".repeat(32)
        )));
        // Embedded form the value extractor surfaces (`file@md5:<hex>`).
        assert!(looks_like_prefixed_hash_digest(&format!(
            "blob@md5:{}",
            "d".repeat(32)
        )));
        // A 31-hex body is not a digest length and below the base64 floor.
        assert!(!looks_like_prefixed_hash_digest(&format!(
            "md5:{}",
            "a".repeat(31)
        )));
    }

    #[test]
    fn prefixed_hash_digest_non_base64_char_body_false() {
        // A 40-char body clears the integrity floor, but a non-base64 byte
        // ('!') makes it neither a hex digest nor a valid base64 integrity blob,
        // so the broad base64 arm cannot suppress it either.
        let v = format!("sha256:{}!", "z".repeat(39));
        assert!(!looks_like_prefixed_hash_digest(&v));
    }

    #[test]
    fn prefixed_hash_digest_unpadded_remainder_one_body_false() {
        // A 41-char unpadded body has length % 4 == 1, which standard base64
        // never produces, so it is not a valid integrity blob (and 41 is not a
        // hex digest length). Pins the base64-shape boundary of the caller.
        let v = format!("sha256:{}", "a".repeat(41));
        assert!(!looks_like_prefixed_hash_digest(&v));
    }

    #[test]
    fn prefixed_hash_digest_requires_the_label() {
        // A bare 64-hex value with NO algo label is NOT this shape (the
        // ambiguous bare-hex arm handles it, anchor-gated).
        assert!(!looks_like_prefixed_hash_digest(&"a".repeat(64)));
    }

    // ---- looks_like_bracketed_template_placeholder: single-owner brace/angle gate ----

    #[test]
    fn bracketed_template_placeholder_matches_brace_angle_and_dollar_forms() {
        assert!(looks_like_bracketed_template_placeholder("{placeholder}"));
        assert!(looks_like_bracketed_template_placeholder(
            "<your-token-here>"
        ));
        assert!(looks_like_bracketed_template_placeholder("${SECRET_TOKEN}"));
    }

    #[test]
    fn bracketed_template_placeholder_rejects_unwrapped_and_overlong() {
        // No wrapping markers: a real token must not be suppressed.
        assert!(!looks_like_bracketed_template_placeholder(
            "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
        ));
        // Opening marker without the matching close.
        assert!(!looks_like_bracketed_template_placeholder("{unterminated"));
        // Exactly at the length ceiling is accepted; one over is rejected.
        let at_cap = format!("{{{}}}", "a".repeat(TEMPLATE_PLACEHOLDER_MAX_LEN - 2));
        assert_eq!(at_cap.len(), TEMPLATE_PLACEHOLDER_MAX_LEN);
        assert!(looks_like_bracketed_template_placeholder(&at_cap));
        let over_cap = format!("{{{}}}", "a".repeat(TEMPLATE_PLACEHOLDER_MAX_LEN - 1));
        assert_eq!(over_cap.len(), TEMPLATE_PLACEHOLDER_MAX_LEN + 1);
        assert!(!looks_like_bracketed_template_placeholder(&over_cap));
    }

    // ---- HIGH_ENTROPY_BASE64_CUTOFF: single-owner shared entropy boundary ----

    #[test]
    fn high_entropy_base64_cutoff_value_is_locked() {
        // The two generic-base64 decoy gates below share this exact bits/char
        // boundary; both were byte-identical `4.8` locals before being hoisted
        // to this one module-level const.
        assert_eq!(HIGH_ENTROPY_BASE64_CUTOFF, 4.8);
    }

    #[test]
    fn both_generic_base64_gates_pivot_on_the_shared_cutoff() {
        // 40-char standard-base64 value engineered to clear BOTH gates'
        // downstream shape checks at once: length in the [40, 300] band, both
        // `+` and `/` present, length a multiple of four, and 38 distinct
        // alphanumeric chars (>= the 32-char diversity floor). Because every
        // structural predicate is satisfied, the ONLY thing that decides each
        // gate's verdict here is the entropy comparison against the shared
        // HIGH_ENTROPY_BASE64_CUTOFF.
        let value = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL+/";
        assert_eq!(value.len(), 40);

        let just_below = HIGH_ENTROPY_BASE64_CUTOFF - 0.1;

        // Below the cutoff: the decoy gate fires (low-entropy byte-distribution
        // blob), the ambiguous gate does NOT (too low to be an ambiguous
        // high-entropy candidate).
        assert!(looks_like_generic_random_base64_blob_decoy(
            value, just_below
        ));
        assert!(!generic_base64_candidate_is_ambiguous(value, just_below));

        // Exactly AT the shared cutoff both flip in lockstep: the decoy gate
        // stops firing (`entropy >= cutoff` short-circuits to false) and the
        // ambiguous gate starts firing (`entropy >= cutoff` proceeds to the
        // shape/diversity check, which passes). Their agreement at this single
        // numeric boundary is what proves both read the same const.
        assert!(!looks_like_generic_random_base64_blob_decoy(
            value,
            HIGH_ENTROPY_BASE64_CUTOFF
        ));
        assert!(generic_base64_candidate_is_ambiguous(
            value,
            HIGH_ENTROPY_BASE64_CUTOFF
        ));
    }

    /// Single-pass rewrite of the dash-group scan must preserve both decoy
    /// arms and the empty-group rejection.
    #[test]
    fn dash_segmented_alnum_decoy_arms_preserved() {
        // Fixed-width upper/digit serial (>=3 groups, each exactly 5).
        assert!(is_dash_segmented_alnum_decoy("ABCDE-12345-FG7HI"));
        // Multi-part all-alpha, non-random identifier.
        assert!(is_dash_segmented_alnum_decoy("alpha-beta-gamma"));
        // Empty group (`foo--bar`) rejects regardless of the arms.
        assert!(!is_dash_segmented_alnum_decoy("ABCDE--12345"));
        // No dash → not a dash-segmented shape.
        assert!(!is_dash_segmented_alnum_decoy("ABCDE12345FG7HI"));
    }

    // ---- sha384 SRI: ONE label owner, suppressed via BOTH entry points ----

    #[test]
    fn sha384_sri_suppressed_via_both_report_time_and_entropy_entry_points() {
        // A `sha384-<base64 integrity body>` value. Before the strip/owner
        // unification, the report-time `looks_like_prefixed_hash_digest` entry
        // point dropped `sha384-` (its dash-label subset diverged from the SRI
        // owner) and LEAKED this back out as a false positive, while the
        // entropy-generation entry point suppressed it, a same-set/different-
        // value split. Both must now agree.
        let lower = format!("sha384-{NPM_SRI_BODY}");
        let upper = format!("SHA384-{NPM_SRI_BODY}");

        // Entry point 1: report-time bare-value suppression.
        assert!(
            looks_like_prefixed_hash_digest(&lower),
            "sha384 SRI must suppress at report time (the leak this fix closes)"
        );
        assert!(
            looks_like_prefixed_hash_digest(&upper),
            "case-insensitive SHA384 label must also suppress at report time"
        );

        // Entry point 2: entropy-generation canonical-non-secret gate.
        assert!(
            looks_like_entropy_canonical_non_secret_shape(&lower),
            "sha384 SRI must stay a canonical non-secret at entropy generation"
        );

        // The label owner really does carry sha384- (guards against a future
        // edit silently dropping it from the ONE owner again).
        assert!(HASH_ALGO_INTEGRITY_LABELS.contains(&"sha384-"));
    }

    #[test]
    fn base64_integrity_body_floor_is_exactly_forty_for_both_gates() {
        // The 40-char floor both integrity gates bind through the single owner
        // `looks_like_base64_integrity_body`. Use pad-free slices of a valid
        // base64 body so ONLY the length floor, not the base64 %4 shape rule 
        // decides: 36 chars is a valid base64 shape (36 % 4 == 0) yet below the
        // floor, 40 chars clears it.
        let under_floor = &NPM_SRI_BODY[..36];
        let at_floor = &NPM_SRI_BODY[..40];
        assert_eq!(
            under_floor.len() % 4,
            0,
            "isolate the floor, not the %4 rule"
        );
        assert!(
            !looks_like_base64_integrity_body(under_floor),
            "a valid-shaped 36-char base64 body is below the 40-char integrity floor"
        );
        assert!(
            looks_like_base64_integrity_body(at_floor),
            "exactly 40 chars clears the integrity floor"
        );
    }

    // ---- decoded hash digest: the decoded path binds the SAME length owner ----

    #[test]
    fn decoded_bare_hex_digest_owner_covers_md5_and_sha1_lengths() {
        // `looks_like_bare_hex_digest` is the ONE length owner the base64-decoded
        // suppression path (`decision::decoded_benign_text_reason`) delegates to.
        // The decoded path previously used a divergent {56,64,72,128} set that
        // DROPPED md5 (32) and sha1 (40), leaking base64-wrapped digests. The
        // owner must cover the full set both paths bind.
        for len in [32usize, 40, 48, 56, 64, 72, 128] {
            assert!(
                looks_like_bare_hex_digest(&"a".repeat(len)),
                "{len}-hex is a bare digest length in the unified owner set"
            );
        }
        // Boundary twins just outside the set are NOT digests.
        for len in [31usize, 33, 41, 47, 127] {
            assert!(
                !looks_like_bare_hex_digest(&"a".repeat(len)),
                "{len}-hex is outside the unified digest length set"
            );
        }
    }

    #[test]
    fn decoded_md5_and_sha1_are_suppressed_end_to_end() {
        // base64("d41d8cd98f00b204e9800998ecf8427e"), the empty-string md5, a
        // 32-hex digest. The decoded path must strip the base64 wrapper and
        // suppress it as a bare hash digest (md5 32-hex was the leaking length).
        assert_eq!(
            decoded_benign_text_reason("ZDQxZDhjZDk4ZjAwYjIwNGU5ODAwOTk4ZWNmODQyN2U="),
            Some("decoded_bare_hash_digest"),
            "base64-wrapped md5 (32-hex) must suppress via the decoded digest arm"
        );
        // base64("da39a3ee5e6b4b0d3255bfef95601890afd80709"), empty-string sha1,
        // a 40-hex digest (the other length the old decoded set dropped).
        assert_eq!(
            decoded_benign_text_reason("ZGEzOWEzZWU1ZTZiNGIwZDMyNTViZmVmOTU2MDE4OTBhZmQ4MDcwOQ=="),
            Some("decoded_bare_hash_digest"),
            "base64-wrapped sha1 (40-hex) must suppress via the decoded digest arm"
        );
        // Negative twin: base64 of a 39-hex string. 39 is OUTSIDE the unified
        // digest length set, so the digest arm provably cannot fire, a real hex
        // token of a non-digest length must not be swallowed by this arm.
        assert_ne!(
            decoded_benign_text_reason("M2Y4YTFjOWUyYjdkNDA1MTZhOGMzZTlmMWIyZDRhNmM4ZTBmMWEy"),
            Some("decoded_bare_hash_digest"),
            "a 39-hex decoded value is not a digest length and must not suppress here"
        );
    }

    // ---- UUID shape: ONE case-uniform owner shared by both callers ----

    #[test]
    fn uuid_shape_owner_agrees_on_case_across_both_callers() {
        // `looks_like_entropy_uuid_shape` delegates to `is_uuid_v4_shape`, so the
        // two must return byte-identical verdicts for EVERY input, a mixed-case
        // UUID must never be a non-secret in one path and a live candidate in the
        // other (the divergence this unification closed).
        let uniform_lower = "a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
        let uniform_upper = "A1B2C3D4-5E6F-4A7B-8C9D-0E1F2A3B4C5D";
        let evil_mixed = "a1b2c3d4-5e6f-4a7b-8C9d-0e1f2a3b4c5d";

        for value in [uniform_lower, uniform_upper, evil_mixed] {
            assert_eq!(
                is_uuid_v4_shape(value),
                looks_like_entropy_uuid_shape(value),
                "both UUID callers must agree on {value:?} (one owner)"
            );
        }

        // Uniform-case UUIDs ARE the canonical non-secret shape.
        assert!(is_uuid_v4_shape(uniform_lower));
        assert!(is_uuid_v4_shape(uniform_upper));
        // Evil mixed-case UUID is rejected by BOTH (real digests/UUIDs are never
        // emitted MiXeD-case), so it is not silently treated as a non-secret.
        assert!(!is_uuid_v4_shape(evil_mixed));
        assert!(!looks_like_entropy_uuid_shape(evil_mixed));
    }
}
