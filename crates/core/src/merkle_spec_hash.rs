//! Detector-spec hash digest for merkle cache invalidation.

use crate::spec::{CompanionSpec, DetectorKind, DetectorSpec, PatternSpec};

/// Compute a stable BLAKE3 digest over the canonical detector set so a
/// later scan can detect that detectors changed.
pub fn compute_spec_hash(detectors: &[DetectorSpec]) -> [u8; 32] {
    let mut keys: Vec<String> = detectors
        .iter()
        .flat_map(|d| {
            assert_scan_hash_field_inventory_is_exhaustive(d);
            let mut entries =
                Vec::with_capacity(2 + d.patterns.len() + d.companions.len() + d.keywords.len());
            entries.push(format!("id:{}", d.id));
            // Bind severity to the detector id: an un-bound `sev:{severity}` key
            // makes swapping severities between two detectors produce the same
            // sorted multiset (identical digest), so the merkle cache would keep
            // a stale skip after severity, and severity-threshold suppression
            // changed (Law 10 silent staleness).
            entries.push(format!("sev:{}:{:?}", d.id, d.severity));
            for (index, p) in d.patterns.iter().enumerate() {
                assert_pattern_hash_field_inventory_is_exhaustive(p);
                let mut pattern_entry = format!(
                    // `cs:` folds `client_safe` in: toggling it downgrades every
                    // match of this pattern to `Severity::ClientSafe` (gated by
                    // `--hide-client-safe`), a material output change that must
                    // invalidate the cache.
                    "p:{}:{}:{}|g:{}|cs:{}",
                    d.id,
                    index,
                    p.regex,
                    p.group.map(|g| g.to_string()).unwrap_or_default(), // LAW10: missing/non-string field => empty/placeholder; recall-safe
                    p.client_safe
                );
                if p.weak_anchor {
                    pattern_entry.push_str("|wa:true");
                }
                entries.push(pattern_entry);
                for (literal_index, literal) in p.required_literals.iter().enumerate() {
                    entries.push(format!(
                        "required-literal-hex:{}:{}:{}:{}",
                        d.id,
                        index,
                        literal_index,
                        crate::hex_encode(literal.as_bytes())
                    ));
                }
            }
            for (index, c) in d.companions.iter().enumerate() {
                assert_companion_hash_field_inventory_is_exhaustive(c);
                entries.push(format!(
                    "c:{}:{}:{}|{}|w:{}|r:{}",
                    d.id, index, c.name, c.regex, c.within_lines, c.required
                ));
            }
            let mut kws: Vec<&String> = d.keywords.iter().collect();
            kws.sort();
            for k in kws {
                entries.push(format!("kw:{}:{}", d.id, k));
            }
            // ── Per-detector recall/precision knobs (migration 2026-07-07) ──────
            // Each field below OVERRIDES a scan-match/suppress decision, so a
            // change to any of them changes WHICH findings a scan emits, the
            // exact staleness the merkle cache must notice before it trusts a
            // "skip this file" (Law 10 silent staleness, the same class as the
            // severity/`client_safe` keys above). Each key is emitted ONLY when
            // its field is NON-DEFAULT, so a detector that sets none of them
            // contributes zero extra bytes and the bare-detector pre-image
            // (`id:..\nsev:..\n`, pinned by `spec_hash_of_bare_detector_matches_
            // hand_fed_blake3`) is preserved. Every key is id-bound (like `kw:`/
            // `p:`) so moving a value between two detectors is not a collision.
            // Each `f64` is hashed by its exact IEEE-754 bits (`to_bits` →
            // `{:016x}`), never a lossy decimal render, so two distinct floors
            // never collide and `-0.0`/`0.0` stay distinguishable.
            //
            // `service` is report identity. Bind it to the id so a service swap
            // cannot reuse cached findings carrying stale public metadata. It
            // does not select detector execution policy.
            if !d.service.is_empty() {
                entries.push(format!("service:{}:{}", d.id, d.service));
            }
            // DELIBERATELY EXCLUDED (like the cosmetic `name` and
            // `PatternSpec.description`, whose exclusion `spec_hash_ignores_
            // cosmetic_name_field` pins): `verify` (live-verification config
            // changing it alters a finding's post-scan verdict, not the scanned
            // finding SET/severity/suppression the merkle cache reuses) and
            // `tests` (self-test fixtures, ignored at scan time). Hashing either
            // would thrash the cache into a full re-scan on a change that cannot
            // alter scan output.
            if d.kind != DetectorKind::default() {
                entries.push(format!("kind:{}:{:?}", d.id, d.kind));
            }
            if let Some(mc) = d.min_confidence {
                entries.push(format!("mc:{}:{:016x}", d.id, mc.to_bits()));
            }
            for (i, b) in d.entropy_floor.iter().enumerate() {
                // Bucket order is SEMANTIC (consulted in listed order, with
                // strictly-increasing `max_len`), so bind the index: a reordered
                // floor table is a different gate and must change the digest.
                entries.push(format!(
                    "ef:{}:{}:{}:{:016x}",
                    d.id,
                    i,
                    b.max_len.map_or_else(String::new, |m| m.to_string()),
                    b.floor.to_bits()
                ));
            }
            if let Some(v) = d.entropy_high {
                entries.push(format!("eh:{}:{:016x}", d.id, v.to_bits()));
            }
            if let Some(v) = d.entropy_low {
                entries.push(format!("el:{}:{:016x}", d.id, v.to_bits()));
            }
            if let Some(v) = d.entropy_very_high {
                entries.push(format!("evh:{}:{:016x}", d.id, v.to_bits()));
            }
            if let Some(metadata) = &d.entropy_fallback {
                entries.push(format!(
                    "entropy-fallback:{}:{}:{}:{}:{}",
                    d.id,
                    metadata.class.as_str(),
                    metadata.id,
                    metadata.name,
                    metadata.service
                ));
            }
            if let Some(confidence) = d.entropy_fallback_confidence {
                entries.push(format!(
                    "entropy-fallback-confidence:{}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}",
                    d.id,
                    confidence.low_entropy_max.to_bits(),
                    confidence.high_entropy.to_bits(),
                    confidence.very_high_entropy.to_bits(),
                    confidence.keyword_lift.to_bits(),
                    confidence.max_confidence.to_bits(),
                ));
            }
            if let Some(confidence) = d.generic_assignment_confidence {
                entries.push(format!(
                    "generic-assignment-confidence:{}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{}:{:016x}:{:016x}:{:016x}",
                    d.id,
                    confidence.ordinary_base.to_bits(),
                    confidence.test_base.to_bits(),
                    confidence.documentation_base.to_bits(),
                    confidence.comment_base.to_bits(),
                    confidence.scanned_comment_base.to_bits(),
                    confidence.entropy_reference.to_bits(),
                    confidence.entropy_gain_per_bit.to_bits(),
                    confidence.entropy_lift_max.to_bits(),
                    confidence.length_reference,
                    confidence.length_gain_per_byte.to_bits(),
                    confidence.length_lift_max.to_bits(),
                    confidence.max_confidence.to_bits(),
                ));
            }
            let mut entropy_roles: Vec<&str> =
                d.entropy_roles.iter().map(|role| role.as_str()).collect();
            entropy_roles.sort_unstable();
            for role in entropy_roles {
                entries.push(format!("entropy-role:{}:{}", d.id, role));
            }
            if let Some(v) = d.sensitive_path_entropy_very_high {
                entries.push(format!("spevh:{}:{:016x}", d.id, v.to_bits()));
            }
            for (index, shape) in d.entropy_shapes.iter().enumerate() {
                let charset = match shape.charset {
                    crate::ShapeCharset::LowerAlnum => "lower-alnum",
                    crate::ShapeCharset::Hex => "hex",
                    crate::ShapeCharset::Base64Standard => "base64-standard",
                    crate::ShapeCharset::Base64Url => "base64-url",
                };
                let grouping = shape.grouping.map_or_else(
                    || "none".to_string(),
                    |g| {
                        format!(
                            "{}:{}:{:x}",
                            g.group_count, g.group_length, g.separator as u32
                        )
                    },
                );
                entries.push(format!(
                    "entropy-shape:{}:{}:{}:{:016x}:{}:{}:{}:{}:{}:{}:{}",
                    d.id,
                    index,
                    charset,
                    shape.entropy_floor.to_bits(),
                    shape.special_min_length,
                    grouping,
                    shape.require_mixed_case,
                    shape.require_digit,
                    shape.min_symbols,
                    shape.require_non_hex_alpha,
                    shape.require_group_alpha_digit,
                ));
            }
            if let Some(policy) = d.plausibility {
                entries.push(format!(
                    "plausibility:{}:{:016x}:{:016x}:{:016x}:{}:{:016x}:{}:{}:{}:{}:{:016x}:{:016x}:{}:{}:{}:{}:{}:{:016x}:{}:{}:{}:{}:{}",
                    d.id,
                    policy.mixed_alnum_floor.to_bits(),
                    policy.symbolic_entropy_floor.to_bits(),
                    policy.second_half_entropy_floor.to_bits(),
                    policy.mixed_alnum_min_len,
                    policy.isolated_mixed_entropy_floor.to_bits(),
                    policy.isolated_symbolic_min_len,
                    policy.isolated_symbolic_min_symbols,
                    policy.isolated_symbolic_requires_non_underscore,
                    policy.isolated_alpha_only_min_symbols,
                    policy.isolated_alpha_only_min_alpha_ratio.to_bits(),
                    policy.min_alnum_ratio.to_bits(),
                    policy.source_type_name_max_len,
                    policy.source_type_name_min_uppercase,
                    policy.url_path_high_entropy_min_len,
                    policy.isolated_colon_left_min_len,
                    policy.isolated_colon_right_min_len,
                    policy.leading_slash_base64_entropy_floor.to_bits(),
                    policy.reject_repeated_blocks,
                    policy.allow_alphabetic_credential,
                    policy.reject_program_identifiers,
                    policy.reject_source_symbol_identifiers,
                    policy.reject_dash_segmented_alnum,
                ));
                if let Some(margin) = policy.keyword_free_operator_margin {
                    entries.push(format!(
                        "keyword-free-operator-margin:{}:{:016x}",
                        d.id,
                        margin.to_bits()
                    ));
                }
                entries.push(format!(
                    "plausibility-shape:{}:{}:{}:{}:{}:{}:{}:{}",
                    d.id,
                    policy.second_half_min_len,
                    policy.unique_chars_min_len,
                    policy.min_unique_chars,
                    policy.unanchored_hex_max_len,
                    policy.identical_char_max_len,
                    policy.structured_dotted_min_len,
                    policy.leading_slash_base64_min_len,
                ));
            }
            if let Some(v) = d.entropy_policy_priority {
                entries.push(format!("entropy-policy-priority:{}:{v}", d.id));
            }
            if let Some(v) = d.bpe_max_bytes_per_token {
                entries.push(format!("bpe:{}:{:016x}", d.id, v.to_bits()));
            }
            if let Some(v) = d.bpe_enabled {
                entries.push(format!("bpe-enabled:{}:{v}", d.id));
            }
            for (length_index, length) in d.decoded_hex_key_material_lengths.iter().enumerate() {
                entries.push(format!(
                    "decoded-hex-key-material-length:{}:{length_index}:{length}",
                    d.id
                ));
            }
            for (prefix_index, prefix) in d
                .decode_transforms
                .reverse_prefixes
                .iter()
                .enumerate()
            {
                entries.push(format!(
                    "decode-reverse-prefix:{}:{prefix_index}:{prefix}",
                    d.id
                ));
            }
            for (prefix_index, prefix) in d
                .decode_transforms
                .caesar_prefixes
                .iter()
                .enumerate()
            {
                entries.push(format!(
                    "decode-caesar-prefix:{}:{prefix_index}:{prefix}",
                    d.id
                ));
            }
            for (policy_index, policy) in d.canonical_hex_key_material.iter().enumerate() {
                for (length_index, length) in policy.lengths.iter().enumerate() {
                    entries.push(format!(
                        "canonical-hex-key-length:{}:{policy_index}:{length_index}:{length}",
                        d.id
                    ));
                }
                for (keyword_index, keyword) in policy.keywords.iter().enumerate() {
                    entries.push(format!(
                        "canonical-hex-key-keyword:{}:{policy_index}:{keyword_index}:{keyword}",
                        d.id
                    ));
                }
                for (suffix_index, suffix) in policy.suffixes.iter().enumerate() {
                    entries.push(format!(
                        "canonical-hex-key-suffix:{}:{policy_index}:{suffix_index}:{suffix}",
                        d.id
                    ));
                }
                for (excluded_index, excluded) in policy.excluded_keywords.iter().enumerate() {
                    entries.push(format!(
                        "canonical-hex-key-excluded:{}:{policy_index}:{excluded_index}:{excluded}",
                        d.id
                    ));
                }
            }
            if let Some(v) = d.keyword_free_min_len {
                entries.push(format!("kfml:{}:{}", d.id, v));
            }
            if let Some(v) = d.min_len {
                entries.push(format!("ml:{}:{}", d.id, v));
            }
            if let Some(v) = d.max_len {
                entries.push(format!("maxl:{}:{}", d.id, v));
            }
            // Allowlist/stopword lists are OR-any membership sets: order is NOT
            // semantic, so sort each (exactly like `keywords`) so a mere reorder
            // does not thrash the cache while any add/remove/edit still changes
            // the digest.
            let mut alp: Vec<&String> = d.allowlist_paths.iter().collect();
            alp.sort();
            for p in alp {
                entries.push(format!("alp:{}:{}", d.id, p));
            }
            let mut alv: Vec<&String> = d.allowlist_values.iter().collect();
            alv.sort();
            for v in alv {
                entries.push(format!("alv:{}:{}", d.id, v));
            }
            let mut sw: Vec<&String> = d.stopwords.iter().collect();
            sw.sort();
            for s in sw {
                entries.push(format!("sw:{}:{}", d.id, s));
            }
            let mut public_markers: Vec<&String> =
                d.public_identifier_assignment_markers.iter().collect();
            public_markers.sort();
            for marker in public_markers {
                entries.push(format!("public-id-marker:{}:{}", d.id, marker));
            }
            let mut hot: Vec<&String> = d.simdsieve_prefixes.iter().collect();
            hot.sort();
            for prefix in hot {
                entries.push(format!("simdsieve:{}:{}", d.id, prefix));
            }
            if d.structural_password_slot {
                entries.push(format!("sps:{}", d.id));
            }
            if d.weak_anchor {
                entries.push(format!("wa:{}", d.id));
            }
            if d.private_key_block {
                entries.push(format!("pkb:{}", d.id));
            }
            if d.resolution_priority != 0 {
                entries.push(format!("rp:{}:{}", d.id, d.resolution_priority));
            }
            for suffix in &d.generic_vendor_suffixes {
                entries.push(format!("gvs:{}:{}", d.id, suffix));
            }
            for suffix in &d.generic_assignment_tail_suffixes {
                entries.push(format!("gats:{}:{}", d.id, suffix));
            }
            if d.ml != crate::DetectorMlPolicySpec::default() {
                entries.push(format!(
                    "model:{}:{}:{}:{:016x}:{}",
                    d.id,
                    d.ml.match_mode.as_str(),
                    d.ml.entropy_mode.as_str(),
                    d.ml.weight.to_bits(),
                    d.ml.context_radius_lines
                ));
            }
            if let Some(confidence) = d.match_confidence {
                entries.push(format!(
                    "match-confidence:{}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{}:{}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}",
                    d.id,
                    confidence.literal_prefix_weight.to_bits(),
                    confidence.context_anchor_weight.to_bits(),
                    confidence.entropy_weight.to_bits(),
                    confidence.high_entropy_partial_weight.to_bits(),
                    confidence.moderate_entropy_threshold.to_bits(),
                    confidence.moderate_entropy_weight.to_bits(),
                    confidence.low_entropy_penalty_floor.to_bits(),
                    confidence.low_entropy_min_match_length,
                    confidence.low_entropy_penalty_multiplier.to_bits(),
                    confidence.keyword_nearby_weight.to_bits(),
                    confidence.sensitive_file_weight.to_bits(),
                    confidence.companion_weight.to_bits(),
                    confidence.very_high_entropy_margin.to_bits(),
                    confidence
                        .named_anchor_floor
                        .map_or_else(|| "none".into(), |value| format!("{:016x}", value.to_bits())),
                    confidence
                        .low_promise_confidence
                        .map_or_else(|| "none".into(), |value| format!("{:016x}", value.to_bits())),
                    confidence.assignment_context_multiplier.to_bits(),
                    confidence.string_literal_context_multiplier.to_bits(),
                    confidence.unknown_context_multiplier.to_bits(),
                    confidence.documentation_context_multiplier.to_bits(),
                    confidence.comment_context_multiplier.to_bits(),
                    confidence.test_context_multiplier.to_bits(),
                    confidence.encrypted_context_multiplier.to_bits(),
                    confidence.soft_context_suppression_threshold.to_bits(),
                    confidence.encrypted_context_suppression_threshold.to_bits(),
                ));
                let post = confidence.post_match;
                entries.push(format!(
                    "post-match-confidence:{}:{:016x}:{:016x}:{:016x}:{:016x}:{}:{:016x}:{}:{:016x}:{:016x}",
                    d.id,
                    post.placeholder_multiplier.to_bits(),
                    post.minimum_byte_diversity.to_bits(),
                    post.low_diversity_multiplier.to_bits(),
                    post.maximum_repeat_ratio.to_bits(),
                    post.degenerate_run_min_length,
                    post.degenerate_repeat_multiplier.to_bits(),
                    post.data_envelope_multiplier.map_or_else(
                        || "none".into(),
                        |value| format!("{:016x}", value.to_bits())
                    ),
                    post.fixture_path_multiplier.to_bits(),
                    post.ml_context_reapply_below.to_bits(),
                ));
            }
            for (validator_index, validator) in d.validators.iter().enumerate() {
                match validator {
                    crate::DetectorValidatorSpec::Crc32Base62 {
                        prefixes: _,
                        entropy_len,
                        checksum_len,
                        reject_overlong,
                        confidence_floor,
                    } => entries.push(format!(
                        "validator:{}:{}:crc32-base62:{}:{}:{}:{:016x}",
                        d.id,
                        validator_index,
                        entropy_len,
                        checksum_len,
                        reject_overlong,
                        confidence_floor.to_bits()
                    )),
                    crate::DetectorValidatorSpec::GithubFineGrainedCrc32 {
                        prefixes: _,
                        left_len,
                        right_len,
                        checksum_len,
                        confidence_floor,
                    } => entries.push(format!(
                        "validator:{}:{}:github-fine-grained-crc32:{}:{}:{}:{:016x}",
                        d.id,
                        validator_index,
                        left_len,
                        right_len,
                        checksum_len,
                        confidence_floor.to_bits()
                    )),
                    crate::DetectorValidatorSpec::Base64Payload {
                        prefixes: _,
                        alphabet,
                        min_encoded_len,
                        max_encoded_len,
                        min_decoded_len,
                        confidence_floor,
                    } => {
                        let alphabet = match alphabet {
                            crate::DetectorBase64Alphabet::Standard => "standard",
                            crate::DetectorBase64Alphabet::StandardNoPad => "standard-no-pad",
                            crate::DetectorBase64Alphabet::UrlSafe => "url-safe",
                            crate::DetectorBase64Alphabet::UrlSafeNoPad => "url-safe-no-pad",
                        };
                        entries.push(format!(
                            "validator:{}:{}:base64-payload:{}:{}:{}:{}:{:016x}",
                            d.id,
                            validator_index,
                            alphabet,
                            min_encoded_len,
                            max_encoded_len,
                            min_decoded_len,
                            confidence_floor.to_bits()
                        ));
                    }
                    crate::DetectorValidatorSpec::PatternShape {
                        prefixes: _,
                        allow_overlong,
                    } => {
                        entries.push(format!(
                            "validator:{}:{}:pattern-shape:{}",
                            d.id, validator_index, allow_overlong
                        ));
                    }
                }
                for (prefix_index, prefix) in validator.prefixes().iter().enumerate() {
                    entries.push(format!(
                        "validator-prefix-hex:{}:{}:{}:{}",
                        d.id,
                        validator_index,
                        prefix_index,
                        crate::hex_encode(prefix.as_bytes())
                    ));
                }
            }
            if let Some(shape) = &d.credential_shape {
                // `CredentialShape` derives `Debug` over its four `Option` fields;
                // its `{:?}` is total and deterministic within a build, and any
                // field change (prefix/exact/body bounds) changes it.
                entries.push(format!("cshape:{}:{:?}", d.id, shape));
            }
            entries
        })
        .collect();
    keys.sort();
    let mut hasher = blake3::Hasher::new();
    for k in keys {
        hasher.update(k.as_bytes());
        hasher.update(b"\n");
    }
    *hasher.finalize().as_bytes()
}

/// Compile-time detector-schema inventory for the scan-execution hash.
///
/// A new `DetectorSpec` field must make this destructure fail to compile until
/// its scan/runtime effect is hashed above or its exclusion is documented next
/// to `name`, `verify`, and `tests`.
#[inline(always)]
fn assert_scan_hash_field_inventory_is_exhaustive(detector: &DetectorSpec) {
    let DetectorSpec {
        id: _,
        name: _,
        service: _,
        severity: _,
        kind: _,
        ml: _,
        match_confidence: _,
        validators: _,
        decode_transforms: _,
        patterns: _,
        companions: _,
        verify: _,
        keywords: _,
        simdsieve_prefixes: _,
        min_confidence: _,
        entropy_floor: _,
        entropy_high: _,
        entropy_low: _,
        entropy_very_high: _,
        entropy_fallback: _,
        entropy_fallback_confidence: _,
        generic_assignment_confidence: _,
        entropy_roles: _,
        sensitive_path_entropy_very_high: _,
        entropy_shapes: _,
        plausibility: _,
        entropy_policy_priority: _,
        bpe_max_bytes_per_token: _,
        bpe_enabled: _,
        decoded_hex_key_material_lengths: _,
        canonical_hex_key_material: _,
        keyword_free_min_len: _,
        min_len: _,
        max_len: _,
        generic_vendor_suffixes: _,
        generic_assignment_tail_suffixes: _,
        allowlist_paths: _,
        allowlist_values: _,
        stopwords: _,
        public_identifier_assignment_markers: _,
        structural_password_slot: _,
        weak_anchor: _,
        resolution_priority: _,
        private_key_block: _,
        credential_shape: _,
        tests: _,
    } = detector;
}

#[inline(always)]
fn assert_pattern_hash_field_inventory_is_exhaustive(pattern: &PatternSpec) {
    let PatternSpec {
        regex: _,
        description: _,
        group: _,
        required_literals: _,
        client_safe: _,
        weak_anchor: _,
    } = pattern;
}

#[inline(always)]
fn assert_companion_hash_field_inventory_is_exhaustive(companion: &CompanionSpec) {
    let CompanionSpec {
        name: _,
        regex: _,
        within_lines: _,
        required: _,
    } = companion;
}

// `hex_encode` lives in `finding.rs` (the single canonical lower-case-hex of a
// `[u8; 32]` digest, used by reporters and the merkle index alike). The former
// hand-rolled copy here duplicated that algorithm; merkle_index now imports the
// canonical one directly.

pub(crate) fn hex_to_array(hex: &str) -> Option<[u8; 32]> {
    // Byte-slice, not `&str[..]`: a 64-byte input with a multibyte UTF-8 char
    // at an odd offset (corrupted / hand-edited cache, deserialized
    // `spec_hash`) would panic on a non-char boundary with `&hex[i*2..i*2+2]`.
    // Decode each nibble directly; any non-hex byte fails the parse cleanly.
    let bytes = hex.as_bytes();
    if bytes.len() != crate::git_lfs::SHA256_HEX_LEN {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Decode a single lowercase/uppercase hex digit byte to its 0-15 value.
/// Shared by the allowlist SHA-256 parser so both sites decode hex identically
/// (byte-wise, never `&str[..]` slicing - that panics on non-char boundaries).
#[inline]
pub(crate) fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
