//! Detector-spec hash digest for merkle cache invalidation.

use crate::spec::{DetectorKind, DetectorSpec};

/// Compute a stable BLAKE3 digest over the canonical detector set so a
/// later scan can detect that detectors changed.
pub fn compute_spec_hash(detectors: &[DetectorSpec]) -> [u8; 32] {
    let mut keys: Vec<String> = detectors
        .iter()
        .flat_map(|d| {
            let mut entries =
                Vec::with_capacity(2 + d.patterns.len() + d.companions.len() + d.keywords.len());
            entries.push(format!("id:{}", d.id));
            // Bind severity to the detector id: an un-bound `sev:{severity}` key
            // makes swapping severities between two detectors produce the same
            // sorted multiset (identical digest), so the merkle cache would keep
            // a stale skip after severity — and severity-threshold suppression —
            // changed (Law 10 silent staleness).
            entries.push(format!("sev:{}:{:?}", d.id, d.severity));
            for (index, p) in d.patterns.iter().enumerate() {
                entries.push(format!(
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
                ));
            }
            for (index, c) in d.companions.iter().enumerate() {
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
            // change to any of them changes WHICH findings a scan emits — the
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
            // DELIBERATELY EXCLUDED (like the cosmetic `name`/`service` and
            // `PatternSpec.description`, whose exclusion `spec_hash_ignores_
            // cosmetic_name_field` pins): `verify` (live-verification config —
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
                    b.max_len.map(|m| m.to_string()).unwrap_or_default(),
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
            if let Some(v) = d.mixed_alnum_floor {
                entries.push(format!("maf:{}:{:016x}", d.id, v.to_bits()));
            }
            if let Some(v) = d.bpe_max_bytes_per_token {
                entries.push(format!("bpe:{}:{:016x}", d.id, v.to_bits()));
            }
            if let Some(v) = d.bpe_enabled {
                entries.push(format!("bpe-enabled:{}:{v}", d.id));
            }
            if let Some(v) = d.keyword_free_min_len {
                entries.push(format!("kfml:{}:{}", d.id, v));
            }
            if let Some(v) = d.min_len {
                entries.push(format!("ml:{}:{}", d.id, v));
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
            if d.structural_password_slot {
                entries.push(format!("sps:{}", d.id));
            }
            if d.weak_anchor {
                entries.push(format!("wa:{}", d.id));
            }
            if d.private_key_block {
                entries.push(format!("pkb:{}", d.id));
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
