//! Secret-safe semantic identity used to prove cross-backend detection parity.

use keyhog_core::{CredentialHash, RawMatch, Severity};

/// Redacted, total user-visible identity of one backend match.
///
/// Plain credentials and companion values never enter this proof object. Their
/// SHA-256 domain values do, so calibration proves semantic parity without
/// making diagnostics or comparison scratch a secret-bearing surface.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CanonicalMatch<'a> {
    chunk_idx: usize,
    detector_id: &'a str,
    detector_name: &'a str,
    service: &'a str,
    severity: Severity,
    credential_value_hash: CredentialHash,
    credential_hash: CredentialHash,
    companions: Vec<(CredentialHash, CredentialHash)>,
    source: &'a str,
    file_path: Option<&'a str>,
    line: Option<usize>,
    offset: usize,
    commit: Option<&'a str>,
    author: Option<&'a str>,
    date: Option<&'a str>,
    entropy_bits: Option<u64>,
    confidence_bits: Option<u64>,
}

pub(crate) fn canonical_matches(matches: &[Vec<RawMatch>]) -> Vec<CanonicalMatch<'_>> {
    let mut out = Vec::with_capacity(canonical_match_count(matches));
    for (chunk_idx, chunk_matches) in matches.iter().enumerate() {
        for m in chunk_matches {
            out.push(canonical_match(chunk_idx, m));
        }
    }
    out.sort_unstable();
    out
}

pub(crate) fn canonical_matches_equal_reference(
    matches: &[Vec<RawMatch>],
    reference: &[CanonicalMatch<'_>],
) -> bool {
    let match_count = canonical_match_count(matches);
    if match_count != reference.len() {
        return false;
    }
    if match_count == 0 {
        return true;
    }
    if match_count > 256 {
        return canonical_matches(matches) == reference;
    }

    let mut matched = [false; 256];
    for (chunk_idx, chunk_matches) in matches.iter().enumerate() {
        for m in chunk_matches {
            let canonical = canonical_match(chunk_idx, m);
            let Ok(mut idx) = reference.binary_search(&canonical) else {
                return false;
            };
            while idx > 0 && reference[idx - 1] == canonical {
                idx -= 1;
            }
            while idx < reference.len() && reference[idx] == canonical {
                if !matched[idx] {
                    matched[idx] = true;
                    break;
                }
                idx += 1;
            }
            if idx == reference.len() || reference[idx] != canonical {
                return false;
            }
        }
    }
    true
}

fn canonical_match_count(matches: &[Vec<RawMatch>]) -> usize {
    matches.iter().map(Vec::len).sum()
}

fn canonical_match(chunk_idx: usize, m: &RawMatch) -> CanonicalMatch<'_> {
    let mut companions: Vec<_> = m
        .companions
        .iter()
        .map(|(name, value)| {
            (
                keyhog_core::sha256_hash(name),
                keyhog_core::sha256_hash(value),
            )
        })
        .collect();
    companions.sort_unstable();
    CanonicalMatch {
        chunk_idx,
        detector_id: m.detector_id.as_ref(),
        detector_name: m.detector_name.as_ref(),
        service: m.service.as_ref(),
        severity: m.severity,
        credential_value_hash: keyhog_core::sha256_hash(m.credential.as_ref()),
        credential_hash: m.credential_hash,
        companions,
        source: m.location.source.as_ref(),
        file_path: m.location.file_path.as_deref(),
        line: m.location.line,
        offset: m.location.offset,
        commit: m.location.commit.as_deref(),
        author: m.location.author.as_deref(),
        date: m.location.date.as_deref(),
        entropy_bits: m.entropy.map(f64::to_bits),
        confidence_bits: m.confidence.map(f64::to_bits),
    }
}

pub(crate) fn render_canonical_match(m: &CanonicalMatch<'_>) -> String {
    let credential_value_hash = keyhog_core::hex_encode(m.credential_value_hash.as_bytes());
    let credential_hash = keyhog_core::hex_encode(m.credential_hash.as_bytes());
    let companions = m
        .companions
        .iter()
        .map(|(name, value)| {
            (
                keyhog_core::hex_encode(name.as_bytes()),
                keyhog_core::hex_encode(value.as_bytes()),
            )
        })
        .collect::<Vec<_>>();
    let commit_hash = secret_safe_optional_hash(m.commit);
    let author_hash = secret_safe_optional_hash(m.author);
    let date_hash = secret_safe_optional_hash(m.date);
    format!(
        "chunk={} detector={} name={} service={} severity={} credential_value_hash={} cred_hash={} credential_hash_consistent={} \
         companions={:?} source={} file={:?} line={:?} offset={} commit_hash={:?} author_hash={:?} date_hash={:?} \
         entropy_bits={:?} confidence_bits={:?}",
        m.chunk_idx,
        m.detector_id,
        m.detector_name,
        m.service,
        m.severity.as_str(),
        credential_value_hash,
        credential_hash,
        m.credential_value_hash == m.credential_hash,
        companions,
        m.source,
        m.file_path,
        m.line,
        m.offset,
        commit_hash,
        author_hash,
        date_hash,
        m.entropy_bits,
        m.confidence_bits,
    )
}

fn secret_safe_optional_hash(value: Option<&str>) -> Option<String> {
    value.map(|value| keyhog_core::hex_encode(keyhog_core::sha256_hash(value).as_bytes()))
}

pub(crate) fn canonical_match_digest(matches: &[CanonicalMatch<'_>]) -> u64 {
    let mut h = crate::stable_hash::StableHasher::new("autoroute-correctness-digest");
    h.field_usize("matches.len", matches.len());
    for m in matches {
        h.field_usize("match.chunk_idx", m.chunk_idx);
        h.field_str("match.detector_id", m.detector_id);
        h.field_str("match.detector_name", m.detector_name);
        h.field_str("match.service", m.service);
        h.field_str("match.severity", m.severity.as_str());
        h.field_bytes(
            "match.credential_value_hash",
            m.credential_value_hash.as_bytes(),
        );
        h.field_bytes("match.credential_hash", m.credential_hash.as_bytes());
        h.field_usize("match.companions.len", m.companions.len());
        for (name_hash, value_hash) in &m.companions {
            h.field_bytes("match.companion.name_hash", name_hash.as_bytes());
            h.field_bytes("match.companion.value_hash", value_hash.as_bytes());
        }
        h.field_str("match.source", m.source);
        h.field_option_str("match.file_path", m.file_path);
        h.field_option_usize("match.line", m.line);
        h.field_usize("match.offset", m.offset);
        h.field_option_str("match.commit", m.commit);
        h.field_option_str("match.author", m.author);
        h.field_option_str("match.date", m.date);
        h.field_option_u64("match.entropy_bits", m.entropy_bits);
        h.field_option_u64("match.confidence_bits", m.confidence_bits);
    }
    h.finish_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diagnostic_match() -> CanonicalMatch<'static> {
        CanonicalMatch {
            chunk_idx: 0,
            detector_id: "detector",
            detector_name: "Detector",
            service: "service",
            severity: Severity::High,
            credential_value_hash: [0x11; 32].into(),
            credential_hash: [0x99; 32].into(),
            companions: vec![([0x22; 32].into(), [0x33; 32].into())],
            source: "git",
            file_path: Some("src/file.rs"),
            line: Some(7),
            offset: 13,
            commit: Some("commit-a"),
            author: Some("author-a@example.test"),
            date: Some("2026-07-14T00:00:00Z"),
            entropy_bits: Some(4.2_f64.to_bits()),
            confidence_bits: Some(0.9_f64.to_bits()),
        }
    }

    #[test]
    fn diagnostic_render_distinguishes_exact_hashed_evidence_without_plaintext() {
        let base = diagnostic_match();
        let base_rendered = render_canonical_match(&base);
        let mut variants = Vec::new();

        let mut changed = base.clone();
        changed.chunk_idx = 1;
        variants.push(("chunk index", changed));

        let mut changed = base.clone();
        changed.detector_id = "detector-b";
        variants.push(("detector id", changed));

        let mut changed = base.clone();
        changed.detector_name = "Detector B";
        variants.push(("detector name", changed));

        let mut changed = base.clone();
        changed.service = "service-b";
        variants.push(("service", changed));

        let mut changed = base.clone();
        changed.severity = Severity::Critical;
        variants.push(("severity", changed));

        let mut changed = base.clone();
        changed.credential_value_hash = [0x12; 32].into();
        variants.push(("credential value", changed));

        let mut changed = base.clone();
        changed.credential_hash = [0x98; 32].into();
        variants.push(("stored credential hash", changed));

        let mut changed = base.clone();
        changed.companions = vec![([0x22; 32].into(), [0x34; 32].into())];
        variants.push(("companion value", changed));

        let mut changed = base.clone();
        changed.companions = vec![([0x23; 32].into(), [0x33; 32].into())];
        variants.push(("companion name", changed));

        let mut changed = base.clone();
        changed.source = "filesystem";
        variants.push(("source", changed));

        let mut changed = base.clone();
        changed.file_path = Some("src/other.rs");
        variants.push(("file path", changed));

        let mut changed = base.clone();
        changed.line = Some(8);
        variants.push(("line", changed));

        let mut changed = base.clone();
        changed.offset = 14;
        variants.push(("offset", changed));

        let mut changed = base.clone();
        changed.commit = Some("commit-b");
        variants.push(("commit", changed));

        let mut changed = base.clone();
        changed.author = Some("author-b@example.test");
        variants.push(("author", changed));

        let mut changed = base.clone();
        changed.date = Some("2026-07-15T00:00:00Z");
        variants.push(("date", changed));

        let mut changed = base.clone();
        changed.entropy_bits = Some(4.3_f64.to_bits());
        variants.push(("entropy", changed));

        let mut changed = base.clone();
        changed.confidence_bits = Some(0.8_f64.to_bits());
        variants.push(("confidence", changed));

        for (field, changed) in variants {
            assert_ne!(
                base_rendered,
                render_canonical_match(&changed),
                "changing {field} must change the parity diagnostic"
            );
        }

        for plaintext in ["commit-a", "author-a@example.test", "2026-07-14T00:00:00Z"] {
            assert!(
                !base_rendered.contains(plaintext),
                "parity diagnostics must hash provenance value {plaintext:?}"
            );
        }
    }
}
