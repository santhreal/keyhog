//! Secret-safe semantic identity used to prove cross-backend detection parity.

use keyhog_core::{CredentialHash, EvidenceReasonCode, EvidenceTier, RawMatch, Severity};

/// Redacted, total user-visible identity of one backend match.
///
/// Plain credentials and companion values never enter this proof object. Their
/// SHA-256 domain values do, so calibration proves semantic parity without
/// making diagnostics or comparison scratch a secret-bearing surface.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
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
    evidence_tier: EvidenceTier,
    evidence_reason_code: EvidenceReasonCode,
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
        evidence_tier: m.evidence.tier(),
        evidence_reason_code: m.evidence.reason_code(),
    }
}

/// Identify which semantic fields differ without rendering their values.
pub(crate) fn differing_canonical_match_fields(
    reference: &[CanonicalMatch<'_>],
    trial: &[CanonicalMatch<'_>],
) -> Vec<&'static str> {
    let mut fields = std::collections::BTreeSet::new();
    if reference.len() != trial.len() {
        fields.insert("match_count");
    }
    for (reference, trial) in reference.iter().zip(trial) {
        if reference.chunk_idx != trial.chunk_idx {
            fields.insert("chunk_idx");
        }
        if reference.detector_id != trial.detector_id {
            fields.insert("detector_id");
        }
        if reference.detector_name != trial.detector_name {
            fields.insert("detector_name");
        }
        if reference.service != trial.service {
            fields.insert("service");
        }
        if reference.severity != trial.severity {
            fields.insert("severity");
        }
        if reference.credential_value_hash != trial.credential_value_hash {
            fields.insert("credential_value");
        }
        if reference.credential_hash != trial.credential_hash {
            fields.insert("credential_hash");
        }
        if reference.companions != trial.companions {
            fields.insert("companions");
        }
        if reference.source != trial.source {
            fields.insert("source");
        }
        if reference.file_path != trial.file_path {
            fields.insert("file_path");
        }
        if reference.line != trial.line {
            fields.insert("line");
        }
        if reference.offset != trial.offset {
            fields.insert("offset");
        }
        if reference.commit != trial.commit {
            fields.insert("commit");
        }
        if reference.author != trial.author {
            fields.insert("author");
        }
        if reference.date != trial.date {
            fields.insert("date");
        }
        if reference.entropy_bits != trial.entropy_bits {
            fields.insert("entropy");
        }
        if reference.confidence_bits != trial.confidence_bits {
            fields.insert("confidence");
        }
        if reference.evidence_tier != trial.evidence_tier {
            fields.insert("evidence_tier");
        }
        if reference.evidence_reason_code != trial.evidence_reason_code {
            fields.insert("evidence_reason_code");
        }
    }
    fields.into_iter().collect()
}

/// One match's identity as a single redacted line.
///
/// Every field here is already secret-safe: credentials are present only as
/// SHA-256 digests, and only the first eight hex characters of those are shown,
/// which is enough to correlate two records without publishing a digest that
/// could be checked against a guess.
pub(crate) fn render_canonical_match(record: &CanonicalMatch<'_>) -> String {
    let digest = keyhog_core::hex_encode(record.credential_value_hash);
    format!(
        "chunk {} {} @ {}:{} offset {} credential {}",
        record.chunk_idx,
        record.detector_id,
        record.file_path.unwrap_or("<no path>"), // LAW10: absent optional path is rendered only in mismatch diagnostics; canonical match identity remains unchanged.
        record
            .line
            .map_or_else(|| "?".to_string(), |line| line.to_string()),
        record.offset,
        &digest[..8.min(digest.len())],
    )
}

/// The records present on one side of the comparison and not the other.
///
/// Counts alone cannot be acted on. A rejected backend candidate blocks the
/// whole calibration, and the operator's first question is which detector, at
/// which file and offset, disagreed. Both slices must already be sorted, which
/// `canonical_matches` guarantees.
///
/// This is a multiset difference, so a record appearing twice on the left and
/// once on the right is reported once.
pub(crate) fn canonical_match_differences<'a>(
    left: &[CanonicalMatch<'a>],
    right: &[CanonicalMatch<'a>],
    limit: usize,
) -> Vec<String> {
    let mut rendered = Vec::new();
    let mut left_index = 0usize;
    let mut right_index = 0usize;
    while left_index < left.len() && rendered.len() < limit {
        let record = &left[left_index];
        while right_index < right.len() && right[right_index] < *record {
            right_index += 1;
        }
        let left_end = run_end(left, left_index);
        let right_count = if right.get(right_index) == Some(record) {
            run_end(right, right_index) - right_index
        } else {
            0
        };
        let missing = (left_end - left_index).saturating_sub(right_count);
        if missing > 0 {
            rendered.push(if missing == 1 {
                render_canonical_match(record)
            } else {
                format!("{} (x{missing})", render_canonical_match(record))
            });
        }
        left_index = left_end;
    }
    rendered
}

fn run_end(records: &[CanonicalMatch<'_>], start: usize) -> usize {
    let mut end = start + 1;
    while end < records.len() && records[end] == records[start] {
        end += 1;
    }
    end
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
        h.field_str("match.evidence_tier", m.evidence_tier.as_str());
        h.field_str(
            "match.evidence_reason_code",
            m.evidence_reason_code.as_str(),
        );
    }
    h.finish_u64()
}

#[cfg(test)]
#[path = "../../../../../tests/unit/backend_match_identity.rs"]
mod tests;
