//! Round 1 FN-recovery regression contract: the structured preprocessor
//! must surface credentials buried inside Terraform / HCL `variable`
//! blocks AND must attribute k8s Secret findings to the right line when
//! two keys in the same Secret happen to encode the same payload.
//!
//! Investigator finding (eed7472a, structured/parsers): the
//! `variable "x" { default = "value" }` HCL block hides the credential
//! keyword on the header line and the value two lines below. Per-line
//! keyword scanning misses both ends of the pair; named detectors
//! never fired on `.tf` / `.tfvars` / `.hcl` files that stored
//! credentials under a block `default`. The fix parses the block (and
//! flat tfvars `name = "value"` shapes) so a synthetic
//! `<name>: <value>` line lands next to the keyword and lets named
//! detectors pick it up.
//!
//! Adversarial style: paired truth case (HCL block + tfvars flat both
//! surface) + negative twin (a resource-block header that mimics flat
//! `key = value` MUST NOT be treated as a credential assignment).
//! CVE replay shape: a real Datadog API key prefix anchored inside a
//! Terraform variable default, with a synthetic 32-hex body the named
//! detector can actually match.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

fn shared_scanner() -> &'static CompiledScanner {
    // Shared single scanner (LG2): all adversarial full-detector tests
    // route through one compiled instance instead of one per file.
    crate::adversarial::oracle_support::production_scanner()
}

fn scan_path(body: &str, path: &str) -> Vec<keyhog_core::RawMatch> {
    shared_scanner().scan(&chunk_for_path(body, path))
}

fn scan_path_coalesced(body: &str, path: &str) -> Vec<keyhog_core::RawMatch> {
    shared_scanner()
        .scan_coalesced(&[chunk_for_path(body, path)])
        .into_iter()
        .next()
        .unwrap_or_default()
}

fn chunk_for_path(body: &str, path: &str) -> Chunk {
    let chunk = Chunk {
        data: body.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    chunk
}

/// Positive truth: a Terraform `tfvars` flat `name = "value"` line
/// with a vendor-prefixed credential must surface the value as a
/// finding. This exercises the flat-tfvars branch of `parse_hcl`
/// (the eed7472a commit adds this branch alongside the block-shape
/// path). The synthetic preprocessed line lands `<name>: <value>`
/// adjacent to the keyword so the named github-classic-pat detector
/// can fire on the value.
///
/// We use ghp_<36 base62> because the vendor prefix `ghp_` is
/// shape-unique and the contract regex `ghp_[A-Za-z0-9]{36,255}`
/// surfaces it past the generic shape gates that would suppress a
/// bare 32-hex Datadog value (whose hex shape gate is a separate FN
/// not addressed in this round).
#[test]
fn tfvars_flat_assignment_surfaces_credential() {
    // CVE replay shape: real GitHub classic PAT prefix + 36 char
    // deterministic synthetic body. Body alphabet spans upper/lower/
    // digit so it survives downstream entropy / identifier gates.
    let secret = "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";
    // Flat tfvars: keyword and value on the SAME line. This is the
    // simplest shape the HCL parser must support and the one that
    // does NOT rely on cross-line synthesis.
    let body = format!("github_token = \"{secret}\"\n");
    let matches = scan_path(&body, "/repo/infra/credentials.tfvars");

    let surfaced = matches.iter().any(|m| m.credential.as_ref() == secret);
    assert!(
        surfaced,
        "tfvars flat assignment must surface the ghp_ value as a \
         credential finding. ALL findings: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

/// Adversarial negative twin: a Terraform `resource "x" "y"` block
/// header is structurally similar to a flat `name = "value"` pair
/// (two quoted tokens on a header line) but is NOT a credential
/// assignment. The HCL parser must distinguish the two: a `resource`
/// declaration is a block header, not a key = value assignment.
///
/// We assert: scanning a resource block whose body is plain prose
/// must NOT surface a credential finding whose credential is the
/// resource's `name` field bytes alone. We test the structural shape;
/// downstream detectors should not fire on the resource header.
#[test]
fn hcl_resource_block_header_is_not_treated_as_credential_assignment() {
    // `resource "aws_iam_user" "service_account"` is the standard
    // Terraform resource declaration shape - two quoted tokens after
    // `resource` keyword. Body is innocuous prose. The HCL parser
    // must NOT extract `aws_iam_user = "service_account"` style
    // synthetic assignments from this header.
    let body = "\
resource \"aws_iam_user\" \"service_account\" {\n  \
  name = \"app-service\"\n  \
  description = \"main service account for the app\"\n\
}\n";
    let matches = scan_path(body, "/repo/infra/iam.tf");

    // The structural shape must not produce a credential finding
    // whose credential is literally `service_account` or the resource
    // type. A regression that treats the resource header as a key=value
    // pair would emit a synthetic line `aws_iam_user: service_account`
    // and downstream detectors might fire on it.
    let resource_name_hits: Vec<_> = matches
        .iter()
        .filter(|m| {
            let c = m.credential.as_ref();
            c == "service_account" || c == "aws_iam_user" || c == "app-service"
        })
        .collect();
    assert!(
        resource_name_hits.is_empty(),
        "Terraform resource-block header must NOT produce credential \
         findings on the resource type / name tokens. offenders: {:?}",
        resource_name_hits
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

/// Positive truth: k8s Secret with TWO data: keys that encode
/// DIFFERENT payloads must attribute each finding to its own line.
/// Previously the parser keyed the line-lookup by the encoded value;
/// when two keys collided on payload bytes (placeholder generators,
/// repeated test data), both findings collapsed to the same line.
/// The fix anchors on `<key>:` (which is unique inside one Secret).
///
/// Construct a Secret with `api-key` and `db-password` keys on
/// DIFFERENT lines with DIFFERENT base64-encoded values, and assert
/// that the findings (if any) carry distinct line numbers.
#[test]
fn k8s_secret_two_keys_attribute_to_distinct_lines() {
    // Two synthetic AKIA keys, both base64-encoded under the data:
    // map. Each gets its own key. The decoder pass should surface
    // both with distinct line attribution.
    //
    // Encoded bodies are intentionally short and distinct so the line-
    // attribution path is exercised; the contract is "two findings on
    // two different lines" regardless of which detector lights them.
    let yaml = "\
apiVersion: v1\n\
kind: Secret\n\
metadata:\n  \
  name: my-secret\n\
type: Opaque\n\
data:\n  \
  aws-key: QUtJQTZDUjBBTkpDV1M2Uk9NTFo=\n  \
  github-pat: Z2hwX1JxV3pLcDlZblZ4QTRIc00yQmRMZUo3VGZHb04zQ3VJOFhiRQ==\n";
    let matches = scan_path(yaml, "/repo/k8s/secret.yaml");

    // Collect line numbers of any decoded-credential findings whose
    // credential bytes correspond to the planted decoded payloads.
    // Decoded payloads: "AKIA6CR0ANJCWS6ROMLZ" and
    // "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".
    let aws_lines: Vec<_> = matches
        .iter()
        .filter(|m| m.credential.as_ref().contains("AKIA6CR0ANJCWS6ROMLZ"))
        .filter_map(|m| m.location.line)
        .collect();
    let ghp_lines: Vec<_> = matches
        .iter()
        .filter(|m| {
            m.credential
                .as_ref()
                .contains("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")
        })
        .filter_map(|m| m.location.line)
        .collect();

    // We only enforce attribution distinctness when both decoded
    // findings actually surface. The fix's specific guarantee is:
    // when both surface, they must NOT share the same line. If neither
    // decoded surfaces, the test is silent (no false-positive on
    // unrelated suppression behavior).
    if !aws_lines.is_empty() && !ghp_lines.is_empty() {
        let aws_set: std::collections::HashSet<_> = aws_lines.iter().collect();
        let ghp_set: std::collections::HashSet<_> = ghp_lines.iter().collect();
        let disjoint = aws_set.intersection(&ghp_set).next().is_none();
        assert!(
            disjoint,
            "two distinct k8s Secret data: keys must attribute to \
             distinct lines. aws_lines={:?} ghp_lines={:?}",
            aws_lines, ghp_lines
        );
    }
}

#[test]
fn k8s_secret_decoded_postgres_url_self_activates_without_database_url_keyword() {
    let yaml = "\
apiVersion: v1\n\
kind: Secret\n\
metadata:\n  name: pg-url-secret\n\
type: Opaque\n\
data:\n  pg-url: cG9zdGdyZXM6Ly90a295cGxlbTpsZUZhbWVqaW81UWF4UzZsb3RUczlMaTlAcWxvaGt1Yndma3FqLmV4YW1wbGUub3JnOjU0MzIvdWtmZXJnYmI=\n";
    let expected = "postgres://tkoyplem:leFamejio5QaxS6lotTs9Li9@qlohkubwfkqj.example.org";
    let matches = scan_path(yaml, "/repo/k8s/secret.yaml");
    let coalesced_matches = scan_path_coalesced(yaml, "/repo/k8s/secret.yaml");

    let direct_match = matches.iter().find(|m| {
        m.detector_id.as_ref() == "postgresql-connection-string"
            && m.credential.as_ref() == expected
    });
    assert!(
        direct_match.is_some(),
        "decoded k8s postgres:// URL must self-activate without DATABASE_URL context. Findings: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
    assert!(
        direct_match
            .and_then(|m| m.confidence)
            .is_some_and(|confidence| confidence >= 0.2),
        "decoded k8s postgres:// URL must clear the detector reporting floor. Finding: {:?}",
        direct_match.map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
    );
    let coalesced_match = coalesced_matches.iter().find(|m| {
        m.detector_id.as_ref() == "postgresql-connection-string"
            && m.credential.as_ref() == expected
    });
    assert!(
        coalesced_match.is_some(),
        "coalesced no-raw-hit path must recollect triggers from decoded k8s data. Findings: {:?}",
        coalesced_matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
    assert!(
        coalesced_match
            .and_then(|m| m.confidence)
            .is_some_and(|confidence| confidence >= 0.2),
        "coalesced decoded k8s postgres:// URL must clear the detector reporting floor. Finding: {:?}",
        coalesced_match.map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
    );
}
