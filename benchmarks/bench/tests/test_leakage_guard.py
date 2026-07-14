import hashlib
import json

import pytest

import bench.leakage_guard as leakage_guard
from bench.leakage_guard import (
    LeakageGuardError,
    LeakageRecord,
    audit_splits,
    load_split_manifest,
    main,
)

CORPUS_DIGEST = hashlib.sha256(b"pinned-corpus-v1").hexdigest()
MANIFEST_DIGEST = hashlib.sha256(b"split-manifest-v1").hexdigest()


def record(
    record_id,
    split,
    *,
    before,
    after,
    credential="secret-value-123456",
    repository="github.com/example/root",
    family="provider/seed-1",
    corpus="secretbench",
    corpus_digest=CORPUS_DIGEST,
):
    content = before + credential + after
    start = len(before)
    return LeakageRecord(
        record_id=record_id,
        split=split,
        corpus_id=corpus,
        corpus_sha256=corpus_digest,
        repository_family=repository,
        credential_family=family,
        credential=credential,
        content=content,
        credential_start=start,
        credential_end=start + len(credential),
    )


def clean_records():
    return [
        record(
            "train-1",
            "train",
            before='resource aws_vpc primary { cidr_block = "',
            after='" } output route_table { value = local.gateway }',
            repository="github.com/acme/network",
            family="aws/seed-1",
            credential="AKIA1111111111111111",
        ),
        record(
            "calibration-1",
            "calibration",
            before="SELECT account_id, region FROM tenant_keys WHERE encrypted_blob = '",
            after="' AND retired_at IS NULL ORDER BY account_id;",
            repository="github.com/globex/database",
            family="database/seed-2",
            credential="postgresql://user:pass@db.example/x",
        ),
        record(
            "sealed-1",
            "sealed-test",
            before='package transport\nfunc signEnvelope(payload []byte) string { return signer.Sign("',
            after='", payload) }\nvar retryBudget = 7',
            repository="github.com/initech/transport",
            family="signing/seed-3",
            credential="ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        ),
    ]


def audit(records, **kwargs):
    return audit_splits(
        records,
        input_manifest_sha256=MANIFEST_DIGEST,
        **kwargs,
    )


def violation_reasons(receipt):
    return {violation.reason for violation in receipt.violations}


def test_clean_split_receipt_is_deterministic_private_and_counts_deduplication():
    records = clean_records()

    forward = audit(records)
    reverse = audit(list(reversed(records)))

    assert forward.ok
    assert forward.to_json() == reverse.to_json()
    assert forward.raw_records == 3
    assert forward.deduplicated_records == 3
    assert forward.assignment_groups == 3
    assert forward.per_split == {
        "calibration": {
            "raw_records": 1,
            "deduplicated_records": 1,
            "assignment_groups": 1,
        },
        "sealed-test": {
            "raw_records": 1,
            "deduplicated_records": 1,
            "assignment_groups": 1,
        },
        "train": {
            "raw_records": 1,
            "deduplicated_records": 1,
            "assignment_groups": 1,
        },
    }
    encoded = json.dumps(forward.to_json(), sort_keys=True)
    for sample in records:
        assert sample.credential not in encoded
        assert sample.repository_family not in encoded
        assert sample.credential_family not in encoded


def test_repository_ancestry_crossing_splits_fails_even_when_content_is_unrelated():
    records = clean_records()[:2]
    records[0] = record(
        "train-repo",
        "train",
        before="alpha configuration start ",
        after=" alpha configuration end",
        repository="git@GitHub.com:Org/Shared.git",
        family="one",
        credential="first-private-value",
    )
    records[1] = record(
        "sealed-repo",
        "sealed-test",
        before="completely unrelated syntax before ",
        after=" and unrelated syntax after",
        repository="https://github.com/org/shared/",
        family="two",
        credential="second-private-value",
    )

    receipt = audit(records)

    assert not receipt.ok
    assert "repository-family" in violation_reasons(receipt)
    with pytest.raises(LeakageGuardError, match="repository-family"):
        receipt.require_clean()


def test_normalized_credential_family_crossing_splits_fails():
    records = clean_records()[:2]
    records[0] = record(
        "train-family",
        "train",
        before="alpha unique context ",
        after=" first ending",
        repository="repo/one",
        family="AWS   Root / Seed-17",
        credential="first-private-value",
    )
    records[1] = record(
        "cal-family",
        "calibration",
        before="beta disjoint context ",
        after=" second ending",
        repository="repo/two",
        family="aws root / seed-17",
        credential="second-private-value",
    )

    receipt = audit(records)

    assert "credential-family" in violation_reasons(receipt)


def test_nfkc_equivalent_credentials_fail_even_when_declared_families_differ():
    records = [
        record(
            "train-value",
            "train",
            before="alpha unique context ",
            after=" first ending",
            repository="repo/one",
            family="family/one",
            credential="ＡＢＣ１２３",
        ),
        record(
            "sealed-value",
            "sealed-test",
            before="beta disjoint context ",
            after=" second ending",
            repository="repo/two",
            family="family/two",
            credential="ABC123",
        ),
    ]

    receipt = audit(records)

    assert "credential-value" in violation_reasons(receipt)


def test_exact_context_duplicate_excludes_credential_bytes_and_fails_cross_split():
    before = 'def connect(client):\n    client.configure(token="'
    after = '")\n    return client.open(timeout=30)\n'
    records = [
        record(
            "train-exact",
            "train",
            before=before,
            after=after,
            repository="repo/one",
            family="family/one",
            credential="private-one",
        ),
        record(
            "sealed-exact",
            "sealed-test",
            before=before,
            after=after,
            repository="repo/two",
            family="family/two",
            credential="private-two",
        ),
    ]

    receipt = audit(records)

    assert "exact-context" in violation_reasons(receipt)
    assert receipt.deduplicated_records == 1
    assert receipt.to_json() == audit(list(reversed(records))).to_json()


def test_research_threshold_token_near_duplicate_fails_cross_split():
    records = [
        record(
            "train-token-near",
            "train",
                before=(
                    "class WalletTest(TestFramework):\n"
                    "  def __init__(self):\n"
                    "    super().__init__(4, 0)\n"
                    "    alpha = beta + gamma + delta + epsilon + zeta + eta + theta + iota + kappa + lambdaValue\n"
                    '    self.sporkprivkey = "'
                ),
                after=(
                    '"\n  def run_test(self):\n'
                    '    self.sporkAddress = self.nodes[0].getaccountaddress("")\n'
                ),
            repository="repo/one",
            family="family/one",
            credential="private-one",
        ),
        record(
            "sealed-token-near",
            "sealed-test",
                before=(
                    "class WalletTest(TestFramework):\n"
                    "  def __init__(self):\n"
                    "    super().__init__(6, 5)\n"
                    "    alpha = beta + gamma + delta + epsilon + zeta + eta + theta + iota + kappa + lambdaValue\n"
                    '    self.sporkprivkey = "'
                ),
                after=(
                    '"\n  def run_test(self):\n'
                    '    self.sporkAddress = self.nodes[0].getaccountaddress("s")\n'
                ),
            repository="repo/two",
            family="family/two",
            credential="private-two",
        ),
    ]

    receipt = audit(records)

    assert "near-token" in violation_reasons(receipt)


def test_byte_near_duplicate_with_one_context_mutation_fails():
    shared = "const serviceEndpoint = client.initialize(region, account);\n" * 5
    records = [
        record(
            "train-byte-near",
            "train",
            before=shared + 'const token = "',
            after='";\nreturn serviceEndpoint;',
            repository="repo/one",
            family="family/one",
            credential="private-one",
        ),
        record(
            "sealed-byte-near",
            "sealed-test",
            before=shared.replace("account", "accounts", 1) + 'const token = "',
            after='";\nreturn serviceEndpoint;',
            repository="repo/two",
            family="family/two",
            credential="private-two",
        ),
    ]

    receipt = audit(records)

    assert "near-byte" in violation_reasons(receipt)


def test_renamed_literal_structure_clone_fails_without_token_identity():
    records = [
        record(
            "cal-structure",
            "calibration",
            before=(
                "def assemble(alpha, beta):\n"
                "  first = alpha.open(17)\n"
                "  if first.ready():\n"
                '    first.attach("'
            ),
            after='")\n  return first.commit(beta)\n',
            repository="repo/one",
            family="family/one",
            credential="private-one",
        ),
        record(
            "sealed-structure",
            "sealed-test",
            before=(
                "def construct(omega, delta):\n"
                "  second = omega.create(93)\n"
                "  if second.valid():\n"
                '    second.register("'
            ),
            after='")\n  return second.persist(delta)\n',
            repository="repo/two",
            family="family/two",
            credential="private-two",
        ),
    ]

    receipt = audit(records)

    assert "near-structure" in violation_reasons(receipt)


def test_unrelated_contexts_below_similarity_contract_remain_independent():
    receipt = audit(clean_records())

    assert receipt.ok
    assert not receipt.violations


def test_source_receipt_binds_redacted_content_outside_similarity_window():
    shared_tail = "tail outside credential window " * 10
    original = record(
        "train-source",
        "train",
        before="original-prefix" + shared_tail,
        after=" common ending",
        repository="repo/one",
        family="family/one",
        credential="private-one",
    )
    changed = record(
        "train-source",
        "train",
        before="modified-prefix" + shared_tail,
        after=" common ending",
        repository="repo/one",
        family="family/one",
        credential="private-one",
    )

    original_receipt = audit([original])
    changed_receipt = audit([changed])

    assert original_receipt.grouping_digest == changed_receipt.grouping_digest
    assert original_receipt.source_digest != changed_receipt.source_digest
    assert original_receipt.receipt_digest != changed_receipt.receipt_digest


def test_conflicting_corpus_provenance_fails_before_receipt():
    records = clean_records()[:2]
    records[1] = record(
        "calibration-conflict",
        "calibration",
        before="unrelated context ",
        after=" unrelated ending",
        repository="repo/two",
        family="family/two",
        corpus_digest=hashlib.sha256(b"other-source").hexdigest(),
    )

    with pytest.raises(LeakageGuardError, match="conflicting provenance digests"):
        audit(records)


def test_similarity_comparison_cap_fails_visibly():
    records = [
        record(
            f"record-{index}",
            split,
            before="shared repeated lexical context alpha beta gamma ",
            after=" shared repeated lexical context delta epsilon",
            repository=f"repo/{index}",
            family=f"family/{index}",
            credential=f"private-{index}",
        )
        for index, split in enumerate(("train", "calibration", "sealed-test"))
    ]

    with pytest.raises(LeakageGuardError, match="comparison cap exceeded"):
        audit(records, max_pair_comparisons=1)


def test_manifest_loader_rejects_type_coercion(tmp_path):
    manifest = tmp_path / "splits.jsonl"
    content_root = tmp_path / "content"
    content_root.mkdir()
    row = {
        "record_id": "sample",
        "split": "train",
        "corpus_id": "fixture-corpus",
        "corpus_sha256": CORPUS_DIGEST,
        "repository_family": None,
        "credential_family": "family/one",
        "secret": "private-one",
        "content_path": "sample.txt",
        "credential_start": 0,
        "credential_end": 11,
    }
    manifest.write_text(json.dumps(row) + "\n", encoding="utf-8")

    with pytest.raises(LeakageGuardError, match="invalid JSON types"):
        load_split_manifest(manifest, content_root)


def test_manifest_loader_bounds_unique_content_and_reuses_repeated_paths(
    tmp_path, monkeypatch
):
    content_root = tmp_path / "content"
    content_root.mkdir()
    content = "private-one"
    (content_root / "one.txt").write_text(content, encoding="utf-8")
    manifest = tmp_path / "splits.jsonl"

    def row(record_id, content_path):
        return {
            "record_id": record_id,
            "split": "train",
            "corpus_id": "fixture-corpus",
            "corpus_sha256": CORPUS_DIGEST,
            "repository_family": f"repo/{record_id}",
            "credential_family": f"family/{record_id}",
            "secret": content,
            "content_path": content_path,
            "credential_start": 0,
            "credential_end": len(content),
        }

    monkeypatch.setattr(leakage_guard, "MAX_TOTAL_CONTENT_BYTES", len(content))
    manifest.write_text(
        json.dumps(row("first", "one.txt"))
        + "\n"
        + json.dumps(row("second", "one.txt"))
        + "\n",
        encoding="utf-8",
    )
    records, _digest = load_split_manifest(manifest, content_root)
    assert records[0].content is records[1].content

    (content_root / "two.txt").write_text(content, encoding="utf-8")
    manifest.write_text(
        manifest.read_text(encoding="utf-8")
        + json.dumps(row("third", "two.txt"))
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(LeakageGuardError, match="aggregate limit"):
        load_split_manifest(manifest, content_root)


def test_receipt_rejects_identifier_containing_another_records_credential():
    records = [
        record(
            "private-two",
            "train",
            before="first context ",
            after=" first ending",
            repository="repo/one",
            family="family/one",
            credential="private-one",
        ),
        record(
            "sealed-safe-id",
            "sealed-test",
            before="second context ",
            after=" second ending",
            repository="repo/two",
            family="family/two",
            credential="private-two",
        ),
    ]

    with pytest.raises(LeakageGuardError, match="must not contain credential bytes"):
        audit(records)


def test_cli_writes_private_failure_receipt_and_returns_two(tmp_path, capsys):
    content_root = tmp_path / "content"
    content_root.mkdir()
    manifest = tmp_path / "splits.jsonl"
    receipt_path = tmp_path / "receipt.json"
    rows = []
    secrets = ["never-print-private-one", "never-print-private-two"]
    for index, (split, secret) in enumerate(
        zip(("train", "sealed-test"), secrets, strict=True)
    ):
        before = 'function authenticate(client) { client.token = "'
        after = '"; return client.connect(); }'
        content = before + secret + after
        path = content_root / f"sample-{index}.js"
        path.write_text(content, encoding="utf-8")
        rows.append(
            {
                "record_id": f"sample-{index}",
                "split": split,
                "corpus_id": "fixture-corpus",
                "corpus_sha256": CORPUS_DIGEST,
                "repository_family": f"repo/{index}",
                "credential_family": f"family/{index}",
                "secret": secret,
                "content_path": path.name,
                "credential_start": len(before),
                "credential_end": len(before) + len(secret),
            }
        )
    manifest.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    status = main(
        [
            str(manifest),
            "--content-root",
            str(content_root),
            "--receipt",
            str(receipt_path),
        ]
    )
    captured = capsys.readouterr()
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    assert status == 2
    assert not receipt["ok"]
    assert receipt["violation_count"] >= 1
    assert receipt["counts"]["raw_records"] == 2
    assert receipt["counts"]["deduplicated_records"] == 1
    visible = captured.out + captured.err + json.dumps(receipt)
    assert all(secret not in visible for secret in secrets)
