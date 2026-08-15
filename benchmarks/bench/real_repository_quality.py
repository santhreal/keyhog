"""Fail-closed quality gate for redacted real-repository evidence.

The harness accepts only opaque repository classes, canonical redacted labels,
and content digests. It never accepts repository names, paths, or finding bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import re
import stat
import subprocess
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass
from decimal import Decimal
from typing import Mapping, Sequence

from .keyhog_version import (
    KeyhogVersionError,
    assert_keyhog_binary_current,
    workspace_detector_digest,
    workspace_git_hash,
    workspace_keyhog_version,
)

REGISTRY_SCHEMA = "keyhog-real-repository-class-registry-v1"
EVIDENCE_SCHEMA = "keyhog-redacted-repository-evidence-v1"
IDENTITY_SCHEMA = "keyhog-current-source-binary-identity-v1"
REPORT_SCHEMA = "keyhog-real-repository-quality-report-v1"
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_CLASSES = 64
MAX_LABELS_PER_CLASS = 100_000
MAX_FINDINGS_PER_CLASS = 1_000_000
MAX_NOISE_FINDINGS_PER_MLOC = Decimal("2")

_CLASS_ID_RE = re.compile(r"rc-[0-9]{3}")
_LABEL_RE = re.compile(r"\[redacted:label-[0-9]{4,6}\]")
_CANARY_RE = re.compile(r"\[redacted:canary-[0-9]{4,6}\]")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_DETECTOR_DIGEST_RE = re.compile(r"[1-9][0-9]*-[0-9a-f]{16}")
_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")

_REASON_TIERS = {
    "unattributed": "review",
    "unsupported-context": "review",
    "required-evidence-missing": "review",
    "weak-anchor": "review",
    "generic-detector": "review",
    "generic-assignment": "review",
    "entropy-only": "review",
    "test-fixture": "review",
    "documentation": "review",
    "rule-definition": "review",
    "identifier": "review",
    "option-declaration": "review",
    "generated-material": "review",
    "source-role-mismatch": "review",
    "vendor-pattern": "likely",
    "structural-grammar": "confirmed",
    "required-companion": "confirmed",
    "checksum-valid": "confirmed",
    "live-verification": "confirmed",
}


class QualityGateError(ValueError):
    """Redacted benchmark evidence cannot prove the quality contract."""


@dataclass(frozen=True)
class RepositoryClass:
    class_id: str
    redacted_label: str
    max_findings_per_mloc: Decimal
    max_blocking_false_positives: int
    min_recall: Decimal
    min_canary_recall: Decimal


@dataclass(frozen=True)
class RepositoryClassRegistry:
    classes: Mapping[str, RepositoryClass]


@dataclass(frozen=True)
class RedactedLabel:
    redacted_label: str
    content_sha256: str
    outcome: str
    canary: bool


@dataclass(frozen=True)
class RedactedFinding:
    content_sha256: str
    label: str | None
    evidence_tier: str
    evidence_reason_code: str


@dataclass(frozen=True)
class RepositoryEvidence:
    class_id: str
    redacted_label: str
    source_content_sha256: str
    source_lines: int
    labels: tuple[RedactedLabel, ...]
    canaries: tuple[RedactedLabel, ...]
    findings: tuple[RedactedFinding, ...]


def _exact_keys(value: object, expected: set[str], what: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise QualityGateError(f"{what} schema is invalid")
    return value


def _strict_int(value: object, what: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise QualityGateError(f"{what} must be an integer >= {minimum}")
    return value


def _decimal(value: object, what: str, *, minimum: Decimal, maximum: Decimal) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise QualityGateError(f"{what} must be numeric")
    if isinstance(value, float) and not math.isfinite(value):
        raise QualityGateError(f"{what} must be finite")
    parsed = Decimal(str(value))
    if parsed < minimum or parsed > maximum:
        raise QualityGateError(f"{what} is outside its allowed range")
    return parsed


def _canonical_class_label(class_id: str) -> str:
    return f"[redacted:{class_id}]"


def _sha256(value: object, what: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise QualityGateError(f"{what} must be a lowercase SHA-256 digest")
    return value


def deterministic_canary_sha256(class_id: str, redacted_label: str) -> str:
    """Return the public deterministic canary digest without storing canary bytes."""
    seed = f"{EVIDENCE_SCHEMA}\0{class_id}\0{redacted_label}".encode()
    return hashlib.sha256(seed).hexdigest()


def _read_bounded(path: pathlib.Path) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise QualityGateError("quality input must be a regular file")
            data = handle.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        raise QualityGateError("quality input cannot be read") from exc
    if len(data) > MAX_INPUT_BYTES:
        raise QualityGateError("quality input exceeds the size limit")
    return data


def load_registry(path: str | pathlib.Path) -> RepositoryClassRegistry:
    """Load the authoritative runtime set of required repository classes."""
    try:
        raw = tomllib.loads(_read_bounded(pathlib.Path(path)).decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise QualityGateError("repository-class registry is not valid UTF-8 TOML") from exc
    root = _exact_keys(raw, {"schema", "repository_class"}, "repository-class registry")
    if root["schema"] != REGISTRY_SCHEMA:
        raise QualityGateError("repository-class registry schema version is invalid")
    rows = root["repository_class"]
    if not isinstance(rows, list) or not rows or len(rows) > MAX_CLASSES:
        raise QualityGateError("repository-class registry class count is invalid")

    classes: dict[str, RepositoryClass] = {}
    expected = {
        "id",
        "redacted_label",
        "max_findings_per_mloc",
        "max_blocking_false_positives",
        "min_recall",
        "min_canary_recall",
    }
    for row_value in rows:
        row = _exact_keys(row_value, expected, "repository-class entry")
        class_id = row["id"]
        if not isinstance(class_id, str) or _CLASS_ID_RE.fullmatch(class_id) is None:
            raise QualityGateError("repository-class ID is not canonical")
        label = row["redacted_label"]
        if label != _canonical_class_label(class_id):
            raise QualityGateError("repository-class redacted label is not canonical")
        if class_id in classes:
            raise QualityGateError("repository-class registry contains a duplicate ID")
        max_blocking_false_positives = _strict_int(
            row["max_blocking_false_positives"],
            "max_blocking_false_positives",
        )
        min_recall = _decimal(
            row["min_recall"],
            "min_recall",
            minimum=Decimal(0),
            maximum=Decimal(1),
        )
        min_canary_recall = _decimal(
            row["min_canary_recall"],
            "min_canary_recall",
            minimum=Decimal(0),
            maximum=Decimal(1),
        )
        if max_blocking_false_positives != 0:
            raise QualityGateError(
                "max_blocking_false_positives must be zero"
            )
        if min_recall != Decimal(1) or min_canary_recall != Decimal(1):
            raise QualityGateError("repository-class recall floors must be exact")
        classes[class_id] = RepositoryClass(
            class_id=class_id,
            redacted_label=label,
            max_findings_per_mloc=_decimal(
                row["max_findings_per_mloc"],
                "max_findings_per_mloc",
                minimum=Decimal(0),
                maximum=MAX_NOISE_FINDINGS_PER_MLOC,
            ),
            max_blocking_false_positives=max_blocking_false_positives,
            min_recall=min_recall,
            min_canary_recall=min_canary_recall,
        )
    return RepositoryClassRegistry(classes=classes)


def _load_label(value: object, *, class_id: str, canary: bool) -> RedactedLabel:
    row = _exact_keys(
        value,
        {"redacted_label", "content_sha256", "outcome"},
        "redacted ground-truth label",
    )
    label = row["redacted_label"]
    pattern = _CANARY_RE if canary else _LABEL_RE
    if not isinstance(label, str) or pattern.fullmatch(label) is None:
        raise QualityGateError("ground-truth redacted label is not canonical")
    digest = _sha256(row["content_sha256"], "ground-truth content hash")
    outcome = row["outcome"]
    if outcome not in {"matched", "missed"}:
        raise QualityGateError("ground-truth outcome must be matched or missed")
    if canary and digest != deterministic_canary_sha256(class_id, label):
        raise QualityGateError("deterministic canary content hash is invalid")
    return RedactedLabel(label, digest, outcome, canary)


def _load_finding(value: object) -> RedactedFinding:
    row = _exact_keys(
        value,
        {"content_sha256", "redacted_label", "evidence"},
        "redacted finding",
    )
    label = row["redacted_label"]
    if label is not None and (
        not isinstance(label, str)
        or (_LABEL_RE.fullmatch(label) is None and _CANARY_RE.fullmatch(label) is None)
    ):
        raise QualityGateError("finding label is not canonical or null")
    verdict = _exact_keys(
        row["evidence"], {"tier", "reason_code"}, "finding evidence"
    )
    reason = verdict["reason_code"]
    tier = verdict["tier"]
    if not isinstance(reason, str) or reason not in _REASON_TIERS:
        raise QualityGateError("finding evidence reason is invalid")
    if tier != _REASON_TIERS[reason]:
        raise QualityGateError("finding evidence tier does not match its reason")
    return RedactedFinding(
        content_sha256=_sha256(row["content_sha256"], "finding content hash"),
        label=label,
        evidence_tier=tier,
        evidence_reason_code=reason,
    )


def load_evidence(path: str | pathlib.Path) -> RepositoryEvidence:
    """Load one path-free, plaintext-free repository-class evidence manifest."""
    try:
        raw = json.loads(_read_bounded(pathlib.Path(path)))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise QualityGateError("repository evidence is not valid UTF-8 JSON") from exc
    root = _exact_keys(
        raw,
        {
            "schema",
            "repository_class_id",
            "redacted_label",
            "source_content_sha256",
            "source_lines",
            "labels",
            "canaries",
            "findings",
        },
        "repository evidence",
    )
    if root["schema"] != EVIDENCE_SCHEMA:
        raise QualityGateError("repository evidence schema version is invalid")
    class_id = root["repository_class_id"]
    if not isinstance(class_id, str) or _CLASS_ID_RE.fullmatch(class_id) is None:
        raise QualityGateError("repository evidence class ID is not canonical")
    if root["redacted_label"] != _canonical_class_label(class_id):
        raise QualityGateError("repository evidence redacted label is not canonical")

    labels_raw = root["labels"]
    canaries_raw = root["canaries"]
    findings_raw = root["findings"]
    if not isinstance(labels_raw, list) or not labels_raw or len(labels_raw) > MAX_LABELS_PER_CLASS:
        raise QualityGateError("repository evidence label count is invalid")
    if not isinstance(canaries_raw, list) or not canaries_raw or len(canaries_raw) > MAX_LABELS_PER_CLASS:
        raise QualityGateError("repository evidence canary count is invalid")
    if not isinstance(findings_raw, list) or len(findings_raw) > MAX_FINDINGS_PER_CLASS:
        raise QualityGateError("repository evidence finding count is invalid")

    labels = tuple(_load_label(value, class_id=class_id, canary=False) for value in labels_raw)
    canaries = tuple(_load_label(value, class_id=class_id, canary=True) for value in canaries_raw)
    all_labels = labels + canaries
    label_names = [label.redacted_label for label in all_labels]
    if len(label_names) != len(set(label_names)):
        raise QualityGateError("repository evidence contains duplicate redacted labels")
    content_hashes = [label.content_sha256 for label in all_labels]
    if len(content_hashes) != len(set(content_hashes)):
        raise QualityGateError("repository evidence contains duplicate ground-truth hashes")

    findings = tuple(_load_finding(value) for value in findings_raw)
    known = {label.redacted_label: label for label in all_labels}
    matched = Counter(finding.label for finding in findings if finding.label is not None)
    if any(label not in known for label in matched):
        raise QualityGateError("finding references an undeclared redacted label")
    for finding in findings:
        if finding.label is not None and (
            finding.content_sha256 != known[finding.label].content_sha256
        ):
            raise QualityGateError(
                "finding content hash disagrees with its redacted label"
            )
    for label in all_labels:
        observed = matched[label.redacted_label] > 0
        if observed != (label.outcome == "matched"):
            raise QualityGateError("ground-truth outcome disagrees with redacted findings")

    return RepositoryEvidence(
        class_id=class_id,
        redacted_label=root["redacted_label"],
        source_content_sha256=_sha256(
            root["source_content_sha256"], "source content hash"
        ),
        source_lines=_strict_int(root["source_lines"], "source_lines", minimum=1),
        labels=labels,
        canaries=canaries,
        findings=findings,
    )


def load_evidence_directory(path: str | pathlib.Path) -> Mapping[str, RepositoryEvidence]:
    """Load every JSON evidence manifest; the contained IDs, not filenames, are authoritative."""
    directory = pathlib.Path(path)
    if not directory.is_dir():
        raise QualityGateError("repository evidence directory is unavailable")
    try:
        paths = sorted(directory.glob("*.json"))
    except OSError as exc:
        raise QualityGateError("repository evidence directory cannot be enumerated") from exc
    if not paths or len(paths) > MAX_CLASSES:
        raise QualityGateError("repository evidence file count is invalid")
    evidence: dict[str, RepositoryEvidence] = {}
    for item in paths:
        loaded = load_evidence(item)
        if loaded.class_id in evidence:
            raise QualityGateError("repository evidence contains a duplicate class ID")
        evidence[loaded.class_id] = loaded
    return evidence


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise QualityGateError("candidate binary cannot be hashed") from exc
    return digest.hexdigest()


def capture_binary_identity(
    binary: str | pathlib.Path, *, repo_root: pathlib.Path | None = None
) -> dict[str, str]:
    """Create a source-built identity receipt after proving the binary is current."""
    root = repo_root or pathlib.Path(__file__).resolve().parents[2]
    try:
        binary_path = pathlib.Path(binary).resolve(strict=True)
        assert_keyhog_binary_current(str(binary_path), repo_root=root)
        return {
            "schema": IDENTITY_SCHEMA,
            "executable_sha256": _sha256_file(binary_path),
            "source_commit": workspace_git_hash(root),
            "source_version": workspace_keyhog_version(root),
            "detector_set_digest": workspace_detector_digest(root),
        }
    except (KeyhogVersionError, subprocess.SubprocessError, OSError) as exc:
        raise QualityGateError(
            f"candidate binary cannot prove current-source identity: {exc}"
        ) from exc


def validate_binary_identity(value: object, current: Mapping[str, str]) -> dict[str, str]:
    """Reject malformed, stale, or mismatched identity receipts."""
    expected = {
        "schema",
        "executable_sha256",
        "source_commit",
        "source_version",
        "detector_set_digest",
    }
    row = _exact_keys(value, expected, "binary identity receipt")
    if row["schema"] != IDENTITY_SCHEMA:
        raise QualityGateError("binary identity receipt schema version is invalid")
    _sha256(row["executable_sha256"], "binary executable hash")
    if not isinstance(row["source_commit"], str) or _COMMIT_RE.fullmatch(row["source_commit"]) is None:
        raise QualityGateError("binary source commit is invalid")
    if (
        not isinstance(row["source_version"], str)
        or _VERSION_RE.fullmatch(row["source_version"]) is None
    ):
        raise QualityGateError("binary source version is invalid")
    if not isinstance(row["detector_set_digest"], str) or _DETECTOR_DIGEST_RE.fullmatch(row["detector_set_digest"]) is None:
        raise QualityGateError("binary detector-set digest is invalid")
    if dict(row) != dict(current):
        raise QualityGateError("binary identity receipt is stale or mismatched")
    return {key: str(row[key]) for key in sorted(expected)}


def load_binary_identity(path: str | pathlib.Path) -> object:
    try:
        return json.loads(_read_bounded(pathlib.Path(path)))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise QualityGateError("binary identity receipt is not valid UTF-8 JSON") from exc


def evaluate_quality(
    registry: RepositoryClassRegistry,
    evidence: Mapping[str, RepositoryEvidence],
    binary_identity: Mapping[str, str],
    current_binary_identity: Mapping[str, str],
) -> dict[str, object]:
    """Score every required class and fail on any coverage or threshold gap."""
    binary_identity = validate_binary_identity(binary_identity, current_binary_identity)
    required = set(registry.classes)
    observed = set(evidence)
    if required != observed:
        raise QualityGateError("repository-class coverage is incomplete or unexpected")

    class_reports: list[dict[str, object]] = []
    violations: list[str] = []
    for class_id in sorted(required):
        spec = registry.classes[class_id]
        sample = evidence[class_id]
        if sample.redacted_label != spec.redacted_label:
            raise QualityGateError("repository-class redacted labels disagree")
        if not sample.labels or not sample.canaries:
            raise QualityGateError(
                f"{class_id}: repository evidence requires labels and canaries"
            )
        matched_labels = sum(label.outcome == "matched" for label in sample.labels)
        matched_canaries = sum(label.outcome == "matched" for label in sample.canaries)
        recall = Decimal(matched_labels) / Decimal(len(sample.labels))
        canary_recall = Decimal(matched_canaries) / Decimal(len(sample.canaries))
        noise_findings = sum(finding.label is None for finding in sample.findings)
        findings_per_mloc = (
            Decimal(noise_findings)
            * Decimal(1_000_000)
            / Decimal(sample.source_lines)
        )
        blocking_false_positives = sum(
            finding.label is None and finding.evidence_tier != "review"
            for finding in sample.findings
        )
        if findings_per_mloc > spec.max_findings_per_mloc:
            violations.append(f"{class_id}:findings-per-mloc")
        if blocking_false_positives > spec.max_blocking_false_positives:
            violations.append(f"{class_id}:blocking-false-positives")
        if recall < spec.min_recall:
            violations.append(f"{class_id}:recall")
        if canary_recall < spec.min_canary_recall:
            violations.append(f"{class_id}:canary-recall")

        class_reports.append(
            {
                "repository_class_id": class_id,
                "redacted_label": sample.redacted_label,
                "source_content_sha256": sample.source_content_sha256,
                "source_lines": sample.source_lines,
                "findings_per_mloc": float(findings_per_mloc),
                "blocking_false_positives": blocking_false_positives,
                "recall": float(recall),
                "canary_recall": float(canary_recall),
                "labels": [
                    {
                        "redacted_label": label.redacted_label,
                        "content_sha256": label.content_sha256,
                        "outcome": label.outcome,
                    }
                    for label in sample.labels
                ],
                "canaries": [
                    {
                        "redacted_label": canary.redacted_label,
                        "content_sha256": canary.content_sha256,
                        "outcome": canary.outcome,
                    }
                    for canary in sample.canaries
                ],
                "findings": [
                    {
                        "content_sha256": finding.content_sha256,
                        "redacted_label": finding.label,
                        "evidence": {
                            "tier": finding.evidence_tier,
                            "reason_code": finding.evidence_reason_code,
                        },
                    }
                    for finding in sample.findings
                ],
            }
        )
    if violations:
        raise QualityGateError("quality thresholds failed: " + ", ".join(violations))
    return {
        "schema": REPORT_SCHEMA,
        "binary_identity": dict(binary_identity),
        "repository_classes": class_reports,
    }


def _write_json(path: pathlib.Path, value: object) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise QualityGateError(f"quality output cannot be written: {exc}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the redacted real-repository quality gate.")
    sub = parser.add_subparsers(dest="command", required=True)
    identity = sub.add_parser("identity", help="capture a current-source binary identity receipt")
    identity.add_argument("--binary", required=True, type=pathlib.Path)
    identity.add_argument("--output", required=True, type=pathlib.Path)
    gate = sub.add_parser("gate", help="validate evidence and enforce every repository class")
    gate.add_argument("--registry", required=True, type=pathlib.Path)
    gate.add_argument("--evidence-dir", required=True, type=pathlib.Path)
    gate.add_argument("--binary", required=True, type=pathlib.Path)
    gate.add_argument("--identity-receipt", required=True, type=pathlib.Path)
    gate.add_argument("--output", required=True, type=pathlib.Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        current = capture_binary_identity(args.binary)
        if args.command == "identity":
            _write_json(args.output, current)
            return 0
        report = evaluate_quality(
            load_registry(args.registry),
            load_evidence_directory(args.evidence_dir),
            load_binary_identity(args.identity_receipt),
            current,
        )
        _write_json(args.output, report)
        return 0
    except QualityGateError as exc:
        print(f"real-repository quality gate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
