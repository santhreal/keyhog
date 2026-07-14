"""Privacy-safe cross-split leakage audit for secret-detection corpora."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import pathlib
import re
import sys
import unicodedata
from collections import Counter, defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

SCHEMA_VERSION = "keyhog-benchmark-leakage-v1"
VALID_SPLITS = frozenset({"train", "calibration", "sealed-test"})
CONTEXT_CHARS = 200
BYTE_SHINGLE_SIZE = 5
STRUCTURE_SHINGLE_SIZE = 4
UNIQUE_TOKEN_JACCARD = 0.80
TOKEN_MULTISET_JACCARD = 0.70
BYTE_JACCARD = 0.90
STRUCTURE_JACCARD = 0.90
MIN_STRUCTURE_SHINGLES = 6
DEFAULT_MAX_PAIR_COMPARISONS = 5_000_000
MAX_CONTENT_CHARS = 8 * 1024 * 1024
MAX_CONTENT_BYTES = MAX_CONTENT_CHARS * 4
MAX_TOTAL_CONTENT_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024 * 1024
MAX_PROVENANCE_CHARS = 4096
MAX_RECORDS = 100_000
MAX_VIOLATION_DETAILS = 50

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}\Z")
_TOKEN_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*"
    r"|0[xX][0-9A-Fa-f]+"
    r"|\d+(?:\.\d+)?"
    r'|"(?:\\.|[^"\\])*"'
    r"|'(?:\\.|[^'\\])*'"
    r"|==|!=|<=|>=|=>|->|::|&&|\|\|"
    r"|[^\s]"
)
_KEYWORDS = frozenset(
    {
        "as",
        "async",
        "await",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "def",
        "default",
        "do",
        "else",
        "enum",
        "except",
        "export",
        "false",
        "finally",
        "fn",
        "for",
        "from",
        "function",
        "if",
        "import",
        "in",
        "let",
        "match",
        "new",
        "none",
        "null",
        "return",
        "static",
        "struct",
        "switch",
        "throw",
        "true",
        "try",
        "var",
        "while",
        "with",
        "yield",
    }
)


class LeakageGuardError(ValueError):
    """The split manifest or similarity audit is invalid or leaky."""


@dataclass(frozen=True)
class LeakageRecord:
    """One labeled benchmark sample with complete split provenance."""

    record_id: str
    split: str
    corpus_id: str
    corpus_sha256: str
    repository_family: str
    credential_family: str
    credential: str
    content: str
    credential_start: int
    credential_end: int

    def __post_init__(self) -> None:
        string_values = (
            self.record_id,
            self.split,
            self.corpus_id,
            self.corpus_sha256,
            self.repository_family,
            self.credential_family,
            self.credential,
            self.content,
        )
        if any(not isinstance(value, str) for value in string_values) or any(
            type(value) is not int
            for value in (self.credential_start, self.credential_end)
        ):
            raise LeakageGuardError("leakage record fields have invalid types")
        if not _SAFE_ID_RE.fullmatch(self.record_id):
            raise LeakageGuardError("record_id must be a safe non-secret identifier")
        if self.split not in VALID_SPLITS:
            raise LeakageGuardError(
                f"record {self.record_id!r} has unsupported split {self.split!r}"
            )
        if not _SAFE_ID_RE.fullmatch(self.corpus_id):
            raise LeakageGuardError(f"record {self.record_id!r} has invalid corpus_id")
        if not _SHA256_RE.fullmatch(self.corpus_sha256):
            raise LeakageGuardError(
                f"record {self.record_id!r} has non-canonical corpus_sha256"
            )
        if not self.repository_family.strip() or not self.credential_family.strip():
            raise LeakageGuardError(
                f"record {self.record_id!r} is missing repository or credential family provenance"
            )
        if (
            len(self.repository_family) > MAX_PROVENANCE_CHARS
            or len(self.credential_family) > MAX_PROVENANCE_CHARS
        ):
            raise LeakageGuardError(
                f"record {self.record_id!r} provenance exceeds {MAX_PROVENANCE_CHARS} characters"
            )
        if not self.credential:
            raise LeakageGuardError(
                f"record {self.record_id!r} has an empty credential"
            )
        if len(self.content) > MAX_CONTENT_CHARS:
            raise LeakageGuardError(
                f"record {self.record_id!r} content exceeds {MAX_CONTENT_CHARS} characters"
            )
        if not (0 <= self.credential_start < self.credential_end <= len(self.content)):
            raise LeakageGuardError(
                f"record {self.record_id!r} has an invalid credential span"
            )
        if self.content[self.credential_start : self.credential_end] != self.credential:
            raise LeakageGuardError(
                f"record {self.record_id!r} credential span does not match its ground truth"
            )
        if self.credential in self.record_id or self.credential in self.corpus_id:
            raise LeakageGuardError(
                "record and corpus identifiers must not contain credential bytes"
            )


@dataclass(frozen=True)
class LeakageViolation:
    """One privacy-safe cross-split group."""

    reason: str
    record_ids: tuple[str, ...]
    splits: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "reason": self.reason,
            "record_ids": list(self.record_ids),
            "splits": list(self.splits),
        }


@dataclass(frozen=True)
class LeakageReceipt:
    """Deterministic audit receipt containing no credential or context bytes."""

    input_manifest_sha256: str
    source_digest: str
    split_digest: str
    policy_digest: str
    grouping_digest: str
    receipt_digest: str
    corpora: tuple[tuple[str, str], ...]
    raw_records: int
    deduplicated_records: int
    assignment_groups: int
    per_split: Mapping[str, Mapping[str, int]]
    comparison_count: int
    violation_count: int
    omitted_violation_details: int
    violations: tuple[LeakageViolation, ...]

    @property
    def ok(self) -> bool:
        return self.violation_count == 0

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "ok": self.ok,
            "input_manifest_sha256": self.input_manifest_sha256,
            "source_digest": self.source_digest,
            "split_digest": self.split_digest,
            "policy_digest": self.policy_digest,
            "grouping_digest": self.grouping_digest,
            "receipt_digest": self.receipt_digest,
            "corpora": [
                {"corpus_id": corpus_id, "corpus_sha256": digest}
                for corpus_id, digest in self.corpora
            ],
            "counts": {
                "raw_records": self.raw_records,
                "deduplicated_records": self.deduplicated_records,
                "removed_exact_or_near_duplicates": (
                    self.raw_records - self.deduplicated_records
                ),
                "assignment_groups": self.assignment_groups,
                "pair_comparisons": self.comparison_count,
            },
            "per_split": {
                split: dict(counts) for split, counts in sorted(self.per_split.items())
            },
            "violation_count": self.violation_count,
            "omitted_violation_details": self.omitted_violation_details,
            "violations": [violation.to_json() for violation in self.violations],
        }

    def require_clean(self) -> None:
        if not self.ok:
            reasons = ", ".join(
                f"{violation.reason}:{'/'.join(violation.record_ids)}"
                for violation in self.violations[:5]
            )
            raise LeakageGuardError(
                f"benchmark split leakage detected in {self.violation_count} group(s): {reasons}"
            )


@dataclass(frozen=True)
class _Fingerprint:
    redacted_content_sha256: str
    exact_context_sha256: str
    byte_shingles: frozenset[int]
    token_set: frozenset[str]
    token_multiset: Counter[str]
    structure_shingles: frozenset[int]


class _DisjointSet:
    def __init__(self, size: int):
        self.parent = list(range(size))
        self.rank = [0] * size
        self.reasons: list[set[str]] = [set() for _ in range(size)]

    def find(self, item: int) -> int:
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != item:
            parent = self.parent[item]
            self.parent[item] = root
            item = parent
        return root

    def union(self, left: int, right: int, reason: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            self.reasons[left_root].add(reason)
            return
        if self.rank[left_root] < self.rank[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        self.reasons[left_root].update(self.reasons[right_root])
        self.reasons[left_root].add(reason)
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1

    def groups(self) -> list[tuple[tuple[int, ...], tuple[str, ...]]]:
        members: dict[int, list[int]] = defaultdict(list)
        for index in range(len(self.parent)):
            members[self.find(index)].append(index)
        return [
            (tuple(indices), tuple(sorted(self.reasons[self.find(root)])))
            for root, indices in sorted(members.items(), key=lambda item: item[1][0])
        ]


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _private_key(domain: str, value: str) -> str:
    return hashlib.sha256(f"{domain}\0{value}".encode()).hexdigest()


def _contains_any(values: Iterable[str], patterns: Iterable[str]) -> bool:
    transitions: list[dict[str, int]] = [{}]
    failures = [0]
    terminal = [False]
    for pattern in set(patterns):
        state = 0
        for character in pattern:
            next_state = transitions[state].get(character)
            if next_state is None:
                next_state = len(transitions)
                transitions[state][character] = next_state
                transitions.append({})
                failures.append(0)
                terminal.append(False)
            state = next_state
        terminal[state] = True

    pending = deque(transitions[0].values())
    while pending:
        state = pending.popleft()
        for character, child in transitions[state].items():
            pending.append(child)
            fallback = failures[state]
            while fallback and character not in transitions[fallback]:
                fallback = failures[fallback]
            failures[child] = transitions[fallback].get(character, 0)
            terminal[child] = terminal[child] or terminal[failures[child]]

    for value in values:
        state = 0
        for character in value:
            while state and character not in transitions[state]:
                state = failures[state]
            state = transitions[state].get(character, 0)
            if terminal[state]:
                return True
    return False


def _normalize_repository_family(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip().replace("\\", "/")
    if re.match(r"^[^/@\s]+@[^:/\s]+:", normalized):
        user_host, path = normalized.split(":", 1)
        normalized = f"{user_host.split('@', 1)[1]}/{path}"
    elif "://" in normalized:
        parsed = urlsplit(normalized)
        normalized = f"{parsed.hostname or ''}/{parsed.path.lstrip('/')}"
    normalized = normalized.rstrip("/")
    if normalized.casefold().endswith(".git"):
        normalized = normalized[:-4]
    normalized = re.sub(r"/+", "/", normalized).casefold()
    if not normalized:
        raise LeakageGuardError("repository family becomes empty after normalization")
    return normalized


def _normalize_family(value: str) -> str:
    normalized = " ".join(unicodedata.normalize("NFKC", value).casefold().split())
    if not normalized:
        raise LeakageGuardError("credential family becomes empty after normalization")
    return normalized


def _normalize_credential(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).replace("\r\n", "\n")
    normalized = normalized.replace("\r", "\n").strip()
    while (
        len(normalized) >= 2
        and normalized[0] == normalized[-1]
        and normalized[0] in "'\"`"
    ):
        normalized = normalized[1:-1].strip()
    if not normalized:
        raise LeakageGuardError("credential becomes empty after normalization")
    return normalized


def _redacted_context(record: LeakageRecord) -> str:
    before = record.content[
        max(0, record.credential_start - CONTEXT_CHARS) : record.credential_start
    ]
    after = record.content[
        record.credential_end : record.credential_end + CONTEXT_CHARS
    ]
    return unicodedata.normalize("NFKC", f"{before}\n<CREDENTIAL>\n{after}")


def _redacted_content(record: LeakageRecord) -> str:
    return unicodedata.normalize(
        "NFKC",
        f"{record.content[: record.credential_start]}<CREDENTIAL>"
        f"{record.content[record.credential_end :]}",
    )


def _hashed_shingles(
    items: Sequence[object], width: int, domain: bytes
) -> frozenset[int]:
    if not items:
        return frozenset()
    windows: Iterable[Sequence[object]]
    if len(items) < width:
        windows = (items,)
    else:
        windows = (
            items[index : index + width] for index in range(len(items) - width + 1)
        )
    output = set()
    for window in windows:
        encoded = _canonical_json(list(window))
        output.add(
            int.from_bytes(
                hashlib.blake2b(encoded, digest_size=8, person=domain).digest()
            )
        )
    return frozenset(output)


def _structure_token(token: str) -> str:
    folded = token.casefold()
    if folded in _KEYWORDS:
        return folded
    if token[0] in "'\"" or token[0].isdigit():
        return "<literal>"
    if token[0].isalpha() or token[0] == "_":
        return "<identifier>"
    return token


def _is_research_context_token(token: str) -> bool:
    """Match the paper's identifier-and-literal near-duplicate token domain."""

    folded = token.casefold()
    return (
        (token[0].isalpha() or token[0] == "_") and folded not in _KEYWORDS
    ) or token[0] in "'\"" or token[0].isdigit()


def _fingerprint(record: LeakageRecord) -> _Fingerprint:
    context = _redacted_context(record)
    tokens = _TOKEN_RE.findall(context)
    research_tokens = [token for token in tokens if _is_research_context_token(token)]
    structure = [_structure_token(token) for token in tokens]
    return _Fingerprint(
        redacted_content_sha256=hashlib.sha256(
            _redacted_content(record).encode()
        ).hexdigest(),
        exact_context_sha256=hashlib.sha256(context.encode()).hexdigest(),
        byte_shingles=_hashed_shingles(
            list(context.encode("utf-8")), BYTE_SHINGLE_SIZE, b"kh-byte-v1"
        ),
        token_set=frozenset(research_tokens),
        token_multiset=Counter(research_tokens),
        structure_shingles=_hashed_shingles(
            structure, STRUCTURE_SHINGLE_SIZE, b"kh-struct-v1"
        ),
    )


def _set_jaccard(left: frozenset[object], right: frozenset[object]) -> float:
    union = len(left | right)
    return len(left & right) / union if union else 1.0


def _multiset_jaccard(left: Counter[str], right: Counter[str]) -> float:
    keys = left.keys() | right.keys()
    union = sum(max(left[key], right[key]) for key in keys)
    return sum(min(left[key], right[key]) for key in keys) / union if union else 1.0


def _candidate_pairs(
    fingerprints: Sequence[frozenset[object]], threshold: float
) -> Iterable[tuple[int, int]]:
    frequencies: Counter[object] = Counter()
    for fingerprint in fingerprints:
        frequencies.update(fingerprint)
    index: dict[object, list[int]] = defaultdict(list)
    ordered_indices = sorted(
        range(len(fingerprints)), key=lambda idx: (len(fingerprints[idx]), idx)
    )
    for right in ordered_indices:
        current = fingerprints[right]
        if not current:
            continue
        ordered = sorted(current, key=lambda token: (frequencies[token], repr(token)))
        prefix_len = len(current) - math.ceil(threshold * len(current)) + 1
        candidates: set[int] = set()
        for token in ordered[:prefix_len]:
            candidates.update(index[token])
        minimum_size = math.ceil(threshold * len(current))
        maximum_size = math.floor(len(current) / threshold)
        for left in sorted(candidates):
            if minimum_size <= len(fingerprints[left]) <= maximum_size:
                yield left, right
        for token in ordered[:prefix_len]:
            index[token].append(right)


def _group_by_key(keys: Sequence[str]) -> list[tuple[int, ...]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, key in enumerate(keys):
        groups[key].append(index)
    return [tuple(members) for _key, members in sorted(groups.items())]


def _union_group(target: _DisjointSet, group: Sequence[int], reason: str) -> None:
    if len(group) < 2:
        return
    first = group[0]
    for member in group[1:]:
        target.union(first, member, reason)


def _cross_split_violations(
    records: Sequence[LeakageRecord],
    groups: Iterable[tuple[Sequence[int], Sequence[str]]],
) -> list[LeakageViolation]:
    violations = []
    for members, reasons in groups:
        splits = tuple(sorted({records[index].split for index in members}))
        if len(splits) < 2:
            continue
        ids = tuple(sorted(records[index].record_id for index in members))
        for reason in reasons:
            violations.append(LeakageViolation(reason, ids, splits))
    return violations


def _policy() -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "context_chars_each_side": CONTEXT_CHARS,
        "credential_excluded_from_context": True,
        "byte_shingle_size": BYTE_SHINGLE_SIZE,
        "structure_shingle_size": STRUCTURE_SHINGLE_SIZE,
        "unique_token_jaccard": UNIQUE_TOKEN_JACCARD,
        "token_multiset_jaccard": TOKEN_MULTISET_JACCARD,
        "byte_jaccard": BYTE_JACCARD,
        "structure_jaccard": STRUCTURE_JACCARD,
        "minimum_structure_shingles": MIN_STRUCTURE_SHINGLES,
    }


def audit_splits(
    records: Sequence[LeakageRecord],
    *,
    input_manifest_sha256: str,
    max_pair_comparisons: int = DEFAULT_MAX_PAIR_COMPARISONS,
) -> LeakageReceipt:
    """Audit three-way split isolation and return a credential-free receipt."""

    if not records:
        raise LeakageGuardError("leakage audit requires at least one record")
    if len(records) > MAX_RECORDS:
        raise LeakageGuardError(
            f"leakage audit exceeds the {MAX_RECORDS}-record in-memory limit"
        )
    if not isinstance(input_manifest_sha256, str) or not _SHA256_RE.fullmatch(
        input_manifest_sha256
    ):
        raise LeakageGuardError("input_manifest_sha256 must be canonical SHA-256")
    if type(max_pair_comparisons) is not int or max_pair_comparisons <= 0:
        raise LeakageGuardError("max_pair_comparisons must be positive")
    record_ids = [record.record_id for record in records]
    if len(set(record_ids)) != len(record_ids):
        raise LeakageGuardError("leakage audit record IDs must be unique")
    public_identifiers = [
        identifier
        for record in records
        for identifier in (record.record_id, record.corpus_id)
    ]
    normalized_public_identifiers = [
        unicodedata.normalize("NFKC", identifier) for identifier in public_identifiers
    ]
    normalized_credentials = [
        _normalize_credential(record.credential) for record in records
    ]
    longest_identifier = max(map(len, normalized_public_identifiers))
    public_matchable_credentials = (
        credential
        for credential in normalized_credentials
        if len(credential) <= longest_identifier
    )
    if _contains_any(normalized_public_identifiers, public_matchable_credentials):
        raise LeakageGuardError(
            "record and corpus identifiers must not contain credential bytes"
        )

    corpus_digests: dict[str, str] = {}
    for record in records:
        previous = corpus_digests.setdefault(record.corpus_id, record.corpus_sha256)
        if previous != record.corpus_sha256:
            raise LeakageGuardError(
                f"corpus {record.corpus_id!r} has conflicting provenance digests"
            )

    fingerprints = [_fingerprint(record) for record in records]
    repository_keys = [
        _private_key(
            "repository", _normalize_repository_family(record.repository_family)
        )
        for record in records
    ]
    family_keys = [
        _private_key("credential-family", _normalize_family(record.credential_family))
        for record in records
    ]
    credential_keys = [
        _private_key("credential-value", credential)
        for credential in normalized_credentials
    ]
    repository_groups = _group_by_key(repository_keys)
    family_groups = _group_by_key(family_keys)
    credential_groups = _group_by_key(credential_keys)

    content = _DisjointSet(len(records))
    exact_groups = _group_by_key(
        [fingerprint.exact_context_sha256 for fingerprint in fingerprints]
    )
    for group in exact_groups:
        _union_group(content, group, "exact-context")

    comparisons = 0

    def compare(axis: str, sets: Sequence[frozenset[object]], threshold: float) -> None:
        nonlocal comparisons
        for left, right in _candidate_pairs(sets, threshold):
            comparisons += 1
            if comparisons > max_pair_comparisons:
                raise LeakageGuardError(
                    "leakage similarity comparison cap exceeded; split the corpus by a stable provenance partition or raise the explicit audit cap"
                )
            similarity = _set_jaccard(sets[left], sets[right])
            if similarity < threshold:
                continue
            if (
                axis == "token"
                and _multiset_jaccard(
                    fingerprints[left].token_multiset,
                    fingerprints[right].token_multiset,
                )
                < TOKEN_MULTISET_JACCARD
            ):
                continue
            if (
                axis == "structure"
                and min(len(sets[left]), len(sets[right])) < MIN_STRUCTURE_SHINGLES
            ):
                continue
            content.union(left, right, f"near-{axis}")

    compare(
        "token",
        [fingerprint.token_set for fingerprint in fingerprints],
        UNIQUE_TOKEN_JACCARD,
    )
    compare(
        "byte",
        [fingerprint.byte_shingles for fingerprint in fingerprints],
        BYTE_JACCARD,
    )
    compare(
        "structure",
        [fingerprint.structure_shingles for fingerprint in fingerprints],
        STRUCTURE_JACCARD,
    )

    assignment = _DisjointSet(len(records))
    for group in repository_groups:
        _union_group(assignment, group, "repository-family")
    for group in family_groups:
        _union_group(assignment, group, "credential-family")
    for group in credential_groups:
        _union_group(assignment, group, "credential-value")
    for members, reasons in content.groups():
        for reason in reasons:
            _union_group(assignment, members, reason)

    relation_groups = {
        "repository-family": repository_groups,
        "credential-family": family_groups,
        "credential-value": credential_groups,
        "content": [members for members, _reasons in content.groups()],
        "assignment": [members for members, _reasons in assignment.groups()],
    }
    grouping_projection = {
        axis: sorted(
            sorted(records[index].record_id for index in members) for members in groups
        )
        for axis, groups in relation_groups.items()
    }

    violations = []
    violations.extend(
        _cross_split_violations(
            records, ((group, ("repository-family",)) for group in repository_groups)
        )
    )
    violations.extend(
        _cross_split_violations(
            records, ((group, ("credential-family",)) for group in family_groups)
        )
    )
    violations.extend(
        _cross_split_violations(
            records, ((group, ("credential-value",)) for group in credential_groups)
        )
    )
    violations.extend(_cross_split_violations(records, content.groups()))
    violations = sorted(
        set(violations), key=lambda item: (item.reason, item.record_ids, item.splits)
    )

    content_roots = [content.find(index) for index in range(len(records))]
    assignment_roots = [assignment.find(index) for index in range(len(records))]
    per_split: dict[str, dict[str, int]] = {}
    for split in sorted(VALID_SPLITS):
        indices = [
            index for index, record in enumerate(records) if record.split == split
        ]
        per_split[split] = {
            "raw_records": len(indices),
            "deduplicated_records": len({content_roots[index] for index in indices}),
            "assignment_groups": len({assignment_roots[index] for index in indices}),
        }

    policy_digest = _digest(_policy())
    source_projection = {
        "input_manifest_sha256": input_manifest_sha256,
        "corpora": sorted(corpus_digests.items()),
        "records": sorted(
            (
                record.record_id,
                record.corpus_id,
                record.corpus_sha256,
                repository_keys[index],
                family_keys[index],
                credential_keys[index],
                fingerprints[index].redacted_content_sha256,
                fingerprints[index].exact_context_sha256,
            )
            for index, record in enumerate(records)
        ),
    }
    split_projection = sorted((record.record_id, record.split) for record in records)
    base = {
        "schema_version": SCHEMA_VERSION,
        "input_manifest_sha256": input_manifest_sha256,
        "source_digest": _digest(source_projection),
        "split_digest": _digest(split_projection),
        "policy_digest": policy_digest,
        "grouping_digest": _digest(grouping_projection),
        "raw_records": len(records),
        "deduplicated_records": len(set(content_roots)),
        "assignment_groups": len(set(assignment_roots)),
        "per_split": per_split,
        "comparison_count": comparisons,
        "violation_count": len(violations),
        "violations": [violation.to_json() for violation in violations],
    }
    receipt_digest = _digest(base)
    visible = tuple(violations[:MAX_VIOLATION_DETAILS])
    return LeakageReceipt(
        input_manifest_sha256=input_manifest_sha256,
        source_digest=base["source_digest"],
        split_digest=base["split_digest"],
        policy_digest=policy_digest,
        grouping_digest=base["grouping_digest"],
        receipt_digest=receipt_digest,
        corpora=tuple(sorted(corpus_digests.items())),
        raw_records=len(records),
        deduplicated_records=len(set(content_roots)),
        assignment_groups=len(set(assignment_roots)),
        per_split=per_split,
        comparison_count=comparisons,
        violation_count=len(violations),
        omitted_violation_details=len(violations) - len(visible),
        violations=visible,
    )


_MANIFEST_FIELDS = frozenset(
    {
        "record_id",
        "split",
        "corpus_id",
        "corpus_sha256",
        "repository_family",
        "credential_family",
        "secret",
        "content_path",
        "credential_start",
        "credential_end",
    }
)


def load_split_manifest(
    manifest: pathlib.Path, content_root: pathlib.Path
) -> tuple[list[LeakageRecord], str]:
    """Load a strict JSONL split manifest and its bounded UTF-8 source files."""

    with manifest.open("rb") as manifest_file:
        raw = manifest_file.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise LeakageGuardError(f"split manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    manifest_digest = hashlib.sha256(raw).hexdigest()
    root = content_root.resolve(strict=True)
    if not root.is_dir():
        raise LeakageGuardError("content root must be a directory")
    records = []
    content_cache: dict[pathlib.Path, str] = {}
    total_content_bytes = 0
    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LeakageGuardError(
                f"split manifest line {line_number} is invalid JSON"
            ) from exc
        if not isinstance(row, dict) or set(row) != _MANIFEST_FIELDS:
            raise LeakageGuardError(
                f"split manifest line {line_number} fields do not match schema"
            )
        string_fields = _MANIFEST_FIELDS - {"credential_start", "credential_end"}
        if any(not isinstance(row[field], str) for field in string_fields) or any(
            type(row[field]) is not int
            for field in ("credential_start", "credential_end")
        ):
            raise LeakageGuardError(
                f"split manifest line {line_number} fields have invalid JSON types"
            )
        relative = pathlib.PurePosixPath(row["content_path"])
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not relative.parts
            or "\\" in row["content_path"]
        ):
            raise LeakageGuardError(
                f"split manifest line {line_number} has unsafe content_path"
            )
        path = root.joinpath(*relative.parts).resolve(strict=True)
        if root not in path.parents or not path.is_file():
            raise LeakageGuardError(
                f"split manifest line {line_number} content_path escapes its root"
            )
        content = content_cache.get(path)
        if content is None:
            with path.open("rb") as content_file:
                payload = content_file.read(MAX_CONTENT_BYTES + 1)
            if len(payload) > MAX_CONTENT_BYTES:
                raise LeakageGuardError(
                    f"split manifest line {line_number} content exceeds byte limit"
                )
            total_content_bytes += len(payload)
            if total_content_bytes > MAX_TOTAL_CONTENT_BYTES:
                raise LeakageGuardError(
                    f"split manifest content exceeds the {MAX_TOTAL_CONTENT_BYTES}-byte aggregate limit"
                )
            try:
                content = payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise LeakageGuardError(
                    f"split manifest line {line_number} content is not UTF-8"
                ) from exc
            content_cache[path] = content
        try:
            records.append(
                LeakageRecord(
                    record_id=row["record_id"],
                    split=row["split"],
                    corpus_id=row["corpus_id"],
                    corpus_sha256=row["corpus_sha256"],
                    repository_family=row["repository_family"],
                    credential_family=row["credential_family"],
                    credential=row["secret"],
                    content=content,
                    credential_start=row["credential_start"],
                    credential_end=row["credential_end"],
                )
            )
            if len(records) > MAX_RECORDS:
                raise LeakageGuardError(
                    f"split manifest exceeds the {MAX_RECORDS}-record limit"
                )
        except (TypeError, ValueError) as exc:
            if isinstance(exc, LeakageGuardError):
                raise
            raise LeakageGuardError(
                f"split manifest line {line_number} has invalid typed fields"
            ) from exc
    return records, manifest_digest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit train/calibration/sealed-test manifests for split leakage."
    )
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument("--content-root", required=True, type=pathlib.Path)
    parser.add_argument("--receipt", required=True, type=pathlib.Path)
    parser.add_argument(
        "--max-pair-comparisons",
        type=int,
        default=DEFAULT_MAX_PAIR_COMPARISONS,
    )
    args = parser.parse_args(argv)
    try:
        records, manifest_digest = load_split_manifest(args.manifest, args.content_root)
        receipt = audit_splits(
            records,
            input_manifest_sha256=manifest_digest,
            max_pair_comparisons=args.max_pair_comparisons,
        )
        encoded = json.dumps(receipt.to_json(), indent=2, sort_keys=True) + "\n"
        args.receipt.write_text(encoded, encoding="utf-8")
        receipt.require_clean()
    except (LeakageGuardError, OSError) as exc:
        print(f"leakage audit failed: {exc}", file=sys.stderr)
        return 2
    print(
        f"leakage audit passed: {receipt.raw_records} records, "
        f"{receipt.deduplicated_records} deduplicated samples, "
        f"receipt={receipt.receipt_digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
