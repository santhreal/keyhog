"""Common result contract for every benchmark run.

One :class:`RunResult` == one (scanner, config, corpus, host) measurement,
serialised to a single JSON file under ``results/<host>/``. This is the
*only* shape the report generator, the matrix runner, and the tests agree
on, so adding an axis (a new scanner config, a new corpus, a new host)
never forks the format.

The schema is a superset of the legacy ``score.py`` ``ScoreReport``: it
keeps the detection block (overall + per-category P/R/F1) byte-for-byte
compatible and adds the requested axes, host hardware, scanner config
(backend/cache/daemon/mode), corpus size, and speed (wall/throughput/RSS).
KeyHog rows additionally retain the resolved scan manifest so a mode label is
backed by the exact detection policy that produced the measurement.

Every dataclass round-trips through :meth:`to_json` / :meth:`from_json`
losslessly; ``test_schema.py`` asserts it.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from . import LEGACY_SCHEMA_VERSIONS, SCHEMA_VERSION

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def is_sha256(value: object) -> bool:
    """Return whether a value is one canonical lowercase SHA-256 digest."""
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


# ── confidence histogram resolution ───────────────────────────────────
# Per-detector findings are bucketed into CONF_BINS bins of width
# CONF_BIN_WIDTH over [0, 1]. 0.05 is the min_confidence tuning resolution
# keyhog detectors are configured at (TOML floors are 2-decimal: 0.40,
# 0.60, …), so a bin maps 1:1 onto a settable floor. Bin ``k`` covers
# ``[k*0.05, (k+1)*0.05)``; a min_confidence threshold of ``k*0.05`` drops
# exactly bins ``0..k-1``.
CONF_BINS = 20
CONF_BIN_WIDTH = 1.0 / CONF_BINS


def precision_of(tp: int, fp: int) -> float:
    """TP / (TP + FP), 0.0 when the detector/outcome never fired. ONE home for
    the precision formula, shared by :class:`Outcome` and :class:`DetectorStat`."""
    d = tp + fp
    return tp / d if d else 0.0


def conf_bin(confidence: float) -> int:
    """Bucket a confidence in [0, 1] into ``[0, CONF_BINS-1]`` (clamped)."""
    idx = int(confidence / CONF_BIN_WIDTH)
    if idx < 0:
        return 0
    if idx >= CONF_BINS:
        return CONF_BINS - 1
    return idx


# ── detection: the SecretBench-paper confusion-matrix arithmetic ──────
# Ported verbatim from tools/secretbench/scoring/score.py::Outcome so the
# numbers a RunResult reports are identical to the standalone scorer.


@dataclass
class Outcome:
    """A single confusion-matrix cell triple with derived P/R/F1."""

    tp: int = 0
    fp: int = 0
    fn: int = 0

    def precision(self) -> float:
        return precision_of(self.tp, self.fp)

    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    def f1(self) -> float:
        p = self.precision()
        r = self.recall()
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_json(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision(), 4),
            "recall": round(self.recall(), 4),
            "f1": round(self.f1(), 4),
        }

    @classmethod
    def from_json(cls, d: dict) -> "Outcome":
        return cls(tp=int(d.get("tp", 0)), fp=int(d.get("fp", 0)), fn=int(d.get("fn", 0)))


RECOVERY_SCORE_SCHEMA_VERSION = "recovery-v1"


@dataclass(frozen=True)
class RecoveryExpectation:
    """One field-qualified expected value for one recovery sample.

    ``None`` means the field must be absent. An empty string is not a useful
    recovery target and is rejected so it cannot score as an accidental hit.
    """

    sample_id: str
    field: str
    value: str | None

    def __post_init__(self) -> None:
        if not self.sample_id:
            raise ValueError("recovery expectation sample_id must not be empty")
        if not self.field:
            raise ValueError("recovery expectation field must not be empty")
        if self.value == "":
            raise ValueError("recovery expectation value must be None or non-empty")


@dataclass(frozen=True)
class RecoveryObservation:
    """One value emitted by a scanner for a qualified recovery field."""

    sample_id: str
    field: str
    value: str

    def __post_init__(self) -> None:
        if not self.sample_id:
            raise ValueError("recovery observation sample_id must not be empty")
        if not self.field:
            raise ValueError("recovery observation field must not be empty")
        if not self.value:
            raise ValueError("recovery observation value must not be empty")


@dataclass
class RecoveryScore:
    """Exact field-qualified recovery outcome, independent of detection score.

    Field qualification prevents one recovered string from receiving credit
    for unrelated claims that happen to contain the same bytes.
    """

    overall: Outcome = field(default_factory=Outcome)
    per_field: dict[str, Outcome] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "schema_version": RECOVERY_SCORE_SCHEMA_VERSION,
            "overall": self.overall.to_json(),
            "per_field": {
                name: outcome.to_json()
                for name, outcome in sorted(self.per_field.items())
            },
        }

    @classmethod
    def from_json(cls, d: dict) -> "RecoveryScore":
        observed = d.get("schema_version")
        if observed != RECOVERY_SCORE_SCHEMA_VERSION:
            raise ValueError(
                "unsupported recovery score schema: "
                f"observed={observed!r}, supported={RECOVERY_SCORE_SCHEMA_VERSION!r}"
            )
        return cls(
            overall=Outcome.from_json(d.get("overall", {})),
            per_field={
                name: Outcome.from_json(outcome)
                for name, outcome in (d.get("per_field") or {}).items()
            },
        )


@dataclass
class DetectorStat:
    """Per-detector confusion stats + confidence histograms, the signal the
    per-detector ``min_confidence`` tuning loop consumes.

    * ``tp``, labeled positive *records* this detector caught (deduped per
      record, matching the overall scorer's record-counting TP semantics).
    * ``fp`` (false-firing *findings* attributed to this detector).
    * ``unique_tp``, positives that **only** this detector caught; raising
      its floor risks losing exactly these, so this is the recall-criticality
      that gates a safe threshold bump.
    * ``tp_hist`` / ``fp_hist``: :data:`CONF_BINS`-bin confidence histograms
      of the detector's TP and FP findings. A TP record is binned at the max
      confidence among the findings that caught it. These let
      :mod:`bench.calibrate` compute the floor that drops FPs without losing
      TPs: without persisting every raw finding.

    Precision is exact (TP/FP are both counts of the detector's own output);
    recall is corpus-relative (``unique_tp`` / corpus positives) and computed
    by the report, which knows the corpus total.
    """

    tp: int = 0
    fp: int = 0
    unique_tp: int = 0
    tp_hist: list[int] = field(default_factory=lambda: [0] * CONF_BINS)
    fp_hist: list[int] = field(default_factory=lambda: [0] * CONF_BINS)

    def precision(self) -> float:
        return precision_of(self.tp, self.fp)

    def add_tp(self, confidence: float | None) -> None:
        self.tp += 1
        if confidence is not None:
            self.tp_hist[conf_bin(confidence)] += 1

    def add_fp(self, confidence: float | None) -> None:
        self.fp += 1
        if confidence is not None:
            self.fp_hist[conf_bin(confidence)] += 1

    def to_json(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "unique_tp": self.unique_tp,
            "precision": round(self.precision(), 4),
            "tp_hist": list(self.tp_hist),
            "fp_hist": list(self.fp_hist),
        }

    @classmethod
    def from_json(cls, d: dict) -> "DetectorStat":
        def _hist(key: str) -> list[int]:
            raw = d.get(key) or []
            hist = [int(x) for x in raw][:CONF_BINS]
            hist += [0] * (CONF_BINS - len(hist))
            return hist

        return cls(
            tp=int(d.get("tp", 0)),
            fp=int(d.get("fp", 0)),
            unique_tp=int(d.get("unique_tp", 0)),
            tp_hist=_hist("tp_hist"),
            fp_hist=_hist("fp_hist"),
        )


@dataclass
class Detection:
    """Overall + per-category confusion matrices for a labeled corpus.

    ``per_category`` is keyed by the SecretBench taxonomy bucket so the
    report can surface where keyhog loses recall/precision to a competitor
    at category granularity, not just overall.
    """

    overall: Outcome = field(default_factory=Outcome)
    per_category: dict[str, Outcome] = field(default_factory=dict)
    per_detector: dict[str, DetectorStat] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "overall": self.overall.to_json(),
            "per_category": {
                c: o.to_json() for c, o in sorted(self.per_category.items())
            },
            "per_detector": {
                d: s.to_json() for d, s in sorted(self.per_detector.items())
            },
        }

    @classmethod
    def from_json(cls, d: dict) -> "Detection":
        return cls(
            overall=Outcome.from_json(d.get("overall", {})),
            per_category={
                c: Outcome.from_json(o)
                for c, o in (d.get("per_category") or {}).items()
            },
            per_detector={
                det: DetectorStat.from_json(s)
                for det, s in (d.get("per_detector") or {}).items()
            },
        )


STATIC_RECOVERY_SCHEMA_VERSION = "static-recovery-v1"
_STATIC_RECOVERY_UNSUPPORTED_REASONS = frozenset({
    "unsupported_call",
    "dynamic_property_access",
})
_STATIC_RECOVERY_ERRONEOUS_REASONS = frozenset({
    "literal_byte_array_element",
    "json_base64",
    "json_utf8",
    "json_byte_array",
    "xor_plaintext_utf8",
    "string_join_json",
    "buffer_base64",
    "buffer_hex",
    "aes_key_length",
    "aes_iv_length",
    "aes_ciphertext_block_length",
    "aes_padding",
    "aes_plaintext_utf8",
    "malformed_expression",
    "resource_limit",
})
_STATIC_RECOVERY_REASONS = (
    _STATIC_RECOVERY_UNSUPPORTED_REASONS | _STATIC_RECOVERY_ERRONEOUS_REASONS
)


def _exact_count(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"static recovery {field_name} must be a non-negative integer")
    return value


@dataclass(frozen=True)
class StaticRecoveryMetrics:
    """Exact bounded static-recovery disposition and rejection totals."""

    schema_version: str = STATIC_RECOVERY_SCHEMA_VERSION
    supported: int = 0
    unsupported: int = 0
    erroneous: int = 0
    reasons: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != STATIC_RECOVERY_SCHEMA_VERSION:
            raise ValueError(
                "static recovery schema_version="
                f"{self.schema_version!r}; supported={STATIC_RECOVERY_SCHEMA_VERSION!r}"
            )
        _exact_count(self.supported, "supported")
        _exact_count(self.unsupported, "unsupported")
        _exact_count(self.erroneous, "erroneous")
        unknown = sorted(set(self.reasons) - _STATIC_RECOVERY_REASONS)
        if unknown:
            raise ValueError(f"static recovery has unknown rejection reasons: {unknown}")
        normalized = {
            reason: _exact_count(count, f"reason {reason!r}")
            for reason, count in self.reasons.items()
        }
        unsupported = sum(
            normalized.get(reason, 0)
            for reason in _STATIC_RECOVERY_UNSUPPORTED_REASONS
        )
        erroneous = sum(
            normalized.get(reason, 0)
            for reason in _STATIC_RECOVERY_ERRONEOUS_REASONS
        )
        if unsupported != self.unsupported or erroneous != self.erroneous:
            raise ValueError(
                "static recovery reason conservation failed: "
                f"reasons unsupported={unsupported}, erroneous={erroneous}; "
                f"totals unsupported={self.unsupported}, erroneous={self.erroneous}"
            )
        object.__setattr__(self, "reasons", dict(sorted(normalized.items())))

    def to_json(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "supported": self.supported,
            "unsupported": self.unsupported,
            "erroneous": self.erroneous,
            "reasons": dict(sorted(self.reasons.items())),
        }

    @classmethod
    def from_json(cls, value: object) -> "StaticRecoveryMetrics":
        if not isinstance(value, dict):
            raise ValueError("static recovery must be an object")
        required = {
            "schema_version",
            "supported",
            "unsupported",
            "erroneous",
            "reasons",
        }
        missing = sorted(required - set(value))
        extra = sorted(set(value) - required)
        if missing:
            raise ValueError(f"static recovery missing required fields: {missing}")
        if extra:
            raise ValueError(f"static recovery has unknown fields: {extra}")
        reasons = value["reasons"]
        if not isinstance(reasons, dict) or any(
            not isinstance(reason, str) for reason in reasons
        ):
            raise ValueError("static recovery reasons must be an object of named counts")
        return cls(
            schema_version=value["schema_version"],
            supported=value["supported"],
            unsupported=value["unsupported"],
            erroneous=value["erroneous"],
            reasons=reasons,
        )


BLOOM_EVIDENCE_SCHEMA_VERSION = "bloom-evidence-v1"
_BLOOM_STATES = frozenset({
    "healthy",
    "saturated-fail-open",
    "invalid-fail-open",
})
_BLOOM_UNAVAILABLE_REASONS = frozenset({"source-file-missing"})


def _bloom_count(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"Bloom evidence {field_name} must be a non-negative integer")
    return value


@dataclass(frozen=True)
class BloomEvidence:
    """Digest-bound real-corpus Bloom rejection and bypass differential."""

    schema_version: str
    corpus_name: str
    corpus_revision: str
    fixture_sha256: str
    corpus_sha256: str
    detector_corpus_sha256: str
    scanner_detector_digest: str
    executable_sha256: str
    workspace_detector_corpus_sha256: str
    declared_input_count: int
    unavailable_input_count: int
    unavailable_reason_counts: dict[str, int]
    input_count: int
    eligible_input_count: int
    admitted_input_count: int
    rejected_input_count: int
    rejection_basis_points: int
    populated_slots: int
    total_slots: int
    saturation_threshold_slots: int
    density_basis_points: int
    state: str
    enabled_finding_count: int
    bypass_finding_count: int
    enabled_findings_sha256: str
    bypass_findings_sha256: str
    findings_identical: bool

    def __post_init__(self) -> None:
        if self.schema_version != BLOOM_EVIDENCE_SCHEMA_VERSION:
            raise ValueError(
                f"Bloom evidence schema_version={self.schema_version!r}; "
                f"supported={BLOOM_EVIDENCE_SCHEMA_VERSION!r}"
            )
        if not self.corpus_name.strip() or not self.corpus_revision.strip():
            raise ValueError("Bloom evidence must name the corpus and revision")
        for field_name in (
            "fixture_sha256",
            "corpus_sha256",
            "detector_corpus_sha256",
            "executable_sha256",
            "workspace_detector_corpus_sha256",
            "enabled_findings_sha256",
            "bypass_findings_sha256",
        ):
            if not _SHA256_RE.fullmatch(getattr(self, field_name)):
                raise ValueError(f"Bloom evidence {field_name} must be lowercase SHA-256")
        if not re.fullmatch(r"[0-9a-f]{16}", self.scanner_detector_digest):
            raise ValueError(
                "Bloom evidence scanner_detector_digest must be 16 lowercase hex digits"
            )
        count_fields = (
            "declared_input_count",
            "unavailable_input_count",
            "input_count",
            "eligible_input_count",
            "admitted_input_count",
            "rejected_input_count",
            "rejection_basis_points",
            "populated_slots",
            "total_slots",
            "saturation_threshold_slots",
            "density_basis_points",
            "enabled_finding_count",
            "bypass_finding_count",
        )
        for field_name in count_fields:
            _bloom_count(getattr(self, field_name), field_name)
        if not isinstance(self.unavailable_reason_counts, dict):
            raise ValueError("Bloom evidence unavailable_reason_counts must be an object")
        normalized_reasons: dict[str, int] = {}
        for reason, count in self.unavailable_reason_counts.items():
            if reason not in _BLOOM_UNAVAILABLE_REASONS:
                raise ValueError(
                    f"Bloom evidence unavailable reason is invalid: {reason!r}"
                )
            normalized_reasons[reason] = _bloom_count(
                count, f"unavailable_reason_counts[{reason!r}]"
            )
        if sum(normalized_reasons.values()) != self.unavailable_input_count:
            raise ValueError("Bloom evidence unavailable reason accounting failed")
        object.__setattr__(
            self, "unavailable_reason_counts", dict(sorted(normalized_reasons.items()))
        )
        if self.input_count == 0 or self.total_slots == 0:
            raise ValueError("Bloom evidence input_count and total_slots must be positive")
        if self.declared_input_count != self.input_count + self.unavailable_input_count:
            raise ValueError("Bloom evidence declared-input conservation failed")
        if self.eligible_input_count > self.input_count:
            raise ValueError("Bloom evidence eligible inputs exceed measured inputs")
        if self.rejected_input_count > self.eligible_input_count:
            raise ValueError("Bloom evidence rejected inputs exceed eligible inputs")
        if self.admitted_input_count + self.rejected_input_count != self.input_count:
            raise ValueError("Bloom evidence admit/reject conservation failed")
        expected_rejection = self.rejected_input_count * 10_000 // self.input_count
        if self.rejection_basis_points != expected_rejection:
            raise ValueError("Bloom evidence rejection basis points are inconsistent")
        expected_density = self.populated_slots * 10_000 // self.total_slots
        if self.density_basis_points != expected_density:
            raise ValueError("Bloom evidence density basis points are inconsistent")
        if not 0 < self.saturation_threshold_slots <= self.total_slots:
            raise ValueError("Bloom evidence saturation threshold is out of range")
        if self.state not in _BLOOM_STATES:
            raise ValueError(f"Bloom evidence state is invalid: {self.state!r}")
        if self.state == "healthy" and self.populated_slots >= self.saturation_threshold_slots:
            raise ValueError("Bloom evidence healthy state crosses saturation threshold")
        if (
            self.state == "saturated-fail-open"
            and self.populated_slots < self.saturation_threshold_slots
        ):
            raise ValueError("Bloom evidence saturated state is below threshold")
        if self.findings_identical and (
            self.enabled_finding_count != self.bypass_finding_count
            or self.enabled_findings_sha256 != self.bypass_findings_sha256
        ):
            raise ValueError("Bloom evidence identical finding claim is inconsistent")

    def to_json(self) -> dict:
        return {
            field_name: getattr(self, field_name)
            for field_name in self.__dataclass_fields__
        }

    @classmethod
    def from_json(cls, value: object) -> "BloomEvidence":
        if not isinstance(value, dict):
            raise ValueError("Bloom evidence must be an object")
        required = set(cls.__dataclass_fields__)
        missing = sorted(required - set(value))
        extra = sorted(set(value) - required)
        if missing:
            raise ValueError(f"Bloom evidence missing required fields: {missing}")
        if extra:
            raise ValueError(f"Bloom evidence has unknown fields: {extra}")
        return cls(**value)


# ── profile: causal profile artifact binding ────────────────────────

PROFILE_ARTIFACT_SCHEMA_VERSION = "profile-artifact-v1"


@dataclass(frozen=True)
class ProfileArtifact:
    """Reference + content digest binding one run to one causal profile artifact.

    The artifact bytes (a ``keyhog-profile`` v2 envelope JSON) live beside the
    result JSON; the result carries only the reference and digest so a profile
    can never be silently swapped for another run's evidence.
    """

    schema_version: str
    path: str
    sha256: str
    bytes: int
    profile_schema: str
    profile_schema_major: int

    def __post_init__(self) -> None:
        if self.schema_version != PROFILE_ARTIFACT_SCHEMA_VERSION:
            raise ValueError(
                f"profile artifact schema_version must be "
                f"{PROFILE_ARTIFACT_SCHEMA_VERSION!r}, got {self.schema_version!r}"
            )
        if not isinstance(self.path, str) or not self.path:
            raise ValueError("profile artifact path must be a non-empty string")
        if not is_sha256(self.sha256):
            raise ValueError(
                "profile artifact sha256 must be a lowercase SHA-256 digest"
            )
        if isinstance(self.bytes, bool) or not isinstance(self.bytes, int) or self.bytes <= 0:
            raise ValueError("profile artifact bytes must be a positive integer")
        if not isinstance(self.profile_schema, str) or not self.profile_schema:
            raise ValueError("profile artifact profile_schema must be a non-empty string")
        if (
            isinstance(self.profile_schema_major, bool)
            or not isinstance(self.profile_schema_major, int)
            or self.profile_schema_major < 0
        ):
            raise ValueError(
                "profile artifact profile_schema_major must be a non-negative integer"
            )

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, value: object) -> "ProfileArtifact":
        if not isinstance(value, dict):
            raise ValueError("profile artifact must be an object")
        required = set(cls.__dataclass_fields__)
        missing = sorted(required - set(value))
        extra = sorted(set(value) - required)
        if missing:
            raise ValueError(f"profile artifact missing required fields: {missing}")
        if extra:
            raise ValueError(f"profile artifact has unknown fields: {extra}")
        return cls(**value)


# ── host: the hardware axis (OS / CPU / GPU) ──────────────────────────


@dataclass(frozen=True)
class HostedBinding:
    """Exact GitHub Actions run ownership bound to hosted context bytes."""

    context_sha256: str
    repository: str
    workflow_ref: str
    workflow_sha: str
    run_id: str
    run_attempt: str
    job: str

    def __post_init__(self) -> None:
        for field_name in self.__dataclass_fields__:
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"hosted binding {field_name} must be a non-empty string"
                )
        if not is_sha256(self.context_sha256):
            raise ValueError(
                "hosted binding context_sha256 must be a lowercase SHA-256"
            )
        if re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", self.workflow_sha) is None:
            raise ValueError(
                "hosted binding workflow_sha must be a full lowercase Git commit"
            )
        for field_name in ("run_id", "run_attempt"):
            value = getattr(self, field_name)
            if not value.isascii() or not value.isdecimal() or int(value) <= 0:
                raise ValueError(
                    f"hosted binding {field_name} must be a positive decimal string"
                )

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, value: object) -> "HostedBinding":
        if not isinstance(value, dict):
            raise ValueError("hosted binding must be an object")
        required = set(cls.__dataclass_fields__)
        missing = sorted(required - set(value))
        extra = sorted(set(value) - required)
        if missing:
            raise ValueError(f"hosted binding missing required fields: {missing}")
        if extra:
            raise ValueError(f"hosted binding has unknown fields: {extra}")
        return cls(**value)


@dataclass
class Host:
    """Captured once per run so Windows-ThinkPad / macOS / santhserver /
    desktop results aggregate into one matrix keyed by real hardware.

    ``hostname_hash`` is a short non-reversible digest of the hostname
    enough to group a machine's runs without committing a raw hostname.
    """

    hostname_hash: str = ""
    os: str = ""
    kernel: str = ""
    cpu: str = ""
    cores: int = 0
    affinity_cores: int = 0
    cgroup_quota_cores: float = 0.0
    ram_mb: int = 0
    gpu: str = ""
    gpu_vram_mb: int = 0

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, d: dict) -> "Host":
        return cls(**{k: d[k] for k in d if k in cls.__dataclass_fields__})


# ── scanner: name + version + the config axis ─────────────────────────


@dataclass
class ScannerConfig:
    """One point in a scanner's config matrix.

    keyhog spans every field; competitors carry the subset that maps to
    their own knobs (e.g. kingfisher's confidence level lands in ``mode``).
    ``config_id`` is the stable matrix key, e.g. ``simd-nocache-nodaemon-full``.
    """

    backend: str = "default"  # cpu | simd | gpu-cuda | gpu-wgpu | auto | default
    cache: str = "off"  # on | off
    daemon: str = "off"  # on | off
    mode: str = "full"  # full | fast | <competitor-specific>
    # Optional report-floor override. None = the scanner's compiled default
    # (what the leaderboard scores). The harvest loop sets this LOW so the ML
    # feedback loop can label the sub-floor candidates a detector fires on but
    # the default floor hides, without those, a retrain can never learn the
    # hard negatives it currently surfaces only as below-threshold scores
    # (the kubernetes-bootstrap-token +203-FP retrain regression came from
    # exactly this blind spot). Left None for every leaderboard config so
    # config_id and scored behavior are byte-identical to before.
    min_confidence: float | None = None

    @property
    def config_id(self) -> str:
        # min_confidence is deliberately NOT part of the matrix key: it is a
        # harvest-only knob, never a leaderboard axis, so a None vs low floor
        # must not fork the stable config_id the README table / gate key on.
        return (
            f"{self.backend}-{'cache' if self.cache == 'on' else 'nocache'}-"
            f"{'daemon' if self.daemon == 'on' else 'nodaemon'}-{self.mode}"
        )

    def to_json(self) -> dict:
        out = {
            "backend": self.backend,
            "cache": self.cache,
            "daemon": self.daemon,
            "mode": self.mode,
        }
        if self.min_confidence is not None:
            out["min_confidence"] = self.min_confidence
        return out

    @classmethod
    def from_json(cls, d: dict) -> "ScannerConfig":
        return cls(**{k: d[k] for k in d if k in cls.__dataclass_fields__})


@dataclass
class Scanner:
    name: str = ""
    version: str = ""
    config: ScannerConfig = field(default_factory=ScannerConfig)
    executable_sha256: str = ""
    detector_corpus_sha256: str = ""
    execution_route: str = ""
    daemon_pid: int = 0
    daemon_requests: int = 0

    @property
    def config_id(self) -> str:
        return self.config.config_id

    def to_json(self) -> dict:
        value = {
            "name": self.name,
            "version": self.version,
            "config_id": self.config_id,
            "config": self.config.to_json(),
        }
        if self.executable_sha256:
            value["executable_sha256"] = self.executable_sha256
        if self.detector_corpus_sha256:
            value["detector_corpus_sha256"] = self.detector_corpus_sha256
        if self.execution_route:
            value["execution_route"] = self.execution_route
        if self.daemon_pid:
            value["daemon_pid"] = self.daemon_pid
        if self.daemon_requests:
            value["daemon_requests"] = self.daemon_requests
        return value

    @classmethod
    def from_json(cls, d: dict) -> "Scanner":
        return cls(
            name=d.get("name", ""),
            version=d.get("version", ""),
            config=ScannerConfig.from_json(d.get("config", {})),
            executable_sha256=d.get("executable_sha256", ""),
            detector_corpus_sha256=d.get("detector_corpus_sha256", ""),
            execution_route=d.get("execution_route", ""),
            daemon_pid=int(d.get("daemon_pid", 0)),
            daemon_requests=int(d.get("daemon_requests", 0)),
        )


# ── corpus: which dataset + its size ──────────────────────────────────


@dataclass
class CorpusInfo:
    name: str = ""
    fixture_count: int = 0
    labeled_positives: int = 0
    bytes: int = 0
    workload_sha256: str = ""

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, d: dict) -> "CorpusInfo":
        return cls(**{k: d[k] for k in d if k in cls.__dataclass_fields__})


# ── speed: wall / throughput / peak RSS ───────────────────────────────


@dataclass
class Speed:
    wall_ms: float = 0.0
    throughput_mb_s: float = 0.0
    peak_rss_kb: int = 0

    def to_json(self) -> dict:
        return {
            "wall_ms": round(self.wall_ms, 2),
            "throughput_mb_s": round(self.throughput_mb_s, 4),
            "peak_rss_kb": int(self.peak_rss_kb),
        }

    @classmethod
    def from_json(cls, d: dict) -> "Speed":
        return cls(
            wall_ms=float(d.get("wall_ms", 0.0)),
            throughput_mb_s=float(d.get("throughput_mb_s", 0.0)),
            peak_rss_kb=int(d.get("peak_rss_kb", 0)),
        )


# ── the top-level record ──────────────────────────────────────────────


@dataclass
class RunResult:
    """One benchmark measurement, fully self-describing.

    A perf-only corpus (kernel) leaves ``detection`` at its zero default and
    sets only ``speed``; a labeled corpus fills both. ``available`` /
    ``error`` mirror the legacy scorer: a missing binary records
    ``available=False`` with the reason instead of vanishing from the matrix.
    """

    schema_version: str = SCHEMA_VERSION
    generated_at: str = ""
    host: Host = field(default_factory=Host)
    scanner: Scanner = field(default_factory=Scanner)
    corpus: CorpusInfo = field(default_factory=CorpusInfo)
    detection: Detection = field(default_factory=Detection)
    speed: Speed = field(default_factory=Speed)
    finding_count: int = 0
    exit_code: int = 0
    timed_out: bool = False
    available: bool = True
    error: str = ""
    scan_manifest: dict[str, object] = field(default_factory=dict)
    static_recovery: StaticRecoveryMetrics | None = None
    bloom: BloomEvidence | None = None
    hosted_binding: HostedBinding | None = None
    profile: ProfileArtifact | None = None

    def to_json(self) -> dict:
        value = {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "host": self.host.to_json(),
            "scanner": self.scanner.to_json(),
            "corpus": self.corpus.to_json(),
            "detection": self.detection.to_json(),
            "speed": self.speed.to_json(),
            "finding_count": self.finding_count,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "available": self.available,
            "error": self.error,
            "scan_manifest": self.scan_manifest,
        }
        if self.schema_version == SCHEMA_VERSION:
            value["static_recovery"] = (
                self.static_recovery.to_json()
                if self.static_recovery is not None
                else None
            )
            value["bloom"] = self.bloom.to_json() if self.bloom is not None else None
            value["hosted_binding"] = (
                self.hosted_binding.to_json()
                if self.hosted_binding is not None
                else None
            )
            # Emitted only when present so rows recorded before profile capture
            # existed stay byte-identical.
            if self.profile is not None:
                value["profile"] = self.profile.to_json()
        return value

    @classmethod
    def from_json(cls, d: dict, *, source: str = "benchmark result") -> "RunResult":
        observed_version = d.get("schema_version")
        if observed_version not in {SCHEMA_VERSION, *LEGACY_SCHEMA_VERSIONS}:
            rendered = (
                "<missing>" if observed_version is None else repr(observed_version)
            )
            raise ValueError(
                f"{source} has schema_version={rendered}; supported={SCHEMA_VERSION!r}, "
                f"legacy={sorted(LEGACY_SCHEMA_VERSIONS)!r}. "
                "Rerun the benchmark with the current harness"
            )
        scanner = Scanner.from_json(d.get("scanner", {}))
        available = bool(d.get("available", True))
        static_recovery = None
        bloom = None
        hosted_binding = None
        profile = None
        if observed_version == SCHEMA_VERSION:
            if "static_recovery" not in d:
                raise ValueError(
                    f"{source} is {SCHEMA_VERSION!r} but lacks required "
                    "'static_recovery' telemetry"
                )
            raw_static_recovery = d["static_recovery"]
            if raw_static_recovery is not None:
                static_recovery = StaticRecoveryMetrics.from_json(raw_static_recovery)
            elif scanner.name == "keyhog" and available:
                raise ValueError(
                    f"{source} is an available keyhog result but static_recovery is null"
                )
            raw_bloom = d.get("bloom")
            if raw_bloom is not None:
                bloom = BloomEvidence.from_json(raw_bloom)
            if "hosted_binding" not in d:
                raise ValueError(
                    f"{source} is {SCHEMA_VERSION!r} but lacks required "
                    "'hosted_binding' receipt"
                )
            raw_hosted_binding = d["hosted_binding"]
            if raw_hosted_binding is not None:
                hosted_binding = HostedBinding.from_json(raw_hosted_binding)
            raw_profile = d.get("profile")
            if raw_profile is not None:
                profile = ProfileArtifact.from_json(raw_profile)
        elif any(
            field_name in d
            for field_name in ("static_recovery", "bloom", "hosted_binding", "profile")
        ):
            current_fields = sorted(
                field_name
                for field_name in ("static_recovery", "bloom", "hosted_binding", "profile")
                if field_name in d
            )
            raise ValueError(
                f"{source} declares legacy schema {observed_version!r} but contains "
                f"current telemetry fields {current_fields}"
            )
        return cls(
            schema_version=observed_version,
            generated_at=d.get("generated_at", ""),
            host=Host.from_json(d.get("host", {})),
            scanner=scanner,
            corpus=CorpusInfo.from_json(d.get("corpus", {})),
            detection=Detection.from_json(d.get("detection", {})),
            speed=Speed.from_json(d.get("speed", {})),
            finding_count=int(d.get("finding_count", 0)),
            exit_code=int(d.get("exit_code", 0)),
            timed_out=bool(d.get("timed_out", False)),
            available=available,
            error=d.get("error", ""),
            scan_manifest=dict(d.get("scan_manifest") or {}),
            static_recovery=static_recovery,
            bloom=bloom,
            hosted_binding=hosted_binding,
            profile=profile,
        )

    def result_filename(self) -> str:
        """Stable per-run filename: ``<corpus>-<scanner>-<config_id>.json``.

        The runner prefixes an ISO timestamp + host dir; this is the
        identity portion that keys the matrix.
        """
        return f"{self.corpus.name}-{self.scanner.name}-{self.scanner.config_id}.json"
