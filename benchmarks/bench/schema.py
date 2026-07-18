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

from . import SCHEMA_VERSION

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


# ── host: the hardware axis (OS / CPU / GPU) ──────────────────────────


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

    def to_json(self) -> dict:
        return {
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

    @classmethod
    def from_json(cls, d: dict, *, source: str = "benchmark result") -> "RunResult":
        observed_version = d.get("schema_version")
        if observed_version != SCHEMA_VERSION:
            rendered = (
                "<missing>" if observed_version is None else repr(observed_version)
            )
            raise ValueError(
                f"{source} has schema_version={rendered}; supported={SCHEMA_VERSION!r}. "
                "Rerun the benchmark with the current harness"
            )
        return cls(
            schema_version=observed_version,
            generated_at=d.get("generated_at", ""),
            host=Host.from_json(d.get("host", {})),
            scanner=Scanner.from_json(d.get("scanner", {})),
            corpus=CorpusInfo.from_json(d.get("corpus", {})),
            detection=Detection.from_json(d.get("detection", {})),
            speed=Speed.from_json(d.get("speed", {})),
            finding_count=int(d.get("finding_count", 0)),
            exit_code=int(d.get("exit_code", 0)),
            timed_out=bool(d.get("timed_out", False)),
            available=bool(d.get("available", True)),
            error=d.get("error", ""),
            scan_manifest=dict(d.get("scan_manifest") or {}),
        )

    def result_filename(self) -> str:
        """Stable per-run filename: ``<corpus>-<scanner>-<config_id>.json``.

        The runner prefixes an ISO timestamp + host dir; this is the
        identity portion that keys the matrix.
        """
        return f"{self.corpus.name}-{self.scanner.name}-{self.scanner.config_id}.json"
