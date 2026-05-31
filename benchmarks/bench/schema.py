"""Common result contract for every benchmark run.

One :class:`RunResult` == one (scanner, config, corpus, host) measurement,
serialised to a single JSON file under ``results/<host>/``. This is the
*only* shape the report generator, the matrix runner, and the tests agree
on, so adding an axis (a new scanner config, a new corpus, a new host)
never forks the format.

The schema is a superset of the legacy ``score.py`` ``ScoreReport``: it
keeps the detection block (overall + per-category P/R/F1) byte-for-byte
compatible and adds the requested axes — host hardware, scanner config
(backend/cache/daemon/mode), corpus size, and speed (wall/throughput/RSS).

Every dataclass round-trips through :meth:`to_json` / :meth:`from_json`
losslessly; ``test_schema.py`` asserts it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from . import SCHEMA_VERSION


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
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

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


@dataclass
class Detection:
    """Overall + per-category confusion matrices for a labeled corpus.

    ``per_category`` is keyed by the SecretBench taxonomy bucket so the
    report can surface where keyhog loses recall/precision to a competitor
    at category granularity, not just overall.
    """

    overall: Outcome = field(default_factory=Outcome)
    per_category: dict[str, Outcome] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "overall": self.overall.to_json(),
            "per_category": {c: o.to_json() for c, o in sorted(self.per_category.items())},
        }

    @classmethod
    def from_json(cls, d: dict) -> "Detection":
        return cls(
            overall=Outcome.from_json(d.get("overall", {})),
            per_category={
                c: Outcome.from_json(o) for c, o in (d.get("per_category") or {}).items()
            },
        )


# ── host: the hardware axis (OS / CPU / GPU) ──────────────────────────


@dataclass
class Host:
    """Captured once per run so Windows-ThinkPad / macOS / santhserver /
    desktop results aggregate into one matrix keyed by real hardware.

    ``hostname_hash`` is a short non-reversible digest of the hostname —
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

    backend: str = "default"   # cpu | simd | gpu | auto | default
    cache: str = "off"         # on | off
    daemon: str = "off"        # on | off
    mode: str = "full"         # full | fast | <competitor-specific>

    @property
    def config_id(self) -> str:
        return f"{self.backend}-{'cache' if self.cache == 'on' else 'nocache'}-" \
               f"{'daemon' if self.daemon == 'on' else 'nodaemon'}-{self.mode}"

    def to_json(self) -> dict:
        return {"backend": self.backend, "cache": self.cache,
                "daemon": self.daemon, "mode": self.mode}

    @classmethod
    def from_json(cls, d: dict) -> "ScannerConfig":
        return cls(**{k: d[k] for k in d if k in cls.__dataclass_fields__})


@dataclass
class Scanner:
    name: str = ""
    version: str = ""
    config: ScannerConfig = field(default_factory=ScannerConfig)

    @property
    def config_id(self) -> str:
        return self.config.config_id

    def to_json(self) -> dict:
        return {"name": self.name, "version": self.version,
                "config_id": self.config_id, "config": self.config.to_json()}

    @classmethod
    def from_json(cls, d: dict) -> "Scanner":
        return cls(name=d.get("name", ""), version=d.get("version", ""),
                   config=ScannerConfig.from_json(d.get("config", {})))


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
        return {"wall_ms": round(self.wall_ms, 2),
                "throughput_mb_s": round(self.throughput_mb_s, 4),
                "peak_rss_kb": int(self.peak_rss_kb)}

    @classmethod
    def from_json(cls, d: dict) -> "Speed":
        return cls(wall_ms=float(d.get("wall_ms", 0.0)),
                   throughput_mb_s=float(d.get("throughput_mb_s", 0.0)),
                   peak_rss_kb=int(d.get("peak_rss_kb", 0)))


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
        }

    @classmethod
    def from_json(cls, d: dict) -> "RunResult":
        return cls(
            schema_version=d.get("schema_version", SCHEMA_VERSION),
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
        )

    def result_filename(self) -> str:
        """Stable per-run filename: ``<corpus>-<scanner>-<config_id>.json``.

        The runner prefixes an ISO timestamp + host dir; this is the
        identity portion that keys the matrix.
        """
        return f"{self.corpus.name}-{self.scanner.name}-{self.scanner.config_id}.json"
