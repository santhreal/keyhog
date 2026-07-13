"""keyhog adapter (the full config matrix).

Maps a :class:`ScannerConfig` to keyhog CLI flags:

* **backend** -> ``--backend {simd,cpu,gpu,auto}``. ``simd``/``cpu`` pass
  ``--no-gpu`` for their bit-deterministic filesystem paths. ``auto`` keeps
  every eligible calibrated backend in competition. ``gpu`` passes
  ``--require-gpu`` so it fails instead of timing a CPU fallback.
* **cache** -> ``--incremental`` (merkle skip-cache). ``on`` measures the
  *warm* re-run: the adapter populates the index once, then times the second
  pass: that's the 10-100x monorepo-re-run speedup, measured honestly.
* **daemon** -> ``--daemon`` / ``--daemon=off``.
* **mode** -> ``--fast`` / ``--deep`` for the two explicit presets, full
  pipeline otherwise.

Scoring parity flags are always present:
``--format json --show-secrets --no-suppress-test-fixtures --no-config`` plus
an explicit repository detector corpus. ``--no-config`` blocks ancestor config
discovery, while ``--detectors`` blocks installed-corpus discovery. Findings are
written to ``--output`` so GNU time's RSS report never crosses the JSON.

The default config (``variants()[0]``) is ``simd-nocache-nodaemon-full`` 
the deterministic build the README leaderboard cites.
"""

from __future__ import annotations

import contextlib
import itertools
import json
import math
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

from ..keyhog_version import (
    assert_keyhog_binary_current,
    detector_corpus_sha256 as compute_detector_corpus_sha256,
)
from ..executable_snapshot import sibling_executable_snapshot
from ..schema import ScannerConfig
from .base import Finding, MeasurementProvenance, RunStats, Scanner, _line, run_measured

_BACKENDS = ("simd", "cpu", "gpu", "auto")
_DETERMINISTIC_BACKENDS = {"simd", "cpu"}
_REQUIRE_GPU_BACKENDS = {"gpu"}

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_DETECTOR_CORPUS = _REPO_ROOT / "detectors"


def _detector_snapshot_root() -> pathlib.Path:
    override = os.environ.get("KEYHOG_BENCH_SNAPSHOT_DIR")
    if override:
        return pathlib.Path(override)
    if os.name == "nt":
        base = pathlib.Path(os.environ.get("LOCALAPPDATA", pathlib.Path.home() / "AppData/Local"))
    elif sys.platform == "darwin":
        base = pathlib.Path.home() / "Library/Caches"
    else:
        base = pathlib.Path(os.environ.get("XDG_CACHE_HOME", pathlib.Path.home() / ".cache"))
    return base / "keyhog" / "benchmark-detector-snapshots-v1"


def _cargo_target_dir() -> pathlib.Path | None:
    """Resolve the cargo target-dir for this repo: ``CARGO_TARGET_DIR`` env,
    else the ``target-dir`` key in ``~/.cargo/config.toml`` / ``config``, else
    ``<repo>/target``. Machine-agnostic: reads the host's own cargo config."""
    env = os.environ.get("CARGO_TARGET_DIR")
    if env:
        return pathlib.Path(env)
    for cfg in (pathlib.Path.home() / ".cargo" / "config.toml",
                pathlib.Path.home() / ".cargo" / "config"):
        try:
            text = cfg.read_text()
        except OSError:
            continue
        m = re.search(r'(?m)^\s*target-dir\s*=\s*"([^"]+)"', text)
        if m:
            return pathlib.Path(m.group(1))
    default = _REPO_ROOT / "target"
    return default if default.exists() else None


def _freshly_built_keyhog() -> str | None:
    """The release binary the current source builds to, so a bare
    ``python -m bench`` scores HEAD, not a stale ``keyhog`` on PATH (the
    stale-binary footgun that silently reported worse recall)."""
    target = _cargo_target_dir()
    if target is None:
        return None
    for profile in ("release", "release-fast"):
        candidate = target / profile / "keyhog"
        if candidate.exists():
            return str(candidate)
    return None


def resolve_keyhog_binary(explicit: str | None = None) -> str | None:
    """Canonical keyhog-binary locator shared by the bench AND the gate tests
    (recall matrix, backend-parity) so there is ONE resolution order, not
    several that drift: explicit arg / `KEYHOG_BIN` env, else the freshly-built
    release binary, else a `release`/`release-fast` binary in either known cargo
    target dir. Returns None if no real binary exists (callers fail LOUDLY 
    never silently treat 'no binary' as 'no findings')."""
    import pathlib as _pl
    # An explicit arg / KEYHOG_BIN is honored unconditionally: the operator
    # pointed at a specific binary, so a missing one must fail LOUDLY at exec 
    # never be silently swapped for the freshly-built or archive binary (Law 10).
    cand = explicit or os.environ.get("KEYHOG_BIN")
    if cand:
        return cand
    fresh = _freshly_built_keyhog()
    if fresh:
        return fresh
    for base in ("/mnt/FlareTraining/santh-archive/cargo-target",
                 str(_REPO_ROOT / "target")):
        for profile in ("release", "release-fast"):
            p = _pl.Path(base) / profile / "keyhog"
            if p.exists():
                return str(p)
    return None


def _normalize_keyhog(data: object) -> list[Finding]:
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        if "findings" not in data:
            # A well-formed dict of an unexpected shape (schema rename/nesting)
            # would otherwise score recall 0.0 on a success exit, the exact
            # silent zero-finding scan _parse fails loud on for corrupt JSON.
            raise RuntimeError(
                "keyhog JSON object has no 'findings' key "
                f"(keys: {sorted(data)}); refusing to score it as zero findings"
            )
        records = data["findings"]
    else:
        raise RuntimeError(
            f"keyhog JSON is neither list nor object (got {type(data).__name__})"
        )
    if not isinstance(records, list):
        raise RuntimeError(
            "keyhog JSON 'findings' must be an array "
            f"(got {type(records).__name__})"
        )
    norm: list[Finding] = []
    output_index: dict[tuple[str, int, int, str, str], int] = {}
    for finding_index, finding in enumerate(records):
        if not isinstance(finding, dict):
            raise RuntimeError(
                f"keyhog finding {finding_index} must be an object "
                f"(got {type(finding).__name__})"
            )
        value = finding.get("credential_redacted") or finding.get("credential") or ""
        detector = finding.get("detector_id") or finding.get("detector_name") or ""
        confidence = finding.get("confidence")
        if not isinstance(value, str) or not value:
            raise RuntimeError(
                f"keyhog finding {finding_index} has no non-empty credential value"
            )
        if not isinstance(detector, str) or not detector:
            raise RuntimeError(
                f"keyhog finding {finding_index} has no non-empty detector identity"
            )
        if confidence is not None:
            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not math.isfinite(confidence)
                or not 0.0 <= confidence <= 1.0
            ):
                raise RuntimeError(
                    f"keyhog finding {finding_index} confidence must be null or a finite number in [0, 1]"
                )

        locations: list[dict] = []
        loc = finding.get("location")
        if not isinstance(loc, dict):
            raise RuntimeError(
                f"keyhog finding {finding_index} location must be an object"
            )
        locations.append(loc)
        additional = finding.get("additional_locations")
        if additional is not None:
            if not isinstance(additional, list):
                raise RuntimeError(
                    f"keyhog finding {finding_index} additional_locations must be an array"
                )
            for location_index, additional_loc in enumerate(additional):
                if not isinstance(additional_loc, dict):
                    raise RuntimeError(
                        "keyhog finding "
                        f"{finding_index} additional location {location_index} must be an object"
                    )
                locations.append(additional_loc)

        for location_index, loc in enumerate(locations):
            path = loc.get("file_path") or loc.get("file")
            if not isinstance(path, str) or not path:
                label = "location" if location_index == 0 else "additional location"
                raise RuntimeError(
                    f"keyhog finding {finding_index} {label} has no non-empty file path"
                )
            normalized = {
                "file": path,
                "line": _line(loc.get("line")),
                "offset": _line(loc.get("offset")),
                "value": value,
                "detector": detector,
                "confidence": confidence,
            }
            key = (
                normalized["file"],
                normalized["line"],
                normalized["offset"],
                normalized["value"],
                normalized["detector"],
            )
            if key in output_index:
                existing = norm[output_index[key]]
                if confidence is not None and (
                    existing["confidence"] is None
                    or confidence > existing["confidence"]
                ):
                    existing["confidence"] = confidence
                continue
            output_index[key] = len(norm)
            norm.append(normalized)
    return norm


class KeyhogScanner(Scanner):
    name = "keyhog"
    binary_name = "keyhog"
    binary_env = "KEYHOG_BIN"
    success_exit_codes = (0, 1, 10)

    def __init__(self, binary: str | None = None,
                 detector_corpus: pathlib.Path = _DETECTOR_CORPUS):
        super().__init__(binary)
        self._detector_corpus = detector_corpus

    @property
    def binary(self) -> str:
        # ONE resolution order, the same locator the gate tests use, so the
        # bench and the tests can never drift. Falls back to a bare PATH lookup
        # only when no real binary is found.
        return resolve_keyhog_binary(self._binary) or self.binary_name

    def detector_corpus_sha256(self) -> str:
        return compute_detector_corpus_sha256(self._detector_corpus)

    def assert_freshness(self) -> str:
        return assert_keyhog_binary_current(self.binary)

    @contextlib.contextmanager
    def _binary_snapshot(self):
        with sibling_executable_snapshot(self.binary) as snapshot:
            version = assert_keyhog_binary_current(
                str(snapshot.launch_path), pass_fds=snapshot.pass_fds,
            )
            yield snapshot.launch_path, snapshot.sha256, version, snapshot.pass_fds

    def _detector_snapshot(self) -> tuple[pathlib.Path, str]:
        digest = self.detector_corpus_sha256()
        root = _detector_snapshot_root()
        target = root / digest / "detectors"
        if target.is_dir():
            observed = compute_detector_corpus_sha256(target)
            if observed != digest:
                raise RuntimeError(
                    f"benchmark detector snapshot {target} is corrupt: "
                    f"expected SHA-256 {digest}, found {observed}. "
                    "Remove that snapshot directory and rerun"
                )
            return target, digest

        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="keyhog-bench-detectors-", dir=root
        ) as raw_staging:
            staging = pathlib.Path(raw_staging)
            staged_detectors = staging / "detectors"
            staged_detectors.mkdir(mode=0o700)
            sources = sorted(
                self._detector_corpus.glob("*.toml"),
                key=lambda path: os.fsencode(path.name),
            )
            if not sources:
                raise RuntimeError(
                    f"{self._detector_corpus} contains no detector TOMLs; "
                    "cannot run a provenance-bound benchmark"
                )
            for source in sources:
                destination = staged_detectors / source.name
                shutil.copyfile(source, destination)
                destination.chmod(0o400)
            staged_detectors.chmod(0o500)
            if compute_detector_corpus_sha256(staged_detectors) != digest:
                raise RuntimeError(
                    "detector corpus changed while its benchmark snapshot was created; rerun"
                )
            published = root / digest
            try:
                staging.rename(published)
            except OSError:
                if not target.is_dir() or compute_detector_corpus_sha256(target) != digest:
                    raise
        return target, digest

    # ── config matrix ──────────────────────────────────────────────────

    def variants(self) -> list[ScannerConfig]:
        # Default first (deterministic leaderboard build), then each axis
        # flipped once, a representative set without the full 40-row cross
        # product (the runner's perf tier expands axes explicitly).
        default = ScannerConfig(backend="simd", cache="off", daemon="off", mode="full")
        flips = [
            ScannerConfig(backend="auto", cache="off", daemon="off", mode="full"),
            ScannerConfig(backend="gpu", cache="off", daemon="off", mode="full"),
            ScannerConfig(backend="simd", cache="on", daemon="off", mode="full"),
            ScannerConfig(backend="simd", cache="off", daemon="on", mode="full"),
            ScannerConfig(backend="simd", cache="off", daemon="off", mode="fast"),
            ScannerConfig(backend="simd", cache="off", daemon="off", mode="deep"),
        ]
        return [default, *flips]

    def matrix(self, axes: list[str]) -> list[ScannerConfig]:
        """Cross-product over the named axes (backend/cache/daemon/mode);
        unlisted axes hold their deterministic-default value."""
        choices = {
            "backend": list(_BACKENDS),
            "cache": ["off", "on"],
            "daemon": ["off", "on"],
            "mode": ["full", "fast", "deep"],
        }
        defaults = {"backend": "simd", "cache": "off", "daemon": "off", "mode": "full"}
        active = [a for a in axes if a in choices]
        if not active:
            return self.variants()
        grids = [choices[a] for a in active]
        out: list[ScannerConfig] = []
        for combo in itertools.product(*grids):
            vals = dict(defaults)
            vals.update(dict(zip(active, combo)))
            out.append(ScannerConfig(**vals))
        return out

    # ── flag mapping ───────────────────────────────────────────────────

    def _cmd(self, root: pathlib.Path, cfg: ScannerConfig,
             output: pathlib.Path, incremental_cache: pathlib.Path | None,
             executable: pathlib.Path,
             detector_corpus: pathlib.Path | None = None) -> list[str]:
        cmd = [str(executable), "scan",
               "--format", "json", "--show-secrets",
               "--no-suppress-test-fixtures",
               # Hermetic config: the leaderboard scores the COMPILED shipped
               # defaults, never a stray `.keyhog.toml` that happens to sit on
               # an ancestor of the corpus (which lives inside the repo tree).
               # `--no-config` skips the walk-up discovery so the benched config
               # is the shipped default by design, not by accident (MC-07).
               "--no-config",
               "--detectors", str(detector_corpus or self._detector_corpus),
               "--backend", cfg.backend,
               "--output", str(output)]
        # Optional report-floor override. None (every leaderboard config) means
        # the compiled shipped default floor is scored, byte-identical to
        # before this knob existed. The ML harvest sets it LOW so it captures
        # the sub-floor candidates a detector fires on but the default floor
        # hides; without those, a retrain can never learn the hard negatives it
        # currently surfaces only as below-threshold scores (the source of the
        # kubernetes-bootstrap-token +203-FP retrain regression).
        if cfg.min_confidence is not None:
            # Fixed decimal, never repr(): repr(0.00001) == '1e-05', which the
            # CLI's numeric flag parser rejects, and the harvest path sets this
            # floor deliberately low.
            cmd += ["--min-confidence", str(float(cfg.min_confidence))]
        cmd += ["--daemon"] if cfg.daemon == "on" else ["--daemon=off"]
        if cfg.mode == "fast":
            cmd.append("--fast")
        elif cfg.mode == "deep":
            cmd.append("--deep")
        if cfg.backend in _DETERMINISTIC_BACKENDS:
            cmd.append("--no-gpu")
        elif cfg.backend in _REQUIRE_GPU_BACKENDS:
            cmd.append("--require-gpu")
        if cfg.cache == "on":
            cmd.append("--incremental")
            if incremental_cache is not None:
                cmd += ["--incremental-cache", str(incremental_cache)]
        cmd.append(str(root))
        return cmd

    def _env(self, cfg: ScannerConfig) -> dict:
        return {}

    # ── run ────────────────────────────────────────────────────────────

    def run(self, root: pathlib.Path, cfg: ScannerConfig,
            output: pathlib.Path | None = None,
            extra_env: dict[str, str] | None = None,
            extra_args: list[str] | None = None,
            timeout: int = 3600) -> tuple[list[Finding], RunStats]:
        findings, stats, _provenance = self.run_with_provenance(
            root, cfg, output=output, extra_env=extra_env,
            extra_args=extra_args, timeout=timeout,
        )
        return findings, stats

    def run_with_provenance(
        self, root: pathlib.Path, cfg: ScannerConfig,
        output: pathlib.Path | None = None,
        extra_env: dict[str, str] | None = None,
        extra_args: list[str] | None = None,
        timeout: int = 3600,
    ) -> tuple[list[Finding], RunStats, MeasurementProvenance]:
        """Scan immutable executable and detector snapshots with exact identity."""
        snapshot, digest = self._detector_snapshot()
        with self._binary_snapshot() as (
            executable, executable_digest, version, pass_fds,
        ):
            findings, stats = self._run_prepared(
                root, cfg, snapshot, executable, output=output, extra_env=extra_env,
                extra_args=extra_args, timeout=timeout, pass_fds=pass_fds,
            )
        observed = compute_detector_corpus_sha256(snapshot)
        if observed != digest:
            raise RuntimeError(
                f"benchmark detector snapshot changed during the scan: "
                f"expected SHA-256 {digest}, found {observed}"
            )
        return findings, stats, MeasurementProvenance(
            scanner_version=version,
            executable_sha256=executable_digest,
            detector_corpus_sha256=digest,
        )

    def _run_prepared(
        self, root: pathlib.Path, cfg: ScannerConfig,
        detector_corpus: pathlib.Path,
        executable: pathlib.Path,
        output: pathlib.Path | None = None,
        extra_env: dict[str, str] | None = None,
        extra_args: list[str] | None = None,
        timeout: int = 3600,
        pass_fds: tuple[int, ...] = (),
    ) -> tuple[list[Finding], RunStats]:
        env = self._env(cfg)
        if extra_env:
            env.update(extra_env)

        # KeyHog writes plaintext credentials for benchmark scoring. Keep every
        # adapter-owned artifact in one private, unique directory and let the
        # context manager remove it on success, timeout, scanner failure, or
        # parse/schema failure. Caller-owned output remains caller-owned.
        owns_artifacts = output is None or cfg.cache == "on"
        run_dir_context = (
            tempfile.TemporaryDirectory(prefix="keyhog-bench-")
            if owns_artifacts
            else contextlib.nullcontext(None)
        )
        with run_dir_context as run_dir_raw:
            run_dir = pathlib.Path(run_dir_raw) if run_dir_raw is not None else None
            result_output = output or (run_dir / "result.json")
            inc_cache = None
            if cfg.cache == "on":
                # Warmup and timed pass share only this run's private index.
                assert run_dir is not None
                inc_cache = run_dir / "merkle.idx"
                warm_out = run_dir / "warm.json"
                warm_stdout, warm_stderr, warm_stats = run_measured(
                    self._cmd(
                        root, cfg, warm_out, inc_cache, executable, detector_corpus
                    ),
                    env=env,
                    timeout=timeout,
                    pass_fds=pass_fds,
                )
                self._require_success(
                    warm_stdout,
                    warm_stderr,
                    warm_stats,
                    cfg,
                    timeout,
                    phase="warmup",
                )
                self._parse(warm_out, config_id=f"{cfg.config_id} warmup")

            cmd = self._cmd(
                root, cfg, result_output, inc_cache, executable, detector_corpus
            )
            if extra_args:
                cmd = [*cmd[:-1], *extra_args, cmd[-1]]
            stdout, stderr, stats = run_measured(
                cmd, env=env, timeout=timeout, pass_fds=pass_fds,
            )
            self._require_success(stdout, stderr, stats, cfg, timeout, phase="timed scan")
            findings = self._parse(result_output, config_id=cfg.config_id)
            return findings, stats

    def _require_success(
        self,
        stdout: str,
        stderr: str,
        stats: RunStats,
        cfg: ScannerConfig,
        timeout: int,
        *,
        phase: str,
    ) -> None:
        if self.exit_success(stats.exit_code):
            return
        detail = (stderr or stdout or "").strip()
        if len(detail) > 1200:
            detail = detail[-1200:]
        if stats.timed_out:
            raise TimeoutError(
                f"keyhog {phase} timed out after {timeout}s for {cfg.config_id}; "
                "the scan was terminated and produced no parity result"
                + (f": {detail}" if detail else "")
            )
        raise RuntimeError(
            f"keyhog {phase} exited {stats.exit_code} for {cfg.config_id}: {detail}"
        )

    @staticmethod
    def _parse(output: pathlib.Path, config_id: str = "") -> list[Finding]:
        # The exit code already confirmed success here, so a read/parse failure
        # is NOT "zero findings", it is corrupt output that would silently score
        # recall 0. Fail closed loudly (Law 10) rather than swallow it. An
        # explicit JSON [] is the only valid zero-finding artifact.
        try:
            text = output.read_text().strip()
        except OSError as exc:
            raise RuntimeError(
                f"keyhog output unreadable for {config_id or output}: {exc}"
            ) from exc
        if not text:
            raise RuntimeError(
                f"keyhog wrote an empty output artifact for {config_id or output} "
                "after a success exit; expected explicit JSON []"
            )
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"keyhog wrote invalid JSON for {config_id or output} "
                f"(exit was success): {exc}"
            ) from exc
        return _normalize_keyhog(data)

    # ── daemon lifecycle (used by the perf matrix for daemon=on rows) ──

    def start_daemon(self) -> None:
        subprocess.run([self.binary, "daemon", "start"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop_daemon(self) -> None:
        subprocess.run([self.binary, "daemon", "stop"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
