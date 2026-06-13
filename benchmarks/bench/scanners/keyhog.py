"""keyhog adapter — the full config matrix.

Maps a :class:`ScannerConfig` to keyhog CLI flags:

* **backend** -> ``--backend {simd,cpu,gpu,auto,megascan}``. ``simd``/``cpu``/
  ``auto`` pin ``KEYHOG_NO_GPU=1`` for the bit-deterministic filesystem path
  the leaderboard is scored on; ``gpu``/``megascan`` set ``KEYHOG_NO_GPU=0``
  and ``KEYHOG_REQUIRE_GPU=1`` so they fail instead of timing a CPU fallback.
* **cache** -> ``--incremental`` (merkle skip-cache). ``on`` measures the
  *warm* re-run: the adapter populates the index once, then times the second
  pass — that's the 10-100x monorepo-re-run speedup, measured honestly.
* **daemon** -> ``--daemon`` / ``--no-daemon``.
* **mode** -> ``--fast`` for ``fast``, full pipeline otherwise.

Scoring parity flags are always present:
``--format json --show-secrets --no-suppress-test-fixtures --no-config``.
``--no-config`` makes the run hermetic — the compiled shipped defaults are
scored, never a stray ``.keyhog.toml`` on a corpus ancestor (MC-07). Findings
are written to ``--output`` so GNU time's RSS report never crosses the JSON.

The default config (``variants()[0]``) is ``simd-nocache-nodaemon-full`` —
the deterministic build the README leaderboard cites.
"""

from __future__ import annotations

import itertools
import json
import os
import pathlib
import re
import subprocess
import tempfile

from ..schema import ScannerConfig
from .base import Finding, RunStats, Scanner, run_measured

_BACKENDS = ("simd", "cpu", "gpu", "auto", "megascan")
_DETERMINISTIC_BACKENDS = {"simd", "cpu", "auto"}
_REQUIRE_GPU_BACKENDS = {"gpu", "megascan"}

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]


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
    stale-binary footgun that silently reported worse recall; backlog MC-06)."""
    target = _cargo_target_dir()
    if target is None:
        return None
    for profile in ("release", "release-fast"):
        candidate = target / profile / "keyhog"
        if candidate.exists():
            return str(candidate)
    return None


def _line(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _normalize_keyhog(data: object) -> list[Finding]:
    records = data if isinstance(data, list) else (
        data.get("findings") if isinstance(data, dict) else []
    )
    norm: list[Finding] = []
    seen: set[tuple[str, int, str, str]] = set()
    for finding in records or []:
        if not isinstance(finding, dict):
            continue
        value = finding.get("credential_redacted") or finding.get("credential") or ""
        detector = finding.get("detector_id") or finding.get("detector_name") or ""
        confidence = finding.get("confidence")

        locations = []
        loc = finding.get("location")
        if isinstance(loc, dict):
            locations.append(loc)
        additional = finding.get("additional_locations")
        if isinstance(additional, list):
            locations.extend(loc for loc in additional if isinstance(loc, dict))

        for loc in locations:
            normalized = {
                "file": loc.get("file_path") or loc.get("file") or "",
                "line": _line(loc.get("line")),
                "value": value,
                "detector": detector,
                "confidence": confidence,
            }
            key = (
                normalized["file"],
                normalized["line"],
                normalized["value"],
                normalized["detector"],
            )
            if key in seen:
                continue
            seen.add(key)
            norm.append(normalized)
    return norm


class KeyhogScanner(Scanner):
    name = "keyhog"
    binary_name = "keyhog"
    binary_env = "KEYHOG_BIN"
    success_exit_codes = (0, 1, 10)

    @property
    def binary(self) -> str:
        # Explicit override wins; else the freshly-built release binary (so
        # the bench scores HEAD, not a stale PATH install); else PATH.
        if self._binary:
            return self._binary
        env = os.environ.get(self.binary_env)
        if env:
            return env
        fresh = _freshly_built_keyhog()
        return fresh or self.binary_name

    # ── config matrix ──────────────────────────────────────────────────

    def variants(self) -> list[ScannerConfig]:
        # Default first (deterministic leaderboard build), then each axis
        # flipped once — a representative set without the full 40-row cross
        # product (the runner's perf tier expands axes explicitly).
        default = ScannerConfig(backend="simd", cache="off", daemon="off", mode="full")
        flips = [
            ScannerConfig(backend="auto", cache="off", daemon="off", mode="full"),
            ScannerConfig(backend="gpu", cache="off", daemon="off", mode="full"),
            ScannerConfig(backend="simd", cache="on", daemon="off", mode="full"),
            ScannerConfig(backend="simd", cache="off", daemon="on", mode="full"),
            ScannerConfig(backend="simd", cache="off", daemon="off", mode="fast"),
        ]
        return [default, *flips]

    def matrix(self, axes: list[str]) -> list[ScannerConfig]:
        """Cross-product over the named axes (backend/cache/daemon/mode);
        unlisted axes hold their deterministic-default value."""
        choices = {
            "backend": list(_BACKENDS),
            "cache": ["off", "on"],
            "daemon": ["off", "on"],
            "mode": ["full", "fast"],
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
             output: pathlib.Path, incremental_cache: pathlib.Path | None) -> list[str]:
        cmd = [self.binary, "scan",
               "--format", "json", "--show-secrets",
               "--no-suppress-test-fixtures",
               # Hermetic config: the leaderboard scores the COMPILED shipped
               # defaults, never a stray `.keyhog.toml` that happens to sit on
               # an ancestor of the corpus (which lives inside the repo tree).
               # `--no-config` skips the walk-up discovery so the benched config
               # is the shipped default by design, not by accident (MC-07).
               "--no-config",
               "--backend", cfg.backend,
               "--output", str(output)]
        # Optional report-floor override. None (every leaderboard config) means
        # the compiled shipped default floor is scored — byte-identical to
        # before this knob existed. The ML harvest sets it LOW so it captures
        # the sub-floor candidates a detector fires on but the default floor
        # hides; without those, a retrain can never learn the hard negatives it
        # currently surfaces only as below-threshold scores (the source of the
        # kubernetes-bootstrap-token +203-FP retrain regression).
        if cfg.min_confidence is not None:
            cmd += ["--min-confidence", repr(float(cfg.min_confidence))]
        cmd += ["--daemon"] if cfg.daemon == "on" else ["--no-daemon"]
        if cfg.mode == "fast":
            cmd.append("--fast")
        if cfg.cache == "on":
            cmd.append("--incremental")
            if incremental_cache is not None:
                cmd += ["--incremental-cache", str(incremental_cache)]
        cmd.append(str(root))
        return cmd

    def _env(self, cfg: ScannerConfig) -> dict:
        return {
            "KEYHOG_NO_GPU": "1" if cfg.backend in _DETERMINISTIC_BACKENDS else "0",
            "KEYHOG_REQUIRE_GPU": "1" if cfg.backend in _REQUIRE_GPU_BACKENDS else "0",
        }

    # ── run ────────────────────────────────────────────────────────────

    def run(self, root: pathlib.Path, cfg: ScannerConfig,
            output: pathlib.Path | None = None) -> tuple[list[Finding], RunStats]:
        tmp_out = None
        if output is None:
            tmp_out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
            tmp_out.close()
            output = pathlib.Path(tmp_out.name)

        env = self._env(cfg)
        inc_cache = None
        if cfg.cache == "on":
            # Dedicated index per config so concurrent matrix rows don't share
            # state; warm it once (unmeasured) so the timed pass is the re-run.
            inc_cache = pathlib.Path(tempfile.gettempdir()) / \
                f"keyhog-bench-merkle-{cfg.config_id}.idx"
            warm_out = pathlib.Path(tempfile.gettempdir()) / \
                f"keyhog-bench-warm-{cfg.config_id}.json"
            run_measured(self._cmd(root, cfg, warm_out, inc_cache),
                         env=env, timeout=3600)
            try:
                warm_out.unlink()
            except OSError:
                pass

        cmd = self._cmd(root, cfg, output, inc_cache)
        _stdout, _stderr, stats = run_measured(cmd, env=env, timeout=3600)

        findings = self._parse(output)
        if tmp_out is not None:
            try:
                output.unlink()
            except OSError:
                pass
        return findings, stats

    @staticmethod
    def _parse(output: pathlib.Path) -> list[Finding]:
        try:
            text = output.read_text().strip()
        except OSError:
            return []
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        return _normalize_keyhog(data)

    # ── daemon lifecycle (used by the perf matrix for daemon=on rows) ──

    def start_daemon(self) -> None:
        subprocess.run([self.binary, "daemon", "start"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop_daemon(self) -> None:
        subprocess.run([self.binary, "daemon", "stop"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
