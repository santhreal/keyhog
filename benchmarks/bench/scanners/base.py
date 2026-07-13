"""Scanner contract + shared subprocess measurement.

Every adapter yields normalised findings (``{file, line, value, detector}``,
plus scanner-specific evidence such as ``offset`` and ``confidence``)
and a :class:`RunStats`. Measurement is uniform across scanners:

* **wall** (a monotonic ``perf_counter`` around the whole invocation).
* **peak RSS**: ``/usr/bin/time -v -o <file>`` parsed for "Maximum resident
  set size", with a ``resource.getrusage(RUSAGE_CHILDREN)`` fallback where
  GNU time is absent (macOS / minimal containers). Never raises.
* **throughput**, corpus bytes / wall, filled in by the runner which knows
  the corpus size.

Findings always go to a ``--output`` file or stdout that GNU time's report
never touches (the report lands in a separate ``-o`` file), so parsing the
two never crosses streams.

Cold-start amortisation (the 257x score.py documents) is preserved:
``scan_roots`` collapses per-fixture paths to the single common ancestor so
a recursive scanner pays one warm()/compile/probe over the whole corpus.
"""

from __future__ import annotations

import os
import pathlib
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..schema import ScannerConfig

try:
    import resource
except ImportError:  # pragma: no cover - Windows has no resource module.
    resource = None

Finding = dict


def _line(value: object) -> int:
    """Coerce a scanner's reported line number to int, defaulting to 0 for
    missing/garbage values. Shared by every adapter's normaliser."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


@dataclass
class RunStats:
    wall_ms: float = 0.0
    peak_rss_kb: int = 0
    throughput_mb_s: float = 0.0
    exit_code: int = 0
    timed_out: bool = False


@dataclass(frozen=True)
class MeasurementProvenance:
    """Exact immutable inputs that produced one measured scanner result."""

    scanner_version: str = ""
    executable_sha256: str = ""
    detector_corpus_sha256: str = ""
    execution_route: str = ""
    daemon_pid: int = 0
    daemon_requests: int = 0


# ── path collapse (verbatim intent from score.py::_scan_roots) ────────


def scan_roots(file_paths: list[pathlib.Path]) -> list[pathlib.Path]:
    """Collapse per-fixture paths to the smallest covering set of dirs so a
    recursive scanner pays ONE cold-start over the corpus. Single common
    ancestor when one exists, else distinct parents."""
    parents = sorted({fp.parent for fp in file_paths})
    if not parents:
        return []
    try:
        common = pathlib.Path(os.path.commonpath([str(p) for p in parents]))
    except ValueError:
        return parents
    return [common]


# ── measured subprocess ───────────────────────────────────────────────

def _find_gnu_time() -> str | None:
    candidates = [shutil.which("gtime"), "/usr/bin/time"]
    for candidate in candidates:
        if not candidate:
            continue
        path = pathlib.Path(candidate)
        if not path.exists():
            continue
        try:
            completed = subprocess.run(
                [str(path), "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if "GNU" in f"{completed.stdout}\n{completed.stderr}":
            return str(path)
    return None


_GNU_TIME = _find_gnu_time()
_RSS_RE = re.compile(r"Maximum resident set size \(kbytes\):\s*(\d+)")


def _has_gnu_time() -> bool:
    return _GNU_TIME is not None


def _child_maxrss_kb() -> int | None:
    if resource is None:
        return None
    rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if sys.platform == "darwin":
        rss //= 1024
    return int(rss)


def run_measured(
    cmd: list[str],
    *,
    env: dict | None = None,
    cwd: str | None = None,
    timeout: int = 1800,
    pass_fds: tuple[int, ...] = (),
) -> tuple[str, str, RunStats]:
    """Run ``cmd``, return (stdout, stderr, RunStats). GNU time captures peak
    RSS into a private file so the child's own stdout/stderr stay clean for
    the adapter to parse findings from."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)

    rss_file = None
    run_cmd = cmd
    if _has_gnu_time():
        rss_file = tempfile.NamedTemporaryFile(
            mode="r", suffix=".time", delete=False)
        rss_file.close()
        assert _GNU_TIME is not None
        run_cmd = [_GNU_TIME, "-v", "-o", rss_file.name, *cmd]

    t0 = time.perf_counter()
    timed_out = False
    try:
        popen_kwargs = {}
        if os.name == "nt":
            popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            popen_kwargs["start_new_session"] = True
            if pass_fds:
                popen_kwargs["pass_fds"] = pass_fds
        process = subprocess.Popen(
            run_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=full_env,
            cwd=cwd,
            **popen_kwargs,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            rc = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_tree(process)
            stdout, stderr = process.communicate()
            rc = -1
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        rc = -1
        timed_out = True
    wall_ms = (time.perf_counter() - t0) * 1000.0

    peak_rss_kb = 0
    if rss_file is not None:
        try:
            text = pathlib.Path(rss_file.name).read_text()
            m = _RSS_RE.search(text)
            if m:
                peak_rss_kb = int(m.group(1))
        except OSError:
            pass
        finally:
            try:
                os.unlink(rss_file.name)
            except OSError:
                pass
    if peak_rss_kb == 0:
        # Fallback (no GNU time, macOS / minimal containers): RUSAGE_CHILDREN
        # ru_maxrss is a MONOTONIC HIGH-WATER MARK across ALL children this
        # process ever reaped, NOT a per-run figure, once a large scan runs,
        # every later fallback measurement in the same process reports at least
        # that peak. GNU time (`/usr/bin/time -v`) is the accurate per-run path
        # and is used whenever present (the whole Linux fleet); treat this value
        # as an upper-bound proxy only. Windows has no resource module, so peak
        # RSS stays 0 there without GNU time.
        after = _child_maxrss_kb()
        if after is not None:
            peak_rss_kb = after

    return stdout, stderr, RunStats(
        wall_ms=wall_ms, peak_rss_kb=peak_rss_kb, exit_code=rc, timed_out=timed_out)


def _kill_process_tree(process: subprocess.Popen) -> None:
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return
        except (OSError, ValueError):
            pass
        process.kill()
        return

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


# ── version probe (verbatim intent from score.py::scanner_version) ────


def probe_version(binary: str, args: tuple[str, ...] = ("--version",)) -> str:
    """Best-effort ``<binary> <args>`` (default ``--version``) so a result
    records exactly which build produced it (closes the stale-binary
    provenance gap). ``args`` lets a scanner whose version command differs
    (e.g. titus ``version``) reuse this. Returns "" if the binary is absent or
    the probe fails, never raises."""
    if shutil.which(binary) is None and not pathlib.Path(binary).exists():
        return ""
    try:
        completed = subprocess.run(
            [binary, *args], capture_output=True, text=True,
            check=False, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    out = (completed.stdout or completed.stderr or "").strip()
    return " ".join(line.strip() for line in out.splitlines() if line.strip())


# ── the contract ───────────────────────────────────────────────────────


class Scanner(ABC):
    #: short stable id used in result filenames + reports
    name: str = ""
    #: default binary name (resolved on PATH unless an env override is set)
    binary_name: str = ""
    #: env var that overrides the binary path (e.g. KEYHOG_BIN)
    binary_env: str = ""
    #: process exit codes that still mean the scanner completed.
    success_exit_codes: tuple[int, ...] = (0,)

    def __init__(self, binary: str | None = None):
        self._binary = binary

    @property
    def binary(self) -> str:
        if self._binary:
            return self._binary
        if self.binary_env and os.environ.get(self.binary_env):
            return os.environ[self.binary_env]
        return self.binary_name

    def available(self) -> bool:
        b = self.binary
        return shutil.which(b) is not None or pathlib.Path(b).exists()

    def version(self) -> str:
        return probe_version(self.binary)

    def exit_success(self, code: int) -> bool:
        return code in self.success_exit_codes

    def default_config(self) -> ScannerConfig:
        """The single config used for the headline leaderboard."""
        return self.variants()[0]

    @abstractmethod
    def variants(self) -> list[ScannerConfig]:
        """Config points this scanner supports. variants()[0] is the default."""

    @abstractmethod
    def run(self, root: pathlib.Path, cfg: ScannerConfig,
            output: pathlib.Path | None = None) -> tuple[list[Finding], RunStats]:
        """Scan ``root`` under ``cfg``; return (normalised findings, stats)."""


def resolve_scanner(name: str, **kw) -> Scanner:
    """Factory: scanner name -> adapter, driven by the single ``SCANNERS``
    registry (:mod:`bench.scanners`) so there is one place adapters register."""
    from . import SCANNERS  # deferred: the registry imports this module

    key = name.lower()
    try:
        return SCANNERS[key](**kw)
    except KeyError:
        raise SystemExit(
            f"unknown scanner {name!r}; known: {', '.join(SCANNERS)}"
        ) from None
