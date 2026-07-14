"""Owned KeyHog daemon lifecycle for single-file benchmark measurements."""

from __future__ import annotations

import os
import pathlib
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import types
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanners.base import RunStats

_STATUS_SCANS_RE = re.compile(r"\b(\d+) scans served\b")
_STATUS_ACTIVE_RE = re.compile(r"\b(\d+) active\b")
_COVERAGE_GAP_MARKER = "daemon input coverage was incomplete"


def run_measured(
    command: list[str], *, timeout: int, pass_fds: tuple[int, ...]
) -> tuple[str, str, RunStats]:
    """Measure a client without importing the scanner registry at module load."""
    from .scanners.base import run_measured as measure

    return measure(command, timeout=timeout, pass_fds=pass_fds)


def validate_daemon_benchmark(root: pathlib.Path, backend: str, cache: str, mode: str) -> None:
    if not sys.platform.startswith("linux"):
        raise RuntimeError(
            "daemon benchmark evidence requires Linux SO_PEERCRED process ownership"
        )
    if not root.is_file():
        raise RuntimeError(
            "daemon benchmark rows require the unlabeled daemon-file corpus: "
            f"{root} is not one regular file"
        )
    if backend not in {"simd", "cpu", "gpu"}:
        raise RuntimeError(
            "daemon benchmark rows require an explicit simd, cpu, or gpu backend; "
            "auto lacks a persisted selected-backend execution receipt"
        )
    if cache != "off":
        raise RuntimeError(
            "daemon benchmark rows do not support the incremental cache axis; "
            "the daemon's compiled scanner is already persistent"
        )
    if mode != "full":
        raise RuntimeError(
            "daemon benchmark rows support only full mode because daemon startup "
            "does not accept fast or deep scan policy"
        )


def daemon_server_command(
    executable: pathlib.Path,
    socket_path: pathlib.Path,
    detector_corpus: pathlib.Path,
    backend: str,
) -> list[str]:
    return [
        str(executable),
        "daemon",
        "start",
        "--socket",
        str(socket_path),
        "--detectors",
        str(detector_corpus),
        "--backend",
        backend,
    ]


def daemon_client_command(
    executable: pathlib.Path,
    socket_path: pathlib.Path,
    root: pathlib.Path,
    output: pathlib.Path,
) -> list[str]:
    return [
        str(executable),
        "scan",
        "--format",
        "json",
        "--no-config",
        "--daemon=on",
        "--daemon-socket",
        str(socket_path),
        "--output",
        str(output),
        str(root),
    ]


@dataclass(frozen=True)
class DaemonEvidence:
    pid: int
    scans_served: int
    active_scans: int
    peak_rss_kb: int


class OwnedKeyhogDaemon:
    def __init__(
        self,
        executable: pathlib.Path,
        pass_fds: tuple[int, ...],
        detector_corpus: pathlib.Path,
        backend: str,
        timeout: int,
    ) -> None:
        self.executable = executable
        self.pass_fds = pass_fds
        self.detector_corpus = detector_corpus
        self.backend = backend
        self.timeout = timeout
        self._tempdir: tempfile.TemporaryDirectory | None = None
        self._stderr_handle = None
        self._process: subprocess.Popen[str] | None = None
        self.socket_path = pathlib.Path()

    def __enter__(self) -> "OwnedKeyhogDaemon":
        self._tempdir = tempfile.TemporaryDirectory(prefix="keyhog-bench-daemon-")
        root = pathlib.Path(self._tempdir.name)
        root.chmod(0o700)
        self.socket_path = root / "keyhog.sock"
        stderr_path = root / "daemon.stderr"
        self._stderr_handle = stderr_path.open("w+", encoding="utf-8")
        kwargs = {
            "stdout": subprocess.DEVNULL,
            "stderr": self._stderr_handle,
            "text": True,
            "start_new_session": True,
        }
        if self.pass_fds:
            kwargs["pass_fds"] = self.pass_fds
        try:
            self._process = subprocess.Popen(
                daemon_server_command(
                    self.executable,
                    self.socket_path,
                    self.detector_corpus,
                    self.backend,
                ),
                **kwargs,
            )
            self._wait_ready()
            scans_served, active_scans = self.status()
            if scans_served != 0 or active_scans != 0:
                raise RuntimeError(
                    "new benchmark daemon did not start with zero served or active scans"
                )
            return self
        except BaseException as primary:
            cleanup_error = self._cleanup_failed_start()
            if cleanup_error is not None:
                raise primary.with_traceback(primary.__traceback__) from cleanup_error
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> bool:
        cleanup_errors: list[BaseException] = []
        try:
            self._stop_and_reap()
        except BaseException as error:
            cleanup_errors.append(error)
            try:
                self._force_reap()
            except BaseException as force_error:
                cleanup_errors.append(force_error)
        try:
            self._close_artifacts()
        except BaseException as close_error:
            cleanup_errors.append(close_error)
        cleanup_error = self._combined_cleanup_error(cleanup_errors)
        if exc is not None:
            if cleanup_error is not None:
                raise exc.with_traceback(traceback) from cleanup_error
            return False
        if cleanup_error is not None:
            raise cleanup_error
        return False

    def _cleanup_failed_start(self) -> BaseException | None:
        errors: list[BaseException] = []
        try:
            self._force_reap()
        except BaseException as error:
            errors.append(error)
        try:
            self._close_artifacts()
        except BaseException as error:
            errors.append(error)
        return self._combined_cleanup_error(errors)

    @staticmethod
    def _combined_cleanup_error(errors: list[BaseException]) -> BaseException | None:
        if not errors:
            return None
        if len(errors) == 1:
            return errors[0]
        details = "; ".join(f"{type(error).__name__}: {error}" for error in errors)
        return RuntimeError(f"multiple daemon cleanup failures: {details}")

    @property
    def pid(self) -> int:
        if self._process is None:
            raise RuntimeError("benchmark daemon process has not started")
        return self._process.pid

    def run_client(self, root: pathlib.Path, output: pathlib.Path, timeout: int) -> RunStats:
        self._assert_owned_peer()
        _stdout, stderr, stats = run_measured(
            daemon_client_command(self.executable, self.socket_path, root, output),
            timeout=timeout,
            pass_fds=self.pass_fds,
        )
        if stats.timed_out:
            raise TimeoutError(
                f"daemon benchmark client timed out after {timeout}s; "
                "the owned daemon will be terminated"
            )
        if _COVERAGE_GAP_MARKER in stderr:
            raise RuntimeError(
                "daemon benchmark input coverage was incomplete; refusing to record "
                "partial-file throughput"
            )
        if stats.exit_code not in (0, 1, 10):
            raise RuntimeError(
                f"daemon benchmark client exited {stats.exit_code}: {stderr.strip()}"
            )
        self._assert_owned_peer()
        stats.peak_rss_kb = self._peak_rss_kb()
        return stats

    def evidence(self) -> DaemonEvidence:
        scans_served, active_scans = self.status()
        return DaemonEvidence(
            pid=self.pid,
            scans_served=scans_served,
            active_scans=active_scans,
            peak_rss_kb=self._peak_rss_kb(),
        )

    def scans_served(self) -> int:
        return self.status()[0]

    def status(self) -> tuple[int, int]:
        self._assert_owned_peer()
        completed = self._admin("status", timeout=min(self.timeout, 30))
        scans_match = _STATUS_SCANS_RE.search(completed.stdout)
        active_match = _STATUS_ACTIVE_RE.search(completed.stdout)
        if scans_match is None or active_match is None:
            raise RuntimeError(
                "daemon status did not report machine-checkable served and active counts: "
                f"{completed.stdout.strip()!r}"
            )
        return int(scans_match.group(1)), int(active_match.group(1))

    def _assert_owned_peer(self) -> None:
        process = self._process
        if process is None:
            raise RuntimeError("benchmark daemon process has not started")
        rc = process.poll()
        if rc is not None:
            raise RuntimeError(
                f"owned benchmark daemon exited {rc}: {self._stderr_text()}"
            )
        peer_pid = self._peer_pid()
        if peer_pid != process.pid:
            raise RuntimeError(
                f"private daemon socket peer pid {peer_pid} != owned pid {process.pid}"
            )

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + self.timeout
        delay = 0.01
        last_error = "socket not ready"
        while time.monotonic() < deadline:
            process = self._process
            if process is None:
                raise RuntimeError("benchmark daemon process was not created")
            rc = process.poll()
            if rc is not None:
                raise RuntimeError(
                    f"benchmark daemon exited {rc} before readiness: {self._stderr_text()}"
                )
            if self.socket_path.exists():
                try:
                    peer_pid = self._peer_pid()
                    if peer_pid != process.pid:
                        raise RuntimeError(
                            f"private daemon socket peer pid {peer_pid} != owned pid {process.pid}"
                        )
                    self._admin("status", timeout=min(self.timeout, 30))
                    return
                except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
                    last_error = str(exc)
            time.sleep(delay)
            delay = min(delay * 2, 0.25)
        raise TimeoutError(
            f"benchmark daemon was not ready after {self.timeout}s: {last_error}; "
            f"stderr={self._stderr_text()}"
        )

    def _peer_pid(self) -> int:
        if not hasattr(socket, "SO_PEERCRED"):
            raise RuntimeError("Linux SO_PEERCRED is unavailable on this Python runtime")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(min(self.timeout, 5))
            client.connect(str(self.socket_path))
            peercred = getattr(socket, "SO_PEERCRED")
            payload = client.getsockopt(
                socket.SOL_SOCKET, peercred, struct.calcsize("3i")
            )
        pid, _uid, _gid = struct.unpack("3i", payload)
        return pid

    def _admin(self, action: str, timeout: int) -> subprocess.CompletedProcess[str]:
        kwargs = {
            "capture_output": True,
            "text": True,
            "timeout": timeout,
            "check": False,
        }
        if self.pass_fds:
            kwargs["pass_fds"] = self.pass_fds
        completed = subprocess.run(
            [str(self.executable), "daemon", action, "--socket", str(self.socket_path)],
            **kwargs,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"daemon {action} exited {completed.returncode}: "
                f"{(completed.stderr or completed.stdout).strip()}"
            )
        return completed

    def _stop_and_reap(self) -> None:
        process = self._process
        if process is None:
            return
        if process.poll() is None:
            self._admin("stop", timeout=min(self.timeout, 30))
        try:
            rc = process.wait(timeout=min(self.timeout, 30))
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("benchmark daemon did not exit after confirmed shutdown") from exc
        if rc != 0:
            raise RuntimeError(
                f"benchmark daemon exited {rc} during shutdown: {self._stderr_text()}"
            )
        if self.socket_path.exists():
            raise RuntimeError(
                f"benchmark daemon exited but left its private socket {self.socket_path}"
            )

    def _force_reap(self) -> None:
        process = self._process
        if process is None or process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)

    def _peak_rss_kb(self) -> int:
        status = pathlib.Path(f"/proc/{self.pid}/status")
        try:
            for line in status.read_text(encoding="utf-8").splitlines():
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
        except (OSError, ValueError, IndexError) as exc:
            raise RuntimeError(
                f"cannot read daemon peak RSS from {status}: {exc}"
            ) from exc
        raise RuntimeError(f"daemon peak RSS is missing from {status}")

    def _stderr_text(self) -> str:
        handle = self._stderr_handle
        if handle is None:
            return ""
        handle.flush()
        handle.seek(0)
        return handle.read()[-2000:]

    def _close_artifacts(self) -> None:
        errors: list[BaseException] = []
        if self._stderr_handle is not None:
            try:
                self._stderr_handle.close()
            except BaseException as error:
                errors.append(error)
            finally:
                self._stderr_handle = None
        if self._tempdir is not None:
            try:
                self._tempdir.cleanup()
            except BaseException as error:
                errors.append(error)
            finally:
                self._tempdir = None
        cleanup_error = self._combined_cleanup_error(errors)
        if cleanup_error is not None:
            raise cleanup_error
