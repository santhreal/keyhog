"""Measure every workload regime and write the matrix.

Run the generator first, then this. Each regime is scanned `--reps` times; the
reported number is the median, because the machine this runs on is rarely idle
and a single sample is noise.

    python3 benchmarks/workload_matrix/generate.py --root /tmp/keyhog-wm
    python3 benchmarks/workload_matrix/run.py --root /tmp/keyhog-wm \
        --binary target/release/keyhog --out benchmarks/reports/workload-matrix.md

Per regime you get: wall seconds, CPU percent, peak RSS, total findings, canary
findings, exit code, scan status, and the coverage gaps the scan admitted to.

The canary column is the one that matters. `canary=0` on a regime whose corpus
contains the canary means the scan never reached those bytes. If the same row
also shows `status=complete` and `exit=0`, that is a SILENT CLEAN: the worst
outcome this product can produce, because the operator is told the tree is fine.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from canary import CANARY_DETECTOR, CANARY_REDACTED, canary_bytes  # noqa: E402
from generate import BUILDERS, REGIMES, force_rmtree, stamp_path  # noqa: E402

TIME_BIN = "/usr/bin/time"

# Regimes whose corpus deliberately holds no canary. Everything else must find
# at least one, or the row is a coverage hole.
NO_CANARY = {"empty_dir"}

# Extra keyhog arguments per regime, where the regime only makes sense with
# them. Keep this list short and justified: the matrix measures the DEFAULT
# scan, and anything here is a documented exception.
REGIME_ARGS: dict[str, list[str]] = {
    # A minified bundle is on the default-exclusion list, so the default scan
    # would skip it for the wrong reason and tell us nothing about long-line
    # handling. Disable the exclusions so the bytes actually reach the scanner.
    "one_long_line": ["--no-default-excludes"],
    # 300 MiB is above the 100 MiB default cap, so a default scan refuses the
    # file and this row would measure the cap instead of the large-file regime.
    # Raise the cap so the bytes are actually read. What the DEFAULT scan does
    # with an over-cap file is measured by `over_max_size`.
    "one_large": ["--max-file-size", "512M"],
}


def binary_identity(binary: Path) -> dict:
    """Name the exact artifact that produced the numbers.

    Shared build directories get overwritten. A matrix that says only
    "target/release-fast/keyhog" is not reproducible, and a comparison that
    unknowingly spans two builds is worse than no comparison.
    """
    digest = hashlib.sha256()
    with binary.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    st = binary.stat()
    version = subprocess.run(
        [str(binary), "--version"], capture_output=True, text=True
    ).stdout.splitlines()
    return {
        "path": str(binary),
        "sha256": digest.hexdigest(),
        "bytes": st.st_size,
        "mtime": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(st.st_mtime)),
        "version": version[0] if version else "unknown",
    }


def which_time() -> str:
    if Path(TIME_BIN).exists():
        return TIME_BIN
    found = shutil.which("time")
    if not found:
        raise SystemExit("GNU time not found; install it (apt install time)")
    return found


class Mutator(threading.Thread):
    """Change file sizes underneath a running scan.

    Only used by the `size_changing` regime. Appends to `grow.log` and
    repeatedly truncates `shrink.log` until stopped, so the scan observes a
    file whose length does not match what it was told at open time.
    """

    def __init__(self, regime_dir: Path):
        super().__init__(daemon=True)
        self.dir = regime_dir
        self.stop = threading.Event()
        self.appends = 0
        self.truncations = 0

    def run(self) -> None:
        grow = self.dir / "grow.log"
        shrink = self.dir / "shrink.log"
        blob = b"padding = 0123456789abcdef\n" * 4096
        target = 1024
        while not self.stop.is_set():
            try:
                with grow.open("ab") as fh:
                    fh.write(blob)
                self.appends += 1
            except OSError:
                pass
            try:
                with shrink.open("r+b") as fh:
                    fh.truncate(target)
                self.truncations += 1
                target = 1024 if target > 4 * 1024 * 1024 else target * 4
            except OSError:
                pass
            time.sleep(0.002)


def parse_time_line(text: str) -> dict:
    """Parse the `%e %P %M %x` line GNU time appends to its stderr file.

    GNU time prefixes its own "Command exited with non-zero status N" line
    whenever the child exits nonzero, and keyhog exits nonzero on every regime
    that finds a secret. Take the last line that actually parses.
    """
    signalled = None
    for line in text.splitlines():
        # `%x` is 0 when the child died by a signal, so the format line alone
        # cannot distinguish a crash from a clean exit. GNU time states it here
        # and nowhere else. Missing this reported a SIGBUS as exit 0.
        if "terminated by signal" in line:
            try:
                signalled = int(line.rsplit(None, 1)[1])
            except (IndexError, ValueError):
                signalled = -1
    for line in reversed(text.strip().splitlines()):
        parts = line.split()
        if len(parts) != 4:
            continue
        try:
            return {
                "wall_s": float(parts[0]),
                "cpu_pct": float(parts[1].rstrip("%")),
                "peak_rss_kib": int(parts[2]),
                "exit_code": int(parts[3]),
                "killed_by_signal": signalled,
            }
        except ValueError:
            continue
    return {}


def read_envelope(path: Path) -> tuple[dict, str]:
    """Load the envelope and say WHY it is unusable when it is.

    "No envelope" has three very different causes and the fix differs for each:
    the scan never wrote the file, wrote an empty one, or wrote something that
    is not JSON. Collapsing them into a falsy dict hides which.
    """
    if not path.exists():
        return {}, "not written"
    raw = path.read_bytes()
    if not raw:
        return {}, "written empty"
    try:
        return json.loads(raw), "ok"
    except ValueError as error:
        return {}, f"unparseable: {error}"


# Regimes whose corpus is destroyed by their own measurement and must be
# rebuilt before every repetition, or rep 2 measures a different workload
# than rep 1.
RESEED = {"size_changing"}


def dogfood_probe(
    binary: Path,
    regime: str,
    regime_dir: Path,
    work: Path,
    extra: list[str],
    timeout: float,
) -> str | None:
    """Ask the scanner whether it MATCHED the canary and then dropped it.

    A zero-finding regime has two very different causes: the bytes were never
    read, or they were read and a suppression gate hid them. `--dogfood` is the
    only way to tell from outside, and the difference decides where the fix
    goes. Returns the suppression reason, or None.

    This runs once per regime, outside the timed repetitions, because
    `--dogfood` adds bookkeeping the timings should not carry.
    """
    cmd = [
        str(binary),
        "scan",
        str(regime_dir),
        "--no-config",
        "--no-color",
        "--quiet",
        "--backend",
        "simd",
        "--dogfood",
        "--format",
        "json",
        "-o",
        str(work / "dogfood-findings.json"),
        *extra,
        *REGIME_ARGS.get(regime, []),
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(regime_dir.parent),
        )
    except subprocess.TimeoutExpired:
        return None
    for line in proc.stderr.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        for event in (payload.get("dogfood") or {}).get("events") or []:
            if CANARY_REDACTED == (event.get("credential_redacted") or ""):
                return event.get("reason") or event.get("kind")
    return None


def one_run(
    binary: Path,
    regime: str,
    regime_dir: Path,
    work: Path,
    extra: list[str],
    timeout: float,
) -> dict:
    env_out = work / "envelope.json"
    time_out = work / "time.txt"
    log_out = work / "stderr.txt"
    for p in (env_out, time_out, log_out):
        p.unlink(missing_ok=True)
    if regime in RESEED:
        # The mutator appends without bound; without this, grow.log crosses
        # --max-file-size after a rep or two and the row silently turns into
        # an over-max-size skip measurement instead of a mid-scan-mutation one.
        scale = 1.0
        sp = stamp_path(regime_dir)
        if sp.exists():
            try:
                scale = json.loads(sp.read_text()).get("scale", 1.0)
            except (OSError, ValueError):
                pass
        force_rmtree(regime_dir)
        regime_dir.mkdir(parents=True, exist_ok=True)
        BUILDERS[regime](regime_dir, scale)

    cmd = [
        which_time(),
        "-f",
        "%e %P %M %x",
        "-o",
        str(time_out),
        str(binary),
        "scan",
        str(regime_dir),
        "--no-config",
        "--no-color",
        "--backend",
        "simd",
        # Default `--dedup credential` collapses the SAME credential across
        # files into one finding, which makes the canary count useless: a regime
        # that plants it in eight files and finds it in one is indistinguishable
        # from finding it in all eight. `file` scope keeps one finding per file
        # so the canary column measures COVERAGE. It changes the finding counts
        # relative to a default scan by design.
        "--dedup",
        "file",
        "--format",
        "json-envelope",
        "-o",
        str(env_out),
        *extra,
        *REGIME_ARGS.get(regime, []),
    ]

    # Run from the corpus root, NOT from wherever the harness was invoked.
    # keyhog's `-d detectors` default resolves relative to the working directory,
    # so invoking from a checkout picks up that checkout's on-disk corpus. A
    # broken detector TOML there fails scanner construction with exit 2, which
    # produces zero findings for a reason that has nothing to do with the regime.
    # From the corpus root there is no `detectors/`, so the embedded corpus is
    # used and the measurement is a property of the input alone.
    scan_cwd = str(regime_dir.parent)

    mutator = Mutator(regime_dir) if regime == "size_changing" else None
    if mutator:
        mutator.start()

    started = time.monotonic()
    timed_out = False
    signalled = None
    try:
        with log_out.open("wb") as errfh:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=errfh,
                timeout=timeout,
                cwd=scan_cwd,
            )
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        rc = None
    wall_outer = time.monotonic() - started

    if mutator:
        mutator.stop.set()
        mutator.join(timeout=5)

    metrics = parse_time_line(time_out.read_text() if time_out.exists() else "")
    envelope, envelope_state = read_envelope(env_out)
    findings = envelope.get("findings") or []
    canary = sum(1 for f in findings if f.get("detector_id") == CANARY_DETECTOR)
    stderr_text = log_out.read_text(errors="replace") if log_out.exists() else ""

    exit_code = metrics.get("exit_code", rc)
    killed = metrics.get("killed_by_signal")
    if killed is None and rc is not None and rc < 0:
        killed = -rc
    if killed is None and exit_code is not None and exit_code > 128:
        killed = exit_code - 128
    if killed is not None and killed > 0:
        try:
            signalled = signal.Signals(killed).name
        except ValueError:
            signalled = f"signal {killed}"

    return {
        "wall_s": metrics.get("wall_s", wall_outer),
        "cpu_pct": metrics.get("cpu_pct", 0.0),
        "peak_rss_kib": metrics.get("peak_rss_kib", 0),
        "exit_code": exit_code,
        "signal": signalled,
        "timed_out": timed_out,
        "findings": len(findings),
        "canary": canary,
        "scan_status": envelope.get("scan_status"),
        "coverage_gaps": envelope.get("coverage_gap_summary") or [],
        "bytes_scanned": (envelope.get("metadata") or {}).get("source_bytes_scanned"),
        "chunks_scanned": (envelope.get("metadata") or {}).get("source_chunks_scanned"),
        "envelope_written": bool(envelope),
        "envelope_state": envelope_state,
        "panic": "panicked at" in stderr_text or exit_code == 11,
        "stderr_tail": stderr_text[-4000:],
        "mutations": (
            {"appends": mutator.appends, "truncations": mutator.truncations}
            if mutator
            else None
        ),
    }


def classify(regime: str, agg: dict, facts: dict) -> tuple[str, list[str]]:
    """Verdict for one row, worst first, because that is also the fix order.

    SILENT CLEAN   a canary copy was missed, the scan exited 0, and
                   `coverage_gap_summary` is empty. An operator reading the exit
                   code or the envelope is told the tree is fine. It is not.
    PANIC          the scanner died. No report, and every other finding in that
                   scan is lost with it.
    NO REPORT      the scan failed loudly but wrote no machine-readable artifact,
                   so a pipeline reading `-o` gets a missing file. Loud to a
                   shell, silent to everything else.
    QUIET CLEAN    a copy was missed and a coverage gap WAS recorded, but the
                   exit code is still 0, so a CI gate on `$?` passes over it.
    LOUD MISS      a copy was missed and the scan refused to report success.
                   Working as intended: a gap you can act on.
    PARTIAL        every copy was found, but part of the input was not scanned.

    `canary_copies` comes from the regime's own stamp. Comparing against it, not
    against zero, is what catches a regime that plants the canary in eight files
    and reports it from one.
    """
    notes: list[str] = []
    expected = facts.get("canary_copies")
    if expected is None:
        expected = 0 if regime in NO_CANARY else 1
    found = agg["canary"]
    has_gaps = bool(agg["coverage_gaps"])
    clean_exit = agg["exit_code"] == 0

    if agg["panic"]:
        notes.append("scanner panicked mid-scan.")
        return "PANIC", notes
    if agg["signal"]:
        notes.append(
            f"killed by {agg['signal']} in at least one repetition, "
            "so the whole scan's report was lost."
        )
        return "PANIC", notes
    if agg["timed_out"]:
        notes.append("exceeded the harness timeout.")
        return "HANG", notes
    if not agg["envelope_written"]:
        notes.append(
            "the machine-readable envelope requested with `-o` was "
            f"{agg.get('envelope_state', 'unusable')}, so a pipeline reading it "
            "gets nothing to act on."
        )
        if not clean_exit:
            notes.append(
                f"the scan did exit {agg['exit_code']}, so a shell sees the "
                "failure even though no artifact describes it."
            )
            return "NO REPORT", notes
        return "BROKEN", notes

    if found < expected:
        notes.append(f"found {found} of {expected} planted canary copies.")
        suppressed = agg.get("canary_suppressed_reason")
        if suppressed:
            notes.append(
                f"a `--dogfood` probe of this corpus reports a canary-shaped "
                f"credential suppressed by `{suppressed}`. That proves a "
                "suppression gate is active on this input; it does not by itself "
                "prove the MISSING copy went that way rather than never being "
                "read. Compare bytes scanned."
            )
        if clean_exit and not has_gaps:
            notes.append(
                f"exit 0, scan_status {agg['scan_status']}, and an empty "
                "coverage_gap_summary: nothing tells the operator a credential "
                "was missed."
            )
            return "SILENT CLEAN", notes
        if clean_exit:
            notes.append(
                "exit 0 despite an admitted coverage gap, so a CI gate on the "
                "exit code passes over the missed credential."
            )
            return "QUIET CLEAN", notes
        notes.append(f"the scan refused to report success (exit {agg['exit_code']}).")
        return "LOUD MISS", notes

    if found > expected:
        notes.append(
            f"found {found} canary copies but only {expected} were planted; "
            "the regime's own accounting is wrong, not the scanner's."
        )
        return "BROKEN", notes

    if has_gaps:
        notes.append(
            "every canary copy was found, but part of the input was not scanned."
        )
        return "PARTIAL", notes

    return "OK", notes


def aggregate(runs: list[dict]) -> dict:
    def med(key: str):
        vals = [r[key] for r in runs if r.get(key) is not None]
        return statistics.median(vals) if vals else None

    last = runs[-1]
    return {
        "reps": len(runs),
        "wall_s": med("wall_s"),
        "wall_min_s": min(r["wall_s"] for r in runs),
        "wall_max_s": max(r["wall_s"] for r in runs),
        "cpu_pct": med("cpu_pct"),
        "peak_rss_kib": med("peak_rss_kib"),
        "exit_code": last["exit_code"],
        # A crash or an unusable envelope in ANY repetition is the finding. The
        # last repetition happening to succeed does not undo it.
        "signal": next((r["signal"] for r in runs if r["signal"]), None),
        "timed_out": any(r["timed_out"] for r in runs),
        "findings": min(r["findings"] for r in runs),
        "canary": min(r["canary"] for r in runs),
        "canary_max": max(r["canary"] for r in runs),
        "scan_status": last["scan_status"],
        "coverage_gaps": last["coverage_gaps"],
        "bytes_scanned": last["bytes_scanned"],
        "chunks_scanned": last["chunks_scanned"],
        "envelope_written": all(r["envelope_written"] for r in runs),
        "envelope_state": next(
            (r["envelope_state"] for r in runs if r["envelope_state"] != "ok"),
            "ok",
        ),
        "panic": any(r["panic"] for r in runs),
        "stderr_tail": last["stderr_tail"],
        "mutations": last["mutations"],
        "exit_codes_seen": sorted({r["exit_code"] for r in runs}),
        "findings_seen": sorted({r["findings"] for r in runs}),
    }


def human_bytes(n) -> str:
    if not n:
        return "-"
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return str(n)


def gap_text(gaps: list[dict]) -> str:
    if not gaps:
        return "none"
    return "; ".join(f"{g.get('reason')} x{g.get('count')}" for g in gaps)


def render_markdown(results: dict, meta: dict) -> str:
    lines = []
    lines.append("# Workload regime matrix")
    lines.append("")
    b = meta["binary"]
    lines.append(f"- binary: `{b['path']}`")
    lines.append(f"- version: {b['version']}")
    lines.append(f"- sha256: `{b['sha256']}`")
    lines.append(f"- binary mtime: {b['mtime']}, {b['bytes']} bytes")
    lines.append(f"- corpus root: `{meta['root']}` (scale {meta['scale']})")
    lines.append(f"- host: {meta['cores']} cores, load average {meta['loadavg']}")
    lines.append(f"- reps per regime: {meta['reps']} (reported value is the median)")
    lines.append(
        "- controls: a canary-only file yields "
        f"{meta['controls']['positive_findings']} canary finding; the same file "
        "with the credential shape broken yields "
        f"{meta['controls']['negative_findings']}. Every zero below is measured "
        "against a proven-visible baseline."
    )
    lines.append(f"- generated: {meta['generated_at']}")
    lines.append("")
    lines.append(
        "Absolute wall times on a loaded machine are not comparable across sessions. "
        "Read the ratios between regimes and the CPU percent, not the seconds."
    )
    lines.append("")
    lines.append(
        "| regime | wall s | CPU % | peak RSS | bytes scanned | findings | canary found/planted | exit | status | verdict |"
    )
    lines.append(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"
    )
    for name in results:
        r = results[name]
        agg = r["agg"]
        rss = f"{agg['peak_rss_kib'] / 1024:.0f} MiB" if agg["peak_rss_kib"] else "-"
        lines.append(
            "| `{name}` | {wall:.2f} | {cpu:.0f} | {rss} | {bytes} | {f} | {c} | {e} | {s} | {v} |".format(
                name=name,
                wall=agg["wall_s"] or 0.0,
                cpu=agg["cpu_pct"] or 0.0,
                rss=rss,
                bytes=human_bytes(agg["bytes_scanned"]),
                f=agg["findings"],
                c=f"{agg['canary']}/{r['facts'].get('canary_copies', '?')}",
                e=agg["exit_code"],
                s=agg["scan_status"] or "-",
                v=r["verdict"],
            )
        )
    lines.append("")
    lines.append("## What the scan admitted per regime")
    lines.append("")
    lines.append("| regime | coverage gaps | canary suppressed by |")
    lines.append("| --- | --- | --- |")
    for name, r in results.items():
        agg = r["agg"]
        lines.append(
            f"| `{name}` | {gap_text(agg['coverage_gaps'])} "
            f"| {agg.get('canary_suppressed_reason') or '-'} |"
        )
    lines.append("")
    order = [
        "SILENT CLEAN",
        "PANIC",
        "NO REPORT",
        "HANG",
        "BROKEN",
        "QUIET CLEAN",
        "LOUD MISS",
        "PARTIAL",
    ]
    broken = [
        (n, r)
        for n, r in sorted(
            results.items(),
            key=lambda kv: order.index(kv[1]["verdict"])
            if kv[1]["verdict"] in order
            else len(order),
        )
        if r["verdict"] != "OK"
    ]
    lines.append("## Broken regimes, worst first")
    lines.append("")
    if not broken:
        lines.append("None.")
    else:
        for name, r in broken:
            lines.append(f"- `{name}`: **{r['verdict']}**. " + " ".join(r["notes"]))
    lines.append("")
    return "\n".join(lines)


def preflight(binary: Path, work: Path, extra: list[str], timeout: float) -> dict:
    """Prove the harness can see a credential, and that it does not see one when
    there is none, BEFORE trusting a single zero in the matrix.

    Every interesting cell in this matrix is a zero, and a zero has two causes
    that look identical from outside: the regime hid a credential the scanner
    missed, or the scanner never ran. Both produce "0 findings". So the run
    starts with two one-file scans:

      positive  a file holding only the canary  -> must be exactly 1 finding
      negative  the same file with the credential's shape broken -> must be 0

    The positive is the one that matters and it has been watched to fail: a
    broken `detectors/` directory on the invocation path made the whole second
    half of a run exit 2 with zero findings, which is exactly what this catches.
    The negative rules out the opposite error, a probe that matches anything.
    """
    probe = work / "preflight"
    probe.mkdir(parents=True, exist_ok=True)

    def scan(name: str, body: bytes) -> tuple[int, list]:
        target = probe / name
        target.write_bytes(body)
        out = probe / f"{name}.json"
        out.unlink(missing_ok=True)
        cmd = [
            str(binary),
            "scan",
            str(target),
            "--no-config",
            "--no-color",
            "--quiet",
            "--backend",
            "simd",
            "--dedup",
            "file",
            "--format",
            "json-envelope",
            "-o",
            str(out),
            *extra,
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=str(work)
        )
        envelope, state = read_envelope(out)
        if state != "ok":
            raise SystemExit(
                f"preflight {name}: the scan wrote no usable envelope ({state}), "
                f"exit {proc.returncode}. Every zero in this matrix would be "
                f"meaningless. stderr:\n{proc.stderr[-2000:]}"
            )
        return proc.returncode, envelope.get("findings") or []

    rc, findings = scan("canary.env", canary_bytes())
    hits = [f for f in findings if f.get("detector_id") == CANARY_DETECTOR]
    if len(hits) != 1 or rc != 1:
        raise SystemExit(
            f"preflight positive control FAILED: expected exit 1 and exactly one "
            f"`{CANARY_DETECTOR}` finding, got exit {rc} and "
            f"{len(hits)} of {len(findings)} findings. The harness cannot see a "
            "credential it planted itself, so no zero in this matrix would mean "
            "anything. Check that the binary loads a working detector corpus."
        )

    broken = canary_bytes().replace(b"sk_live_", b"sk_dead_")
    rc_neg, findings_neg = scan("no-canary.env", broken)
    neg_hits = [f for f in findings_neg if f.get("detector_id") == CANARY_DETECTOR]
    if neg_hits:
        raise SystemExit(
            f"preflight negative control FAILED: {len(neg_hits)} "
            f"`{CANARY_DETECTOR}` findings in a file with no canary in it. The "
            "canary count would over-report."
        )

    # The negative control can still exit 1: breaking the `sk_live_` prefix
    # leaves a high-entropy token that generic detectors legitimately match. The
    # assertion is about the CANARY detector, not about the file being silent.
    print(
        f"  preflight: positive control {len(hits)} canary finding, exit {rc}; "
        f"negative control {len(neg_hits)} canary findings out of "
        f"{len(findings_neg)} total, exit {rc_neg}",
        flush=True,
    )
    return {"positive_findings": len(hits), "negative_findings": len(neg_hits)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--binary", required=True, type=Path)
    ap.add_argument("--only", nargs="*", default=None, choices=REGIMES)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--timeout", type=float, default=900.0)
    ap.add_argument("--out", type=Path, default=None, help="markdown matrix path")
    ap.add_argument("--json-out", type=Path, default=None, help="raw results path")
    ap.add_argument(
        "--extra", nargs="*", default=[], help="extra keyhog scan args for every regime"
    )
    args = ap.parse_args(argv)

    binary = args.binary.resolve()
    if not binary.exists():
        raise SystemExit(f"binary not found: {binary}")

    work = args.root / ".work"
    work.mkdir(parents=True, exist_ok=True)

    controls = preflight(binary, work, args.extra, args.timeout)

    only = args.only or REGIMES
    results: dict[str, dict] = {}
    for name in only:
        regime_dir = args.root / name
        if not regime_dir.exists():
            print(f"  {name}: SKIPPED, not generated")
            continue
        facts = {}
        sp = stamp_path(regime_dir)
        if sp.exists():
            try:
                facts = json.loads(sp.read_text())
            except (OSError, ValueError):
                pass
        runs = []
        for rep in range(args.reps):
            r = one_run(binary, name, regime_dir, work, args.extra, args.timeout)
            runs.append(r)
            print(
                f"  {name} rep {rep + 1}/{args.reps}: "
                f"wall={r['wall_s']:.2f}s cpu={r['cpu_pct']:.0f}% "
                f"rss={r['peak_rss_kib'] / 1024:.0f}MiB exit={r['exit_code']} "
                f"findings={r['findings']} canary={r['canary']} "
                f"status={r['scan_status']}",
                flush=True,
            )
            if r["timed_out"] or r["panic"]:
                break
        agg = aggregate(runs)
        if agg["canary"] < (facts.get("canary_copies") or 0):
            agg["canary_suppressed_reason"] = dogfood_probe(
                binary, name, regime_dir, work, args.extra, args.timeout
            )
        verdict, notes = classify(name, agg, facts)
        results[name] = {"agg": agg, "verdict": verdict, "notes": notes, "facts": facts}
        print(f"  {name}: {verdict} {' '.join(notes)}", flush=True)

    meta = {
        "binary": binary_identity(binary),
        "root": str(args.root),
        "scale": next(
            (r["facts"].get("scale") for r in results.values() if r["facts"]), "unknown"
        ),
        "cores": os.cpu_count(),
        "loadavg": ", ".join(f"{v:.1f}" for v in os.getloadavg()),
        "reps": args.reps,
        "controls": controls,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }

    md = render_markdown(results, meta)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(md)
        print(f"\nwrote {args.out}")
    else:
        print("\n" + md)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps({"meta": meta, "results": results}, indent=2))
        print(f"wrote {args.json_out}")

    worst = [
        n
        for n, r in results.items()
        if r["verdict"] in {"SILENT CLEAN", "PANIC", "NO REPORT", "BROKEN", "HANG"}
    ]
    return 1 if worst else 0


if __name__ == "__main__":
    raise SystemExit(main())
