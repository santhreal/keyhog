"""Score the IoC-recovery corpus on five independent exact axes.

Value alone is a weak recovery target. A run that returns the right bytes from
the wrong expression, attributed to the wrong detector family, is not the same
result as a correct recovery, and a target that only counts positives cannot
tell a recovery from a fabrication. This scorer reads the corpus manifest and
one KeyHog report and scores, per axis:

* ``value``            the exact recovered credential
* ``certificate``      SHA-256 of the recovered value, mutating it fails alone
* ``detector_family``  the detector that claimed the recovery
* ``span``             the reported line against the manifest's expression span
* ``mechanism``        the concealment the fixture actually used

and, per fixture class:

* ``phase``        the P0-P12 progression
* ``holdout``      independently generated AST spellings of supported mechanisms
* ``metamorphic``  semantically non-static programs where ANY recovery is a
                   fabrication

Dedup: the corpus deliberately reuses one value across all thirteen phases of a
sample, so KeyHog's default ``--dedup credential`` collapses P1-P12 into
whichever phase the walker reached first. That turns a per-phase recovery score
into a function of scan order. This scorer refuses to run without
``--dedup none``.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import pathlib
import subprocess
import sys

AXES = ("value", "certificate", "detector_family", "span", "mechanism")


class Outcome:
    __slots__ = ("tp", "fp", "fn", "tn")

    def __init__(self) -> None:
        self.tp = self.fp = self.fn = self.tn = 0

    def as_dict(self) -> dict[str, int]:
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn}


def certificate(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def scan(binary: pathlib.Path, corpus: pathlib.Path, out: pathlib.Path, mode: str) -> None:
    cmd = [
        str(binary),
        "scan",
        str(corpus / "corpus"),
        "--no-config",
        "--daemon=off",
        "--backend",
        "cpu",
        # Per-fixture scoring is impossible with value dedup on. See module docs.
        "--dedup",
        "none",
        "--show-secrets",
        "--no-default-excludes",
        "--no-suppress-test-fixtures",
        "--format",
        "json",
        "--output",
        str(out),
    ]
    if mode != "full":
        cmd.append(f"--{mode}")
    # Remove any report from a previous invocation FIRST. A run that is rejected
    # before it scans (conflicting flags exit 2 and write nothing) would
    # otherwise leave the old file in place, and the scorer would digest a stale
    # result as if this run had produced it. A stale file is indistinguishable
    # from a reproduced one.
    out.unlink(missing_ok=True)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    if not out.is_file():
        raise SystemExit(
            f"keyhog scan exited {result.returncode} and wrote no report at all, so there is "
            f"nothing to score. This is a rejected or aborted run, not an empty result.\n"
            f"command: {' '.join(cmd)}\n{result.stderr[-4000:]}"
        )
    # Exit 1 means findings were reported, which is the normal case here.
    if result.returncode not in (0, 1):
        # An incomplete scan still recovered real findings, and discarding them
        # would turn a partial result into no result. Score what landed and say
        # loudly that coverage was incomplete, rather than refusing outright.
        recovered = 0
        if out.is_file() and out.stat().st_size:
            try:
                recovered = len(json.loads(out.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                recovered = -1
        if recovered <= 0:
            raise SystemExit(
                f"keyhog scan exited {result.returncode} and produced no scorable report\n"
                f"{result.stderr[-4000:]}"
            )
        print(
            f"WARNING: keyhog scan exited {result.returncode}; coverage is INCOMPLETE. "
            f"Scoring the {recovered} finding(s) that were recovered rather than discarding "
            "them. Every axis below is a lower bound.",
            file=sys.stderr,
        )
        print(result.stderr[-2000:], file=sys.stderr)


def observations(report: pathlib.Path, corpus: pathlib.Path) -> dict[str, list[dict]]:
    scan_root = (corpus / "corpus").resolve()
    grouped: dict[str, list[dict]] = collections.defaultdict(list)
    for finding in json.loads(report.read_text(encoding="utf-8")):
        raw = (finding.get("location") or {}).get("file_path") or ""
        path = pathlib.Path(raw)
        if path.is_absolute():
            try:
                relative = path.resolve().relative_to(scan_root).as_posix()
            except ValueError:
                continue
        else:
            # Reports are relative to the scan root's parent chain, so anchor on
            # the corpus directory name rather than guessing.
            text = path.as_posix()
            marker = scan_root.name + "/"
            relative = text.split(marker, 1)[1] if marker in text else text
        grouped[relative].append(finding)
    return grouped


def score(manifest_rows: list[dict], grouped: dict[str, list[dict]]) -> dict:
    per_axis: dict[str, Outcome] = {axis: Outcome() for axis in AXES}
    per_class: dict[str, Outcome] = collections.defaultdict(Outcome)
    per_family: dict[str, Outcome] = collections.defaultdict(Outcome)
    per_phase: dict[str, Outcome] = collections.defaultdict(Outcome)
    fabrications: list[dict] = []

    for row in manifest_rows:
        path = row["on_disk_path"]
        found = grouped.get(path, [])
        klass = row["kind"]
        family = row["family"]
        phase_key = f"p{row['phase']:02d}" if row["phase"] >= 0 else klass

        if not row["label"]:
            # Negative and metamorphic fixtures: any recovery is a fabrication.
            if found:
                for finding in found:
                    fabrications.append(
                        {
                            "path": path,
                            "kind": klass,
                            "family": family,
                            "detector_id": finding.get("detector_id"),
                            "credential_redacted": finding.get("credential_redacted"),
                        }
                    )
                for bucket in (per_class[klass], per_family[family], per_phase[phase_key]):
                    bucket.fp += len(found)
                for axis in AXES:
                    per_axis[axis].fp += len(found)
            else:
                for bucket in (per_class[klass], per_family[family], per_phase[phase_key]):
                    bucket.tn += 1
                for axis in AXES:
                    per_axis[axis].tn += 1
            continue

        expected = row["secret"]
        values = {finding.get("credential_redacted") for finding in found}
        exact = expected in values
        for bucket in (per_class[klass], per_family[family], per_phase[phase_key]):
            if exact:
                bucket.tp += 1
            else:
                bucket.fn += 1

        # value / certificate
        for axis, hit in (
            ("value", exact),
            ("certificate", any(certificate(v) == row["certificate"] for v in values if v)),
        ):
            if hit:
                per_axis[axis].tp += 1
            else:
                per_axis[axis].fn += 1

        # detector_family: the right value claimed by the right detector.
        claimed = {
            finding.get("detector_id")
            for finding in found
            if finding.get("credential_redacted") == expected
        }
        if row["detector_family"] in claimed:
            per_axis["detector_family"].tp += 1
        else:
            per_axis["detector_family"].fn += 1

        # span: the reported line must be the expression the value came from.
        lines = {
            (finding.get("location") or {}).get("line")
            for finding in found
            if finding.get("credential_redacted") == expected
        }
        if row["start_line"] in lines:
            per_axis["span"].tp += 1
        else:
            per_axis["span"].fn += 1

        # mechanism: recovery of a concealed value proves the mechanism ran;
        # a plaintext phase proves nothing about recovery, so it is excluded.
        if row["kind"] == "phase" and row["phase"] == 0:
            per_axis["mechanism"].tn += 1
        elif exact:
            per_axis["mechanism"].tp += 1
        else:
            per_axis["mechanism"].fn += 1

    return {
        "per_axis": {axis: outcome.as_dict() for axis, outcome in per_axis.items()},
        "per_class": {name: outcome.as_dict() for name, outcome in sorted(per_class.items())},
        "per_family": {name: outcome.as_dict() for name, outcome in sorted(per_family.items())},
        "per_phase": {name: outcome.as_dict() for name, outcome in sorted(per_phase.items())},
        "fabrications": fabrications,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keyhog", required=True, type=pathlib.Path)
    parser.add_argument(
        "--corpus",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1] / "corpora" / "ioc-recovery-v4",
    )
    parser.add_argument("--mode", default="deep", choices=["full", "fast", "deep", "precision"])
    parser.add_argument("--out", type=pathlib.Path)
    parser.add_argument(
        "--require-no-fabrication",
        action="store_true",
        help="exit nonzero if any negative or metamorphic fixture produced a finding",
    )
    args = parser.parse_args()

    manifest = args.corpus / "manifest.jsonl"
    if not manifest.is_file():
        raise SystemExit(
            f"corpus manifest missing: {manifest}\n"
            "  generate it with: make -C benchmarks ioc-recovery-corpus"
        )
    rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines() if line.strip()]

    report = args.out.with_suffix(".report.json") if args.out else pathlib.Path("ioc-axes-report.json")
    scan(args.keyhog, args.corpus, report, args.mode)
    result = score(rows, observations(report, args.corpus))
    result["corpus"] = str(args.corpus)
    result["mode"] = args.mode
    result["fixtures"] = len(rows)

    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(payload)

    print(f"IoC recovery axes ({args.mode}, --dedup none, {len(rows)} fixtures)")
    for axis in AXES:
        outcome = result["per_axis"][axis]
        total = outcome["tp"] + outcome["fn"]
        rate = f"{outcome['tp'] / total:.3f}" if total else "n/a"
        print(
            f"  {axis:<16} tp={outcome['tp']:<5} fn={outcome['fn']:<5} "
            f"fp={outcome['fp']:<5} tn={outcome['tn']:<5} recall={rate}"
        )
    print("  per class:")
    for name, outcome in result["per_class"].items():
        print(
            f"    {name:<14} tp={outcome['tp']:<5} fn={outcome['fn']:<5} "
            f"fp={outcome['fp']:<5} tn={outcome['tn']:<5}"
        )
    print("  per family:")
    for name, outcome in result["per_family"].items():
        print(
            f"    {name:<16} tp={outcome['tp']:<5} fn={outcome['fn']:<5} "
            f"fp={outcome['fp']:<5} tn={outcome['tn']:<5}"
        )

    if result["fabrications"]:
        print(
            f"\n{len(result['fabrications'])} FABRICATED recover(ies) from fixtures with no "
            "statically recoverable value:",
            file=sys.stderr,
        )
        for row in result["fabrications"][:20]:
            print(f"  {row['kind']:<12} {row['family']:<14} {row['path']}  {row['detector_id']}", file=sys.stderr)
        if args.require_no_fabrication:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
