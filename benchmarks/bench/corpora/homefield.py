"""Home-turf corpora: each competitor's OWN labeled ground truth.

betterleaks (a gitleaks fork) and kingfisher ship their detection rules with
embedded ``tps``/``fps`` example lists, the exact strings their regexes
were tuned to pass. Harvesting those (``harvest_betterleaks.py`` /
``harvest_kingfisher.py``) into a SecretBench-shape ``manifest.jsonl`` lets
us ask the only fair "home turf" question: how close does keyhog get on a
competitor's own truth, and which services they cover that keyhog misses (a
capability gap, not a tuning gap).

Same manifest shape and the same split layout as the mirror (answer key at
``<home>/manifest.jsonl``, scan tree under a neutrally-named
``<home>/corpus/``, see :mod:`bench.corpora.mirror` for why both rules are
mandatory), so the loader is shared.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

from .base import Corpus, LabeledRecord, load_jsonl_manifest

_THIS = pathlib.Path(__file__).resolve()
_BENCH_ROOT = _THIS.parents[2]

_TURFS = ("betterleaks", "kingfisher")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _candidate_homes(turf: str) -> list[pathlib.Path]:
    return [
        _BENCH_ROOT / "corpora" / "homefield" / turf,
    ]


class HomefieldCorpus(Corpus):
    def __init__(self, turf: str, corpus_dir: str | pathlib.Path | None = None):
        if turf not in _TURFS:
            raise SystemExit(f"unknown home-turf {turf!r}; known: {_TURFS}")
        self.turf = turf
        self.name = f"homefield-{turf}"
        if corpus_dir is not None:
            self._home = pathlib.Path(corpus_dir)
        else:
            self._home = next(
                (d for d in _candidate_homes(turf) if (d / "manifest.jsonl").exists()),
                _candidate_homes(turf)[0],
            )

    @property
    def _scan_dir(self) -> pathlib.Path:
        sub = self._home / "corpus"
        return sub if sub.is_dir() else self._home

    @property
    def root(self) -> pathlib.Path:
        return self._home

    @property
    def scan_root(self) -> pathlib.Path:
        return self._scan_dir

    @property
    def file_root(self) -> pathlib.Path:
        return self._scan_dir

    def _load_records(self) -> list[LabeledRecord]:
        man = self._home / "manifest.jsonl"
        if not man.exists():
            raise SystemExit(
                f"home-turf manifest missing: {man}\n"
                f"  harvest it with: "
                f"python benchmarks/generators/homefield/harvest_{self.turf}.py\n"
                f"  then score with:  python -m bench leaderboard "
                f"--corpus homefield-{self.turf}"
            )
        if self.turf == "betterleaks":
            self._validate_betterleaks_provenance(man)
        return load_jsonl_manifest(man)

    @staticmethod
    def _validate_betterleaks_provenance(manifest: pathlib.Path) -> None:
        """Reject harvested fixtures that cannot identify their source rules."""
        expected: tuple[str, str, str] | None = None
        rows = 0
        with manifest.open() as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                rows += 1
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    raise SystemExit(
                        f"betterleaks homefield manifest line {line_number} is invalid JSON: {error}"
                    ) from error
                if row.get("source_tool") != "betterleaks":
                    raise SystemExit(
                        f"betterleaks homefield manifest line {line_number} has invalid source_tool"
                    )
                provenance = (
                    row.get("source_version"),
                    row.get("source_commit"),
                    row.get("source_rules_sha256"),
                )
                if not isinstance(provenance[0], str) or not provenance[0].startswith("v"):
                    raise SystemExit(
                        f"betterleaks homefield manifest line {line_number} is missing source_version"
                    )
                if not isinstance(provenance[1], str) or not _COMMIT.fullmatch(provenance[1]):
                    raise SystemExit(
                        f"betterleaks homefield manifest line {line_number} has invalid source_commit"
                    )
                if not isinstance(provenance[2], str) or not _SHA256.fullmatch(provenance[2]):
                    raise SystemExit(
                        f"betterleaks homefield manifest line {line_number} has invalid source_rules_sha256"
                    )
                if expected is None:
                    expected = provenance
                elif provenance != expected:
                    raise SystemExit(
                        "betterleaks homefield manifest mixes source versions or rule digests; "
                        "re-harvest one pinned source"
                    )
        if rows == 0:
            raise SystemExit("betterleaks homefield manifest contains no provenance-bound fixtures")


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Home-turf corpus info.")
    ap.add_argument("--turf", choices=_TURFS, default="betterleaks")
    args = ap.parse_args(argv)
    c = HomefieldCorpus(turf=args.turf)
    info = c.info()
    print(f"{c.name}: {info.fixture_count} fixtures, "
          f"{info.labeled_positives} positives at {c.root}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
