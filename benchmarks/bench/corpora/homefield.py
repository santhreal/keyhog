"""Home-turf corpora: each competitor's OWN labeled ground truth.

betterleaks (a gitleaks fork) and kingfisher ship their detection rules with
embedded ``tps``/``fps`` example lists — the exact strings their regexes
were tuned to pass. Harvesting those (``harvest_betterleaks.py`` /
``harvest_kingfisher.py``) into a SecretBench-shape ``manifest.jsonl`` lets
us ask the only fair "home turf" question: how close does keyhog get on a
competitor's own truth, and which services they cover that keyhog misses (a
capability gap, not a tuning gap).

Same manifest shape as the mirror, so the loader is shared.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .base import Corpus, LabeledRecord

_THIS = pathlib.Path(__file__).resolve()
_BENCH_ROOT = _THIS.parents[2]
_REPO_ROOT = _BENCH_ROOT.parent

_TURFS = ("betterleaks", "kingfisher")


def _candidate_dirs(turf: str) -> list[pathlib.Path]:
    return [
        _BENCH_ROOT / "corpora" / "homefield" / turf / "corpus",
        _REPO_ROOT / "tools" / "secretbench" / "homefield" / turf / "corpus",
    ]


class HomefieldCorpus(Corpus):
    def __init__(self, turf: str, corpus_dir: str | pathlib.Path | None = None):
        if turf not in _TURFS:
            raise SystemExit(f"unknown home-turf {turf!r}; known: {_TURFS}")
        self.turf = turf
        self.name = f"homefield-{turf}"
        if corpus_dir is not None:
            self._dir = pathlib.Path(corpus_dir)
        else:
            self._dir = next(
                (d for d in _candidate_dirs(turf) if (d / "manifest.jsonl").exists()),
                _candidate_dirs(turf)[0],
            )

    @property
    def root(self) -> pathlib.Path:
        return self._dir

    def records(self) -> list[LabeledRecord]:
        man = self._dir / "manifest.jsonl"
        if not man.exists():
            raise SystemExit(
                f"home-turf manifest missing: {man}\n"
                f"  harvest it with: tools/secretbench/homefield/run.sh"
            )
        out: list[LabeledRecord] = []
        with open(man) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                out.append(LabeledRecord(
                    id=r["id"],
                    secret=r.get("secret", ""),
                    label=bool(r.get("label")),
                    category=r.get("category", "unknown"),
                    file_path=r.get("on_disk_path") or r.get("file_path", ""),
                    line_start=int(r.get("start_line", 0) or 0),
                    line_end=int(r.get("end_line", 0) or 0),
                ))
        return out


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
