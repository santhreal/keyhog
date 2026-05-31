"""Mirror corpus: the 15k synthetic SecretBench-shape dataset.

Wraps the existing generator (``tools/secretbench/mirror/generate.py``) and
loads its ``manifest.jsonl`` into :class:`LabeledRecord`. One record per
file (single secret), so it scores bit-identically to the legacy scorer —
the migration's regression anchor.

The corpus location is resolved in order: explicit ``corpus_dir`` arg, the
``KEYHOG_BENCH_MIRROR`` env, the new ``benchmarks/corpora/mirror/corpus``
home, then the legacy ``tools/secretbench/mirror/corpus`` (so this works
before and after the task-20 migration).
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys

from .base import Corpus, LabeledRecord

_THIS = pathlib.Path(__file__).resolve()
_BENCH_ROOT = _THIS.parents[2]                 # benchmarks/
_REPO_ROOT = _BENCH_ROOT.parent                # repo root


def _generator_path() -> pathlib.Path:
    return _REPO_ROOT / "tools" / "secretbench" / "mirror" / "generate.py"


def _candidate_dirs() -> list[pathlib.Path]:
    env = os.environ.get("KEYHOG_BENCH_MIRROR")
    cands = []
    if env:
        cands.append(pathlib.Path(env))
    cands.append(_BENCH_ROOT / "corpora" / "mirror" / "corpus")
    cands.append(_REPO_ROOT / "tools" / "secretbench" / "mirror" / "corpus")
    return cands


class MirrorCorpus(Corpus):
    name = "mirror"

    def __init__(self, corpus_dir: str | pathlib.Path | None = None):
        if corpus_dir is not None:
            self._dir = pathlib.Path(corpus_dir)
        else:
            self._dir = next(
                (d for d in _candidate_dirs() if (d / "manifest.jsonl").exists()),
                _candidate_dirs()[0],
            )

    @property
    def root(self) -> pathlib.Path:
        return self._dir

    def manifest(self) -> pathlib.Path:
        return self._dir / "manifest.jsonl"

    def records(self) -> list[LabeledRecord]:
        man = self.manifest()
        if not man.exists():
            raise SystemExit(
                f"mirror manifest missing: {man}\n"
                f"  generate it with: make mirror  (or python -m bench.corpora.mirror --ensure)"
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

    def ensure(self, positives: int = 15000, negatives: int = 80000, seed: int = 0) -> None:
        """Generate the corpus if its manifest is absent (idempotent)."""
        if self.manifest().exists():
            print(f"mirror corpus present: {self._dir}", file=sys.stderr)
            return
        gen = _generator_path()
        if not gen.exists():
            raise SystemExit(f"mirror generator not found: {gen}")
        self._dir.mkdir(parents=True, exist_ok=True)
        print(f"generating mirror corpus -> {self._dir} "
              f"({positives}+{negatives}, seed={seed})", file=sys.stderr)
        subprocess.run(
            [sys.executable, str(gen), "--out", str(self._dir),
             "--positives", str(positives), "--negatives", str(negatives),
             "--seed", str(seed)],
            check=True,
        )


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Mirror corpus management.")
    ap.add_argument("--ensure", action="store_true",
                    help="Generate the corpus if its manifest is absent.")
    ap.add_argument("--positives", type=int, default=15000)
    ap.add_argument("--negatives", type=int, default=80000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--corpus-dir", default=None)
    args = ap.parse_args(argv)
    c = MirrorCorpus(corpus_dir=args.corpus_dir)
    if args.ensure:
        c.ensure(args.positives, args.negatives, args.seed)
    info = c.info()
    print(f"{c.name}: {info.fixture_count} fixtures, "
          f"{info.labeled_positives} positives, {info.bytes} bytes "
          f"at {c.root}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
