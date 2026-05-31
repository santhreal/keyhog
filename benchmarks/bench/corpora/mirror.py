"""Mirror corpus: the 15k synthetic SecretBench-shape dataset.

Wraps the existing generator (``tools/secretbench/mirror/generate.py``) and
loads its ``manifest.jsonl`` into :class:`LabeledRecord`. One record per
file (single secret), so the per-fixture attribution is identical to the
legacy scorer — the migration's regression anchor.

Layout (the home dir holds both the answer key and the scan tree, kept
apart so no scanner is ever shown the manifest):

    <home>/manifest.jsonl          the ground-truth answer key
    <home>/corpus/<shards>/<id>    the fixtures a scanner is pointed at

Two fairness/hygiene rules are baked into this split, both learned the hard
way against the live keyhog binary:

1. **The manifest is OUTSIDE the scan tree.** A scanner that reads
   ``manifest.jsonl`` finds every labeled secret in plaintext — betterleaks
   fires 9392 spurious matches on it, kingfisher 7581. ``scan_root`` is the
   ``corpus/`` subtree only.
2. **The scan dir has a NEUTRAL name** (``corpus``, not ``fixtures``/
   ``test``/``examples``). keyhog applies a path-context confidence penalty
   to anything living under a "fixtures"-shaped directory, and
   ``--no-suppress-test-fixtures`` does NOT fully override it: the same 15k
   files scored 1880 findings under ``fixtures/`` vs 2484 under a neutral
   name. The corpus must never sit under a path token a scanner treats as
   "this is test data, relax".

Resolution order for the home: explicit ``corpus_dir`` arg, the
``KEYHOG_BENCH_MIRROR`` env, the ``benchmarks/corpora/mirror`` home, then the
legacy ``tools/secretbench/mirror/corpus`` flat home.
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


def _candidate_homes() -> list[pathlib.Path]:
    """Dirs that may hold ``manifest.jsonl``. A home is either the new split
    layout (manifest + ``corpus/`` subtree) or a legacy flat home (manifest
    + shards in the same dir)."""
    env = os.environ.get("KEYHOG_BENCH_MIRROR")
    cands: list[pathlib.Path] = []
    if env:
        cands.append(pathlib.Path(env))
    cands.append(_BENCH_ROOT / "corpora" / "mirror")
    cands.append(_REPO_ROOT / "tools" / "secretbench" / "mirror" / "corpus")
    return cands


class MirrorCorpus(Corpus):
    name = "mirror"

    def __init__(self, corpus_dir: str | pathlib.Path | None = None):
        if corpus_dir is not None:
            # Explicit dir is a flat home (manifest + shards together).
            self._home = pathlib.Path(corpus_dir)
        else:
            self._home = next(
                (d for d in _candidate_homes() if (d / "manifest.jsonl").exists()),
                _candidate_homes()[0],
            )

    @property
    def _scan_dir(self) -> pathlib.Path:
        """The neutral, manifest-free scan tree: ``<home>/corpus`` in the
        split layout, else the home itself (legacy flat)."""
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
        # on_disk_path ("00/<id>.ext") is relative to the shard parent.
        return self._scan_dir

    def manifest(self) -> pathlib.Path:
        return self._home / "manifest.jsonl"

    def records(self) -> list[LabeledRecord]:
        man = self.manifest()
        if not man.exists():
            raise SystemExit(
                f"mirror manifest missing: {man}\n"
                f"  generate it with: make mirror  "
                f"(or python -m bench.corpora.mirror --ensure)"
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
        """Generate the corpus into the split layout if absent (idempotent).

        The generator emits a flat tree (manifest + shards); we point it at
        ``<home>/corpus`` and then lift ``manifest.jsonl`` up to ``<home>``
        so the answer key sits beside, not inside, the scan tree."""
        scan_dir = self._home / "corpus"
        self._lift_manifest_from_scan_dir(scan_dir)
        if self.manifest().exists():
            print(f"mirror corpus present: {self._home}", file=sys.stderr)
            return
        gen = _generator_path()
        if not gen.exists():
            raise SystemExit(f"mirror generator not found: {gen}")
        scan_dir.mkdir(parents=True, exist_ok=True)
        print(f"generating mirror corpus -> {scan_dir} "
              f"({positives}+{negatives}, seed={seed})", file=sys.stderr)
        subprocess.run(
            [sys.executable, str(gen), "--out", str(scan_dir),
             "--positives", str(positives), "--negatives", str(negatives),
             "--seed", str(seed)],
            check=True,
        )
        self._lift_manifest_from_scan_dir(scan_dir)

    def _lift_manifest_from_scan_dir(self, scan_dir: pathlib.Path) -> None:
        for meta in ("manifest.jsonl", "manifest.sha256"):
            src = scan_dir / meta
            if src.exists():
                src.replace(self._home / meta)


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
          f"scan_root={c.scan_root}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
