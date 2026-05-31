"""Perf-only corpus: a large real source tree (the Linux kernel).

No labels — scored on wall time, throughput, and peak RSS alone. This is the
"never wait for something" target: keyhog must scan the whole kernel
faster than any competitor, and the backend×cache×daemon×mode matrix is
measured here.

Path resolution: explicit ``root`` arg, ``KEYHOG_BENCH_KERNEL`` env, then
the desktop default ``/mnt/FlareTraining/santh-corpus/repos/linux``. A
perf run records the path it actually measured in the result so a number is
never silently attributed to the wrong tree.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys

from .base import Corpus, LabeledRecord

_DEFAULT_KERNEL = "/mnt/FlareTraining/santh-corpus/repos/linux"


class KernelCorpus(Corpus):
    name = "kernel"

    def __init__(self, root: str | pathlib.Path | None = None):
        if root is not None:
            self._root = pathlib.Path(root)
        else:
            self._root = pathlib.Path(os.environ.get("KEYHOG_BENCH_KERNEL", _DEFAULT_KERNEL))

    @property
    def root(self) -> pathlib.Path:
        return self._root

    def records(self) -> list[LabeledRecord]:
        # Perf-only: no ground truth.
        return []

    def exists(self) -> bool:
        return self._root.is_dir()


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Perf corpus (kernel) info.")
    ap.add_argument("--root", default=None)
    args = ap.parse_args(argv)
    c = KernelCorpus(root=args.root)
    if not c.exists():
        print(f"kernel tree not found at {c.root}; set KEYHOG_BENCH_KERNEL",
              file=sys.stderr)
        return 1
    info = c.info()
    print(f"{c.name}: {info.fixture_count} files, {info.bytes} bytes at {c.root}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
