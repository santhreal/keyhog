"""Deterministic secret recovery under progressive JavaScript concealment.

This corpus adapts the 13-stage P0-P12 methodology from Morales, Pastrana,
and Tapiador's *Benchmarking Large Language Models for IoC Recovery under
Adversarial Code Obfuscation and Encryption* to synthetic credential values.
It is part of KeyHog's unified benchmark harness, not a separate evaluator.

The authors publish 13 demonstration files at a repository and commit pinned
by the generator. That repository does not contain the paper's 336-program
evaluation corpus. This adapter therefore records the public source provenance
without claiming byte identity with the unpublished evaluation data.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

from ..corpus_integrity import file_sha256, tree_sha256
from ..ioc_recovery_provenance import (
    UPSTREAM_EVALUATION_CORPUS_PUBLISHED,
    UPSTREAM_PUBLIC_EXAMPLE_COUNT,
    UPSTREAM_REPOSITORY_COMMIT,
    UPSTREAM_REPOSITORY_URL,
)
from .base import Corpus, LabeledRecord, load_jsonl_manifest

_THIS = pathlib.Path(__file__).resolve()
_BENCH_ROOT = _THIS.parents[2]


def _generator_path() -> pathlib.Path:
    return _BENCH_ROOT / "generators" / "ioc_recovery" / "generate.py"


class IocRecoveryCorpus(Corpus):
    """Manifest-free scan tree plus exact recovered-value ground truth."""

    name = "ioc-recovery"

    def __init__(self, corpus_dir: str | pathlib.Path | None = None):
        self._home = (
            pathlib.Path(corpus_dir)
            if corpus_dir is not None
            else _BENCH_ROOT / "corpora" / "ioc-recovery"
        )

    @property
    def root(self) -> pathlib.Path:
        return self._home

    @property
    def scan_root(self) -> pathlib.Path:
        return self._home / "corpus"

    @property
    def file_root(self) -> pathlib.Path:
        return self.scan_root

    @property
    def manifest(self) -> pathlib.Path:
        return self._home / "manifest.jsonl"

    @property
    def metadata(self) -> pathlib.Path:
        return self._home / "corpus.json"

    def _load_metadata(self) -> dict[str, object]:
        if not self.metadata.is_file():
            raise SystemExit(
                f"IoC-recovery metadata missing: {self.metadata}\n"
                "  remove the incomplete corpus and regenerate it with: "
                "make -C benchmarks ioc-recovery-corpus"
            )
        try:
            value = json.loads(self.metadata.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(
                f"IoC-recovery metadata is unreadable: {self.metadata}: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise SystemExit(
                f"IoC-recovery metadata must be a JSON object: {self.metadata}"
            )
        return value

    def _validate_layout(
        self,
        *,
        requested_samples: int | None = None,
        requested_seed: int | None = None,
    ) -> dict[str, object]:
        if not self.scan_root.is_dir():
            raise SystemExit(
                f"IoC-recovery scan tree missing: {self.scan_root}\n"
                "  remove the incomplete corpus and regenerate it with: "
                "make -C benchmarks ioc-recovery-corpus"
            )
        if not self.manifest.is_file():
            raise SystemExit(
                f"IoC-recovery manifest missing: {self.manifest}\n"
                "  generate it with: make -C benchmarks ioc-recovery-corpus"
            )
        metadata = self._load_metadata()
        required = {
            "schema_version": 2,
            "name": "keyhog-ioc-recovery",
            "phases": 13,
            "match_mode": "exact",
            "artifact_relationship": "methodology-adaptation",
            "upstream_repository_url": UPSTREAM_REPOSITORY_URL,
            "upstream_repository_commit": UPSTREAM_REPOSITORY_COMMIT,
            "upstream_public_example_count": UPSTREAM_PUBLIC_EXAMPLE_COUNT,
            "upstream_evaluation_corpus_published": UPSTREAM_EVALUATION_CORPUS_PUBLISHED,
        }
        for key, expected in required.items():
            if metadata.get(key) != expected:
                raise SystemExit(
                    f"IoC-recovery metadata field {key!r} is "
                    f"{metadata.get(key)!r}; expected {expected!r}"
                )
        requested = {
            "samples": requested_samples,
            "seed": requested_seed,
        }
        for key, expected in requested.items():
            if expected is not None and metadata.get(key) != expected:
                raise SystemExit(
                    f"IoC-recovery corpus at {self._home} uses {key}="
                    f"{metadata.get(key)!r}, but this run requested {expected!r}; "
                    "remove that generated corpus explicitly before regenerating"
                )
        manifest_digest = file_sha256(self.manifest)
        if metadata.get("manifest_sha256") != manifest_digest:
            raise SystemExit(
                f"IoC-recovery manifest digest mismatch at {self.manifest}; "
                "the generated corpus is incomplete or modified"
            )
        scan_digest = tree_sha256(self.scan_root)
        if metadata.get("scan_tree_sha256") != scan_digest:
            raise SystemExit(
                f"IoC-recovery scan-tree digest mismatch at {self.scan_root}; "
                "the generated corpus is incomplete or modified"
            )
        return metadata

    def _load_records(self) -> list[LabeledRecord]:
        metadata = self._validate_layout()
        records = load_jsonl_manifest(self.manifest)
        invalid = [record.id for record in records if record.match_mode != "exact"]
        if invalid:
            raise SystemExit(
                "IoC-recovery manifest contains non-exact records: "
                + ", ".join(invalid[:5])
            )
        expected_fixtures = metadata.get("fixtures")
        if expected_fixtures != len(records):
            raise SystemExit(
                f"IoC-recovery manifest has {len(records)} records; "
                f"metadata declares {expected_fixtures!r}"
            )
        ids = {record.id for record in records}
        if len(ids) != len(records):
            raise SystemExit("IoC-recovery manifest contains duplicate record ids")
        for record in records:
            relative = pathlib.PurePosixPath(record.file_path)
            if relative.is_absolute() or ".." in relative.parts:
                raise SystemExit(
                    f"IoC-recovery record {record.id!r} has unsafe path "
                    f"{record.file_path!r}"
                )
            if not (self.scan_root / pathlib.Path(relative)).is_file():
                raise SystemExit(
                    f"IoC-recovery fixture missing for record {record.id!r}: "
                    f"{record.file_path}"
                )
        return records

    def ensure(self, samples: int = 336, seed: int = 260506910) -> None:
        if self.manifest.exists():
            self._validate_layout(
                requested_samples=samples,
                requested_seed=seed,
            )
            print(f"IoC-recovery corpus present: {self._home}", file=sys.stderr)
            return
        if self._home.exists():
            raise SystemExit(
                f"IoC-recovery corpus is incomplete at {self._home}; "
                "remove that generated directory explicitly before regenerating"
            )
        generator = _generator_path()
        if not generator.exists():
            raise SystemExit(f"IoC-recovery generator not found: {generator}")
        subprocess.run(
            [
                sys.executable,
                str(generator),
                "--out",
                str(self._home),
                "--samples",
                str(samples),
                "--seed",
                str(seed),
            ],
            check=True,
        )


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IoC-recovery corpus management.")
    parser.add_argument("--ensure", action="store_true")
    parser.add_argument("--samples", type=int, default=336)
    parser.add_argument("--seed", type=int, default=260506910)
    parser.add_argument("--corpus-dir", default=None)
    args = parser.parse_args(argv)

    corpus = IocRecoveryCorpus(corpus_dir=args.corpus_dir)
    if args.ensure:
        corpus.ensure(samples=args.samples, seed=args.seed)
    info = corpus.info()
    print(
        f"{corpus.name}: {info.fixture_count} fixtures, "
        f"{info.labeled_positives} positives, {info.bytes} bytes "
        f"scan_root={corpus.scan_root}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
