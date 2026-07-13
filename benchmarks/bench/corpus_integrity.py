"""Deterministic integrity helpers for generated benchmark corpora."""

from __future__ import annotations

import hashlib
import pathlib


def file_sha256(path: pathlib.Path) -> str:
    """Hash one corpus metadata or manifest file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_sha256(root: pathlib.Path) -> str:
    """Hash relative paths and bytes for every file in a corpus scan tree."""
    digest = hashlib.sha256()
    files = (candidate for candidate in root.rglob("*") if candidate.is_file())
    for path in sorted(files):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()
