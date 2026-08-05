"""Build the workload-regime corpora on disk.

Each regime is one directory under the corpus root and one shape of input.
The point is not volume, it is shape: the same scanner meets 300 MiB as
300 files, as one file, and as one line, and you get to see which of those
it handles.

Every regime hides the canary from `canary.py` exactly once, so a zero-finding
result is provably a coverage hole rather than a clean tree.

Usage:

    python3 benchmarks/workload_matrix/generate.py --root /tmp/keyhog-wm
    python3 benchmarks/workload_matrix/generate.py --root /tmp/keyhog-wm \
        --only one_long_line deep_nest

Regeneration is idempotent per regime: a regime directory that already carries
a matching `.stamp` is left alone. Pass `--force` to rebuild it.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from canary import CANARY_LINE, canary_base64_bytes, canary_bytes  # noqa: E402

MIB = 1024 * 1024

# Filler that looks like configuration source: keyword-adjacent lines, some
# high-entropy values, nothing that trips a named detector. Phase 1 admits a
# realistic fraction of it instead of rejecting the whole corpus on alphabet.
FILLER_LINES = [
    "# generated filler, no credentials below this line",
    "service_name = orders-api",
    "listen_addr = 0.0.0.0:8080",
    'log_level = "info"',
    "retry_backoff_ms = 250",
    "pool_size = 32",
    'region = "us-east-1"',
    "feature_flags = [alpha, beta, gamma]",
    "build_id = 4f2a9c1e7b3d5086",
    "checksum = 9d2b7f4a1c6e8035bd47a29f1e5c8730",
    'description = "aggregates order events and fans them out"',
    "timeout_seconds = 15",
]


def filler_block(rng: random.Random, size: int) -> bytes:
    """Deterministic filler of at least `size` bytes."""
    out = bytearray()
    while len(out) < size:
        out += FILLER_LINES[rng.randrange(len(FILLER_LINES))].encode()
        out += b"\n"
    return bytes(out[:size])


def stamp_path(regime_dir: Path) -> Path:
    return regime_dir.parent / f".{regime_dir.name}.stamp"


# How many directory levels one removal pass descends before unwinding. Bounded
# so a 4096-deep tree cannot exhaust the process file-descriptor limit.
RMTREE_FD_WINDOW = 128


def _prune_pass(root: Path, counter: list[int]) -> int:
    """One removal pass. Returns how many entries it actually removed.

    `shutil.rmtree` and `os.walk` cannot touch the `deep_nest` regime: they build
    absolute path strings, and 4096 levels is past `PATH_MAX`, so every stat
    raises ENAMETOOLONG. `shutil.rmtree`'s fd-based path recurses once per level
    and blows the Python recursion limit instead. This descends with directory
    file descriptors, iteratively, and does every operation relative to one, so
    no path string is ever assembled and no recursion is involved.

    A bounded descent alone is not enough: you cannot `rmdir` a directory that
    still has a subdirectory below the window. So when the descent runs out of
    window with more tree underneath, the remainder is RENAMED up to the root,
    which is legal relative to two directory fds and makes it shallow again. Each
    pass therefore retires `RMTREE_FD_WINDOW` levels, and 4096 levels finish in
    about thirty passes.
    """
    removed = 0
    fds = [os.open(root, os.O_RDONLY | os.O_DIRECTORY)]
    descended: list[str] = []
    try:
        leftover = None
        while True:
            here = fds[-1]
            subdir = None
            for name in os.listdir(here):
                try:
                    mode = os.lstat(name, dir_fd=here).st_mode
                except OSError:
                    continue
                if stat.S_ISDIR(mode):
                    subdir = name
                else:
                    try:
                        os.unlink(name, dir_fd=here)
                        removed += 1
                    except OSError:
                        pass
            if subdir is None:
                break
            try:
                # A chmod-000 directory (the `unreadable_dir` regime) cannot be
                # opened until we give ourselves permission back.
                os.chmod(subdir, 0o755, dir_fd=here)
            except OSError:
                pass
            if len(fds) >= RMTREE_FD_WINDOW:
                leftover = (here, subdir)
                break
            try:
                fds.append(os.open(subdir, os.O_RDONLY | os.O_DIRECTORY, dir_fd=here))
            except OSError:
                break
            descended.append(subdir)
        if leftover is not None:
            tip_fd, name = leftover
            counter[0] += 1
            hoisted = f".wm-prune-{counter[0]}"
            try:
                os.rename(name, hoisted, src_dir_fd=tip_fd, dst_dir_fd=fds[0])
            except OSError:
                return removed
        while descended:
            os.close(fds.pop())
            try:
                os.rmdir(descended.pop(), dir_fd=fds[-1])
                removed += 1
            except OSError:
                break
        return removed
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass


def force_rmtree(path: Path) -> None:
    """Remove a tree that may be chmod-000 or deeper than `PATH_MAX`."""
    if path.is_symlink() or path.is_file():
        path.unlink()
        return
    if not path.is_dir():
        return
    try:
        path.chmod(0o755)
    except OSError:
        pass
    counter = [0]
    while _prune_pass(path, counter):
        pass
    try:
        path.rmdir()
    except OSError as error:
        raise SystemExit(
            f"cannot remove {path}: {error}. Something under it is not removable "
            "relative to a directory fd (an unreadable mount, or a file held open "
            "by a running scan). Remove it by hand before rebuilding."
        ) from error


# --------------------------------------------------------------------------
# Regime builders. Each returns a dict of facts recorded in the stamp.
# --------------------------------------------------------------------------


def build_many_small(d: Path, scale: float) -> dict:
    """The existing baseline: many small source files. 300 MiB as 3000 files."""
    count = max(4, int(3000 * scale))
    per_file = 100 * 1024
    rng = random.Random(1)
    block = filler_block(rng, per_file)
    canary_index = count // 2
    for i in range(count):
        sub = d / f"pkg{i // 250:04d}"
        sub.mkdir(parents=True, exist_ok=True)
        body = block
        if i == canary_index:
            body = block[: per_file // 2] + canary_bytes() + block[per_file // 2 :]
        (sub / f"config{i:05d}.toml").write_bytes(body)
    return {"files": count, "bytes": count * per_file, "canary_copies": 1}


def build_one_large(d: Path, scale: float) -> dict:
    """The same bytes as one file. This is the regime the baseline never covers."""
    d.mkdir(parents=True, exist_ok=True)
    total = max(4 * MIB, int(300 * MIB * scale))
    rng = random.Random(2)
    block = filler_block(rng, 4 * MIB)
    target = d / "one-large.log"
    written = 0
    canary_at = total // 2
    with target.open("wb") as fh:
        while written < total:
            chunk = block[: min(len(block), total - written)]
            if written <= canary_at < written + len(chunk):
                fh.write(chunk)
                fh.write(canary_bytes())
            else:
                fh.write(chunk)
            written += len(chunk)
    return {"files": 1, "bytes": target.stat().st_size, "canary_copies": 1}


def build_over_max_size(d: Path, scale: float) -> dict:
    """One file just past the 100 MiB default `--max-file-size`, holding the
    canary. This is what an operator hits by accident: a log, a heap dump, a
    vendored dataset. Scanned with DEFAULT arguments, unlike `one_large`, so the
    row measures the cap decision rather than large-file throughput."""
    d.mkdir(parents=True, exist_ok=True)
    default_cap = 100 * MIB
    total = max(4 * MIB, int((default_cap + 8 * MIB) * scale))
    rng = random.Random(17)
    block = filler_block(rng, 4 * MIB)
    target = d / "over-cap.log"
    with target.open("wb") as fh:
        fh.write(canary_bytes())
        written = len(canary_bytes())
        while written < total:
            chunk = block[: min(len(block), total - written)]
            fh.write(chunk)
            written += len(chunk)
    # A small sibling holding the canary too, so a scan that refuses the big
    # file still has readable bytes and the row separates "refused one file"
    # from "refused the whole directory".
    (d / "small.env").write_bytes(canary_bytes())
    return {
        "files": 2,
        "bytes": target.stat().st_size,
        "default_cap": default_cap,
        "over_cap_by": target.stat().st_size - default_cap,
        # Both copies are reachable: the small file entirely, and the big file's
        # first bytes are inside the cap.
        "canary_copies": 2,
    }



def build_one_long_line(d: Path, scale: float) -> dict:
    """One 50 MiB line. Any line-oriented buffer meets its worst case here.

    Named `single-line.json`, deliberately NOT `*.min.js`. A `.min.*` name hits
    the default minified-path exclusion, and then the row would measure that
    exclusion instead of long-line handling. The minified-path behavior is its
    own question and belongs in its own test.
    """
    d.mkdir(parents=True, exist_ok=True)
    total = max(4 * MIB, int(50 * MIB * scale))
    rng = random.Random(3)
    target = d / "single-line.json"
    # A single-line JSON object: no newline anywhere except the very end.
    piece = json.dumps(
        {
            "k": "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(48)),
            "v": rng.randrange(1 << 40),
        }
    ).encode()
    with target.open("wb") as fh:
        fh.write(b'{"records":[')
        written = 12
        first = True
        canary_written = False
        while written < total:
            if not first:
                fh.write(b",")
                written += 1
            if not canary_written and written >= total // 2:
                blob = json.dumps({"note": CANARY_LINE}).encode()
                canary_written = True
            else:
                blob = piece
            fh.write(blob)
            written += len(blob)
            first = False
        if not canary_written:
            fh.write(b"," + json.dumps({"note": CANARY_LINE}).encode())
        fh.write(b"]}\n")
    return {"files": 1, "bytes": target.stat().st_size, "lines": 1, "canary_copies": 1}


def build_deep_nest(d: Path, scale: float) -> dict:
    """Nesting depth, not breadth. Built with relative mkdir so PATH_MAX on the
    absolute path is not the binding limit: the walker's own recursion is."""
    d.mkdir(parents=True, exist_ok=True)
    want = max(16, int(4096 * scale))
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    depth = 0
    fds = [fd]
    try:
        while depth < want:
            try:
                os.mkdir("d", dir_fd=fds[-1])
                nxt = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fds[-1])
            except OSError:
                break
            fds.append(nxt)
            depth += 1
            # Keep the open-fd set bounded; only the tip needs to stay open.
            if len(fds) > 3:
                os.close(fds.pop(0))
        # Canary at the deepest level reached.
        leaf = os.open("secret.env", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644, dir_fd=fds[-1])
        with os.fdopen(leaf, "wb") as fh:
            fh.write(canary_bytes())
        # And a shallow marker so a walker that gives up early still sees files.
        (d / "shallow.env").write_bytes(b"# shallow marker, no credential\n")
    finally:
        for f in fds:
            try:
                os.close(f)
            except OSError:
                pass
    return {"depth": depth, "requested_depth": want, "files": 2, "canary_copies": 1}


def build_flat_many(d: Path, scale: float) -> dict:
    """200k entries in ONE directory. Tests readdir batching, not tree walking."""
    d.mkdir(parents=True, exist_ok=True)
    count = max(16, int(200_000 * scale))
    body = b"api_endpoint = https://orders.internal/v1\nretries = 3\n"
    canary_index = count // 2
    for i in range(count):
        p = d / f"f{i:06d}.env"
        p.write_bytes(canary_bytes() if i == canary_index else body)
    return {"files": count, "flat": True, "canary_copies": 1}


def build_binary_reject(d: Path, scale: float) -> dict:
    """Mostly-binary tree. Measures the cost of REJECTION, and whether a
    credential inside a rejected file is reported as unscanned or vanishes."""
    d.mkdir(parents=True, exist_ok=True)
    count = max(8, int(2000 * scale))
    per_file = 128 * 1024
    rng = random.Random(5)
    # Real binary: ELF magic, NUL runs, non-text bytes.
    blob = bytearray(b"\x7fELF\x02\x01\x01\x00" + bytes(8))
    blob += bytes(rng.randrange(256) for _ in range(4096))
    while len(blob) < per_file:
        blob += blob[:4096]
    blob = bytes(blob[:per_file])
    canary_index = count // 2
    for i in range(count):
        body = blob
        if i == canary_index:
            # Credential embedded in a genuinely binary file, the way a
            # compiled artifact or core dump carries one.
            body = blob[:4096] + canary_bytes() + blob[4096 + len(canary_bytes()) :]
        (d / f"artifact{i:05d}.bin").write_bytes(body)
    # One text file so the regime is not 100% rejected and we can tell a
    # reject-everything walker from a scan-nothing walker.
    (d / "readme.txt").write_bytes(b"# binary artifacts, no credentials here\n")
    return {
        "files": count + 1,
        "bytes": count * per_file,
        "canary_in": "binary file",
        "canary_copies": 1,
    }


def build_symlink_cycle(d: Path, scale: float) -> dict:
    """Symlink-heavy, including a self cycle, a mutual cycle, a dangling link,
    an absolute link, and a link that escapes the scan root."""
    d.mkdir(parents=True, exist_ok=True)
    real = d / "real"
    real.mkdir(exist_ok=True)
    (real / "plain.env").write_bytes(canary_bytes())
    (real / "filler.env").write_bytes(b"host = db.internal\n")

    outside = d.parent / f".{d.name}-outside"
    outside.mkdir(exist_ok=True)
    (outside / "escaped.env").write_bytes(b"OUTSIDE_ONLY=not-the-canary\n")

    links = {
        "self_cycle": ".",
        "loop_a": "loop_b",
        "loop_b": "loop_a",
        "dangling": "nowhere-at-all",
        "to_real": "real",
        "to_file": "real/plain.env",
        "abs_to_real": str(real.resolve()),
        "escape": str(outside.resolve()),
        "up_and_back": "../" + d.name + "/real",
    }
    count = max(1, int(64 * scale))
    for name, target in links.items():
        p = d / name
        if p.is_symlink() or p.exists():
            continue
        os.symlink(target, p)
    # A fan of links all pointing at the same real file: dedup pressure.
    fan = d / "fan"
    fan.mkdir(exist_ok=True)
    for i in range(count):
        p = fan / f"link{i:03d}"
        if not p.is_symlink():
            os.symlink("../real/plain.env", p)
    # real/plain.env plus every symlink that resolves to it. Counting only the
    # real file keeps the row about loop termination rather than link dedup
    # policy, which is a separate question.
    return {
        "links": len(links) + count,
        "cycles": 2,
        "canary_in": "real/plain.env",
        "canary_copies": 1,
    }


def build_no_extension(d: Path, scale: float) -> dict:
    """Extensionless files. Separate evidence says archive handling infers type
    from extension alone; this asks whether the plain walker does too."""
    d.mkdir(parents=True, exist_ok=True)
    names = [
        "Dockerfile",
        "Makefile",
        "credentials",
        "config",
        "id_rsa",
        "authorized_keys",
        "environment",
        "secrets",
        "LICENSE",
        "PKGBUILD",
    ]
    for name in names:
        (d / name).write_bytes(b"# nothing here\nmode = production\n")
    # Canary in an extensionless file whose name gives no hint at all.
    (d / "blob").write_bytes(canary_bytes())
    # A dotfile with no extension either.
    (d / ".envrc").write_bytes(b"export MODE=production\n")
    return {"files": len(names) + 2, "canary_in": "blob", "canary_copies": 1}


def build_encoding_mixed(d: Path, scale: float) -> dict:
    """Non-UTF-8 and mixed encodings. The canary is planted twice: once in
    plain UTF-8 (must be found) and once in UTF-16LE (documents whether
    wide-character content is covered)."""
    d.mkdir(parents=True, exist_ok=True)
    (d / "utf8.env").write_bytes(canary_bytes())
    (d / "utf8-bom.env").write_bytes(b"\xef\xbb\xbf" + canary_bytes())
    (d / "utf16le.env").write_bytes(
        b"\xff\xfe" + (CANARY_LINE + "\n").encode("utf-16-le")
    )
    (d / "utf16be.env").write_bytes(
        b"\xfe\xff" + (CANARY_LINE + "\n").encode("utf-16-be")
    )
    # Latin-1 high bytes make the file invalid UTF-8 while the canary itself
    # stays pure ASCII: a scan that gives up on the whole file loses a
    # credential it could read byte for byte.
    (d / "latin1.env").write_bytes(
        "# caf\u00e9 na\u00efve r\u00e9sum\u00e9\n".encode("latin-1") + canary_bytes()
    )
    # Shift-JIS comment, ASCII canary. Same question as latin-1 for a
    # double-byte legacy encoding.
    (d / "shift_jis.env").write_bytes(
        "# \u8a2d\u5b9a\u30d5\u30a1\u30a4\u30eb\n".encode("shift_jis") + canary_bytes()
    )
    # Invalid UTF-8: lone continuation bytes and a truncated sequence, with a
    # valid canary line sandwiched between them.
    (d / "invalid-utf8.env").write_bytes(
        b"\x80\x81\xfe\xff broken prefix\n" + canary_bytes() + b"\xc3 truncated\n"
    )
    # Mixed inside one file: UTF-8 line, then UTF-16 line, then UTF-8 again.
    (d / "mixed.env").write_bytes(
        b"MODE=production\n"
        + "OTHER=value\n".encode("utf-16-le")
        + canary_bytes()
    )
    return {
        "files": 8,
        "canary_in": "every file except none; all 8 carry it",
        "canary_copies": 8,
        "canary_encodings": [
            "utf-8",
            "utf-8 with BOM",
            "utf-16le with BOM",
            "utf-16be with BOM",
            "latin-1 comment then ascii canary",
            "shift-jis comment then ascii canary",
            "invalid utf-8 around an ascii canary",
            "utf-8 then utf-16le then ascii canary in one file",
        ],
    }


def build_sparse(d: Path, scale: float) -> dict:
    """Sparse files: apparent size far above allocated blocks. A scanner that
    trusts st_size budgets for a file it will never actually read."""
    d.mkdir(parents=True, exist_ok=True)
    apparent = max(1 * MIB, int(64 * MIB * scale))
    # Hole first, canary at the very end: reaching it requires traversing
    # the whole apparent length.
    tail = d / "sparse-tail.log"
    with tail.open("wb") as fh:
        fh.truncate(apparent)
        fh.seek(apparent)
        fh.write(canary_bytes())
    # Canary first, then a huge hole: cheap to find, expensive to finish.
    head = d / "sparse-head.log"
    with head.open("wb") as fh:
        fh.write(canary_bytes())
        fh.truncate(apparent)
    # All hole, no data at all.
    hole = d / "sparse-hole.log"
    with hole.open("wb") as fh:
        fh.truncate(apparent)
    facts = {}
    for p in (tail, head, hole):
        st = p.stat()
        facts[p.name] = {"apparent": st.st_size, "allocated": st.st_blocks * 512}
    # sparse-tail.log and sparse-head.log; sparse-hole.log is all hole and
    # deliberately carries nothing.
    return {
        "files": 3,
        "apparent_each": apparent,
        "detail": facts,
        "canary_copies": 2,
    }


def build_size_changing(d: Path, scale: float) -> dict:
    """Files that change size WHILE the scan runs. The mutator is started by
    run.py; generate.py only lays down the initial state and the canary."""
    d.mkdir(parents=True, exist_ok=True)
    rng = random.Random(11)
    block = filler_block(rng, 4 * MIB)
    base = max(4 * MIB, int(32 * MIB * scale))
    # grow.log is appended to during the scan.
    with (d / "grow.log").open("wb") as fh:
        fh.write(block[: base // 2])
    # shrink.log is truncated during the scan; the canary lives in the first
    # bytes so truncation cannot excuse missing it.
    with (d / "shrink.log").open("wb") as fh:
        fh.write(canary_bytes())
        written = len(canary_bytes())
        while written < base:
            chunk = block[: min(len(block), base - written)]
            fh.write(chunk)
            written += len(chunk)
    # A stable file with the canary, so the regime has a fixed point of truth.
    (d / "stable.env").write_bytes(canary_bytes())
    # shrink.log's canary is at byte 0 and stable.env's is the fixed point;
    # grow.log deliberately carries none.
    return {
        "files": 3,
        "mutated_during_scan": ["grow.log", "shrink.log"],
        "canary_copies": 2,
    }


def build_empty_dir(d: Path, scale: float) -> dict:
    """Genuinely nothing. The only regime where zero findings is correct, and
    the control that proves a zero-finding result is not always a bug."""
    force_rmtree(d)
    d.mkdir(parents=True, exist_ok=True)
    (d / "nested-empty").mkdir(exist_ok=True)
    return {"files": 0, "canary_in": None, "canary_copies": 0}


def build_unreadable_dir(d: Path, scale: float) -> dict:
    """A directory the scan cannot open, holding the canary. The scan must say
    so and must not report clean."""
    d.mkdir(parents=True, exist_ok=True)
    (d / "readable.env").write_bytes(b"MODE=production\n")
    locked = d / "locked"
    if locked.exists():
        locked.chmod(0o755)
    locked.mkdir(exist_ok=True)
    (locked / "secret.env").write_bytes(canary_bytes())
    locked.chmod(0o000)
    # An unreadable FILE in a readable directory, the other half of the case.
    unreadable_file = d / "unreadable.env"
    unreadable_file.write_bytes(canary_bytes())
    unreadable_file.chmod(0o000)
    return {
        "files": 3,
        "canary_in": "locked/secret.env + unreadable.env",
        # Neither copy is reachable without elevated privileges. Expecting 0 is
        # the point: this regime asks whether the scan SAYS so.
        "canary_copies": 0,
        "unreadable_dirs": 1,
        "unreadable_files": 1,
    }


def build_all_sources_fail(d: Path, scale: float) -> dict:
    """A tree where EVERY file errors, and the canary is inside the readable
    part of the one file present.

    This is `over_max_size` with the small sibling removed. The difference is
    not cosmetic: with a sibling the scan reports the sibling's finding and a
    coverage gap, and with no sibling every source row errors and the scan
    discards everything, including the canary sitting at byte 0 of a file whose
    first 100 MiB the cap allows. A scan that cannot honor its whole input must
    say so loudly, but it must not throw away what it already found, and it must
    still write the machine-readable report it was asked for.
    """
    d.mkdir(parents=True, exist_ok=True)
    default_cap = 100 * MIB
    total = max(4 * MIB, int((default_cap + 8 * MIB) * scale))
    rng = random.Random(23)
    block = filler_block(rng, 4 * MIB)
    target = d / "only-over-cap.log"
    with target.open("wb") as fh:
        fh.write(canary_bytes())
        written = len(canary_bytes())
        while written < total:
            chunk = block[: min(len(block), total - written)]
            fh.write(chunk)
            written += len(chunk)
    return {
        "files": 1,
        "bytes": target.stat().st_size,
        "default_cap": default_cap,
        "canary_at_offset": 0,
        "canary_copies": 1,
    }


def build_encoded_midfile(d: Path, scale: float) -> dict:
    """An encoded payload in the INTERIOR of a large file, with a small-file
    control beside it.

    Decode-through is capped per CHUNK, not per file. The filesystem reader
    windows a large file at 1 MiB with 128 KiB of overlap, and the decode-through
    cap defaults to 512 KiB. So a full-size window can never be decode-expanded,
    and an encoded credential anywhere in the interior of a file over 1 MiB is
    unreachable, deterministically, at every size.

    That is invisible if you plant at EOF. The last window is whatever is left
    over, so its size oscillates with file size and a payload there is recovered
    whenever the remainder happens to fall under the cap. Measured on the
    pristine reference, same payload, one Base64 layer, default preset:

        1,500,103 bytes   head MISS   mid MISS   eof MISS
        2,048,101 bytes   head MISS   mid MISS   eof FOUND
        4,194,421 bytes   head MISS   mid MISS   eof FOUND only at 2 MiB-ish sizes

    Interior and head miss at every size; only the tail is ever reachable and only
    at the sizes where the remainder fits. So the fixture plants mid-file, where
    the outcome does not depend on arithmetic nobody will remember.

    `reachable.log` is the control. It holds the same encoded payload in a file
    far below the cap, so it MUST be found. Without it, a zero on this regime
    cannot be told apart from "the encoded canary is not detectable at all",
    which would make the row meaningless.
    """
    d.mkdir(parents=True, exist_ok=True)
    encoded = canary_base64_bytes()
    # One repeated low-entropy line, deliberately not the varied FILLER_LINES
    # used elsewhere: the point of this regime is the decode cap, and filler that
    # trips per-chunk match ceilings or shape suppressions would give the row a
    # second possible cause for its zero.
    line = b"service_name = orders-api  retry_backoff_ms = 250  pool_size = 32\n"

    total = max(2 * MIB, int(4 * MIB * scale))
    interior = d / "interior.log"
    body = line * (total // len(line))
    with interior.open("wb") as fh:
        half = len(body) // 2
        fh.write(body[:half])
        fh.write(encoded)
        fh.write(body[half:])

    reachable = d / "reachable.log"
    with reachable.open("wb") as fh:
        fh.write(line * (64 * 1024 // len(line)))
        fh.write(encoded)

    return {
        "files": 2,
        "interior_bytes": interior.stat().st_size,
        "reachable_bytes": reachable.stat().st_size,
        "encoding": "one base64 layer, assignment-anchored",
        "canary_copies": 2,
        "control": "reachable.log must be found; interior.log is the defect",
    }


BUILDERS = {
    "many_small": build_many_small,
    "one_large": build_one_large,
    "encoded_midfile": build_encoded_midfile,
    "over_max_size": build_over_max_size,
    "one_long_line": build_one_long_line,
    "deep_nest": build_deep_nest,
    "flat_many": build_flat_many,
    "binary_reject": build_binary_reject,
    "symlink_cycle": build_symlink_cycle,
    "no_extension": build_no_extension,
    "encoding_mixed": build_encoding_mixed,
    "sparse": build_sparse,
    "size_changing": build_size_changing,
    "empty_dir": build_empty_dir,
    "unreadable_dir": build_unreadable_dir,
    "all_sources_fail": build_all_sources_fail,
}

REGIMES = list(BUILDERS)


# Bump when a builder changes what it plants or what it reports. A regime whose
# stamp carries an older version is rebuilt, because `run.py` reads the stamp to
# decide how many canary copies the row should find, and a stale stamp would
# quietly compare against the wrong number.
STAMP_VERSION = 2


def generate(root: Path, only: list[str], scale: float, force: bool) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    facts = {}
    for name in only:
        d = root / name
        sp = stamp_path(d)
        want = {"regime": name, "scale": scale, "stamp_version": STAMP_VERSION}
        if not force and sp.exists():
            try:
                have = json.loads(sp.read_text())
            except (OSError, ValueError):
                have = None
            fresh = (
                have
                and have.get("scale") == scale
                and have.get("stamp_version") == STAMP_VERSION
            )
            if fresh:
                facts[name] = have
                print(f"  {name}: already built (scale={scale})")
                continue
        print(f"  {name}: building (scale={scale}) ...", flush=True)
        force_rmtree(d)
        d.mkdir(parents=True, exist_ok=True)
        want.update(BUILDERS[name](d, scale))
        sp.write_text(json.dumps(want, indent=2, sort_keys=True))
        facts[name] = want
    return facts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", required=True, type=Path, help="corpus root directory")
    ap.add_argument("--only", nargs="*", default=None, choices=REGIMES)
    ap.add_argument(
        "--scale",
        type=float,
        default=1.0,
        help="multiply every regime's size/count (0.05 for a quick smoke build)",
    )
    ap.add_argument("--force", action="store_true", help="rebuild even if stamped")
    ap.add_argument("--clean", action="store_true", help="remove the corpus root and exit")
    args = ap.parse_args(argv)

    if args.clean:
        force_rmtree(args.root)
        print(f"removed {args.root}")
        return 0

    only = args.only or REGIMES
    print(f"corpus root: {args.root}")
    facts = generate(args.root, only, args.scale, args.force)
    print(json.dumps(facts, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
