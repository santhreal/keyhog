#!/usr/bin/env python3
"""Create one exact OpenPGP-signed release tag without exposing its passphrase."""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

SEMVER_TAG_RE = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z"
)
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
FINGERPRINT_RE = re.compile(r"[0-9A-F]{40}(?:[0-9A-F]{24})?\Z")


class SigningError(RuntimeError):
    """The requested tag cannot be created without weakening signing policy."""


def run(
    args: list[str], *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run one argument-safe command and retain its complete diagnostic output."""
    result = subprocess.run(
        args,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise SigningError(
            f"command exited {result.returncode}: {' '.join(args)}"
            + (f"\n{detail}" if detail else "")
        )
    return result


def validate_passphrase_file(path: Path) -> Path:
    """Require one owner-only regular file so another local user cannot replace it."""
    if not path.is_absolute():
        raise SigningError("--passphrase-file must be an absolute path")
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise SigningError(f"passphrase file does not exist: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SigningError("passphrase file must be a regular file, not a symlink")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SigningError("passphrase file permissions must deny group and other access")
    if metadata.st_size == 0 or metadata.st_size > 4096:
        raise SigningError("passphrase file must contain between 1 and 4096 bytes")
    return path


def primary_secret_key(fingerprint: str, env: dict[str, str]) -> tuple[str, str]:
    """Resolve the exact primary fingerprint and keygrip of one local secret key."""
    result = subprocess.run(
        [
            "gpg",
            "--batch",
            "--with-colons",
            "--with-keygrip",
            "--fingerprint",
            "--fingerprint",
            "--list-secret-keys",
            fingerprint,
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    if result.returncode != 0:
        raise SigningError(f"no OpenPGP secret key exists for {fingerprint}")
    primary_fingerprint: str | None = None
    saw_primary = False
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "sec":
            saw_primary = True
        elif (
            saw_primary
            and primary_fingerprint is None
            and fields[0] == "fpr"
            and len(fields) > 9
        ):
            primary_fingerprint = fields[9].upper()
        elif (
            saw_primary
            and primary_fingerprint is not None
            and fields[0] == "grp"
            and len(fields) > 9
            and fields[9]
        ):
            return primary_fingerprint, fields[9]
    raise SigningError(f"no complete OpenPGP secret key exists for {fingerprint}")


def valid_signature_fingerprints(tag: str, env: dict[str, str]) -> set[str]:
    """Return every primary and signing fingerprint authenticated by Git."""
    result = subprocess.run(
        ["git", "verify-tag", "--raw", tag],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise SigningError(
            f"created tag {tag} does not have a valid OpenPGP signature"
            + (f": {detail}" if detail else "")
        )
    fingerprints: set[str] = set()
    marker = "[GNUPG:] VALIDSIG "
    for line in (result.stderr + "\n" + result.stdout).splitlines():
        if marker not in line:
            continue
        fields = line.partition(marker)[2].split()
        if fields:
            fingerprints.add(fields[0].upper())
            fingerprints.add(fields[-1].upper())
    return fingerprints


def create_signed_tag(
    *, tag: str, commit: str, fingerprint: str, passphrase_file: Path
) -> None:
    """Create and verify one immutable annotated tag at one exact commit."""
    if not SEMVER_TAG_RE.fullmatch(tag):
        raise SigningError("--tag must be a canonical stable vX.Y.Z tag")
    if not COMMIT_RE.fullmatch(commit):
        raise SigningError("--commit must be one lowercase 40-hex Git commit")
    normalized_fingerprint = fingerprint.upper()
    if not FINGERPRINT_RE.fullmatch(normalized_fingerprint):
        raise SigningError("--fingerprint must be one full uppercase OpenPGP fingerprint")
    passphrase_file = validate_passphrase_file(passphrase_file)
    env = os.environ.copy()
    resolved = run(["git", "rev-parse", "--verify", f"{commit}^{{commit}}"], env=env)
    if resolved.stdout.strip() != commit:
        raise SigningError(f"commit {commit} did not resolve to itself")
    existing = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", f"refs/tags/{tag}"],
        check=False,
        env=env,
    )
    if existing.returncode == 0:
        raise SigningError(f"tag {tag} already exists and will not be replaced")
    if existing.returncode != 1:
        raise SigningError(f"cannot determine whether tag {tag} already exists")
    primary_fingerprint, keygrip = primary_secret_key(normalized_fingerprint, env)
    if primary_fingerprint != normalized_fingerprint:
        raise SigningError(
            f"configured secret key is not primary fingerprint {normalized_fingerprint}"
        )
    run(["gpg-connect-agent", f"CLEAR_PASSPHRASE {keygrip}", "/bye"], env=env)
    if not env.get("GNUPGHOME"):
        raise SigningError("GNUPGHOME must name the dedicated release keyring")
    run(["gpgconf", "--kill", "gpg-agent"], env=env)

    with tempfile.TemporaryDirectory(prefix="keyhog-release-sign-") as directory:
        wrapper = Path(directory) / "gpg-wrapper"
        wrapper.write_text(
            "#!/bin/sh\n"
            "exec gpg --batch --no-tty --pinentry-mode loopback "
            '"--passphrase-file=$KEYHOG_RELEASE_GPG_PASSPHRASE_FILE" "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
        signing_env = env.copy()
        signing_env["KEYHOG_RELEASE_GPG_PASSPHRASE_FILE"] = str(passphrase_file)
        created = False
        try:
            run(
                [
                    "git",
                    "-c",
                    f"user.signingkey={normalized_fingerprint}",
                    "-c",
                    "gpg.format=openpgp",
                    "-c",
                    f"gpg.program={wrapper}",
                    "tag",
                    "-s",
                    "-a",
                    tag,
                    commit,
                    "-m",
                    f"KeyHog {tag}",
                ],
                env=signing_env,
            )
            created = True
            valid = valid_signature_fingerprints(tag, signing_env)
            if normalized_fingerprint not in valid:
                raise SigningError(
                    f"tag {tag} was not signed by {normalized_fingerprint}"
                )
            peeled = run(["git", "rev-parse", "--verify", f"{tag}^{{commit}}"], env=env)
            if peeled.stdout.strip() != commit:
                raise SigningError(f"tag {tag} does not peel to {commit}")
        except Exception:
            if created:
                subprocess.run(
                    ["git", "tag", "--delete", tag],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                )
            raise


def parser() -> argparse.ArgumentParser:
    """Build the fail-closed command-line contract."""
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--tag", required=True)
    command.add_argument("--commit", required=True)
    command.add_argument("--fingerprint", required=True)
    command.add_argument("--passphrase-file", required=True, type=Path)
    return command


def main() -> int:
    """Create the requested tag or report one controlled signing error."""
    args = parser().parse_args()
    try:
        create_signed_tag(
            tag=args.tag,
            commit=args.commit,
            fingerprint=args.fingerprint,
            passphrase_file=args.passphrase_file,
        )
    except SigningError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(f"Created and verified {args.tag} at {args.commit} with {args.fingerprint.upper()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
