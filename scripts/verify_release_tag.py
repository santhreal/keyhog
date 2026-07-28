#!/usr/bin/env python3
"""Validate one exact GitHub signed annotated release-tag API proof."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

TAG = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)

OBJECT_SHA = re.compile(r"^[0-9a-f]{40}$")
AUTHORIZED_TAGGER_NAME = "Santh"
AUTHORIZED_TAGGER_EMAIL = "64453045+santhreal@users.noreply.github.com"
AUTHORIZED_ACTOR_ID = "64453045"


class TagVerificationError(RuntimeError):
    """The release ref is not one exact verified annotated Git tag."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TagVerificationError(f"{label} is not a JSON object")
    return value


def verify_release_actor(actor_id: str) -> None:
    """Fail unless GitHub identifies the immutable authorized release account."""

    if actor_id != AUTHORIZED_ACTOR_ID:
        raise TagVerificationError("release entry actor is not the authorized stable account ID")

def _validate_tag(tag: str) -> None:
    match = TAG.fullmatch(tag)
    if match is None:
        raise TagVerificationError(
            f"release tag is not canonical semantic version syntax: {tag!r}"
        )
    prerelease = match.group(4)
    if prerelease is not None:
        for identifier in prerelease.split("."):
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                raise TagVerificationError(
                    f"release tag has a leading-zero numeric prerelease identifier: {tag!r}"
                )




def verify_signed_tag(
    *,
    tag: str,
    expected_commit: str,
    ref_record: dict[str, Any],
    tag_record: dict[str, Any],
) -> str:
    _validate_tag(tag)
    if OBJECT_SHA.fullmatch(expected_commit) is None:
        raise TagVerificationError(f"expected commit is not lowercase 40-hex: {expected_commit!r}")

    if ref_record.get("ref") != f"refs/tags/{tag}":
        raise TagVerificationError("Git ref response does not name the requested exact tag")
    ref_object = _object(ref_record.get("object"), "Git ref object")
    if ref_object.get("type") != "tag":
        raise TagVerificationError("release ref is lightweight; an annotated Git tag is required")
    tag_object_sha = ref_object.get("sha")
    if not isinstance(tag_object_sha, str) or OBJECT_SHA.fullmatch(tag_object_sha) is None:
        raise TagVerificationError("annotated tag ref has no lowercase 40-hex object SHA")

    if tag_record.get("sha") != tag_object_sha or tag_record.get("tag") != tag:
        raise TagVerificationError("Git tag object response does not match the requested ref object")
    peeled = _object(tag_record.get("object"), "peeled tag object")
    if peeled.get("type") != "commit" or peeled.get("sha") != expected_commit:
        raise TagVerificationError("signed tag object does not peel to the triggering CI commit")

    tagger = _object(tag_record.get("tagger"), "annotated tagger")
    if (
        tagger.get("name") != AUTHORIZED_TAGGER_NAME
        or tagger.get("email") != AUTHORIZED_TAGGER_EMAIL
    ):
        raise TagVerificationError("annotated release tag does not use the authorized tagger identity")
    date = tagger.get("date")
    if not isinstance(date, str):
        raise TagVerificationError("annotated tagger has no exact date")
    try:
        parsed_date = dt.datetime.fromisoformat(date.replace("Z", "+00:00"))
    except ValueError as error:
        raise TagVerificationError(f"annotated tagger date is invalid: {date!r}") from error
    if parsed_date.tzinfo is None or parsed_date.microsecond != 0:
        raise TagVerificationError("annotated tagger date must be timezone-qualified whole seconds")

    message = tag_record.get("message")
    if not isinstance(message, str) or not message:
        raise TagVerificationError("annotated release tag has no message")
    verification = _object(tag_record.get("verification"), "tag signature verification")
    if verification.get("verified") is not True:
        reason = verification.get("reason")
        raise TagVerificationError(f"annotated release tag signature is not verified: {reason!r}")
    signature = verification.get("signature")
    if not isinstance(signature, str) or not signature.strip():
        raise TagVerificationError("verified annotated tag has no signature bytes")
    payload = verification.get("payload")
    if not isinstance(payload, str):
        raise TagVerificationError("verified annotated tag has no signed payload bytes")
    payload_match = re.fullmatch(
        r"object (?P<object>[0-9a-f]{40})\n"
        r"type (?P<type>[^\n]+)\n"
        r"tag (?P<tag>[^\n]+)\n"
        r"tagger (?P<name>[^<\n]+) <(?P<email>[^>\n]+)> "
        r"(?P<timestamp>[0-9]+) (?P<offset>[+-][0-9]{4})\n\n"
        r"(?P<message>[\s\S]*)",
        payload,
    )
    if payload_match is None:
        raise TagVerificationError("verified signature payload is not one canonical Git tag object")
    fields = payload_match.groupdict()
    if (
        fields["object"] != expected_commit
        or fields["type"] != "commit"
        or fields["tag"] != tag
        or fields["name"] != AUTHORIZED_TAGGER_NAME
        or fields["email"] != AUTHORIZED_TAGGER_EMAIL
        or fields["message"] != message
    ):
        raise TagVerificationError(
            "verified signature payload does not exactly encode the authenticated tag metadata"
        )
    offset_text = fields["offset"]
    offset_hours = int(offset_text[1:3])
    offset_minutes = int(offset_text[3:5])
    if offset_hours > 23 or offset_minutes > 59:
        raise TagVerificationError("verified signature payload has an invalid Git UTC offset")
    payload_offset = dt.timedelta(hours=offset_hours, minutes=offset_minutes)
    if offset_text.startswith("-"):
        payload_offset = -payload_offset
    try:
        payload_date = dt.datetime.fromtimestamp(
            int(fields["timestamp"]), dt.timezone(payload_offset)
        )
    except (OverflowError, OSError, ValueError) as error:
        raise TagVerificationError("verified signature payload has an invalid Git timestamp") from error
    if payload_date.astimezone(dt.timezone.utc) != parsed_date.astimezone(dt.timezone.utc):
        raise TagVerificationError(
            "verified signature payload date does not match annotated tagger metadata"
        )
    return tag_object_sha


def verify_authorized_signature(
    *,
    tag_record: dict[str, Any],
    authorized_fingerprint: str,
    authorized_public_key: str,
    github_gpg_keys: Any,
) -> None:
    """Cryptographically bind the tag signature to one allowlisted release key."""

    fingerprint = authorized_fingerprint.upper()
    if re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})", fingerprint) is None:
        raise TagVerificationError(
            "no exact santhreal release-key fingerprint is configured; enroll the "
            "release key with GitHub and configure KEYHOG_RELEASE_SIGNING_FINGERPRINT"
        )
    if not isinstance(github_gpg_keys, list) or not github_gpg_keys:
        raise TagVerificationError(
            "santhreal has no enrolled GitHub GPG signing key; release publication is blocked"
        )
    raw_keys: list[str] = []
    for index, record in enumerate(github_gpg_keys):
        if not isinstance(record, dict):
            raise TagVerificationError(
                f"GitHub santhreal GPG key record {index} is not an object"
            )
        raw_key = record.get("raw_key")
        if not isinstance(raw_key, str) or not raw_key.strip() or len(raw_key) > 1_000_000:
            raise TagVerificationError(
                f"GitHub santhreal GPG key record {index} has invalid raw_key bytes"
            )
        raw_keys.append(raw_key)
    if (
        not isinstance(authorized_public_key, str)
        or not authorized_public_key.strip()
        or len(authorized_public_key) > 1_000_000
    ):
        raise TagVerificationError(
            "no committed santhreal release public key is configured; enroll and "
            "commit the exact armored key before publication"
        )
    if authorized_public_key not in raw_keys:
        raise TagVerificationError(
            "committed santhreal release public key is not enrolled in GitHub"
        )
    if len(set(raw_keys)) != len(raw_keys):
        raise TagVerificationError("GitHub returned duplicate santhreal GPG key records")
    verification = _object(tag_record.get("verification"), "tag signature verification")
    payload = verification.get("payload")
    signature = verification.get("signature")
    if not isinstance(payload, str) or not isinstance(signature, str):
        raise TagVerificationError("verified tag has no cryptographic payload/signature pair")

    # Import only the committed allowlisted key. GitHub's key list is an
    # independent enrollment proof, never an alternate trust root.
    try:
        with tempfile.TemporaryDirectory(prefix="keyhog-release-gpg-") as directory:
            home = Path(directory)
            home.chmod(0o700)
            payload_path = home / "tag.payload"
            signature_path = home / "tag.signature"
            payload_path.write_text(payload, encoding="utf-8")
            signature_path.write_text(signature, encoding="utf-8")
            imported = subprocess.run(
                [
                    "gpg",
                    "--no-options",
                    "--batch",
                    "--homedir",
                    str(home),
                    "--import",
                ],
                input=authorized_public_key,
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
            if imported.returncode != 0:
                raise TagVerificationError(
                    f"cannot import enrolled santhreal release keys: {imported.stderr.strip()}"
                )
            checked = subprocess.run(
                [
                    "gpg",
                    "--no-options",
                    "--batch",
                    "--homedir",
                    str(home),
                    "--status-fd",
                    "1",
                    "--verify",
                    str(signature_path),
                    str(payload_path),
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
    except (OSError, subprocess.SubprocessError) as error:
        raise TagVerificationError(
            f"cannot execute isolated GPG release-tag verification: {error}"
        ) from error

    valid_fingerprints: set[str] = set()
    for line in checked.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[:2] == ["[GNUPG:]", "VALIDSIG"]:
            valid_fingerprints.add(fields[2].upper())
            primary = fields[-1].upper()
            if re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})", primary):
                valid_fingerprints.add(primary)
    if checked.returncode != 0 or fingerprint not in valid_fingerprints:
        raise TagVerificationError(
            "annotated tag signature is not made by the allowlisted santhreal release key"
        )


def verify_main_ancestry(
    *,
    expected_commit: str,
    main_ref_record: dict[str, Any],
    compare_record: dict[str, Any],
) -> str:
    """Return the pinned main SHA iff the release commit is in main ancestry."""

    if OBJECT_SHA.fullmatch(expected_commit) is None:
        raise TagVerificationError(f"expected commit is not lowercase 40-hex: {expected_commit!r}")
    if main_ref_record.get("ref") != "refs/heads/main":
        raise TagVerificationError("trusted branch response does not name refs/heads/main")
    main_object = _object(main_ref_record.get("object"), "trusted main ref object")
    main_sha = main_object.get("sha")
    if (
        main_object.get("type") != "commit"
        or not isinstance(main_sha, str)
        or OBJECT_SHA.fullmatch(main_sha) is None
    ):
        raise TagVerificationError("trusted main ref has no pinned commit SHA")

    base = _object(compare_record.get("base_commit"), "compare base commit")
    head = _object(compare_record.get("head_commit"), "compare head commit")
    merge_base = _object(compare_record.get("merge_base_commit"), "compare merge base")
    if (
        base.get("sha") != expected_commit
        or head.get("sha") != main_sha
        or merge_base.get("sha") != expected_commit
        or compare_record.get("status") not in {"ahead", "identical"}
    ):
        raise TagVerificationError(
            "signed release commit is not in the pinned trusted main ancestry"
        )
    return main_sha


def _read_text(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise TagVerificationError(f"cannot read {label} {path}: {error}") from error


def _read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TagVerificationError(f"cannot read {label} JSON {path}: {error}") from error


def _read(path: Path, label: str) -> dict[str, Any]:
    return _object(_read_json(path, label), label)


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--actor-id", required=True)
    parser.add_argument("--ref-json", required=True, type=Path)
    parser.add_argument("--tag-json", required=True, type=Path)
    parser.add_argument("--main-ref-json", required=True, type=Path)
    parser.add_argument("--compare-json", required=True, type=Path)
    parser.add_argument("--authorized-key", required=True, type=Path)
    parser.add_argument("--signer-keys-json", required=True, type=Path)
    parser.add_argument("--authorized-fingerprint", required=True)
    options = parser.parse_args(arguments)
    verify_release_actor(options.actor_id)
    tag_record = _read(options.tag_json, "Git tag response")
    tag_object_sha = verify_signed_tag(
        tag=options.tag,
        expected_commit=options.expected_commit,
        ref_record=_read(options.ref_json, "Git ref response"),
        tag_record=tag_record,
    )
    verify_authorized_signature(
        tag_record=tag_record,
        authorized_fingerprint=options.authorized_fingerprint,
        authorized_public_key=_read_text(
            options.authorized_key, "committed release public key"
        ),
        github_gpg_keys=_read_json(options.signer_keys_json, "GitHub signer keys"),
    )
    verify_main_ancestry(
        expected_commit=options.expected_commit,
        main_ref_record=_read(options.main_ref_json, "trusted main ref response"),
        compare_record=_read(options.compare_json, "pinned compare response"),
    )
    print(tag_object_sha)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TagVerificationError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
