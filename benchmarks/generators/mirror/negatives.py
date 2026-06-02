"""False-positive-shape generators for the SecretBench mirror corpus.

These produce realistic, non-secret payloads that LOOK like
credentials to a naive scanner: UUIDs, SHA digests, commit hashes,
JWT-shaped tokens drawn from RFC examples, base64-of-protobuf,
license keys formatted like cloud secrets, etc. Every output is a
LABEL=false fixture and any finding fired on it counts as a
scanner false positive.
"""

from __future__ import annotations

import random
import string
from collections.abc import Iterator
from typing import Callable

B62 = string.ascii_letters + string.digits
HEX = string.hexdigits.lower()


def _rand_chars(rnd: random.Random, alphabet: str, length: int) -> str:
    return "".join(rnd.choice(alphabet) for _ in range(length))


def uuid_v4(rnd: random.Random) -> str:
    parts = [
        _rand_chars(rnd, HEX, 8),
        _rand_chars(rnd, HEX, 4),
        "4" + _rand_chars(rnd, HEX, 3),
        rnd.choice("89ab") + _rand_chars(rnd, HEX, 3),
        _rand_chars(rnd, HEX, 12),
    ]
    return "-".join(parts)


def sha256_hex(rnd: random.Random) -> str:
    return _rand_chars(rnd, HEX, 64)


def sha1_hex(rnd: random.Random) -> str:
    return _rand_chars(rnd, HEX, 40)


def git_commit_sha(rnd: random.Random) -> str:
    return _rand_chars(rnd, HEX, 40)


def npm_lockfile_integrity(rnd: random.Random) -> str:
    return "sha512-" + _rand_chars(rnd, B62 + "+/", 86) + "=="


def python_requirements_hash(rnd: random.Random) -> str:
    return "--hash=sha256:" + _rand_chars(rnd, HEX, 64)


def template_placeholder(rnd: random.Random) -> str:
    tag = rnd.choice(["YOUR_API_KEY", "your-token", "INSERT_TOKEN_HERE", "<change-me>"])
    return f"{{ {tag} }}" if rnd.random() < 0.5 else f"<{tag}>"


def docs_example_marker(rnd: random.Random) -> str:
    return rnd.choice([
        "ghp_EXAMPLE_TOKEN_FROM_DOCS",
        "AKIAEXAMPLEEXAMPLE12",
        "xoxb-1234567890-1234567890-EXAMPLE-TOKEN",
        "sk_live_PLACEHOLDER_NOT_A_REAL_KEY",
    ])


def base64_of_protobuf(rnd: random.Random) -> str:
    # protobuf wire format produces a distinct-looking but base64-y string
    body = bytes([rnd.randint(0, 255) for _ in range(rnd.randint(30, 80))])
    import base64
    return base64.b64encode(body).decode()


def license_key_shape(rnd: random.Random) -> str:
    blocks = [_rand_chars(rnd, string.ascii_uppercase + string.digits, 5) for _ in range(5)]
    return "-".join(blocks)


def aws_arn(rnd: random.Random) -> str:
    return f"arn:aws:iam::{_rand_chars(rnd, string.digits, 12)}:role/{rnd.choice(['Admin', 'Reader', 'Writer'])}Role"


def lorem_ipsum_with_high_entropy_token(rnd: random.Random) -> str:
    # a fake "session ID" embedded in prose
    tok = _rand_chars(rnd, B62, rnd.randint(24, 48))
    return f"Session opened with handle {tok}. See documentation for details."


def jwt_example_from_rfc(rnd: random.Random) -> str:
    # The RFC 7519 specimen JWT — a famous public example token.
    return (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )


def html_color_or_hash(rnd: random.Random) -> str:
    return "#" + _rand_chars(rnd, HEX, 6)


def docker_image_digest(rnd: random.Random) -> str:
    return f"nginx@sha256:{_rand_chars(rnd, HEX, 64)}"


def k8s_resource_uid(rnd: random.Random) -> str:
    return uuid_v4(rnd)


NEGATIVE_CATALOG: list[tuple[str, Callable[[random.Random], str], int]] = [
    ("uuid",                       uuid_v4,                       80),
    ("sha256-hex",                 sha256_hex,                    70),
    ("sha1-hex",                   sha1_hex,                      50),
    ("git-commit-sha",             git_commit_sha,                40),
    ("npm-lock-integrity",         npm_lockfile_integrity,        40),
    ("python-requirements-hash",   python_requirements_hash,      30),
    ("template-placeholder",       template_placeholder,          40),
    ("docs-example-marker",        docs_example_marker,           40),
    ("base64-protobuf",            base64_of_protobuf,            50),
    ("license-key-shape",          license_key_shape,             30),
    ("aws-arn",                    aws_arn,                       20),
    ("lorem-with-high-entropy",    lorem_ipsum_with_high_entropy_token, 30),
    ("jwt-rfc-example",            jwt_example_from_rfc,          10),
    ("html-color",                 html_color_or_hash,            20),
    ("docker-image-digest",        docker_image_digest,           20),
    ("k8s-resource-uid",           k8s_resource_uid,              20),
]


def weighted_iter(
    rnd: random.Random, total: int
) -> Iterator[tuple[str, str]]:
    """Yield `total` (negative_kind, body) tuples."""
    weights = [w for _, _, w in NEGATIVE_CATALOG]
    choices = list(range(len(NEGATIVE_CATALOG)))
    for _ in range(total):
        idx = rnd.choices(choices, weights=weights, k=1)[0]
        kind, builder, _ = NEGATIVE_CATALOG[idx]
        yield kind, builder(rnd)
