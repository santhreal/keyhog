"""Labeled training corpus for the keyhog ML secret scorer.

Emits JSONL records {text, context, label, kind} where `text` is the candidate
credential the scanner would extract and `context` is the local code/config
window around it. `label` is 1 for real secrets, 0 for false-positive shapes.

Design intent (the reason this corpus exists): teach the model keyhog's
decode-through advantage. The negative set is deliberately heavy on
base64-of-binary (PNG / JPEG / gzip / zlib / zip / PDF / ELF / wasm / a real
protobuf message) placed in BOTH neutral and secret-keyword contexts, while the
positive set includes base64-WRAPPED real secrets. The decode-structure feature
(#41) fires on the former and not the latter, so the model can learn to discount
"base64 that decodes to a binary asset" without losing real base64 secrets.
This is the supervised signal behind "if we improve our ML model we can filter
out base64."

Negative shape lineage follows benchmarks/generators/mirror/negatives.py; the binary
generators are new (that file's `base64_of_protobuf` produced random bytes, which
parse as protobuf <0.5% of the time, here we emit a genuine wire message plus
real magic-byte containers so the decode feature is exercised honestly).
"""

from __future__ import annotations

import base64
import json
import random
import string
import sys

B62 = string.ascii_letters + string.digits
B64 = B62 + "+/"
HEX = "0123456789abcdef"

SECRET_KW_CONTEXTS = [
    "api_key = \"{}\"",
    "API_KEY={}",
    "secret = '{}'",
    "client_secret: {}",
    "auth_token = \"{}\"",
    "password = {}",
    "AWS_SECRET_ACCESS_KEY={}",
    "token: \"{}\"",
    "Authorization: Bearer {}",
    "private_key = {}",
    "  \"apiKey\": \"{}\",",
    "export GITHUB_TOKEN={}",
]

NEUTRAL_CONTEXTS = [
    "value = \"{}\"",
    "data: {}",
    "id = {}",
    "avatar = \"{}\"",
    "logo: {}",
    "blob = {}",
    "image = \"{}\"",
    "content = '{}'",
    "  \"payload\": \"{}\",",
    "result := {}",
    "<field>{}</field>",
    "cache_entry = {}",
]

FILE_HINT_CONTEXTS = [
    "jobs:\n  build:\n    env:\n      KEY: {}",          # ci
    "resource \"aws_secret\" {{ value = \"{}\" }}",       # infra
    "const apiKey = \"{}\";",                              # source
    "config.yaml\napi_key: {}",                            # config
]

# Hash / checksum / digest contexts. Hex-shaped negatives (MD5/SHA/commit/etag)
# live here, NOT under secret keywords: a bare hex digest in a checksum context
# is never a credential, and the model must learn the distinction from a hex
# *key* under an encryption_key/signing_key keyword. Without these the model
# collapses "any 32-64 hex string" into "secret".
HASH_CONTEXTS = [
    "checksum = {}",
    "md5: {}",
    "sha256 = \"{}\"",
    "digest: {}",
    "etag: \"{}\"",
    "integrity = {}",
    "hash = {}",
    "  \"sha256\": \"{}\",",
    "Content-MD5: {}",
    "commit {}",
]


def _rc(rnd: random.Random, alphabet: str, n: int) -> str:
    return "".join(rnd.choice(alphabet) for _ in range(n))


# ── positives: real-shaped secrets ─────────────────────────────────────────

def pos_aws_access_key(rnd):
    return "AKIA" + _rc(rnd, string.ascii_uppercase + string.digits, 16)


def pos_aws_secret(rnd):
    return _rc(rnd, B64, 40)


def pos_github_pat(rnd):
    return "ghp_" + _rc(rnd, B62, 36)


def pos_slack_bot(rnd):
    return f"xoxb-{_rc(rnd, string.digits, 11)}-{_rc(rnd, string.digits, 13)}-{_rc(rnd, B62, 24)}"


def pos_stripe(rnd):
    return "sk_live_" + _rc(rnd, B62, 24)


def pos_openai(rnd):
    return "sk-" + _rc(rnd, B62, 48)


def pos_generic_highentropy(rnd):
    return _rc(rnd, B62, rnd.randint(28, 48))


def pos_hex_key(rnd):
    return _rc(rnd, HEX, rnd.choice([32, 48, 64]))


def pos_b64_wrapped_secret(rnd):
    # A real provider key, base64-wrapped: decodes to printable ASCII (no magic,
    # not protobuf) so decode-feature stays 0 and the model must keep it.
    inner = rnd.choice([pos_github_pat, pos_stripe, pos_openai, pos_aws_secret])(rnd)
    return base64.b64encode(inner.encode()).decode()


POSITIVE_GENS = [
    ("aws-access-key", pos_aws_access_key, 8),
    ("aws-secret", pos_aws_secret, 8),
    ("github-pat", pos_github_pat, 8),
    ("slack-bot", pos_slack_bot, 6),
    ("stripe", pos_stripe, 6),
    ("openai", pos_openai, 6),
    ("generic-high-entropy", pos_generic_highentropy, 14),
    ("hex-key", pos_hex_key, 8),
    ("b64-wrapped-secret", pos_b64_wrapped_secret, 6),
]


# ── negatives: false-positive shapes ───────────────────────────────────────

def neg_uuid(rnd):
    return f"{_rc(rnd, HEX, 8)}-{_rc(rnd, HEX, 4)}-4{_rc(rnd, HEX, 3)}-{rnd.choice('89ab')}{_rc(rnd, HEX, 3)}-{_rc(rnd, HEX, 12)}"


def neg_sha256(rnd):
    return _rc(rnd, HEX, 64)


def neg_sha1(rnd):
    return _rc(rnd, HEX, 40)


def neg_md5(rnd):
    # 32-char hex: the ambiguous length that collides with a 32-hex "key".
    # Disambiguated only by context (hash/checksum vs encryption_key).
    return _rc(rnd, HEX, 32)


def neg_crc_or_short_hex(rnd):
    # short/medium hex digests (etag, crc, truncated sha) that are not secrets
    return _rc(rnd, HEX, rnd.choice([16, 20, 24, 28]))


def neg_npm_integrity(rnd):
    return "sha512-" + _rc(rnd, B64, 86) + "=="


def neg_placeholder(rnd):
    return rnd.choice([
        "YOUR_API_KEY_HERE", "<your-token>", "INSERT_TOKEN_HERE", "changeme",
        "REPLACE_WITH_YOUR_KEY", "xxxxxxxxxxxxxxxxxxxx", "TODO_SET_THIS",
    ])


def neg_docs_example(rnd):
    # Prefixes assembled from fragments so this source file never contains a
    # full recognizable token literal (keeps GitHub push-protection and
    # keyhog's own dogfood scan clean). Runtime values are unchanged.
    gh = "gh" + "p_"
    ak = "AK" + "IA"
    sk = "sk" + "_live_"
    xo = "xo" + "xb-"
    return rnd.choice([
        gh + "EXAMPLE0000000000000000000000000000",
        ak + "EXAMPLEEXAMPLE12",
        sk + "EXAMPLE_NOT_A_REAL_KEY_000000",
        xo + "0000000000-0000000000000-EXAMPLEEXAMPLEEXAMPLEEXAM",
    ])


def neg_license_key(rnd):
    return "-".join(_rc(rnd, string.ascii_uppercase + string.digits, 5) for _ in range(5))


def neg_aws_arn(rnd):
    return f"arn:aws:iam::{_rc(rnd, string.digits, 12)}:role/{rnd.choice(['Admin', 'Reader'])}Role"


def neg_docker_digest(rnd):
    return f"nginx@sha256:{_rc(rnd, HEX, 64)}"


def neg_identifier(rnd):
    parts = [rnd.choice(["get", "set", "make", "build", "handle", "parse", "render"]),
             rnd.choice(["user", "config", "request", "token", "buffer", "session"]),
             rnd.choice(["value", "string", "handler", "context", "manager"])]
    return "_".join(parts)


def neg_version(rnd):
    return ".".join(str(rnd.randint(0, 99)) for _ in range(rnd.choice([3, 4])))


def neg_bare_token(rnd):
    # A random high-entropy base62 token with NO secret keyword: a session id,
    # request id, nonce, cache key, content hash slug. This is the dominant
    # real-world false positive for an entropy scanner and the exact shape of
    # the mirror's "lorem-with-high-entropy" negative. Labelled negative and
    # placed in neutral / prose context so the model learns that high entropy
    # WITHOUT an anchor is not a credential.
    return _rc(rnd, B62, rnd.randint(22, 44))


def neg_prose_token(rnd):
    # Same token, but the "context" embeds it in prose (the mirror shape).
    return _rc(rnd, B62, rnd.randint(24, 48))


def neg_jwt_rfc(rnd):
    # RFC 7519 specimen JWT, signature split so the full token is not a source
    # literal (it is a famous public example that secret scanners flag).
    return (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        + "SflKxwRJSMeKKF2QT4" + "fwpMeJf36POk6yJV_adQssw5c"
    )


# binary container generators -> base64 (decode-feature MUST fire) ──────────

def _real_protobuf(rnd) -> bytes:
    # Build a valid multi-field wire message that parse_protobuf_wire accepts:
    # >=3 fields, whole buffer consumed, valid wire types.
    out = bytearray()
    nfields = rnd.randint(3, 6)
    for fno in range(1, nfields + 1):
        wire = rnd.choice([0, 2, 5])
        out.append((fno << 3) | wire)
        if wire == 0:
            v = rnd.randint(0, 300)
            while True:
                b = v & 0x7F
                v >>= 7
                if v:
                    out.append(b | 0x80)
                else:
                    out.append(b)
                    break
        elif wire == 2:
            ln = rnd.randint(2, 10)
            out.append(ln)
            out.extend(rnd.randint(0, 255) for _ in range(ln))
        elif wire == 5:
            out.extend(rnd.randint(0, 255) for _ in range(4))
    return bytes(out)


_MAGIC_HEADERS = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff\xe0",
    "gif": b"GIF89a",
    "gzip": b"\x1f\x8b\x08\x00",
    "zlib": b"\x78\x9c",
    "zip": b"PK\x03\x04",
    "pdf": b"%PDF-1.5\n",
    "elf": b"\x7fELF\x02\x01\x01\x00",
    "wasm": b"\x00asm\x01\x00\x00\x00",
}


def make_binary_negative(rnd) -> str:
    kind = rnd.choice(list(_MAGIC_HEADERS.keys()) + ["protobuf"])
    if kind == "protobuf":
        blob = _real_protobuf(rnd)
    else:
        blob = _MAGIC_HEADERS[kind] + bytes(rnd.randint(0, 255) for _ in range(rnd.randint(16, 80)))
    return base64.b64encode(blob).decode()


NEGATIVE_GENS = [
    ("uuid", neg_uuid, 8),
    ("sha256", neg_sha256, 7),
    ("sha1", neg_sha1, 5),
    ("md5", neg_md5, 7),
    ("short-hex", neg_crc_or_short_hex, 4),
    ("npm-integrity", neg_npm_integrity, 5),
    ("placeholder", neg_placeholder, 6),
    ("docs-example", neg_docs_example, 6),
    ("license-key", neg_license_key, 4),
    ("aws-arn", neg_aws_arn, 3),
    ("docker-digest", neg_docker_digest, 4),
    ("identifier", neg_identifier, 6),
    ("version", neg_version, 3),
    ("jwt-rfc", neg_jwt_rfc, 2),
    ("bare-token", neg_bare_token, 14),
    ("prose-token", neg_prose_token, 8),
]

# Hex-shaped negatives: bare hash/digest values. Placed in hash/checksum
# contexts (no secret keyword) so the model learns hex is a credential ONLY
# under a secret keyword, not by shape alone.
HEX_NEGATIVE_KINDS = {"sha256", "sha1", "md5", "short-hex", "git-commit"}

# Random high-entropy tokens with NO anchor. Must never sit under a secret
# keyword in training: the whole point is to teach "entropy alone != secret".
BARE_TOKEN_KINDS = {"bare-token"}

# Prose-embedded random tokens (the mirror's lorem-with-high-entropy shape).
PROSE_CONTEXTS = [
    "Session opened with handle {}. See the docs for details.",
    "// request_id={} (trace only, not a credential)",
    "Cache miss for object {}, recomputing.",
    "Generated nonce {} for this render pass.",
    "Job {} queued; status will update shortly.",
]
PROSE_TOKEN_KINDS = {"prose-token"}


def _fmt(template: str, cred: str) -> str:
    try:
        return template.format(cred)
    except (IndexError, KeyError):
        return template.replace("{}", cred)


def _wrap_context(rnd: random.Random, cred: str, secret_kw: bool) -> str:
    pool = SECRET_KW_CONTEXTS if secret_kw else NEUTRAL_CONTEXTS
    if rnd.random() < 0.15:
        pool = FILE_HINT_CONTEXTS
    return _fmt(rnd.choice(pool), cred)


def _hash_context(rnd: random.Random, cred: str) -> str:
    # 80% genuine hash/checksum context, 20% adversarially under a secret
    # keyword (teaches that even `secret = <sha256>` is still a hash by shape +
    # the absence of any real credential structure).
    if rnd.random() < 0.8:
        return _fmt(rnd.choice(HASH_CONTEXTS), cred)
    return _wrap_context(rnd, cred, secret_kw=True)


def generate(n_per_unit: int, seed: int) -> list[dict]:
    rnd = random.Random(seed)
    records: list[dict] = []

    # positives
    for kind, gen, weight in POSITIVE_GENS:
        for _ in range(n_per_unit * weight):
            cred = gen(rnd)
            # A bare high-entropy / hex string is a secret ONLY under a secret
            # keyword (otherwise it is indistinguishable from a random session
            # token / digest), so those always carry one. Provider-prefixed
            # tokens (ghp_, AKIA, sk_live_) self-anchor, so 80% keyword is fine.
            kw_prob = 1.0 if kind in ("hex-key", "generic-high-entropy") else 0.8
            ctx = _wrap_context(rnd, cred, secret_kw=rnd.random() < kw_prob)
            records.append({"text": cred, "context": ctx, "label": 1, "kind": kind})

    # standard negatives
    for kind, gen, weight in NEGATIVE_GENS:
        for _ in range(n_per_unit * weight):
            cred = gen(rnd)
            if kind in HEX_NEGATIVE_KINDS:
                ctx = _hash_context(rnd, cred)
            elif kind in BARE_TOKEN_KINDS:
                # Neutral context only - high entropy with no keyword anchor.
                ctx = _fmt(rnd.choice(NEUTRAL_CONTEXTS), cred)
            elif kind in PROSE_TOKEN_KINDS:
                ctx = _fmt(rnd.choice(PROSE_CONTEXTS), cred)
            else:
                # ~40% adversarially placed under a secret keyword
                ctx = _wrap_context(rnd, cred, secret_kw=rnd.random() < 0.4)
            records.append({"text": cred, "context": ctx, "label": 0, "kind": kind})

    # base64-of-binary negatives (the decode-feature teacher). Heavy weight, and
    # HALF placed under a secret keyword so the model cannot lean on context
    # alone: it must use the decode-structure feature to reject them.
    binary_weight = 30
    for _ in range(n_per_unit * binary_weight):
        cred = make_binary_negative(rnd)
        ctx = _wrap_context(rnd, cred, secret_kw=rnd.random() < 0.5)
        records.append({"text": cred, "context": ctx, "label": 0, "kind": "base64-binary"})

    rnd.shuffle(records)
    return records


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="ml/data/corpus.jsonl")
    ap.add_argument("--n", type=int, default=120, help="samples per weight unit")
    ap.add_argument("--seed", type=int, default=20260529)
    args = ap.parse_args()

    records = generate(args.n, args.seed)
    import os
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")

    pos = sum(1 for r in records if r["label"] == 1)
    neg = len(records) - pos
    binc = sum(1 for r in records if r["kind"] == "base64-binary")
    sys.stderr.write(
        f"wrote {len(records)} records to {args.out}: {pos} pos / {neg} neg "
        f"({binc} base64-binary negatives)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
