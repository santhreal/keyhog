#!/usr/bin/env python3
"""Generate KeyHog's paper-compatible deterministic recovery corpus.

The generated scan tree follows the P0-P12 progression described in
arXiv:2605.06910, but uses synthetic GitHub-shaped credentials instead of
network IoCs. That keeps the task inside KeyHog's product contract: recover a
concealed credential value, then run the normal detector pipeline over the
recovered plaintext.

The answer key lives beside ``corpus/`` and is never shown to scanners.
AES fixtures are produced and round-trip verified with Node's standard
``crypto`` module, the same runtime used by the generated JavaScript decryptor.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import pathlib
import random
import signal
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from bench.corpus_integrity import file_sha256, tree_sha256  # noqa: E402
from bench.generator_checksums import crc32_base62  # noqa: E402
from bench.ioc_recovery_provenance import (  # noqa: E402
    PAPER_ARXIV_ID,
    PAPER_PDF_BYTES,
    PAPER_PDF_SHA256,
    PAPER_PDF_URL,
    PAPER_REVISION,
    PAPER_TITLE,
    PAPER_URL,
    UPSTREAM_EVALUATION_CORPUS_PUBLISHED,
    UPSTREAM_PUBLIC_EXAMPLE_COUNT,
    UPSTREAM_REPOSITORY_COMMIT,
    UPSTREAM_REPOSITORY_URL,
)

PHASES: tuple[tuple[int, str], ...] = (
    (0, "plaintext"),
    (1, "base64"),
    (2, "identifier-obfuscation"),
    (3, "dead-code"),
    (4, "structural-obfuscation"),
    (5, "xor"),
    (6, "aes-256-cbc"),
    (7, "xor-simple-obfuscation"),
    (8, "aes-simple-obfuscation"),
    (9, "xor-dead-code"),
    (10, "aes-dead-code"),
    (11, "xor-structural-obfuscation"),
    (12, "aes-structural-obfuscation"),
)

# Recovery is only interesting if the recovered plaintext is then detected, and
# detection behaves very differently across credential families. A corpus built
# from one family measures one detector's interaction with the decoder and
# reports it as "recovery works".
#
# Each family declares how to build a positive value, how to build a matched
# NEGATIVE of the same shape that must never be reported, and the assignment
# context the family needs to be recognized at all (a contextual family has no
# prefix to anchor on, so the surrounding variable name carries the keyword).
FAMILIES: tuple[dict[str, object], ...] = (
    {
        "name": "checksum",
        "detector_family": "github-classic-pat",
        "variable": "recovered",
        # 30 entropy characters plus the six-character base62 CRC32 suffix
        # KeyHog's production validator enforces. A valid checksum is not
        # authentication; the value is deterministic and synthetic.
        "positive": lambda body: "ghp_" + body[:30] + crc32_base62(body[:30]),
        # Same prefix and length, deliberately WRONG checksum: the validator
        # must reject it, so recovering it must not produce a finding.
        "negative": lambda body: "ghp_" + body[:30] + crc32_base62(body[1:31]),
    },
    {
        "name": "fixed-prefix",
        "detector_family": "stripe-secret-key",
        "variable": "recovered",
        "positive": lambda body: "sk_live_" + body[:32],
        # Placeholder body: a degenerate repeat the suppression stage rejects.
        "negative": lambda body: "sk_live_" + "X" * 32,
    },
    {
        "name": "contextual",
        "detector_family": "aws-secret-access-key",
        # No literal prefix exists for this family, so the keyword has to come
        # from the assignment the recovered value lands in.
        "variable": "AWS_SECRET_ACCESS_KEY",
        "positive": lambda body: (body[:20] + body[20:40].upper()).replace("0", "/")[:40],
        "negative": lambda body: "EXAMPLEKEY" * 4,
    },
    {
        "name": "hex",
        "detector_family": "generic-hex-token",
        "variable": "api_secret_key",
        "positive": lambda body: body[:64],
        "negative": lambda body: "deadbeef" * 8,
    },
    {
        "name": "url",
        "detector_family": "postgresql-connection-string",
        "variable": "DATABASE_URL",
        "positive": lambda body: f"postgresql://svc_{body[:8]}:{body[8:32]}@db.internal",
        "negative": lambda body: "postgresql://user:password@localhost:5432/postgres",
    },
    {
        "name": "jwt-like",
        "detector_family": "jwt-token",
        "variable": "session_token",
        "positive": lambda body: _jwt_like(body),
        "negative": lambda body: "eyJ" + "A" * 20 + "." + "B" * 20 + "." + "C" * 20,
    },
)


def _jwt_like(body: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = (
        base64.urlsafe_b64encode(
            f'{{"sub":"{body[:12]}","iss":"keyhog-recovery","exp":2000000000}}'.encode()
        )
        .decode()
        .rstrip("=")
    )
    signature = base64.urlsafe_b64encode(bytes.fromhex(body[:64])).decode().rstrip("=")
    return f"{header}.{payload}.{signature}"


# Independently generated variants of the SUPPORTED mechanisms. The primary
# phases emit exactly the statement shapes the decoder recognizes, so a green
# result there proves the decoder handles its own templates and nothing more.
# These spell the same semantics differently at the AST level, so recovery has
# to follow the meaning rather than the template.
HOLDOUT_VARIANTS: tuple[tuple[str, str], ...] = (
    ("let-binding", "the binding is `let`, not `const`"),
    ("var-binding", "the binding is `var`, not `const`"),
    ("from-code-point", "String.fromCodePoint instead of String.fromCharCode"),
    ("template-literal", "the concatenation is a template literal, not join('')"),
    ("index-access", "the parts are read by index instead of joined"),
)

# Semantic mutations of the same programs whose value is NOT statically
# determined. Recovery must produce nothing; a recovered value here is a
# fabricated finding, which is worse than a miss.
METAMORPHIC_VARIANTS: tuple[tuple[str, str], ...] = (
    ("env-key", "the XOR key comes from process.env and is unknown statically"),
    ("argv-part", "one concatenated part comes from process.argv"),
    ("date-branch", "the value depends on a runtime date comparison"),
)

NODE_AES_TIMEOUT_SECONDS = 30
NODE_AES_REAP_SECONDS = 5

_NODE_AES = r"""
const crypto = require('crypto');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', () => {
  const rows = JSON.parse(input);
  const output = rows.map(row => {
    const key = Buffer.from(row.key, 'hex');
    const iv = Buffer.from(row.iv, 'hex');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([
      cipher.update(row.plaintext, 'utf8'),
      cipher.final(),
    ]).toString('base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const recovered = Buffer.concat([
      decipher.update(Buffer.from(encrypted, 'base64')),
      decipher.final(),
    ]).toString('utf8');
    if (recovered !== row.plaintext) throw new Error('AES round-trip mismatch');
    return encrypted;
  });
  process.stdout.write(JSON.stringify(output));
});
"""


def _digest(seed: int, sample: int, purpose: str) -> bytes:
    return hashlib.sha256(f"{seed}:{sample}:{purpose}".encode()).digest()


def _secret(seed: int, sample: int) -> str:
    # GitHub classic PAT contract: 30 entropy characters plus the six-character
    # base62 CRC32 suffix enforced by KeyHog's production validator. The value
    # is deterministic and synthetic; a valid checksum is not authentication.
    entropy = hashlib.sha256(
        f"keyhog-recovery:{seed}:{sample}".encode()
    ).hexdigest()[:30]
    return "ghp_" + entropy + crc32_base62(entropy)


def _family_body(family: str, seed: int, sample: int, polarity: str) -> str:
    """Deterministic hex entropy the family builders slice for their shape."""
    return hashlib.sha256(
        f"keyhog-recovery:{family}:{polarity}:{seed}:{sample}".encode()
    ).hexdigest()


def _family_value(family: dict[str, object], seed: int, sample: int, polarity: str) -> str:
    build = family["positive" if polarity == "positive" else "negative"]
    return build(_family_body(str(family["name"]), seed, sample, polarity))  # type: ignore[operator]


def _certificate(value: str) -> str:
    """Value identity for the certificate scoring axis (KH-546)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ident(seed: int, sample: int, slot: int) -> str:
    return "_" + hashlib.sha256(
        f"ident:{seed}:{sample}:{slot}".encode()
    ).hexdigest()[:12]


def _xor_material(seed: int, sample: int, plaintext: str) -> tuple[list[int], list[int]]:
    key = list(_digest(seed, sample, "xor-key")[:8])
    data = [byte ^ key[index % len(key)] for index, byte in enumerate(plaintext.encode())]
    recovered = bytes(
        byte ^ key[index % len(key)] for index, byte in enumerate(data)
    ).decode()
    if recovered != plaintext:
        raise RuntimeError(f"XOR round-trip failed for sample {sample}")
    return data, key


def _aes_materials(seed: int, secrets: list[str]) -> list[tuple[str, str, str]]:
    node = shutil.which("node")
    if node is None:
        raise SystemExit(
            "IoC-recovery AES generation requires Node.js (standard crypto module); "
            "install Node and rerun the corpus generator"
        )
    rows = []
    keys: list[tuple[str, str]] = []
    for sample, secret in enumerate(secrets):
        key = _digest(seed, sample, "aes-key").hex()
        iv = _digest(seed, sample, "aes-iv")[:16].hex()
        rows.append({"plaintext": secret, "key": key, "iv": iv})
        keys.append((key, iv))
    process = subprocess.Popen(
        [node, "-e", _NODE_AES],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=os.name == "posix",
    )
    try:
        stdout, stderr = process.communicate(
            json.dumps(rows), timeout=NODE_AES_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired as exc:
        _terminate_process(process)
        raise SystemExit(
            f"Node AES generation exceeded {NODE_AES_TIMEOUT_SECONDS}s and was terminated"
        ) from exc
    if process.returncode != 0:
        detail = stderr.strip() or stdout.strip()
        raise SystemExit(f"Node AES generation failed: {detail}")
    try:
        ciphertexts = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Node AES generation returned invalid JSON: {exc}") from exc
    if not isinstance(ciphertexts, list):
        raise SystemExit(
            "Node AES generation returned a JSON value that is not an array"
        )
    if len(ciphertexts) != len(secrets):
        raise SystemExit(
            f"Node AES generation returned {len(ciphertexts)} rows for {len(secrets)} samples"
        )
    for index, ciphertext in enumerate(ciphertexts):
        if not isinstance(ciphertext, str) or not ciphertext:
            raise SystemExit(
                f"Node AES generation row {index} is not a non-empty Base64 string"
            )
        try:
            raw = base64.b64decode(ciphertext, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise SystemExit(
                f"Node AES generation row {index} is not canonical Base64"
            ) from exc
        if base64.b64encode(raw).decode("ascii") != ciphertext:
            raise SystemExit(
                f"Node AES generation row {index} is not canonical Base64"
            )
        expected_bytes = (len(secrets[index].encode("utf-8")) // 16 + 1) * 16
        if len(raw) != expected_bytes:
            raise SystemExit(
                f"Node AES generation row {index} is not canonical AES-CBC ciphertext"
            )
    return [(*keys[index], ciphertext) for index, ciphertext in enumerate(ciphertexts)]


def _terminate_process(process: subprocess.Popen, *, posix: bool | None = None) -> None:
    """Bound termination and reap even when a detached child retains pipes."""
    use_process_group = os.name == "posix" if posix is None else posix
    try:
        if use_process_group:
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass

    # Never call unbounded communicate() here. A descendant that escaped the
    # process group can retain stdout/stderr and prevent EOF forever. Closing
    # our pipe endpoints makes generator progress independent of that process.
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            stream.close()
    try:
        process.wait(timeout=NODE_AES_REAP_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=NODE_AES_REAP_SECONDS)


def _dead_code(seed: int, sample: int) -> str:
    rng = random.Random((seed << 16) ^ sample)
    values = [rng.randrange(10_000, 99_999) for _ in range(4)]
    return (
        f"function unused_{values[0]}(x) {{ return (x * {values[1]}) % {values[2]}; }}\n"
        f"if (false) {{ console.log(unused_{values[0]}({values[3]})); }}\n"
    )


def _base_program(expression: str, variable: str = "recovered", prefix: str = "") -> str:
    return (
        "'use strict';\n"
        f"{prefix}"
        f"const {variable} = {expression};\n"
        f"if (require.main === module) process.stdout.write({variable});\n"
        f"module.exports = {variable};\n"
    )


def _xor_expression(
    data: list[int],
    key: list[int],
    names: tuple[str, str] = ("data", "key"),
) -> str:
    data_name, key_name = names
    return (
        f"(() => {{ const {data_name} = {json.dumps(data)}; "
        f"const {key_name} = {json.dumps(key)}; "
        f"return String.fromCharCode(...{data_name}.map((b, i) => "
        f"b ^ {key_name}[i % {key_name}.length])); }})()"
    )


def _aes_expression(key: str, iv: str, ciphertext: str, names: tuple[str, str, str]) -> str:
    key_name, iv_name, ciphertext_name = names
    return (
        "(() => { const crypto = require('crypto'); "
        f"const {key_name} = Buffer.from({json.dumps(key)}, 'hex'); "
        f"const {iv_name} = Buffer.from({json.dumps(iv)}, 'hex'); "
        f"const {ciphertext_name} = Buffer.from({json.dumps(ciphertext)}, 'base64'); "
        f"const decipher = crypto.createDecipheriv('aes-256-cbc', {key_name}, {iv_name}); "
        f"return Buffer.concat([decipher.update({ciphertext_name}), "
        "decipher.final()]).toString('utf8'); })()"
    )


def _render_holdout(
    variant: str,
    *,
    seed: int,
    sample: int,
    value: str,
    variable: str,
    xor_data: list[int],
    xor_key: list[int],
) -> str:
    """Spell a SUPPORTED mechanism differently at the AST level.

    Same semantics, different statement shape. Recovery has to follow meaning
    rather than the exact template the primary phases emit.
    """
    ident = tuple(_ident(seed, sample, slot) for slot in range(4))
    parts = [value[i : i + 8] for i in range(0, len(value), 8)]
    if variant == "let-binding":
        body = _xor_expression(xor_data, xor_key)
        return f"'use strict';\nlet {variable} = {body};\nmodule.exports = {variable};\n"
    if variant == "var-binding":
        body = _xor_expression(xor_data, xor_key)
        return f"'use strict';\nvar {variable} = {body};\nmodule.exports = {variable};\n"
    if variant == "from-code-point":
        expression = (
            f"(() => {{ const {ident[0]} = {json.dumps(xor_data)}; "
            f"const {ident[1]} = {json.dumps(xor_key)}; "
            f"return String.fromCodePoint(...{ident[0]}.map((b, i) => "
            f"b ^ {ident[1]}[i % {ident[1]}.length])); }})()"
        )
        return _base_program(expression, variable=variable)
    if variant == "template-literal":
        joined = "".join("${" + f"{ident[0]}[{index}]" + "}" for index in range(len(parts)))
        expression = (
            f"(() => {{ const {ident[0]} = {json.dumps(parts)}; "
            f"return `{joined}`; }})()"
        )
        return _base_program(expression, variable=variable)
    if variant == "index-access":
        reads = " + ".join(f"{ident[0]}[{index}]" for index in range(len(parts)))
        expression = f"(() => {{ const {ident[0]} = {json.dumps(parts)}; return {reads}; }})()"
        return _base_program(expression, variable=variable)
    raise ValueError(f"unsupported holdout variant {variant!r}")


def _render_metamorphic(
    variant: str,
    *,
    seed: int,
    sample: int,
    value: str,
    variable: str,
    xor_data: list[int],
    xor_key: list[int],
) -> str:
    """Break static determinacy while keeping the surrounding program identical.

    Nothing here is statically recoverable, so any reported value is fabricated.
    """
    ident = tuple(_ident(seed, sample, slot) for slot in range(4))
    parts = [value[i : i + 8] for i in range(0, len(value), 8)]
    if variant == "env-key":
        expression = (
            f"(() => {{ const {ident[0]} = {json.dumps(xor_data)}; "
            f"const {ident[1]} = Buffer.from(process.env.KEYHOG_XOR_KEY || '', 'hex'); "
            f"return String.fromCharCode(...{ident[0]}.map((b, i) => "
            f"b ^ {ident[1]}[i % {ident[1]}.length])); }})()"
        )
        return _base_program(expression, variable=variable)
    if variant == "argv-part":
        head = parts[:-1]
        expression = (
            f"(() => {{ const {ident[0]} = {json.dumps(head)}; "
            f"return {ident[0]}.join('') + (process.argv[2] || ''); }})()"
        )
        return _base_program(expression, variable=variable)
    if variant == "date-branch":
        expression = (
            f"(() => {{ const {ident[0]} = {json.dumps(parts)}; "
            f"return Date.now() % 2 === 0 ? {ident[0]}.join('') : "
            f"{ident[0]}.reverse().join(''); }})()"
        )
        return _base_program(expression, variable=variable)
    raise ValueError(f"unsupported metamorphic variant {variant!r}")


def _render_phase(
    phase: int,
    *,
    seed: int,
    sample: int,
    secret: str,
    variable: str = "recovered",
    xor_data: list[int],
    xor_key: list[int],
    aes_key: str,
    aes_iv: str,
    aes_ciphertext: str,
) -> str:
    ident = tuple(_ident(seed, sample, slot) for slot in range(8))
    if phase == 0:
        return _base_program(json.dumps(secret), variable=variable)
    if phase == 1:
        encoded = base64.b64encode(secret.encode()).decode()
        return _base_program(
            f"Buffer.from({json.dumps(encoded)}, 'base64').toString('utf8')",
            variable=variable,
        )
    if phase == 2:
        return _base_program(json.dumps(secret), variable=ident[0])
    if phase == 3:
        return _base_program(
            json.dumps(secret), variable=variable, prefix=_dead_code(seed, sample)
        )
    if phase == 4:
        parts = [secret[:4], secret[4:16], secret[16:28], secret[28:]]
        expression = (
            f"(() => {{ const {ident[0]} = {json.dumps(parts)}; "
            f"return {ident[0]}.join(''); }})()"
        )
        return _base_program(expression, variable=ident[1])
    if phase == 5:
        return _base_program(_xor_expression(xor_data, xor_key), variable=variable)
    if phase == 6:
        return _base_program(
            _aes_expression(aes_key, aes_iv, aes_ciphertext, ("key", "iv", "payload")),
            variable=variable,
        )
    if phase == 7:
        return _base_program(
            _xor_expression(xor_data, xor_key, (ident[0], ident[1])), variable=ident[2]
        )
    if phase == 8:
        return _base_program(
            _aes_expression(aes_key, aes_iv, aes_ciphertext, ident[0:3]),
            variable=ident[3],
        )
    if phase == 9:
        return _base_program(
            _xor_expression(xor_data, xor_key),
            variable=variable,
            prefix=_dead_code(seed, sample),
        )
    if phase == 10:
        return _base_program(
            _aes_expression(aes_key, aes_iv, aes_ciphertext, ("key", "iv", "payload")),
            variable=variable,
            prefix=_dead_code(seed, sample),
        )
    if phase == 11:
        data_blob = base64.b64encode(json.dumps(xor_data).encode()).decode()
        key_blob = base64.b64encode(json.dumps(xor_key).encode()).decode()
        expression = (
            f"(() => {{ const {ident[0]} = JSON.parse(Buffer.from({json.dumps(data_blob)}, "
            f"'base64').toString('utf8')); const {ident[1]} = JSON.parse(Buffer.from("
            f"{json.dumps(key_blob)}, 'base64').toString('utf8')); return String.fromCharCode("
            f"...{ident[0]}.map((b, i) => b ^ {ident[1]}[i % {ident[1]}.length])); }})()"
        )
        return _base_program(expression, variable=ident[2])
    if phase == 12:
        key_parts = [aes_key[:32], aes_key[32:]]
        ciphertext_parts = [aes_ciphertext[:24], aes_ciphertext[24:]]
        expression = (
            f"(() => {{ const crypto = require('crypto'); const {ident[0]} = "
            f"{json.dumps(key_parts)}.join(''); const {ident[1]} = "
            f"{json.dumps(ciphertext_parts)}.join(''); const {ident[2]} = "
            f"crypto.createDecipheriv('aes-256-cbc', Buffer.from({ident[0]}, 'hex'), "
            f"Buffer.from({json.dumps(aes_iv)}, 'hex')); return Buffer.concat(["
            f"{ident[2]}.update(Buffer.from({ident[1]}, 'base64')), "
            f"{ident[2]}.final()]).toString('utf8'); }})()"
        )
        return _base_program(expression, variable=ident[3])
    raise ValueError(f"unsupported recovery phase {phase}")


def _manifest_row(
    *,
    kind: str,
    variant: str,
    phase: int,
    family: str,
    detector_family: str,
    polarity: str,
    positive: bool,
    value: str,
    relative: pathlib.Path,
    source: str,
    sample: int,
    seed: int,
    mechanism: str,
) -> dict[str, object]:
    """One ground-truth row with every axis scored independently.

    Value alone is a weak target: a recovery that returns the right bytes from
    the wrong expression, attributed to the wrong detector, is not the same
    result. `detector_family`, `start_line`/`end_line`, `mechanism`, and
    `certificate` are separate exact axes, so mutating any one of them fails
    the target on its own.
    """
    lines = source.splitlines()
    assignment = next(
        (index for index, line in enumerate(lines, start=1) if "=" in line and "'use strict'" not in line),
        1,
    )
    return {
        "id": f"ioc-recovery-{kind}-{variant}-{family}-{polarity}-{sample:04d}",
        # A negative has no recoverable credential. The scorer reads `None` as
        # "any observation here is a false recovery".
        "secret": value if positive else None,
        "label": positive,
        "category": f"recovery/{kind}/{variant}/{family}",
        "on_disk_path": relative.as_posix(),
        "start_line": assignment,
        "end_line": assignment,
        "match_mode": "exact",
        "phase": phase,
        "transform": variant,
        "kind": kind,
        "family": family,
        "detector_family": detector_family,
        "polarity": polarity,
        "mechanism": mechanism,
        "certificate": _certificate(value) if positive else None,
        "source_id": f"synthetic-js-{family}-{sample:04d}",
        "seed": seed,
        "key_material_embedded": phase >= 5,
    }


def generate(
    out: pathlib.Path,
    samples: int,
    seed: int,
    *,
    families: tuple[dict[str, object], ...] = FAMILIES,
    holdout: bool = True,
) -> None:
    if samples < 1 or samples > 10_000:
        raise SystemExit("--samples must be between 1 and 10000")
    if out.exists():
        raise SystemExit(
            f"output already exists: {out}; remove the generated corpus "
            "explicitly before regenerating"
        )
    out.parent.mkdir(parents=True, exist_ok=True)
    # Stage beside the official corpus path, never in the system temporary
    # directory, so the final rename is atomic on the same filesystem.
    staging = pathlib.Path(tempfile.mkdtemp(prefix=f".{out.name}-", dir=out.parent))
    try:
        scan_root = staging / "corpus"
        manifest_rows: list[dict[str, object]] = []

        # Every (family, polarity) pair needs its own AES material, so collect
        # the plaintexts first and encrypt them in one Node round trip.
        plan: list[tuple[dict[str, object], str, int, str]] = []
        for family in families:
            for polarity in ("positive", "negative"):
                for sample in range(samples):
                    plan.append(
                        (family, polarity, sample, _family_value(family, seed, sample, polarity))
                    )
        aes_rows = _aes_materials(seed, [value for _f, _p, _s, value in plan])

        for index, (family, polarity, sample, value) in enumerate(plan):
            fname = str(family["name"])
            variable = str(family["variable"])
            detector_family = str(family["detector_family"])
            xor_data, xor_key = _xor_material(seed, index, value)
            aes_key, aes_iv, aes_ciphertext = aes_rows[index]
            positive = polarity == "positive"
            stem = f"{fname}-{polarity}-{sample:04d}"

            for phase, transform in PHASES:
                relative = pathlib.Path(f"p{phase:02d}") / f"{stem}.js"
                destination = scan_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = _render_phase(
                    phase,
                    seed=seed,
                    sample=index,
                    secret=value,
                    variable=variable,
                    xor_data=xor_data,
                    xor_key=xor_key,
                    aes_key=aes_key,
                    aes_iv=aes_iv,
                    aes_ciphertext=aes_ciphertext,
                )
                destination.write_text(source, encoding="utf-8")
                manifest_rows.append(
                    _manifest_row(
                        kind="phase",
                        variant=transform,
                        phase=phase,
                        family=fname,
                        detector_family=detector_family,
                        polarity=polarity,
                        positive=positive,
                        value=value,
                        relative=relative,
                        source=source,
                        sample=sample,
                        seed=seed,
                        mechanism=transform,
                    )
                )

            if not holdout or not positive:
                continue

            for variant, rationale in HOLDOUT_VARIANTS:
                relative = pathlib.Path("holdout") / variant / f"{stem}.js"
                destination = scan_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = _render_holdout(
                    variant,
                    seed=seed,
                    sample=index,
                    value=value,
                    variable=variable,
                    xor_data=xor_data,
                    xor_key=xor_key,
                )
                destination.write_text(source, encoding="utf-8")
                manifest_rows.append(
                    _manifest_row(
                        kind="holdout",
                        variant=variant,
                        phase=-1,
                        family=fname,
                        detector_family=detector_family,
                        polarity="positive",
                        positive=True,
                        value=value,
                        relative=relative,
                        source=source,
                        sample=sample,
                        seed=seed,
                        mechanism=rationale,
                    )
                )

            for variant, rationale in METAMORPHIC_VARIANTS:
                relative = pathlib.Path("metamorphic") / variant / f"{stem}.js"
                destination = scan_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = _render_metamorphic(
                    variant,
                    seed=seed,
                    sample=index,
                    value=value,
                    variable=variable,
                    xor_data=xor_data,
                    xor_key=xor_key,
                )
                destination.write_text(source, encoding="utf-8")
                manifest_rows.append(
                    _manifest_row(
                        kind="metamorphic",
                        variant=variant,
                        phase=-2,
                        family=fname,
                        detector_family=detector_family,
                        polarity="negative",
                        positive=False,
                        value=value,
                        relative=relative,
                        source=source,
                        sample=sample,
                        seed=seed,
                        mechanism=rationale,
                    )
                )
        manifest = staging / "manifest.jsonl"
        manifest.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in manifest_rows),
            encoding="utf-8",
        )
        metadata = {
            "schema_version": 4,
            "name": "keyhog-ioc-recovery",
            "methodology": "P0-P12 adapted to synthetic credentials",
            "methodology_title": PAPER_TITLE,
            "methodology_url": PAPER_URL,
            "methodology_arxiv_id": PAPER_ARXIV_ID,
            "methodology_revision": PAPER_REVISION,
            "methodology_pdf_url": PAPER_PDF_URL,
            "methodology_pdf_sha256": PAPER_PDF_SHA256,
            "methodology_pdf_bytes": PAPER_PDF_BYTES,
            "methodology_license": "CC-BY-4.0",
            "upstream_repository_url": UPSTREAM_REPOSITORY_URL,
            "upstream_repository_commit": UPSTREAM_REPOSITORY_COMMIT,
            "upstream_public_example_count": UPSTREAM_PUBLIC_EXAMPLE_COUNT,
            "upstream_evaluation_corpus_published": UPSTREAM_EVALUATION_CORPUS_PUBLISHED,
            "artifact_relationship": "methodology-adaptation",
            "credential_shape": "six synthetic detector families, positive and negative",
            "match_mode": "exact",
            "samples": samples,
            "phases": len(PHASES),
            "families": [str(family["name"]) for family in families],
            "detector_families": [str(family["detector_family"]) for family in families],
            "holdout_variants": [name for name, _why in HOLDOUT_VARIANTS] if holdout else [],
            "metamorphic_variants": [name for name, _why in METAMORPHIC_VARIANTS] if holdout else [],
            "scored_axes": ["value", "detector_family", "span", "mechanism", "certificate"],
            "positives": sum(1 for row in manifest_rows if row["label"]),
            "negatives": sum(1 for row in manifest_rows if not row["label"]),
            "fixtures": len(manifest_rows),
            "seed": seed,
            "scan_tree_sha256": tree_sha256(scan_root),
            "manifest_sha256": file_sha256(manifest),
        }
        (staging / "corpus.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(staging, out)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--samples", type=int, default=336)
    parser.add_argument("--seed", type=int, default=260506910)
    parser.add_argument(
        "--families",
        default="all",
        help="comma-separated family names, or 'all' (default): "
        + ",".join(str(family["name"]) for family in FAMILIES),
    )
    parser.add_argument(
        "--no-holdout",
        action="store_true",
        help="emit only the P0-P12 phases, without the independently generated "
        "AST holdout and the metamorphic no-recovery set",
    )
    args = parser.parse_args()
    if args.families == "all":
        families = FAMILIES
    else:
        wanted = [name.strip() for name in args.families.split(",") if name.strip()]
        known = {str(family["name"]): family for family in FAMILIES}
        missing = [name for name in wanted if name not in known]
        if missing:
            raise SystemExit(
                f"unknown recovery families {missing}; known: {sorted(known)}"
            )
        families = tuple(known[name] for name in wanted)
    generate(
        args.out, args.samples, args.seed, families=families, holdout=not args.no_holdout
    )
    print(f"generated recovery corpus at {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
