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


def _render_phase(
    phase: int,
    *,
    seed: int,
    sample: int,
    secret: str,
    xor_data: list[int],
    xor_key: list[int],
    aes_key: str,
    aes_iv: str,
    aes_ciphertext: str,
) -> str:
    ident = tuple(_ident(seed, sample, slot) for slot in range(8))
    if phase == 0:
        return _base_program(json.dumps(secret))
    if phase == 1:
        encoded = base64.b64encode(secret.encode()).decode()
        return _base_program(
            f"Buffer.from({json.dumps(encoded)}, 'base64').toString('utf8')"
        )
    if phase == 2:
        return _base_program(json.dumps(secret), variable=ident[0])
    if phase == 3:
        return _base_program(json.dumps(secret), prefix=_dead_code(seed, sample))
    if phase == 4:
        parts = [secret[:4], secret[4:16], secret[16:28], secret[28:]]
        expression = (
            f"(() => {{ const {ident[0]} = {json.dumps(parts)}; "
            f"return {ident[0]}.join(''); }})()"
        )
        return _base_program(expression, variable=ident[1])
    if phase == 5:
        return _base_program(_xor_expression(xor_data, xor_key))
    if phase == 6:
        return _base_program(
            _aes_expression(aes_key, aes_iv, aes_ciphertext, ("key", "iv", "payload"))
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
            _xor_expression(xor_data, xor_key), prefix=_dead_code(seed, sample)
        )
    if phase == 10:
        return _base_program(
            _aes_expression(aes_key, aes_iv, aes_ciphertext, ("key", "iv", "payload")),
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


def generate(out: pathlib.Path, samples: int, seed: int) -> None:
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
        secrets = [_secret(seed, sample) for sample in range(samples)]
        aes_rows = _aes_materials(seed, secrets)
        manifest_rows: list[dict[str, object]] = []
        for sample, secret in enumerate(secrets):
            xor_data, xor_key = _xor_material(seed, sample, secret)
            aes_key, aes_iv, aes_ciphertext = aes_rows[sample]
            for phase, transform in PHASES:
                relative = pathlib.Path(f"p{phase:02d}") / f"sample-{sample:04d}.js"
                destination = scan_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = _render_phase(
                    phase,
                    seed=seed,
                    sample=sample,
                    secret=secret,
                    xor_data=xor_data,
                    xor_key=xor_key,
                    aes_key=aes_key,
                    aes_iv=aes_iv,
                    aes_ciphertext=aes_ciphertext,
                )
                destination.write_text(source, encoding="utf-8")
                manifest_rows.append(
                    {
                        "id": f"ioc-recovery-p{phase:02d}-{sample:04d}",
                        "secret": secret,
                        "label": True,
                        "category": f"recovery/p{phase:02d}-{transform}",
                        "on_disk_path": relative.as_posix(),
                        "start_line": 0,
                        "end_line": 0,
                        "match_mode": "exact",
                        "phase": phase,
                        "transform": transform,
                        "source_id": f"synthetic-js-{sample:04d}",
                        "seed": seed,
                        "key_material_embedded": phase >= 5,
                    }
                )
        manifest = staging / "manifest.jsonl"
        manifest.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in manifest_rows),
            encoding="utf-8",
        )
        metadata = {
            "schema_version": 2,
            "name": "keyhog-ioc-recovery",
            "methodology": "P0-P12 adapted to synthetic credentials",
            "methodology_title": PAPER_TITLE,
            "methodology_url": PAPER_URL,
            "methodology_license": "CC-BY-4.0",
            "upstream_repository_url": UPSTREAM_REPOSITORY_URL,
            "upstream_repository_commit": UPSTREAM_REPOSITORY_COMMIT,
            "upstream_public_example_count": UPSTREAM_PUBLIC_EXAMPLE_COUNT,
            "upstream_evaluation_corpus_published": UPSTREAM_EVALUATION_CORPUS_PUBLISHED,
            "artifact_relationship": "methodology-adaptation",
            "credential_shape": "checksum-valid synthetic GitHub classic PAT",
            "match_mode": "exact",
            "samples": samples,
            "phases": len(PHASES),
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
    args = parser.parse_args()
    generate(args.out, args.samples, args.seed)
    print(
        f"generated {args.samples * len(PHASES)} recovery fixtures at {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
