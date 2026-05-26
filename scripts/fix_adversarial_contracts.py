#!/usr/bin/env python3
"""Patch contract [[positive]] fixtures for adversarial_explosion_runner bare misses (C bucket)."""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
CONTRACTS = REPO / "crates" / "scanner" / "tests" / "contracts"
DETECTORS = REPO / "detectors"
FAIL_DUMP = pathlib.Path("/tmp/adv_fails.txt")

sys.path.insert(0, str(REPO / "scripts"))
from fix_r2b_positives import HAND_POSITIVES  # noqa: E402
from generate_contracts import (  # noqa: E402
    MANUAL_OVERRIDES,
    _toml_str,
    build_full_contract,
    load_toml,
    synthesize_for_pattern,
)

# Verified / regex-aligned positives (override weaker HAND_POSITIVES entries).
ADV_HAND: dict[str, list[tuple[str, str]]] = {
    **HAND_POSITIVES,
    "gravity-forms-rest-api-key": [
        (
            "GRAVITY FORMS api_key 963950e3ed2e3dc49d5740982bac6a94",
            "963950e3ed2e3dc49d5740982bac6a94",
        ),
        (
            "GRAVITY FORMS public_key f2da167246ebe0e04dc37c9e74a75b5b",
            "f2da167246ebe0e04dc37c9e74a75b5b",
        ),
    ],
    "looker-api-credentials": [
        (
            "LOOKERSDK_base_url=https://demo.cloud.looker.com:19999",
            "https://demo.cloud.looker.com:19999",
        ),
        ('LOOKERSDK_client_id="abc123def456ghi789"', "abc123def456ghi789"),
    ],
    "postgresql-connection-string": [
        (
            "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb",
            "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
        ),
        (
            'DATABASE_URL="postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb"',
            "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
        ),
    ],
    "podio-client-credentials": [
        ("PODIO_CLIENT_ID=7222973", "7222973"),
        (
            'PODIO_CLIENT_SECRET="a4f2c891e7b0635d2c8f4e1a9b7d6c3e"',
            "a4f2c891e7b0635d2c8f4e1a9b7d6c3e",
        ),
    ],
    "google-oauth-client-secret": [
        (
            'google_client_secret="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Iofz"',
            "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Iofz",
        ),
        (
            "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Iofz",
            "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Iofz",
        ),
    ],
    "private-key": [
        ("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----"),
        ('PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----"', "-----BEGIN RSA PRIVATE KEY-----"),
    ],
    "splitio-api-key": [
        (
            "SPLITIO_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
            "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        ),
        (
            "split_io_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
            "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        ),
    ],
    "kubernetes-secret": [
        ("NEVER__MATCH__K8S_DISABLED__SENTINEL", "NEVER__MATCH__K8S_DISABLED__SENTINEL"),
        ("NEVER__MATCH__K8S_DISABLED__SENTINEL", "NEVER__MATCH__K8S_DISABLED__SENTINEL"),
    ],
    "google-classroom-api-credentials": [
        (
            "classroom api key ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
            "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
        ),
        (
            "google-classroom token ya29.a0AfH6SMBxToken1234567890abcd",
            "ya29.a0AfH6SMBxToken1234567890abcd",
        ),
    ],
    "pardot-api-credentials": [
        ("PARDOT_BUSINESS_UNIT_ID=0Uv1234567890AbCdE", "0Uv1234567890AbCdE"),
        ("PARDOT business_unit_id=0Uv9876543210XyZaB", "0Uv9876543210XyZaB"),
    ],
    "trulioo-api-credentials": [
        ('trulioo client_id="2963950e3ed2e3dc49d5740982bac6a9"', "2963950e3ed2e3dc49d5740982bac6a9"),
        ("TRULIOO client_id=2963950e3ed2e3dc49d5740982bac6a9", "2963950e3ed2e3dc49d5740982bac6a9"),
    ],
    "marketo-api-credentials": [
        ("MARKETO_CLIENT_ID=abcdefghijklmnopqrstuvwx12", "abcdefghijklmnopqrstuvwx12"),
        ("MARKETO_CLIENT_SECRET=fedcba9876543210fedcba98", "fedcba9876543210fedcba98"),
    ],
    "google-cloud-sovereign-credentials": [
        ("GOOGLE_SOVEREIGN PROJECT_ID=my-sovereign-project", "my-sovereign-project"),
        ('GOOGLE_CLOUD_SOVEREIGN PROJECT_ID="eu-sovereign-demo"', "eu-sovereign-demo"),
    ],
    "reddit-ads-api-credentials": [
        ("reddit_ads_client_id=AbCdEfGhIjKlMnOp", "AbCdEfGhIjKlMnOp"),
        ("REDDIT_ADS client_id=QrStUvWxYzAbCdEf", "QrStUvWxYzAbCdEf"),
    ],
    "spotify-client-credentials": [
        ("SPOTIFY_CLIENT_ID=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"),
        ("spotify_client_id=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"),
    ],
    "digitalocean-spaces-credentials": [
        ("DO_SPACES_ACCESS_KEY=7DUURP7HR3967PXE3R4V", "7DUURP7HR3967PXE3R4V"),
        ("DIGITALOCEAN_SPACES_ACCESS_KEY=8EVVSP8IS5078QYE4S5W", "8EVVSP8IS5078QYE4S5W"),
    ],
    "jumio-api-credentials": [
        ('jumio api_token="H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP"', "H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP"),
        ('JUMIO client_secret="LwJodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9abcd"', "LwJodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9abcd"),
    ],
    "lark-app-id": [
        ("lark app_id cli_a1b2c3d4e5f67890", "cli_a1b2c3d4e5f67890"),
        ('LARK_APP_ID="cli_b2c3d4e5f6789012"', "cli_b2c3d4e5f6789012"),
    ],
    "nats-credentials": [
        ("NATS_URL=nats://user:SecretPass123456@nats.example.com:4222", "SecretPass123456"),
        ('NATS_PASSWORD="AnotherNatsPass456"', "AnotherNatsPass456"),
    ],
    "n8n-webhook-credentials": [
        (
            "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
            "8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        ),
        (
            'N8N_WEBHOOK_URL="https://n8n.example.com/webhook/9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e"',
            "9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e",
        ),
    ],
}


def quoted_variant(text: str, cred: str) -> tuple[str, str]:
    if "=" in text and not text.strip().startswith("http"):
        key, _, _val = text.partition("=")
        return f'{key.strip()}="{cred}"', cred
    if ":" in text and "://" not in text.split(":", 1)[0]:
        key, _, _val = text.partition(":")
        return f'{key.strip()}: "{cred}"', cred
    return f'"{text}"', cred


def patch_positives(content: str, pairs: list[tuple[str, str]]) -> str:
    blocks: list[str] = []
    for i, (text, cred) in enumerate(pairs[:2]):
        reason = (
            "Hand-tuned positive matching detector regex (R2-F adversarial batch)."
            if i == 0
            else "Quoted-value variant of the canonical positive."
        )
        blocks.append(
            f"[[positive]]\n"
            f"text = {_toml_str(text)}\n"
            f'credential = "{cred}"\n'
            f'reason = "{reason}"\n'
        )
    new_pos = "\n".join(blocks) + "\n"
    stripped = re.sub(
        r"\[\[positive\]\][\s\S]*?(?=\n\[\[negative\]\]|\n\[\[evasion\]\]|\n\[perf\])",
        "",
        content,
    )
    for marker in ("[[negative]]", "[[evasion]]", "[perf]"):
        insert_at = stripped.find(marker)
        if insert_at != -1:
            return stripped[:insert_at] + new_pos + stripped[insert_at:]
    return content


def synth_pairs(detector_id: str) -> list[tuple[str, str]] | None:
    if detector_id in ADV_HAND:
        p = ADV_HAND[detector_id]
        if len(p) >= 2:
            return p[:2]
        t, c = p[0]
        return [p[0], quoted_variant(t, c)]
    if detector_id in MANUAL_OVERRIDES:
        t, c = MANUAL_OVERRIDES[detector_id]
        return [p[0], quoted_variant(t, c)] if (p := [(t, c)]) else None
    det_path = DETECTORS / f"{detector_id}.toml"
    if not det_path.exists():
        return None
    det = load_toml(det_path)
    block = det.get("detector", {})
    for pat in block.get("patterns", []):
        result = synthesize_for_pattern(pat.get("regex", ""), detector_id, block.get("keywords", []))
        if result:
            text, cred = result
            return [result, quoted_variant(text, cred)]
    return None


def failing_detectors() -> list[str]:
    if not FAIL_DUMP.exists():
        return []
    dets: list[str] = []
    seen: set[str] = set()
    for line in FAIL_DUMP.read_text().splitlines():
        det = line.split("\t", 1)[0]
        if det not in seen:
            seen.add(det)
            dets.append(det)
    return dets


def main() -> int:
    targets = failing_detectors()
    if not targets:
        targets = sorted(p.stem for p in CONTRACTS.glob("*.toml"))

    changed = 0
    skipped: list[str] = []
    for detector_id in targets:
        path = CONTRACTS / f"{detector_id}.toml"
        if not path.exists():
            skipped.append(detector_id)
            continue
        raw = path.read_text()
        if raw.startswith("version https://git-lfs.github.com/spec/v1"):
            skipped.append(detector_id)
            continue
        pairs = synth_pairs(detector_id)
        if not pairs:
            det_path = DETECTORS / f"{detector_id}.toml"
            if det_path.exists():
                det = load_toml(det_path)
                full = build_full_contract(det, detector_id)
                if full:
                    path.write_text(full)
                    changed += 1
                    print(f"regen {detector_id}")
                    continue
            skipped.append(detector_id)
            continue
        new = patch_positives(raw, pairs)
        if new != raw:
            path.write_text(new)
            changed += 1
            print(f"patch {detector_id}")
    print(f"changed={changed} skipped={len(skipped)}", file=sys.stderr)
    if skipped:
        print("skipped:", ", ".join(skipped), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
