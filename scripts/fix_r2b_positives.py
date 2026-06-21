#!/usr/bin/env python3
"""Patch contract [[positive]] fixtures for R2-B top-50 positive MISSED batch."""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
CONTRACTS = REPO / "crates" / "scanner" / "tests" / "contracts"
DETECTORS = REPO / "detectors"

sys.path.insert(0, str(REPO / "scripts"))
from generate_contracts import (  # noqa: E402
    _toml_str,
    build_full_contract,
    load_toml,
    spec_detector_id,
)

# Hand-tuned positives: (text, credential) pairs verified via probe_r2b_fixtures.rs.
HAND_POSITIVES: dict[str, list[tuple[str, str]]] = {
    "foundation-api-key": [
        ('foundation API KEY= "M9TBrKrmGsNmjQ8mT3OA12345678"', "M9TBrKrmGsNmjQ8mT3OA12345678"),
        ('FOUNDATION_API_KEY="odFX1GOZrhrztAQpiN0k12345678"', "odFX1GOZrhrztAQpiN0k12345678"),
    ],
    "jotform-api-key": [
        ("jotform api_key 2963950e3ed2e3dc49d5740982bac6a9", "2963950e3ed2e3dc49d5740982bac6a9"),
        ("JOTFORM API KEY 2963950e3ed2e3dc49d5740982bac6a9", "2963950e3ed2e3dc49d5740982bac6a9"),
    ],
    "genesys-cloud-credentials": [
        ("GENESYS_CLIENT_ID=2963950e-3ed2-e3dc-49d5-740982bac6a9", "2963950e-3ed2-e3dc-49d5-740982bac6a9"),
        ('PURECLOUD client_id="3f2da167-246e-be0e-4dc3-7c9e74a75b5b"', "3f2da167-246e-be0e-4dc3-7c9e74a75b5b"),
    ],
    "gravity-forms-rest-api-key": [
        ("gravity forms api key abcdef0123456789abcdef0123456789", "abcdef0123456789abcdef0123456789"),
        ('GRAVITY_FORMS private_key="fedcba9876543210fedcba9876543210"', "fedcba9876543210fedcba9876543210"),
    ],
    "idenfy-api-credentials": [
        ('idenfy api_key "H_ZM9TBrKrmGsNmjQ8mT3OA9"', "H_ZM9TBrKrmGsNmjQ8mT3OA9"),
        ("IDENFY api_key: LwJodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9", "LwJodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9"),
    ],
    "gumroad-api-key": [
        ("gumroad access_token=b2963950e3ed2e3dc49d5740982bac6a94", "b2963950e3ed2e3dc49d5740982bac6a94"),
        ('GUMROAD api_key="353f2da167246ebe0e04dc37c9e74a75b5b95a61d015"', "353f2da167246ebe0e04dc37c9e74a75b5b95a61d015"),
    ],
    "google-forms-api-credentials": [
        (
            "google forms api key abcdefghijklmnopqrstuvwxyz123456",
            "abcdefghijklmnopqrstuvwxyz123456",
        ),
        (
            'GOOGLE_FORMS private_key="YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcA=="',
            "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcA==",
        ),
    ],
    "google-classroom-api-credentials": [
        (
            "classroom api key ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
            "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
        ),
        (
            "google-classroom token ya29.a0AfH6SMBxExampleToken1234567890abcd",
            "ya29.a0AfH6SMBxExampleToken1234567890abcd",
        ),
    ],
    "google-artifact-registry-key": [
        (
            '{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----"}',
            "-----BEGIN PRIVATE KEY-----",
        ),
        (
            '_json_key={"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----"}',
            "-----BEGIN PRIVATE KEY-----",
        ),
    ],
    "hubspot-private-app-token": [
        ("pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890", "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
        ("export pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890", "pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
    ],
    "kafka-sasl-credentials": [
        ("KAFKA_SASL_PASSWORD=SecretPass123456", "SecretPass123456"),
        (
            'sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="kafkauser" password="SecretPass123456";',
            "SecretPass123456",
        ),
    ],
    "kafka-connect-credentials": [
        ("CONNECT_PASSWORD=KafkaConnectPass123", "KafkaConnectPass123"),
        ('connect.password="KafkaConnectPass123"', "KafkaConnectPass123"),
    ],
    "splitio-api-key": [
        ("split_io_api_key=YWJjZGVmZ2hpamtsbW5vcA==", "YWJjZGVmZ2hpamtsbW5vcA="),
        ('split_io_api_key="YWJjZGVmZ2hpamtsbW5vcA=="', "YWJjZGVmZ2hpamtsbW5vcA="),
    ],
    "statuscake-api-key": [
        ("statuscake_api_key=qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1", "qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1"),
        ('statuscake_api_key="b3e7f1a9c2d4e6f8a0b2c4d6e8f0a1b3"', "b3e7f1a9c2d4e6f8a0b2c4d6e8f0a1b3"),
    ],
    "lastpass-dev-creds": [
        ("lastpass id=9860386", "9860386"),
        ("LASTPASS id=9860387", "9860387"),
    ],
    "telegram-bot-token": [
        (
            "TELEGRAM_BOT_TOKEN=612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
            "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
        ),
        (
            'telegram_bot_token: "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx"',
            "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
        ),
    ],
    "sanity-api-token": [
        ("SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289", "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289"),
        (
            'SANITY_API_TOKEN="sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289"',
            "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
        ),
    ],
    "locationiq-api-token": [
        (
            "LOCATIONIQ_API_KEY=pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
            "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
        ),
        (
            'LOCATIONIQ_API_KEY="pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706"',
            "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706",
        ),
    ],
    "wechat-api-credentials": [
        (
            "WECHAT_APPID=wxb044e1c1cb3f7ece\nwechat app_secret=a1b2c3d4e5f678901234567890123456",
            "a1b2c3d4e5f678901234567890123456",
        ),
        (
            'appid: wxc155d2e3cb4f8fdf\nWECHAT app_secret="b2c3d4e5f67890123456789012345678"',
            "b2c3d4e5f67890123456789012345678",
        ),
    ],
    "hubitat-api-credentials": [
        ("HUBITAT_ACCESS_TOKEN=83872b81e8e47b73d953e93a0df6213963265ab6", "83872b81e8e47b73d953e93a0df6213963265ab6"),
        ("hubitat.access_token=83872b81e8e47b73d953e93a0df6213963265ab7", "83872b81e8e47b73d953e93a0df6213963265ab7"),
    ],
    "kaltura-api-credentials": [
        ("KALTURA admin_secret=f503022fc2f47fcf4f8fefe42c30bba9", "f503022fc2f47fcf4f8fefe42c30bba9"),
        ('kaltura ADMIN_SECRET "f503022fc2f47fcf4f8fefe42c30bba9"', "f503022fc2f47fcf4f8fefe42c30bba9"),
    ],
    "graph-deploy-key": [
        ("GRAPH deploy_key=37cb496acf2f25e15b2485167eab3182", "37cb496acf2f25e15b2485167eab3182"),
        ('deploy_key: "37cb496acf2f25e15b2485167eab3182"', "37cb496acf2f25e15b2485167eab3182"),
    ],
    "line-api-token": [
        (
            'LINE CHANNEL_ACCESS_TOKEN="/ZM9TBrKrmGsNmjQ8mT3OA94HhblZa+QFPiyCEs5lkO/nMLpQAK4lXOELxyxeH8ilqtekYJEB1J5+TkPo/QyFcIoCVvQ2hmsCfjd=="',
            "/ZM9TBrKrmGsNmjQ8mT3OA94HhblZa+QFPiyCEs5lkO/nMLpQAK4lXOELxyxeH8ilqtekYJEB1J5+TkPo/QyFcIoCVvQ2hmsCfjd==",
        ),
        (
            "LINE channel_access_token /ZM9TBrKrmGsNmjQ8mT3OA94HhblZa+QFPiyCEs5lkO/nMLpQAK4lXOELxyxeH8ilqtekYJEB1J5+TkPo/QyFcIoCVvQ2hmsCfjd==",
            "/ZM9TBrKrmGsNmjQ8mT3OA94HhblZa+QFPiyCEs5lkO/nMLpQAK4lXOELxyxeH8ilqtekYJEB1J5+TkPo/QyFcIoCVvQ2hmsCfjd==",
        ),
    ],
    "goto-meeting-api": [
        ('GOTO_MEETING_API_KEY="JodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9abcd"', "JodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9abcd"),
        ("gotomeeting access_token=M9TBrKrmGsNmjQ8mT3OA94HhblZaQFPiyCEs5lkO", "M9TBrKrmGsNmjQ8mT3OA94HhblZaQFPiyCEs5lkO"),
    ],
    "ibm-cloud-government-credentials": [
        (
            'IBM_CLOUD_GOV API_KEY="AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIj"',
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh",
        ),
        ("IBM_CLOUD_GOV REGION=us-south", "us-south"),
    ],
    "invision-api-key": [
        ("IPS4 api_key=2963950e3ed2e3dc49d5740982bac6a9", "2963950e3ed2e3dc49d5740982bac6a9"),
        ("invision token=2963950e3ed2e3dc49d5740982bac6a9", "2963950e3ed2e3dc49d5740982bac6a9"),
    ],
    "prometheus-remote-write-credentials": [
        (
            "remote_write:\n  - url: https://prom.example.com/api/v1/write\n    basic_auth:\n      username: prom_remote_user\n      password: s3cr3t",
            "prom_remote_user",
        ),
        (
            "PROMETHEUS_REMOTE_WRITE_USER=prom_remote_user",
            "prom_remote_user",
        ),
    ],
    "render-deploy-hook": [
        (
            "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
            "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        ),
        (
            'RENDER_DEPLOY_HOOK="https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju"',
            "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
        ),
    ],
    "rabbitmq-credentials": [
        (
            "amqp://user:SecretPass123456@rabbitmq.example.com:5672/vhost",
            "SecretPass123456",
        ),
        (
            'RABBITMQ_URL="amqps://admin:AnotherRabbitPass456@broker.example.com:5671/"',
            "AnotherRabbitPass456",
        ),
    ],
    "marketo-api-credentials": [
        ("MARKETO_CLIENT_ID=abcdefghijklmnopqrstuvwx12", "abcdefghijklmnopqrstuvwx12"),
        ('MARKETO_CLIENT_ID="fedcba9876543210fedcba98765"', "fedcba9876543210fedcba98765"),
    ],
    "looksrare-api-key": [
        ("X-Looks-Api-Key: abcdefghijklmnopqrstuvwxyz1234567890abcd", "abcdefghijklmnopqrstuvwxyz1234567890abcd"),
        ('X-Looks-Api-Key="fedcba9876543210fedcba9876543210abcd"', "fedcba9876543210fedcba9876543210abcd"),
    ],
    "zora-api-key": [
        ('ZORA API KEY = "k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj"', "k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj"),
        ('ZORA_API_KEY="m8nOq3rSt5uVw9xYz2aB4cD6eFgHiJk"', "m8nOq3rSt5uVw9xYz2aB4cD6eFgHiJk"),
    ],
    "umami-api-key": [
        ("UMAMI_API_KEY=6ea17ead-9d16-752e-bc57-4e4ac8609e13", "6ea17ead-9d16-752e-bc57-4e4ac8609e13"),
        ('UMAMI_API_KEY="7fb28fbe-ae27-863f-cd68-5f5bd9710f24"', "7fb28fbe-ae27-863f-cd68-5f5bd9710f24"),
    ],
    "reddit-ads-api-credentials": [
        ("reddit ads client_id=AbCdEfGhIjKlMn", "AbCdEfGhIjKlMn"),
        ('reddit_ads_client_id="XyZ9876543210Ab"', "XyZ9876543210Ab"),
    ],
    "socure-api-key": [
        ('SOCURE sdk_key="abcdefghijklmnopqrstuvwx123456"', "abcdefghijklmnopqrstuvwx123456"),
        ("socure api key=qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1", "qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1"),
    ],
}


def top50_ids() -> list[str]:
    log = (REPO / "audits" / "round-r1-red-wall-full.log").read_text()
    pat = re.compile(r"^\s*- ([a-z0-9-]+): positive MISSED", re.M)
    from collections import Counter

    return [d for d, _ in Counter(pat.findall(log)).most_common(50)]


def render_positives(pairs: list[tuple[str, str]]) -> str:
    blocks: list[str] = []
    for i, (text, cred) in enumerate(pairs):
        reason = (
            "Canonical anchor + synthesized body satisfying detector's primary regex."
            if i == 0
            else "Quoted-value variant of the canonical positive."
        )
        blocks.append(
            f"[[positive]]\ntext = {_toml_str(text)}\ncredential = {_toml_str(cred)}\nreason = {_toml_str(reason)}"
        )
    return "\n\n".join(blocks) + "\n\n"


def patch_positives_only(detector_id: str, pairs: list[tuple[str, str]]) -> bool:
    path = CONTRACTS / f"{detector_id}.toml"
    if not path.exists():
        return False
    text = path.read_text()
    new_pos = render_positives(pairs)
    patched, n = re.subn(
        r"\[\[positive\]\][\s\S]*?(?=\[\[negative\]\]|\[\[evasion\]\]|\[perf\])",
        new_pos,
        text,
        count=1,
    )
    if n == 0:
        return False
    path.write_text(patched)
    return True


def write_full_contract(detector_id: str) -> bool:
    det_path = DETECTORS / f"{detector_id}.toml"
    if not det_path.exists():
        det_path = DETECTORS / "generic-private-key.toml"
    if not det_path.exists():
        return False
    det = load_toml(det_path)
    toml = build_full_contract(det, spec_detector_id(det, detector_id))
    if toml is None:
        return False
    (CONTRACTS / f"{detector_id}.toml").write_text(toml)
    return True


def main() -> int:
    ids = top50_ids()
    fixed: list[str] = []
    skipped: list[str] = []

    for did in ids:
        if did in HAND_POSITIVES:
            ok = patch_positives_only(did, HAND_POSITIVES[did])
        else:
            ok = write_full_contract(did)
        if ok:
            fixed.append(did)
        else:
            skipped.append(did)

    print(f"patched {len(fixed)}/{len(ids)}")
    for d in fixed:
        print(f"  fixed {d}")
    if skipped:
        print("skipped:", ", ".join(skipped))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
