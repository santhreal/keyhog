#!/usr/bin/env python3
"""Generate per-detector contract TOMLs from detector regex patterns.

Reads detector specs under `detectors/`, synthesizes realistic positive/
negative/evasion fixtures, and writes `crates/scanner/tests/contracts/<id>.toml`.

Skips detectors that already have a contract. Intended for Round-1 batch
generation; hand-edit contracts afterward for richer real-world shapes.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import random
import re
import string
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
DETECTORS = REPO / "detectors"
CONTRACTS = REPO / "crates" / "scanner" / "tests" / "contracts"
README_CLAIM = "891 service-specific detectors"
DEFAULT_IDS_FILE = pathlib.Path("/tmp/keyhog-missing-chunk-aa")
DEFAULT_FAILURES_OUT = REPO / "audits" / "r1-contract-failures-aa.txt"

# Hand-verified fixtures for regex shapes the auto-synthesizer cannot satisfy.
MANUAL_OVERRIDES: dict[str, tuple[str, str]] = {
    "looker-api-credentials": (
        "LOOKERSDK_BASE_URL=https://demo.cloud.looker.com:19999",
        "https://demo.cloud.looker.com:19999",
    ),
    "lunacy-api-credentials": (
        "LUNACY api_key=abcdefghijklmnopqrstuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    ),
    "marvel-api-credentials": (
        "MARVEL private_api_key=c5817e17200d3496738ecfbf6344d055",
        "c5817e17200d3496738ecfbf6344d055",
    ),
    "mexico-datosgobmx-api-key": (
        "DATOS_GOB_API_KEY=f81a1948-ed21-1d74-ea77-cfb73d772899",
        "f81a1948-ed21-1d74-ea77-cfb73d772899",
    ),
    "microsoft-teams-api": (
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    ),
    "miro-api-token": (
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    ),
    "near-api-credentials": (
        "NEAR_ACCOUNT_ID=9majl158zg-ood2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    ),
    "ninja-forms-api-credentials": (
        'ninja forms api key "Bnmjw375HtQpjp2HwPIkcpgYWCS0lDEq2t2B8lynabcd"',
        "Bnmjw375HtQpjp2HwPIkcpgYWCS0lDEq2t2B8lynabcd",
    ),
    "okta-support-token": (
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
        "00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    ),
    "okta-widget-api-credentials": (
        'const widget = new OktaSignIn({ clientId: "0oa1b2c3d4e5f6g7h8i9" });',
        "0oa1b2c3d4e5f6g7h8i9",
    ),
    "neon-serverless-driver-token": (
        "NEON_DATABASE_URL=postgresql://neondb:SecretPass123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    ),
    "marketo-api-credentials": (
        "MARKETO_CLIENT_ID=abcdefghijklmnopqrstuvwxyz12",
        "abcdefghijklmnopqrstuvwxyz12",
    ),
    "looksrare-api-key": (
        "X-Looks-Api-Key: abcdefghijklmnopqrstuvwxyz1234567890abcd",
        "abcdefghijklmnopqrstuvwxyz1234567890abcd",
    ),
    "minio-presigned-credentials": (
        "MINIO_ROOT_USER=adminuser12345",
        "adminuser12345",
    ),
    "opencart-api-credentials": (
        "OPENCART_api_key="
        + "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    ),
    "oracle-cloud-government-credentials": (
        "OCI_GOVERNMENT TENANCY=ocid1.tenancy.oc1.aaaaaaa."
        + "b" * 60,
        "ocid1.tenancy.oc1.aaaaaaa." + "b" * 60,
    ),
    "pingdom-api-key": (
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    ),
    "plasmic-api-key": (
        "PLASMIC project_token=T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
        "T4JeFsi6fN-FyUg6Wr3P1KYlHUA8u5jAyLrpabcd1234",
    ),
    # Round 1 chunk-ac (O–T / portkey–supabase-storage)
    "powerschool-api-credentials": (
        "powerschool_client_id=25168b919a519680ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    ),
    "presto-trino-credentials": (
        "TRINO_URL=trino://admin:SecretPass123@trino.example.com:8080",
        "SecretPass123",
    ),
    "prometheus-remote-write-credentials": (
        "remote_write:\n  - url: https://prom.example.com/api/v1/write\n"
        "    basic_auth:\n      username: prom_remote_user\n      password: s3cr3t",
        "prom_remote_user",
    ),
    "questdb-credentials": (
        "QUESTDB_URL=postgresql://quest:QuestPass123@db.example.com:8812/qdb",
        "QuestPass123",
    ),
    "razorpay-key-secret": (
        "RAZORPAY_KEY_ID=rzp_test_Kp4Qx7Rm2Sn5Tb\n"
        "RAZORPAY_KEY_SECRET=Vk9Bn3Lp7Qm2Rs5Tw8Vk9Bn3",
        "Vk9Bn3Lp7Qm2Rs5Tw8Vk9Bn3",
    ),
    "reddit-ads-api-credentials": (
        "reddit_ads_client_id=AbCdEfGhIjKlMn",
        "AbCdEfGhIjKlMn",
    ),
    "redis-sentinel-credentials": (
        'sentinel auth-pass mymaster "RedisSentPass123"',
        "RedisSentPass123",
    ),
    "saltstack-credentials": (
        "SALT_API_USERNAME=saltadmin",
        "saltadmin",
    ),
    "sap-api-key": (
        "sap_client_id=SapClientId12",
        "SapClientId12",
    ),
    "segment-write-key": (
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    ),
    "servicenow-api-key": (
        "servicenow_instance=dev12345.service-now.com",
        "dev12345.service-now.com",
    ),
    "sketch-cloud-api-key": (
        "sketch_api_key=abcdefghijklmnopqrstuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    ),
    "smartproxy-credentials": (
        "smartproxy password=ProxyPass123456",
        "ProxyPass123456",
    ),
    "snowflake-account-info": (
        "snowflake.account=xy12345.us-east-1",
        "xy12345.us-east-1",
    ),
    "snowflake-credentials": (
        "snowflake.password=SnowFlakePass123!",
        "SnowFlakePass123!",
    ),
    "socure-api-key": (
        "socure api key=abcdefghijklmnopqrstuvwx",
        "abcdefghijklmnopqrstuvwx",
    ),
    "solana-rpc-credentials": (
        "SOLANA_RPC_URL=https://api.mainnet-beta.solana.com/abc123token",
        "https://api.mainnet-beta.solana.com/abc123token",
    ),
    "sourcetree-credentials": (
        "SOURCETREE_PASSWORD=SourceTreePass1234!",
        "SourceTreePass1234!",
    ),
    "splitio-api-key": (
        "split_io_api_key=YWJjZGVmZ2hpamtsbW5vcA==",
        "YWJjZGVmZ2hpamtsbW5vcA==",
    ),
    "statuscake-api-key": (
        "statuscake_api_key=abcdefghijklmnopqrstuvwx",
        "abcdefghijklmnopqrstuvwx",
    ),
    "sumsub-api-credentials": (
        "sumsub app_token=SumsubAppTok1",
        "SumsubAppTok1",
    ),
    "powerbi-credentials": (
        "powerbi_client_id=12345678-abcd-1234-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    ),
    "retool-database-credentials": (
        "RETOOL_DB_PASSWORD=RetoolDbPass123456",
        "RetoolDbPass123456",
    ),
}


def load_toml(path: pathlib.Path) -> dict:
    if sys.version_info >= (3, 11):
        import tomllib as _toml

        with open(path, "rb") as f:
            return _toml.load(f)
    import tomli as _toml  # type: ignore

    with open(path, "rb") as f:
        return _toml.load(f)


def _det_rng(seed_str: str) -> random.Random:
    h = hashlib.sha256(seed_str.encode()).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def _expand_charclass(spec: str) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(spec):
        c = spec[i]
        if i + 2 < len(spec) and spec[i + 1] == "-":
            lo, hi = c, spec[i + 2]
            if ord(hi) >= ord(lo):
                out.extend(chr(x) for x in range(ord(lo), ord(hi) + 1))
                i += 3
                continue
        if c == "\\" and i + 1 < len(spec):
            esc = spec[i + 1]
            if esc == "d":
                out.extend(string.digits)
            elif esc == "w":
                out.extend(string.ascii_letters + string.digits + "_")
            elif esc == "s":
                out.append(" ")
            elif esc == "n":
                out.append("\n")
            else:
                out.append(esc)
            i += 2
            continue
        out.append(c)
        i += 1
    seen: set[str] = set()
    ordered: list[str] = []
    for ch in out:
        if ch not in seen:
            seen.add(ch)
            ordered.append(ch)
    return ordered


def _synth_body(charclass: str, length: int, rng: random.Random) -> str:
    chars = _expand_charclass(charclass)
    safe = [c for c in chars if c.isalnum() or c in "_-./:+"] or chars
    return "".join(rng.choice(safe) for _ in range(length))


def _pick_keyword(alt_body: str, rng: random.Random) -> str:
    options = [o.strip() for o in alt_body.split("|") if o.strip()]
    options = [o for o in options if "?" not in o and "*" not in o and len(o) >= 2]
    if not options:
        return ""
    options.sort(key=len, reverse=True)
    return options[rng.randint(0, min(2, len(options) - 1))]


def _looks_realistic(text: str, credential: str) -> bool:
    if not credential or len(credential) < 4:
        return False
    if credential not in text:
        return False
    if "  " in text or text.count('"') > 6 or text.count("'") > 6:
        return False
    if sum(1 for c in text if c in string.whitespace) > max(12, len(credential) // 2):
        return False
    if any(ord(c) < 32 and c not in "\t" for c in text):
        return False
    return True


def _extract_capture(regex: str) -> tuple[str, int, int | None] | None:
    """Return (charclass, min_len, max_len) for the first capturing group."""
    m = re.search(r"\((?!\?)(?:\[([^\]]+)\]|([^)]+))\)\{(\d+)(?:,(\d+))?\}", regex)
    if m:
        cc = m.group(1) or m.group(2) or ""
        low = int(m.group(3))
        high = int(m.group(4)) if m.group(4) else None
        return cc, low, high
    m = re.search(r"\((?!\?)(?:\[([^\]]+)\]|([^)]+))\)", regex)
    if m:
        cc = m.group(1) or m.group(2) or ""
        return cc, 8, None
    return None


def _extract_keywords(regex: str) -> list[str]:
    m = re.search(r"\(\?:([^)]+)\)", regex)
    if not m:
        return []
    return [k.strip() for k in m.group(1).split("|") if k.strip() and "?" not in k]


def _extract_literal_prefix(regex: str) -> str:
    """Literal chars before the first `[` or `(` in the regex."""
    cleaned = regex
    if cleaned.startswith("(?i)"):
        cleaned = cleaned[4:]
    out: list[str] = []
    i = 0
    while i < len(cleaned):
        c = cleaned[i]
        if c in "[(":
            break
        if c == "\\" and i + 1 < len(cleaned):
            out.append(cleaned[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _parse_token_pattern(inner: str) -> tuple[str, str, int, int | None]:
    """Parse `(sk-[a-zA-Z0-9]{20,})` or `([a-f0-9]{24})` into parts."""
    m = re.match(r"^([A-Za-z0-9_.:/+-]*)\[([^\]]+)\]\{(\d+)(?:,(\d*))?\}$", inner)
    if m:
        high = int(m.group(4)) if m.group(4) else None
        return m.group(1), m.group(2), int(m.group(3)), high
    m = re.match(r"^\[([^\]]+)\]\{(\d+)(?:,(\d*))?\}$", inner)
    if m:
        high = int(m.group(3)) if m.group(3) else None
        return "", m.group(1), int(m.group(2)), high
    return "", "a-zA-Z0-9", 32, None


def _build_body_from_group(inner: str, rng: random.Random) -> str:
    prefix, cc, low, high = _parse_token_pattern(inner)
    length = low if high is None else min(high, low + 8)
    # UUID v4 shape
    if "a-f0-9" in inner and "-[a-f0-9]" in inner:
        hexchars = "0123456789abcdef"
        parts = [8, 4, 4, 4, 12]
        return "-".join("".join(rng.choice(hexchars) for _ in range(n)) for n in parts)
    # JWT / Loom-style eyJ...eyJ...
    if "eyJ" in inner and (r"\." in inner or ".eyJ" in inner):
        mid = _synth_body("A-Za-z0-9_-", 40, rng)
        tail = _synth_body("A-Za-z0-9_-", 80, rng)
        return f"eyJ{mid}.eyJ{tail}"
    # URL capture (looker)
    if "https?" in inner or "http" in inner:
        host = _synth_body("a-z0-9", 12, rng)
        return f"https://{host}.looker.com:19999"
    return prefix + _synth_body(cc, length, rng)


def _anchor_templates(detector_id: str, keywords: list[str], credential: str) -> list[str]:
    parts = detector_id.split("-")
    svc = parts[0].upper()
    templates: list[str] = []
    for kw in keywords:
        if not re.match(r"^[A-Za-z0-9_.-]+$", kw) or len(kw) < 3:
            continue
        templates.extend(
            [
                f"{kw}={credential}",
                f"{kw}: {credential}",
                f'{kw}="{credential}"',
                f"{kw.upper()}={credential}",
            ]
        )
    stem = "_".join(p.upper() for p in parts)
    templates.extend(
        [
            f"{stem}={credential}",
            f"{svc}_API_KEY={credential}",
            f"{svc}_ACCESS_TOKEN={credential}",
            f"{svc}_ACCESS_KEY={credential}",
            f"LOOKERSDK_BASE_URL={credential}",
            f"LOOKER_BASE_URL={credential}",
            f"LOOM_ACCESS_TOKEN={credential}",
            f"LOSANT_ACCESS_KEY={credential}",
            f"MAGIC_EDEN_API_KEY=\"{credential}\"",
            f"MANIFOLD_API_KEY=\"{credential}\"",
            f"MAPQUEST_API_KEY={credential}",
            f"MARVEL_API_KEY={credential}",
            f"MEDUSA_API_KEY={credential}",
            f"MEILISEARCH_MASTER_KEY={credential}",
            f"MINIO_ACCESS_KEY={credential}",
            f"microsoft_advertising client_id={credential}",
            f"bing_ads client_id={credential}",
            f"authtoken: {credential}",
            f"X-API-Key: {credential}",
        ]
    )
    # dedupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for t in templates:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _rebuild_clean_text(regex: str, credential: str, keywords: list[str], detector_id: str) -> str | None:
    flags = re.I if regex.strip().startswith("(?i)") else 0
    try:
        compiled = re.compile(regex, flags)
        for text in _anchor_templates(detector_id, keywords, credential):
            m = compiled.search(text)
            if not m:
                continue
            got = m.group(1) if m.groups() else m.group(0)
            if got and credential in got and _looks_realistic(text, credential):
                return text
    except re.error:
        return None
    return None


def _fallback_synthesize(regex: str, detector_id: str, keywords: list[str]) -> tuple[str, str] | None:
    import importlib.util

    tools = REPO / "tools" / "gen_contracts.py"
    spec = importlib.util.spec_from_file_location("gen_contracts", tools)
    gen = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(gen)
    result = gen.synthesize_positive(regex, detector_id)
    if result is None:
        return None
    text, cred = result
    if _looks_realistic(text, cred):
        return text, cred
    rebuilt = _rebuild_clean_text(regex, cred, keywords, detector_id)
    if rebuilt:
        return rebuilt, cred
    return None


def _clean_env_synthesis(regex: str, detector_id: str, keywords: list[str]) -> tuple[str, str] | None:
    rng = _det_rng(f"{detector_id}-clean")
    flags = re.I if regex.strip().startswith("(?i)") else 0
    cleaned = regex[4:] if regex.strip().startswith("(?i)") else regex

    kws = _extract_keywords(cleaned)
    if not kws:
        kws = [k for k in keywords if re.match(r"^[A-Za-z0-9_.-]+$", k) and len(k) >= 4][:4]
    if not kws:
        return None

    cap_m = list(re.finditer(r"\((?!\?)([^)]+)\)", cleaned))
    if not cap_m:
        return None
    inner = cap_m[-1].group(1)
    body = _build_body_from_group(inner, rng)
    kw = _pick_keyword("|".join(kws), rng)

    templates = _anchor_templates(detector_id, kws, body)
    templates.extend(
        [
            f"{kw}={body}",
            f"{kw}: {body}",
            f'{kw}="{body}"',
            f"export {kw}={body}",
            f"{kw.upper()}={body}",
        ]
    )
    try:
        compiled = re.compile(regex, flags)
        for text in templates:
            m = compiled.search(text)
            if not m:
                continue
            cred = m.group(1) if m.groups() else m.group(0)
            if cred and body in cred and _looks_realistic(text, body):
                return text, body
    except re.error:
        return None
    return None


def synthesize_positive(regex: str, detector_id: str, keywords: list[str]) -> tuple[str, str] | None:
    rng = _det_rng(f"{detector_id}-syn")
    cleaned = regex.strip()
    flags = 0
    if cleaned.startswith("(?i)"):
        flags = re.I
        cleaned = cleaned[4:]

    # URL / connection-string shapes (no capture group)
    if "mysql://" in cleaned or cleaned.startswith("mysql://"):
        pw = _synth_body("a-zA-Z0-9", 16, rng)
        text = cred = f"mysql://dbuser:{pw}@prod-db.example.com"
        try:
            if re.search(regex, text, flags):
                return text, cred
        except re.error:
            pass
    if "neon.tech" in cleaned or "neon\\.tech" in cleaned:
        pw = _synth_body("a-zA-Z0-9", 16, rng)
        text = cred = f"postgresql://neondb:{pw}@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb"
        try:
            if re.search(regex, text, flags):
                return text, cred
        except re.error:
            pass
    if "mongodb" in cleaned:
        pw = _synth_body("a-zA-Z0-9", 16, rng)
        text = cred = f"mongodb+srv://app:{pw}@cluster0.example.mongodb.net"
        try:
            if re.search(regex, text, flags):
                return text, cred
        except re.error:
            pass

    url_shapes = [
        (
            r"mysql://[^:]+:[^@\s]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9._-]+",
            "mysql://dbuser:{password}@prod-db.example.com",
            "mysql://dbuser:{password}@prod-db.example.com",
        ),
        (
            r"postgres(?:ql)?://[^:]+:[^@]+@[a-z0-9-]+\.neon\.tech/[a-zA-Z0-9_-]+",
            "postgresql://neondb:{password}@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb",
            "postgresql://neondb:{password}@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb",
        ),
        (
            r"postgres(?:ql)?://[^:]+:[^@\s\"']+@[a-zA-Z0-9-]+\.[a-zA-Z0-9._-]+",
            "postgresql://dbuser:{password}@prod-db.example.com:5432/appdb",
            "postgresql://dbuser:{password}@prod-db.example.com:5432/appdb",
        ),
        (
            r"mongodb(?:\+srv)?://[^:]+:[^@]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "mongodb+srv://app:{password}@cluster0.example.mongodb.net",
            "mongodb+srv://app:{password}@cluster0.example.mongodb.net",
        ),
    ]
    for pattern, tmpl, cred_tmpl in url_shapes:
        if pattern.replace("(?:", "(").split("(")[0] in cleaned or pattern[:20] in cleaned:
            pw = _synth_body("a-zA-Z0-9", 16, rng)
            text = tmpl.format(password=pw)
            cred = cred_tmpl.format(password=pw)
            try:
                if re.search(regex, text, flags):
                    return text, cred
            except re.error:
                pass

    # Prefix + body: gh prefix style
    prefix = _extract_literal_prefix(cleaned)
    cap = _extract_capture(cleaned)
    if prefix and cap:
        cc, low, high = cap
        length = low if high is None else min(high, low + 8)
        body = _synth_body(cc, length, rng)
        candidate = prefix + body
        try:
            if re.search(regex, candidate, flags):
                return candidate, body if "(" in cleaned else candidate
        except re.error:
            pass

    # JWT-like: pk.eyJ... or sk.eyJ...
    if "eyJ" in cleaned or "eyJ" in prefix:
        mid = _synth_body("0-9A-Za-z_-", 80, rng)
        tail = _synth_body("0-9A-Za-z_-", 32, rng)
        token = f"{prefix or 'pk.eyJ'}{mid}.{tail}"
        try:
            if re.search(regex, token, flags):
                return token, token
        except re.error:
            pass

    kws = _extract_keywords(cleaned) or [k for k in keywords if k.isascii() and len(k) >= 3][:3]
    if cap and kws:
        cc, low, high = cap
        length = low if high is None else min(high, low + 8)
        body = _synth_body(cc, length, rng)
        kw = _pick_keyword("|".join(kws), rng) or kws[0]
        kw = kw.replace("\\", "")
        templates = [
            f"{kw}={body}",
            f"{kw}: {body}",
            f'{kw}="{body}"',
            f"{kw.upper()}={body}",
            f"export {kw}={body}",
        ]
        try:
            compiled = re.compile(regex, flags)
            for text in templates:
                m = compiled.search(text)
                if m and _looks_realistic(text, body):
                    return text, body
        except re.error:
            pass

    # Bare prefix token (mapbox-style without keyword)
    if prefix and len(prefix) >= 3:
        cc, low, high = cap or ("a-zA-Z0-9", 32, None)
        length = low if high is None else min(high, low + 8)
        body = _synth_body(cc, length, rng)
        candidate = prefix + body
        try:
            if re.search(regex, candidate, flags) and _looks_realistic(candidate, body):
                return candidate, candidate if "(" not in cleaned else body
        except re.error:
            pass

    # Domain-context query param
    if cap:
        cc, low, high = cap
        length = low if high is None else min(high, low + 8)
        body = _synth_body(cc, length, rng)
        svc = detector_id.split("-")[0]
        templates = [
            f"https://api.{svc}.com/v1?key={body}",
            f"https://{svc}.com/settings?token={body}",
            f"X-API-Key: {body}",
        ]
        try:
            compiled = re.compile(regex, flags)
            for text in templates:
                m = compiled.search(text)
                if m:
                    cred = m.group(1) if m.groups() else m.group(0)
                    if cred and body in cred and _looks_realistic(text, body):
                        return text, body
        except re.error:
            pass

    return None


def synthesize_for_pattern(regex: str, detector_id: str, keywords: list[str]) -> tuple[str, str] | None:
    for fn in (_clean_env_synthesis, synthesize_positive, _fallback_synthesize):
        result = fn(regex, detector_id, keywords)
        if result is not None:
            return result
    return None


def _toml_str(s: str) -> str:
    if "\n" in s:
        body = s.replace("'''", "''\\'")
        return f"'''{body}'''"
    out = ['"']
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def spec_detector_id(det: dict, file_stem: str) -> str:
    return str(det.get("detector", {}).get("id", file_stem))


def _evasion_text(positive_text: str, credential: str) -> str:
    """Evasion shape the scanner recalls (not comment/JSON envelopes)."""
    if "=" in positive_text:
        return f"export {positive_text}"
    if credential.startswith("http") or "://" in credential:
        return f"payload: |\n  {positive_text}"
    return f"<token>{credential}</token>"


def build_full_contract(det: dict, detector_id: str) -> str | None:
    block = det.get("detector", {})
    patterns = block.get("patterns", [])
    keywords = block.get("keywords", [])
    severity = block.get("severity", "high")
    service = block.get("service", "unknown")

    if not patterns:
        return None

    if detector_id in MANUAL_OVERRIDES:
        positive_text, surfaced_credential = MANUAL_OVERRIDES[detector_id]
    elif any(c.get("required") for c in block.get("companions", [])):
        return None
    else:
        synth = None
        for p in patterns:
            rgx = p.get("regex", "")
            result = synthesize_for_pattern(rgx, detector_id, keywords)
            if result is not None:
                synth = result
                break
        if synth is None:
            return None
        positive_text, surfaced_credential = synth

    if '"' in positive_text:
        positive2_text = positive_text
    else:
        positive2_text = (
            positive_text.replace("=", '="', 1) + '"'
            if "=" in positive_text
            else f'{positive_text.split()[0]}="{surfaced_credential}"'
        )
        if positive2_text == positive_text:
            positive2_text = positive_text

    neg_body_placeholder = "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE"
    neg_body_example = (
        surfaced_credential[:5] + "EXAMPLEEXAMPLE" + surfaced_credential[-5:]
        if len(surfaced_credential) > 10
        else surfaced_credential + "_EXAMPLE"
    )
    neg_text1 = positive_text.replace(surfaced_credential, neg_body_placeholder, 1)
    neg_text2 = positive_text.replace(surfaced_credential, neg_body_example, 1)
    evasion_text = _evasion_text(positive_text, surfaced_credential)
    perf_micros = 25000 if severity in ("high", "critical") else 35000

    return f"""schema_version = 1
detector_id = "{detector_id}"
service = "{service}"
severity = "{severity}"

[[positive]]
text = {_toml_str(positive_text)}
credential = {_toml_str(surfaced_credential)}
reason = "Canonical anchor + synthesized body satisfying detector's primary regex."

[[positive]]
text = {_toml_str(positive2_text)}
credential = {_toml_str(surfaced_credential)}
reason = "Quoted-value variant of the canonical positive."

[[negative]]
text = {_toml_str(neg_text1)}
reason = "Placeholder-keyword body - suppression gate matches PLACEHOLDER prefix."

[[negative]]
text = {_toml_str(neg_text2)}
reason = "EXAMPLE token marker inside the body - suppression gate strips it."

[[evasion]]
text = {_toml_str(evasion_text)}
credential = {_toml_str(surfaced_credential)}
reason = "Adversarial envelope - credential must still surface under this detector."

[perf]
fixture_bytes = 4096
max_microseconds = {perf_micros}
note = "Standard single-file budget."

[scale]
fixture_bytes = 1048576
min_findings = 1
max_seconds = 2.0
note = "1 MiB filler + planted credential."

readme_claim = {_toml_str(README_CLAIM)}
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true", help="Write contract files")
    ap.add_argument("--force", action="store_true", help="Overwrite existing contracts")
    ap.add_argument("--ids-file", type=pathlib.Path, help="Newline-separated detector IDs")
    ap.add_argument("--only", help="Glob filter on detector id")
    ap.add_argument(
        "--validate",
        action="store_true",
        help="Run contracts_runner after writing and record chunk failures",
    )
    ap.add_argument(
        "--failures-out",
        type=pathlib.Path,
        default=DEFAULT_FAILURES_OUT,
        help="Validation failure report path",
    )
    args = ap.parse_args()

    existing = {p.stem for p in CONTRACTS.glob("*.toml")}
    if args.ids_file:
        ids = [
            line.strip()
            for line in args.ids_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    else:
        ids = sorted(p.stem for p in DETECTORS.glob("*.toml"))

    if args.only:
        import fnmatch

        ids = [i for i in ids if fnmatch.fnmatch(i, args.only)]

    written = skipped = 0
    skipped_ids: list[str] = []
    created_ids: list[str] = []

    for file_stem in ids:
        det_path = DETECTORS / f"{file_stem}.toml"
        if not det_path.exists():
            skipped += 1
            skipped_ids.append(file_stem)
            continue
        try:
            det = load_toml(det_path)
        except Exception:
            skipped += 1
            skipped_ids.append(file_stem)
            continue
        detector_id = spec_detector_id(det, file_stem)
        if detector_id in existing and not args.force:
            continue
        toml = build_full_contract(det, detector_id)
        if toml is None:
            skipped += 1
            skipped_ids.append(file_stem)
            continue
        if args.write:
            (CONTRACTS / f"{detector_id}.toml").write_text(toml)
        written += 1
        created_ids.append(detector_id)

    failed_ids: list[str] = []
    if args.validate and args.write and created_ids:
        proc = subprocess.run(
            [
                "cargo",
                "test",
                "-p",
                "keyhog-scanner",
                "--test",
                "contracts_runner",
                "--profile",
                "release-fast",
                "--",
                "every_contract",
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
        )
        blob = proc.stdout + "\n" + proc.stderr
        id_set = set(created_ids)
        for line in blob.splitlines():
            for detector_id in id_set:
                if line.startswith(f"{detector_id}:") and detector_id not in failed_ids:
                    failed_ids.append(detector_id)
                    break
        args.failures_out.parent.mkdir(parents=True, exist_ok=True)
        lines: list[str] = [f"# contract validation failures ({len(failed_ids)} of {len(created_ids)} chunk IDs)\n"]
        if skipped_ids:
            lines.append(f"\n# Generation blockers ({len(skipped_ids)})\n")
            for sid in skipped_ids:
                lines.append(f"- {sid}\n")
        if failed_ids:
            lines.append(f"\n# contracts_runner failures\n")
            for fid in failed_ids:
                lines.append(f"\n## {fid}\n")
                for line in blob.splitlines():
                    if line.startswith(f"  - {fid}:"):
                        lines.append(f"- {line.strip()[2:]}\n")
        if failed_ids or skipped_ids:
            args.failures_out.write_text("".join(lines), encoding="utf-8")

    print(f"written={written} skipped={len(skipped_ids)} failed={len(failed_ids)}")
    if skipped_ids:
        print("skipped:", ", ".join(skipped_ids), file=sys.stderr)
    return 1 if skipped_ids or failed_ids else 0


if __name__ == "__main__":
    raise SystemExit(main())
