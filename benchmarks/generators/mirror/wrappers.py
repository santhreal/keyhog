"""Wrapper formats — embed a credential in a realistic file shape.

Each builder takes ``(secret, rnd, key_override)`` and returns the file
CONTENTS (a str). Wrappers are chosen randomly per positive so the generated
corpus has wide format coverage: .env, YAML, JSON, Dockerfile, shell export,
INI, k8s Secret, GitHub-Actions step, Terraform, Helm, Python source, JS
source, Rust source, log line. The extension travels alongside the builder in
the :data:`Wrapper` tuple, not as a return value.
"""

from __future__ import annotations

import base64
import json
import random
from typing import Callable, Optional

# builder(secret, rnd, key_override) -> file contents
WrapperFn = Callable[[str, random.Random, Optional[str]], str]
# (display_name, extension, builder)
Wrapper = tuple[str, str, WrapperFn]


# All wrappers accept an optional `key_override` so the generator
# can splice in real-world service-anchor keys (e.g. AWS_SECRET_ACCESS_KEY)
# 70% of the time. When None, the wrapper picks from its generic pool.

def _pick(rnd: random.Random, override: str | None, pool: list[str], *, lower: bool = False) -> str:
    if override is not None:
        return override.lower() if lower else override
    return rnd.choice(pool)


def _dotenv(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    key = _pick(rnd, key_override, [
        "API_KEY", "SECRET_KEY", "AUTH_TOKEN", "ACCESS_KEY",
        "PRIVATE_KEY", "DB_URL", "WEBHOOK_URL", "TOKEN",
    ])
    return f"{key}={secret}\n"


def _yaml(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    key = _pick(rnd, key_override, ["api_key", "secret_key", "token", "auth"], lower=True)
    return f"config:\n  {key}: \"{secret}\"\n  enabled: true\n"


def _json(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    # JSON keys typically use camelCase. If overriding with a SCREAMING_SNAKE
    # env var, lowercase it to camelCase first segment.
    if key_override is not None:
        key = key_override
    else:
        key = rnd.choice(["apiKey", "secretKey", "token", "auth"])
    return json.dumps({key: secret, "ttl": 3600}, indent=2) + "\n"


def _dockerfile(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    key = _pick(rnd, key_override, ["API_KEY", "SECRET", "TOKEN"])
    return f"FROM alpine:3.18\nENV {key}={secret}\nCMD [\"/bin/true\"]\n"


def _shell_export(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    key = _pick(rnd, key_override, ["API_KEY", "SECRET", "TOKEN"])
    return f"#!/bin/bash\nset -euo pipefail\nexport {key}=\"{secret}\"\n./deploy.sh\n"


def _ini(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    section = rnd.choice(["credentials", "default", "production"])
    key = _pick(rnd, key_override, ["api_key", "secret", "token"], lower=True)
    return f"[{section}]\n{key} = {secret}\n"


def _k8s_secret(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    encoded = base64.b64encode(secret.encode()).decode()
    # k8s data keys use kebab-case; lowercase and dash-ify the override.
    if key_override is not None:
        key = key_override.lower().replace("_", "-")
    else:
        key = rnd.choice(["api-key", "token", "secret-key"])
    return (
        "apiVersion: v1\n"
        "kind: Secret\n"
        f"metadata:\n  name: {key}-secret\n"
        "type: Opaque\n"
        f"data:\n  {key}: {encoded}\n"
    )


def _gh_actions(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    env = _pick(rnd, key_override, ["API_KEY", "DEPLOY_TOKEN", "REGISTRY_AUTH"])
    return (
        "name: deploy\n"
        "on: [push]\n"
        "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    env:\n"
        f"      {env}: {secret}\n"
        "    steps:\n      - run: ./deploy.sh\n"
    )


def _terraform(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    var = _pick(rnd, key_override, ["api_key", "deploy_token", "secret"], lower=True)
    return (
        f"variable \"{var}\" {{\n  type    = string\n  default = \"{secret}\"\n}}\n"
        "\nresource \"null_resource\" \"deploy\" {}\n"
    )


def _helm(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    # Helm values use camelCase by convention; override env-var → camelCase first segment lowercased.
    if key_override is not None:
        # E.g. "AWS_SECRET_ACCESS_KEY" → "awsSecretAccessKey"
        parts = key_override.split("_")
        key = parts[0].lower() + "".join(p.title() for p in parts[1:])
    else:
        key = rnd.choice(["apiKey", "secret"])
    return (
        "replicaCount: 1\n"
        f"image:\n  repository: nginx\n  tag: \"1.25\"\n"
        f"env:\n  {key}: \"{secret}\"\n"
    )


def _py(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    name = _pick(rnd, key_override, ["API_KEY", "TOKEN", "SECRET"])
    return (
        "import requests\n\n"
        f"{name} = \"{secret}\"\n"
        f"def call():\n    return requests.get('https://api.example.org', headers={{'auth': {name}}})\n"
    )


def _js(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    name = _pick(rnd, key_override, ["API_KEY", "TOKEN", "SECRET"])
    return (
        f"const {name} = \"{secret}\";\n"
        f"export async function call() {{\n  return fetch('https://api.example.org', "
        f"{{ headers: {{ auth: {name} }} }});\n}}\n"
    )


def _rust(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    name = _pick(rnd, key_override, ["API_KEY", "TOKEN", "SECRET"])
    return (
        f"const {name}: &str = \"{secret}\";\n\n"
        "pub fn call() -> reqwest::Result<reqwest::blocking::Response> {\n"
        f"    reqwest::blocking::Client::new().get(\"https://api.example.org\").header(\"auth\", {name}).send()\n}}\n"
    )


def _go(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    # Go const conventionally uses camelCase first-lower
    if key_override is not None:
        parts = key_override.split("_")
        name = parts[0].lower() + "".join(p.title() for p in parts[1:])
    else:
        name = rnd.choice(["apiKey", "token", "secret"])
    return (
        "package main\n\nimport \"net/http\"\n\n"
        f"const {name} = \"{secret}\"\n\n"
        f"func call() (*http.Response, error) {{\n"
        f"\treq, _ := http.NewRequest(\"GET\", \"https://api.example.org\", nil)\n"
        f"\treq.Header.Set(\"auth\", {name})\n"
        f"\treturn http.DefaultClient.Do(req)\n}}\n"
    )


def _log_line(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    ts = "2026-05-23T10:00:42.137Z"
    field = key_override.lower() if key_override is not None else "auth_token"
    return (
        f"{ts} INFO outbound_request "
        f"endpoint=/api/v1/charge {field}={secret} status=200 latency_ms=83\n"
    )


def _properties(secret: str, rnd: random.Random, key_override: str | None = None) -> str:
    if key_override is not None:
        key = key_override.lower().replace("_", ".")
    else:
        key = rnd.choice(["api.key", "auth.token", "secret"])
    return f"# Application configuration\n{key}={secret}\n"


def _pem_file(secret: str, _rnd: random.Random, key_override: str | None = None) -> str:
    # PEM blocks already include their full BEGIN/END framing.
    return secret + "\n"


WRAPPERS: dict[str, list[Wrapper]] = {
    # Map default file_type from the catalog to the LIST of plausible
    # wrappers. The generator picks one per positive at random.
    "env": [
        ("dotenv", "env", _dotenv),
        ("yaml", "yaml", _yaml),
        ("json", "json", _json),
        ("dockerfile", "Dockerfile", _dockerfile),
        ("shell-export", "sh", _shell_export),
        ("ini", "ini", _ini),
        ("k8s-secret", "yaml", _k8s_secret),
        ("github-actions", "yaml", _gh_actions),
        ("terraform", "tf", _terraform),
        ("helm-values", "yaml", _helm),
        ("python", "py", _py),
        ("javascript", "js", _js),
        ("rust", "rs", _rust),
        ("go", "go", _go),
        ("log-line", "log", _log_line),
        ("properties", "properties", _properties),
    ],
    "yaml": [
        ("yaml", "yaml", _yaml),
        ("k8s-secret", "yaml", _k8s_secret),
        ("github-actions", "yaml", _gh_actions),
        ("helm-values", "yaml", _helm),
    ],
    "json": [
        ("json", "json", _json),
        ("k8s-secret", "yaml", _k8s_secret),
    ],
    "pem": [
        ("pem-file", "pem", _pem_file),
    ],
}


def pick_wrapper(file_type_default: str, rnd: random.Random) -> Wrapper:
    pool = WRAPPERS.get(file_type_default) or WRAPPERS["env"]
    return rnd.choice(pool)


def pick_anchor_key(
    rnd: random.Random,
    anchors: list[str],
    *,
    service_anchor_probability: float = 0.7,
) -> str | None:
    """Decide whether to use a service-specific anchor key for this fixture.

    Returns one of `anchors` with probability `service_anchor_probability`
    (defaulting to 0.7 = 70%). Returns None otherwise, signaling the
    wrapper to fall back to its generic-key pool. This split keeps
    generic-secret detection exercised on a meaningful fraction
    (~30%) of positives so we don't accidentally narrow the bench
    to service-anchored shapes only.
    """
    if not anchors:
        return None
    if rnd.random() >= service_anchor_probability:
        return None
    return rnd.choice(anchors)
