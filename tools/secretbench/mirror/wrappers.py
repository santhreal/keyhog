"""Wrapper formats — embed a credential in a realistic file shape.

Each wrapper returns (file_extension, contents). Wrappers are chosen
randomly per positive so the generated corpus has wide format
coverage: .env, YAML, JSON, Dockerfile, shell export, INI, k8s
Secret, GitHub-Actions step, Terraform, Helm, Python source, JS
source, Rust source, log line.
"""

from __future__ import annotations

import base64
import json
import random
from typing import Callable

# (display_name, extension, builder)
Wrapper = tuple[str, str, Callable[[str, random.Random], str]]


def _dotenv(secret: str, rnd: random.Random) -> str:
    key = rnd.choice([
        "API_KEY", "SECRET_KEY", "AUTH_TOKEN", "ACCESS_KEY",
        "PRIVATE_KEY", "DB_URL", "WEBHOOK_URL", "TOKEN",
    ])
    return f"{key}={secret}\n"


def _yaml(secret: str, rnd: random.Random) -> str:
    key = rnd.choice(["api_key", "secret_key", "token", "auth"])
    return f"config:\n  {key}: \"{secret}\"\n  enabled: true\n"


def _json(secret: str, rnd: random.Random) -> str:
    key = rnd.choice(["apiKey", "secretKey", "token", "auth"])
    return json.dumps({key: secret, "ttl": 3600}, indent=2) + "\n"


def _dockerfile(secret: str, rnd: random.Random) -> str:
    key = rnd.choice(["API_KEY", "SECRET", "TOKEN"])
    return f"FROM alpine:3.18\nENV {key}={secret}\nCMD [\"/bin/true\"]\n"


def _shell_export(secret: str, rnd: random.Random) -> str:
    key = rnd.choice(["API_KEY", "SECRET", "TOKEN"])
    return f"#!/bin/bash\nset -euo pipefail\nexport {key}=\"{secret}\"\n./deploy.sh\n"


def _ini(secret: str, rnd: random.Random) -> str:
    section = rnd.choice(["credentials", "default", "production"])
    key = rnd.choice(["api_key", "secret", "token"])
    return f"[{section}]\n{key} = {secret}\n"


def _k8s_secret(secret: str, rnd: random.Random) -> str:
    encoded = base64.b64encode(secret.encode()).decode()
    key = rnd.choice(["api-key", "token", "secret-key"])
    return (
        "apiVersion: v1\n"
        "kind: Secret\n"
        f"metadata:\n  name: {key}-secret\n"
        "type: Opaque\n"
        f"data:\n  {key}: {encoded}\n"
    )


def _gh_actions(secret: str, rnd: random.Random) -> str:
    env = rnd.choice(["API_KEY", "DEPLOY_TOKEN", "REGISTRY_AUTH"])
    return (
        "name: deploy\n"
        "on: [push]\n"
        "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    env:\n"
        f"      {env}: {secret}\n"
        "    steps:\n      - run: ./deploy.sh\n"
    )


def _terraform(secret: str, rnd: random.Random) -> str:
    var = rnd.choice(["api_key", "deploy_token", "secret"])
    return (
        f"variable \"{var}\" {{\n  type    = string\n  default = \"{secret}\"\n}}\n"
        "\nresource \"null_resource\" \"deploy\" {}\n"
    )


def _helm(secret: str, rnd: random.Random) -> str:
    key = rnd.choice(["apiKey", "secret"])
    return (
        "replicaCount: 1\n"
        f"image:\n  repository: nginx\n  tag: \"1.25\"\n"
        f"env:\n  {key}: \"{secret}\"\n"
    )


def _py(secret: str, rnd: random.Random) -> str:
    name = rnd.choice(["API_KEY", "TOKEN", "SECRET"])
    return (
        "import requests\n\n"
        f"{name} = \"{secret}\"\n"
        f"def call():\n    return requests.get('https://api.example.org', headers={{'auth': {name}}})\n"
    )


def _js(secret: str, rnd: random.Random) -> str:
    name = rnd.choice(["API_KEY", "TOKEN", "SECRET"])
    return (
        f"const {name} = \"{secret}\";\n"
        f"export async function call() {{\n  return fetch('https://api.example.org', "
        f"{{ headers: {{ auth: {name} }} }});\n}}\n"
    )


def _rust(secret: str, rnd: random.Random) -> str:
    name = rnd.choice(["API_KEY", "TOKEN", "SECRET"])
    return (
        f"const {name}: &str = \"{secret}\";\n\n"
        "pub fn call() -> reqwest::Result<reqwest::blocking::Response> {\n"
        f"    reqwest::blocking::Client::new().get(\"https://api.example.org\").header(\"auth\", {name}).send()\n}}\n"
    )


def _go(secret: str, rnd: random.Random) -> str:
    name = rnd.choice(["apiKey", "token", "secret"])
    return (
        "package main\n\nimport \"net/http\"\n\n"
        f"const {name} = \"{secret}\"\n\n"
        f"func call() (*http.Response, error) {{\n"
        f"\treq, _ := http.NewRequest(\"GET\", \"https://api.example.org\", nil)\n"
        f"\treq.Header.Set(\"auth\", {name})\n"
        f"\treturn http.DefaultClient.Do(req)\n}}\n"
    )


def _log_line(secret: str, rnd: random.Random) -> str:
    ts = "2026-05-23T10:00:42.137Z"
    return (
        f"{ts} INFO outbound_request "
        f"endpoint=/api/v1/charge auth_token={secret} status=200 latency_ms=83\n"
    )


def _properties(secret: str, rnd: random.Random) -> str:
    key = rnd.choice(["api.key", "auth.token", "secret"])
    return f"# Application configuration\n{key}={secret}\n"


def _pem_file(secret: str, _rnd: random.Random) -> str:
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
