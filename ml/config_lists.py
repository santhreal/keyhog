"""Serve-path detector keyword lists, mirrored from
`crates/core/src/config.rs` (`ScanConfig::default`).

These are the lists the scanner passes to `score_with_config` at runtime, so
both the parity harness and the trainer must compute features with exactly
these to avoid train/serve skew. Single source of truth for the Python side;
keep in sync with config.rs.
"""

from __future__ import annotations

KNOWN_PREFIXES = ["AKIA", "ASIA", "ghp_", "sk_"]

SECRET_KEYWORDS = [
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "api-key", "access_key", "auth_token", "auth_key", "private_key",
    "client_secret", "encryption_key", "signing_key", "bearer", "credential",
    "license_key",
]

TEST_KEYWORDS = [
    "test", "mock", "fake", "dummy", "stub", "fixture", "example", "sample",
    "sandbox", "staging",
]

PLACEHOLDER_KEYWORDS = [
    "change_me", "changeme", "replace_me", "todo", "fixme", "your_", "insert_",
    "put_your", "fill_in", "<your",
]

DEFAULT_LISTS = (KNOWN_PREFIXES, SECRET_KEYWORDS, TEST_KEYWORDS, PLACEHOLDER_KEYWORDS)
EMPTY_LISTS = ([], [], [], [])
