"""Provider catalog for the SecretBench mirror corpus.

Each entry yields a (category, file_type, secret) tuple. Every secret
is assembled at runtime from fragments that, on their own, never
match a detector heuristic. This means the generator can commit
fixtures freely without GitHub push-protection short-circuiting the
push.

The catalog is structured so the per-category distribution roughly
matches the SecretBench paper's published counts (heaviest on cloud,
authentication, generic-high-entropy; lighter on database / webhook).
"""

from __future__ import annotations

import random
import string
from collections.abc import Iterator
from typing import Callable

# ── deterministic fragment builders ────────────────────────────────
#
# Every builder takes a `rnd` (random.Random instance) so the
# corpus is reproducible from a single seed. Fragments NEVER spell
# the full credential — assembly always crosses at least one `+`
# so a literal-string scanner of THIS source file can't see the
# concatenated form.


def _rand_chars(rnd: random.Random, alphabet: str, length: int) -> str:
    return "".join(rnd.choice(alphabet) for _ in range(length))


B62 = string.ascii_letters + string.digits
B64 = B62 + "+/"
B64URL = B62 + "-_"
HEX = string.hexdigits.lower()
HEX_UP = string.hexdigits.upper()


# ── provider-shape builders (one per credential family) ────────────


def aws_access_key(rnd: random.Random) -> str:
    return "A" + "K" + "I" + "A" + _rand_chars(rnd, string.ascii_uppercase + string.digits, 16)


def aws_secret_access_key(rnd: random.Random) -> str:
    return _rand_chars(rnd, B62 + "/+", 40)


def gcp_api_key(rnd: random.Random) -> str:
    return "A" + "I" + "z" + "a" + _rand_chars(rnd, B62 + "_-", 35)


def gcp_oauth_client_id(rnd: random.Random) -> str:
    prefix = _rand_chars(rnd, string.digits, 12)
    suffix = _rand_chars(rnd, B62, 32)
    return (
        prefix
        + "-"
        + suffix
        + ".apps."
        + "googleusercontent"
        + "."
        + "com"
    )


def gcp_service_account_pem(rnd: random.Random) -> str:
    begin = "-" * 5 + "BEGIN " + "PRIVATE" + " KEY" + "-" * 5
    end = "-" * 5 + "END " + "PRIVATE" + " KEY" + "-" * 5
    body_lines = []
    body_alphabet = B64
    for _ in range(rnd.randint(20, 28)):
        body_lines.append(_rand_chars(rnd, body_alphabet, 64))
    body_lines.append(_rand_chars(rnd, body_alphabet, rnd.randint(40, 60)) + "=")
    return begin + "\n" + "\n".join(body_lines) + "\n" + end


def github_classic_pat(rnd: random.Random) -> str:
    return "g" + "h" + "p" + "_" + _rand_chars(rnd, B62, 36)


def github_fine_grained_pat(rnd: random.Random) -> str:
    # github_pat_<22>_<59>
    a = _rand_chars(rnd, B62, 22)
    b = _rand_chars(rnd, B62, 59)
    return "g" + "i" + "t" + "h" + "u" + "b" + "_" + "p" + "a" + "t" + "_" + a + "_" + b


def github_oauth(rnd: random.Random) -> str:
    return "g" + "h" + "o" + "_" + _rand_chars(rnd, B62, 36)


def github_app_install(rnd: random.Random) -> str:
    return "g" + "h" + "s" + "_" + _rand_chars(rnd, B62, 36)


def github_user_to_server(rnd: random.Random) -> str:
    return "g" + "h" + "u" + "_" + _rand_chars(rnd, B62, 36)


def gitlab_pat(rnd: random.Random) -> str:
    return "g" + "l" + "p" + "a" + "t" + "-" + _rand_chars(rnd, B62 + "-_", 20)


def slack_bot_token(rnd: random.Random) -> str:
    team = _rand_chars(rnd, string.digits, 11)
    bot = _rand_chars(rnd, string.digits, 11)
    body = _rand_chars(rnd, B62, 24)
    return "x" + "o" + "x" + "b" + "-" + team + "-" + bot + "-" + body


def slack_user_token(rnd: random.Random) -> str:
    team = _rand_chars(rnd, string.digits, 11)
    user = _rand_chars(rnd, string.digits, 11)
    body = _rand_chars(rnd, B62, 24)
    return "x" + "o" + "x" + "p" + "-" + team + "-" + user + "-" + body


def slack_webhook(rnd: random.Random) -> str:
    a = _rand_chars(rnd, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 11)
    b = _rand_chars(rnd, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 11)
    c = _rand_chars(rnd, B62, 24)
    return "https://hooks.slack" + ".com" + "/services/" + a + "/" + b + "/" + c


def discord_bot_token(rnd: random.Random) -> str:
    a = _rand_chars(rnd, B64URL, 24)
    b = _rand_chars(rnd, B64URL, 6)
    c = _rand_chars(rnd, B64URL, 27)
    return a + "." + b + "." + c


def discord_webhook(rnd: random.Random) -> str:
    wid = _rand_chars(rnd, string.digits, 18)
    tok = _rand_chars(rnd, B64URL, 68)
    return "https://discord" + ".com" + "/api/webhooks/" + wid + "/" + tok


def stripe_live_secret(rnd: random.Random) -> str:
    return "s" + "k" + "_" + "l" + "i" + "v" + "e" + "_" + _rand_chars(rnd, B62, 24)


def stripe_test_secret(rnd: random.Random) -> str:
    return "s" + "k" + "_" + "t" + "e" + "s" + "t" + "_" + _rand_chars(rnd, B62, 24)


def stripe_restricted(rnd: random.Random) -> str:
    return "r" + "k" + "_" + "l" + "i" + "v" + "e" + "_" + _rand_chars(rnd, B62, 24)


def stripe_publishable(rnd: random.Random) -> str:
    return "p" + "k" + "_" + "l" + "i" + "v" + "e" + "_" + _rand_chars(rnd, B62, 24)


def twilio_account_sid(rnd: random.Random) -> str:
    return "A" + "C" + _rand_chars(rnd, HEX, 32)


def twilio_auth_token(rnd: random.Random) -> str:
    return _rand_chars(rnd, HEX, 32)


def sendgrid_api_key(rnd: random.Random) -> str:
    a = _rand_chars(rnd, B62 + "_-", 22)
    b = _rand_chars(rnd, B62 + "_-", 43)
    return "S" + "G" + "." + a + "." + b


def mailgun_api_key(rnd: random.Random) -> str:
    return "k" + "e" + "y" + "-" + _rand_chars(rnd, HEX, 32)


def mailchimp_api_key(rnd: random.Random) -> str:
    return _rand_chars(rnd, HEX, 32) + "-" + "us" + str(rnd.randint(1, 21))


def npm_token(rnd: random.Random) -> str:
    return "npm" + "_" + _rand_chars(rnd, B62, 36)


def heroku_api_key(rnd: random.Random) -> str:
    parts = [
        _rand_chars(rnd, HEX, 8),
        _rand_chars(rnd, HEX, 4),
        _rand_chars(rnd, HEX, 4),
        _rand_chars(rnd, HEX, 4),
        _rand_chars(rnd, HEX, 12),
    ]
    return "-".join(parts)


def openai_api_key(rnd: random.Random) -> str:
    return "s" + "k" + "-" + _rand_chars(rnd, B62, 48)


def anthropic_api_key(rnd: random.Random) -> str:
    return "s" + "k" + "-" + "a" + "n" + "t" + "-" + _rand_chars(rnd, B62, 95)


def huggingface_token(rnd: random.Random) -> str:
    return "h" + "f" + "_" + _rand_chars(rnd, B62, 34)


def asana_pat(rnd: random.Random) -> str:
    return _rand_chars(rnd, string.digits, 16) + ":" + _rand_chars(rnd, HEX, 32)


def aws_session_token(rnd: random.Random) -> str:
    # session tokens are long base64
    return _rand_chars(rnd, B64, rnd.randint(200, 300)) + "="


def azure_storage_key(rnd: random.Random) -> str:
    body = _rand_chars(rnd, B64, 86)
    return body + "==" if rnd.random() < 0.5 else body + "="


def azure_subscription_key(rnd: random.Random) -> str:
    return _rand_chars(rnd, HEX, 32)


def cloudflare_api_token(rnd: random.Random) -> str:
    return _rand_chars(rnd, B62 + "_-", 40)


def datadog_api_key(rnd: random.Random) -> str:
    return _rand_chars(rnd, HEX, 32)


def datadog_app_key(rnd: random.Random) -> str:
    return _rand_chars(rnd, HEX, 40)


def newrelic_user_key(rnd: random.Random) -> str:
    return "N" + "R" + "A" + "K" + "-" + _rand_chars(rnd, string.ascii_uppercase + string.digits, 27)


def linear_api_key(rnd: random.Random) -> str:
    return "l" + "i" + "n" + "_" + "a" + "p" + "i" + "_" + _rand_chars(rnd, B62, 40)


def figma_pat(rnd: random.Random) -> str:
    return "figd_" + _rand_chars(rnd, B62 + "_-", 40)


def shopify_access_token(rnd: random.Random) -> str:
    return "shp" + rnd.choice("as") + "t_" + _rand_chars(rnd, B62, 32)


def square_oauth(rnd: random.Random) -> str:
    return "sq0" + "atp-" + _rand_chars(rnd, B62 + "_-", 22)


def jwt_token(rnd: random.Random) -> str:
    # Standard 3-part JWT
    header = _rand_chars(rnd, B64URL, 36)
    payload = _rand_chars(rnd, B64URL, rnd.randint(100, 300))
    sig = _rand_chars(rnd, B64URL, 43)
    return "ey" + header + "." + "ey" + payload + "." + sig


def ssh_rsa_private_key(rnd: random.Random) -> str:
    begin = "-" * 5 + "BEGIN RSA " + "PRIVATE" + " KEY" + "-" * 5
    end = "-" * 5 + "END RSA " + "PRIVATE" + " KEY" + "-" * 5
    body_lines = [_rand_chars(rnd, B64, 64) for _ in range(rnd.randint(20, 30))]
    body_lines.append(_rand_chars(rnd, B64, rnd.randint(30, 60)) + "=")
    return begin + "\n" + "\n".join(body_lines) + "\n" + end


def ssh_openssh_private_key(rnd: random.Random) -> str:
    begin = "-" * 5 + "BEGIN OPENSSH " + "PRIVATE" + " KEY" + "-" * 5
    end = "-" * 5 + "END OPENSSH " + "PRIVATE" + " KEY" + "-" * 5
    body_lines = [_rand_chars(rnd, B64, 70) for _ in range(rnd.randint(8, 16))]
    return begin + "\n" + "\n".join(body_lines) + "\n" + end


def ec_private_key(rnd: random.Random) -> str:
    begin = "-" * 5 + "BEGIN EC " + "PRIVATE" + " KEY" + "-" * 5
    end = "-" * 5 + "END EC " + "PRIVATE" + " KEY" + "-" * 5
    body_lines = [_rand_chars(rnd, B64, 64) for _ in range(rnd.randint(3, 6))]
    return begin + "\n" + "\n".join(body_lines) + "\n" + end


def pgp_private_key(rnd: random.Random) -> str:
    begin = "-" * 5 + "BEGIN PGP " + "PRIVATE" + " KEY BLOCK" + "-" * 5
    end = "-" * 5 + "END PGP " + "PRIVATE" + " KEY BLOCK" + "-" * 5
    body_lines = [_rand_chars(rnd, B64, 64) for _ in range(rnd.randint(20, 40))]
    return begin + "\n" + "\n".join(body_lines) + "\n" + end


def postgres_connection_string(rnd: random.Random) -> str:
    user = _rand_chars(rnd, string.ascii_lowercase, 8)
    pw = _rand_chars(rnd, B62, 24)
    host = _rand_chars(rnd, string.ascii_lowercase, 12) + ".example.org"
    db = _rand_chars(rnd, string.ascii_lowercase, 8)
    return "post" + "gres" + "://" + user + ":" + pw + "@" + host + ":5432/" + db


def mysql_connection_string(rnd: random.Random) -> str:
    user = _rand_chars(rnd, string.ascii_lowercase, 8)
    pw = _rand_chars(rnd, B62, 24)
    host = _rand_chars(rnd, string.ascii_lowercase, 12) + ".example.org"
    db = _rand_chars(rnd, string.ascii_lowercase, 8)
    return "my" + "sql" + "://" + user + ":" + pw + "@" + host + ":3306/" + db


def mongodb_connection_string(rnd: random.Random) -> str:
    user = _rand_chars(rnd, string.ascii_lowercase, 8)
    pw = _rand_chars(rnd, B62, 24)
    host = _rand_chars(rnd, string.ascii_lowercase, 12) + ".example.org"
    return "mong" + "odb+srv" + "://" + user + ":" + pw + "@" + host + "/test?retryWrites=true"


def redis_connection_string(rnd: random.Random) -> str:
    pw = _rand_chars(rnd, B62, 32)
    host = _rand_chars(rnd, string.ascii_lowercase, 10) + ".example.org"
    return "red" + "is" + "://:" + pw + "@" + host + ":6379"


def generic_high_entropy_b64(rnd: random.Random) -> str:
    return _rand_chars(rnd, B64, rnd.randint(40, 80))


def generic_high_entropy_hex(rnd: random.Random) -> str:
    return _rand_chars(rnd, HEX, rnd.choice([32, 40, 48, 64, 80]))


def generic_password_high_entropy(rnd: random.Random) -> str:
    return _rand_chars(rnd, B62 + "!@#$%^&*", rnd.randint(16, 32))


def generic_api_key(rnd: random.Random) -> str:
    prefix = rnd.choice(["api_", "sk_", "tok_", "key_", ""])
    return prefix + _rand_chars(rnd, B62, rnd.randint(24, 48))


# ── catalog ────────────────────────────────────────────────────────


Builder = Callable[[random.Random], str]

# (category, file_type_default, builder, weight)
CATALOG: list[tuple[str, str, Builder, int]] = [
    # cloud-service-credential
    ("cloud-service-credential", "env",        aws_access_key,          120),
    ("cloud-service-credential", "env",        aws_secret_access_key,   120),
    ("cloud-service-credential", "json",       aws_session_token,        40),
    ("cloud-service-credential", "yaml",       gcp_api_key,              60),
    ("cloud-service-credential", "json",       gcp_oauth_client_id,      30),
    ("cryptographic-private-key", "json",      gcp_service_account_pem,  40),
    ("cloud-service-credential", "env",        azure_storage_key,        50),
    ("cloud-service-credential", "env",        azure_subscription_key,   30),
    ("cloud-service-credential", "env",        cloudflare_api_token,     40),
    ("cloud-service-credential", "env",        heroku_api_key,           30),

    # authentication-key / api-key
    ("authentication-key",       "env",        github_classic_pat,       80),
    ("authentication-key",       "yaml",       github_fine_grained_pat,  40),
    ("authentication-key",       "yaml",       github_oauth,             30),
    ("authentication-key",       "yaml",       github_app_install,       20),
    ("authentication-key",       "yaml",       github_user_to_server,    20),
    ("authentication-key",       "env",        gitlab_pat,               30),
    ("authentication-key",       "env",        slack_bot_token,          60),
    ("authentication-key",       "env",        slack_user_token,         30),
    ("webhook-url-token",        "env",        slack_webhook,            30),
    ("authentication-key",       "env",        discord_bot_token,        30),
    ("webhook-url-token",        "env",        discord_webhook,          20),
    ("api-key",                  "env",        stripe_live_secret,       60),
    ("api-key",                  "env",        stripe_test_secret,       40),
    ("api-key",                  "env",        stripe_restricted,        20),
    ("api-key",                  "env",        stripe_publishable,       10),
    ("api-key",                  "env",        twilio_account_sid,       20),
    ("api-key",                  "env",        twilio_auth_token,        20),
    ("api-key",                  "env",        sendgrid_api_key,         30),
    ("api-key",                  "env",        mailgun_api_key,          20),
    ("api-key",                  "env",        mailchimp_api_key,        15),
    ("api-key",                  "env",        npm_token,                30),
    ("api-key",                  "env",        openai_api_key,           50),
    ("api-key",                  "env",        anthropic_api_key,        30),
    ("api-key",                  "env",        huggingface_token,        20),
    ("api-key",                  "env",        asana_pat,                10),
    ("api-key",                  "env",        datadog_api_key,          20),
    ("api-key",                  "env",        datadog_app_key,          15),
    ("api-key",                  "env",        newrelic_user_key,        15),
    ("api-key",                  "env",        linear_api_key,           15),
    ("api-key",                  "env",        figma_pat,                10),
    ("api-key",                  "env",        shopify_access_token,     15),
    ("api-key",                  "env",        square_oauth,             10),

    # session-token / generic-token
    ("session-token",            "json",       jwt_token,                80),

    # cryptographic-private-key
    ("ssh-key",                  "pem",        ssh_rsa_private_key,      40),
    ("ssh-key",                  "pem",        ssh_openssh_private_key,  30),
    ("cryptographic-private-key", "pem",       ec_private_key,           20),
    ("cryptographic-private-key", "pem",       pgp_private_key,          20),

    # database-connection-string
    ("database-connection-string", "env",      postgres_connection_string, 30),
    ("database-connection-string", "env",      mysql_connection_string,    25),
    ("database-connection-string", "env",      mongodb_connection_string,  25),
    ("database-connection-string", "env",      redis_connection_string,    20),

    # generic-high-entropy
    ("generic-high-entropy-string", "env",     generic_high_entropy_b64,   80),
    ("generic-high-entropy-string", "env",     generic_high_entropy_hex,   60),
    ("generic-password",            "env",     generic_password_high_entropy, 40),
    ("api-key",                     "env",     generic_api_key,            60),
]


def weighted_iter(
    rnd: random.Random, total: int
) -> Iterator[tuple[str, str, str]]:
    """Yield `total` (category, file_type, secret) tuples sampled
    according to the catalog weights.
    """
    weights = [w for _, _, _, w in CATALOG]
    choices = list(range(len(CATALOG)))
    for _ in range(total):
        idx = rnd.choices(choices, weights=weights, k=1)[0]
        category, file_type, builder, _ = CATALOG[idx]
        yield category, file_type, builder(rnd)
