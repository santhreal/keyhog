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
# the full credential, assembly always crosses at least one `+`
# so a literal-string scanner of THIS source file can't see the
# concatenated form.


def _rand_chars(rnd: random.Random, alphabet: str, length: int) -> str:
    return "".join(rnd.choice(alphabet) for _ in range(length))


from alphabets import B62, B64, B64URL, HEX  # noqa: E402


# Tokens for several detector families (github classic/fine-grained PATs,
# npm access tokens) embed a CRC32-over-entropy checksum encoded as
# base62. Keyhog rejects fixtures with invalid checksums at the
# named-detector emit path (`scan.rs:723`), which is correct behavior
# for production scans but artificially floors bench recall on these
# families. Generate real checksums so the bench measures detector
# logic, not the fixture's CRC bookkeeping.

_GH_BASE62_DIGITS = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _crc32_iso_hdlc(data: bytes) -> int:
    # Standard CRC-32 (ISO HDLC), same polynomial and reflection that
    # keyhog's `checksum::github::crc32` uses (0xEDB88320, reflected).
    # Hand-rolled rather than `zlib.crc32` to keep the per-byte path
    # explicit + auditable against the Rust impl.
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


def _base62_encode_u32(value: int, width: int) -> str:
    # Left-pad to `width` with '0'. Matches `checksum::github::base62_encode_u32`.
    if value == 0:
        return "0" * width
    digits = []
    while value > 0:
        digits.append(chr(_GH_BASE62_DIGITS[value % 62]))
        value //= 62
    while len(digits) < width:
        digits.append("0")
    return "".join(reversed(digits))


def _crc32_base62(entropy: str, width: int = 6) -> str:
    return _base62_encode_u32(_crc32_iso_hdlc(entropy.encode()), width)


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
    # Real github_pat format: ghp_ + 30 chars entropy + 6 chars CRC32(base62).
    # The previous "ghp_ + 36 random chars" was the right SHAPE but the last
    # 6 chars never validated as the CRC of the first 30: keyhog's
    # `checksum::github::GithubClassicPatValidator` rejected bench fixtures
    # as `Invalid` and dropped them in scan.rs:723 before emit, flooring
    # github_classic_pat recall on the bench at 0%.
    entropy = _rand_chars(rnd, B62, 30)
    crc = _crc32_base62(entropy, 6)
    return "g" + "h" + "p" + "_" + entropy + crc


def github_fine_grained_pat(rnd: random.Random) -> str:
    # Real format: github_pat_<22 entropy>_<53 entropy + 6 CRC>. The
    # checksum validator tries both `full_payload` and `right_only` 
    # we generate the simpler `right_only` form (CRC over the right
    # 53-char segment), which validates the same way as a real PAT
    # rotated through GitHub's emit path.
    left = _rand_chars(rnd, B62, 22)
    right_entropy = _rand_chars(rnd, B62, 53)
    right_crc = _crc32_base62(right_entropy, 6)
    right = right_entropy + right_crc
    return "g" + "i" + "t" + "h" + "u" + "b" + "_" + "p" + "a" + "t" + "_" + left + "_" + right


def github_oauth(rnd: random.Random) -> str:
    # gho_ tokens follow the same checksum design as ghp_ classic PATs.
    entropy = _rand_chars(rnd, B62, 30)
    crc = _crc32_base62(entropy, 6)
    return "g" + "h" + "o" + "_" + entropy + crc


def github_app_install(rnd: random.Random) -> str:
    # ghs_ tokens follow the same checksum design as ghp_ classic PATs.
    entropy = _rand_chars(rnd, B62, 30)
    crc = _crc32_base62(entropy, 6)
    return "g" + "h" + "s" + "_" + entropy + crc


def github_user_to_server(rnd: random.Random) -> str:
    # ghu_ tokens follow the same checksum design as ghp_ classic PATs.
    entropy = _rand_chars(rnd, B62, 30)
    crc = _crc32_base62(entropy, 6)
    return "g" + "h" + "u" + "_" + entropy + crc


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
    # Slack webhook URLs always carry T-prefixed team IDs (workspace) and
    # B-prefixed bot/channel IDs. The previous generator emitted random
    # uppercase alphanumerics for both ID segments which doesn't match
    # any real Slack webhook (or any precise detector regex). Scanners
    # that anchor on T/B prefixes, including keyhog's slack-webhook-url
    # detector: correctly reject the old shape as not-a-webhook.
    # Bringing the synth fixture in line with the real format closes
    # the recall floor on the webhook-url-token category.
    team_id = "T" + _rand_chars(rnd, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 9)
    bot_id = "B" + _rand_chars(rnd, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 9)
    token = _rand_chars(rnd, B62, 24)
    return "https://hooks.slack" + ".com" + "/services/" + team_id + "/" + bot_id + "/" + token


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
    # Real npm format: npm_ + 30 chars entropy + 6 chars CRC32(base62).
    # Same CRC scheme as github_classic_pat (the npm token rotated to
    # this design when GitHub acquired npm).
    entropy = _rand_chars(rnd, B62, 30)
    crc = _crc32_base62(entropy, 6)
    return "npm" + "_" + entropy + crc


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
    # Real Azure storage keys never appear bare in production code 
    # they're always inside an `AccountName=...;AccountKey=<88-char
    # b64>;EndpointSuffix=core.windows.net` connection string OR
    # behind an `AZURE_STORAGE_KEY=` environment variable. The bare
    # 88-char body alone is indistinguishable from protobuf wire
    # dumps and is correctly suppressed by keyhog's base64-blob
    # gate on the generic-secret path. To measure recall on the
    # real-world Azure shape, emit the canonical connection-string
    # form so keyhog's `azure-storage-account-key` detector
    # (regex anchored on `AccountKey=`) can fire on the named-
    # detector path instead of falling back to generic-secret.
    body = _rand_chars(rnd, B64, 86)
    padding = "==" if rnd.random() < 0.5 else "="
    key = body + padding
    account = _rand_chars(rnd, string.ascii_lowercase + string.digits, rnd.randint(3, 20))
    return f"DefaultEndpointsProtocol=https;AccountName={account};AccountKey={key};EndpointSuffix=core.windows.net"


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
    # Real JWTs are base64url of a canonical JOSE header. The previous
    # generator emitted random base64url bytes prefixed with literal
    # "ey", which a JWT-aware detector (regex anchored on `eyJhbGci`,
    # i.e. base64url of `{"alg":`) rejects out of hand because the
    # random bytes after "ey" are almost never `J` followed by the
    # canonical `hbGci`. Bench JWT recall was floored at ~0% for the
    # jwt-token detector. Emit a canonical {"alg":"...","typ":"JWT"}
    # header (one of the IANA-registered algs) so the prefix anchor
    # fires; payload + signature stay random to keep entropy realistic.
    import base64
    import json
    alg = rnd.choice(["HS256", "HS384", "HS512", "RS256", "RS512", "ES256", "PS256"])
    header_json = json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode()
    header = base64.urlsafe_b64encode(header_json).rstrip(b"=").decode()
    # Payload starts with "{" → base64url begins with "eyJ", matches
    # the second `eyJ` anchor in the detector. Use a real-shape claims
    # set with sub/iat/exp so the encoded length lands in the
    # `{10,1000}` window the jwt-token detector requires.
    claims = {
        "sub": _rand_chars(rnd, string.digits, 10),
        "iat": rnd.randint(1_600_000_000, 1_800_000_000),
        "exp": rnd.randint(1_800_000_001, 2_000_000_000),
        "jti": _rand_chars(rnd, B62, 16),
    }
    payload_json = json.dumps(claims, separators=(",", ":")).encode()
    payload = base64.urlsafe_b64encode(payload_json).rstrip(b"=").decode()
    sig = _rand_chars(rnd, B64URL, 43)
    return header + "." + payload + "." + sig


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


def supabase_anon_jwt(rnd: random.Random) -> str:
    # Supabase anon/service keys are JWTs (3-segment, ey-prefixed).
    return jwt_token(rnd)


def neon_api_key(rnd: random.Random) -> str:
    return "neon_api_" + _rand_chars(rnd, B62 + "_-", 48)


def vercel_token(rnd: random.Random) -> str:
    return _rand_chars(rnd, B62, 24)


def deepgram_api_key(rnd: random.Random) -> str:
    return _rand_chars(rnd, HEX, 40)


def dbt_cloud_pat(rnd: random.Random) -> str:
    return "dbtu_" + _rand_chars(rnd, B62, 40)


def pinecone_api_key(rnd: random.Random) -> str:
    # UUID-shaped, but Pinecone keys live in `PINECONE_API_KEY=…`
    # context: the synthesizer emits the value bare and relies on
    # the wrapper to add the env-var anchor.
    return uuid_v4_str(rnd)


def uuid_v4_str(rnd: random.Random) -> str:
    parts = [
        _rand_chars(rnd, HEX, 8),
        _rand_chars(rnd, HEX, 4),
        "4" + _rand_chars(rnd, HEX, 3),
        rnd.choice("89ab") + _rand_chars(rnd, HEX, 3),
        _rand_chars(rnd, HEX, 12),
    ]
    return "-".join(parts)


def auth0_api_key(rnd: random.Random) -> str:
    return _rand_chars(rnd, B62, 64)


def algolia_admin_key(rnd: random.Random) -> str:
    return _rand_chars(rnd, HEX, 32)


def render_api_key(rnd: random.Random) -> str:
    return "rnd_" + _rand_chars(rnd, B62, 28)


def planetscale_api_token(rnd: random.Random) -> str:
    return "pscale_tkn_" + _rand_chars(rnd, B62 + "_-", 32)


def fly_api_token(rnd: random.Random) -> str:
    return "fo1_" + _rand_chars(rnd, B62 + "-_", 64)


def railway_api_token(rnd: random.Random) -> str:
    return _rand_chars(rnd, HEX, 32) + "-" + _rand_chars(rnd, HEX, 4)


def replicate_api_token(rnd: random.Random) -> str:
    return "r8_" + _rand_chars(rnd, B62, 40)


def groq_api_key(rnd: random.Random) -> str:
    return "gsk_" + _rand_chars(rnd, B62, 52)


def together_api_key(rnd: random.Random) -> str:
    return _rand_chars(rnd, HEX, 64)


def perplexity_api_key(rnd: random.Random) -> str:
    return "pplx-" + _rand_chars(rnd, B62, 48)


def turso_api_token(rnd: random.Random) -> str:
    # Turso tokens are JWTs (long, ey-prefixed)
    return jwt_token(rnd)


def doppler_token(rnd: random.Random) -> str:
    # Real Doppler tokens are `dp.{st|pt|sa|ct}.<44 b62>` per the
    # keyhog doppler-cli-token detector (regex anchored on `{44}`).
    # The previous 40-char body was the wrong length and floored
    # Doppler recall at 0% on bench (~635 session-token positives
    # are doppler-prefixed, half the recall gap for the category).
    prefix = rnd.choice(["dp.st.", "dp.pt.", "dp.sa.", "dp.ct."])
    return prefix + _rand_chars(rnd, B62, 44)


def clerk_secret_key(rnd: random.Random) -> str:
    env = rnd.choice(["live", "test"])
    return f"sk_{env}_" + _rand_chars(rnd, B62, 50)


def resend_api_key(rnd: random.Random) -> str:
    return "re_" + _rand_chars(rnd, B62 + "_-", 32)


def expo_access_token(rnd: random.Random) -> str:
    return "expo_" + _rand_chars(rnd, B62, 36)


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

    # modern SaaS providers (2024-2026 wave)
    ("authentication-key",       "env",        supabase_anon_jwt,        25),
    ("api-key",                  "env",        neon_api_key,             15),
    ("api-key",                  "env",        vercel_token,             20),
    ("api-key",                  "env",        deepgram_api_key,         15),
    ("api-key",                  "env",        dbt_cloud_pat,            10),
    ("api-key",                  "env",        pinecone_api_key,         15),
    ("api-key",                  "env",        auth0_api_key,            20),
    ("api-key",                  "env",        algolia_admin_key,        15),
    ("api-key",                  "env",        render_api_key,           10),
    ("api-key",                  "env",        planetscale_api_token,    10),
    ("authentication-key",       "env",        fly_api_token,            15),
    ("api-key",                  "env",        railway_api_token,        10),
    ("api-key",                  "env",        replicate_api_token,      15),
    ("api-key",                  "env",        groq_api_key,             20),
    ("api-key",                  "env",        together_api_key,         15),
    ("api-key",                  "env",        perplexity_api_key,       15),
    ("authentication-key",       "env",        turso_api_token,          15),
    ("session-token",            "env",        doppler_token,            15),
    ("api-key",                  "env",        clerk_secret_key,         15),
    ("api-key",                  "env",        resend_api_key,           10),
    ("api-key",                  "env",        expo_access_token,        10),
]


# ── Service-specific anchor keys ──────────────────────────────────
#
# Real production code wraps service-bound credentials in
# provider-named environment variables (e.g. `AWS_SECRET_ACCESS_KEY=`,
# `STRIPE_API_KEY=`), not in generic `SECRET_KEY=`. A bench that
# always uses generic keys is testing the generic-secret detector
# only: and that detector necessarily over-suppresses base64
# blobs to control protobuf-class FPs, which floors recall on
# real shapes that happen to be 40-char b64 (AWS, Azure, etc).
#
# Map every builder to its real-world anchor keys. `make_positive_record`
# uses one of these 70% of the time, falling back to the generic
# pool the other 30% (so generic-secret recall stays tested).
PROVIDER_ANCHORS: dict[str, list[str]] = {
    "aws_access_key":              ["AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY"],
    "aws_secret_access_key":       ["AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY"],
    "aws_session_token":           ["AWS_SESSION_TOKEN"],
    "gcp_api_key":                 ["GCP_API_KEY", "GOOGLE_API_KEY", "GOOGLE_MAPS_API_KEY"],
    "gcp_oauth_client_id":         ["GOOGLE_CLIENT_ID", "OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_ID"],
    "gcp_service_account_pem":     ["GOOGLE_SERVICE_ACCOUNT_KEY", "GCP_SERVICE_ACCOUNT_KEY"],
    "azure_storage_key":           ["AZURE_STORAGE_CONNECTION_STRING", "AZURE_STORAGE_KEY"],
    "azure_subscription_key":      ["AZURE_SUBSCRIPTION_KEY", "OCP_APIM_SUBSCRIPTION_KEY"],
    "cloudflare_api_token":        ["CLOUDFLARE_API_TOKEN", "CF_API_TOKEN"],
    "heroku_api_key":              ["HEROKU_API_KEY"],
    "github_classic_pat":          ["GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT"],
    "github_fine_grained_pat":     ["GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT"],
    "github_oauth":                ["GITHUB_OAUTH_TOKEN"],
    "github_app_install":          ["GITHUB_APP_INSTALL_TOKEN"],
    "github_user_to_server":       ["GITHUB_USER_TO_SERVER_TOKEN"],
    "gitlab_pat":                  ["GITLAB_TOKEN", "GITLAB_PAT", "GL_TOKEN"],
    "slack_bot_token":             ["SLACK_BOT_TOKEN", "SLACK_TOKEN"],
    "slack_user_token":            ["SLACK_USER_TOKEN", "SLACK_TOKEN"],
    "slack_webhook":               ["SLACK_WEBHOOK_URL", "SLACK_WEBHOOK"],
    "discord_bot_token":           ["DISCORD_BOT_TOKEN", "DISCORD_TOKEN"],
    "discord_webhook":             ["DISCORD_WEBHOOK_URL", "DISCORD_WEBHOOK"],
    "stripe_live_secret":          ["STRIPE_API_KEY", "STRIPE_SECRET_KEY"],
    "stripe_test_secret":          ["STRIPE_TEST_KEY", "STRIPE_SECRET_KEY"],
    "stripe_restricted":           ["STRIPE_RESTRICTED_KEY"],
    "stripe_publishable":          ["STRIPE_PUBLISHABLE_KEY"],
    "twilio_account_sid":          ["TWILIO_ACCOUNT_SID"],
    "twilio_auth_token":           ["TWILIO_AUTH_TOKEN"],
    "sendgrid_api_key":            ["SENDGRID_API_KEY", "SG_API_KEY"],
    "mailgun_api_key":             ["MAILGUN_API_KEY"],
    "mailchimp_api_key":           ["MAILCHIMP_API_KEY", "MC_API_KEY"],
    "npm_token":                   ["NPM_TOKEN", "NPM_AUTH_TOKEN"],
    "openai_api_key":              ["OPENAI_API_KEY"],
    "anthropic_api_key":           ["ANTHROPIC_API_KEY", "ANTHROPIC_KEY"],
    "huggingface_token":           ["HUGGINGFACE_TOKEN", "HF_TOKEN"],
    "asana_pat":                   ["ASANA_PAT", "ASANA_TOKEN"],
    "datadog_api_key":             ["DATADOG_API_KEY", "DD_API_KEY"],
    "datadog_app_key":             ["DATADOG_APP_KEY", "DD_APP_KEY"],
    "newrelic_user_key":           ["NEW_RELIC_API_KEY", "NEW_RELIC_USER_KEY"],
    "linear_api_key":              ["LINEAR_API_KEY"],
    "figma_pat":                   ["FIGMA_PAT", "FIGMA_TOKEN"],
    "shopify_access_token":        ["SHOPIFY_ACCESS_TOKEN", "SHOPIFY_TOKEN"],
    "square_oauth":                ["SQUARE_OAUTH_TOKEN", "SQUARE_ACCESS_TOKEN"],
    "jwt_token":                   ["JWT_TOKEN", "ACCESS_TOKEN", "BEARER_TOKEN"],
    "ssh_rsa_private_key":         ["SSH_PRIVATE_KEY"],
    "ssh_openssh_private_key":     ["SSH_PRIVATE_KEY"],
    "ec_private_key":              ["EC_PRIVATE_KEY", "TLS_PRIVATE_KEY"],
    "pgp_private_key":             ["PGP_PRIVATE_KEY", "GPG_PRIVATE_KEY"],
    "postgres_connection_string":  ["DATABASE_URL", "POSTGRES_URL", "PG_URL"],
    "mysql_connection_string":     ["DATABASE_URL", "MYSQL_URL"],
    "mongodb_connection_string":   ["MONGODB_URI", "MONGO_URL"],
    "redis_connection_string":     ["REDIS_URL", "REDIS_CONNECTION_STRING"],
    "supabase_anon_jwt":           ["SUPABASE_ANON_KEY", "SUPABASE_KEY"],
    "neon_api_key":                ["NEON_API_KEY"],
    "vercel_token":                ["VERCEL_TOKEN"],
    "deepgram_api_key":            ["DEEPGRAM_API_KEY"],
    "dbt_cloud_pat":               ["DBT_CLOUD_TOKEN", "DBT_TOKEN"],
    "pinecone_api_key":            ["PINECONE_API_KEY"],
    "auth0_api_key":               ["AUTH0_API_KEY", "AUTH0_CLIENT_SECRET"],
    "algolia_admin_key":           ["ALGOLIA_ADMIN_KEY"],
    "render_api_key":              ["RENDER_API_KEY"],
    "planetscale_api_token":       ["PLANETSCALE_TOKEN"],
    "fly_api_token":               ["FLY_API_TOKEN", "FLY_TOKEN"],
    "railway_api_token":           ["RAILWAY_TOKEN"],
    "replicate_api_token":         ["REPLICATE_API_TOKEN"],
    "groq_api_key":                ["GROQ_API_KEY"],
    "together_api_key":            ["TOGETHER_API_KEY"],
    "perplexity_api_key":          ["PERPLEXITY_API_KEY", "PPLX_API_KEY"],
    "turso_api_token":             ["TURSO_TOKEN", "TURSO_API_TOKEN"],
    "doppler_token":               ["DOPPLER_TOKEN"],
    "clerk_secret_key":            ["CLERK_SECRET_KEY"],
    "resend_api_key":              ["RESEND_API_KEY"],
    "expo_access_token":           ["EXPO_TOKEN", "EXPO_ACCESS_TOKEN"],
}


def weighted_iter(
    rnd: random.Random, total: int
) -> Iterator[tuple[str, str, str, list[str]]]:
    """Yield `total` (category, file_type, secret, anchor_keys) tuples
    sampled according to the catalog weights. `anchor_keys` is the
    list of real-world environment-variable names typically used
    to hold this credential family in production code; the
    generator picks one of these 70% of the time when wrapping the
    secret so the bench reflects realistic anchor density.
    Empty list means "no service-specific anchor known".
    """
    weights = [w for _, _, _, w in CATALOG]
    choices = list(range(len(CATALOG)))
    for _ in range(total):
        idx = rnd.choices(choices, weights=weights, k=1)[0]
        category, file_type, builder, _ = CATALOG[idx]
        anchors = PROVIDER_ANCHORS.get(builder.__name__, [])
        yield category, file_type, builder(rnd), anchors
