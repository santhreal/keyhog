#!/usr/bin/env python3
"""Add verification specs to detectors that don't have them.

Uses common API verification patterns:
- Bearer token → GET /me or /account endpoint
- API key header → GET /account or /status endpoint
- Basic auth → GET /account endpoint
"""
import os
import tomllib

DETECTORS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "detectors")

# Known verification endpoints by service pattern
VERIFY_PATTERNS = {
    # Cloud providers
    "azure-openai": {
        "method": "GET",
        "url": "https://{service}.openai.azure.com/openai/models?api-version=2024-02-01",
        "headers": [{"name": "api-key", "value": "{credential}"}],
        "success_codes": [200],
    },
    "azure-functions": {
        "method": "GET",
        "url": "https://{service}.azurewebsites.net/admin/host/status?code={credential}",
        "success_codes": [200],
    },
    # Payment
    "braintree": {
        "method": "GET",
        "url": "https://api.braintreegateway.com/merchants/{companion}/transactions",
        "auth": {"type": "basic", "username": "{companion}", "password": "{credential}"},
        "success_codes": [200, 401],  # 401 = valid format but wrong key
    },
    # Communication
    "africastalking": {
        "method": "GET",
        "url": "https://api.africastalking.com/version1/user?username={companion}",
        "headers": [{"name": "apiKey", "value": "{credential}"}],
        "success_codes": [200],
    },
}

# Generic patterns for common auth types
GENERIC_BEARER = """
[detector.verify]
method = "GET"
url = "{url}"
success_codes = [200]

[[detector.verify.headers]]
name = "Authorization"
value = "Bearer {{credential}}"
"""

GENERIC_API_KEY_HEADER = """
[detector.verify]
method = "GET"
url = "{url}"
success_codes = [200]

[[detector.verify.headers]]
name = "{header_name}"
value = "{{credential}}"
"""

def add_verify_to_file(filepath, verify_toml):
    """Append verify section to a detector TOML file."""
    with open(filepath) as f:
        content = f.read()

    if "[detector.verify]" in content:
        return False  # Already has verify

    content = content.rstrip() + "\n\n" + verify_toml.strip() + "\n"
    with open(filepath, 'w') as f:
        f.write(content)
    return True


# Known verification endpoints for specific services
KNOWN_ENDPOINTS = {
    "azure-openai-api-key": ("Bearer", "https://eastus.api.cognitive.microsoft.com/openai/models?api-version=2024-02-01", "api-key"),
    "braintree-api-key": ("ApiKey", "https://api.braintreegateway.com/", "Authorization"),
    "africastalking-api-key": ("ApiKey", "https://api.africastalking.com/version1/user", "apiKey"),
    "aws-ses-smtp-credentials": None,  # SMTP, not HTTP
    "apple-push-notification-key": None,  # Certificate-based
    "authentik-token": ("Bearer", "https://{service}/api/v3/core/users/me/", "Authorization"),
    "azure-key-vault-credentials": None,  # OAuth flow required
    "azure-iot-connection-string": None,  # Connection string, not HTTP API
}

added = 0
skipped = 0

for fname in sorted(os.listdir(DETECTORS_DIR)):
    if not fname.endswith('.toml'):
        continue

    filepath = os.path.join(DETECTORS_DIR, fname)
    with open(filepath, 'rb') as f:
        try:
            data = tomllib.load(f)
        except:
            continue

    det = data.get('detector', {})
    if 'verify' in det:
        continue  # Already has verify
    if det.get('severity') != 'critical':
        continue  # Only add to critical

    detector_id = det.get('id', fname.replace('.toml', ''))

    # Check if we have a known endpoint
    if detector_id in KNOWN_ENDPOINTS:
        info = KNOWN_ENDPOINTS[detector_id]
        if info is None:
            skipped += 1
            continue
        auth_type, url, header = info
        verify_toml = GENERIC_API_KEY_HEADER.format(url=url, header_name=header)
        if add_verify_to_file(filepath, verify_toml):
            added += 1
            print(f"Added verify: {detector_id}")

print(f"\nAdded {added} verify specs, skipped {skipped}")
