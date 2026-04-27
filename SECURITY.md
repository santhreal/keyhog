# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately** through GitHub's
built-in **Private Vulnerability Reporting**:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** and fill out the advisory form.

If private reporting is unavailable for some reason, email
**security@santh.dev** with:

- Affected version / commit SHA
- Reproduction steps and proof-of-concept (where safe to share)
- Impact assessment

You will receive an acknowledgement within **5 business days**.
Coordinated-disclosure timeline is up to **90 days** from
acknowledgement; we will notify you before the patch ships.

## Supported Versions

Only the `main` branch (and the latest published crate / package
release) receives security fixes. Vendored snapshots and forks are
responsible for backporting.

## Out of Scope

- Findings against archived branches or deprecated tags.
- Self-XSS or social-engineering attacks against maintainers.
- Reports that depend on a compromised upstream package without a
  reproducible downstream impact.

## Coordinated Disclosure

GHSA advisories are filed under the appropriate Santh GitHub
organization. We coordinate CVE assignment via GitHub's CNA when a
fix ships.