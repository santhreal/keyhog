# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities through GitHub's built-in
**Private Vulnerability Reporting** first:

1. Open [Report a vulnerability](https://github.com/santhreal/keyhog/security/advisories/new).
2. Fill out and submit the private advisory form.

If GitHub private reporting is unavailable or the form cannot be submitted,
email **security@santh.dev** with:

- Affected version / commit SHA
- Reproduction steps and proof-of-concept (where safe to share)
- Impact assessment

PGP encryption is not required for email reports.

Do not open a public issue or include live credentials in a report. We will
coordinate remediation and disclosure through the private advisory or email
thread. Timing depends on the impact, affected releases, and fix validation.

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

## RustSec Advisory Assessment (v0.5.41)

A `cargo audit` of `Cargo.lock` surfaces four accepted advisories total (one
vulnerability and three informational warnings across the workspace and VYRE).
Each was reviewed against KeyHog's actual usage of the affected crate
and given an explicit accept-with-rationale decision or a fix path.
The accepts are reflected in the `[advisories]` ignore list at the
workspace-root `audit.toml`; `cargo audit` exits clean with that file
in place.

### Accepted (rationale-documented)

#### RUSTSEC-2023-0071 - `rsa 0.9.7` Marvin attack

**Risk:** the crate's RSA private-key operations are not fully constant-time;
an attacker who can submit chosen ciphertexts and remotely observe decryption
timing may recover private-key material.

**Why not applicable:** the OOB verifier is a client, not a decryption service.
It generates an ephemeral keypair, shares the public half with the configured
Interactsh server, and decrypts one server-pushed OAEP-wrapped session key
locally. KeyHog returns neither a validity verdict nor decryption timing to a
caller, and transport is HTTPS through the verifier's screened/pinned client.
The Interactsh server already generated and therefore knows the wrapped AES
session key. There is no remote RSA decryption oracle exposed by KeyHog.

#### RUSTSEC-2026-0002 - `lru 0.12.5` IterMut Stacked Borrows violation

**Risk:** `LruCache::iter_mut()` invalidates an internal pointer
(detectable by Miri's Stacked Borrows checker).

**Why not applicable:** `crates/scanner/src/multiline/fragment_cache.rs`
uses `lru::LruCache::get_or_insert_mut()` and `cluster.iter_mut()` on
its own `Vec<SecretFragment>`, not on `LruCache::iter_mut()`. The
unsound API isn't called.

#### RUSTSEC-2024-0436 - `paste 1.0.15` unmaintained

**Risk:** crate is unmaintained; future advisories will not get fixes.

**Why accepted:** `paste` is a build-time proc-macro pulled through the
Metal backend. It is absent from the runtime dependency graph as executable
library code, and the release build pins and audits its exact source version.

#### RUSTSEC-2025-0141 - `bincode 2.0.1` unmaintained

**Risk:** bincode is unmaintained upstream; security defects
against it will not be patched.

**Why not applicable now:** KeyHog itself does not depend on bincode
directly. It is only pulled in transitively through the published VYRE
GPU stack, which uses bincode for serializing compiled GPU pattern
databases. The serialization surface is local disk caches keyed under
`$KEYHOG_CACHE_DIR`; there is no untrusted network input deserialized
through bincode. KeyHog pins the exact VYRE versions, records the resolved
bincode version in `Cargo.lock`, and treats the cache as local state rather than
a network interchange format.

### Resolved in v0.5.3

#### RUSTSEC-2025-0140 - `gix-date 0.9.4` non-utf8 String construction

**Risk:** A malicious commit with a non-UTF-8 timestamp string could
have triggered UB through `TimeBuf::as_str`.

**Resolution:** Bumped `gix` from `=0.70.0` to `0.77.0` (which pulls
`gix-date 0.12.0`+). The bump is API-clean - all five git-using
sources tests pass without source changes. See commits under
"security: bump gix".

#### RUSTSEC-2025-0021 - `gix-features 0.40.0` SHA-1 collision attacks

**Risk:** `gix-features 0.40.0` did not detect SHA-1 collisions in
git objects (Severity 6.8 / medium).

**Resolution:** Same gix bump pulls `gix-features 0.42.0`+, which
adds collision detection. No source changes needed in keyhog's git
source layer.

The gix bump also coordinated with two transitive dependency updates required
by its newer versions: `smallvec` 1.14.0 → 1.15.1 and `memmap2` 0.9.9 →
0.9.10.
