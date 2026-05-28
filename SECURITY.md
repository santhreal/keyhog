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

## RustSec Advisory Assessment (v0.5.3)

A `cargo audit` of `Cargo.lock` surfaces six advisories (3 vulnerability,
3 informational). Each was reviewed against keyhog's actual usage of
the affected crate and given an explicit accept-with-rationale decision
or a fix path. The accepts are reflected in the `[advisories]` ignore
list at the workspace-root `audit.toml`; `cargo audit` exits clean with
that file in place.

### Accepted (rationale-documented)

#### RUSTSEC-2023-0071 - `rsa 0.9.7` Marvin attack

**Risk:** PKCS#1 v1.5 RSA decryption is timing-sidechannel-vulnerable
(Marvin attack); an attacker with a decryption oracle can recover a key.

**Why not applicable:** `crates/verifier/src/oob/client.rs` uses ONLY
`rsa::Oaep` for decryption (`use rsa::{Oaep, RsaPrivateKey, RsaPublicKey}`).
PKCS#1 v1.5 decryption code paths are not invoked. Even if the rsa
crate's PKCS#1 v1.5 implementation has timing leaks, keyhog never
exercises them.

**Threat-model gate:** the OOB verifier is a client, not a server. We
generate a keypair, share the public half with the InteractSh server,
and decrypt server-pushed payloads locally. There is no remote
decryption oracle exposed by keyhog.

#### RUSTSEC-2026-0002 - `lru 0.12.5` IterMut Stacked Borrows violation

**Risk:** `LruCache::iter_mut()` invalidates an internal pointer
(detectable by Miri's Stacked Borrows checker).

**Why not applicable:** `crates/scanner/src/multiline/fragment_cache.rs`
uses `lru::LruCache::get_or_insert_mut()` and `cluster.iter_mut()` on
its own `Vec<SecretFragment>`, not on `LruCache::iter_mut()`. The
unsound API isn't called.

#### RUSTSEC-2026-0097 - `rand 0.8.5` unsound with custom logger

**Risk:** `rand::rng()` interaction with custom `tracing` logger has a
data race when the global rng is replaced.

**Why not applicable:** keyhog does not replace the global rng. `rand`
is pulled transitively via `num-bigint-dig` → `rsa`; both use only the
default `OsRng` seed path. Our tracing logger does not call into rand.

#### RUSTSEC-2024-0436 - `paste 1.0.15` unmaintained

**Risk:** crate is unmaintained; future advisories will not get fixes.

**Why not applicable now:** `paste` is a proc-macro used at compile
time; it produces no runtime code in keyhog binaries. An unmaintained
proc-macro can't introduce runtime CVEs. We will migrate when a
suitable replacement appears in our transitive dep tree.

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

The gix bump also coordinated with two transitive dep updates that
its newer versions required: `smallvec` 1.14.0 → 1.15.1 (in vyre's
vendored workspace pin) and `memmap2` 0.9.9 → 0.9.10 (workspace
pin).