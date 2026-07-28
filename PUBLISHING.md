# Publishing KeyHog 0.5.48

This guide separates local release proof from publication. The local gate does
not create tags or upload anything. Only after the candidate passes every gate
does pushing `v0.5.48` start the outward, tag-triggered release.

## Current publication state

KeyHog 0.5.48 is a candidate, not a public release. The last observed public
state is:

| surface | public state | 0.5.48 candidate |
| --- | --- | --- |
| GitHub release | 0.5.47 | not published |
| GHCR | 0.5.47 | not published |
| GitHub Marketplace | not listed | first-publication UI step remains |
| `keyhog` on crates.io | 0.5.44 | not published |
| `keyhog-core` on crates.io | 0.5.44 | not published |
| `keyhog-scanner` on crates.io | 0.5.44 | not published |
| `keyhog-sources` on crates.io | 0.5.44 | not published |
| `keyhog-verifier` on crates.io | 0.5.44 | not published |
| source workspace | candidate 0.5.48 after the reviewed bump | local only |

A public GitHub release does not prove that crates.io or Marketplace
publication completed. Treat each surface as a separate result. Do not describe
0.5.48, its SBOMs, its new Action inputs, or the Marketplace listing as public
before the steps below succeed.

The hardened verifier currently stops before the listing check because public
`v0.5.47` is a lightweight Git ref (`object.type = commit`), not a signed
annotated tag. A direct request also observes that the expected Marketplace URL
returns `404`, but neither fact is a successful verifier receipt. The 0.5.48
procedure below fixes the release-tag provenance requirement.

The public release API also reports `"immutable": false` for 0.5.47. Enabling
repository release immutability affects only future releases, so this historical
release remains mutable and cannot satisfy the hardened verifier.

The workspace resolves `vyre`, `vyre-libs`, `vyre-driver-wgpu`,
`vyre-driver-cuda`, and `vyre-runtime` from crates.io at exact version `0.6.5`.
KeyHog does not publish these crates. If KeyHog needs a newer VYRE version,
publish that dependency chain from the upstream repository first. Then update
the five root `Cargo.toml` pins and run:

```console
python3 scripts/gates/vyre_pin_consistency.py
```

## Prerequisites

Before you create the release tag:

The workflow entry identity is owner-only: GitHub `actor_id` must equal the
stable owner ID `64453045` for release tag events, manual release dispatches,
and `publish-crates` entry. Those jobs fail closed for every other actor ID;
the mutable actor login is not used as the authority.

1. Confirm that the workspace version and the four exact internal dependency
   pins in `Cargo.toml` are `0.5.48`.
2. Cut the root and per-crate changelog entries for `0.5.48`.
3. Use the enrolled OpenPGP release key whose full uppercase fingerprint is
   `45B4239F87DBCB01428A8939C035E85273132EB2`. The annotated tag identity is
   exactly `Santh <64453045+santhreal@users.noreply.github.com>`.
   `user.signingkey` names that key, `gpg.format` is `openpgp`, and the private
   half remains protected in the local GnuPG keyring. The exact ASCII-armored
   public half returned by `/users/santhreal/gpg_keys` is committed as
   `.github/release-signing-key.asc`. The repository Actions variable
   `KEYHOG_RELEASE_SIGNING_FINGERPRINT` contains the same full fingerprint.
   Short key IDs, a different enrolled key, or placeholder bytes are rejected.
   This identity was enrolled and byte-checked on 2026-07-27. Treat any
   difference among the local secret key, committed armor, GitHub `raw_key`,
   and repository variable as a new hard prepublication blocker.

   At release time, confirm exact identity, local secret-key availability, the
   committed public key, enrolled `raw_key`, and full fingerprint without
   printing private key material:

   ```console
   test "$(git config --get user.name)" = 'Santh'
   test "$(git config --get user.email)" = '64453045+santhreal@users.noreply.github.com'
   test "$(git config --get gpg.format)" = 'openpgp'
   test -n "$(git config --get user.signingkey)"
   test -s .github/release-signing-key.asc
   gpg --list-secret-keys "$(git config --get user.signingkey)"
   gpg --fingerprint --with-colons "$(git config --get user.signingkey)"
   gpg --show-keys --fingerprint --with-colons .github/release-signing-key.asc
   curl -fSs https://api.github.com/users/santhreal/gpg_keys \
     -o /tmp/santhreal-gpg-keys.json
   python3 -c 'import json,pathlib,sys; armor=pathlib.Path(sys.argv[1]).read_text(); keys=json.load(open(sys.argv[2])); assert any(k.get("raw_key")==armor for k in keys)' \
     .github/release-signing-key.asc /tmp/santhreal-gpg-keys.json
   ```

   The full uppercase `fpr` value from the local secret key and committed public
   key must be identical to `KEYHOG_RELEASE_SIGNING_FINGERPRINT`, and the API
   must contain the committed armor exactly, before creating the tag.

4. Require immutable releases to remain enabled for `santhreal/keyhog`. The
   repository setting was enabled through GitHub's owner-only immutable
   releases endpoint on 2026-07-27. Confirm it before creating every release
   tag:
   ```console
   gh api repos/santhreal/keyhog/immutable-releases
   ```
   The response must contain `"enabled": true`. GitHub applies the setting only
   to future releases, so the historical check below remains useful evidence
   that an older release does not prove the current setting:

   ```console
   curl -fSs https://api.github.com/repos/santhreal/keyhog/releases/tags/v0.5.47 \
     | python3 -c 'import json,sys; print(json.load(sys.stdin)["immutable"])'
   ```

   The current result is `False`. After 0.5.48 publication, its release API and
   the hardened Marketplace verifier must instead report `immutable: true`.
   GitHub documents the repository setting under
   [Preventing changes to your releases](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes).

5. Commit the complete candidate. The full prerelease gate requires a clean
   tree.
6. Configure the repository Actions secrets
   `KEYHOG_MINISIGN_SECRET_KEY` and `CARGO_REGISTRY_TOKEN`.
7. Prepare a signed local candidate bundle from the exact release commit.

The file passed as the candidate must have these nonempty siblings:

```text
keyhog-linux-x86_64
keyhog-linux-x86_64.sha256
keyhog-linux-x86_64.minisig
keyhog-linux-x86_64.gpu-literals.tar.gz
keyhog-linux-x86_64.gpu-literals.tar.gz.sha256
keyhog-linux-x86_64.gpu-literals.tar.gz.minisig
```

## Prove the candidate locally

Run the full prerelease gate from the clean release commit:

```console
scripts/prerelease.sh \
  --release-candidate /absolute/path/to/keyhog-linux-x86_64
```

This command builds the source candidate, runs the benchmark and coherence
gates, runs the per-crate Rust gates, and exercises the signed install bundle.
The install smoke checks `--version`, `doctor`, a planted-secret scan, and
uninstall. It does not tag, push, upload, or use a registry credential.

The maintained push/PR source lanes in `.github/workflows/action-e2e.yml` use
explicit `backend: cpu`: a digest-pinned Rust container runs real root and
nested composite CPU+lockdown with `IPC_LOCK` and unlimited memlock, while
cross-platform lanes exercise clean and precision scans. Source refs reject auto
without persisted routing proof. A local production Docker run separately
proves release-like calibration and auto scan complete with `mlocked` status.

These are reviewed-source proofs; they cannot authenticate release assets that
do not exist yet. After 0.5.48 becomes public, authenticated manual dispatch
runs a separate release-ref lane with default proof-backed auto, fetches and
verifies the signed binary/sidecar bundle, and reruns auto+lockdown.

Both lanes must prove the Action's report publication boundary: the requested
workspace copy retains the stable
`keyhog-results-<analysis-category>.<ext>` basename but is not an upload
authority and is untrusted after the Action returns. A successful wrapper
publishes a receipt-bound, mode-`0400` snapshot inside a unique mode-`0700`
runtime under the unpredictable
`RUNNER_TEMP/keyhog-action-runtime.*/report-snapshot.*/` parent, re-verifies it
against the scanner receipt, and exposes that path only for downstream steps in
the same runner job. `report-present` means the receipt-bound snapshot was
published; SARIF and artifact upload must SHA-check it again, and runner job
cleanup ends its lifetime. The snapshot is private but not immutable against
another process under the same runner UID, so publication-time validation must
not be presented as a promise of later byte integrity.

If the source has not been bumped yet, you may use the script as the version
mutation helper:

```console
scripts/prerelease.sh --bump 0.5.48
```

That invocation updates the workspace, lockfile, crate changelogs, and
canonical documentation. It is not the final proof. The GPU evidence gate
requires a clean tree, and the install gate requires the signed bundle. Review
and commit the bump, build the signed bundle from that commit, then rerun the
full command without `--bump`.

Do not run `scripts/publish.sh` as a prerelease check. It uploads to crates.io.
The tag workflow invokes it only after the signed GitHub release is public.

## Start publication

After the local gate passes, create a signed annotated stable tag, verify its
signature and target locally, then push that exact tag:

```console
git tag -s v0.5.48 -m 'KeyHog 0.5.48'
git tag -v v0.5.48
test "$(git rev-list -n 1 v0.5.48)" = "$(git rev-parse HEAD)"
git push origin refs/tags/v0.5.48
```

`git tag -v` must report a good signature from the configured release key.
After push, GitHub's tag API must report `verification.verified == true` and
nonempty signature bytes. From the trusted `workflow_sha` automation checkout,
the workflow imports only committed `.github/release-signing-key.asc`, requires
that exact armor to appear as a `raw_key` returned by GitHub for `santhreal`,
cryptographically verifies GitHub's exact tag payload/signature with GPG, and
requires the `VALIDSIG` signing/primary fingerprint to equal the full
`KEYHOG_RELEASE_SIGNING_FINGERPRINT`. GitHub's generic **Verified** badge alone
is insufficient.
The verifier accepts one header-free, LF-terminated canonical ASCII armor
block, validates its radix-64 layout and CRC-24, and binds the receipt SHA-256
to the exact decoded public-key packets. It does not compare armor regenerated
by the installed GnuPG version, because valid GnuPG releases can reserialize
the same enrolled key differently.

The verified payload must encode the same peeled commit, `type commit`, exact
tag, exact tagger name/email/date, and exact message returned by the tag-object
API; the tag ref must resolve to that annotated object and peel to the
triggering commit. The workflow also pins current `refs/heads/main`, compares
`<release-commit>...<pinned-main-sha>`, and requires base and merge-base to
equal the release commit, head to equal pinned main, and status to be `ahead` or
`identical`. Immutable actor ID, the enrolled fingerprint-bound signed payload,
and trusted-main ancestry independently authorize publication.

The Marketplace verifier also rejects a lightweight, unsigned, or unverified
release tag. Do not move the tag after pushing it.
`.github/workflows/release.yml` binds builds, attestations, the private draft,
the container digest, the public release, and registry publication to that tag
object and commit. The separate `v0` tag remains the mutable floating stable
ref.

For a manual recovery dispatch, choose `v0.5.48` under **Use workflow from** and
enter `v0.5.48` as the workflow input. The workflow rejects a dispatch whose
event ref is not the same exact tag.

## Automated publication order

The `Release` workflow performs these steps in order:

1. **Build and attest.** Four platform jobs build the CLI and GPU literal
   sidecar. A separate job stages `install.sh` and `install.ps1`. Every checkout
   must match the tag event commit.
2. **Create SBOMs, sign, and stage privately.** The release job creates the ten
   deterministic SPDX 2.3 JSON SBOMs listed below, validates them against tagged
   source and built payloads, and signs every payload, checksum, and SBOM. It
   creates or reuses the draft for the exact tag, uploads the complete signed
   manifest, and emits a signed `release-publication.json` receipt for the
   immutable release ID. The GitHub release remains a draft.
3. **Smoke the staged candidate.** The smoke job downloads the signed Linux
   candidate from the private Actions artifact. It verifies checksums, minisign
   signatures, release completeness, and SBOM structure, installs the candidate,
   runs `doctor`, and requires a planted-secret scan to return the findings exit
   status without disclosing the secret.
4. **Publish GHCR.** After smoke passes, the workflow pushes
   `ghcr.io/santhreal/keyhog:0.5.48` for `linux/amd64` and `linux/arm64`,
   verifies the returned digest and both platforms, and attests the digest. For
   the newest stable release, it then advances `latest`.
5. **Publish the GitHub release.** The workflow verifies the signed receipt,
   source commit, immutable release ID, successful container digest, and
   complete signed payload/SBOM set. It then transitions that exact draft to
   public.
6. **Publish crates.io.** The release workflow calls
   `.github/workflows/publish-crates.yml` directly. Releases created with the
   workflow token do not start a second release-event run. The crate workflow
   re-verifies the exact tag, workspace version, public signed release, and
   release assets before exposing the registry token.
7. **Advance the Action tag.** Independently of crate publication, the
   post-release job moves the floating `v0` tag only when `v0.5.48` is the
   newest stable release. Prereleases never advance it.

GHCR publication is the first public payload mutation. It happens after the
private smoke but before the GitHub release becomes public. If a later job
fails, the versioned GHCR image may already be public.

The crates.io publisher uploads and verifies these dependency tiers:

1. `keyhog-core`
2. `keyhog-verifier`
3. `keyhog-sources`, then `keyhog-scanner`
4. `keyhog`

It waits for each required registry version to become visible before packaging
the next dependent tier.

For 0.5.47, crates.io publication was explicitly skipped after registry
authentication rejected the configured token. The five registry packages
therefore remain at 0.5.44. The GitHub release, GHCR image, and floating Action
tag remain complete and independently verifiable.

## Signed SBOM contract

The 0.5.48 release contract requires deterministic SPDX 2.3 JSON for these ten
payloads:

```text
keyhog-linux-x86_64
keyhog-linux-x86_64.gpu-literals.tar.gz
keyhog-macos-aarch64
keyhog-macos-aarch64.gpu-literals.tar.gz
keyhog-macos-x86_64
keyhog-macos-x86_64.gpu-literals.tar.gz
keyhog-windows-x86_64.exe
keyhog-windows-x86_64.exe.gpu-literals.tar.gz
install.sh
install.ps1
```

For each listed `<asset>`, a publishable release must contain
`<asset>.spdx.json`, `<asset>.spdx.json.sha256`, and
`<asset>.spdx.json.minisig`. Combined with each payload's own `.sha256` and
`.minisig`, this is exactly 60 public release assets: 10 payloads, 20 payload
proofs, 10 SBOM documents, and 20 SBOM proofs.

Every binary and GPU-sidecar SBOM binds an attested
`<asset>.dependencies.json` generated offline from package-scoped
`cargo tree -p <root>` with the exact target and feature set, complete non-dev
normal/build closure, enabled features, `Cargo.lock` hash, tag and commit, and
graph digest. A GPU bundle uses an SPDX `GENERATED_FROM` relationship to its
scanner graph. The Linux binary additionally binds attested
`keyhog-linux-x86_64.native.json`: a statically linked Hyperscan `5.4.2`
BSD-3-Clause package, the exact `libhs.a` hash, `libhs.pc` provenance hash, and
an SPDX `STATIC_LINK` relationship. It does not claim a runtime `libhs`.

Installer SBOMs contain no Cargo graph. `install.sh` enumerates the exact three
Unix binaries and three GPU bundles from the manifest with their SHA-256 values
and conditional `OPTIONAL_DEPENDENCY_OF` relationships, plus `sh`, `curl`,
`awk`, `sha256sum` or `shasum`, `minisign`, and POSIX file utilities.
`install.ps1` enumerates the Windows binary and GPU bundle plus PowerShell 5+,
`Invoke-WebRequest`, `Get-FileHash`, and `minisign`.

Every document also binds its payload hash, size and kind plus the
`keyhog-release-sbom` generator schema/version. The SBOMs are part of the signed
release manifest and provenance-attested release payload; public completeness
checks fail when any document or adjacent proof is missing.

The release job proves staged structure and source binding before publication:

```console
python3 scripts/release_sbom.py verify \
  --source-dir . \
  --asset-dir signed \
  --manifest signed/release-sbom-manifest.json \
  --output-dir signed
```

A consumer verifies a downloaded SBOM with the same public key as the binary:

```console
SBOM=keyhog-linux-x86_64.spdx.json
PUB='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
sha256sum -c "$SBOM.sha256"
minisign -Vm "$SBOM" -P "$PUB"
```

Both commands must pass before trusting the document. `sha256sum` proves the
download matches the adjacent digest; minisign authenticates it as a KeyHog
release asset.

## Verify completion

Check every outward surface:

```console
gh release view v0.5.48 --json tagName,isDraft,isPrerelease
docker buildx imagetools inspect ghcr.io/santhreal/keyhog:0.5.48
cargo info keyhog-core@0.5.48
cargo info keyhog-verifier@0.5.48
cargo info keyhog-sources@0.5.48
cargo info keyhog-scanner@0.5.48
cargo info keyhog@0.5.48
git ls-remote --tags origin refs/tags/v0 refs/tags/v0.5.48
```

For this stable release, the GitHub result must not be a draft or prerelease,
the container manifest must include both target architectures, all five crates
must resolve at 0.5.48, and `v0` must resolve to the `v0.5.48` commit. If any
surface is absent, publication is partial and recovery remains required.

## Publish and update the Marketplace listing

Marketplace publication is the one deliberate UI step after the automated
stable release is public. Do not create a second release, edit assets, or move
the immutable version tag for this step.

### First publication

Use an organization owner or repository administrator with two-factor
authentication enabled:

1. Confirm the repository is public, the root `action.yml` is the single root
   Action metadata file, and its name is `KeyHog Secret Scanner`. Subdirectory
   actions are allowed but are not separate Marketplace listings.
2. Open **Releases**, open `v0.5.48`, and choose **Edit**.
3. Under **Release Action**, select **Publish this Action to the GitHub
   Marketplace**. If the control is disabled, follow its link as an organization
   owner and accept the GitHub Marketplace Developer Agreement, then return to
   the release editor. If the publisher is not an owner, send that Release
   Action page to an owner; repository access does not substitute for the
   organization agreement.
4. Resolve every metadata error until GitHub shows **Everything looks good!**.
   Choose **Security** as the primary category and **Continuous integration** as
   the secondary category. If either exact label is absent, stop and record the
   labels GitHub offers rather than substituting an undocumented category.
5. Leave the tag, title, notes, and release assets unchanged. Choose **Update
   release** and complete GitHub's two-factor authentication prompt. Publication
   is immediate; there is no separate GitHub review queue for a conforming
   Action.

### Publish a stable update

For each later stable version, first let the tag-triggered workflow finish and
verify every outward surface. The workflow advances `v0` only after the signed
GitHub release is public and only for the newest stable version; a prerelease
must neither move `v0` nor become the advertised stable Marketplace update.
Then edit that exact stable release, keep **Publish this Action to the GitHub
Marketplace** selected, keep the categories above, and choose **Update release**.
This UI update and its 2FA prompt cannot be replaced by creating another tag or
release.

### Verify the public listing and refs

The verifier's only Python dependency is locked to exact CPython 3.12 wheels
for Linux x86_64/aarch64 and macOS x86_64/arm64 in
`scripts/requirements-marketplace.txt`. Do not use an ambient site package,
an sdist fallback, another Python minor, or an unsupported platform. Build an
isolated environment and require every downloaded wheel hash before loading
the signer inputs:

```console
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64|Linux/aarch64|Darwin/x86_64|Darwin/arm64) ;;
  *) echo "unsupported Marketplace verifier platform" >&2; exit 1 ;;
esac
python3.12 -c 'import sys; assert sys.version_info[:2] == (3, 12)'
MARKETPLACE_VENV=$(mktemp -d)
trap 'rm -rf "$MARKETPLACE_VENV"' EXIT
python3.12 -m venv "$MARKETPLACE_VENV"
"$MARKETPLACE_VENV/bin/python" -m pip install \
  --disable-pip-version-check \
  --no-deps \
  --only-binary=:all: \
  --require-hashes \
  -r scripts/requirements-marketplace.txt
"$MARKETPLACE_VENV/bin/python" -c 'import yaml; assert yaml.__version__ == "6.0.3"'
```

After first publication, and only after completing the signer enrollment
prerequisite above, copy the exact repository fingerprint into the shell
environment and use the committed public key. Do not export a different local
key or invent a placeholder fingerprint:

```console
test -n "$KEYHOG_RELEASE_SIGNING_FINGERPRINT"
RELEASE_SIGNING_KEY=.github/release-signing-key.asc
test -s "$RELEASE_SIGNING_KEY"
gpg --show-keys --fingerprint --with-colons "$RELEASE_SIGNING_KEY"
```

Run the verifier with both fail-closed signer inputs and the expected listing
slug. If the Marketplace UI assigns a different slug, replace only the listing
URL:

```console
"$MARKETPLACE_VENV/bin/python" scripts/verify_marketplace_action.py \
  --repository santhreal/keyhog \
  --action-tag v0 \
  --release-tag v0.5.48 \
  --release-signing-key "$RELEASE_SIGNING_KEY" \
  --release-signer-fingerprint "$KEYHOG_RELEASE_SIGNING_FINGERPRINT" \
  --listing-url https://github.com/marketplace/actions/keyhog-secret-scanner \
  --action-name 'KeyHog Secret Scanner' \
  --category security \
  --category continuous-integration
```

Success emits the final JSON receipt fields: `schema_version`, `repository`,
`action_tag`, `release_tag`, signed annotated `release_tag_sha`,
`release_signer_fingerprint`, exact OpenPGP-packet
`release_signing_key_sha256`, stable `release_id`, canonical `release_url`, and
`release_published_at`, common `commit`, `root_action_sha`, `action_name`,
`listing_url`, rendered
`marketplace_ref`, and both `categories`.

The verifier separately requires the stable release to have a nonempty
publication timestamp, report `immutable: true`, expose the exact 60-asset
signed payload/SBOM inventory above, and link the exact `security` and
`continuous-integration` Marketplace topics. Every asset API
`browser_download_url` must be the canonical GitHub release URL for repository
`santhreal/keyhog`, exact tag `v0.5.48`, and that asset's exact name.

A missing or extra asset, noncanonical/cross-repository asset URL, missing
listing, stale `v0`, private repository, non-public, unstable, or mutable
release, lightweight/unsigned/unverified release tag, absent or malformed
signer input, key/fingerprint/signature mismatch, missing or malformed root
action, name/repository mismatch, or missing category fails the command.
Preserve the receipt with the release verification evidence; do not infer
publication from the release page alone.

## Recover a partial publication

Publication steps are intentionally re-runnable, but public uploads are not
reversible.

- If a job fails before the GitHub release is public, use **Re-run failed
  jobs** on the same tag-triggered run. Leave the private draft in place. The
  signing job addresses it through its immutable release ID. Do not publish the
  draft by hand.
- If GHCR succeeded before a later failure, treat
  `ghcr.io/santhreal/keyhog:0.5.48` as already public. Inspect its digest before
  rerunning the failed workflow jobs.
- If crates.io publication fails after the GitHub release is public, manually
  dispatch **Publish crates.io** with exact tag `v0.5.48`. Select the same tag
  as the workflow ref. The workflow verifies every existing registry archive
  against freshly packaged tagged source and resumes without republishing
  matching crates.
- Never cancel a crates.io run after an upload may have started. The workflow
  serializes all KeyHog registry publication and disables cancellation.
- Never change the source or move the tag to recover a partially published
  version. Fix the automation in a later commit if necessary, then dispatch it
  against the existing immutable tag only when its verification rules permit
  that recovery.


## Roll back or remove the Marketplace Action

A version tag and its signed public assets are immutable. If a new Action
release is faulty, leave that exact tag and release intact for pinned consumers.
A floating-ref rollback is permitted only when you retained a successful
Marketplace verifier receipt for an earlier signed annotated stable tag. Take
`GOOD_TAG` from that receipt; never substitute the currently public
`v0.5.47`, whose lightweight tag cannot satisfy the hardened verifier:

```console
git fetch --tags origin
BAD_OID=$(git rev-parse refs/tags/v0)
GOOD_TAG=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["release_tag"])' previous-marketplace-receipt.json)
git tag -f v0 "$GOOD_TAG^{}"
git push --force-with-lease="refs/tags/v0:$BAD_OID" origin refs/tags/v0
```

The lease prevents overwriting a concurrent repair. Next edit the previous
stable release in GitHub, select **Publish this Action to the GitHub
Marketplace**, and choose **Update release** so the rendered listing advertises
`GOOD_TAG`. Only after that update, re-run the Marketplace verifier with
`--release-tag "$GOOD_TAG"` and retain the new receipt. Publish the correction
under a new immutable tag; never retag the broken version.

For the first 0.5.48 Marketplace publication there is no earlier verified
listing receipt. Do not manufacture a rollback to 0.5.47. Remove the listing
using the procedure below and lease-delete the faulty floating ref so unpinned
consumers fail closed:

```console
git fetch --tags origin
BAD_OID=$(git rev-parse refs/tags/v0)
git push --force-with-lease="refs/tags/v0:$BAD_OID" origin :refs/tags/v0
```

To remove KeyHog from Marketplace, update **every** release that was published
there:

1. Open **Releases**.
2. Choose **Edit** beside one published Action release.
3. Clear **Publish this Action to the GitHub Marketplace**.
4. Choose **Update release**, then repeat for every published Action release.
5. Run the verifier above and require it to fail with a missing listing before
   treating removal as complete.

Unlisting does not delete releases or disable workflows pinned to existing
refs. Deleting the repository also deletes the listing and releases the unique
Action name, so it is not a rollback procedure.