# Publishing KeyHog 0.5.47

This guide separates local release proof from publication. The local gate does
not create tags or upload anything. Pushing `v0.5.47` starts the outward,
tag-triggered release.

## Current publication state

This state records the completed 0.5.47 GitHub and GHCR publication:

| surface | current version |
| --- | --- |
| GitHub release | 0.5.47 |
| `keyhog` on crates.io | 0.5.44 |
| `keyhog-core` on crates.io | 0.5.44 |
| `keyhog-scanner` on crates.io | 0.5.44 |
| `keyhog-sources` on crates.io | 0.5.44 |
| `keyhog-verifier` on crates.io | 0.5.44 |
| source workspace | 0.5.47 |

A public GitHub release does not prove that crates.io publication completed.
Treat each surface as a separate result.

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

1. Confirm that the workspace version and the four exact internal dependency
   pins in `Cargo.toml` are `0.5.47`.
2. Cut the root and per-crate changelog entries for `0.5.47`.
3. Commit the complete candidate. The full prerelease gate requires a clean
   tree.
4. Configure the repository Actions secrets
   `KEYHOG_MINISIGN_SECRET_KEY` and `CARGO_REGISTRY_TOKEN`.
5. Prepare a signed local candidate bundle from the exact release commit.

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

If the source has not been bumped yet, you may use the script as the version
mutation helper:

```console
scripts/prerelease.sh --bump 0.5.47
```

That invocation updates the workspace, lockfile, crate changelogs, and
canonical documentation. It is not the final proof. The GPU evidence gate
requires a clean tree, and the install gate requires the signed bundle. Review
and commit the bump, build the signed bundle from that commit, then rerun the
full command without `--bump`.

Do not run `scripts/publish.sh` as a prerelease check. It uploads to crates.io.
The tag workflow invokes it only after the signed GitHub release is public.

## Start publication

After the local gate passes, create and push the exact stable tag:

```console
git tag v0.5.47
git push origin v0.5.47
```

Do not move the tag after pushing it. `.github/workflows/release.yml` binds
builds, attestations, the private draft, the container digest, the public
release, and registry publication to that tag and commit.

For a manual recovery dispatch, choose `v0.5.47` under **Use workflow from** and
enter `v0.5.47` as the workflow input. The workflow rejects a dispatch whose
event ref is not the same exact tag.

## Automated publication order

The `Release` workflow performs these steps in order:

1. **Build and attest.** Four platform jobs build the CLI and GPU literal
   sidecar. A separate job stages `install.sh` and `install.ps1`. Every checkout
   must match the tag event commit.
2. **Sign and stage privately.** One job signs every payload, creates or reuses
   the draft for the exact tag, uploads the complete signed manifest, and emits
   a signed `release-publication.json` receipt for the immutable release ID.
   The GitHub release remains a draft.
3. **Smoke the staged candidate.** The smoke job downloads the signed Linux
   candidate from the private Actions artifact. It verifies checksums and
   minisign signatures, installs the candidate, runs `doctor`, and requires a
   planted-secret scan to return the findings exit status without disclosing
   the secret.
4. **Publish GHCR.** After smoke passes, the workflow pushes
   `ghcr.io/santhreal/keyhog:0.5.47` for `linux/amd64` and `linux/arm64`,
   verifies the returned digest and both platforms, and attests the digest. For
   the newest stable release, it then advances `latest`.
5. **Publish the GitHub release.** The workflow verifies the signed receipt,
   source commit, immutable release ID, and successful container digest. It
   then transitions that exact draft to public.
6. **Publish crates.io.** The release workflow calls
   `.github/workflows/publish-crates.yml` directly. Releases created with the
   workflow token do not start a second release-event run. The crate workflow
   re-verifies the exact tag, workspace version, public signed release, and
   release assets before exposing the registry token.
7. **Advance the Action tag.** Independently of crate publication, the
   post-release job moves the floating `v0` tag when `v0.5.47` is the newest
   stable release.

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

## Verify completion

Check every outward surface:

```console
gh release view v0.5.47 --json tagName,isDraft,isPrerelease
docker buildx imagetools inspect ghcr.io/santhreal/keyhog:0.5.47
cargo info keyhog-core@0.5.44
cargo info keyhog-verifier@0.5.44
cargo info keyhog-sources@0.5.44
cargo info keyhog-scanner@0.5.44
cargo info keyhog@0.5.44
git ls-remote --tags origin refs/tags/v0 refs/tags/v0.5.47
```

For this stable release, the GitHub result must not be a draft or prerelease,
the container manifest must include both target architectures, the five crates
must remain verifiable at 0.5.44, and `v0` must resolve to the `v0.5.47` commit.

## Recover a partial publication

Publication steps are intentionally re-runnable, but public uploads are not
reversible.

- If a job fails before the GitHub release is public, use **Re-run failed
  jobs** on the same tag-triggered run. Leave the private draft in place. The
  signing job addresses it through its immutable release ID. Do not publish the
  draft by hand.
- If GHCR succeeded before a later failure, treat
  `ghcr.io/santhreal/keyhog:0.5.47` as already public. Inspect its digest before
  rerunning the failed workflow jobs.
- If crates.io publication fails after the GitHub release is public, manually
  dispatch **Publish crates.io** with exact tag `v0.5.47`. Select the same tag
  as the workflow ref. The workflow verifies every existing registry archive
  against freshly packaged tagged source and resumes without republishing
  matching crates.
- Never cancel a crates.io run after an upload may have started. The workflow
  serializes all KeyHog registry publication and disables cancellation.
- Never change the source or move the tag to recover a partially published
  version. Fix the automation in a later commit if necessary, then dispatch it
  against the existing immutable tag only when its verification rules permit
  that recovery.
