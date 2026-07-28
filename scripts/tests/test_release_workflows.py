"""Fail-closed contracts for CI and release publication workflows."""

from __future__ import annotations

import datetime as dt
import subprocess
import tempfile
import re
import unittest
from unittest import mock
from pathlib import Path

from scripts.verify_published_release import expected_asset_names
from scripts.verify_release_tag import (
    AUTHORIZED_ACTOR_ID,
    AUTHORIZED_TAGGER_EMAIL,
    AUTHORIZED_TAGGER_NAME,
    TagVerificationError,
    verify_authorized_signature,
    verify_main_ancestry,
    verify_release_actor,
    verify_signed_tag,
)


ROOT = Path(__file__).resolve().parents[2]
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
RELEASE = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
CRATES = (ROOT / ".github/workflows/publish-crates.yml").read_text(encoding="utf-8")


def job_block(workflow: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n.*?(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"workflow has no {job!r} job")
    return match.group(0)


class SinglePublisherContracts(unittest.TestCase):
    def test_ci_has_no_crates_io_publisher_or_credential(self) -> None:
        """Prevents a second crates.io publisher or registry secret in general CI."""
        self.assertNotIn("cargo publish", CI)
        self.assertNotIn("CARGO_REGISTRY_TOKEN", CI)
        self.assertNotRegex(CI, r"(?m)^  publish:\s*$")

    def test_only_reusable_publisher_invokes_publish_script(self) -> None:
        """Prevents direct release scripting from bypassing the reusable publisher."""
        self.assertEqual(CRATES.count("bash automation/scripts/publish.sh"), 1)
        self.assertEqual(RELEASE.count("./.github/workflows/publish-crates.yml"), 1)
        self.assertNotIn("scripts/publish.sh", RELEASE)


class CompleteCiVerdictContracts(unittest.TestCase):
    blocking_jobs = {
        "audit-gates",
        "strict-runners",
        "test",
        "integration-core-scanner",
        "integration-sources",
        "integration-verifier",
        "integration-cli",
        "integration-detector-contracts",
        "macos-build",
        "integration-verdict",
        "windows-build",
        "feature-matrix",
        "install-scripts",
        "fuzz-smoke",
        "fmt",
        "deny",
        "audit",
        "build",
        "static-release-linkage",
    }

    def test_ci_verdict_aggregates_every_blocking_lane(self) -> None:
        """Prevents any blocking lane, including static linkage, escaping CI verdict."""
        verdict = job_block(CI, "ci-verdict")
        needs_match = re.search(r"(?m)^    needs:\n(?P<body>(?:      - [^\n]+\n)+)", verdict)
        self.assertIsNotNone(needs_match)
        actual = {
            line.removeprefix("      - ")
            for line in needs_match.group("body").splitlines()
        }
        self.assertEqual(actual, self.blocking_jobs)
        self.assertNotIn("clippy", actual)
        self.assertIn('all(.[]; .result == "success")', verdict)
        self.assertIn("length == 19", verdict)
        self.assertIn("permissions: {}", verdict)

    def test_static_hyperscan_release_profile_is_a_blocking_ci_gate(self) -> None:
        """Rejects first-at-tag static linking and any Linux release retaining libhs."""
        gate = job_block(CI, "static-release-linkage")
        for contract in (
            "libhyperscan-dev=5.4.2-2",
            "pkg-config=1.8.1-2build1",
            "HYPERSCAN_ROOT",
            "cargo build --locked --release -p keyhog --features static-hyperscan",
            "ldd target/release/keyhog",
            "grep -Eiq 'libhs|libhyperscan'",
        ):
            self.assertIn(contract, gate)

    def test_native_receipts_bracket_build_before_untracked_payload_staging(self) -> None:
        """Rejects pre-build native capture after execution or post-build proof after staging."""
        build = job_block(RELEASE, "build")
        capture = build.index("Record exact static native build inputs")
        compile_binary = build.index("Build keyhog")
        link = build.index("Record exact Linux linkage closure")
        gpu = build.index("Build GPU literal artifacts")
        self.assertLess(capture, compile_binary)
        self.assertLess(compile_binary, link)
        for contract in (
            "-C linker=$KEYHOG_LINKER_WRAPPER",
            "-Wl,-Map=$GITHUB_WORKSPACE/keyhog-linux-x86_64.link.map",
            "--link-map keyhog-linux-x86_64.link.map",
            '--linked-native-archive "$KEYHOG_LINKED_NATIVE_CAPTURE"',
            '--linked-native-path "$KEYHOG_LINKED_NATIVE_PATH"',
            'exec /usr/bin/cc "$@"',
        ):
            self.assertIn(contract, build)
        self.assertLess(link, gpu)
        self.assertLess(
            build.index("Attest finalized static native linkage"),
            gpu,
        )
        self.assertIn("--binary target/release/keyhog", build)
        self.assertIn(
            "KEYHOG_RELEASE_TAG_OBJECT: ${{ needs.ci-verdict.outputs.tag_object }}",
            build[capture:gpu],
        )

    def test_offline_sbom_rederivation_prefetches_with_pinned_rust(self) -> None:
        """Rejects signing or smoke SBOM verification without its exact Cargo inputs."""
        for job_name in ("sign", "smoke"):
            block = job_block(RELEASE, job_name)
            toolchain = block.index("toolchain: '1.89'")
            fetch = block.index("cargo fetch --locked")
            sbom = block.index("release_sbom.py")
            self.assertLess(toolchain, fetch, job_name)
            self.assertLess(fetch, sbom, job_name)

    def test_five_integration_lanes_preserve_every_command(self) -> None:
        """Prevents integration sharding from silently dropping any existing command."""
        commands = (
            "cargo test -p keyhog-core --test all_tests --profile release-fast",
            "cargo test -p keyhog-scanner --test all_tests --no-default-features --features ci-lean --profile release-fast",
            "cargo test -p keyhog-scanner --test unit_gates_live ci_scanner --no-default-features --features ci-lean --profile release-fast -- --nocapture",
            "cargo test -p keyhog-scanner --test gpu_literal_artifact_writer --no-default-features --features ci-lean --profile release-fast",
            "cargo test -p keyhog-scanner --test adversarial_suite --no-default-features --features ci-lean --profile release-fast",
            "cargo test -p keyhog-sources --test all_tests --profile release-fast",
            "cargo test -p keyhog-sources --test all_tests --features binary --profile release-fast",
            'cargo test -p keyhog-sources --lib --features "github,gitlab,bitbucket,slack,azure,gcs,s3,docker,binary" --profile release-fast',
            'cargo test -p keyhog-sources --features "github,gitlab,bitbucket,slack,azure,gcs,s3,docker,binary" --profile release-fast -- --test-threads=1',
            "cargo test -p keyhog-verifier --test all_tests --profile release-fast",
            "cargo test -p keyhog-verifier --test break_it --profile release-fast -- --test-threads=1",
            "cargo test -p keyhog --test all_tests --no-default-features --features ci-lean --profile release-fast",
            "cargo test -p keyhog --test vyre_pin_coherence_lane3 --no-default-features --features ci-lean --profile release-fast",
            "cargo test -p keyhog --no-default-features --features ci-lean --profile release-fast --test coherence_wiring_lane7 --test lane10_verification_doc_coherence --test coherence_verify_count",
            "cargo test -p keyhog --test property --profile release-fast",
            "cargo test -p keyhog --test adversarial --profile release-fast -- --test-threads=4",
            "cargo test -p keyhog-scanner --test all_detectors_self_validate --profile release-fast",
            "cargo test -p keyhog-scanner --no-default-features --features ci-lean --profile release-fast --test homoglyph_ascii_skip_parity homoglyph_ascii_skip_parity_default",
            "cargo test -p keyhog-scanner --no-default-features --features ci-lean --profile release-fast --test regression_ac_overlap_shadow shadowed_inner_literal_is_ac_confirmed_with_variant_skipped",
            "cargo test -p keyhog-scanner --no-default-features --features ci-lean --profile release-fast --test fallback_order_independence push_match_eviction_set_is_insertion_order_independent",
            "cargo test -p keyhog-scanner --no-default-features --features ci-lean --profile release-fast --test basic_auth_credentials_recall",
            "cargo test -p keyhog-scanner --no-default-features --features ci-lean --profile release-fast --test regression_named_detector_anchor_floor_recall",
            "cargo test -p keyhog-scanner --no-default-features --features ci-lean --profile release-fast --test regression_named_canonical_hex_key_recall",
            "cargo test -p keyhog-scanner --no-default-features --features ci-lean --profile release-fast --test regression_per_pattern_weak_anchor_recall",
            "cargo test -p keyhog-scanner --no-default-features --features ci-lean --profile release-fast --test regression_charclass_prefix_expansion_recall",
            "cargo test -p keyhog-scanner --no-default-features --features ci-lean --profile release-fast --test regression_leading_assertion_and_alternation_prefix_recall",
            "cargo test -p keyhog-scanner --no-default-features --features ci-lean --profile release-fast --test regression_distinctive_infix_anchor_recall",
            "cargo test -p keyhog-scanner --no-default-features --features ci-lean --profile release-fast --test regression_checksum_boundary_no_downgrade",
            "cargo test -p keyhog-scanner --no-default-features --features ci-lean --profile release-fast --test regression_detector_owned_keyword_separators",
            "cargo test -p keyhog-core --test new_core_finding_dedup --profile release-fast",
        )
        for command in commands:
            self.assertEqual(CI.count(command), 1, command)
        for lane in (
            "integration-core-scanner",
            "integration-sources",
            "integration-verifier",
            "integration-cli",
            "integration-detector-contracts",
        ):
            block = job_block(CI, lane)
            self.assertIn("lfs: true", block)
            self.assertIn("Install Vectorscan", block)
            self.assertIn("rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32", block)
        aggregate = job_block(CI, "integration-verdict")
        for lane in (
            "integration-core-scanner",
            "integration-sources",
            "integration-verifier",
            "integration-cli",
            "integration-detector-contracts",
        ):
            self.assertIn(f"- {lane}", aggregate)
        self.assertIn("if: ${{ always() }}", aggregate)
        self.assertIn("length == 5", aggregate)
        self.assertIn('all(.[]; .result == "success")', aggregate)


    def test_automatic_trigger_is_tag_push_for_oidc_provenance(self) -> None:
        """Prevents detached workflow_run provenance from authorizing a release."""
        trigger = RELEASE.split("jobs:", 1)[0]
        self.assertIn("push:\n    tags:\n      - 'v*'", trigger)
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("workflow_run:", trigger)
        self.assertNotIn("github.event.workflow_run", RELEASE)

    def test_gate_binds_ci_event_tag_ref_sha_and_final_verdict(self) -> None:
        """Prevents actor/ref/SHA/tag/main or final-CI drift at the release boundary."""
        gate = job_block(RELEASE, "ci-verdict")
        for contract in (
            'KEYHOG_EVENT_REF: ${{ github.ref }}',
            'KEYHOG_EVENT_SHA: ${{ github.sha }}',
            'KEYHOG_EVENT_ACTOR_ID: ${{ github.actor_id }}',
            '"$KEYHOG_EVENT_ACTOR_ID" != "64453045"',
            'KEYHOG_TRIGGER_EVENT" == "push"',
            '"$KEYHOG_EVENT_REF" != "refs/tags/$tag"',
            '"$KEYHOG_EVENT_SHA" != "$tag_commit"',
            'actions/workflows/ci.yml/runs?head_sha=$tag_commit&event=push',
            'for _attempt in $(seq 1 360)',
            '"pending"',
            'git/ref/tags/$tag',
            'git/tags/$tag_object',
            "verify_release_tag.py",
            "tag_object: ${{ steps.verdict.outputs.tag_object }}",
            '.name == "CI verdict"',
            'git/ref/heads/main',
            'compare/$commit...$main_sha',
            "--main-ref-json",
            "--compare-json",
            '.conclusion == "success"',
        ):
            self.assertIn(contract, gate)
        self.assertNotIn(".url", gate)

    def test_crate_recovery_revalidates_same_fixed_tag_api_proof(self) -> None:
        """Prevents manual crate recovery from bypassing the signed-tag API proof."""
        self.assertIn(
            'gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$KEYHOG_RELEASE_TAG"',
            CRATES,
        )
        self.assertIn('KEYHOG_EVENT_ACTOR_ID: ${{ github.actor_id }}', CRATES)
        self.assertIn('"$KEYHOG_EVENT_ACTOR_ID" != "64453045"', CRATES)
        self.assertIn('--actor-id "$KEYHOG_EVENT_ACTOR_ID"', CRATES)
        self.assertIn(
            'gh api "repos/$GITHUB_REPOSITORY/git/tags/$tag_object"',
            CRATES,
        )
        self.assertIn("automation/scripts/verify_release_tag.py", CRATES)
        self.assertNotIn(".object.url", CRATES)
        self.assertLess(
            CRATES.index("automation/scripts/verify_release_tag.py"),
            CRATES.index("Require crates.io credential"),
        )

    def test_manual_recovery_ref_and_sha_must_match_requested_tag(self) -> None:
        """Prevents a manual run from substituting another tag ref or commit."""
        gate = job_block(RELEASE, "ci-verdict")
        self.assertIn('tag="$KEYHOG_MANUAL_TAG"', gate)
        self.assertIn('commit="$KEYHOG_MANUAL_SHA"', gate)
        self.assertIn('"$KEYHOG_EVENT_REF" != "refs/tags/$tag"', gate)
        self.assertIn('"$KEYHOG_EVENT_SHA" != "$tag_commit"', gate)
        self.assertIn('.status != "completed"', gate)
        self.assertIn('.conclusion == "success"', gate)

    def test_every_privileged_or_build_job_is_downstream_of_gate(self) -> None:
        """Prevents privileged jobs from consuming unvalidated event or input refs."""
        direct = {
            "build",
            "installers",
            "sign",
            "smoke",
            "docker",
            "publish",
            "major-tag",
        }
        for job in direct:
            self.assertIn("ci-verdict", job_block(RELEASE, job), job)
        downstream = RELEASE.split("  build:\n", 1)[1]
        self.assertNotIn("${{ github.sha }}", downstream)
        self.assertNotIn("${{ github.ref }}", downstream)
        self.assertNotIn("${{ inputs.tag }}", downstream)
    def test_global_serial_publication_revalidates_latest_after_version_push(self) -> None:
        """Prevents an older serialized release from rolling the latest image backward."""
        header = RELEASE.split("jobs:", 1)[0]
        self.assertIn("group: release-${{ github.repository }}", header)
        self.assertIn("cancel-in-progress: false", header)

        docker = job_block(RELEASE, "docker")
        version_push = docker.index("Build and push new multi-arch version image")
        digest_attestation = docker.index("Attest new published image digest")
        revalidate = docker.index(
            "Revalidate newest stable immediately before latest mutation"
        )
        latest_mutation = docker.index("Advance latest image for the newest stable release")
        self.assertLess(version_push, digest_attestation)
        self.assertLess(digest_attestation, revalidate)
        self.assertLess(revalidate, latest_mutation)
        self.assertEqual(docker.count("is-newest-stable-tag.sh"), 1)

    def test_existing_version_image_is_verified_not_overwritten_and_runtime_smoked(self) -> None:
        """Rejects GHCR rerun overwrite or publication without digest-addressed product smoke."""
        docker = job_block(RELEASE, "docker")
        resolve = docker.index("Resolve existing immutable version image")
        conditional_build = docker.index("if: steps.existing-image.outputs.exists != 'true'")
        smoke = docker.index("Smoke exact digest-addressed container runtime")
        latest = docker.index("Advance latest image for the newest stable release")
        self.assertLess(resolve, conditional_build)
        self.assertLess(conditional_build, smoke)
        self.assertLess(smoke, latest)
        for contract in (
            'gh attestation verify "oci://$KEYHOG_IMAGE@$digest"',
            '--signer-digest "$KEYHOG_WORKFLOW_SHA"',
            '--source-digest "$KEYHOG_RELEASE_COMMIT"',
            'candidate="$KEYHOG_IMAGE@$KEYHOG_IMAGE_DIGEST"',
            "docker run --rm --platform linux/amd64",
            "--backend simd",
            "stripe-secret-key",
        ):
            self.assertIn(contract, docker)

    def test_newer_overlapping_tag_cannot_be_rolled_back_by_older_run(self) -> None:
        """Prevents overlapping older publication from moving latest backward."""
        header = RELEASE.split("jobs:", 1)[0]
        docker = job_block(RELEASE, "docker")
        # A global non-cancelling lock prevents overlap. If a newer tag appears
        # while an older version image builds, the last-moment helper fetches
        # tags again and returns false for the older run before `latest` mutates.
        self.assertIn("group: release-${{ github.repository }}", header)
        self.assertIn("cancel-in-progress: false", header)
        self.assertIn(
            "Global release concurrency plus this immediate\n"
            "      # revalidation prevents an older overlapping run",
            docker,
        )
        self.assertLess(
            docker.index("is-newest-stable-tag.sh"),
            docker.index('ghcr.io/${{ github.repository }}:latest'),
        )

    def test_privileged_jobs_execute_only_workflow_revision_automation(self) -> None:
        """Rejects tag-controlled scripts executing in contents/packages-write jobs."""
        docker = job_block(RELEASE, "docker")
        publish = job_block(RELEASE, "publish")
        major = job_block(RELEASE, "major-tag")
        for block in (docker, publish, major):
            self.assertIn("ref: ${{ github.workflow_sha }}", block)
            self.assertIn("path: automation", block)
            self.assertIn("persist-credentials: false", block)
        self.assertIn(
            "automation/scripts/is-newest-stable-tag.sh",
            docker,
        )
        self.assertIn(
            "automation/scripts/publish_release_assets.py",
            publish,
        )
        self.assertIn(
            "automation/scripts/is-newest-stable-tag.sh",
            major,
        )
        self.assertNotIn("python3 scripts/publish_release_assets.py", publish)
        self.assertNotIn("bash scripts/is-newest-stable-tag.sh", docker + major)



class SignedAnnotatedTagBehaviorTests(unittest.TestCase):
    tag = "v0.5.48"
    commit = "a" * 40
    tag_object = "b" * 40

    def ref_record(self, *, object_type: str = "tag") -> dict[str, object]:
        return {
            "ref": f"refs/tags/{self.tag}",
            "object": {"type": object_type, "sha": self.tag_object},
        }

    tagger_date = "2026-07-27T12:34:56+00:00"
    message = "Release v0.5.48"

    def tag_record(
        self,
        *,
        verified: bool = True,
        object_sha: str | None = None,
        peeled_commit: str | None = None,
        tagger_name: str = AUTHORIZED_TAGGER_NAME,
        tagger_email: str = AUTHORIZED_TAGGER_EMAIL,
        payload: str | None = None,
    ) -> dict[str, object]:
        commit = peeled_commit or self.commit
        timestamp = int(dt.datetime.fromisoformat(self.tagger_date).timestamp())
        expected_payload = (
            f"object {commit}\n"
            "type commit\n"
            f"tag {self.tag}\n"
            f"tagger {tagger_name} <{tagger_email}> {timestamp} +0000\n\n"
            f"{self.message}"
        )
        return {
            "tag": self.tag,
            "sha": object_sha or self.tag_object,
            "object": {"type": "commit", "sha": commit},
            "tagger": {
                "name": tagger_name,
                "email": tagger_email,
                "date": self.tagger_date,
            },
            "message": self.message,
            "verification": {
                "verified": verified,
                "reason": "valid" if verified else "unsigned",
                "signature": "-----BEGIN PGP SIGNATURE-----\nsigned\n",
                "payload": payload if payload is not None else expected_payload,
            },
        }

    def verify(
        self,
        *,
        ref_record: dict[str, object] | None = None,
        tag_record: dict[str, object] | None = None,
    ) -> str:
        return verify_signed_tag(
            tag=self.tag,
            expected_commit=self.commit,
            ref_record=ref_record or self.ref_record(),
            tag_record=tag_record or self.tag_record(),
        )

    def test_valid_signed_annotated_tag_binds_top_level_object(self) -> None:
        """Prevents trusting only a peeled commit instead of the signed tag object."""
        self.assertEqual(self.verify(), self.tag_object)

    def test_lightweight_tag_is_rejected(self) -> None:
        """Prevents unsigned lightweight refs from reaching release publication."""
        with self.assertRaisesRegex(TagVerificationError, "lightweight"):
            self.verify(ref_record=self.ref_record(object_type="commit"))

    def test_unsigned_annotated_tag_is_rejected(self) -> None:
        """Prevents an annotated but unsigned object from authorizing release."""
        with self.assertRaisesRegex(TagVerificationError, "not verified"):
            self.verify(tag_record=self.tag_record(verified=False))

    def test_wrong_top_level_tag_object_is_rejected(self) -> None:
        """Prevents authenticated ref/object substitution before signature proof."""
        with self.assertRaisesRegex(TagVerificationError, "does not match"):
            self.verify(tag_record=self.tag_record(object_sha="c" * 40))

    def test_signed_tag_peeling_to_wrong_commit_is_rejected(self) -> None:
        """Prevents a valid signed tag from authorizing a different build commit."""
        with self.assertRaisesRegex(TagVerificationError, "triggering CI commit"):
            self.verify(tag_record=self.tag_record(peeled_commit="d" * 40))

    def test_noncanonical_semver_tags_are_rejected(self) -> None:
        """Rejects tags whose numeric or prerelease identifiers are noncanonical SemVer."""
        for tag in (
            "v00.5.48",
            "v0.05.48",
            "v0.5.048",
            "v0.5.48-01",
            "v0.5.48-rc..1",
            "v0.5.48-rc.",
            "v0.5.48+build",
        ):
            with self.subTest(tag=tag), self.assertRaisesRegex(
                TagVerificationError, "canonical|leading-zero"
            ):
                verify_signed_tag(
                    tag=tag,
                    expected_commit=self.commit,
                    ref_record=self.ref_record(),
                    tag_record=self.tag_record(),
                )

    def test_spoofed_tagger_identity_is_rejected(self) -> None:
        """Rejects a valid signature payload that claims a foreign tagger identity."""
        with self.assertRaisesRegex(TagVerificationError, "authorized tagger identity"):
            self.verify(tag_record=self.tag_record(tagger_name="Mallory"))

    def test_spoofed_verified_payload_is_rejected(self) -> None:
        """Rejects signed payload drift in object type, tag, tagger date, or message."""
        replacements = (
            ("type commit", "type tree"),
            (f"tag {self.tag}", "tag v9.9.9"),
            (" 1785155696 +0000", " 1785155697 +0000"),
            (self.message, "Different release message"),
        )
        for old, new in replacements:
            signed = self.tag_record()
            verification = dict(signed["verification"])
            verification["payload"] = str(verification["payload"]).replace(old, new)
            signed["verification"] = verification
            with self.subTest(field=old), self.assertRaisesRegex(
                TagVerificationError, "payload"
            ):
                self.verify(tag_record=signed)

    def test_api_date_timezone_normalization_preserves_signed_instant(self) -> None:
        """Accepts GitHub API timezone normalization only when the signed instant is equal."""
        signed = self.tag_record()
        signed["tagger"] = {
            "name": AUTHORIZED_TAGGER_NAME,
            "email": AUTHORIZED_TAGGER_EMAIL,
            "date": "2026-07-27T14:34:56+02:00",
        }
        self.assertEqual(self.verify(tag_record=signed), self.tag_object)

    def test_release_actor_is_bound_to_stable_account_id(self) -> None:
        """Rejects release entry by any mutable login or non-owner stable actor ID."""
        verify_release_actor(AUTHORIZED_ACTOR_ID)
        with self.assertRaisesRegex(TagVerificationError, "stable account ID"):
            verify_release_actor("99999999")

    def main_ref_record(self, sha: str) -> dict[str, object]:
        return {
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": sha},
        }

    def compare_record(
        self,
        *,
        main_sha: str,
        merge_base: str | None = None,
    ) -> dict[str, object]:
        return {
            "status": "ahead",
            "base_commit": {"sha": self.commit},
            "head_commit": {"sha": main_sha},
            "merge_base_commit": {"sha": merge_base or self.commit},
        }

    def test_release_commit_must_be_in_pinned_main_ancestry(self) -> None:
        """Rejects owner-signed side-branch commits outside pinned main ancestry."""
        main_sha = "c" * 40
        self.assertEqual(
            verify_main_ancestry(
                expected_commit=self.commit,
                main_ref_record=self.main_ref_record(main_sha),
                compare_record=self.compare_record(main_sha=main_sha),
            ),
            main_sha,
        )
        with self.assertRaisesRegex(TagVerificationError, "trusted main ancestry"):
            verify_main_ancestry(
                expected_commit=self.commit,
                main_ref_record=self.main_ref_record(main_sha),
                compare_record=self.compare_record(
                    main_sha=main_sha,
                    merge_base="d" * 40,
                ),
            )


class AuthorizedSignerBehaviorTests(unittest.TestCase):
    """Exercise real isolated GPG signatures at the release trust boundary."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary_homes: list[tempfile.TemporaryDirectory[str]] = []
        cls.authorized = cls._generate_signer("Authorized release fixture")
        cls.foreign = cls._generate_signer("Foreign verified fixture")

    @classmethod
    def tearDownClass(cls) -> None:
        for temporary in cls._temporary_homes:
            temporary.cleanup()

    @classmethod
    def _generate_signer(cls, name: str) -> tuple[Path, str, str]:
        temporary = tempfile.TemporaryDirectory()
        cls._temporary_homes.append(temporary)
        home = Path(temporary.name)
        home.chmod(0o700)
        subprocess.run(
            [
                "gpg",
                "--no-options",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--homedir",
                str(home),
                "--quick-gen-key",
                f"{name} <fixture@example.invalid>",
                "ed25519",
                "sign",
                "0",
            ],
            check=True,
            text=True,
            capture_output=True,
        )
        listed = subprocess.run(
            [
                "gpg",
                "--no-options",
                "--batch",
                "--homedir",
                str(home),
                "--with-colons",
                "--list-keys",
            ],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
        fingerprint = next(
            line.split(":")[9]
            for line in listed.splitlines()
            if line.startswith("fpr:")
        )
        exported = subprocess.run(
            [
                "gpg",
                "--no-options",
                "--batch",
                "--homedir",
                str(home),
                "--armor",
                "--export",
                fingerprint,
            ],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
        return home, fingerprint, exported

    def _signed_record(self, signer: tuple[Path, str, str]) -> dict[str, object]:
        record = SignedAnnotatedTagBehaviorTests().tag_record()
        verification = dict(record["verification"])
        payload = str(verification["payload"])
        payload_path = signer[0] / "payload"
        signature_path = signer[0] / "payload.asc"
        payload_path.write_text(payload, encoding="utf-8")
        signature_path.unlink(missing_ok=True)
        subprocess.run(
            [
                "gpg",
                "--no-options",
                "--batch",
                "--homedir",
                str(signer[0]),
                "--armor",
                "--detach-sign",
                "--output",
                str(signature_path),
                str(payload_path),
            ],
            check=True,
            text=True,
            capture_output=True,
        )
        verification["signature"] = signature_path.read_text(encoding="utf-8")
        record["verification"] = verification
        return record

    def test_allowlisted_release_key_authenticates_exact_payload(self) -> None:
        """Accepts an exact tag payload signed by the enrolled allowlisted primary key."""
        verify_authorized_signature(
            tag_record=self._signed_record(self.authorized),
            authorized_fingerprint=self.authorized[1],
            authorized_public_key=self.authorized[2],
            github_gpg_keys=[{"raw_key": self.authorized[2]}],
        )

    def test_valid_foreign_signed_tag_is_rejected(self) -> None:
        """Rejects a cryptographically valid foreign tag even if GitHub enrolled its key."""
        with self.assertRaisesRegex(TagVerificationError, "allowlisted"):
            verify_authorized_signature(
                tag_record=self._signed_record(self.foreign),
                authorized_fingerprint=self.authorized[1],
                authorized_public_key=self.authorized[2],
                github_gpg_keys=[
                    {"raw_key": self.authorized[2]},
                    {"raw_key": self.foreign[2]},
                ],
            )

    def test_missing_fingerprint_blocks_publication(self) -> None:
        """Blocks release publication until an exact full release-key fingerprint exists."""
        with self.assertRaisesRegex(TagVerificationError, "no exact santhreal"):
            verify_authorized_signature(
                tag_record=self._signed_record(self.authorized),
                authorized_fingerprint="",
                authorized_public_key=self.authorized[2],
                github_gpg_keys=[{"raw_key": self.authorized[2]}],
            )

    def test_missing_committed_public_key_blocks_publication(self) -> None:
        """Blocks publication until the enrolled allowlisted public key is committed."""
        with self.assertRaisesRegex(TagVerificationError, "no committed santhreal"):
            verify_authorized_signature(
                tag_record=self._signed_record(self.authorized),
                authorized_fingerprint=self.authorized[1],
                authorized_public_key="",
                github_gpg_keys=[{"raw_key": self.authorized[2]}],
            )

    def test_malformed_or_duplicate_github_keys_are_rejected(self) -> None:
        """Rejects malformed or duplicate GitHub key API records instead of skipping them."""
        malformed = (
            [None],
            [{}],
            [{"raw_key": ""}],
            [{"raw_key": self.authorized[2]}, {"raw_key": self.authorized[2]}],
        )
        for keys in malformed:
            with self.subTest(keys=keys), self.assertRaisesRegex(
                TagVerificationError, "record|duplicate"
            ):
                verify_authorized_signature(
                    tag_record=self._signed_record(self.authorized),
                    authorized_fingerprint=self.authorized[1],
                    authorized_public_key=self.authorized[2],
                    github_gpg_keys=keys,
                )

    def test_missing_gpg_is_contextual_verification_failure(self) -> None:
        """Wraps a missing GPG executable as a fail-closed release verification error."""
        signed = self._signed_record(self.authorized)
        with mock.patch(
            "scripts.verify_release_tag.subprocess.run",
            side_effect=FileNotFoundError("gpg unavailable"),
        ), self.assertRaisesRegex(TagVerificationError, "isolated GPG"):
            verify_authorized_signature(
                tag_record=signed,
                authorized_fingerprint=self.authorized[1],
                authorized_public_key=self.authorized[2],
                github_gpg_keys=[{"raw_key": self.authorized[2]}],
            )


class SignedSbomManifestContracts(unittest.TestCase):
    sbom_assets = {
        "install.sh.spdx.json",
        "install.ps1.spdx.json",
        "keyhog-linux-x86_64.spdx.json",
        "keyhog-macos-aarch64.spdx.json",
        "keyhog-macos-x86_64.spdx.json",
        "keyhog-windows-x86_64.exe.spdx.json",
        "keyhog-linux-x86_64.gpu-literals.tar.gz.spdx.json",
        "keyhog-macos-aarch64.gpu-literals.tar.gz.spdx.json",
        "keyhog-macos-x86_64.gpu-literals.tar.gz.spdx.json",
        "keyhog-windows-x86_64.exe.gpu-literals.tar.gz.spdx.json",
    }

    def test_public_verifier_requires_exact_signed_sbom_triples(self) -> None:
        """Rejects the obsolete 48-asset/6-SBOM release inventory."""
        names = expected_asset_names()
        self.assertEqual(len(names), 60)
        for sbom in self.sbom_assets:
            self.assertTrue({sbom, f"{sbom}.sha256", f"{sbom}.minisig"} <= names)

    def test_workflow_generates_signs_attests_stages_and_smokes_sboms(self) -> None:
        """Requires attested native/Cargo receipts and all ten signed SBOM triples."""
        sign = job_block(RELEASE, "sign")
        smoke = job_block(RELEASE, "smoke")
        build = job_block(RELEASE, "build")
        self.assertIn("release_sbom.py dependency-receipt", build)
        self.assertIn("${{ matrix.asset }}.dependencies.json", build)
        self.assertIn("--tag '${{ needs.ci-verdict.outputs.tag }}'", build)
        self.assertIn("native-build-receipt", build)
        self.assertIn("native-link-receipt", build)
        self.assertIn("Attest dependency receipts before build scripts execute", build)
        self.assertLess(
            build.index("Attest dependency receipts before build scripts execute"),
            build.index("name: Build keyhog"),
        )
        self.assertIn("Attest static native inputs before linking", build)
        for command in ("manifest", "generate", "verify"):
            self.assertIn(f'release_sbom.py" {command} \\', sign)
        self.assertEqual(sign.count('--dependency-dir "$workdir"'), 3)
        self.assertIn('signed_payloads=("${payloads[@]}" "${sboms[@]}")', sign)
        self.assertIn('final=("${expected[@]}")', sign)
        self.assertIn("Attest generated SPDX release assets", sign)
        self.assertIn(
            "subject-path: ${{ runner.temp }}/keyhog-release-signed/*.spdx.json",
            sign,
        )
        self.assertIn("keyhog-release-signed/*.spdx.json.sha256", sign)
        self.assertIn("keyhog-release-signed/*.spdx.json.minisig", sign)
        self.assertIn("keyhog-release-signed/*.dependencies.json", sign)
        self.assertIn("keyhog-release-signed/*.native-build.json", sign)
        self.assertIn("keyhog-release-signed/*.native-link.json", sign)
        self.assertIn("gh attestation verify", sign)
        self.assertIn("KEYHOG_RELEASE_TAG_OBJECT:", sign)
        self.assertIn('"${#final[@]}" -ne 60', sign)
        self.assertIn('sboms+=("$payload.spdx.json")', smoke)
        self.assertIn("release_sbom.py\" verify", smoke)
        self.assertIn('--dependency-dir "$sbom_dir"', smoke)
        self.assertIn('sha256sum -c "$sbom.sha256"', smoke)
        self.assertIn('minisign -Vm "$sbom"', smoke)
        self.assertIn('"${#sboms[@]}" -ne 10', smoke)
        for block in (sign, smoke):
            self.assertIn("path: source", block)
            self.assertIn('--source-dir "$GITHUB_WORKSPACE/source"', block)
            self.assertNotIn("--allow-untracked-path", block)
        self.assertIn("$RUNNER_TEMP/keyhog-release-signed", sign)
        self.assertIn("$RUNNER_TEMP/keyhog-sbom-candidate", smoke)
        self.assertIn("external release work path already exists", sign)
        self.assertIn("external candidate work path already exists", smoke)


class LeastPrivilegeAndPinContracts(unittest.TestCase):
    def test_workflows_encode_default_deny_or_read_only_permissions(self) -> None:
        self.assertIn("permissions: {}", RELEASE.split("jobs:", 1)[0])
        self.assertIn("permissions: {}", CRATES.split("jobs:", 1)[0])
        self.assertIn("permissions:\n  contents: read", CI.split("jobs:", 1)[0])
        self.assertIn("actions: read", job_block(RELEASE, "ci-verdict"))
        self.assertNotIn("write", job_block(RELEASE, "ci-verdict"))
        self.assertEqual(
            re.findall(r"(?m)^      ([a-z-]+): write", job_block(RELEASE, "docker")),
            ["packages", "id-token", "attestations"],
        )
        self.assertNotIn("write", job_block(CRATES, "publish"))

    def test_production_runner_images_are_not_floating(self) -> None:
        """Prevents any workflow job or OS matrix from inheriting a moving VM image."""
        workflows = sorted(
            path
            for path in (ROOT / ".github" / "workflows").iterdir()
            if path.suffix in {".yml", ".yaml"}
        )
        self.assertTrue(workflows)
        for path in workflows:
            workflow = path.read_text(encoding="utf-8")
            self.assertNotRegex(
                workflow,
                r"\b(?:ubuntu|windows|macos)-latest\b",
                f"{path.name} contains a floating production runner label",
            )
        self.assertIn("runs-on: ubuntu-24.04", CI)
        self.assertIn("runs-on: macos-15", CI)
        self.assertIn("runs-on: windows-2025", CI)
        self.assertIn("- os: ubuntu-24.04", RELEASE)
        self.assertIn("- os: macos-15", RELEASE)
        self.assertIn("- os: windows-2025", RELEASE)
        self.assertIn("runs-on: ubuntu-24.04", CRATES)

    def test_every_external_action_is_sha_pinned(self) -> None:
        """Prevents any workflow, not only release CI, from executing a moving action."""
        workflows = sorted(
            path
            for path in (ROOT / ".github" / "workflows").iterdir()
            if path.suffix in {".yml", ".yaml"}
        )
        for path in workflows:
            workflow = path.read_text(encoding="utf-8")
            for action in re.findall(
                r"(?m)^\s+(?:-\s+)?uses:\s+([^\s#]+)", workflow
            ):
                if action.startswith("./"):
                    continue
                self.assertRegex(action, r"@[0-9a-f]{40}$", f"{path.name}: {action}")

    def test_crates_credential_is_unavailable_until_public_verdict(self) -> None:
        verify_at = CRATES.index("Require immutable published release verdict")
        credential_at = CRATES.index("Require crates.io credential")
        publish_at = CRATES.index("Publish and verify every workspace crate")
        self.assertLess(verify_at, credential_at)
        self.assertLess(credential_at, publish_at)
        self.assertIn("verify_published_release.py", CRATES[verify_at:credential_at])


if __name__ == "__main__":
    unittest.main()
