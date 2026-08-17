"""Pass/fail locks for `scripts/gates/gpu_wired.py` (Row 2).

Unit-tests all 4 gate rules in isolation against fixture workflows, including YAML
folded scalars (`run: >`), step-level absorption, orphan detection, and release
lane policy arming/preflight ordering.
"""

from __future__ import annotations

import unittest

from scripts.gates import gpu_wired as gw


class IsGpuTargetTests(unittest.TestCase):
    def test_gpu_token_matching(self) -> None:
        self.assertTrue(gw.is_gpu_target("gpu_parity"))
        self.assertTrue(gw.is_gpu_target("e2e_gpu_autoroute_optin"))
        self.assertTrue(gw.is_gpu_target("regression_require_gpu_fails_closed"))
        self.assertFalse(gw.is_gpu_target("perf_floor"))
        self.assertFalse(gw.is_gpu_target("all_tests"))


class FoldYamlScalarsTests(unittest.TestCase):
    def test_folded_scalar_joining(self) -> None:
        text = (
            "      - name: fail-closed\n"
            "        run: >\n"
            "          cargo test -p keyhog --no-fail-fast\n"
            "          --test regression_require_gpu_fails_closed\n"
        )
        folded = gw.fold_yaml_scalars(text)
        self.assertIn("cargo test -p keyhog --no-fail-fast --test regression_require_gpu_fails_closed", folded)


class Rule1FeatureFlagTests(unittest.TestCase):
    def test_unfeatured_gpu_step_fails(self) -> None:
        unfeatured = {
            "ci.yml": (
                "      - name: gpu\n"
                "        run: |\n"
                "          cargo test -p keyhog-scanner \\\n"
                "            --test gpu_parity\n"
            )
        }
        failures = gw.check_workflows(unfeatured)
        self.assertTrue(bool(failures))
        self.assertIn("without `--features gpu`", failures[0])
    def test_featured_gpu_step_passes(self) -> None:
        featured = {
            "ci.yml": (
                "      - name: gpu\n"
                "        run: |\n"
                "          cargo test -p keyhog-scanner --features gpu \\\n"
                "            --test gpu_parity\n"
            )
        }
        failures = gw.check_workflows(featured)
        self.assertEqual(failures, [])

    def test_folded_scalar_unfeatured_fails(self) -> None:
        folded_unfeatured = {
            "ci.yml": (
                "      - name: fail-closed\n"
                "        run: >\n"
                "          cargo test -p keyhog --no-fail-fast\n"
                "          --test regression_require_gpu_fails_closed\n"
            )
        }
        failures = gw.check_workflows(folded_unfeatured)
        self.assertTrue(bool(failures))

    def test_folded_scalar_featured_passes(self) -> None:
        folded_featured = {
            "ci.yml": (
                "      - name: fail-closed\n"
                "        run: >\n"
                "          cargo test -p keyhog --features gpu --no-fail-fast\n"
                "          --test regression_require_gpu_fails_closed\n"
            )
        }
        failures = gw.check_workflows(folded_featured)
        self.assertEqual(failures, [])


class Rule2AbsorptionTests(unittest.TestCase):
    def test_absorbed_gpu_step_fails(self) -> None:
        absorbed = {
            "ci.yml": (
                "      - name: gpu\n"
                "        continue-on-error: true\n"
                "        run: |\n"
                "          cargo test -p keyhog-scanner --features gpu \\\n"
                "            --test gpu_parity\n"
            )
        }
        failures = gw.check_workflows(absorbed)
        self.assertTrue(bool(failures))
        self.assertIn("continue-on-error: true", failures[0])
    def test_neighbour_absorbed_step_does_not_blame_gpu(self) -> None:
        neighbour = {
            "ci.yml": (
                "      - name: flaky\n"
                "        continue-on-error: true\n"
                "        run: cargo test -p keyhog-scanner --test perf_floor\n"
                "      - name: gpu\n"
                "        run: |\n"
                "          cargo test -p keyhog-scanner --features gpu --test gpu_parity\n"
            )
        }
        failures = gw.check_workflows(neighbour)
        self.assertEqual(failures, [])


class Rule3OrphanTests(unittest.TestCase):
    def test_unwired_gpu_test_file_fails(self) -> None:
        workflows = {
            "ci.yml": "        run: cargo test -p keyhog-scanner --features gpu --test gpu_parity\n"
        }
        stems = {
            "gpu_parity": "crates/scanner/tests/gpu_parity.rs",
            "gpu_unwired": "crates/scanner/tests/gpu_unwired.rs",
        }
        failures = gw.check_orphans(workflows, stems)
        self.assertEqual(len(failures), 1)
        self.assertIn("gpu_unwired", failures[0])

    def test_wired_gpu_test_file_passes(self) -> None:
        workflows = {
            "ci.yml": "        run: cargo test -p keyhog-scanner --features gpu --test gpu_parity\n"
        }
        stems = {"gpu_parity": "crates/scanner/tests/gpu_parity.rs"}
        failures = gw.check_orphans(workflows, stems)
        self.assertEqual(failures, [])


class Rule4ReleaseLaneTests(unittest.TestCase):
    def test_armed_release_lane_passes(self) -> None:
        lane = (
            "export KEYHOG_REQUIRE_GPU=1\n"
            "keyhog backend --self-test --require-gpu\n"
            "cargo test -p keyhog-scanner --features gpu --test gpu_parity\n"
        )
        self.assertEqual(gw.check_release_lane(lane), [])

    def test_unarmed_release_lane_fails(self) -> None:
        lane = (
            "keyhog backend --self-test --require-gpu\n"
            "cargo test -p keyhog-scanner --features gpu --test gpu_parity\n"
        )
        failures = gw.check_release_lane(lane)
        self.assertTrue(bool(failures))
        self.assertIn(gw.RELEASE_ARM, failures[0])

    def test_preflight_after_test_fails(self) -> None:
        lane = (
            "export KEYHOG_REQUIRE_GPU=1\n"
            "cargo test -p keyhog-scanner --features gpu --test gpu_parity\n"
            "keyhog backend --self-test --require-gpu\n"
        )
        failures = gw.check_release_lane(lane)
        self.assertTrue(bool(failures))
        self.assertIn("runs after the first GPU test", failures[0])

class LiveGpuWiringTests(unittest.TestCase):
    def test_live_repo_gpu_wiring(self) -> None:
        self.assertEqual(gw.main([]), 0)


if __name__ == "__main__":
    unittest.main()
