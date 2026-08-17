"""Unit tests for `scripts/gates/vacuous_tests.py`."""

import unittest
from scripts.gates import vacuous_tests as vt


class VacuousTestsGateTests(unittest.TestCase):
    def test_self_test_passes(self) -> None:
        self.assertEqual(vt.self_test(), 0)

    def test_bad_fixture_detected(self) -> None:
        fixture = """
        #[test]
        fn test_sample() {
            if !gpu_available() {
                return;
            }
        }
        """
        violations = vt.check_test_content(fixture, "sample.rs")
        self.assertEqual(len(violations), 1)
        self.assertIn("sample.rs", violations[0])

    def test_good_fixture_accepted(self) -> None:
        fixture = """
        #[test]
        fn test_sample() {
            support::gpu_gate::arm_policy_from_env();
            if !gpu_available() {
                if keyhog_scanner::gpu::gpu_required_by_policy() {
                    panic!("required");
                }
                return;
            }
        }
        """
        violations = vt.check_test_content(fixture, "sample.rs")
        self.assertEqual(violations, [])

    def test_live_repo_check_passes(self) -> None:
        violations = vt.scan_all_test_files()
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
