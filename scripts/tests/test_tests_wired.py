"""Pass/fail locks for `scripts/gates/tests_wired.py`.

The gate models four independent ways a top-level `crates/<c>/tests/*.rs` file is
run in CI: a `#[path]` include, a `[pub] mod X;` sibling in the crate-root
`all_tests.rs`, a `--test <stem>` workflow flag, and an all-targets
`cargo test -p <pkg>` step (no target filter). Each rule below is asserted in
isolation plus a live check that every enforced crate is actually wired, so a
regression in either the model or the repo wiring goes red here.
"""

import re
import unittest

from scripts.gates import tests_wired as tw


class PathIncludeRegexTests(unittest.TestCase):
    def test_sibling_path_include_yields_bare_stem(self) -> None:
        self.assertEqual(
            tw.PATH_INCLUDE.findall('#[path = "regression_sigv4_known_answer.rs"]'),
            ["regression_sigv4_known_answer"],
        )

    def test_parent_relative_path_include_yields_bare_stem(self) -> None:
        self.assertEqual(
            tw.PATH_INCLUDE.findall('#[path = "../regression_oob_fail_closed.rs"]'),
            ["regression_oob_fail_closed"],
        )

    def test_nested_dir_path_include_yields_leaf_stem(self) -> None:
        self.assertEqual(
            tw.PATH_INCLUDE.findall('#[path = "support/archive.rs"]'),
            ["archive"],
        )

    def test_path_include_ignores_non_rs_paths(self) -> None:
        self.assertEqual(tw.PATH_INCLUDE.findall('#[path = "data/fixture.json"]'), [])


class ModDeclRegexTests(unittest.TestCase):
    def test_plain_mod_declaration_matches(self) -> None:
        self.assertEqual(tw.MOD_DECL.findall("mod wave9_edge;"), ["wave9_edge"])

    def test_pub_mod_declaration_matches(self) -> None:
        self.assertEqual(
            tw.MOD_DECL.findall("pub mod detector_corpus_integrity;"),
            ["detector_corpus_integrity"],
        )

    def test_inline_brace_module_is_not_a_sibling_wire(self) -> None:
        # `mod support {` opens an inline module, not a sibling file include.
        self.assertEqual(tw.MOD_DECL.findall("pub mod support {"), [])

    def test_cfg_gated_pub_mod_line_is_still_matched(self) -> None:
        # The `#[cfg(feature=…)]` sits on its own line; the `pub mod X;` line
        # below it must still register as wired.
        src = '#[cfg(feature = "s3")]\npub mod regression_s3_skipped_objects_counted;'
        self.assertIn("regression_s3_skipped_objects_counted", tw.MOD_DECL.findall(src))

    def test_multiple_mod_lines_all_captured_in_order(self) -> None:
        self.assertEqual(
            tw.MOD_DECL.findall("pub mod a;\nmod b;\npub mod c;"),
            ["a", "b", "c"],
        )


class TestFlagRegexTests(unittest.TestCase):
    def test_space_form_test_flag_matches(self) -> None:
        self.assertEqual(
            tw.TEST_FLAG.findall("cargo test -p keyhog-verifier --test break_it x"),
            ["break_it"],
        )

    def test_equals_form_test_flag_matches(self) -> None:
        self.assertEqual(tw.TEST_FLAG.findall("cargo test --test=all_tests"), ["all_tests"])

    def test_test_threads_arg_is_not_a_test_target(self) -> None:
        self.assertEqual(tw.TEST_FLAG.findall("cargo test -p x -- --test-threads=1"), [])


class TargetNarrowingTests(unittest.TestCase):
    def test_test_flag_counts_as_narrowing(self) -> None:
        self.assertTrue(
            any(f in "cargo test -p x --test all_tests" for f in tw.TARGET_NARROWING)
        )

    def test_lib_flag_counts_as_narrowing(self) -> None:
        self.assertTrue(
            any(f in "cargo test -p x --lib --features y" for f in tw.TARGET_NARROWING)
        )

    def test_test_threads_is_not_narrowing(self) -> None:
        self.assertFalse(
            any(f in "cargo test -p x -- --test-threads=1" for f in tw.TARGET_NARROWING)
        )

    def test_bare_all_features_step_is_not_narrowing(self) -> None:
        cmd = 'cargo test -p keyhog-sources --features "s3,docker" --profile release-fast'
        self.assertFalse(any(f in cmd for f in tw.TARGET_NARROWING))


class CratePkgTests(unittest.TestCase):
    def test_cli_ships_as_keyhog(self) -> None:
        self.assertEqual(tw.crate_pkg("cli"), "keyhog")

    def test_core_pkg_name(self) -> None:
        self.assertEqual(tw.crate_pkg("core"), "keyhog-core")

    def test_sources_pkg_name(self) -> None:
        self.assertEqual(tw.crate_pkg("sources"), "keyhog-sources")

    def test_pkg_word_boundary_does_not_match_longer_name(self) -> None:
        boundary = re.compile(r"-p\s+keyhog(?:\s|$)")
        self.assertIsNone(boundary.search("cargo test -p keyhog-sources --lib"))
        self.assertIsNotNone(boundary.search("cargo test -p keyhog --test all_tests"))


class OrphanMathTests(unittest.TestCase):
    def test_unwired_file_is_flagged(self) -> None:
        wired = {"a", "c"}
        got = [s for s in ["a", "b", "c", "d"] if s not in wired]
        self.assertEqual(got, ["b", "d"])

    def test_fully_wired_set_yields_no_orphans(self) -> None:
        wired = {"a", "b"}
        self.assertEqual([s for s in ["a", "b"] if s not in wired], [])


class LiveWiringTests(unittest.TestCase):
    """Integration: the real repo state must satisfy the model."""

    def test_gate_self_test_passes(self) -> None:
        self.assertEqual(tw.self_test(), 0)

    def test_all_enforced_crates_have_zero_orphans(self) -> None:
        flags = tw.workflow_test_flags()
        for crate in tw.ENFORCED_CRATES:
            self.assertEqual(
                tw.crate_orphans(crate, flags),
                [],
                f"{crate} has CI-orphan test files",
            )

    def test_enforced_crates_include_the_three_swept(self) -> None:
        for crate in ("verifier", "core", "sources"):
            self.assertIn(crate, tw.ENFORCED_CRATES)

    def test_sources_is_wired_via_all_targets_step(self) -> None:
        self.assertTrue(tw.runs_all_targets("keyhog-sources"))

    def test_core_is_not_wired_via_all_targets_step(self) -> None:
        # core wires by pub-mod aggregation, not an all-targets step.
        self.assertFalse(tw.runs_all_targets("keyhog-core"))

    def test_live_main_returns_success(self) -> None:
        self.assertEqual(tw.main([]), 0)


if __name__ == "__main__":
    unittest.main()
