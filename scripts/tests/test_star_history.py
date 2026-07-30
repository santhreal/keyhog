"""Behavioral regressions for the repository-owned star-history viewer."""

from __future__ import annotations

import datetime as dt
import tempfile
import unittest
from pathlib import Path

from scripts import star_history as stars


class StarHistoryDataTests(unittest.TestCase):
    """Protect truthful star observations and low-noise recording behavior."""

    def test_real_unstar_events_remain_valid_observations(self) -> None:
        """A user removing a star must not corrupt or silently rewrite historical data."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stars.json"
            path.write_text(
                '[{"date":"2026-07-01","count":84},'
                '{"date":"2026-07-02","count":83}]\n'
            )

            loaded = stars.load_observations(path)

            self.assertEqual(
                loaded,
                [
                    stars.Observation(dt.date(2026, 7, 1), 84),
                    stars.Observation(dt.date(2026, 7, 2), 83),
                ],
            )

    def test_unchanged_count_does_not_create_daily_commit_noise(self) -> None:
        """Flat star counts must not race product pushes with meaningless metrics commits."""
        original = [stars.Observation(dt.date(2026, 7, 1), 84)]

        updated = stars.record_observation(original, dt.date(2026, 7, 2), 84)

        self.assertIs(updated, original)

    def test_historical_flat_runs_compact_to_count_transitions(self) -> None:
        """Existing daily duplicates must collapse without changing any observed transition."""
        observations = [
            stars.Observation(dt.date(2026, 7, 1), 84),
            stars.Observation(dt.date(2026, 7, 2), 84),
            stars.Observation(dt.date(2026, 7, 3), 83),
            stars.Observation(dt.date(2026, 7, 4), 83),
            stars.Observation(dt.date(2026, 7, 5), 85),
        ]

        compacted = stars.compact_observations(observations)

        self.assertEqual(
            compacted,
            [observations[0], observations[2], observations[4]],
        )

    def test_empty_history_fails_with_domain_error(self) -> None:
        """Callers must receive an actionable error instead of an indexing traceback."""
        with self.assertRaisesRegex(stars.StarHistoryError, "at least one"):
            stars.compact_observations([])

    def test_backdated_unchanged_count_is_a_safe_noop(self) -> None:
        """Clock skew must not fail a run that has no new repository state to record."""
        original = [stars.Observation(dt.date(2026, 7, 2), 84)]
        updated = stars.record_observation(original, dt.date(2026, 7, 1), 84)
        self.assertIs(updated, original)

    def test_changed_count_appends_one_exact_observation(self) -> None:
        """A genuine count change must retain its exact UTC date and public count."""
        original = [stars.Observation(dt.date(2026, 7, 1), 84)]

        updated = stars.record_observation(original, dt.date(2026, 7, 2), 86)

        self.assertEqual(
            updated,
            [
                stars.Observation(dt.date(2026, 7, 1), 84),
                stars.Observation(dt.date(2026, 7, 2), 86),
            ],
        )

    def test_same_day_rerun_replaces_instead_of_duplicating(self) -> None:
        """Manual and scheduled runs on one UTC day must leave one authoritative point."""
        original = [
            stars.Observation(dt.date(2026, 6, 30), 83),
            stars.Observation(dt.date(2026, 7, 1), 84),
        ]

        updated = stars.record_observation(original, dt.date(2026, 7, 1), 85)

        self.assertEqual(len(updated), 2)
        self.assertEqual(updated[-1], stars.Observation(dt.date(2026, 7, 1), 85))

    def test_same_day_correction_back_to_previous_count_removes_transition(self) -> None:
        """A corrected API sample must not retain a false one-day star transition."""
        original = [
            stars.Observation(dt.date(2026, 6, 30), 83),
            stars.Observation(dt.date(2026, 7, 1), 84),
        ]

        updated = stars.record_observation(original, dt.date(2026, 7, 1), 83)

        self.assertEqual(
            updated,
            [stars.Observation(dt.date(2026, 6, 30), 83)],
        )

    def test_backdated_or_negative_observation_fails_closed(self) -> None:
        """Bad workflow clocks and malformed API values must not reorder committed history."""
        original = [stars.Observation(dt.date(2026, 7, 2), 84)]
        with self.assertRaisesRegex(stars.StarHistoryError, "predates"):
            stars.record_observation(original, dt.date(2026, 7, 1), 85)
        with self.assertRaisesRegex(stars.StarHistoryError, "nonnegative"):
            stars.record_observation(original, dt.date(2026, 7, 3), -1)
        with self.assertRaisesRegex(stars.StarHistoryError, "integer"):
            stars.record_observation(original, dt.date(2026, 7, 3), True)

    def test_duplicate_or_unsorted_dates_are_rejected(self) -> None:
        """The chart timeline must never choose an arbitrary point order."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stars.json"
            path.write_text(
                '[{"date":"2026-07-02","count":84},'
                '{"date":"2026-07-02","count":85}]\n'
            )
            with self.assertRaisesRegex(stars.StarHistoryError, "strictly increasing"):
                stars.load_observations(path)


class StarHistoryRenderingTests(unittest.TestCase):
    """Prove the generated SVG remains accessible, exact, and self-contained."""

    def setUp(self) -> None:
        self.observations = [
            stars.Observation(dt.date(2026, 5, 27), 44),
            stars.Observation(dt.date(2026, 6, 28), 81),
            stars.Observation(dt.date(2026, 7, 30), 87),
        ]

    def test_svg_has_accessible_identity_and_zero_based_scale(self) -> None:
        """The README chart must state its exact range and avoid a misleading truncated axis."""
        svg = stars.render_svg(self.observations)

        self.assertIn('role="img" aria-labelledby="title description"', svg)
        self.assertIn("KeyHog GitHub stars: 44 on 2026-05-27 to 87 on 2026-07-30", svg)
        self.assertIn(">0</text>", svg)
        self.assertIn(">90</text>", svg)
        self.assertIn(">87 stars</text>", svg)
        self.assertNotIn("<image", svg)
        self.assertNotIn(" href=", svg)

    def test_unstar_decline_uses_a_single_negative_sign(self) -> None:
        """A real count decline must render as -N instead of the malformed +-N label."""
        svg = stars.render_svg(
            [
                stars.Observation(dt.date(2026, 7, 1), 84),
                stars.Observation(dt.date(2026, 7, 2), 83),
            ]
        )

        self.assertIn(">-1 since 2026-07-01", svg)
        self.assertNotIn("+-1", svg)

    def test_single_observation_renders_one_date_without_invented_area_history(self) -> None:
        """A new repository history must show one measured point, not a fake trend span."""
        svg = stars.render_svg(
            [stars.Observation(dt.date(2026, 7, 30), 87)]
        )

        self.assertEqual(svg.count(">2026-07-30</text>"), 1)
        self.assertNotIn('<path d="', svg)
        self.assertIn(">+0 since 2026-07-30", svg)

    def test_svg_bytes_are_deterministic(self) -> None:
        """Scheduled reruns over unchanged data must not create a new chart commit."""
        first = stars.render_svg(self.observations)
        second = stars.render_svg(list(self.observations))
        self.assertEqual(first, second)

    def test_canonical_json_round_trips_exact_values(self) -> None:
        """Formatting cleanup must never alter dates or public star counts."""
        rendered = stars.dump_observations(self.observations)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stars.json"
            path.write_text(rendered)
            self.assertEqual(stars.load_observations(path), self.observations)

    def test_atomic_writer_preserves_existing_mode(self) -> None:
        """Regeneration must not change repository file permissions or leave temporary bytes."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stars.svg"
            path.write_text("old")
            path.chmod(0o640)

            stars.write_atomic(path, "new\n")

            self.assertEqual(path.read_text(), "new\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertFalse(path.with_name("stars.svg.star-history-tmp").exists())


if __name__ == "__main__":
    unittest.main()
